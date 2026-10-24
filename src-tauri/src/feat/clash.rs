use crate::core::notify::NoticeStatus;
use crate::core::notify::{Refresh, announce};
use crate::{
    config::{Config, MixedPort},
    core::{CoreManager, handle, tray},
    feat::clean_async,
    utils,
};
use bytes::BytesMut;
use clash_verge_logging::{Type, logging};
use serde_yaml_ng::{Mapping, Value};
use smartstring::alias::String;
use std::sync::{Arc, LazyLock};

#[allow(clippy::expect_used)]
pub(super) static TLS_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let root_store = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("Failed to set TLS versions")
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Arc::new(config)
});

pub async fn restart_clash_core() {
    match CoreManager::global().restart_core().await {
        Ok(_) => {
            announce(Refresh::Clash);
        }
        Err(err) => {
            handle::Handle::notice(NoticeStatus::SetConfigError, format!("{err:#}"));
            logging!(error, Type::Core, "restart core failed: {err:#}");
        }
    }
}

pub async fn restart_app() {
    logging!(debug, Type::System, "启动重启应用流程");
    handle::Handle::global().set_is_exiting();

    Config::apply_all_and_save_file().await;

    let cleanup_result = clean_async().await;

    logging!(
        info,
        Type::System,
        "资源清理完成，退出代码: {}",
        if cleanup_result.all_success { 0 } else { 1 }
    );

    if !cleanup_result.core_stopped {
        handle::Handle::global().clear_is_exiting();
        // A failed stop may still have marked the core stopped, and exit cleanup skipped the DNS restore.
        // A core that kept running keeps its DNS, whatever an unapplied config draft says.
        #[cfg(target_os = "macos")]
        {
            let manager = CoreManager::global();
            let _lifecycle = manager.lifecycle_lock.lock().await;
            if matches!(
                *manager.get_running_mode(),
                crate::core::manager::RunningMode::NotRunning
            ) {
                crate::utils::resolve::dns::sync_public_dns().await;
            }
        }
        handle::Handle::notice(
            NoticeStatus::AppRestartCoreStopFailed,
            cleanup_result.stop_error.unwrap_or_default(),
        );
        return;
    }

    utils::server::shutdown_embedded_server();
    let app_handle = handle::Handle::app_handle();
    app_handle.restart();
}

pub(crate) struct LiveChainSettings {
    pub mode: std::string::String,
    pub tun_enabled: Option<bool>,
    pub mixed_port: Option<u16>,
}

pub(crate) async fn live_chain_settings() -> anyhow::Result<LiveChainSettings> {
    let parsed = match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        handle::Handle::mihomo().get_base_config(),
    )
    .await
    {
        Ok(Ok(config)) => serde_json::to_value(config)?,
        _ => {
            // Older plugin models can reject otherwise valid /configs fields.
            let info = Config::clash().await.data_arc().get_client_info();
            let endpoint: std::net::SocketAddr = info.server.parse()?;
            anyhow::ensure!(endpoint.ip().is_loopback(), "Local controller readback unavailable");
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(3))
                .build()?;
            let mut request = client.get(format!("http://{endpoint}/configs"));
            if let Some(secret) = info.secret {
                request = request.bearer_auth(secret.as_str());
            }
            request
                .send()
                .await?
                .error_for_status()?
                .json::<serde_json::Value>()
                .await?
        }
    };
    let mode = parsed
        .get("mode")
        .and_then(serde_json::Value::as_str)
        .filter(|mode| matches!(*mode, "rule" | "global" | "direct"))
        .ok_or_else(|| anyhow::anyhow!("Live mode is unavailable"))?
        .to_owned();
    Ok(LiveChainSettings {
        mode,
        tun_enabled: parsed.pointer("/tun/enable").and_then(serde_json::Value::as_bool),
        mixed_port: parsed
            .get("mixed-port")
            .or_else(|| parsed.get("mixedPort"))
            .or_else(|| parsed.get("mixed_port"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0),
    })
}

pub async fn change_clash_mode(mode: String) -> Result<(), String> {
    let _operation = crate::config::runtime::CHAIN_OPERATION.lock().await;
    if !matches!(mode.as_str(), "rule" | "global" | "direct") {
        return Err("Invalid proxy mode".into());
    }
    let mut mapping = Mapping::new();
    mapping.insert(Value::from("mode"), Value::from(mode.as_str()));
    let json_value = serde_json::json!({
        "mode": mode
    });
    if let Err(err) = handle::Handle::mihomo().patch_base_config(&json_value).await {
        logging!(error, Type::Core, "change clash mode failed: {err}");
        return Err(err.to_string().into());
    }

    let live = live_chain_settings()
        .await
        .map_err(|_| String::from("Mode PATCH returned, but live mode could not be read back"))?;
    if live.mode != mode.as_str() {
        return Err("The core did not confirm the requested proxy mode".into());
    }

    let clash = Config::clash().await;
    clash.edit_draft(|d| d.patch_config(&mapping));
    clash.apply();

    let clash_data = clash.data_arc();
    let saved = clash_data.save_config().await;
    announce(Refresh::Clash);
    tray::Tray::global().update_menu_and_icon().await;

    let is_auto_close_connection = Config::verge().await.data_arc().auto_close_connection.unwrap_or(false);
    if is_auto_close_connection {
        handle::Handle::mihomo()
            .close_all_connections()
            .await
            .map_err(|_| String::from("Mode applied, but old connections could not be closed"))?;
    }
    saved.map_err(|_| String::from("Mode applied, but the saved preference could not be updated"))?;
    Ok(())
}

/// Test delay to a URL through proxy.
/// HTTPS: measures TLS handshake time. HTTP: measures HEAD round-trip time.
#[tracing::instrument(skip_all, level = "trace", fields(url = %url))]
pub async fn test_delay(url: String) -> anyhow::Result<u32> {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;
    use tokio::time::Instant;

    let parsed = tauri::Url::parse(&url)?;
    let is_https = parsed.scheme() == "https";
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid URL: no host"))?
        .to_string();
    let port = parsed.port().unwrap_or(if is_https { 443 } else { 80 });

    let verge = Config::verge().await.latest_arc();
    let proxy_enabled = verge.enable_system_proxy.unwrap_or(false) || verge.enable_tun_mode.unwrap_or(false);
    let proxy_port = if proxy_enabled {
        Some(MixedPort::desired().await)
    } else {
        None
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        let start = Instant::now();
        let mut buf = BytesMut::with_capacity(1024);

        if is_https {
            let stream = match proxy_port {
                Some(pp) => {
                    let mut s = TcpStream::connect(format!("127.0.0.1:{pp}")).await?;
                    s.write_all(format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes())
                        .await?;
                    s.read_buf(&mut buf).await?;
                    if !buf.windows(3).any(|w| w == b"200") {
                        return Err(anyhow::anyhow!("Proxy CONNECT failed"));
                    }
                    s
                }
                None => TcpStream::connect(format!("{host}:{port}")).await?,
            };
            let connector = tokio_rustls::TlsConnector::from(Arc::clone(&TLS_CONFIG));
            let server_name = rustls::pki_types::ServerName::try_from(host.as_str())
                .map_err(|_| anyhow::anyhow!("Invalid DNS name: {host}"))?
                .to_owned();
            connector.connect(server_name, stream).await?;
        } else {
            let (mut stream, req) = match proxy_port {
                Some(pp) => (
                    TcpStream::connect(format!("127.0.0.1:{pp}")).await?,
                    format!("HEAD {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
                ),
                None => (
                    TcpStream::connect(format!("{host}:{port}")).await?,
                    format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
                ),
            };
            stream.write_all(req.as_bytes()).await?;
            let _ = stream.read(&mut buf).await?;
        }

        Ok((start.elapsed().as_millis() as u32).max(1))
    })
    .await
    .unwrap_or(Ok(10000u32))
}
