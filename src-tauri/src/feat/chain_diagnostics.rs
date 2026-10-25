use crate::{
    cmd::{CmdResult, CommandFailure},
    config::Config,
    core::handle::Handle,
};
use serde::Serialize;
use serde_yaml_ng::Value;
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout},
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainDiagnosticStep {
    hop: Option<usize>,
    stage: &'static str,
    status: &'static str,
    code: String,
    elapsed_ms: u128,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChainNodeReport {
    alias: String,
    address: String,
    protocol: &'static str,
    port: Option<u64>,
    username_password_configured: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainDiagnosticReport {
    format: &'static str,
    app_version: &'static str,
    generated_at: String,
    pub mode: String,
    pub links_applied: bool,
    pub selection_applied: bool,
    pub scope_active: bool,
    pub snapshot_stable: bool,
    group: &'static str,
    selected: String,
    tun_enabled: Option<bool>,
    system_proxy_requested: bool,
    system_proxy_effective: &'static str,
    nodes: Vec<ChainNodeReport>,
    pub steps: Vec<ChainDiagnosticStep>,
    pub egress_matches: Option<bool>,
    egress_family: Option<&'static str>,
    server_side_upstream: &'static str,
    observed_routes: Vec<ObservedRoute>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObservedRoute {
    target: String,
    rule: &'static str,
    chain: Vec<String>,
    includes_expected_exit: bool,
    has_response_bytes: bool,
}

fn step(
    hop: Option<usize>,
    stage: &'static str,
    status: &'static str,
    code: impl Into<String>,
    start: Instant,
) -> ChainDiagnosticStep {
    ChainDiagnosticStep {
        hop,
        stage,
        status,
        code: code.into(),
        elapsed_ms: start.elapsed().as_millis(),
    }
}

pub(super) fn classify(message: &str) -> &'static str {
    let message = message.to_ascii_lowercase();
    if message.contains("authentication") || message.contains("auth failed") || message.contains("no acceptable") {
        "AUTHENTICATION_FAILED"
    } else if message.contains("dns") || message.contains("resolve") || message.contains("no such host") {
        "DNS_FAILED"
    } else if message.contains("deadline") || message.contains("timeout") || message.contains("timed out") {
        "TIMEOUT"
    } else if message.contains("eof") || message.contains("closed") || message.contains("reset") {
        "PEER_CLOSED"
    } else if message.contains("certificate") {
        "TLS_CERTIFICATE_FAILED"
    } else if message.contains("tls") || message.contains("ssl") {
        "TLS_FAILED"
    } else if message.contains("refused") {
        "CONNECTION_REFUSED"
    } else {
        "UNCLASSIFIED_CONNECTION_FAILURE"
    }
}

pub(super) fn classify_error(error: &(dyn std::error::Error + 'static)) -> &'static str {
    let mut current = Some(error);
    while let Some(cause) = current {
        let code = classify(&cause.to_string());
        if code != "UNCLASSIFIED_CONNECTION_FAILURE" {
            return code;
        }
        current = cause.source();
    }
    "UNCLASSIFIED_CONNECTION_FAILURE"
}

pub(super) fn io_code(error: std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
            "PEER_CLOSED"
        }
        std::io::ErrorKind::TimedOut => "TIMEOUT",
        std::io::ErrorKind::ConnectionRefused => "CONNECTION_REFUSED",
        _ => "CONNECTION_FAILED",
    }
}

async fn direct_socks(proxy: &Value, hop: usize, limit: Duration) -> ChainDiagnosticStep {
    let started = Instant::now();
    let mut stage = "NODE_DNS";
    let result = timeout(limit, async {
        let host = proxy
            .get("server")
            .and_then(Value::as_str)
            .ok_or("NODE_CONFIG_UNAVAILABLE")?
            .trim_matches(['[', ']']);
        let port = proxy
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .ok_or("NODE_CONFIG_UNAVAILABLE")?;
        if proxy.get("tls").and_then(Value::as_bool) == Some(true) {
            return Err("DIRECT_TLS_PROXY_NOT_TESTED");
        }
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| "DNS_FAILED")?
            .collect::<Vec<_>>();
        stage = "DIRECT_NODE_TCP";
        let mut stream = TcpStream::connect(addresses.as_slice()).await.map_err(io_code)?;
        let username = proxy.get("username").and_then(Value::as_str).unwrap_or("").as_bytes();
        let password = proxy.get("password").and_then(Value::as_str).unwrap_or("").as_bytes();
        if username.len() > 255 || password.len() > 255 {
            return Err("AUTH_CONFIG_INVALID");
        }
        let method = if username.is_empty() { 0 } else { 2 };
        stage = "DIRECT_SOCKS5_NEGOTIATION";
        stream.write_all(&[5, 1, method]).await.map_err(io_code)?;
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).await.map_err(io_code)?;
        if reply != [5, method] {
            return Err("AUTH_METHOD_REJECTED");
        }
        if method == 2 {
            stage = "DIRECT_SOCKS5_AUTHENTICATION";
            let mut auth = vec![1, username.len() as u8];
            auth.extend_from_slice(username);
            auth.push(password.len() as u8);
            auth.extend_from_slice(password);
            stream.write_all(&auth).await.map_err(io_code)?;
            stream.read_exact(&mut reply).await.map_err(io_code)?;
            if reply != [1, 0] {
                return Err("AUTHENTICATION_FAILED");
            }
        }
        stage = "DIRECT_SOCKS5_TARGET_CONNECT";
        let target = b"example.com";
        let mut request = vec![5, 1, 0, 3, target.len() as u8];
        request.extend_from_slice(target);
        request.extend_from_slice(&443u16.to_be_bytes());
        stream.write_all(&request).await.map_err(io_code)?;
        let mut header = [0; 4];
        stream.read_exact(&mut header).await.map_err(io_code)?;
        if header[0] != 5 || header[2] != 0 {
            return Err("SOCKS_INVALID_RESPONSE");
        }
        match header[1] {
            0 => {}
            2 => return Err("SOCKS_RULE_DENIED"),
            3 => return Err("SOCKS_NETWORK_UNREACHABLE"),
            4 => return Err("SOCKS_HOST_UNREACHABLE"),
            5 => return Err("SOCKS_TARGET_REFUSED"),
            _ => return Err("SOCKS_TARGET_CONNECT_REJECTED"),
        }
        let length = match header[3] {
            1 => 4,
            4 => 16,
            3 => {
                stream.read_exact(&mut reply[..1]).await.map_err(io_code)?;
                usize::from(reply[0])
            }
            _ => return Err("SOCKS_INVALID_RESPONSE"),
        };
        let mut address = vec![0; length + 2];
        stream.read_exact(&mut address).await.map_err(io_code)?;
        stage = "DIRECT_TARGET_TLS";
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&super::clash::TLS_CONFIG));
        let name = rustls::pki_types::ServerName::try_from("example.com").map_err(|_| "TLS_NAME_INVALID")?;
        let mut tls = connector
            .connect(name, stream)
            .await
            .map_err(|error| classify_error(&error))?;
        stage = "DIRECT_TARGET_HTTP";
        tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            .await
            .map_err(io_code)?;
        let mut line = Vec::new();
        while !line.ends_with(b"\r\n") && line.len() < 4096 {
            tls.read_exact(&mut reply[..1]).await.map_err(io_code)?;
            line.push(reply[0]);
        }
        let line = std::str::from_utf8(&line).map_err(|_| "HTTP_INVALID_RESPONSE")?;
        let status = line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or("HTTP_INVALID_RESPONSE")?;
        if !line.starts_with("HTTP/") || !(200..400).contains(&status) {
            return Err("HTTP_TARGET_REJECTED");
        }
        Ok::<_, &'static str>(())
    })
    .await;
    match result {
        Ok(Ok(())) => step(Some(hop), stage, "pass", "HTTPS_RESPONSE_RECEIVED", started),
        Ok(Err("DIRECT_TLS_PROXY_NOT_TESTED")) => {
            step(Some(hop), stage, "skipped", "DIRECT_TLS_PROXY_NOT_TESTED", started)
        }
        Ok(Err(code)) => step(Some(hop), stage, "fail", code, started),
        Err(_) => step(Some(hop), stage, "fail", "TIMEOUT", started),
    }
}

fn route_alias(name: &str, nodes: &[String]) -> String {
    nodes.iter().position(|node| node == name).map_or_else(
        || {
            if matches!(name, "GLOBAL" | "DIRECT" | "REJECT") {
                name.to_owned()
            } else {
                "OTHER_NODE_OR_GROUP".to_owned()
            }
        },
        |index| format!("NODE_{}", index + 1),
    )
}

fn masked_address(host: Option<&str>, index: usize) -> String {
    match host.and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok()) {
        Some(IpAddr::V4(address)) => {
            let bytes = address.octets();
            format!("{}.{}.*.*", bytes[0], bytes[1])
        }
        Some(IpAddr::V6(address)) => {
            let segments = address.segments();
            format!("{:x}:{:x}:*:*:*:*:*:*", segments[0], segments[1])
        }
        None => format!("HOST_NODE_{}", index + 1),
    }
}

async fn observed_routes(nodes: &[String]) -> Vec<ObservedRoute> {
    let Ok(connections) = Handle::mihomo().get_connections().await else {
        return vec![];
    };
    let Ok(value) = serde_json::to_value(connections) else {
        return vec![];
    };
    let Some(connections) = value.get("connections").and_then(serde_json::Value::as_array) else {
        return vec![];
    };
    let mut hosts = std::collections::HashMap::new();
    connections
        .iter()
        .take(20)
        .map(|connection| {
            let host = connection
                .pointer("/metadata/host")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let next = hosts.len() + 1;
            let target = hosts
                .entry(host.to_owned())
                .or_insert_with(|| format!("HOST_{next}"))
                .clone();
            let chain = connection
                .get("chains")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>();
            let raw_rule = connection.get("rule").and_then(serde_json::Value::as_str).unwrap_or("");
            let rule = match raw_rule {
                "Match" => "MATCH",
                "Global" | "GLOBAL" => "GLOBAL",
                "Domain" => "DOMAIN",
                "DomainKeyword" => "DOMAIN_KEYWORD",
                "DomainSuffix" => "DOMAIN_SUFFIX",
                "IPCIDR" | "IPCIDR6" => "IP_CIDR",
                "GeoIP" => "GEO_IP",
                _ => "OTHER_RULE",
            };
            ObservedRoute {
                target,
                rule,
                includes_expected_exit: nodes.last().is_some_and(|exit| chain.contains(&exit.as_str())),
                chain: chain.into_iter().map(|name| route_alias(name, nodes)).collect(),
                has_response_bytes: connection
                    .get("download")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
                    > 0,
            }
        })
        .collect()
}

pub async fn diagnose_chain(expected_egress: Option<String>) -> CmdResult<ChainDiagnosticReport> {
    let expected = expected_egress
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().parse::<IpAddr>())
        .transpose()
        .map_err(|_| {
            CommandFailure::coded(
                "CHAIN_EXPECTED_IP_INVALID",
                "Expected exit must be an IPv4 or IPv6 address",
            )
        })?;
    let _operation = crate::config::runtime::CHAIN_OPERATION.lock().await;
    let runtime = Config::runtime().await.data_arc();
    let state_result = timeout(Duration::from_secs(8), crate::cmd::proxy_chain::chain_state()).await;
    let core_available = matches!(&state_result, Ok(Ok(_)));
    let state = match state_result {
        Ok(Ok(state)) => state,
        _ => crate::cmd::proxy_chain::ProxyChainState {
            group: runtime.proxy_chain.as_ref().map(|session| session.group.clone()),
            nodes: runtime
                .proxy_chain
                .as_ref()
                .map(|session| session.nodes.clone())
                .unwrap_or_default(),
            selected: None,
            tun_enabled: None,
            mixed_port: None,
            mode: "unknown".to_owned(),
            links_applied: false,
            selection_applied: false,
            scope_active: false,
            warnings: vec![],
        },
    };
    let view = if core_available {
        timeout(
            Duration::from_secs(4),
            crate::cmd::proxy::proxy_view(Some(Duration::from_secs(2))),
        )
        .await
        .ok()
        .and_then(Result::ok)
    } else {
        None
    };
    let config = runtime.config.as_ref();
    let verge = Config::verge().await.data_arc();
    let mut report = ChainDiagnosticReport {
        format: "clash-verge-chain-private-report-v1",
        app_version: env!("CARGO_PKG_VERSION"),
        generated_at: chrono::Utc::now().to_rfc3339(),
        mode: state.mode.clone(),
        links_applied: state.links_applied,
        selection_applied: state.selection_applied,
        scope_active: state.scope_active,
        snapshot_stable: true,
        group: if state.group.as_deref() == Some("GLOBAL") {
            "GLOBAL"
        } else if state.group.is_some() {
            "GROUP_1"
        } else {
            "UNBOUND"
        },
        selected: state
            .selected
            .as_deref()
            .map(|name| route_alias(name, &state.nodes))
            .unwrap_or_else(|| "NONE".to_owned()),
        tun_enabled: state.tun_enabled,
        system_proxy_requested: verge.enable_system_proxy.unwrap_or(false),
        system_proxy_effective: "NOT_VERIFIED",
        nodes: vec![],
        steps: vec![],
        egress_matches: None,
        egress_family: None,
        server_side_upstream: "NOT_OBSERVABLE_FROM_CLIENT",
        observed_routes: vec![],
    };
    let started = Instant::now();
    report.steps.push(step(
        None,
        "CONFIGURATION",
        if state.links_applied && state.selection_applied && state.scope_active {
            "pass"
        } else {
            "fail"
        },
        if !core_available {
            "CHAIN_CORE_UNAVAILABLE"
        } else if state.links_applied && state.selection_applied && state.scope_active {
            "LIVE_STATE_CONFIRMED"
        } else {
            "CHAIN_NOT_ACTIVE_IN_CURRENT_SCOPE"
        },
        started,
    ));
    let deadline = Instant::now() + Duration::from_secs(60);
    for (index, name) in state.nodes.iter().enumerate() {
        let proxy = config
            .and_then(|config| config.get("proxies"))
            .and_then(Value::as_sequence)
            .and_then(|proxies| {
                proxies
                    .iter()
                    .find(|proxy| proxy.get("name").and_then(Value::as_str) == Some(name.as_str()))
            });
        let protocol = match proxy.and_then(|proxy| proxy.get("type")).and_then(Value::as_str) {
            Some("socks5") => "socks5",
            Some("http") => "http",
            Some("ss") => "ss",
            Some("vless") => "vless",
            Some("vmess") => "vmess",
            Some("trojan") => "trojan",
            Some("hysteria2") => "hysteria2",
            _ => "other_or_provider",
        };
        report.nodes.push(ChainNodeReport {
            alias: format!("NODE_{}", index + 1),
            protocol,
            address: masked_address(
                proxy.and_then(|proxy| proxy.get("server")).and_then(Value::as_str),
                index,
            ),
            port: proxy
                .and_then(|proxy| proxy.get("port"))
                .and_then(Value::as_u64)
                .filter(|port| (1..=65535).contains(port)),
            username_password_configured: proxy
                .and_then(|proxy| proxy.get("username"))
                .and_then(Value::as_str)
                .is_some_and(|user| !user.is_empty()),
        });
        if Instant::now() >= deadline {
            report.steps.push(step(
                Some(index + 1),
                "CHAIN_PREFIX_ACCESS",
                "skipped",
                "DIAGNOSTIC_BUDGET_EXHAUSTED",
                Instant::now(),
            ));
            continue;
        }
        if let Some(proxy) = proxy.filter(|_| protocol == "socks5") {
            if report.tun_enabled == Some(false) {
                report.steps.push(
                    direct_socks(
                        proxy,
                        index + 1,
                        deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_secs(6)),
                    )
                    .await,
                );
            } else {
                report.steps.push(step(
                    Some(index + 1),
                    "DIRECT_NODE_TCP",
                    "skipped",
                    "DIRECT_ROUTE_NOT_VERIFIED_WITH_TUN",
                    Instant::now(),
                ));
            }
        }
        let start = Instant::now();
        if !core_available {
            report.steps.push(step(
                Some(index + 1),
                "CHAIN_PREFIX_ACCESS",
                "skipped",
                "CHAIN_CORE_UNAVAILABLE",
                start,
            ));
            continue;
        }
        let mihomo = Handle::mihomo();
        let result = timeout(
            deadline.saturating_duration_since(start).min(Duration::from_secs(7)),
            async {
                let source = view
                    .as_ref()
                    .and_then(|view| view.records.values().find(|node| node.name == *name))
                    .map(|node| &node.source);
                if let Some(crate::core::proxy_view::ProxyNodeSource::Provider {
                    provider_name,
                    proxy_name,
                }) = source
                {
                    mihomo
                        .healthcheck_node_in_provider(provider_name, proxy_name, "https://example.com", 6000)
                        .await
                } else {
                    mihomo.delay_proxy_by_name(name, "https://example.com", 6000).await
                }
            },
        )
        .await;
        report.steps.push(match result {
            Ok(Ok(delay)) if delay.delay > 0 => step(
                Some(index + 1),
                "CHAIN_PREFIX_ACCESS",
                "pass",
                "CORE_HTTPS_PROBE_PASSED",
                start,
            ),
            // The plugin maps some failed health checks to Ok(ProxyDelay { delay: 0 }).
            Ok(Ok(_)) => step(
                Some(index + 1),
                "CHAIN_PREFIX_ACCESS",
                "fail",
                "CONNECTION_FAILED",
                start,
            ),
            Ok(Err(error)) => step(
                Some(index + 1),
                "CHAIN_PREFIX_ACCESS",
                "fail",
                classify(&error.to_string()),
                start,
            ),
            Err(_) => step(Some(index + 1), "CHAIN_PREFIX_ACCESS", "fail", "TIMEOUT", start),
        });
    }
    if state.links_applied && state.selection_applied && state.scope_active {
        let start = Instant::now();
        let mut local_stage = "LOCAL_PROXY_TARGET_HTTP";
        let mut target_passed = false;
        let result = timeout(Duration::from_secs(10), async {
            let local_port = state.mixed_port.ok_or("LOCAL_PROXY_CONFIG_FAILED")?;
            let mut local = reqwest::Proxy::http(format!("http://127.0.0.1:{local_port}"))
                .map_err(|_| "LOCAL_PROXY_CONFIG_FAILED")?;
            if let Some((user, password)) = config
                .and_then(|config| config.get("authentication"))
                .and_then(Value::as_sequence)
                .and_then(|items| items.first())
                .and_then(Value::as_str)
                .and_then(|value| value.split_once(':'))
            {
                local = local.basic_auth(user, password);
            }
            let client = reqwest::Client::builder()
                .no_proxy()
                .proxy(local)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(9))
                .build()
                .map_err(|_| "LOCAL_PROXY_CONFIG_FAILED")?;
            let response = client
                .get("https://example.com")
                .send()
                .await
                .map_err(|error| classify_error(&error))?;
            report.observed_routes = observed_routes(&state.nodes).await;
            if !response.status().is_success() {
                return Err("HTTP_TARGET_REJECTED");
            }
            target_passed = true;
            if let Some(expected) = expected {
                local_stage = "EGRESS_QUERY";
                let mut response = client
                    .get("https://ifconfig.me/ip")
                    .send()
                    .await
                    .map_err(|error| classify_error(&error))?;
                if !response.status().is_success() {
                    return Err("EGRESS_SERVICE_REJECTED");
                }
                let mut body = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(|_| "EGRESS_RESPONSE_FAILED")? {
                    if body.len() + chunk.len() > 128 {
                        return Err("EGRESS_RESPONSE_INVALID");
                    }
                    body.extend_from_slice(&chunk);
                }
                let observed = std::str::from_utf8(&body)
                    .ok()
                    .and_then(|body| body.trim().parse::<IpAddr>().ok())
                    .ok_or("EGRESS_RESPONSE_INVALID")?;
                report.egress_family = Some(if observed.is_ipv4() { "IPv4" } else { "IPv6" });
                report.egress_matches = Some(observed == expected);
            }
            Ok::<_, &'static str>(())
        })
        .await;
        if target_passed && local_stage == "EGRESS_QUERY" {
            report.steps.push(step(
                None,
                "LOCAL_PROXY_TARGET_HTTP",
                "pass",
                "HTTPS_RESPONSE_RECEIVED",
                start,
            ));
        }
        report.steps.push(match result {
            Ok(Ok(())) => step(
                None,
                local_stage,
                "pass",
                if local_stage == "EGRESS_QUERY" {
                    "EGRESS_RESPONSE_RECEIVED"
                } else {
                    "HTTPS_RESPONSE_RECEIVED"
                },
                start,
            ),
            Ok(Err(code)) => step(None, local_stage, "fail", code, start),
            Err(_) => step(None, local_stage, "fail", "TIMEOUT", start),
        });
    } else {
        report.steps.push(step(
            None,
            "LOCAL_PROXY_TARGET_HTTP",
            "skipped",
            "CHAIN_NOT_ACTIVE_IN_CURRENT_SCOPE",
            Instant::now(),
        ));
    }
    report.steps.push(step(
        None,
        "EGRESS_VERIFICATION",
        if report.egress_matches == Some(true) {
            "pass"
        } else if report.egress_matches == Some(false) {
            "fail"
        } else {
            "skipped"
        },
        match report.egress_matches {
            Some(true) => "EXPECTED_EXIT_MATCHED",
            Some(false) => "EXPECTED_EXIT_MISMATCH",
            None => "EXIT_NOT_VERIFIED",
        },
        Instant::now(),
    ));
    if let Ok(Ok(current)) = timeout(Duration::from_secs(3), crate::cmd::proxy_chain::chain_state()).await {
        report.snapshot_stable = current.mode == state.mode
            && current.group == state.group
            && current.nodes == state.nodes
            && current.selected == state.selected
            && current.links_applied == state.links_applied
            && current.tun_enabled == state.tun_enabled
            && current.mixed_port == state.mixed_port;
    } else {
        report.snapshot_stable = false;
    }
    report.snapshot_stable &= Arc::ptr_eq(&runtime, &Config::runtime().await.data_arc());
    Ok(report)
}
