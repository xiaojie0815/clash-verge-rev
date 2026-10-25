use super::{
    chain_diagnostics::{classify_error, io_code},
    diagnostic_snapshot::mask_ip,
};
use crate::config::Config;
use serde_json::{Value, json};
use serde_yaml_ng::Value as Yaml;
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout},
};

struct Endpoint {
    host: String,
    port: u16,
    username: Vec<u8>,
    password: Vec<u8>,
    tls: bool,
}
struct IpProbe {
    address: Option<IpAddr>,
    stage: &'static str,
    code: &'static str,
    elapsed_ms: u128,
}

impl IpProbe {
    fn report(&self) -> Value {
        json!({"status":if self.address.is_some() { "pass" } else { "fail" }, "stage":self.stage, "code":self.code,
            "elapsedMs":self.elapsed_ms, "exitMasked":self.address.map(mask_ip),
            "exitFamily":self.address.map(|ip| if ip.is_ipv4() { "IPv4" } else { "IPv6" })})
    }
}

fn parse_http_ip(raw: &[u8]) -> Result<IpAddr, &'static str> {
    let end = raw
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .ok_or("HTTP_INVALID_RESPONSE")?;
    let header = std::str::from_utf8(&raw[..end]).map_err(|_| "HTTP_INVALID_RESPONSE")?;
    if header.lines().next().and_then(|line| line.split_whitespace().nth(1)) != Some("200") {
        return Err("HTTP_TARGET_REJECTED");
    }
    let mut body = raw[end + 4..].to_vec();
    if header.lines().any(|line| {
        line.to_ascii_lowercase().starts_with("transfer-encoding:") && line.to_ascii_lowercase().contains("chunked")
    }) {
        let mut decoded = Vec::new();
        let mut offset = 0;
        loop {
            let line_end = body
                .get(offset..)
                .and_then(|tail| tail.windows(2).position(|part| part == b"\r\n"))
                .map(|size| offset + size)
                .ok_or("HTTP_INVALID_RESPONSE")?;
            let line = std::str::from_utf8(&body[offset..line_end]).map_err(|_| "HTTP_INVALID_RESPONSE")?;
            let count = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| "HTTP_INVALID_RESPONSE")?;
            offset = line_end + 2;
            if count == 0 {
                break;
            }
            if count > 128 || decoded.len() + count > 128 || offset + count + 2 > body.len() {
                return Err("EXIT_RESPONSE_INVALID");
            }
            decoded.extend_from_slice(&body[offset..offset + count]);
            if &body[offset + count..offset + count + 2] != b"\r\n" {
                return Err("HTTP_INVALID_RESPONSE");
            }
            offset += count + 2;
        }
        body = decoded;
    }
    if body.len() > 128 {
        return Err("EXIT_RESPONSE_INVALID");
    }
    std::str::from_utf8(&body)
        .ok()
        .and_then(|body| body.trim().parse().ok())
        .ok_or("EXIT_RESPONSE_INVALID")
}

async fn probe(endpoint: &Endpoint, target: &'static str, family: u8) -> IpProbe {
    let start = Instant::now();
    let mut stage = "PROXY_DNS";
    let result = timeout(Duration::from_secs(12), async {
        if endpoint.tls { return Err("TLS_WRAPPED_SOCKS_BASELINE_NOT_SUPPORTED"); }
        let addresses = tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port)).await.map_err(|_| "DNS_FAILED")?.collect::<Vec<_>>();
        stage = "PROXY_TCP_CONNECT";
        let mut stream = TcpStream::connect(addresses.as_slice()).await.map_err(io_code)?;
        stage = "SOCKS5_NEGOTIATION";
        let method = if endpoint.username.is_empty() { 0 } else { 2 };
        stream.write_all(&[5, 1, method]).await.map_err(io_code)?;
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await.map_err(io_code)?;
        if reply != [5, method] { return Err("AUTH_METHOD_REJECTED"); }
        if method == 2 {
            stage = "SOCKS5_AUTHENTICATION";
            if endpoint.username.len() > 255 || endpoint.password.len() > 255 { return Err("AUTH_CONFIG_INVALID"); }
            let mut auth = vec![1, endpoint.username.len() as u8];
            auth.extend_from_slice(&endpoint.username);
            auth.push(endpoint.password.len() as u8);
            auth.extend_from_slice(&endpoint.password);
            stream.write_all(&auth).await.map_err(io_code)?;
            stream.read_exact(&mut reply).await.map_err(io_code)?;
            if reply != [1, 0] { return Err("AUTHENTICATION_FAILED"); }
        }
        stage = "SOCKS5_CONNECT_TARGET";
        let mut request = vec![5, 1, 0, 3, target.len() as u8];
        request.extend_from_slice(target.as_bytes()); request.extend_from_slice(&443u16.to_be_bytes());
        stream.write_all(&request).await.map_err(io_code)?;
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await.map_err(io_code)?;
        if head[0] != 5 || head[2] != 0 { return Err("SOCKS_INVALID_RESPONSE"); }
        match head[1] { 0 => {}, 2 => return Err("SOCKS_RULE_DENIED"), 3 => return Err("SOCKS_NETWORK_UNREACHABLE"),
            4 => return Err("SOCKS_HOST_UNREACHABLE"), 5 => return Err("SOCKS_TARGET_REFUSED"), _ => return Err("SOCKS_CONNECT_FAILED") }
        let length = match head[3] { 1 => 4, 4 => 16, 3 => { stream.read_exact(&mut reply[..1]).await.map_err(io_code)?; usize::from(reply[0]) }, _ => return Err("SOCKS_INVALID_RESPONSE") };
        let mut address = vec![0; length + 2];
        stream.read_exact(&mut address).await.map_err(io_code)?;
        stage = "TARGET_TLS";
        let name = rustls::pki_types::ServerName::try_from(target).map_err(|_| "TLS_NAME_INVALID")?;
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&super::clash::TLS_CONFIG));
        let mut tls = connector.connect(name, stream).await.map_err(|error| classify_error(&error))?;
        stage = "EXIT_IP_HTTP";
        let request = format!("GET / HTTP/1.0\r\nHost: {target}\r\nAccept: text/plain\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
        tls.write_all(request.as_bytes()).await.map_err(io_code)?;
        let mut raw = Vec::new();
        (&mut tls).take(16385).read_to_end(&mut raw).await.map_err(io_code)?;
        if raw.len() > 16384 { return Err("HTTP_RESPONSE_TOO_LONG"); }
        let ip = parse_http_ip(&raw)?;
        if (family == 4 && ip.is_ipv6()) || (family == 6 && ip.is_ipv4()) { return Err("EXIT_FAMILY_MISMATCH"); }
        Ok(ip)
    }).await;
    let (address, code) = match result {
        Ok(Ok(ip)) => (Some(ip), "EXIT_IP_RECEIVED"),
        Ok(Err(code)) => (None, code),
        Err(_) => (None, "TIMEOUT"),
    };
    IpProbe {
        address,
        stage,
        code,
        elapsed_ms: start.elapsed().as_millis(),
    }
}

pub(super) async fn compare_exits() -> Result<Value, &'static str> {
    let _operation = crate::config::runtime::CHAIN_OPERATION.lock().await;
    let before = crate::cmd::proxy_chain::chain_state()
        .await
        .map_err(|_| "CORE_UNAVAILABLE")?;
    if !before.links_applied || !before.selection_applied || !before.scope_active {
        return Err("CHAIN_NOT_ACTIVE_IN_CURRENT_SCOPE");
    }
    let runtime = Config::runtime().await.data_arc();
    let config = runtime.config.as_ref().ok_or("RUNTIME_CONFIG_UNAVAILABLE")?;
    let exit = before.nodes.last().ok_or("CHAIN_NOT_APPLIED")?;
    let node = config
        .get("proxies")
        .and_then(Yaml::as_sequence)
        .and_then(|items| {
            items
                .iter()
                .find(|item| item.get("name").and_then(Yaml::as_str) == Some(exit.as_str()))
        })
        .ok_or("EXIT_DEFINITION_UNAVAILABLE")?;
    if node.get("type").and_then(Yaml::as_str) != Some("socks5") {
        return Err("DIRECT_BASELINE_REQUIRES_SOCKS5_EXIT");
    }
    let direct = Endpoint {
        host: node
            .get("server")
            .and_then(Yaml::as_str)
            .ok_or("EXIT_DEFINITION_UNAVAILABLE")?
            .trim_matches(['[', ']'])
            .to_owned(),
        port: node
            .get("port")
            .and_then(Yaml::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .ok_or("EXIT_DEFINITION_UNAVAILABLE")?,
        username: node
            .get("username")
            .and_then(Yaml::as_str)
            .unwrap_or("")
            .as_bytes()
            .to_vec(),
        password: node
            .get("password")
            .and_then(Yaml::as_str)
            .unwrap_or("")
            .as_bytes()
            .to_vec(),
        tls: node.get("tls").and_then(Yaml::as_bool).unwrap_or(false),
    };
    let (username, password) = config
        .get("authentication")
        .and_then(Yaml::as_sequence)
        .and_then(|items| items.first())
        .and_then(Yaml::as_str)
        .and_then(|value| value.split_once(':'))
        .unwrap_or(("", ""));
    let local = Endpoint {
        host: "127.0.0.1".to_owned(),
        port: before.mixed_port.ok_or("MIXED_PORT_UNAVAILABLE")?,
        username: username.as_bytes().to_vec(),
        password: password.as_bytes().to_vec(),
        tls: false,
    };
    let direct_allowed = before.tun_enabled == Some(false);
    let mut rows = Vec::new();
    for (label, host, family) in [
        ("IPv4", "api.ipify.org", 4),
        ("IPv6", "api6.ipify.org", 6),
        ("AUTO", "api64.ipify.org", 0),
    ] {
        let (direct_probe, local_probe, samples) = tokio::join!(
            async {
                if direct_allowed {
                    Some(probe(&direct, host, family).await)
                } else {
                    None
                }
            },
            probe(&local, host, family),
            async {
                tokio::time::sleep(Duration::from_millis(800)).await;
                let first = super::diagnostic_snapshot::probe_connections().await;
                tokio::time::sleep(Duration::from_millis(1500)).await;
                let second = super::diagnostic_snapshot::probe_connections().await;
                vec![first, second]
            }
        );
        let matches = direct_probe
            .as_ref()
            .and_then(|direct| direct.address)
            .zip(local_probe.address)
            .map(|(direct, local)| direct == local);
        rows.push(json!({"test":label,"sameExit":matches,"directVps":direct_probe.as_ref().map(IpProbe::report).unwrap_or_else(|| json!({"status":"skipped","code":"DIRECT_ROUTE_NOT_VERIFIED_WITH_TUN"})),"clash":local_probe.report(),"requestSamples":samples,"samplesMatchFixedQueryHostsOnly":true,"samplesUniquelyIdentifyProbe":false}));
    }
    let after = crate::cmd::proxy_chain::chain_state().await.ok();
    let stable = after.is_some_and(|after| {
        after.mode == before.mode
            && after.group == before.group
            && after.nodes == before.nodes
            && after.selected == before.selected
            && after.tun_enabled == before.tun_enabled
            && after.mixed_port == before.mixed_port
    }) && Arc::ptr_eq(&runtime, &Config::runtime().await.data_arc());
    Ok(
        json!({"format":"clash-mcp-exit-comparison-v1","observedAt":chrono::Utc::now().to_rfc3339(),"snapshotStable":stable,
        "mode":match before.mode.as_str() { "global" => "global", "rule" => "rule", "direct" => "direct", _ => "unknown" },
        "tunEnabled":before.tun_enabled,"systemRouteBypassVerified":false,"sameExitProvesSameRoute":false,
        "upstreamConfigurationVerified":false,"results":rows}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_mcp_ip_parser_accepts_bounded_plain_and_chunked_responses() {
        assert_eq!(
            parse_http_ip(b"HTTP/1.0 200 OK\r\n\r\n203.0.113.21\n")
                .unwrap()
                .to_string(),
            "203.0.113.21"
        );
        assert_eq!(
            parse_http_ip(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nb\r\n2001:db8::1\r\n0\r\n\r\n")
                .unwrap()
                .to_string(),
            "2001:db8::1"
        );
        assert!(parse_http_ip(b"HTTP/1.0 302 Redirect\r\n\r\n203.0.113.21").is_err());
        assert!(parse_http_ip(b"HTTP/1.0 200 OK\r\n\r\nusername:password@203.0.113.21").is_err());
    }
}
