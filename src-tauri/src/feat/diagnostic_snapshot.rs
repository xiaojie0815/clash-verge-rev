use crate::{
    config::Config,
    core::{CoreManager, handle::Handle},
};
use serde_json::{Value, json};
use std::{collections::HashMap, net::IpAddr};

pub(super) fn mask_ip(value: IpAddr) -> String {
    match value {
        IpAddr::V4(ip) => {
            let a = ip.octets();
            format!("{}.{}.*.*", a[0], a[1])
        }
        IpAddr::V6(ip) => {
            let a = ip.segments();
            format!("{:x}:{:x}:*:*:*:*:*:*", a[0], a[1])
        }
    }
}

pub(super) struct Aliases {
    names: HashMap<String, String>,
}

impl Aliases {
    pub(super) fn from_proxies(proxies: &Value) -> Self {
        let mut names = HashMap::new();
        let mut keys = proxies
            .as_object()
            .map(|map| map.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        keys.sort();
        let (mut node, mut group) = (0, 0);
        for name in keys {
            if matches!(name.as_str(), "GLOBAL" | "DIRECT" | "REJECT") {
                names.insert(name.clone(), name);
                continue;
            }
            let is_group = proxies
                .get(&name)
                .and_then(|value| value.get("all"))
                .is_some_and(Value::is_array);
            let alias = if is_group {
                group += 1;
                format!("GROUP_{group}")
            } else {
                node += 1;
                format!("NODE_{node}")
            };
            names.insert(name, alias);
        }
        Self { names }
    }
    pub(super) fn get(&self, name: &str) -> String {
        self.names
            .get(name)
            .cloned()
            .unwrap_or_else(|| "UNKNOWN_NODE_OR_GROUP".to_owned())
    }
}

pub(super) async fn live_proxies() -> Result<Value, &'static str> {
    let value = Handle::mihomo().get_proxies().await.map_err(|_| "CORE_UNAVAILABLE")?;
    serde_json::to_value(value)
        .map_err(|_| "CORE_STATE_UNAVAILABLE")?
        .get("proxies")
        .cloned()
        .ok_or("CORE_STATE_UNAVAILABLE")
}

fn protocol(value: &str) -> &'static str {
    match value.to_ascii_lowercase().as_str() {
        "socks5" => "socks5",
        "http" => "http",
        "ss" | "shadowsocks" => "ss",
        "vmess" => "vmess",
        "vless" => "vless",
        "trojan" => "trojan",
        "hysteria2" => "hysteria2",
        "tuic" => "tuic",
        "direct" => "direct",
        "reject" => "reject",
        _ => "other_or_provider",
    }
}

fn safe_mode(value: &str) -> &'static str {
    match value {
        "global" => "global",
        "rule" => "rule",
        "direct" => "direct",
        _ => "unknown",
    }
}

pub(super) async fn status() -> Result<Value, &'static str> {
    let base = super::live_chain_settings().await.map_err(|_| "CORE_UNAVAILABLE")?;
    let proxies = live_proxies().await?;
    let aliases = Aliases::from_proxies(&proxies);
    let runtime = Config::runtime().await.data_arc();
    let config = runtime.config.as_ref();
    let boolean = |key: &str| {
        config
            .and_then(|value| value.get(key))
            .and_then(serde_yaml_ng::Value::as_bool)
    };
    let session = runtime.proxy_chain.as_ref();
    let chain = crate::cmd::proxy_chain::chain_state().await.ok();
    let mapping = |key: &str, child: &str| {
        config
            .and_then(|value| value.get(key))
            .and_then(|value| value.get(child))
            .and_then(serde_yaml_ng::Value::as_bool)
    };
    let tun_stack = config
        .and_then(|value| value.get("tun"))
        .and_then(|value| value.get("stack"))
        .and_then(serde_yaml_ng::Value::as_str);
    let stack = match tun_stack {
        Some("system") => "system",
        Some("gvisor") => "gvisor",
        Some("mixed") => "mixed",
        _ => "unknown",
    };
    Ok(
        json!({"format":"clash-diagnostic-status-v1", "appVersion":env!("CARGO_PKG_VERSION"),
        "observedAt":chrono::Utc::now().to_rfc3339(), "os":std::env::consts::OS, "architecture":std::env::consts::ARCH,
        "mode":safe_mode(&base.mode), "tunEnabled":base.tun_enabled, "mixedPort":base.mixed_port,
        "ipv6Configured":boolean("ipv6"), "dnsEnabledConfigured":mapping("dns", "enable"),
        "dnsIpv6Configured":mapping("dns", "ipv6"), "tunAutoRouteConfigured":mapping("tun", "auto-route"),
        "tunStrictRouteConfigured":mapping("tun", "strict-route"), "tunStackConfigured":stack,
        "configurationFlagsAreLiveReadback":false,
        "systemProxyRequested":Config::verge().await.data_arc().enable_system_proxy.unwrap_or(false),
        "systemProxyEffective":"NOT_VERIFIED", "serverSideUpstream":"NOT_OBSERVABLE_FROM_CLIENT",
        "binding":session.map(|session| json!({"group":aliases.get(&session.group),
            "nodes":session.nodes.iter().map(|name| aliases.get(name)).collect::<Vec<_>>(),
            "linksApplied":chain.as_ref().is_some_and(|state| state.links_applied),
            "selectionApplied":chain.as_ref().is_some_and(|state| state.selection_applied),
            "scopeActive":chain.as_ref().is_some_and(|state| state.scope_active)})) }),
    )
}

pub(super) async fn inventory() -> Result<Value, &'static str> {
    let proxies = live_proxies().await?;
    let aliases = Aliases::from_proxies(&proxies);
    let runtime = Config::runtime().await.data_arc();
    let definitions = runtime
        .config
        .as_ref()
        .and_then(|config| config.get("proxies"))
        .and_then(serde_yaml_ng::Value::as_sequence);
    let mut names = proxies
        .as_object()
        .map(|map| map.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    names.sort();
    let total = names.len();
    let entries = names.into_iter().take(500).map(|name| {
        let value = &proxies[&name];
        let definition = definitions.and_then(|items| items.iter().find(|item| item.get("name").and_then(serde_yaml_ng::Value::as_str) == Some(name.as_str())));
        let server = definition.and_then(|value| value.get("server")).and_then(serde_yaml_ng::Value::as_str);
        let address = server.and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok()).map(mask_ip);
        let all = value.get("all").and_then(Value::as_array);
        json!({"alias":aliases.get(&name), "protocol":protocol(value.get("type").and_then(Value::as_str).unwrap_or("")),
            "isGroup":all.is_some(), "address":address, "hostnameOrAddressUnavailable":server.is_none_or(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().is_err()),
            "port":definition.and_then(|value| value.get("port")).and_then(serde_yaml_ng::Value::as_u64).filter(|port| (1..=65535).contains(port)),
            "usernamePasswordConfigured":definition.is_some_and(|value| value.get("username").is_some() || value.get("password").is_some()),
            "selected":value.get("now").and_then(Value::as_str).map(|name| aliases.get(name)),
            "dialer":value.get("dialerProxy").or_else(|| value.get("dialer-proxy")).and_then(Value::as_str).filter(|name| !name.is_empty()).map(|name| aliases.get(name)),
            "members":all.map(|items| items.iter().filter_map(Value::as_str).take(100).map(|name| aliases.get(name)).collect::<Vec<_>>())})
    }).collect::<Vec<_>>();
    Ok(json!({"observedAt":chrono::Utc::now().to_rfc3339(), "entries":entries, "total":total, "truncated":total > 500}))
}

pub(super) async fn connections() -> Result<Value, &'static str> {
    let proxies = live_proxies().await?;
    let aliases = Aliases::from_proxies(&proxies);
    let value = Handle::mihomo()
        .get_connections()
        .await
        .map_err(|_| "CONNECTIONS_UNAVAILABLE")?;
    let value = serde_json::to_value(value).map_err(|_| "CONNECTIONS_UNAVAILABLE")?;
    Ok(connection_snapshot(&value, &aliases))
}

pub(super) async fn probe_connections() -> Value {
    let result = async {
        let proxies = live_proxies().await?;
        let aliases = Aliases::from_proxies(&proxies);
        let data = Handle::mihomo()
            .get_connections()
            .await
            .map_err(|_| "CONNECTIONS_UNAVAILABLE")?;
        let mut value = serde_json::to_value(data).map_err(|_| "CONNECTIONS_UNAVAILABLE")?;
        if let Some(rows) = value.get_mut("connections").and_then(Value::as_array_mut) {
            rows.retain(|row| {
                matches!(
                    row.pointer("/metadata/host").and_then(Value::as_str),
                    Some("api.ipify.org" | "api6.ipify.org" | "api64.ipify.org")
                )
            });
            rows.truncate(12);
        }
        Ok::<_, &'static str>(connection_snapshot(&value, &aliases))
    };
    match tokio::time::timeout(std::time::Duration::from_secs(2), result).await {
        Ok(Ok(value)) => value,
        _ => json!({"available":false,"code":"PROBE_CONNECTION_SAMPLE_UNAVAILABLE"}),
    }
}

fn connection_snapshot(value: &Value, aliases: &Aliases) -> Value {
    let mut hosts = HashMap::new();
    let empty = Vec::new();
    let rows = value.get("connections").and_then(Value::as_array).unwrap_or(&empty);
    let entries = rows.iter().rev().take(100).map(|row| {
        let meta = row.get("metadata").unwrap_or(&Value::Null);
        let host = meta.get("host").and_then(Value::as_str).unwrap_or("");
        let next = hosts.len() + 1;
        let host_alias = hosts.entry(host.to_owned()).or_insert_with(|| format!("HOST_{next}")).clone();
        let rule = match row.get("rule").and_then(Value::as_str).unwrap_or("") {
            "Match" => "MATCH", "Global" | "GLOBAL" => "GLOBAL", "Domain" => "DOMAIN", "DomainKeyword" => "DOMAIN_KEYWORD",
            "DomainSuffix" => "DOMAIN_SUFFIX", "IPCIDR" | "IPCIDR6" => "IP_CIDR", "GeoIP" => "GEO_IP", _ => "OTHER_RULE",
        };
        let network = match meta.get("network").and_then(Value::as_str).unwrap_or("") { "tcp" => "tcp", "udp" => "udp", _ => "other" };
        let kind = match meta.get("type").and_then(Value::as_str).unwrap_or("") {
            "Tun" | "TUN" => "TUN", "Socks5" => "SOCKS5", "HTTP" | "Http" | "HTTP Connect" => "HTTP", _ => "OTHER",
        };
        let started = row.get("start").and_then(Value::as_str).and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok()).map(|value| value.to_rfc3339());
        json!({"target":host_alias, "rule":rule, "network":network, "inbound":kind, "startedAt":started,
            "destinationMasked":meta.get("destinationIP").and_then(Value::as_str).and_then(|value| value.parse().ok()).map(mask_ip),
            "destinationPort":meta.get("destinationPort").and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok())).filter(|port| (1..=65535).contains(port)),
            "chain":row.get("chains").and_then(Value::as_array).map(|items| items.iter().filter_map(Value::as_str).take(16).map(|name| aliases.get(name)).collect::<Vec<_>>()),
            "hasResponseBytes":row.get("download").and_then(Value::as_u64).is_some_and(|value| value > 0)})
    }).collect::<Vec<_>>();
    json!({"observedAt":chrono::Utc::now().to_rfc3339(), "activeConnectionsOnly":true, "total":rows.len(), "entries":entries})
}

pub(super) async fn recent_errors() -> Result<Value, &'static str> {
    let proxies = live_proxies().await?;
    let aliases = Aliases::from_proxies(&proxies);
    let runtime = Config::runtime().await.data_arc();
    let targets = runtime
        .config
        .as_ref()
        .and_then(|config| config.get("proxies"))
        .and_then(serde_yaml_ng::Value::as_sequence)
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(|node| {
                    let name = node.get("name")?.as_str()?;
                    let server = node.get("server")?.as_str()?.trim_matches(['[', ']']);
                    (server.len() >= 3).then(|| (server.to_owned(), aliases.get(name)))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let logs = CoreManager::global()
        .get_clash_logs()
        .await
        .map_err(|_| "CORE_LOGS_UNAVAILABLE")?;
    let entries = logs
        .iter()
        .rev()
        .take(300)
        .filter_map(|line| classify_log(line, &proxies, &aliases, &targets))
        .take(60)
        .collect::<Vec<_>>();
    Ok(
        json!({"observedAt":chrono::Utc::now().to_rfc3339(), "originalLogTextIncluded":false,
        "originalLogTimesPreserved":false, "entries":entries}),
    )
}

fn classify_log(line: &str, proxies: &Value, aliases: &Aliases, targets: &[(String, String)]) -> Option<Value> {
    let lower = line.to_ascii_lowercase();
    let code = super::chain_diagnostics::classify(line);
    if code == "UNCLASSIFIED_CONNECTION_FAILURE" && !["error", "warn", "fail"].iter().any(|word| lower.contains(word)) {
        return None;
    }
    let mut matched = proxies
        .as_object()
        .map(|map| {
            map.keys()
                .filter(|name| !name.is_empty() && line.contains(name.as_str()))
                .map(|name| aliases.get(name))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    matched.sort();
    matched.truncate(8);
    let stage = if lower.contains("socks") && code == "AUTHENTICATION_FAILED" {
        "SOCKS5_AUTHENTICATION"
    } else if code == "DNS_FAILED" {
        "DNS"
    } else if lower.contains("tls") || lower.contains("ssl") {
        "TLS"
    } else if lower.contains("connect") || lower.contains("dial") {
        "CONNECT_OR_DIAL"
    } else {
        "UNDETERMINED"
    };
    let mut endpoints = targets
        .iter()
        .filter(|(host, _)| line.contains(host.as_str()))
        .map(|(_, alias)| alias.clone())
        .collect::<Vec<_>>();
    endpoints.sort();
    endpoints.dedup();
    endpoints.truncate(8);
    Some(json!({"code":code, "stage":stage, "mentionedNodes":matched, "mentionedEndpointNodes":endpoints}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_mcp_snapshots_do_not_return_raw_sensitive_fields() {
        let proxies = json!({"private-user-node":{"type":"Socks5"}, "secret-group":{"all":["private-user-node"]}});
        let aliases = Aliases::from_proxies(&proxies);
        let data = json!({"connections":[{"metadata":{"host":"private-site.invalid", "destinationIP":"203.0.113.81", "destinationPort":"443", "processPath":"/secret/user", "type":"Tun", "network":"tcp"}, "chains":["private-user-node","secret-group"], "rule":"Match", "rulePayload":"password=private-password", "download":1}]});
        let encoded = connection_snapshot(&data, &aliases).to_string();
        for secret in [
            "private-user-node",
            "secret-group",
            "private-site.invalid",
            "203.0.113.81",
            "/secret/user",
            "private-password",
        ] {
            assert!(!encoded.contains(secret));
        }
        assert!(encoded.contains("203.0.*.*"));
        let log = classify_log(
            "WARN dial private-user-node to private-site.invalid password=private-password timeout 203.0.113.81",
            &proxies,
            &aliases,
            &[("203.0.113.81".to_owned(), "NODE_1".to_owned())],
        )
        .unwrap()
        .to_string();
        assert!(log.contains("TIMEOUT"));
        for secret in [
            "private-user-node",
            "private-site.invalid",
            "private-password",
            "203.0.113.81",
        ] {
            assert!(!log.contains(secret));
        }
    }
}
