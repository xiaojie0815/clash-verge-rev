use serde_yaml_ng::{Mapping, Value};
use smartstring::alias::String;
use std::collections::{HashMap, HashSet};

use crate::enhance::field::use_keys;

const PATCH_CONFIG_INNER: [&str; 5] = ["allow-lan", "ipv6", "log-level", "unified-delay", "tunnels"];
pub(crate) static CHAIN_OPERATION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyChainSession {
    pub group: std::string::String,
    pub nodes: Vec<std::string::String>,
    pub previous_selection: Option<std::string::String>,
    #[serde(skip)]
    original_dialers: HashMap<std::string::String, Option<Value>>,
    #[serde(skip)]
    owned_dialers: HashMap<std::string::String, Option<Value>>,
}

#[cfg(test)]
mod chain_tests {
    use super::*;

    fn runtime() -> IRuntime {
        let config = serde_yaml_ng::from_str("mode: global\nproxies:\n  - {name: entry, type: vless}\n  - {name: exit, type: socks5, dialer-proxy: original}\n  - {name: unrelated, type: socks5, dialer-proxy: keep}\n").unwrap();
        IRuntime {
            config: Some(config),
            ..IRuntime::default()
        }
    }

    #[test]
    fn chain_disconnect_restores_only_owned_links() {
        let mut runtime = runtime();
        let original = runtime.config.clone();
        runtime
            .set_proxy_chain(
                Some("GLOBAL".to_owned()),
                Some(vec!["entry".to_owned(), "exit".to_owned()]),
                Some("entry".to_owned()),
                "global",
            )
            .unwrap();
        let proxies = runtime
            .config
            .as_ref()
            .unwrap()
            .get("proxies")
            .unwrap()
            .as_sequence()
            .unwrap();
        assert_eq!(proxies[1].get("dialer-proxy").and_then(Value::as_str), Some("entry"));
        assert_eq!(proxies[2].get("dialer-proxy").and_then(Value::as_str), Some("keep"));
        runtime.set_proxy_chain(None, None, None, "global").unwrap();
        assert_eq!(runtime.config, original);
        assert!(runtime.proxy_chain.is_none());
    }

    #[test]
    fn invalid_order_does_not_commit_a_partial_chain() {
        let mut runtime = runtime();
        let original = runtime.config.clone();
        assert!(
            runtime
                .set_proxy_chain(
                    Some("GLOBAL".to_owned()),
                    Some(vec!["entry".to_owned(), "entry".to_owned()]),
                    None,
                    "global"
                )
                .is_err()
        );
        assert_eq!(runtime.config, original);
        assert!(runtime.proxy_chain.is_none());
    }

    #[test]
    fn chain_reload_preserves_live_mode_instead_of_reapplying_the_stale_snapshot_mode() {
        let mut runtime = runtime();
        runtime.config.as_mut().unwrap().insert("mode".into(), "rule".into());
        runtime
            .set_proxy_chain(
                Some("GLOBAL".to_owned()),
                Some(vec!["entry".to_owned(), "exit".to_owned()]),
                None,
                "global",
            )
            .unwrap();
        assert_eq!(
            runtime.config.as_ref().unwrap().get("mode").and_then(Value::as_str),
            Some("global")
        );
        runtime.set_proxy_chain(None, None, None, "rule").unwrap();
        assert_eq!(
            runtime.config.as_ref().unwrap().get("mode").and_then(Value::as_str),
            Some("rule")
        );
    }
}

#[derive(Default, Clone)]
pub struct IRuntime {
    pub config: Option<Mapping>,
    pub proxy_chain: Option<ProxyChainSession>,
    pub(crate) dns_override: Option<super::dns::DnsOverrideState>,
    // Keys seen in the profile pipeline, including merge and script output.
    pub exists_keys: HashSet<String>,
    // TODO 或许可以用 FixMap 来存储以提升效率
    pub chain_logs: HashMap<String, Vec<(String, String)>>,
}

impl IRuntime {
    #[inline]
    pub fn patch_config(&mut self, patch: &Mapping) {
        let config = if let Some(config) = self.config.as_mut() {
            config
        } else {
            return;
        };

        for key in PATCH_CONFIG_INNER.iter() {
            if let Some(value) = patch.get(key) {
                config.insert((*key).into(), value.clone());
            }
        }

        let Some(patch_tun) = patch.get("tun") else {
            return;
        };

        let tun_key = Value::from("tun");
        if !matches!(config.get(&tun_key), Some(Value::Mapping(_))) {
            config.insert(tun_key.clone(), Value::Mapping(Mapping::new()));
        }

        if let (Some(patch_tun_mapping), Some(Value::Mapping(tun))) = (patch_tun.as_mapping(), config.get_mut(&tun_key))
        {
            for key in use_keys(patch_tun_mapping) {
                if let Some(value) = patch_tun_mapping.get(key.as_str()) {
                    tun.insert(Value::from(key.as_str()), value.clone());
                }
            }
        }
    }

    pub fn set_proxy_chain(
        &mut self,
        group: Option<std::string::String>,
        nodes: Option<Vec<std::string::String>>,
        previous_selection: Option<std::string::String>,
        mode: &str,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(matches!(mode, "global" | "rule" | "direct"), "CHAIN_MODE_INVALID");
        let mut candidate = self.clone();
        let config = candidate
            .config
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("CHAIN_RUNTIME_UNAVAILABLE"))?;
        // Mode PATCH does not regenerate this snapshot; reloading it must retain the live mode.
        config.insert("mode".into(), mode.into());
        let proxies = config
            .get_mut("proxies")
            .and_then(Value::as_sequence_mut)
            .ok_or_else(|| anyhow::anyhow!("CHAIN_PROXIES_UNAVAILABLE"))?;

        if let Some(session) = candidate.proxy_chain.take() {
            for proxy in proxies.iter_mut().filter_map(Value::as_mapping_mut) {
                let Some(name) = proxy.get("name").and_then(Value::as_str) else {
                    continue;
                };
                let Some(original) = session.original_dialers.get(name) else {
                    continue;
                };
                // An independently edited link no longer belongs to this session.
                if proxy.get("dialer-proxy") != session.owned_dialers.get(name).and_then(Option::as_ref) {
                    continue;
                }
                match original {
                    Some(value) => {
                        proxy.insert("dialer-proxy".into(), value.clone());
                    }
                    None => {
                        proxy.remove("dialer-proxy");
                    }
                }
            }
        }

        if let Some(nodes) = nodes {
            let group = group.ok_or_else(|| anyhow::anyhow!("CHAIN_GROUP_REQUIRED"))?;
            let unique: HashSet<_> = nodes.iter().collect();
            anyhow::ensure!(
                (2..=8).contains(&nodes.len()) && unique.len() == nodes.len(),
                "CHAIN_INVALID_ORDER"
            );
            anyhow::ensure!(
                !nodes
                    .iter()
                    .any(|name| name == &group || matches!(name.as_str(), "DIRECT" | "REJECT" | "GLOBAL")),
                "CHAIN_CYCLE"
            );
            let mut original_dialers = HashMap::new();
            let mut owned_dialers = HashMap::new();
            for (index, name) in nodes.iter().enumerate() {
                let matches = proxies
                    .iter()
                    .filter(|proxy| proxy.get("name").and_then(Value::as_str) == Some(name.as_str()))
                    .count();
                anyhow::ensure!(matches <= 1, "CHAIN_AMBIGUOUS_NODE");
                if matches == 0 {
                    anyhow::ensure!(index == 0, "CHAIN_PROVIDER_EXIT_UNSUPPORTED");
                    continue;
                }
                let proxy = proxies
                    .iter_mut()
                    .find(|proxy| proxy.get("name").and_then(Value::as_str) == Some(name.as_str()))
                    .and_then(Value::as_mapping_mut)
                    .ok_or_else(|| anyhow::anyhow!("CHAIN_NODE_UNAVAILABLE"))?;
                original_dialers.insert(name.clone(), proxy.get("dialer-proxy").cloned());
                let owned = index
                    .checked_sub(1)
                    .map(|previous| Value::from(nodes[previous].as_str()));
                match &owned {
                    Some(value) => {
                        proxy.insert("dialer-proxy".into(), value.clone());
                    }
                    None => {
                        proxy.remove("dialer-proxy");
                    }
                }
                owned_dialers.insert(name.clone(), owned);
            }
            candidate.proxy_chain = Some(ProxyChainSession {
                group,
                nodes,
                previous_selection,
                original_dialers,
                owned_dialers,
            });
        }
        *self = candidate;
        Ok(())
    }
}
