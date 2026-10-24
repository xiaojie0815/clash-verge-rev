use super::{CmdResult, CommandFailure};
use crate::{
    config::Config,
    core::{CoreManager, handle::Handle},
};
use serde::Serialize;
use std::time::Duration;

use crate::config::runtime::CHAIN_OPERATION;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyChainState {
    pub group: Option<String>,
    pub nodes: Vec<String>,
    pub selected: Option<String>,
    pub mode: String,
    pub tun_enabled: Option<bool>,
    pub mixed_port: Option<u16>,
    pub links_applied: bool,
    pub selection_applied: bool,
    pub scope_active: bool,
    pub warnings: Vec<String>,
}

pub(crate) async fn chain_state() -> CmdResult<ProxyChainState> {
    let session = Config::runtime().await.data_arc().proxy_chain.clone();
    let mihomo = Handle::mihomo();
    let (base, proxies) = tokio::try_join!(crate::feat::live_chain_settings(), async {
        mihomo
            .get_proxies()
            .await
            .map_err(|_| anyhow::anyhow!("CHAIN_CORE_UNAVAILABLE"))
    })
    .map_err(|_| CommandFailure::coded("CHAIN_CORE_UNAVAILABLE", "Cannot read live core state"))?;
    let mode = base.mode;
    let Some(session) = session else {
        return Ok(ProxyChainState {
            group: None,
            nodes: vec![],
            selected: None,
            mode,
            tun_enabled: base.tun_enabled,
            mixed_port: base.mixed_port,
            links_applied: false,
            selection_applied: false,
            scope_active: false,
            warnings: vec![],
        });
    };
    let selected = proxies.proxies.get(&session.group).and_then(|group| group.now.clone());
    let links_applied = session.nodes.iter().enumerate().all(|(index, name)| {
        if index == 0 {
            return proxies
                .proxies
                .get(name)
                .is_none_or(|proxy| proxy.dialer_proxy.is_empty());
        }
        proxies
            .proxies
            .get(name)
            .is_some_and(|proxy| proxy.dialer_proxy == session.nodes[index - 1])
    });
    let selection_applied = selected.as_ref() == session.nodes.last();
    let scope_active = (mode == "global" && session.group == "GLOBAL") || (mode == "rule" && session.group != "GLOBAL");
    Ok(ProxyChainState {
        group: Some(session.group),
        nodes: session.nodes,
        selected,
        mode,
        tun_enabled: base.tun_enabled,
        mixed_port: base.mixed_port,
        links_applied,
        selection_applied,
        scope_active,
        warnings: vec![],
    })
}

#[tauri::command]
pub async fn get_proxy_chain_state() -> CmdResult<ProxyChainState> {
    let _operation = CHAIN_OPERATION.lock().await;
    tokio::time::timeout(Duration::from_secs(10), chain_state())
        .await
        .map_err(|_| CommandFailure::coded("CHAIN_CORE_TIMEOUT", "Live core state timed out"))?
}

#[tauri::command]
pub async fn set_proxy_chain(group: Option<String>, nodes: Option<Vec<String>>) -> CmdResult<ProxyChainState> {
    let _operation = CHAIN_OPERATION.lock().await;
    let previous = Config::runtime().await.data_arc().proxy_chain.clone();
    if nodes.is_none() && previous.is_none() {
        return chain_state().await;
    }
    let live_mode = crate::feat::live_chain_settings()
        .await
        .map_err(|_| CommandFailure::coded("CHAIN_CORE_UNAVAILABLE", "Cannot read live mode"))?
        .mode;
    let mut warnings = vec![];
    let previous_selection = if let Some(nodes) = nodes.as_ref() {
        if !(2..=8).contains(&nodes.len()) {
            return Err(CommandFailure::coded(
                "CHAIN_INVALID_ORDER",
                "A chain requires two to eight distinct nodes",
            ));
        }
        let group = group
            .as_ref()
            .ok_or_else(|| CommandFailure::coded("CHAIN_GROUP_REQUIRED", "Select a target group"))?;
        let mihomo = Handle::mihomo();
        if (group == "GLOBAL" && live_mode != "global") || (group != "GLOBAL" && live_mode != "rule") {
            return Err(CommandFailure::coded(
                "CHAIN_MODE_MISMATCH",
                "The live core mode does not match the requested chain scope",
            ));
        }
        let proxies = mihomo
            .get_proxies()
            .await
            .map_err(|_| CommandFailure::coded("CHAIN_CORE_UNAVAILABLE", "Cannot read live groups"))?;
        let target = proxies
            .proxies
            .get(group)
            .ok_or_else(|| CommandFailure::coded("CHAIN_GROUP_MISSING", "The target group no longer exists"))?;
        let exit = nodes
            .last()
            .ok_or_else(|| CommandFailure::coded("CHAIN_INVALID_ORDER", "Select at least two nodes"))?;
        if !target.all.as_ref().is_some_and(|members| members.contains(exit)) {
            return Err(CommandFailure::coded(
                "CHAIN_EXIT_NOT_IN_GROUP",
                "The selected group does not contain the exit node",
            ));
        }
        let view = super::proxy::proxy_view(Some(Duration::from_secs(3))).await?;
        for name in nodes {
            if view.records.values().filter(|node| node.name == *name).count() != 1 {
                return Err(CommandFailure::coded(
                    "CHAIN_AMBIGUOUS_NODE",
                    "A chain node is missing or has duplicate names",
                ));
            }
        }
        if let Some(entry) = nodes.first()
            && proxies
                .proxies
                .get(entry)
                .is_none_or(|proxy| !proxy.provider_name.is_empty())
        {
            let providers = mihomo
                .get_proxy_providers()
                .await
                .map_err(|_| CommandFailure::coded("CHAIN_PROVIDER_UNAVAILABLE", "Cannot verify the provider entry"))?;
            if providers
                .providers
                .values()
                .flat_map(|provider| provider.proxies.iter())
                .any(|proxy| proxy.name == *entry && !proxy.dialer_proxy.is_empty())
            {
                return Err(CommandFailure::coded(
                    "CHAIN_PROVIDER_ENTRY_HAS_DIALER",
                    "The provider entry already has a dialer; select an entry without an existing chain",
                ));
            }
        }
        if previous.as_ref().is_some_and(|session| session.group == *group) {
            previous.as_ref().and_then(|session| session.previous_selection.clone())
        } else {
            target.now.clone()
        }
    } else {
        None
    };

    let mut candidate = (*Config::runtime().await.data_arc()).clone();
    candidate
        .set_proxy_chain(group.clone(), nodes.clone(), previous_selection.clone(), &live_mode)
        .map_err(|error| {
            CommandFailure::coded(
                &error.to_string(),
                "The requested chain order or node configuration is not supported",
            )
        })?;

    if let Some(session) = previous.as_ref()
        && group.as_ref() != Some(&session.group)
        && let Some(selection) = session.previous_selection.as_ref()
    {
        Handle::mihomo()
            .select_node_for_group(&session.group, selection)
            .await
            .map_err(|_| {
                CommandFailure::coded(
                    "CHAIN_RESTORE_SELECTION_FAILED",
                    "Cannot restore the previous group selection; chain retained",
                )
            })?;
        if crate::config::profiles::record_selected_node(&session.group, selection)
            .await
            .is_err()
        {
            warnings.push("CHAIN_SELECTION_NOT_PERSISTED".to_owned());
        }
    }

    let requested_group = group.clone();
    let requested_nodes = nodes.clone();
    let outcome = CoreManager::global()
        .update_runtime_config(move |runtime| runtime.set_proxy_chain(group, nodes, previous_selection, &live_mode))
        .await
        .map_err(|_| CommandFailure::coded("CHAIN_APPLY_FAILED", "The core could not apply the chain configuration"))?;
    if !outcome.is_valid() {
        return Err(CommandFailure::coded(
            "CHAIN_APPLY_REJECTED",
            "Configuration validation failed or another update is in progress",
        ));
    }
    if let (Some(group), Some(exit)) = (
        requested_group.as_ref(),
        requested_nodes.as_ref().and_then(|nodes| nodes.last()),
    ) {
        Handle::mihomo().select_node_for_group(group, exit).await.map_err(|_| {
            CommandFailure::coded(
                "CHAIN_SELECTION_FAILED",
                "Links applied, but selecting the exit failed; check live state",
            )
        })?;
        if crate::config::profiles::record_selected_node(group, exit)
            .await
            .is_err()
        {
            warnings.push("CHAIN_SELECTION_NOT_PERSISTED".to_owned());
        }
    }
    if Handle::mihomo().close_all_connections().await.is_err() {
        warnings.push("CHAIN_OLD_CONNECTIONS_REMAIN".to_owned());
    }
    let mut state = chain_state().await?;
    if requested_nodes.is_some() && (!state.links_applied || !state.selection_applied || !state.scope_active) {
        return Err(CommandFailure::coded(
            "CHAIN_READBACK_MISMATCH",
            "Core readback does not match the requested links and exit",
        ));
    }
    state.warnings = warnings;
    crate::core::notify::announce(crate::core::notify::Refresh::Proxies);
    Handle::refresh_clash();
    Ok(state)
}

#[tauri::command]
pub async fn diagnose_proxy_chain(expected_egress: Option<String>) -> CmdResult<crate::feat::ChainDiagnosticReport> {
    crate::feat::diagnose_chain(expected_egress).await
}
