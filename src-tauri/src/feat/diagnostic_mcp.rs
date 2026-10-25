use super::diagnostic_snapshot as snapshot;
use crate::cmd::{CmdResult, CommandFailure};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex, Semaphore, oneshot},
    task::JoinHandle,
};
use warp::{
    Filter as _,
    http::{HeaderMap, Method, Response, StatusCode},
};

const PROTOCOL: &str = "2025-06-18";
const LIFETIME: Duration = Duration::from_secs(7200);
static SERVER: LazyLock<Mutex<Option<Server>>> = LazyLock::new(|| Mutex::new(None));

struct Server {
    info: ConnectionInfo,
    gate: Arc<Gate>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

struct Gate {
    token: String,
    authority: String,
    peer: IpAddr,
    active: AtomicBool,
    busy: Semaphore,
    last_call: parking_lot::Mutex<Option<String>>,
    calls: std::sync::atomic::AtomicU64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInfo {
    enabled: bool,
    bind_ip: Option<String>,
    allowed_peer: Option<String>,
    endpoint: Option<String>,
    token: Option<String>,
    expires_at: Option<String>,
    last_tool: Option<String>,
    calls: u64,
}

impl ConnectionInfo {
    fn disabled() -> Self {
        Self {
            enabled: false,
            bind_ip: None,
            allowed_peer: None,
            endpoint: None,
            token: None,
            expires_at: None,
            last_tool: None,
            calls: 0,
        }
    }
}

fn private_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local(),
    }
}

fn fixed_error(code: &str) -> CommandFailure {
    CommandFailure::coded(code, code)
}

#[tauri::command]
pub async fn get_diagnostic_mcp() -> CmdResult<ConnectionInfo> {
    let server = SERVER.lock().await;
    Ok(server
        .as_ref()
        .filter(|server| server.gate.active.load(Ordering::Acquire))
        .map(|server| {
            let mut info = server.info.clone();
            info.last_tool = server.gate.last_call.lock().clone();
            info.calls = server.gate.calls.load(Ordering::Relaxed);
            info
        })
        .unwrap_or_else(ConnectionInfo::disabled))
}

#[tauri::command]
pub async fn start_diagnostic_mcp(bind_ip: String, allowed_peer: String, port: u16) -> CmdResult<ConnectionInfo> {
    let ip: IpAddr = bind_ip.parse().map_err(|_| fixed_error("MCP_INVALID_BIND_ADDRESS"))?;
    let peer: IpAddr = allowed_peer
        .parse()
        .map_err(|_| fixed_error("MCP_INVALID_PEER_ADDRESS"))?;
    if !private_address(ip) || !private_address(peer) || (ip.is_loopback() != peer.is_loopback()) {
        return Err(fixed_error("MCP_USE_LOOPBACK_OR_PRIVATE_HOST_ONLY_ADDRESSES"));
    }
    if port < 1024 {
        return Err(fixed_error("MCP_PORT_MUST_BE_1024_OR_HIGHER"));
    }
    let mut state = SERVER.lock().await;
    if state
        .as_ref()
        .is_some_and(|server| server.gate.active.load(Ordering::Acquire))
    {
        return Err(fixed_error("MCP_ALREADY_RUNNING"));
    }
    if let Some(old) = state.take() {
        old.task.abort();
        let _ = old.task.await;
    }
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(ip, port))
        .await
        .map_err(|_| fixed_error("MCP_BIND_FAILED"))?;
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| fixed_error("MCP_TOKEN_GENERATION_FAILED"))?;
    let token: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let authority = SocketAddr::new(ip, port).to_string();
    let gate = Arc::new(Gate {
        token: token.clone(),
        authority: authority.clone(),
        peer,
        active: AtomicBool::new(true),
        busy: Semaphore::new(1),
        last_call: parking_lot::Mutex::new(None),
        calls: std::sync::atomic::AtomicU64::new(0),
    });
    let info = ConnectionInfo {
        enabled: true,
        bind_ip: Some(ip.to_string()),
        allowed_peer: Some(peer.to_string()),
        endpoint: Some(format!("http://{authority}/mcp")),
        token: Some(token),
        expires_at: Some((chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339()),
        last_tool: None,
        calls: 0,
    };
    let (tx, rx) = oneshot::channel();
    let route = routes(Arc::clone(&gate));
    let active = Arc::clone(&gate);
    let task = tokio::spawn(async move {
        warp::serve(route)
            .incoming(listener)
            .graceful(async move {
                tokio::select! { _ = rx => {}, _ = tokio::time::sleep(LIFETIME) => {} }
                active.active.store(false, Ordering::Release);
            })
            .run()
            .await;
    });
    *state = Some(Server {
        info: info.clone(),
        gate,
        shutdown: Some(tx),
        task,
    });
    Ok(info)
}

#[tauri::command]
pub async fn stop_diagnostic_mcp() -> CmdResult<()> {
    if let Some(mut server) = SERVER.lock().await.take() {
        server.gate.active.store(false, Ordering::Release);
        if let Some(shutdown) = server.shutdown.take() {
            let _ = shutdown.send(());
        }
        server.task.abort();
        let _ = server.task.await;
    }
    Ok(())
}

fn routes(gate: Arc<Gate>) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let payload = warp::post()
        .and(warp::body::content_length_limit(16384))
        .and(warp::body::bytes())
        .map(|body| (Method::POST, body))
        .or(warp::get().map(|| (Method::GET, bytes::Bytes::new())))
        .unify();
    warp::path("mcp")
        .and(warp::path::end())
        .and(warp::header::headers_cloned())
        .and(warp::addr::remote())
        .and(payload)
        .and_then(
            move |headers: HeaderMap, peer: Option<SocketAddr>, (method, body): (Method, bytes::Bytes)| {
                let gate = Arc::clone(&gate);
                async move { Ok::<_, Infallible>(handle(method, headers, peer, &body, gate).await) }
            },
        )
}

fn equal_token(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right).fold(0u8, |sum, (a, b)| sum | (a ^ b)) == 0
}

fn authorized(headers: &HeaderMap, peer: Option<SocketAddr>, gate: &Gate) -> bool {
    if !gate.active.load(Ordering::Acquire)
        || peer.map(|peer| peer.ip()) != Some(gate.peer)
        || headers.contains_key("origin")
    {
        return false;
    }
    if headers.get("host").and_then(|value| value.to_str().ok()) != Some(gate.authority.as_str()) {
        return false;
    }
    let expected = format!("Bearer {}", gate.token);
    headers
        .get("authorization")
        .is_some_and(|value| equal_token(value.as_bytes(), expected.as_bytes()))
}

fn response(status: StatusCode, value: Option<Value>) -> Response<String> {
    let mut builder = Response::builder()
        .status(status)
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff");
    if value.is_some() {
        builder = builder.header("Content-Type", "application/json");
    }
    builder
        .body(value.map(|value| value.to_string()).unwrap_or_default())
        .unwrap_or_default()
}

fn rpc_error(id: Value, code: i32, message: &'static str) -> Value {
    json!({"jsonrpc":"2.0", "id":id, "error":{"code":code,"message":message}})
}
fn rpc_result(id: Value, value: Value) -> Value {
    json!({"jsonrpc":"2.0", "id":id, "result":value})
}

async fn handle(
    method: Method,
    headers: HeaderMap,
    peer: Option<SocketAddr>,
    body: &[u8],
    gate: Arc<Gate>,
) -> Response<String> {
    if !authorized(&headers, peer, &gate) {
        return response(StatusCode::UNAUTHORIZED, None);
    }
    if method != Method::POST {
        return response(StatusCode::METHOD_NOT_ALLOWED, None);
    }
    if headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| value.split(';').next().unwrap_or("").trim() != "application/json")
    {
        return response(StatusCode::UNSUPPORTED_MEDIA_TYPE, None);
    }
    if headers
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value != PROTOCOL)
    {
        return response(StatusCode::BAD_REQUEST, None);
    }
    let request: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => {
            return response(
                StatusCode::BAD_REQUEST,
                Some(rpc_error(Value::Null, -32700, "Invalid JSON")),
            );
        }
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return response(StatusCode::BAD_REQUEST, Some(rpc_error(id, -32600, "Invalid request")));
    };
    if !request.is_object()
        || request.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || (!id.is_null() && !id.is_string() && !id.is_number())
    {
        return response(
            StatusCode::BAD_REQUEST,
            Some(rpc_error(Value::Null, -32600, "Invalid request")),
        );
    }
    if id.is_null() {
        return response(
            if matches!(method, "notifications/initialized" | "notifications/cancelled") {
                StatusCode::ACCEPTED
            } else {
                StatusCode::BAD_REQUEST
            },
            None,
        );
    }
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    let result = match method {
        "initialize" => rpc_result(
            id,
            json!({"protocolVersion":PROTOCOL,"capabilities":{"tools":{"listChanged":false}},
            "serverInfo":{"name":"clash-verge-private-diagnostics","version":env!("CARGO_PKG_VERSION")},
            "instructions":"Read-only private diagnostics. Names are aliases. Raw credentials, configuration and logs are never returned. Exit equality alone does not prove every hop. Node aliases in chain_diagnostics are chain-order scoped; inventory aliases are snapshot scoped."}),
        ),
        "ping" => rpc_result(id, json!({})),
        "tools/list" => rpc_result(id, json!({"tools":tool_list()})),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            if !tool_names().contains(&name) {
                rpc_error(id, -32602, "Unknown diagnostic tool")
            } else if params
                .get("arguments")
                .is_some_and(|value| !value.as_object().is_some_and(|map| map.is_empty()))
            {
                rpc_error(id, -32602, "Diagnostic tools accept no arguments")
            } else {
                let Ok(_permit) = gate.busy.try_acquire() else {
                    return response(StatusCode::OK, Some(rpc_result(id, tool_error("DIAGNOSTIC_BUSY"))));
                };
                *gate.last_call.lock() = Some(name.to_owned());
                gate.calls.fetch_add(1, Ordering::Relaxed);
                let value = tokio::time::timeout(Duration::from_secs(110), run_tool(name))
                    .await
                    .unwrap_or(Err("DIAGNOSTIC_TIMEOUT"));
                if !gate.active.load(Ordering::Acquire) {
                    return response(StatusCode::SERVICE_UNAVAILABLE, None);
                }
                rpc_result(
                    id,
                    match value {
                        Ok(value) => json!({"content":[{"type":"text","text":value.to_string()}],"isError":false}),
                        Err(code) => tool_error(code),
                    },
                )
            }
        }
        _ => rpc_error(id, -32601, "Method not found"),
    };
    response(StatusCode::OK, Some(result))
}

fn tool_names() -> [&'static str; 7] {
    [
        "read_status",
        "read_nodes",
        "read_connections",
        "read_recent_errors",
        "diagnose_chain",
        "compare_exits",
        "collect_snapshot",
    ]
}
fn tool_list() -> Vec<Value> {
    let descriptions = [
        "Read live mode, TUN, listener and applied chain flags. Never verifies browser capture.",
        "Read proxy groups, selections, dialer links and masked node addresses. Node names are snapshot-scoped aliases.",
        "Read active request chains and response presence without domains, process paths or full IP addresses.",
        "Classify recent core errors locally; returns fixed codes and node aliases, never original log messages.",
        "Run bounded chain diagnostics with credentials local to Clash. Prefix health checks are not isolated per-hop capture. Aliases follow chain order.",
        "Compare direct VPS SOCKS5 and current local Clash exit over IPv4 and IPv6. Direct baseline is skipped when TUN is enabled or unknown. Queries fixed ipify endpoints only.",
        "Collect status, node inventory, active connections and classified errors. Does not query external websites.",
    ];
    tool_names().iter().zip(descriptions).map(|(name, description)| json!({"name":name,"description":description,
        "inputSchema":{"type":"object","properties":{},"additionalProperties":false},
        "annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":false,"openWorldHint":matches!(*name,"diagnose_chain" | "compare_exits")}})).collect()
}
fn tool_error(code: &'static str) -> Value {
    json!({"content":[{"type":"text","text":json!({"code":code}).to_string()}],"isError":true})
}
fn snapshot_result(value: Result<Value, &'static str>) -> Value {
    value.unwrap_or_else(|code| json!({"code":code,"available":false}))
}

async fn run_tool(name: &str) -> Result<Value, &'static str> {
    match name {
        "read_status" => snapshot::status().await,
        "read_nodes" => snapshot::inventory().await,
        "read_connections" => snapshot::connections().await,
        "read_recent_errors" => snapshot::recent_errors().await,
        "diagnose_chain" => crate::feat::diagnose_chain(None)
            .await
            .map(|report| json!({"nodeAliasesScope":"CHAIN_ORDER","report":report}))
            .map_err(|_| "CHAIN_DIAGNOSTIC_FAILED"),
        "compare_exits" => super::diagnostic_probes::compare_exits().await,
        "collect_snapshot" => {
            let (status, nodes, connections, errors) = tokio::join!(
                snapshot::status(),
                snapshot::inventory(),
                snapshot::connections(),
                snapshot::recent_errors()
            );
            Ok(
                json!({"format":"clash-diagnostic-snapshot-v1","observedAt":chrono::Utc::now().to_rfc3339(),"atomicSnapshot":false,
                "status":snapshot_result(status),"nodes":snapshot_result(nodes),"connections":snapshot_result(connections),"errors":snapshot_result(errors)}),
            )
        }
        _ => Err("UNKNOWN_TOOL"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn gate() -> Arc<Gate> {
        Arc::new(Gate {
            token: "TEST_SECRET_NOT_FOR_REPORTS".to_owned(),
            authority: "127.0.0.1:17998".to_owned(),
            peer: "127.0.0.1".parse().unwrap(),
            active: AtomicBool::new(true),
            busy: Semaphore::new(1),
            last_call: parking_lot::Mutex::new(None),
            calls: std::sync::atomic::AtomicU64::new(0),
        })
    }
    #[tokio::test]
    async fn diagnostic_mcp_transport_rejects_untrusted_clients_and_raw_commands() {
        let gate = gate();
        let peer = Some("127.0.0.1:10000".parse().unwrap());
        let mut headers = HeaderMap::new();
        headers.insert("host", "127.0.0.1:17998".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        let init = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#;
        assert_eq!(
            handle(Method::POST, headers.clone(), peer, init, gate.clone())
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        headers.insert("authorization", "Bearer TEST_SECRET_NOT_FOR_REPORTS".parse().unwrap());
        let response = handle(Method::POST, headers.clone(), peer, init, gate.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.body().contains("TEST_SECRET"));
        headers.insert("origin", "http://untrusted.invalid".parse().unwrap());
        assert!(!authorized(&headers, peer, &gate));
        headers.remove("origin");
        assert!(!authorized(&headers, Some("127.0.0.2:10000".parse().unwrap()), &gate));
        let request = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_shell","arguments":{"command":"SECRET_COMMAND"}}}"#;
        let response = handle(Method::POST, headers.clone(), peer, request, gate.clone()).await;
        assert!(response.body().contains("Unknown diagnostic tool"));
        assert!(!response.body().contains("SECRET_COMMAND"));
        gate.active.store(false, Ordering::Release);
        assert!(!authorized(&headers, peer, &gate));
    }
    #[test]
    fn diagnostic_mcp_requires_private_explicit_addresses() {
        assert!(!private_address("0.0.0.0".parse().unwrap()));
        assert!(!private_address("8.8.8.8".parse().unwrap()));
        assert!(private_address("192.168.56.101".parse().unwrap()));
        assert!(private_address("127.0.0.1".parse().unwrap()));
    }
}
