# Private diagnostic MCP

This fork includes an opt-in, read-only Streamable HTTP MCP endpoint inside the
desktop process. Open Settings, Advanced, Private diagnostics (MCP). The proxy
chain page retains configuration controls; its diagnostic/report section has
been removed. Existing native probes are reused by MCP.

The service is disabled on startup. Enable it locally, choosing an explicit
loopback or private interface and one allowed client IP. For a Windows host and
Kali guest, use an isolated host-only network. Do not bind it to a public or
shared untrusted network. The current HTTP transport does not encrypt traffic.
Public and wildcard bind addresses are rejected. Requests also require a fresh
256-bit bearer key, an exact Host header, the allowed peer address, and no Origin
header. Browser requests are not supported. The key is revoked on disable; the
service expires after two hours and does not restart automatically.

The access key is separate from proxy credentials and the Mihomo controller
secret. The settings dialog displays it locally. The MCP tools cannot retrieve
it. Never send it in chat or include it in a diagnostic report.

## Tools

All tool arguments must be empty objects. No raw URL, node name, command,
filesystem path, configuration patch, or proxy credentials can be passed.

| Tool | Output / behavior |
| --- | --- |
| `collect_snapshot` | Status, node inventory, active requests and classified errors; no public website query |
| `read_status` | Live mode, TUN, mixed port, applied chain flags; saved DNS/routing flags are explicitly identified |
| `read_nodes` | Group selections, dialer relationships, protocol and masked endpoint information |
| `read_connections` | Active chains, rule category and response presence; no process paths or original domains |
| `read_recent_errors` | Fixed error codes plus aliases of nodes/endpoints mentioned in local core logs |
| `diagnose_chain` | Existing bounded chain checks; node aliases here follow chain order |
| `compare_exits` | Same-provider IPv4, IPv6 and automatic exit comparison for direct VPS SOCKS5 and local Clash |

Only one diagnostic tool runs at a time. Network operations have bounded
timeouts. Exit probes contact only `api.ipify.org`, `api6.ipify.org` and
`api64.ipify.org`, verify TLS certificates, do not follow redirects, and never
fall back to a direct website connection. The direct VPS baseline is skipped
if TUN is on or its state is unknown. This is not proof that other system-level
transparent interception has been disabled.

Full exit IPs are compared only in memory; output contains masked IPs and an
equality flag. Request samples are collected while exit probes are pending,
filtered to fixed query hosts. A sample may include another concurrent request
to the same service and therefore is not asserted to identify the probe uniquely.

## Privacy boundary and interpretation

Output is constructed from an allowlist; original configuration and log objects
are never forwarded. Names and domains are replaced by aliases. IPv4 keeps the
first two octets; IPv6 keeps the first two groups. Passwords, usernames, UUIDs,
subscription URLs, controller secrets, cookies, process paths and original log
text are omitted. Unknown errors produce a fixed code rather than raw error text.

Inventory aliases are scoped to the current core inventory snapshot. Chain
diagnostic aliases follow chain order and must not be confused with inventory
aliases. Timestamped outputs are observations, not an atomic system snapshot.

A health-check response with zero delay is failure, even if the plugin returns
`Ok`. A positive prefix health check is not packet capture of an isolated hop.
Matching exit IPs do not prove all intermediate hops. Browser proxy capture and
the GOST server's internal upstream configuration are not observable from this
client and are never marked verified.

## Connect the Windows client

Copy the configuration from the settings dialog. It uses:

```toml
[mcp_servers.clash_diagnostics]
url = "http://192.168.56.101:17998/mcp"
bearer_token_env_var = "CLASH_DIAGNOSTIC_TOKEN"
tool_timeout_sec = 120
```

The address above is an example. Use the endpoint shown in Kali. Configure the
session key in the Windows client's local `CLASH_DIAGNOSTIC_TOKEN` environment,
then add/restart the MCP connection in the host client. Enabling the desktop
service does not automatically register a tool in an existing conversation.

References: [MCP transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports),
[Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp).
