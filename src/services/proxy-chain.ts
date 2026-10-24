import { writeText } from '@tauri-apps/plugin-clipboard-manager'
import { save } from '@tauri-apps/plugin-dialog'
import { writeFile } from '@tauri-apps/plugin-fs'

import { diagnoseProxyChain, setProxyChain } from '@/services/cmds'
import { mutate } from '@/services/mutate'
import type { ChainDiagnosticReport } from '@/types/proxy-chain'

export const applyProxyChain = (group: string | null, nodes: string[] | null) =>
  mutate(() => setProxyChain(group, nodes), {
    id: 'proxy-chain-operation',
    revalidate: [['getRuntimeConfig'], ['getProxyChainState']],
    errorNotice: false,
  })

export const runChainDiagnostics = (expectedEgress: string) =>
  mutate(() => diagnoseProxyChain(expectedEgress.trim() || null), {
    id: 'proxy-chain-operation',
    errorNotice: false,
  })

const stages = new Set([
  'EGRESS_QUERY',
  'CONFIGURATION',
  'NODE_DNS',
  'DIRECT_NODE_TCP',
  'DIRECT_SOCKS5_NEGOTIATION',
  'DIRECT_SOCKS5_AUTHENTICATION',
  'DIRECT_SOCKS5_TARGET_CONNECT',
  'DIRECT_TARGET_TLS',
  'DIRECT_TARGET_HTTP',
  'CHAIN_PREFIX_ACCESS',
  'LOCAL_PROXY_TARGET_HTTP',
  'EGRESS_VERIFICATION',
])
const codes = new Set([
  'DIRECT_ROUTE_NOT_VERIFIED_WITH_TUN',
  'EGRESS_RESPONSE_RECEIVED',
  'CHAIN_CORE_UNAVAILABLE',
  'SOCKS_RULE_DENIED',
  'SOCKS_NETWORK_UNREACHABLE',
  'SOCKS_HOST_UNREACHABLE',
  'SOCKS_TARGET_REFUSED',
  'LIVE_STATE_CONFIRMED',
  'CHAIN_NOT_ACTIVE_IN_CURRENT_SCOPE',
  'NODE_CONFIG_UNAVAILABLE',
  'DIRECT_TLS_PROXY_NOT_TESTED',
  'DNS_FAILED',
  'CONNECTION_FAILED',
  'CONNECTION_REFUSED',
  'PEER_CLOSED',
  'TIMEOUT',
  'AUTH_CONFIG_INVALID',
  'AUTH_METHOD_REJECTED',
  'AUTHENTICATION_FAILED',
  'SOCKS_TARGET_CONNECT_REJECTED',
  'SOCKS_INVALID_RESPONSE',
  'TLS_NAME_INVALID',
  'TLS_FAILED',
  'TLS_CERTIFICATE_FAILED',
  'HTTP_INVALID_RESPONSE',
  'HTTP_TARGET_REJECTED',
  'HTTPS_RESPONSE_RECEIVED',
  'CORE_HTTPS_PROBE_PASSED',
  'UNCLASSIFIED_CONNECTION_FAILURE',
  'DIAGNOSTIC_BUDGET_EXHAUSTED',
  'LOCAL_PROXY_CONFIG_FAILED',
  'EGRESS_SERVICE_REJECTED',
  'EGRESS_RESPONSE_FAILED',
  'EGRESS_RESPONSE_INVALID',
  'EXPECTED_EXIT_MATCHED',
  'EXPECTED_EXIT_MISMATCH',
  'EXIT_NOT_VERIFIED',
])
const protocols = new Set([
  'socks5',
  'http',
  'ss',
  'vless',
  'vmess',
  'trojan',
  'hysteria2',
])
const alias = (value: string) =>
  /^(NODE_[1-8]|GLOBAL|DIRECT|REJECT|OTHER_NODE_OR_GROUP|NONE)$/.test(value)
    ? value
    : 'OTHER_NODE_OR_GROUP'

const maskedAddress = (value: string, index: number) => {
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.\*\.\*$/.exec(value)
  if (ipv4 && Number(ipv4[1]) <= 255 && Number(ipv4[2]) <= 255) return value
  if (/^[\da-f]{1,4}:[\da-f]{1,4}(?::\*){6}$/i.test(value)) return value
  return `HOST_NODE_${index + 1}`
}

// Export is an allowlist: new native fields cannot silently become shareable data.
export const privateChainReport = (report: ChainDiagnosticReport) => ({
  format: 'clash-verge-chain-private-report-v1',
  appVersion: /^\d+\.\d+\.\d+$/.test(report.appVersion)
    ? report.appVersion
    : 'unknown',
  generatedAt: Number.isFinite(Date.parse(report.generatedAt))
    ? new Date(report.generatedAt).toISOString()
    : null,
  mode: ['global', 'rule', 'direct'].includes(report.mode)
    ? report.mode
    : 'unknown',
  linksApplied: report.linksApplied === true,
  selectionApplied: report.selectionApplied === true,
  scopeActive: report.scopeActive === true,
  snapshotStable: report.snapshotStable === true,
  group: ['GLOBAL', 'GROUP_1', 'UNBOUND'].includes(report.group)
    ? report.group
    : 'UNBOUND',
  selected: alias(report.selected),
  tunEnabled: typeof report.tunEnabled === 'boolean' ? report.tunEnabled : null,
  systemProxyRequested: report.systemProxyRequested === true,
  systemProxyEffective: 'NOT_VERIFIED',
  nodes: report.nodes.slice(0, 8).map((node, index) => ({
    alias: `NODE_${index + 1}`,
    address: maskedAddress(node.address, index),
    protocol: protocols.has(node.protocol)
      ? node.protocol
      : 'other_or_provider',
    port:
      Number.isInteger(node.port) && node.port! >= 1 && node.port! <= 65535
        ? node.port
        : null,
    usernamePasswordConfigured: node.usernamePasswordConfigured === true,
  })),
  steps: report.steps.slice(0, 30).map((item) => ({
    hop:
      Number.isInteger(item.hop) && item.hop! >= 1 && item.hop! <= 8
        ? item.hop
        : null,
    stage: stages.has(item.stage) ? item.stage : 'UNKNOWN_STAGE',
    status: ['pass', 'fail', 'skipped'].includes(item.status)
      ? item.status
      : 'skipped',
    code: codes.has(item.code) ? item.code : 'UNCLASSIFIED_CONNECTION_FAILURE',
    elapsedMs: Number.isFinite(item.elapsedMs)
      ? Math.max(0, Math.min(120000, Math.round(item.elapsedMs)))
      : 0,
  })),
  egressMatches:
    typeof report.egressMatches === 'boolean' ? report.egressMatches : null,
  egressFamily: ['IPv4', 'IPv6'].includes(report.egressFamily ?? '')
    ? report.egressFamily
    : null,
  serverSideUpstream: 'NOT_OBSERVABLE_FROM_CLIENT',
  observedRoutes: report.observedRoutes.slice(0, 20).map((route) => ({
    target: /^HOST_\d{1,2}$/.test(route.target) ? route.target : 'HOST_UNKNOWN',
    rule: [
      'MATCH',
      'GLOBAL',
      'DOMAIN',
      'DOMAIN_KEYWORD',
      'DOMAIN_SUFFIX',
      'IP_CIDR',
      'GEO_IP',
    ].includes(route.rule)
      ? route.rule
      : 'OTHER_RULE',
    chain: route.chain.slice(0, 16).map(alias),
    includesExpectedExit: route.includesExpectedExit === true,
    hasResponseBytes: route.hasResponseBytes === true,
  })),
})

export const chainReportText = (report: ChainDiagnosticReport) =>
  JSON.stringify(privateChainReport(report), null, 2)

export const copyChainReport = (report: ChainDiagnosticReport) =>
  mutate(() => writeText(chainReportText(report)), {
    id: 'copy-proxy-chain-report',
    errorNotice: false,
  })

export const exportChainReport = async (report: ChainDiagnosticReport) => {
  const path = await save({
    defaultPath: `clash-chain-report-${Date.now()}.json`,
    filters: [{ name: 'JSON', extensions: ['json'] }],
  })
  if (!path) return
  await mutate(
    () => writeFile(path, new TextEncoder().encode(chainReportText(report))),
    {
      id: 'export-proxy-chain-report',
      errorNotice: false,
    },
  )
}
