export interface ProxyChainState {
  group: string | null
  nodes: string[]
  selected: string | null
  mode: string
  tunEnabled: boolean | null
  mixedPort: number | null
  linksApplied: boolean
  selectionApplied: boolean
  scopeActive: boolean
  warnings: string[]
}

export interface ChainDiagnosticStep {
  hop: number | null
  stage: string
  status: 'pass' | 'fail' | 'skipped'
  code: string
  elapsedMs: number
}

export interface ChainDiagnosticReport {
  format: string
  appVersion: string
  generatedAt: string
  mode: string
  linksApplied: boolean
  selectionApplied: boolean
  scopeActive: boolean
  snapshotStable: boolean
  group: string
  selected: string
  tunEnabled: boolean | null
  systemProxyRequested: boolean
  systemProxyEffective: string
  nodes: Array<{
    alias: string
    address: string
    protocol: string
    port: number | null
    usernamePasswordConfigured: boolean
  }>
  steps: ChainDiagnosticStep[]
  egressMatches: boolean | null
  egressFamily: string | null
  serverSideUpstream: string
  observedRoutes: Array<{
    target: string
    rule: string
    chain: string[]
    includesExpectedExit: boolean
    hasResponseBytes: boolean
  }>
}
