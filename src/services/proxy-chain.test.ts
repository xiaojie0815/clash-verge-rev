import { describe, expect, it } from 'vitest'

import type { ChainDiagnosticReport } from '@/types/proxy-chain'

import { chainReportText } from './proxy-chain'

const report = (): ChainDiagnosticReport => ({
  format: 'clash-verge-chain-private-report-v1',
  appVersion: '2.5.8',
  generatedAt: '2026-10-25T00:00:00Z',
  mode: 'global',
  group: 'GLOBAL',
  selected: 'NODE_2',
  linksApplied: true,
  selectionApplied: true,
  scopeActive: true,
  snapshotStable: true,
  tunEnabled: false,
  systemProxyRequested: true,
  systemProxyEffective: 'NOT_VERIFIED',
  nodes: [
    {
      alias: 'NODE_1',
      address: '203.0.*.*',
      protocol: 'vless',
      port: 443,
      usernamePasswordConfigured: false,
    },
    {
      alias: 'NODE_2',
      address: '2001:db8:*:*:*:*:*:*',
      protocol: 'socks5',
      port: 1080,
      usernamePasswordConfigured: true,
    },
  ],
  steps: [
    {
      hop: 2,
      stage: 'DIRECT_SOCKS5_AUTHENTICATION',
      status: 'fail',
      code: 'AUTHENTICATION_FAILED',
      elapsedMs: 9,
    },
  ],
  egressMatches: null,
  egressFamily: null,
  serverSideUpstream: 'NOT_OBSERVABLE_FROM_CLIENT',
  observedRoutes: [
    {
      target: 'HOST_1',
      rule: 'GLOBAL',
      chain: ['NODE_2', 'GLOBAL'],
      includesExpectedExit: true,
      hasResponseBytes: true,
    },
  ],
})

describe('shareable chain report', () => {
  it('keeps stale diagnostics distinct from configuration still applied', () => {
    const value = report()
    value.snapshotStable = false
    const exported = JSON.parse(chainReportText(value))
    expect(exported.snapshotStable).toBe(false)
    expect(exported.linksApplied).toBe(true)
    expect(exported.egressMatches).toBe(null)
  })

  it('rejects sensitive text injected into labels and unknown diagnostic stages', () => {
    const value = report()
    const secret = 'private-user@203.0.113.23'
    value.nodes[0].protocol = secret
    value.group = secret
    value.steps[0].stage = secret
    value.observedRoutes[0].target = secret
    value.observedRoutes[0].rule = secret
    expect(chainReportText(value)).not.toContain(secret)
    expect(JSON.parse(chainReportText(value)).steps[0].stage).toBe(
      'UNKNOWN_STAGE',
    )
  })
  it('exports only allowed fields and removes injected credentials, raw logs and subscription URLs', () => {
    const value = report()
    Object.assign(value, {
      username: 'private-user',
      password: 'private-password',
      logs: ['raw-sensitive-log'],
      subscription: 'https://secret.invalid/?token=private-token',
    })
    Object.assign(value.nodes[1], {
      username: 'private-user',
      password: 'private-password',
    })
    const exported = chainReportText(value)
    for (const secret of [
      'private-user',
      'private-password',
      'raw-sensitive-log',
      'secret.invalid',
      'private-token',
    ]) {
      expect(exported).not.toContain(secret)
    }
    expect(JSON.parse(exported).steps[0].code).toBe('AUTHENTICATION_FAILED')
  })

  it('keeps masked IPv4 and IPv6, but rejects complete addresses and untrusted node names', () => {
    const value = report()
    expect(chainReportText(value)).toContain('203.0.*.*')
    expect(chainReportText(value)).toContain('2001:db8:*:*:*:*:*:*')
    value.nodes[0].address = '203.0.113.23'
    value.nodes[1].address = '2001:db8::23'
    value.selected = 'private-node-203.0.113.23'
    value.observedRoutes[0].chain.push('private-node-203.0.113.23')
    const exported = chainReportText(value)
    expect(exported).not.toContain('203.0.113.23')
    expect(exported).not.toContain('2001:db8::23')
    expect(exported).not.toContain('private-node')
  })

  it('does not export raw failure text or infer a browser or upstream verification', () => {
    const value = report()
    value.steps[0].code =
      'authentication failed for private-user at 203.0.113.23'
    value.systemProxyEffective = 'browser traffic verified'
    value.serverSideUpstream = 'upstream.example.invalid:443'
    const exported = chainReportText(value)
    expect(exported).not.toContain('private-user')
    expect(exported).not.toContain('203.0.113.23')
    expect(exported).not.toContain('upstream.example.invalid')
    expect(JSON.parse(exported).systemProxyEffective).toBe('NOT_VERIFIED')
    expect(JSON.parse(exported).egressMatches).toBe(null)
  })
})
