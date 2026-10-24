import { expect, it } from 'vitest'

import type { ProxyChainState } from '@/types/proxy-chain'

import {
  chainBindingKey,
  chainConfigurationApplied,
  chainDraftMatches,
} from './proxy-chain-model'

const chain = [{ name: 'entry' }, { name: 'exit' }]

const applied: ProxyChainState = {
  group: 'GLOBAL',
  nodes: ['entry', 'exit'],
  selected: 'exit',
  mode: 'global',
  tunEnabled: false,
  mixedPort: 7897,
  linksApplied: true,
  selectionApplied: true,
  scopeActive: true,
  warnings: [],
}

it('marks a reordered draft or changed group pending without changing the applied configuration', () => {
  expect(chainDraftMatches(chain, 'GLOBAL', applied)).toBe(true)
  expect(chainDraftMatches([...chain].reverse(), 'GLOBAL', applied)).toBe(false)
  expect(chainDraftMatches(chain, 'rule-group', applied)).toBe(false)
  expect(chainConfigurationApplied(applied)).toBe(true)
  expect(applied.nodes).toEqual(['entry', 'exit'])
})

it('invalidates a diagnostic binding when the actual mode or exit selection changes', () => {
  expect(
    chainBindingKey({ ...applied, mode: 'rule', scopeActive: false }),
  ).not.toBe(chainBindingKey(applied))
  expect(
    chainBindingKey({ ...applied, selected: 'entry', selectionApplied: false }),
  ).not.toBe(chainBindingKey(applied))
  expect(
    chainConfigurationApplied({ ...applied, selectionApplied: false }),
  ).toBe(false)
})

it('invalidates the test binding when TUN or the live mixed port changes', () => {
  expect(chainBindingKey({ ...applied, tunEnabled: true })).not.toBe(
    chainBindingKey(applied),
  )
  expect(chainBindingKey({ ...applied, mixedPort: 7898 })).not.toBe(
    chainBindingKey(applied),
  )
  expect(chainConfigurationApplied(undefined)).toBe(false)
})
