import type { ProxyChainState } from '@/types/proxy-chain'
import {
  getRecord,
  rebindNode,
  type ProxyNodeView,
  type ProxyViewV1,
} from '@/types/proxy-view'

export interface ProxyChainItem {
  id: string
  name: string
  recordId?: string
  source?: ProxyNodeView['source']
  type?: string
  delay?: number
}

export const chainBindingKey = (state: ProxyChainState | undefined) =>
  JSON.stringify(
    state
      ? [
          state.group,
          state.nodes,
          state.selected,
          state.mode,
          state.tunEnabled,
          state.mixedPort,
          state.linksApplied,
          state.selectionApplied,
          state.scopeActive,
        ]
      : null,
  )

export const chainDraftMatches = (
  chain: readonly Pick<ProxyChainItem, 'name'>[],
  group: string | null,
  state: ProxyChainState | undefined,
) =>
  !!state &&
  group === state.group &&
  chain.length === state.nodes.length &&
  chain.every((node, index) => node.name === state.nodes[index])

export const chainConfigurationApplied = (state: ProxyChainState | undefined) =>
  !!state &&
  state.nodes.length >= 2 &&
  state.linksApplied &&
  state.selectionApplied

export const rebindProxyChainItems = (
  items: readonly ProxyChainItem[],
  candidates: readonly ProxyNodeView[],
  proxyView: ProxyViewV1,
): ProxyChainItem[] =>
  items.map((item) => {
    const binding = {
      name: item.name,
      source: item.source,
    }
    const rebound =
      rebindNode(candidates, binding) ??
      rebindNode(Object.values(proxyView.records), binding)
    const record =
      rebound === undefined ? undefined : getRecord(proxyView, rebound.recordId)
    return {
      ...item,
      recordId: rebound?.recordId,
      source: rebound?.source ?? item.source,
      type: rebound?.type ?? item.type,
      delay: record?.history.at(-1)?.delay,
    }
  })
