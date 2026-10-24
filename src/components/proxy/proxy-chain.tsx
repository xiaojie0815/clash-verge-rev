import { arrayMove } from '@dnd-kit/helpers'
import {
  DragDropProvider,
  KeyboardSensor,
  PointerSensor,
  type DragEndEvent,
} from '@dnd-kit/react'
import { isSortable, useSortable } from '@dnd-kit/react/sortable'
import {
  ArrowDownward,
  Delete as DeleteIcon,
  DragIndicator,
  Link,
  LinkOff,
  WarningRounded,
} from '@mui/icons-material'
import {
  Alert,
  Box,
  Button,
  Chip,
  IconButton,
  Paper,
  Typography,
  keyframes,
  useTheme,
} from '@mui/material'
import {
  type Ref,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import { useTranslation } from 'react-i18next'

import { TooltipIcon } from '@/components/base'
import { useRuntimeConfig } from '@/hooks/use-clash'
import { useAppRefreshers, useProxiesData } from '@/providers/app-data-context'
import { getProxyChainState } from '@/services/cmds'
import { showNotice } from '@/services/notice-service'
import { applyProxyChain } from '@/services/proxy-chain'
import { useQuery } from '@/services/query-client'
import {
  selectGlobalChainNodes,
  selectRuleChainMembers,
} from '@/types/proxy-view'

import { ProxyChainDiagnostics } from './proxy-chain-diagnostics'
import {
  chainConfigurationApplied,
  chainDraftMatches,
  rebindProxyChainItems,
  type ProxyChainItem,
} from './proxy-chain-model'

const chainPointerSensor = PointerSensor.configure({
  activationConstraints: () => undefined,
})

type RuntimeConfigWithProxySequence = IConfigData & { proxies?: unknown }

interface ProxyChainProps {
  proxyChain: ProxyChainItem[]
  onUpdateChain: (chain: ProxyChainItem[]) => void
  chainConfigData?: string | null
  onMarkUnsavedChanges?: () => void
  mode?: string
  selectedGroup?: string | null
}

interface ProxyChainItemProps {
  id: string
  proxy: ProxyChainItem
  index: number
  isFirst: boolean
  isLast: boolean
  onRemove: (id: string) => void
}

const arrowFadeIn = keyframes`
  from {
    opacity: 0;
    transform: translateY(4px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
`

interface ChainCardProps {
  proxy: ProxyChainItem
  index: number
  isFirst: boolean
  isLast: boolean
  isDragging?: boolean
  isDropping?: boolean
  handleRef?: Ref<HTMLElement> | null
  onRemove?: (id: string) => void
}

const ChainCard = ({
  proxy,
  index,
  isFirst,
  isLast,
  isDragging,
  isDropping,
  handleRef,
  onRemove,
}: ChainCardProps) => {
  const theme = useTheme()
  const { t } = useTranslation()

  const roleLabel = isFirst
    ? t('proxies.page.chain.entryNode')
    : isLast
      ? t('proxies.page.chain.exitNode')
      : undefined

  const roleColor = isFirst
    ? theme.palette.success.main
    : isLast
      ? theme.palette.warning.main
      : undefined

  return (
    <Box
      sx={{
        mb: 0,
        display: 'flex',
        alignItems: 'center',
        p: 1,
        backgroundColor: theme.palette.background.default,
        borderRadius: 1,
        border: roleColor
          ? `1.5px solid ${roleColor}`
          : `1px solid ${theme.palette.divider}`,
        opacity: proxy.recordId === undefined ? 0.55 : undefined,
        transition: 'box-shadow 0.2s, background-color 0.2s',
        boxShadow: isDropping
          ? `0 0 0 2px ${theme.palette.primary.main}66`
          : undefined,
      }}
    >
      <Box
        ref={handleRef}
        sx={{
          display: 'flex',
          alignItems: 'center',
          mr: 1,
          color: theme.palette.text.secondary,
          cursor: isDragging ? 'grabbing' : 'grab',
        }}
      >
        <DragIndicator />
      </Box>

      {roleLabel ? (
        <Chip
          label={roleLabel}
          size="small"
          sx={{
            mr: 1,
            fontWeight: 700,
            color: '#fff',
            backgroundColor: roleColor,
          }}
        />
      ) : (
        <Chip
          label={`${index + 1}`}
          size="small"
          color="primary"
          sx={{ mr: 1, minWidth: 32 }}
        />
      )}

      <Typography
        variant="body2"
        sx={{
          flex: 1,
          fontWeight: 500,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {proxy.name}
      </Typography>

      {proxy.type && (
        <Chip
          label={proxy.type}
          size="small"
          variant="outlined"
          sx={{ mr: 1 }}
        />
      )}

      {proxy.delay !== undefined && (
        <Chip
          title={t('proxies.page.chain.nodeDelayHint')}
          label={
            proxy.delay > 0 ? `${proxy.delay}ms` : t('shared.labels.timeout')
          }
          size="small"
          color={
            proxy.delay > 0 && proxy.delay < 200
              ? 'success'
              : proxy.delay > 0 && proxy.delay < 800
                ? 'warning'
                : 'error'
          }
          sx={{ mr: 1, fontSize: '0.7rem', minWidth: 50 }}
        />
      )}

      {onRemove && (
        <IconButton
          size="small"
          onClick={() => onRemove(proxy.id)}
          sx={{
            color: theme.palette.error.main,
            '&:hover': {
              backgroundColor: theme.palette.error.light + '20',
            },
          }}
        >
          <DeleteIcon fontSize="small" />
        </IconButton>
      )}
    </Box>
  )
}

const SortableProxyChainItem = ({
  id,
  proxy,
  index,
  isFirst,
  isLast,
  onRemove,
}: ProxyChainItemProps) => {
  const theme = useTheme()
  const [element, setElement] = useState<Element | null>(null)
  const handleRef = useRef<HTMLElement | null>(null)
  const { isDragging, isDropping } = useSortable({
    id,
    index,
    element,
    handle: handleRef,
  })

  return (
    <Box
      ref={setElement}
      sx={{
        width: '100%',
        '&[data-dnd-dragging]': {
          height: 'auto',
          boxShadow: 'none !important',
          '.proxy-chain-arrow': {
            display: 'none',
          },
        },
        '& .proxy-chain-arrow': {
          animation: `${arrowFadeIn} 0.25s ease`,
        },
      }}
    >
      <ChainCard
        proxy={proxy}
        index={index}
        isFirst={isFirst}
        isLast={isLast}
        isDragging={isDragging}
        isDropping={isDropping}
        handleRef={handleRef}
        onRemove={onRemove}
      />
      {!isLast && (
        <Box
          className="proxy-chain-arrow"
          sx={{
            display: 'flex',
            justifyContent: 'center',
            py: 0.25,
          }}
        >
          <ArrowDownward
            sx={{
              fontSize: 20,
              color: theme.palette.primary.main,
              opacity: 0.7,
            }}
          />
        </Box>
      )}
    </Box>
  )
}

export const ProxyChain = ({
  proxyChain,
  onUpdateChain,
  onMarkUnsavedChanges,
  mode,
  selectedGroup,
}: ProxyChainProps) => {
  const theme = useTheme()
  const { t } = useTranslation()
  const chainWarning = t('proxies.page.chain.warning')
  const { proxyView } = useProxiesData()
  const { refreshProxy } = useAppRefreshers()
  const { data: runtimeConfig, refetch: refreshRuntime } =
    useRuntimeConfig(true)
  const [isConnecting, setIsConnecting] = useState(false)
  const [operationWarning, setOperationWarning] = useState('')
  const {
    data: chainState,
    error: stateError,
    refetch: refreshChainState,
  } = useQuery({
    queryKey: ['getProxyChainState'],
    queryFn: getProxyChainState,
    refetchInterval: 5000,
    refetchOnWindowFocus: true,
  })
  const targetGroup =
    mode === 'global'
      ? 'GLOBAL'
      : mode === 'rule'
        ? (selectedGroup ?? null)
        : null
  const draftMatches = chainDraftMatches(proxyChain, targetGroup, chainState)
  const isApplied = chainConfigurationApplied(chainState)
  const hasAppliedChain = (chainState?.nodes.length ?? 0) >= 2
  const hydratedRef = useRef(false)
  useEffect(() => {
    if (!chainState || hydratedRef.current) return
    hydratedRef.current = true
    if (proxyChain.length === 0 && chainState.nodes.length > 0) {
      onUpdateChain(
        chainState.nodes.map((name, index) => ({
          id: `restored-${index}-${name}`,
          name,
        })),
      )
    }
  }, [chainState, proxyChain.length, onUpdateChain])
  const markUnsavedChanges = useCallback(() => {
    onMarkUnsavedChanges?.()
  }, [onMarkUnsavedChanges])

  const candidates = useMemo(() => {
    if (!proxyView) return []
    if (mode === 'rule' && selectedGroup) {
      return selectRuleChainMembers(proxyView, selectedGroup).flatMap(
        ({ member }) => (member.kind === 'node' ? [member.node] : []),
      )
    }
    if (!runtimeConfig) return []
    const runtimeProxies = (
      runtimeConfig as RuntimeConfigWithProxySequence | null
    )?.proxies
    return selectGlobalChainNodes(proxyView, runtimeProxies)
  }, [mode, proxyView, runtimeConfig, selectedGroup])

  const currentProxyChain = useMemo(
    () =>
      proxyView
        ? rebindProxyChainItems(proxyChain, candidates, proxyView)
        : proxyChain.map((item) => ({
            ...item,
            recordId: undefined,
            delay: undefined,
          })),
    [candidates, proxyChain, proxyView],
  )

  // 监听链的变化，但排除从配置加载的情况
  const chainLengthRef = useRef(currentProxyChain.length)
  useEffect(() => {
    // 只有当链长度发生变化且不是初始加载时，才标记为未保存
    if (
      chainLengthRef.current !== currentProxyChain.length &&
      chainLengthRef.current !== 0
    ) {
      markUnsavedChanges()
    }
    chainLengthRef.current = currentProxyChain.length
  }, [currentProxyChain.length, markUnsavedChanges])

  const handleDragEnd = useCallback(
    (event: DragEndEvent) => {
      if (isConnecting) return
      const { operation, canceled } = event
      const { source, target } = operation
      if (canceled || !target || !isSortable(source)) return

      const { index: newIndex, initialIndex: oldIndex } = source.sortable
      if (
        oldIndex < 0 ||
        newIndex < 0 ||
        oldIndex >= currentProxyChain.length ||
        newIndex >= currentProxyChain.length ||
        oldIndex === newIndex
      ) {
        return
      }

      onUpdateChain(arrayMove(currentProxyChain, oldIndex, newIndex))
      markUnsavedChanges()
    },
    [currentProxyChain, onUpdateChain, markUnsavedChanges, isConnecting],
  )

  const handleRemoveProxy = useCallback(
    (id: string) => {
      if (isConnecting) return
      const newChain = currentProxyChain.filter((item) => item.id !== id)
      onUpdateChain(newChain)
      markUnsavedChanges()
    },
    [currentProxyChain, onUpdateChain, markUnsavedChanges, isConnecting],
  )

  const refreshState = useCallback(async () => {
    await Promise.allSettled([
      refreshProxy(),
      refreshChainState(),
      refreshRuntime(),
    ])
  }, [refreshProxy, refreshChainState, refreshRuntime])

  const handleApply = useCallback(async () => {
    if (
      !targetGroup ||
      currentProxyChain.length < 2 ||
      currentProxyChain.some((node) => !node.recordId)
    )
      return
    setIsConnecting(true)
    setOperationWarning('')
    try {
      const result = await applyProxyChain(
        targetGroup,
        currentProxyChain.map((node) => node.name),
      )
      if (result.ok) {
        localStorage.setItem('proxy-chain-group', targetGroup)
        localStorage.setItem(
          'proxy-chain-exit-node',
          currentProxyChain.at(-1)!.name,
        )
        setOperationWarning(result.value.warnings.join(', '))
      }
    } catch (error) {
      showNotice.error(error)
    } finally {
      await refreshState()
      setIsConnecting(false)
    }
  }, [currentProxyChain, targetGroup, refreshState])

  const handleDisconnect = useCallback(
    async (clear = false) => {
      setIsConnecting(true)
      setOperationWarning('')
      try {
        const result = await applyProxyChain(null, null)
        if (result.ok) {
          localStorage.removeItem('proxy-chain-group')
          localStorage.removeItem('proxy-chain-exit-node')
          setOperationWarning(result.value.warnings.join(', '))
          if (clear) {
            localStorage.removeItem('proxy-chain-items')
            onUpdateChain([])
          }
        }
      } catch (error) {
        showNotice.error(error)
      } finally {
        await refreshState()
        setIsConnecting(false)
      }
    },
    [onUpdateChain, refreshState],
  )

  return (
    <Paper
      elevation={1}
      sx={{
        height: '100%',
        p: 2,
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          mb: 2,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
          <Typography variant="h6">{t('proxies.page.chain.header')}</Typography>
          <TooltipIcon
            title={chainWarning}
            icon={WarningRounded}
            color="warning"
            sx={{ p: 0.25 }}
          />
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {currentProxyChain.length > 0 && (
            <IconButton
              size="small"
              onClick={() => handleDisconnect(true)}
              disabled={isConnecting}
              sx={{
                color: theme.palette.error.main,
                '&:hover': {
                  backgroundColor: theme.palette.error.light + '20',
                },
              }}
              title={t('proxies.page.actions.clearChainConfig')}
            >
              <DeleteIcon fontSize="small" />
            </IconButton>
          )}
          {hasAppliedChain && (
            <Button
              size="small"
              color="error"
              disabled={isConnecting}
              startIcon={<LinkOff />}
              onClick={() => handleDisconnect()}
            >
              {t('proxies.page.actions.disconnect')}
            </Button>
          )}
          <Button
            size="small"
            variant="contained"
            startIcon={<Link />}
            onClick={handleApply}
            disabled={
              isConnecting ||
              !targetGroup ||
              currentProxyChain.length < 2 ||
              currentProxyChain.length > 8 ||
              currentProxyChain.some((node) => node.recordId === undefined) ||
              (draftMatches && isApplied && chainState?.scopeActive)
            }
          >
            {t(
              isConnecting
                ? 'proxies.page.chain.busy'
                : 'proxies.page.chain.apply',
            )}
          </Button>
        </Box>
      </Box>

      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 1 }}>
        <Chip
          size="small"
          color={stateError ? 'error' : isApplied ? 'success' : 'default'}
          label={t(
            stateError
              ? 'proxies.page.chain.stateUnknown'
              : isApplied
                ? 'proxies.page.chain.applied'
                : 'proxies.page.chain.notApplied',
          )}
        />
        {currentProxyChain.length > 0 && !draftMatches && (
          <Chip
            size="small"
            color="warning"
            label={t('proxies.page.chain.pending')}
          />
        )}
        {hasAppliedChain && !chainState?.scopeActive && (
          <Chip
            size="small"
            color="warning"
            label={t('proxies.page.chain.inactiveScope')}
          />
        )}
      </Box>
      <Typography variant="caption" sx={{ mb: 1, overflowWrap: 'anywhere' }}>
        {t('proxies.page.chain.scope', {
          group: chainState?.group ?? '—',
          selected: chainState?.selected ?? '—',
          mode: chainState?.mode ?? '—',
        })}
      </Typography>
      {chainState?.group && chainState.group !== 'GLOBAL' && (
        <Alert severity="info" sx={{ mb: 1 }}>
          {t('proxies.page.chain.ruleScopeHint')}
        </Alert>
      )}
      {operationWarning && (
        <Alert severity="warning" sx={{ mb: 1 }}>
          {operationWarning}
        </Alert>
      )}
      <Alert
        severity={currentProxyChain.length === 1 ? 'warning' : 'info'}
        sx={{ mb: 2 }}
      >
        {currentProxyChain.length === 1
          ? t('proxies.page.chain.minimumNodesHint')
          : t('proxies.page.chain.instruction')}
      </Alert>

      <Box sx={{ flex: 1, overflow: 'auto' }}>
        {currentProxyChain.length === 0 ? (
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              height: '100%',
              color: theme.palette.text.secondary,
            }}
          >
            <Typography>{t('proxies.page.chain.empty')}</Typography>
          </Box>
        ) : (
          <DragDropProvider
            sensors={[chainPointerSensor, KeyboardSensor]}
            onDragEnd={handleDragEnd}
          >
            <Box sx={{ borderRadius: 1, minHeight: 60, p: 1 }}>
              {currentProxyChain.map((proxy, index) => (
                <SortableProxyChainItem
                  key={proxy.id}
                  id={proxy.id}
                  proxy={proxy}
                  index={index}
                  isFirst={index === 0}
                  isLast={
                    index === currentProxyChain.length - 1 &&
                    currentProxyChain.length > 1
                  }
                  onRemove={handleRemoveProxy}
                />
              ))}
            </Box>
          </DragDropProvider>
        )}
        <ProxyChainDiagnostics
          state={chainState}
          draftKey={JSON.stringify([
            targetGroup,
            currentProxyChain.map((node) => node.name),
          ])}
          busy={isConnecting}
          onBusy={setIsConnecting}
        />
      </Box>
    </Paper>
  )
}
