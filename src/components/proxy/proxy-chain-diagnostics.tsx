import { Alert, Box, Button, Chip, TextField, Typography } from '@mui/material'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { useConnectionData } from '@/hooks/use-connection-data'
import { showNotice } from '@/services/notice-service'
import {
  chainReportText,
  copyChainReport,
  exportChainReport,
  runChainDiagnostics,
} from '@/services/proxy-chain'
import type {
  ChainDiagnosticReport,
  ProxyChainState,
} from '@/types/proxy-chain'

import { chainBindingKey } from './proxy-chain-model'

interface Props {
  state: ProxyChainState | undefined
  draftKey: string
  busy: boolean
  onBusy: (busy: boolean) => void
}

export const ProxyChainDiagnostics = ({
  state,
  draftKey,
  busy,
  onBusy,
}: Props) => {
  const { t } = useTranslation()
  const [report, setReport] = useState<ChainDiagnosticReport | null>(null)
  const [testedKey, setTestedKey] = useState('')
  const [expectedEgress, setExpectedEgress] = useState('')
  const [diagnosing, setDiagnosing] = useState(false)
  const { response } = useConnectionData()
  const bindingKey = chainBindingKey(state) + draftKey
  const stale = testedKey !== bindingKey || report?.snapshotStable === false
  const currentReport = report
    ? { ...report, snapshotStable: report.snapshotStable && !stale }
    : null
  const reachable = !!report?.steps.some(
    (step) =>
      step.stage === 'LOCAL_PROXY_TARGET_HTTP' && step.status === 'pass',
  )
  const recent = [
    ...response.data.activeConnections,
    ...response.data.closedConnections,
  ]
    .sort((left, right) => Date.parse(right.start) - Date.parse(left.start))
    .slice(0, 3)

  const diagnose = async () => {
    setDiagnosing(true)
    onBusy(true)
    setReport(null)
    const startedKey = bindingKey
    try {
      const result = await runChainDiagnostics(expectedEgress)
      if (result.ok) {
        setReport(result.value)
        setTestedKey(startedKey)
      }
    } catch (error) {
      showNotice.error(error)
    } finally {
      setDiagnosing(false)
      onBusy(false)
    }
  }

  return (
    <Box sx={{ mt: 2 }}>
      <Typography variant="subtitle2">
        {t('proxies.page.chain.diagnostics.title')}
      </Typography>
      <Typography
        variant="caption"
        color="text.secondary"
        sx={{ display: 'block', mb: 1 }}
      >
        {t('proxies.page.chain.diagnostics.explanation')}
      </Typography>
      <TextField
        size="small"
        fullWidth
        autoComplete="off"
        value={expectedEgress}
        disabled={busy}
        label={t('proxies.page.chain.diagnostics.expectedExit')}
        helperText={t('proxies.page.chain.diagnostics.expectedExitHint')}
        onChange={(event) => {
          setExpectedEgress(event.target.value)
          setReport(null)
        }}
      />
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, my: 1 }}>
        <Button
          size="small"
          variant="outlined"
          disabled={busy}
          onClick={diagnose}
        >
          {t(
            diagnosing
              ? 'proxies.page.chain.diagnostics.running'
              : 'proxies.page.chain.diagnostics.run',
          )}
        </Button>
        {report && (
          <>
            <Button
              size="small"
              disabled={busy}
              onClick={() =>
                copyChainReport(currentReport ?? report).catch(showNotice.error)
              }
            >
              {t('proxies.page.chain.diagnostics.copy')}
            </Button>
            <Button
              size="small"
              disabled={busy}
              onClick={() =>
                exportChainReport(currentReport ?? report).catch(
                  showNotice.error,
                )
              }
            >
              {t('proxies.page.chain.diagnostics.export')}
            </Button>
          </>
        )}
      </Box>
      <Chip
        size="small"
        color={!report || stale ? 'default' : reachable ? 'success' : 'error'}
        label={t(
          !report
            ? 'proxies.page.chain.diagnostics.notTested'
            : stale
              ? 'proxies.page.chain.diagnostics.stale'
              : reachable
                ? 'proxies.page.chain.diagnostics.reachable'
                : 'proxies.page.chain.diagnostics.failed',
        )}
      />
      {report && (
        <Box sx={{ mt: 1 }}>
          <Chip
            size="small"
            color={
              stale || report.egressMatches === null
                ? 'default'
                : report.egressMatches
                  ? 'success'
                  : 'error'
            }
            label={t(
              stale || report.egressMatches === null
                ? 'proxies.page.chain.diagnostics.exitUnknown'
                : report.egressMatches
                  ? 'proxies.page.chain.diagnostics.exitMatched'
                  : 'proxies.page.chain.diagnostics.exitMismatch',
            )}
          />
          {report.steps.map((step) => (
            <Alert
              key={`${step.hop ?? 'chain'}:${step.stage}`}
              sx={{ mt: 0.5, py: 0 }}
              severity={
                step.status === 'pass'
                  ? 'success'
                  : step.status === 'fail'
                    ? 'error'
                    : 'info'
              }
            >
              <Typography variant="caption" component="div">
                {step.hop ? `NODE_${step.hop} · ` : ''}
                {t(
                  `proxies.page.chain.diagnostics.stages.${step.stage}` as 'proxies.page.chain.diagnostics.stages.CONFIGURATION',
                  { defaultValue: step.stage },
                )}
              </Typography>
              <Typography variant="caption" component="div">
                {step.code} · {step.elapsedMs} ms
              </Typography>
              <Typography variant="caption" component="div">
                {t(
                  `proxies.page.chain.diagnostics.codes.${step.code}` as 'proxies.page.chain.diagnostics.codes.TIMEOUT',
                  { defaultValue: '' },
                )}
              </Typography>
            </Alert>
          ))}
          <Box component="details" sx={{ mt: 1 }}>
            <Typography component="summary" variant="caption">
              {t('proxies.page.chain.diagnostics.preview')}
            </Typography>
            <Box
              component="pre"
              sx={{
                fontSize: 11,
                whiteSpace: 'pre-wrap',
                overflowWrap: 'anywhere',
              }}
            >
              {chainReportText(currentReport ?? report)}
            </Box>
          </Box>
        </Box>
      )}
      <Typography variant="subtitle2" sx={{ mt: 2 }}>
        {t('proxies.page.chain.diagnostics.actualRequests')}
      </Typography>
      <Typography variant="caption" color="text.secondary">
        {t('proxies.page.chain.diagnostics.requestHint')}
      </Typography>
      {recent.length === 0 && (
        <Typography variant="caption" component="div">
          {t('proxies.page.chain.diagnostics.noRequests')}
        </Typography>
      )}
      {recent.map((connection) => (
        <Box key={connection.id} sx={{ mt: 0.75, overflowWrap: 'anywhere' }}>
          <Typography variant="caption" component="div">
            {connection.metadata.host || connection.metadata.destinationIP} ·{' '}
            {connection.rule}
          </Typography>
          <Typography variant="caption" component="div">
            {[...connection.chains].reverse().join(' → ')}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {new Date(connection.start).toLocaleTimeString()} ·{' '}
            {connection.download > 0
              ? t('proxies.page.chain.diagnostics.responseObserved')
              : t('proxies.page.chain.diagnostics.noResponseObserved')}
          </Typography>
        </Box>
      ))}
    </Box>
  )
}
