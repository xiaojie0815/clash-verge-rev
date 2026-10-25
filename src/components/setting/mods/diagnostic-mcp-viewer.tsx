import { Alert, Box, Button, Stack, TextField, Typography } from '@mui/material'
import { writeText } from '@tauri-apps/plugin-clipboard-manager'
import { useEffect, useImperativeHandle, useState, type Ref } from 'react'
import { useTranslation } from 'react-i18next'

import { BaseDialog, type DialogRef } from '@/components/base'
import {
  getDiagnosticMcp,
  startDiagnosticMcp,
  stopDiagnosticMcp,
  type DiagnosticMcpConnection,
} from '@/services/cmds'
import { mutate } from '@/services/mutate'
import { showNotice } from '@/services/notice-service'

export function DiagnosticMcpViewer({ ref }: { ref?: Ref<DialogRef> }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [known, setKnown] = useState(false)
  const [info, setInfo] = useState<DiagnosticMcpConnection | null>(null)
  const [bindIp, setBindIp] = useState('127.0.0.1')
  const [peer, setPeer] = useState('127.0.0.1')
  const [port, setPort] = useState('17998')

  useImperativeHandle(ref, () => ({
    open: () => setOpen(true),
    close: () => setOpen(false),
  }))
  useEffect(() => {
    if (!open) return
    let cancelled = false
    const refresh = async () => {
      try {
        const value = await getDiagnosticMcp()
        if (!cancelled) {
          setInfo(value)
          setKnown(true)
          if (value.enabled) {
            setBindIp(value.bindIp ?? '127.0.0.1')
            setPeer(value.allowedPeer ?? '127.0.0.1')
            if (value.endpoint) setPort(new URL(value.endpoint).port)
          }
        }
      } catch {
        if (!cancelled) setKnown(false)
      }
    }
    void refresh()
    const timer = window.setInterval(() => void refresh(), 2500)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [open])

  const change = async (enable: boolean) => {
    setBusy(true)
    try {
      const result = await mutate(
        async () => {
          if (enable)
            return startDiagnosticMcp(bindIp.trim(), peer.trim(), Number(port))
          await stopDiagnosticMcp()
          return getDiagnosticMcp()
        },
        { id: 'diagnostic-mcp', errorNotice: false },
      )
      if (result.ok) {
        setInfo(result.value)
        setKnown(true)
      }
    } catch (error) {
      showNotice.error(error)
    } finally {
      setBusy(false)
    }
  }

  const copy = async (text: string) => {
    try {
      await mutate(() => writeText(text), {
        id: 'diagnostic-mcp-copy',
        errorNotice: false,
      })
    } catch (error) {
      showNotice.error(error)
    }
  }
  const config = info?.endpoint
    ? `[mcp_servers.clash_diagnostics]\nurl = ${JSON.stringify(info.endpoint)}\nbearer_token_env_var = "CLASH_DIAGNOSTIC_TOKEN"\ntool_timeout_sec = 120\n`
    : ''

  return (
    <BaseDialog
      open={open}
      title={t('settings.diagnosticMcp.title')}
      contentSx={{ width: 560 }}
      okBtn={t('shared.actions.close')}
      onOk={() => setOpen(false)}
      onClose={() => setOpen(false)}
    >
      <Stack spacing={2} sx={{ py: 1 }}>
        <Alert severity="info">{t('settings.diagnosticMcp.privacy')}</Alert>
        <Typography variant="body2">
          {t('settings.diagnosticMcp.scope')}
        </Typography>
        <Alert
          severity={!known ? 'warning' : info?.enabled ? 'success' : 'info'}
        >
          {!known
            ? t('settings.diagnosticMcp.unconfirmed')
            : !info?.enabled
              ? t('settings.diagnosticMcp.disabled')
              : info.calls > 0
                ? t('settings.diagnosticMcp.calls', { count: info.calls })
                : t('settings.diagnosticMcp.waiting')}
        </Alert>
        <TextField
          label={t('settings.diagnosticMcp.bindIp')}
          value={bindIp}
          disabled={busy || info?.enabled}
          onChange={(event) => setBindIp(event.target.value)}
        />
        <TextField
          label={t('settings.diagnosticMcp.peerIp')}
          value={peer}
          disabled={busy || info?.enabled}
          onChange={(event) => setPeer(event.target.value)}
        />
        <TextField
          label={t('settings.diagnosticMcp.port')}
          value={port}
          disabled={busy || info?.enabled}
          onChange={(event) => setPort(event.target.value)}
          slotProps={{ htmlInput: { inputMode: 'numeric' } }}
        />
        <Typography variant="caption">
          {t('settings.diagnosticMcp.networkHint')}
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="contained"
            disabled={
              busy ||
              !known ||
              info?.enabled ||
              !/^\d+$/.test(port) ||
              Number(port) < 1024 ||
              Number(port) > 65535
            }
            onClick={() => void change(true)}
          >
            {t('settings.diagnosticMcp.enable')}
          </Button>
          <Button
            color="error"
            disabled={busy || !info?.enabled}
            onClick={() => void change(false)}
          >
            {t('settings.diagnosticMcp.disable')}
          </Button>
        </Box>
        {info?.enabled && (
          <>
            <TextField
              label={t('settings.diagnosticMcp.endpoint')}
              value={info.endpoint ?? ''}
              slotProps={{ input: { readOnly: true } }}
            />
            <TextField
              label={t('settings.diagnosticMcp.token')}
              type="password"
              value={info.token ?? ''}
              slotProps={{ input: { readOnly: true } }}
            />
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button onClick={() => void copy(config)}>
                {t('settings.diagnosticMcp.copyConfig')}
              </Button>
              <Button onClick={() => void copy(info.token ?? '')}>
                {t('settings.diagnosticMcp.copyToken')}
              </Button>
            </Box>
            <Typography variant="caption">
              {t('settings.diagnosticMcp.setupHint')}
            </Typography>
            <Typography variant="caption">
              {t('settings.diagnosticMcp.expires', {
                time: info.expiresAt
                  ? new Date(info.expiresAt).toLocaleString()
                  : '',
              })}
            </Typography>
            {info.lastTool && (
              <Typography variant="caption">
                {t('settings.diagnosticMcp.lastTool', { name: info.lastTool })}
              </Typography>
            )}
          </>
        )}
      </Stack>
    </BaseDialog>
  )
}
