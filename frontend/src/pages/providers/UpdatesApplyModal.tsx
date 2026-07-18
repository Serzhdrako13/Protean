import { useEffect, useRef, useState } from 'react';
import { Modal, Button, Tag, Popconfirm, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { useTheme } from '@/hooks/useTheme';
import { ApiError } from '@/api/http-init';
import { useStartUpdatesApplyMutation } from '@/api/queries/updates';

interface ServerFrame { t: 'exit' | 'err'; code?: number; msg?: string }

type Phase = 'starting' | 'running' | 'done' | 'error';

// A single streamed `updates-apply` run rendered live -- reuses the same
// WS protocol/ticket mechanism as the interactive console (see
// internal/console/bridge.go), just output-only: no keystrokes are sent,
// so no onData wiring. Closing mid-run genuinely aborts the remote package
// manager transaction (the WS disconnect tears the bridge down), which can
// leave a package manager's own state half-applied -- the Close button is
// disabled while running; abandoning early needs an explicit confirm.
export function UpdatesApplyModal({
  open, onClose, serverId,
}: { open: boolean; onClose: () => void; serverId: string }) {
  const { t } = useTranslation(['server-providers', 'common']);
  const { isDark } = useTheme();
  const startApply = useStartUpdatesApplyMutation(serverId);

  const [phase, setPhase] = useState<Phase>('starting');
  const [phaseMsg, setPhaseMsg] = useState('');

  const termContainerRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!open) return;
    setPhase('starting');
    setPhaseMsg('');

    const term = new Terminal({
      cursorBlink: false,
      disableStdin: true,
      fontSize: 13,
      fontFamily: 'Menlo, Consolas, "Liberation Mono", monospace',
      theme: isDark ? { background: '#1e1e2e', foreground: '#cdd6f4' } : { background: '#ffffff', foreground: '#1f1f1f' },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    if (termContainerRef.current) term.open(termContainerRef.current);
    fit.fit();
    const ro = new ResizeObserver(() => { try { fit.fit(); } catch { /* not laid out yet */ } });
    if (termContainerRef.current) ro.observe(termContainerRef.current);

    let cancelled = false;
    (async () => {
      let session;
      try {
        session = await startApply.mutateAsync();
      } catch (err) {
        if (cancelled) return;
        setPhase('error');
        setPhaseMsg(err instanceof ApiError ? err.message : String(err));
        return;
      }
      if (cancelled) return;

      const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = `${scheme}//${window.location.host}${session.ws_url}&rows=${term.rows}&cols=${term.cols}`;
      const ws = new WebSocket(url);
      ws.binaryType = 'arraybuffer';
      wsRef.current = ws;

      ws.onopen = () => setPhase('running');
      ws.onmessage = (ev) => {
        if (typeof ev.data === 'string') {
          try {
            const frame = JSON.parse(ev.data) as ServerFrame;
            if (frame.t === 'exit') {
              setPhase(frame.code && frame.code !== 0 ? 'error' : 'done');
              setPhaseMsg(frame.code ? t('updates.exitedWithCode', { code: frame.code }) : '');
            } else if (frame.t === 'err') {
              setPhase('error');
              setPhaseMsg(frame.msg ?? '');
            }
          } catch { /* not a control frame */ }
          return;
        }
        term.write(new Uint8Array(ev.data as ArrayBuffer));
      };
      ws.onclose = () => {
        if (wsRef.current === ws) {
          wsRef.current = null;
          setPhase((p) => (p === 'running' ? 'done' : p));
        }
      };
    })();

    return () => {
      cancelled = true;
      wsRef.current?.close(1000, 'modal closed');
      wsRef.current = null;
      ro.disconnect();
      term.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const running = phase === 'starting' || phase === 'running';

  function forceClose() {
    wsRef.current?.close(1000, 'force close');
    onClose();
  }

  const statusTag = {
    starting: <Tag color="processing">{t('updates.starting')}</Tag>,
    running: <Tag color="processing">{t('updates.running')}</Tag>,
    done: <Tag color="success">{t('updates.done')}</Tag>,
    error: <Tag color="error">{t('updates.failed')}</Tag>,
  }[phase];

  return (
    <Modal
      title={t('updates.applyTitle')}
      open={open}
      onCancel={running ? undefined : onClose}
      closable={!running}
      maskClosable={false}
      width={800}
      footer={running ? (
        <Popconfirm
          title={t('updates.abortConfirmTitle')}
          description={t('updates.abortConfirmDescription')}
          okButtonProps={{ danger: true }}
          onConfirm={forceClose}
        >
          <Button danger>{t('updates.abort')}</Button>
        </Popconfirm>
      ) : (
        <Button onClick={onClose}>{t('common:actions.close')}</Button>
      )}
    >
      <div style={{ marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
        {statusTag}
        {phaseMsg && <Typography.Text type="secondary">{phaseMsg}</Typography.Text>}
      </div>
      <div
        style={{
          border: '1px solid var(--ant-color-border, #424242)',
          borderRadius: 8,
          padding: 8,
          height: 400,
          background: isDark ? '#1e1e2e' : '#ffffff',
        }}
      >
        <div ref={termContainerRef} style={{ width: '100%', height: '100%' }} />
      </div>
    </Modal>
  );
}
