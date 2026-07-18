import { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Select, Button, Tag, Modal, Space, Typography, Empty, message } from 'antd';
import { SettingOutlined, PlayCircleOutlined, StopOutlined, ReloadOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { PageShell } from '@/layouts/PageShell';
import { PageTitleBar } from '@/components/PageTitleBar';
import { useTheme } from '@/hooks/useTheme';
import { ApiError } from '@/api/http-init';
import {
  useConsoleTargetsQuery, useCreateConsoleSessionMutation, usePanelHostQuery, usePanelHostMutations,
} from '@/api/queries/console';
import { useServersQuery } from '@/api/queries/servers';

type Status = 'idle' | 'connecting' | 'connected' | 'disconnected';

// Client -> server / server -> client control-frame shapes (see
// internal/console/bridge.go's clientFrame/serverFrame -- kept in sync by
// hand, this is a small enough protocol that a shared schema isn't worth
// the build-time codegen it would need).
interface ServerFrame { t: 'exit' | 'err'; code?: number; msg?: string }

const TERM_THEME_DARK = {
  background: '#1e1e2e', foreground: '#cdd6f4', cursor: '#f5e0dc',
};
const TERM_THEME_LIGHT = {
  background: '#ffffff', foreground: '#1f1f1f', cursor: '#1f1f1f',
};

export function ConsolePage() {
  const { t } = useTranslation(['console', 'common']);
  const { isDark } = useTheme();
  const [searchParams] = useSearchParams();

  const { data: targets, isLoading: targetsLoading } = useConsoleTargetsQuery();
  const createSession = useCreateConsoleSessionMutation();

  const [target, setTarget] = useState<string | undefined>(searchParams.get('target') ?? undefined);
  const [status, setStatus] = useState<Status>('idle');
  const [statusMsg, setStatusMsg] = useState<string>('');

  const termContainerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Pre-select the target passed in via ?target=server:<id> (the
  // contextual "Open console" button on a server's page) once targets have
  // loaded, in case the query param arrived before the list did.
  useEffect(() => {
    if (target || !targets?.length) return;
    const fromQuery = searchParams.get('target');
    if (fromQuery && targets.some((x) => x.target === fromQuery)) setTarget(fromQuery);
  }, [targets, target, searchParams]);

  useEffect(() => {
    const term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: 'Menlo, Consolas, "Liberation Mono", monospace',
      theme: isDark ? TERM_THEME_DARK : TERM_THEME_LIGHT,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    if (termContainerRef.current) term.open(termContainerRef.current);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    const ro = new ResizeObserver(() => {
      try { fit.fit(); } catch { /* container not yet laid out */ }
    });
    if (termContainerRef.current) ro.observe(termContainerRef.current);

    return () => {
      ro.disconnect();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
    // Deliberately only on mount/unmount -- the terminal instance persists
    // across connect/disconnect/reconnect within one page visit; only its
    // color theme should react to a live dark/light toggle (next effect).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (termRef.current) termRef.current.options.theme = isDark ? TERM_THEME_DARK : TERM_THEME_LIGHT;
  }, [isDark]);

  const disconnect = useCallback((reason?: string) => {
    wsRef.current?.close(1000, reason ?? 'client disconnect');
    wsRef.current = null;
    setStatus('disconnected');
    setStatusMsg(reason ?? '');
  }, []);

  useEffect(() => () => { wsRef.current?.close(1000, 'page unmount'); }, []);

  async function connect() {
    if (!target || !termRef.current || !fitRef.current) return;
    setStatus('connecting');
    setStatusMsg('');
    let session;
    try {
      session = await createSession.mutateAsync(target);
    } catch (err) {
      setStatus('disconnected');
      setStatusMsg(err instanceof ApiError ? err.message : String(err));
      return;
    }

    // A fresh shell every (re)connect -- the previous session's state
    // doesn't survive a disconnect, so starting from a clean screen avoids
    // implying continuity that isn't there.
    termRef.current.reset();
    fitRef.current.fit();
    const { rows, cols } = termRef.current;

    const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${scheme}//${window.location.host}${session.ws_url}&rows=${rows}&cols=${cols}`;
    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus('connected');
      setStatusMsg('');
    };
    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') {
        try {
          const frame = JSON.parse(ev.data) as ServerFrame;
          if (frame.t === 'exit') {
            setStatus('disconnected');
            setStatusMsg(t('status.remoteExited', { code: frame.code ?? 0 }));
          } else if (frame.t === 'err') {
            setStatus('disconnected');
            setStatusMsg(frame.msg ?? '');
          }
        } catch { /* not a control frame we understand; ignore */ }
        return;
      }
      termRef.current?.write(new Uint8Array(ev.data as ArrayBuffer));
    };
    ws.onclose = () => {
      if (wsRef.current === ws) {
        wsRef.current = null;
        setStatus((s) => (s === 'connected' ? 'disconnected' : s));
      }
    };
    ws.onerror = () => { /* onclose follows; nothing extra to do here */ };

    const dataDisposable = termRef.current.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: 'i', d: data }));
    });
    const resizeDisposable = termRef.current.onResize(({ cols: c, rows: r }) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: 'r', cols: c, rows: r }));
    });
    ws.addEventListener('close', () => {
      dataDisposable.dispose();
      resizeDisposable.dispose();
    }, { once: true });
  }

  const panelHost = usePanelHostQuery();
  const allServers = useServersQuery();
  const panelHostMutations = usePanelHostMutations();
  const [panelHostModalOpen, setPanelHostModalOpen] = useState(false);
  const [panelHostPick, setPanelHostPick] = useState<string | undefined>();

  useEffect(() => {
    if (panelHostModalOpen) setPanelHostPick(panelHost.data?.server_id);
  }, [panelHostModalOpen, panelHost.data]);

  async function savePanelHost() {
    try {
      if (panelHostPick) await panelHostMutations.set.mutateAsync(panelHostPick);
      else await panelHostMutations.clear.mutateAsync();
      setPanelHostModalOpen(false);
      void message.success(t('common:actions.saved'));
    } catch (err) {
      void message.error(err instanceof ApiError ? err.message : String(err));
    }
  }

  const options = (targets ?? []).map((x) => ({
    value: x.target,
    label: (
      <Space>
        {x.kind === 'panel-host' && <Tag color="gold">{t('picker.panelHostTag')}</Tag>}
        {x.label}
      </Space>
    ),
  }));

  const statusTag = {
    idle: null,
    connecting: <Tag color="processing">{t('status.connecting')}</Tag>,
    connected: <Tag color="success">{t('status.connected')}</Tag>,
    disconnected: <Tag color="default">{t('status.disconnected')}</Tag>,
  }[status];

  return (
    <PageShell>
      <PageTitleBar
        extra={(
          <Button icon={<SettingOutlined />} onClick={() => setPanelHostModalOpen(true)}>
            {t('panelHost.configure')}
          </Button>
        )}
      >
        {t('title')}
      </PageTitleBar>

      <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <Space wrap>
          <Select
            style={{ minWidth: 280 }}
            placeholder={t('picker.placeholder')}
            loading={targetsLoading}
            value={target}
            onChange={setTarget}
            options={options}
            disabled={status === 'connecting' || status === 'connected'}
          />
          {status === 'connected' ? (
            <Button danger icon={<StopOutlined />} onClick={() => disconnect()}>
              {t('actions.disconnect')}
            </Button>
          ) : (
            <Button
              type="primary"
              icon={status === 'disconnected' ? <ReloadOutlined /> : <PlayCircleOutlined />}
              loading={status === 'connecting'}
              disabled={!target}
              onClick={connect}
            >
              {status === 'disconnected' ? t('actions.reconnect') : t('actions.connect')}
            </Button>
          )}
          {statusTag}
          {statusMsg && <Typography.Text type="secondary">{statusMsg}</Typography.Text>}
        </Space>

        {!targetsLoading && !targets?.length ? (
          <Empty description={t('picker.empty')} />
        ) : (
          <div
            style={{
              border: '1px solid var(--ant-color-border, #424242)',
              borderRadius: 8,
              padding: 8,
              height: 'calc(100vh - 280px)',
              minHeight: 320,
              background: isDark ? TERM_THEME_DARK.background : TERM_THEME_LIGHT.background,
            }}
          >
            <div ref={termContainerRef} style={{ width: '100%', height: '100%' }} />
          </div>
        )}
      </Space>

      <Modal
        title={t('panelHost.title')}
        open={panelHostModalOpen}
        onCancel={() => setPanelHostModalOpen(false)}
        onOk={savePanelHost}
        confirmLoading={panelHostMutations.set.isPending || panelHostMutations.clear.isPending}
      >
        <Typography.Paragraph type="secondary">{t('panelHost.description')}</Typography.Paragraph>
        <Select
          style={{ width: '100%' }}
          allowClear
          placeholder={t('panelHost.placeholder')}
          loading={allServers.isLoading}
          value={panelHostPick}
          onChange={(v) => setPanelHostPick(v)}
          options={(allServers.data ?? []).map((srv) => ({ value: srv.id, label: srv.label }))}
        />
      </Modal>
    </PageShell>
  );
}
