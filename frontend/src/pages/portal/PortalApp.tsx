import { useEffect, useRef, useState, type CSSProperties } from 'react';
import {
  ConfigProvider, Layout, Card, Form, Input, Button, Alert, Typography,
  List, Space, Tag, message, Modal, Image, Dropdown, Avatar, Segmented,
  Row, Col, Statistic,
} from 'antd';
import type { MenuProps } from 'antd';
import {
  LockOutlined, UserOutlined, SafetyOutlined, DownloadOutlined,
  QrcodeOutlined, LogoutOutlined, BulbOutlined, MoonOutlined, HistoryOutlined,
  QuestionCircleOutlined, TranslationOutlined, FileTextOutlined,
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { useTheme } from '@/hooks/useTheme';
import { useLang } from '@/hooks/useLang';
import { HttpUtil, ApiError } from '@/api/http-init';
import { InsecureConnectionBanner } from '@/components/InsecureConnectionBanner';
import { ProteanBrand } from '@/components/ProteanBrand';
import { LoginForm } from '@/components/LoginForm';
import { PasswordPolicyHint } from '@/components/PasswordPolicyHint';
import { passwordPolicyIssues } from '@/utils/passwordPolicy';
import type { PasswordPolicySettings } from '@/types/passwordPolicy';

// One provider instance as this user can see it — every registered instance
// shows up (see api_portal.go apiPortalMe), in one of 4 states. "pending"
// covers both "just requested" and "admin approved but no confirmed peer
// yet" — that distinction is admin-side only, not shown here (matches how
// it was scoped: the user just sees "waiting" until it's actually usable).
interface PortalInstance {
  provider: string;
  provider_label: string;
  provider_type: string;
  description?: string;
  state: 'none' | 'pending' | 'denied' | 'granted';
  peer_key?: string;
  name?: string;
  online?: boolean;
  rx_bytes?: number;
  tx_bytes?: number;
  last_handshake?: string;
  // Admin changed this instance's server-config (address/port/DNS/subnet/
  // MTU) after this device's config was last downloaded -- prompt a
  // re-download.
  config_stale?: boolean;
}

// Display name for the raw protocol type -- shown as a badge so a user with
// several devices can tell at a glance "this one is IKEv2, that's OpenVPN"
// without needing to know the panel's internal naming.
const PROTOCOL_LABELS: Record<string, string> = {
  wireguard: 'WireGuard',
  amneziawg: 'AmneziaWG',
  openvpn: 'OpenVPN',
  ikev2: 'IKEv2',
};

interface PortalMe {
  username: string;
  password_expired: boolean;
  totp_enabled: boolean;
  language?: string;
  instances: PortalInstance[];
}

interface PortalConnectionEvent {
  ts: string;
  provider_label: string;
  device_name: string;
  event: 'connect' | 'disconnect';
}

function formatBytes(n: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

// Chrome-less standalone entry (see entries/portal.tsx) for a role=="user"
// account -- never the admin sidebar/router, just this one page: login,
// "my devices" (request/download/QR per instance), change password, theme.
function PortalLogin({ onLoggedIn }: { onLoggedIn: () => void }) {
  return (
    <Layout style={{ minHeight: '100vh', alignItems: 'center', justifyContent: 'center' }}>
      <Card style={{ width: 360 }}>
        <div style={{ textAlign: 'center', marginBottom: 20 }}>
          <ProteanBrand size="xl" />
        </div>
        <InsecureConnectionBanner />
        <LoginForm i18nNamespace="portal" onLoggedIn={onLoggedIn} />
      </Card>
    </Layout>
  );
}

type SetupOs = 'windows' | 'macos' | 'linux' | 'ios' | 'android';
type LinuxVariant = 'nm' | 'cli';

// Turns bare URLs/domains inside a step's text into real clickable links
// (the content in vpn-setup.json is authored as plain sentences mentioning
// e.g. "https://www.wireguard.com/install/" or "strongswan.org" inline --
// this is what makes those mentions actually clickable instead of dead text).
const URL_PATTERN = /(https?:\/\/[^\s]+)|(\b[a-z0-9-]+\.(?:com|org|net|io)\b(?:\/[^\s.,;:()]*)?)/gi;

function Linkify({ text }: { text: string }) {
  const parts: (string | { url: string; display: string })[] = [];
  let lastIndex = 0;
  for (const match of text.matchAll(URL_PATTERN)) {
    const raw = match[0];
    const start = match.index ?? 0;
    if (start > lastIndex) parts.push(text.slice(lastIndex, start));
    const href = raw.startsWith('http') ? raw : `https://${raw}`;
    parts.push({ url: href, display: raw });
    lastIndex = start + raw.length;
  }
  if (lastIndex < text.length) parts.push(text.slice(lastIndex));

  return (
    <>
      {parts.map((p, i) =>
        typeof p === 'string'
          ? <span key={i}>{p}</span>
          : (
            <Typography.Link key={i} href={p.url} target="_blank" rel="noopener noreferrer">
              {p.display}
            </Typography.Link>
          ))}
    </>
  );
}

interface VpnSetupProtocol {
  app: string;
  appUrl?: string;
  appNote: string;
  windows: string[];
  macos: string[];
  linux_nm: string[];
  linux_cli: string[];
  ios: string[];
  android: string[];
}
type VpnSetupContent = Record<string, VpnSetupProtocol>;

// Per-protocol, per-OS setup instructions -- deliberately NOT a full
// platform x protocol matrix with separate steps per distro/version:
// WireGuard/OpenVPN's own apps work near-identically everywhere, so one
// blurb per (protocol, OS) is enough. Linux gets a second axis
// (NetworkManager GUI vs CLI) since both audiences are common and the
// steps genuinely differ.
//
// The actual text is fetched from /api/portal/vpn-setup-content rather than
// bundled via i18n -- it's served from a volume-mounted directory on the
// backend (see internal/vpnsetup) specifically so an admin can fix a stale
// app name/link/step by editing a file on the host, without rebuilding or
// redeploying the panel (app names and install flows drift over time).
function VpnSetupModal({ open, onClose, providerType }: { open: boolean; onClose: () => void; providerType: string }) {
  const { t } = useTranslation(['vpn-setup', 'portal']);
  const [os, setOs] = useState<SetupOs>('windows');
  const [linuxVariant, setLinuxVariant] = useState<LinuxVariant>('nm');
  const [content, setContent] = useState<VpnSetupContent | null>(null);
  const [loadError, setLoadError] = useState(false);

  useEffect(() => {
    if (!open || content || loadError) return;
    HttpUtil.get<VpnSetupContent>('/api/portal/vpn-setup-content')
      .then(setContent)
      .catch(() => setLoadError(true));
  }, [open, content, loadError]);

  const osOptions: { value: SetupOs; label: string }[] = [
    { value: 'windows', label: t('vpn-setup:os.windows') },
    { value: 'macos', label: t('vpn-setup:os.macos') },
    { value: 'linux', label: t('vpn-setup:os.linux') },
    { value: 'ios', label: t('vpn-setup:os.ios') },
    { value: 'android', label: t('vpn-setup:os.android') },
  ];

  const contentKey = os === 'linux' ? (linuxVariant === 'nm' ? 'linux_nm' : 'linux_cli') : os;
  const proto = content?.[providerType];
  const steps = proto?.[contentKey as keyof VpnSetupProtocol];

  return (
    <Modal title={t('vpn-setup:modalTitle')} open={open} onCancel={onClose} footer={null} width={620}>
      <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
        {loadError && <Alert type="error" showIcon message={t('vpn-setup:loadError')} />}
        {proto && (
          <div>
            <Space align="center">
              <Typography.Text strong style={{ fontSize: 15 }}>{proto.app}</Typography.Text>
              {proto.appUrl && (
                <Typography.Link href={proto.appUrl} target="_blank" rel="noopener noreferrer">
                  {t('vpn-setup:openSite')} ↗
                </Typography.Link>
              )}
            </Space>
            <div style={{ marginTop: 4 }}>
              <Typography.Text type="secondary" style={{ fontSize: 13, lineHeight: 1.6 }}>
                <Linkify text={proto.appNote} />
              </Typography.Text>
            </div>
          </div>
        )}
        <Segmented
          value={os}
          onChange={(v) => setOs(v as SetupOs)}
          options={osOptions}
          block
        />
        {os === 'linux' && (
          <Segmented
            value={linuxVariant}
            onChange={(v) => setLinuxVariant(v as LinuxVariant)}
            options={[
              { value: 'nm', label: t('vpn-setup:linuxNm') },
              { value: 'cli', label: t('vpn-setup:linuxCli') },
            ]}
            block
          />
        )}
        {Array.isArray(steps) && (
          <ol style={{ margin: 0, paddingLeft: 22, lineHeight: 1.9 }}>
            {steps.map((step, i) => (
              <li key={i}>
                <Linkify text={step} />
              </li>
            ))}
          </ol>
        )}
      </Space>
    </Modal>
  );
}

// Protocol badge + admin note, shown identically across every instance
// state -- so a user can tell "this one's IKEv2, that one's OpenVPN" and
// read WHY a connection exists even before requesting/getting access to it.
function ProtocolMeta({ inst }: { inst: PortalInstance }) {
  return (
    <Space size={4} wrap>
      <Tag>{PROTOCOL_LABELS[inst.provider_type] ?? inst.provider_type}</Tag>
      {inst.description && (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>{inst.description}</Typography.Text>
      )}
    </Space>
  );
}

function downloadUrl(inst: PortalInstance): string {
  return `/api/portal/peers/${encodeURIComponent(inst.provider)}/${encodeURIComponent(inst.peer_key ?? '')}/config`;
}
function qrUrl(inst: PortalInstance): string {
  return `/api/portal/peers/${encodeURIComponent(inst.provider)}/${encodeURIComponent(inst.peer_key ?? '')}/qr`;
}
function manualConfigUrl(inst: PortalInstance): string {
  return `/api/portal/peers/${encodeURIComponent(inst.provider)}/${encodeURIComponent(inst.peer_key ?? '')}/config/text`;
}

// Only these produce a plain-text INI-style config a person could type in
// by hand (IKEv2's .p12 and Xray's setup aren't -- see errNoManualSetup on
// the backend, which this mirrors so the button doesn't even show for
// providers where it would just error).
const MANUAL_SETUP_TYPES = new Set(['wireguard', 'amneziawg', 'openvpn']);

function InstanceRow({ inst, onRefresh, onQr, onManualSetup }: {
  inst: PortalInstance;
  onRefresh: () => void;
  onQr: (inst: PortalInstance) => void;
  onManualSetup: (inst: PortalInstance) => void;
}) {
  const { t } = useTranslation(['portal', 'common']);
  const [requesting, setRequesting] = useState(false);
  const [setupOpen, setSetupOpen] = useState(false);

  async function onRequest() {
    setRequesting(true);
    try {
      await HttpUtil.post('/api/portal/requests', { provider: inst.provider });
      message.success(t('portal:instance.requestSent'));
      onRefresh();
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : t('portal:instance.requestFailed'));
    } finally {
      setRequesting(false);
    }
  }

  const setupModal = (
    <VpnSetupModal open={setupOpen} onClose={() => setSetupOpen(false)} providerType={inst.provider_type} />
  );

  // No AntD List.Item `actions` prop anywhere in this component: that slot
  // renders as a narrow right-side column that overlapped/clipped the meta
  // text once there was more than one line of it. Buttons instead go in
  // their own full-width row, visually separated at the BOTTOM of the item.
  const titleStyle: CSSProperties = { whiteSpace: 'nowrap', overflow: 'visible' };

  if (inst.state === 'granted') {
    return (
      <List.Item style={{ display: 'block' }}>
        <List.Item.Meta
          title={<span style={titleStyle}>{inst.name || inst.provider_label}</span>}
          description={
            <Space direction="vertical" size={2}>
              <ProtocolMeta inst={inst} />
              <Space wrap>
                <span style={titleStyle}>{inst.provider_label}</span>
                <Tag color="success">{t('portal:instance.available')}</Tag>
                {inst.online ? <Tag color="success">{t('portal:instance.online')}</Tag> : <Tag color="default">{t('portal:instance.offline')}</Tag>}
                {inst.config_stale && <Tag color="warning">{t('portal:instance.configStale')}</Tag>}
              </Space>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {t('portal:instance.traffic', { rx: formatBytes(inst.rx_bytes ?? 0), tx: formatBytes(inst.tx_bytes ?? 0) })}
                {' · '}
                {inst.last_handshake && new Date(inst.last_handshake).getTime() > 0
                  ? t('portal:instance.lastSeen', { time: new Date(inst.last_handshake).toLocaleString() })
                  : t('portal:instance.neverConnected')}
              </Typography.Text>
            </Space>
          }
        />
        {inst.config_stale && (
          <Alert
            type="warning"
            showIcon
            style={{ marginTop: 12 }}
            message={t('portal:instance.configStaleBanner')}
          />
        )}
        <Space wrap style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid var(--ant-color-border-secondary)', width: '100%' }}>
          <Button icon={<DownloadOutlined />} href={downloadUrl(inst)}>{t('portal:instance.downloadConfig')}</Button>
          <Button icon={<QrcodeOutlined />} onClick={() => onQr(inst)}>{t('portal:instance.qrCode')}</Button>
          {MANUAL_SETUP_TYPES.has(inst.provider_type) && (
            <Button icon={<FileTextOutlined />} onClick={() => onManualSetup(inst)}>{t('portal:instance.manualSetup')}</Button>
          )}
          <Button icon={<QuestionCircleOutlined />} onClick={() => setSetupOpen(true)}>{t('vpn-setup:modalTitle')}</Button>
        </Space>
        {setupModal}
      </List.Item>
    );
  }

  if (inst.state === 'pending') {
    return (
      <List.Item>
        <List.Item.Meta
          title={<span style={titleStyle}>{inst.provider_label}</span>}
          description={
            <Space direction="vertical" size={2}>
              <ProtocolMeta inst={inst} />
              <Tag color="blue">{t('portal:instance.pendingApproval')}</Tag>
            </Space>
          }
        />
      </List.Item>
    );
  }

  if (inst.state === 'denied') {
    return (
      <List.Item style={{ display: 'block' }}>
        <List.Item.Meta
          title={<span style={titleStyle}>{inst.provider_label}</span>}
          description={
            <Space direction="vertical" size={2}>
              <ProtocolMeta inst={inst} />
              <Tag color="red">{t('portal:instance.denied')}</Tag>
            </Space>
          }
        />
        <Space style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid var(--ant-color-border-secondary)', width: '100%' }}>
          <Button onClick={onRequest} loading={requesting}>{t('portal:instance.retryRequest')}</Button>
        </Space>
      </List.Item>
    );
  }

  return (
    <List.Item style={{ display: 'block', opacity: 0.6 }}>
      <List.Item.Meta
        title={<span style={titleStyle}>{inst.provider_label}</span>}
        description={
          <Space direction="vertical" size={2}>
            <ProtocolMeta inst={inst} />
            <Typography.Text type="secondary">{t('portal:instance.noAccess')}</Typography.Text>
          </Space>
        }
      />
      <Space style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid var(--ant-color-border-secondary)', width: '100%' }}>
        <Button onClick={onRequest} loading={requesting}>{t('portal:instance.requestAccess')}</Button>
      </Space>
    </List.Item>
  );
}

// Connect/disconnect history for the user's own devices only (see
// api_portal.go apiPortalConnectionHistory -- scoped server-side via
// peer_owner, never accepts a provider/peer_id the client could use to
// probe someone else's devices).
function ConnectionHistoryCard() {
  const { t } = useTranslation(['portal', 'common']);
  const [events, setEvents] = useState<PortalConnectionEvent[] | null>(null);

  useEffect(() => {
    HttpUtil.get<PortalConnectionEvent[]>('/api/portal/connection-history')
      .then((rows) => setEvents(rows ?? []))
      .catch(() => setEvents([]));
  }, []);

  return (
    <Card
      title={<Space><HistoryOutlined />{t('portal:history.title')}</Space>}
      style={{ marginTop: 16 }}
      loading={events === null}
    >
      {events && events.length === 0 && (
        <Typography.Paragraph type="secondary">{t('portal:history.empty')}</Typography.Paragraph>
      )}
      {events && events.length > 0 && (
        <List
          size="small"
          dataSource={events}
          renderItem={(ev) => (
            <List.Item>
              <List.Item.Meta
                title={
                  <Space>
                    {ev.device_name || ev.provider_label}
                    <Tag color={ev.event === 'connect' ? 'success' : 'default'}>
                      {ev.event === 'connect' ? t('portal:history.connect') : t('portal:history.disconnect')}
                    </Tag>
                  </Space>
                }
                description={`${ev.provider_label} · ${new Date(ev.ts).toLocaleString()}`}
              />
            </List.Item>
          )}
        />
      )}
    </Card>
  );
}

function PortalHome({ me, onLoggedOut, onRefresh }: { me: PortalMe; onLoggedOut: () => void; onRefresh: () => void }) {
  const { t } = useTranslation(['portal', 'common']);
  const { isDark, toggleTheme } = useTheme();
  const { lang, toggleLang, setLang } = useLang();
  const [qrInstance, setQrInstance] = useState<PortalInstance | null>(null);
  const [manualInstance, setManualInstance] = useState<PortalInstance | null>(null);
  const [manualText, setManualText] = useState('');
  const [manualLoading, setManualLoading] = useState(false);

  async function onManualSetup(inst: PortalInstance) {
    setManualInstance(inst);
    setManualText('');
    setManualLoading(true);
    try {
      const res = await HttpUtil.get<{ text: string }>(manualConfigUrl(inst));
      setManualText(res.text);
    } catch (e) {
      setManualText(e instanceof ApiError ? e.message : String(e));
    } finally {
      setManualLoading(false);
    }
  }

  // Apply the account's saved language preference once, on load -- same
  // reasoning as AppSidebar's equivalent effect: a portal user's choice
  // should follow them across devices/browsers, not just this browser's
  // localStorage.
  const appliedAccountLang = useRef(false);
  useEffect(() => {
    if (appliedAccountLang.current || !me.language) return;
    appliedAccountLang.current = true;
    if (me.language !== lang) setLang(me.language as 'ru' | 'en');
  }, [me.language, lang, setLang]);

  function onToggleLang() {
    const next = lang === 'en' ? 'ru' : 'en';
    toggleLang();
    HttpUtil.put('/api/account/language', { language: next }).catch(() => {});
  }
  const [pwOpen, setPwOpen] = useState(me.password_expired);
  const [pwForm] = Form.useForm();
  const [pwLoading, setPwLoading] = useState(false);
  const [passwordPolicy, setPasswordPolicy] = useState<PasswordPolicySettings | null>(null);
  useEffect(() => {
    HttpUtil.get<PasswordPolicySettings>('/api/portal/password-policy').then(setPasswordPolicy).catch(() => {});
  }, []);

  // 2FA: mirrors AccountPage.tsx's enroll/disable flow (same
  // /api/account/2fa/* endpoints -- already reachable for role=="user",
  // no backend change needed), just inlined here rather than via
  // react-query hooks since this standalone entry has no QueryClientProvider.
  const [totpEnrollOpen, setTotpEnrollOpen] = useState(false);
  const [totpEnroll, setTotpEnroll] = useState<{ secret: string; qr_png: string } | null>(null);
  const [totpEnrollLoading, setTotpEnrollLoading] = useState(false);
  const [enrollForm] = Form.useForm();
  const [totpDisableOpen, setTotpDisableOpen] = useState(false);
  const [totpDisableLoading, setTotpDisableLoading] = useState(false);
  const [disableForm] = Form.useForm();

  async function onChangePassword(values: { current_password: string; new_password: string; confirm_password: string }) {
    setPwLoading(true);
    try {
      await HttpUtil.post('/api/account', { current_password: values.current_password, new_password: values.new_password });
      message.success(t('portal:password.changed'));
      pwForm.resetFields();
      setPwOpen(false);
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : t('portal:password.changeError'));
    } finally {
      setPwLoading(false);
    }
  }

  async function onLogout() {
    await HttpUtil.post('/api/logout').catch(() => {});
    onLoggedOut();
  }

  async function onStartTotpEnroll() {
    try {
      const res = await HttpUtil.post<{ secret: string; qr_png: string }>('/api/account/2fa/setup');
      setTotpEnroll(res);
      setTotpEnrollOpen(true);
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : t('portal:totp.setupError'));
    }
  }

  async function onConfirmTotpEnroll() {
    if (!totpEnroll) return;
    setTotpEnrollLoading(true);
    try {
      const { code } = await enrollForm.validateFields();
      await HttpUtil.post('/api/account/2fa/enable', { secret: totpEnroll.secret, code });
      setTotpEnrollOpen(false);
      enrollForm.resetFields();
      message.success(t('portal:totp.enableSuccess'));
      onRefresh();
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    } finally {
      setTotpEnrollLoading(false);
    }
  }

  async function onConfirmTotpDisable() {
    setTotpDisableLoading(true);
    try {
      const { password } = await disableForm.validateFields();
      await HttpUtil.post('/api/account/2fa/disable', { password });
      setTotpDisableOpen(false);
      disableForm.resetFields();
      message.success(t('portal:totp.disableSuccess'));
      onRefresh();
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    } finally {
      setTotpDisableLoading(false);
    }
  }

  // Password/theme/logout are secondary to "my devices" -- tucked behind
  // one avatar menu (same pattern as the admin sidebar's avatar dropdown)
  // instead of top-level buttons/cards competing with the device list.
  const menuItems: MenuProps['items'] = [
    { key: 'password', icon: <LockOutlined />, label: t('portal:password.title'), onClick: () => setPwOpen(true) },
    {
      key: 'totp',
      icon: <SafetyOutlined />,
      label: t('portal:totp.menuItem'),
      onClick: () => (me.totp_enabled ? setTotpDisableOpen(true) : onStartTotpEnroll()),
    },
    {
      key: 'theme',
      icon: isDark ? <BulbOutlined /> : <MoonOutlined />,
      label: isDark ? t('common:nav.lightTheme') : t('common:nav.darkTheme'),
      onClick: toggleTheme,
    },
    {
      key: 'lang',
      icon: <TranslationOutlined />,
      label: lang === 'ru' ? 'English' : 'Русский',
      onClick: onToggleLang,
    },
    { type: 'divider' },
    { key: 'logout', icon: <LogoutOutlined />, label: t('common:actions.logout'), danger: true, onClick: onLogout },
  ];

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <div style={{ maxWidth: 1000, margin: '0 auto', padding: 24, width: '100%', position: 'relative' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
          <ProteanBrand size="xl" />
          <Dropdown menu={{ items: menuItems }} trigger={['click']} placement="bottomRight">
            <Space style={{ cursor: 'pointer' }}>
              <Avatar size="small" icon={<UserOutlined />} />
              <Typography.Text>{me.username}</Typography.Text>
            </Space>
          </Dropdown>
        </div>
        <Typography.Paragraph type="secondary">{t('portal:home.loggedInAs', { username: me.username })}</Typography.Paragraph>
        <InsecureConnectionBanner />
        {me.password_expired && (
          <Alert type="warning" showIcon message={t('portal:password.expired')} style={{ marginBottom: 16 }} />
        )}

        {me.instances.length > 0 && (
          <Row gutter={12} style={{ marginBottom: 16 }}>
            <Col span={8}>
              <Card size="small">
                <Statistic
                  title={t('portal:home.statsAvailable')}
                  value={me.instances.filter((i) => i.state === 'granted').length}
                  valueStyle={{ color: 'var(--ant-color-success)' }}
                />
              </Card>
            </Col>
            <Col span={8}>
              <Card size="small">
                <Statistic
                  title={t('portal:home.statsPending')}
                  value={me.instances.filter((i) => i.state === 'pending').length}
                />
              </Card>
            </Col>
            <Col span={8}>
              <Card size="small">
                <Statistic
                  title={t('portal:home.statsDenied')}
                  value={me.instances.filter((i) => i.state === 'denied').length}
                  valueStyle={me.instances.some((i) => i.state === 'denied') ? { color: 'var(--ant-color-error)' } : undefined}
                />
              </Card>
            </Col>
          </Row>
        )}

        <Card title={t('portal:home.myDevices')}>
          {me.instances.length === 0 && (
            <Typography.Paragraph type="secondary">
              {t('portal:home.noInstances')}
            </Typography.Paragraph>
          )}
          <List
            dataSource={me.instances}
            renderItem={(inst) => <InstanceRow inst={inst} onRefresh={onRefresh} onQr={setQrInstance} onManualSetup={onManualSetup} />}
          />
        </Card>

        <ConnectionHistoryCard />
      </div>

      <Modal title={t('portal:instance.qrCode')} open={!!qrInstance} onCancel={() => setQrInstance(null)} footer={null}>
        {qrInstance && (
          <div style={{ textAlign: 'center' }}>
            <Image src={qrUrl(qrInstance)} alt="QR" preview={false} />
          </div>
        )}
      </Modal>

      <Modal
        title={t('portal:instance.manualSetup')}
        open={!!manualInstance}
        onCancel={() => setManualInstance(null)}
        footer={<Button onClick={() => setManualInstance(null)}>{t('common:actions.close')}</Button>}
        width={640}
      >
        <Typography.Paragraph type="secondary">{t('portal:instance.manualSetupHint')}</Typography.Paragraph>
        <Typography.Paragraph copyable={!manualLoading ? { text: manualText } : false}>
          <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, fontSize: 13 }}>
            {manualLoading ? t('common:actions.loading') : manualText}
          </pre>
        </Typography.Paragraph>
      </Modal>

      <Modal title={t('portal:password.title')} open={pwOpen} onCancel={() => setPwOpen(false)} footer={null}>
        <PasswordPolicyHint policy={passwordPolicy} />
        <Form form={pwForm} layout="vertical" onFinish={onChangePassword} disabled={pwLoading}>
          <Form.Item name="current_password" label={t('portal:password.currentPassword')} rules={[{ required: true }]}>
            <Input.Password />
          </Form.Item>
          <Form.Item
            name="new_password"
            label={t('portal:password.newPassword')}
            dependencies={['confirm_password']}
            rules={[
              { required: true },
              {
                validator: (_, value: string) => {
                  if (!passwordPolicy || !value) return Promise.resolve();
                  const issues = passwordPolicyIssues(passwordPolicy, value);
                  if (issues.length === 0) return Promise.resolve();
                  return Promise.reject(new Error(t('common:passwordPolicy.missing', { list: issues.map((k) => t(`common:passwordPolicy.${k}`)).join(', ') })));
                },
              },
            ]}
          >
            <Input.Password />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            label={t('common:passwordPolicy.confirmPassword')}
            dependencies={['new_password']}
            rules={[
              { required: true, message: t('common:passwordPolicy.confirmRequired') },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue('new_password') === value) return Promise.resolve();
                  return Promise.reject(new Error(t('common:passwordPolicy.confirmMismatch')));
                },
              }),
            ]}
          >
            <Input.Password />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={pwLoading}>{t('portal:password.title')}</Button>
        </Form>
      </Modal>

      <Modal
        title={t('portal:totp.enableModalTitle')}
        open={totpEnrollOpen}
        onCancel={() => setTotpEnrollOpen(false)}
        onOk={onConfirmTotpEnroll}
        confirmLoading={totpEnrollLoading}
      >
        {totpEnroll && (
          <Space orientation="vertical" align="center" style={{ width: '100%' }}>
            <Image src={totpEnroll.qr_png} width={200} preview={false} />
            <code>{totpEnroll.secret}</code>
            <Form form={enrollForm} layout="vertical" style={{ width: '100%' }}>
              <Form.Item name="code" label={t('portal:totp.codeLabel')} rules={[{ required: true, len: 6 }]}>
                <Input maxLength={6} />
              </Form.Item>
            </Form>
          </Space>
        )}
      </Modal>

      <Modal
        title={t('portal:totp.disableModalTitle')}
        open={totpDisableOpen}
        onCancel={() => setTotpDisableOpen(false)}
        onOk={onConfirmTotpDisable}
        confirmLoading={totpDisableLoading}
      >
        <Form form={disableForm} layout="vertical">
          <Form.Item name="password" label={t('portal:totp.passwordLabel')} rules={[{ required: true }]}>
            <Input.Password />
          </Form.Item>
        </Form>
      </Modal>
    </Layout>
  );
}

export function PortalApp() {
  const { antdThemeConfig } = useTheme();
  const { antdLocale } = useLang();
  const [me, setMe] = useState<PortalMe | null>(null);
  const [checked, setChecked] = useState(false);

  // Deliberately a raw fetch, not HttpUtil: HttpUtil's 401 handler redirects
  // to /portal.html (this same page) on any protected-route 401, which would
  // reload-loop forever on the very probe used to decide "not logged in yet".
  async function checkSession() {
    try {
      const res = await fetch('/api/portal/me', { credentials: 'same-origin' });
      if (res.status === 200) {
        const env = (await res.json()) as { obj?: PortalMe };
        // instances is a Go nil slice with nothing registered -> JSON null,
        // not []. Normalize here once instead of null-guarding every use.
        setMe(env.obj ? { ...env.obj, instances: env.obj.instances ?? [] } : null);
      } else {
        setMe(null);
      }
    } catch {
      setMe(null);
    } finally {
      setChecked(true);
    }
  }

  useEffect(() => {
    checkSession();
  }, []);

  if (!checked) return null;

  return (
    <ConfigProvider theme={antdThemeConfig} locale={antdLocale}>
      {me
        ? <PortalHome me={me} onLoggedOut={() => setMe(null)} onRefresh={checkSession} />
        : <PortalLogin onLoggedIn={checkSession} />}
    </ConfigProvider>
  );
}
