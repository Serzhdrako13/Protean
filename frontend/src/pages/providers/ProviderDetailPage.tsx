import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  Card, Table, Tag, Switch, Button, Space, Modal, Form, Input, InputNumber,
  Popconfirm, message, Descriptions, Radio, Image, Skeleton, Empty, Progress, Row, Col, Tabs, Select, Alert, Typography, Tooltip,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import {
  PlusOutlined, QrcodeOutlined, DownloadOutlined, SyncOutlined,
  DeleteOutlined, EditOutlined, BellOutlined, BellFilled, ArrowLeftOutlined, FileTextOutlined,
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { PageShell } from '@/layouts/PageShell';
import { PageTitleBar } from '@/components/PageTitleBar';
import { useProviderDetailQuery, useTrafficQuery, usePeerMutations, useProviderSetupMutation } from '@/api/queries/providers';
import { usePortalUsersQuery, usePeerOwnerMutation } from '@/api/queries/users';
import { useNodesQuery, useNodeOwnerMutation } from '@/api/queries/nodes';
import { Sparkline } from '@/components/viz/Sparkline';
import { PollIntervalSelect } from '@/components/viz/PollIntervalSelect';
import { HeaderTip } from '@/components/HeaderTip';
import { XrayPage } from '@/pages/xray/XrayPage';
import { ProviderSettingsPanel } from '@/pages/providers/ProviderSettingsPanel';
import { ApiError, HttpUtil } from '@/api/http-init';
import type { Peer } from '@/types/api';
import { splitAllowedIPs } from '@/utils/address';
import { useTableSearch } from '@/hooks/useTableSearch';
import { TableSearch } from '@/components/TableSearch';
import { textSorter, numSorter, dateSorter } from '@/utils/tableSort';

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

function timeAgo(iso: string, t: TFunction): string {
  if (!iso || iso.startsWith('0001-01-01')) return t('provider-detail:time.never');
  const d = Date.now() - new Date(iso).getTime();
  if (d < 60_000) return t('provider-detail:time.secondsAgo', { n: Math.floor(d / 1000) });
  if (d < 3_600_000) return t('provider-detail:time.minutesAgo', { n: Math.floor(d / 60_000) });
  if (d < 86_400_000) return t('provider-detail:time.hoursAgo', { n: Math.floor(d / 3_600_000) });
  return new Date(iso).toLocaleString('ru-RU');
}

function expiryTag(iso: string, t: TFunction) {
  if (!iso || iso.startsWith('0001-01-01')) return null;
  const daysLeft = (new Date(iso).getTime() - Date.now()) / 86_400_000;
  const color = daysLeft <= 0 ? 'error' : daysLeft <= 7 ? 'warning' : 'default';
  return <Tag color={color}>⏳ {timeAgo(iso, t)}</Tag>;
}

const RANGE_KEYS = ['1h', '6h', '24h', '3d'] as const;
const MANUAL_SETUP_TYPES = new Set(['wireguard', 'amneziawg', 'openvpn']);

export function ProviderDetailPage() {
  const { t } = useTranslation(['provider-detail', 'common']);
  const { provider = '' } = useParams();
  const navigate = useNavigate();
  // Provider keys are "serverId:localName" — back goes to that server's
  // provider list (where this page is always reached from), falling back to
  // the server list itself if the key is somehow unscoped.
  const serverId = provider.includes(':') ? provider.split(':')[0] : '';
  const backTo = serverId ? `/servers/${serverId}/providers` : '/servers';
  const { data, isLoading } = useProviderDetailQuery(provider);
  const [range, setRange] = useState('1h');
  const [pollMs, setPollMs] = useState(60_000);
  const { data: traffic } = useTrafficQuery(provider, range, pollMs);
  const mut = usePeerMutations(provider);
  const setup = useProviderSetupMutation(provider);
  const { data: portalUsers } = usePortalUsersQuery();
  const { data: nodes } = useNodesQuery();
  const ownerMut = usePeerOwnerMutation(provider);
  const nodeOwnerMut = useNodeOwnerMutation(provider);

  async function onSetup() {
    try {
      await setup.mutateAsync();
      message.success(t('provider-detail:messages.serverConfigured'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Peer | null>(null);
  const [qrPeer, setQrPeer] = useState<Peer | null>(null);
  const [manualPeer, setManualPeer] = useState<Peer | null>(null);
  const [linkedRequestId, setLinkedRequestId] = useState<number | null>(null);
  const [form] = Form.useForm();
  const [importOpen, setImportOpen] = useState(false);
  const [importForm] = Form.useForm();
  const { query: peerQuery, setQuery: setPeerQuery, filtered: filteredPeers } = useTableSearch(data?.peers, (p) => p.Name);

  // Adopts an already-issued client certificate (e.g. a client from a VPN
  // server being taken over by the panel) instead of issuing a new one --
  // only meaningful once the provider's CA is the one that actually signed
  // it (see CACard's CA-import flow on the Settings tab).
  async function onImportPeer() {
    try {
      const values = await importForm.validateFields();
      await mut.importPeer.mutateAsync({ cert_pem: values.cert_pem, key_pem: values.key_pem || undefined });
      setImportOpen(false);
      importForm.resetFields();
      message.success(t('provider-detail:modals.importPeer.importedMessage'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  function openCreate() {
    setEditing(null);
    setLinkedRequestId(null);
    form.resetFields();
    setFormOpen(true);
  }

  // Opened from the "одобрен, ждёт настройки" banner below — prefills the
  // client name and threads access_request_id through so the backend
  // assigns ownership + marks the request granted once the peer checks out.
  function openCreateForRequest(requestId: number, username: string) {
    setEditing(null);
    setLinkedRequestId(requestId);
    form.resetFields();
    form.setFieldsValue({ name: username });
    setFormOpen(true);
  }

  function openEdit(peer: Peer) {
    setEditing(peer);
    form.setFieldsValue({
      name: peer.Name,
      client_address: peer.AllowedIPs?.[0] ?? '',
      keepalive: peer.PersistentKeepalive,
      category: peer.Category || 'client',
    });
    setFormOpen(true);
  }

  async function onSubmit() {
    try {
      const values = await form.validateFields();
      if (editing) {
        await mut.update.mutateAsync({ id: editing.URLID, ...values, subnet_ids: [] });
      } else {
        await mut.create.mutateAsync({
          ...values, subnet_ids: [], own_public_key: values.own_public_key || '', client_csr: values.client_csr || '',
          expire_days: values.expire_days || 0, access_request_id: linkedRequestId ?? undefined,
        });
      }
      setFormOpen(false);
      setLinkedRequestId(null);
      message.success(t('common:actions.saved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  const columns: ColumnsType<Peer> = [
    {
      title: t('provider-detail:table.columns.name'),
      key: 'name',
      sorter: textSorter((p: Peer) => p.Name || nodes?.find((n) => n.id === p.NodeOwnerID)?.name || ''),
      render: (_: unknown, p: Peer) => {
        // An adopted peer promoted to equipment via network detection never
        // gets its own conf-side name rewritten (Protean never touches an
        // existing hand-authored config) -- fall back to the owning Node's
        // name so the row doesn't read as blank with just a "Сайт" tag
        // hanging where the name should be.
        const displayName = p.Name || (p.NodeOwnerID ? nodes?.find((n) => n.id === p.NodeOwnerID)?.name : undefined) || '—';
        return (
          <span>
            {displayName}
            {p.Category === 'site' && <Tag style={{ marginLeft: 6 }}>{t('provider-detail:table.siteTag')}</Tag>}
            {expiryTag(p.ExpiresAt, t) && <div>{expiryTag(p.ExpiresAt, t)}</div>}
          </span>
        );
      },
    },
    {
      title: t('provider-detail:table.columns.status'),
      key: 'status',
      filters: [
        { text: t('provider-detail:table.status.online'), value: 'online' },
        { text: t('provider-detail:table.status.offline'), value: 'offline' },
        { text: t('provider-detail:table.status.disabled'), value: 'disabled' },
      ],
      onFilter: (value, p: Peer) => (p.Disabled ? 'disabled' : p.Online ? 'online' : 'offline') === value,
      sorter: numSorter((p: Peer) => (p.Disabled ? 0 : p.Online ? 2 : 1)),
      render: (_: unknown, p: Peer) =>
        p.Disabled ? (
          <Tag>{t('provider-detail:table.status.disabled')}</Tag>
        ) : p.Online ? (
          <Tag color="success">{t('provider-detail:table.status.online')}</Tag>
        ) : (
          <Tag color="default">{t('provider-detail:table.status.offline')}</Tag>
        ),
    },
    {
      title: <HeaderTip label={t('provider-detail:table.columns.address.label')} tip={t('provider-detail:table.columns.address.tip')} />,
      key: 'address',
      render: (_: unknown, p: Peer) => {
        const { ownAddress, subnets } = splitAllowedIPs(p.AllowedIPs);
        if (!ownAddress && subnets.length === 0) return '—';
        return (
          <span>
            {ownAddress && <code>{ownAddress}</code>}
            {subnets.length > 0 && (
              <Tooltip title={subnets.join(', ')}>
                <Tag style={{ marginLeft: ownAddress ? 6 : 0 }}>+{subnets.length} {t('provider-detail:table.columns.address.subnets')}</Tag>
              </Tooltip>
            )}
          </span>
        );
      },
    },
    {
      title: <HeaderTip label={t('provider-detail:table.columns.endpoint.label')} tip={t('provider-detail:table.columns.endpoint.tip')} />,
      dataIndex: 'Endpoint',
      key: 'endpoint',
    },
    {
      title: <HeaderTip label={t('provider-detail:table.columns.handshake.label')} tip={t('provider-detail:table.columns.handshake.tip')} />,
      key: 'handshake',
      sorter: dateSorter((p: Peer) => p.LastHandshake),
      render: (_: unknown, p: Peer) => (p.Disabled ? '' : timeAgo(p.LastHandshake, t)),
    },
    {
      title: t('provider-detail:table.columns.traffic'),
      key: 'traffic',
      sorter: numSorter((p: Peer) => p.RxBytes + p.TxBytes),
      render: (_: unknown, p: Peer) =>
        p.Disabled ? '' : (
          <span>
            <Tag color="blue">↓{formatBytes(p.RxBytes)}</Tag>
            <Tag color="purple">↑{formatBytes(p.TxBytes)}</Tag>
          </span>
        ),
    },
    {
      title: <HeaderTip label={t('provider-detail:table.columns.owner.label')} tip={t('provider-detail:table.columns.owner.tip')} />,
      key: 'owner',
      render: (_: unknown, p: Peer) => {
        // Composite "u:<id>"/"n:<id>" values disambiguate the two owner
        // kinds, which live in separate tables (peer_owner/node_peer) --
        // see ProviderDetailPage's plan notes. A peer has at most one
        // owner of either kind (enforced server-side); switching kinds
        // clears the old one first.
        const value = p.OwnerUserID ? `u:${p.OwnerUserID}` : p.NodeOwnerID ? `n:${p.NodeOwnerID}` : undefined;
        async function onChange(v?: string) {
          if (p.NodeOwnerID) await nodeOwnerMut.mutateAsync({ peerId: p.URLID, nodeId: 0 });
          if (p.OwnerUserID) await ownerMut.mutateAsync({ peerId: p.URLID, userId: 0 });
          if (!v) return;
          const [kind, idStr] = v.split(':');
          const id = Number(idStr);
          if (kind === 'u') await ownerMut.mutateAsync({ peerId: p.URLID, userId: id });
          else await nodeOwnerMut.mutateAsync({ peerId: p.URLID, nodeId: id });
        }
        return (
          <Select
            size="small"
            allowClear
            style={{ minWidth: 160 }}
            placeholder={t('provider-detail:table.owner.unassigned')}
            value={value}
            options={[
              { label: t('provider-detail:table.owner.groupUsers'), options: (portalUsers ?? []).map((u) => ({ value: `u:${u.id}`, label: u.username })) },
              { label: t('provider-detail:table.owner.groupNodes'), options: (nodes ?? []).map((n) => ({ value: `n:${n.id}`, label: n.name })) },
            ]}
            onChange={onChange}
            onClear={() => onChange(undefined)}
            disabled={p.Disabled}
          />
        );
      },
    },
    {
      title: t('provider-detail:table.columns.enabled'),
      key: 'enabled',
      render: (_: unknown, p: Peer) => (
        <Switch
          checked={!p.Disabled}
          onChange={(checked) => (checked ? mut.enable.mutate(p.URLID) : mut.disable.mutate(p.URLID))}
          title={p.Disabled ? t('provider-detail:table.enableSwitch.enableTitle') : t('provider-detail:table.enableSwitch.disableTitle')}
        />
      ),
    },
    {
      title: '',
      key: 'actions',
      render: (_: unknown, p: Peer) =>
        p.Disabled ? (
          <Popconfirm title={t('provider-detail:table.actions.confirmDeleteDisabled', { name: p.Name })} onConfirm={() => mut.remove.mutate(p.URLID)}>
            <Button size="small" danger icon={<DeleteOutlined />} title={t('provider-detail:table.actions.deletePermanently')} />
          </Popconfirm>
        ) : (
          <Space>
            <Button size="small" icon={<EditOutlined />} onClick={() => openEdit(p)} title={t('common:actions.edit')} />
            <Button
              size="small"
              icon={<DownloadOutlined />}
              onClick={() => window.open(`/api/providers/${encodeURIComponent(provider)}/peers/${p.URLID}/config`, '_blank')}
              title={t('provider-detail:table.actions.downloadConfig')}
            />
            <Button size="small" icon={<QrcodeOutlined />} onClick={() => setQrPeer(p)} title={t('provider-detail:table.actions.showQr')} />
            {MANUAL_SETUP_TYPES.has(data?.type ?? '') && (
              <Button size="small" icon={<FileTextOutlined />} onClick={() => setManualPeer(p)} title={t('provider-detail:table.actions.manualSetup')} />
            )}
            <Popconfirm title={t('provider-detail:table.actions.confirmRotate', { name: p.Name })} onConfirm={() => mut.rotate.mutate(p.URLID)}>
              <Button size="small" icon={<SyncOutlined />} title={t('provider-detail:table.actions.rotateKeys')} />
            </Popconfirm>
            <Button
              size="small"
              icon={p.Muted ? <BellFilled /> : <BellOutlined />}
              onClick={() => mut.toggleMute.mutate(p.URLID)}
              title={p.Muted ? t('provider-detail:table.actions.muteOff') : t('provider-detail:table.actions.muteOn')}
            />
            <Popconfirm title={t('provider-detail:table.actions.confirmDelete', { name: p.Name })} onConfirm={() => mut.remove.mutate(p.URLID)}>
              <Button size="small" danger icon={<DeleteOutlined />} title={t('provider-detail:table.actions.deletePermanently')} />
            </Popconfirm>
          </Space>
        ),
    },
  ];

  if (isLoading) {
    return <PageShell><Skeleton active /></PageShell>;
  }
  if (!data) {
    return <PageShell><Empty description={t('provider-detail:notFound')} /></PageShell>;
  }
  if (data.type === 'xray') {
    return (
      <PageShell>
        <PageTitleBar
          prefix={<Button icon={<ArrowLeftOutlined />} onClick={() => navigate(backTo)} title={t('provider-detail:backToProviders')} />}
        >
          {data.provider_label}
        </PageTitleBar>
        <XrayPage provider={provider} />
      </PageShell>
    );
  }

  const overview = (
    <>
      {data.pending_approved_request && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message={t('provider-detail:banners.pendingApproved.message', { username: data.pending_approved_request.username })}
          description={t('provider-detail:banners.pendingApproved.description')}
          action={
            <Button
              size="small"
              type="primary"
              onClick={() => openCreateForRequest(data.pending_approved_request!.request_id, data.pending_approved_request!.username)}
            >
              {t('provider-detail:banners.pendingApproved.createButton')}
            </Button>
          }
        />
      )}
      <Card style={{ marginBottom: 16 }}>
        {data.not_implemented && <p>{t('provider-detail:notImplemented')}</p>}
        {!data.not_implemented && !data.status.Up && (
          <div>
            <p>{data.needs_setup ? t('provider-detail:needsSetup') : t('provider-detail:interfaceDown')}</p>
            {data.needs_setup && (
              <Button type="primary" loading={setup.isPending} onClick={onSetup}>
                {t('provider-detail:setupServerButton')}
              </Button>
            )}
          </div>
        )}
        {data.status.Up && (
          <Row gutter={16} align="middle">
            <Col flex="auto">
              <Descriptions size="small" column={{ xs: 1, sm: 2, md: 4 }}>
                <Descriptions.Item label={<HeaderTip label={t('provider-detail:overview.descriptions.endpoint.label')} tip={t('provider-detail:overview.descriptions.endpoint.tip')} />}>
                  {data.status.Endpoint || '—'}
                </Descriptions.Item>
                <Descriptions.Item label={<HeaderTip label={t('provider-detail:overview.descriptions.publicKey.label')} tip={t('provider-detail:overview.descriptions.publicKey.tip')} />}>
                  <code>{data.status.PublicKey}</code>
                </Descriptions.Item>
                <Descriptions.Item label={t('provider-detail:overview.descriptions.address')}>{data.status.Address}</Descriptions.Item>
                <Descriptions.Item label={t('provider-detail:overview.descriptions.peersOnline')}>{data.status.PeersOnline} / {data.status.PeerCount}</Descriptions.Item>
              </Descriptions>
            </Col>
            <Col flex="none">
              <Progress
                type="dashboard"
                size={72}
                percent={data.status.PeerCount ? Math.round((data.status.PeersOnline / data.status.PeerCount) * 100) : 0}
                format={() => `${data.status.PeersOnline}/${data.status.PeerCount}`}
              />
            </Col>
          </Row>
        )}
      </Card>

      {data.status.Up && (
        <Card
          style={{ marginBottom: 16 }}
          title={t('provider-detail:overview.trafficCardTitle')}
          extra={
            <Space>
              <PollIntervalSelect value={pollMs} onChange={setPollMs} />
              <Radio.Group size="small" value={range} onChange={(e) => setRange(e.target.value)}>
                {RANGE_KEYS.map((r) => (
                  <Radio.Button key={r} value={r}>{t(`provider-detail:ranges.${r}`)}</Radio.Button>
                ))}
              </Radio.Group>
            </Space>
          }
        >
          <Sparkline points={traffic ?? []} />
        </Card>
      )}

      {data.status.Up && <TopClients peers={data.peers ?? []} />}

      {/* The table (incl. owner assignment) shows for any peers the panel
          already knows about even while the interface is down — assigning
          ownership is a DB-only action, it doesn't need a live host.
          Adding a NEW client does need one, so that button stays Up-gated. */}
      {((data.peers?.length ?? 0) > 0 || data.status.Up) && (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
            <TableSearch value={peerQuery} onChange={setPeerQuery} placeholder={t('provider-detail:table.searchPlaceholder')} />
            {data.status.Up && (
              <Space>
                {data.cert_based && (
                  <Button onClick={() => setImportOpen(true)}>{t('provider-detail:overview.importPeerButton')}</Button>
                )}
                <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>{t('provider-detail:overview.addClientButton')}</Button>
              </Space>
            )}
          </div>
          <Table
            rowKey="URLID"
            columns={columns}
            dataSource={filteredPeers ?? []}
            pagination={{ pageSize: 20, showSizeChanger: true }}
            scroll={{ x: true }}
          />
        </>
      )}
    </>
  );

  return (
    <PageShell>
      <PageTitleBar
        prefix={<Button icon={<ArrowLeftOutlined />} onClick={() => navigate(backTo)} title={t('provider-detail:backToProviders')} />}
      >
        {data.provider_label}
      </PageTitleBar>

      <Tabs
        defaultActiveKey="overview"
        items={[
          { key: 'overview', label: t('provider-detail:tabs.overview'), children: overview },
          {
            key: 'settings',
            label: t('provider-detail:tabs.settings'),
            children: (
              <ProviderSettingsPanel
                provider={provider}
                type={data.type}
                certBased={data.cert_based}
                supportsBackups={data.supports_backups}
              />
            ),
          },
        ]}
      />

      <Modal
        title={editing ? t('provider-detail:modals.form.editTitle', { name: editing.Name }) : t('provider-detail:modals.form.createTitle')}
        open={formOpen}
        onCancel={() => setFormOpen(false)}
        onOk={onSubmit}
        confirmLoading={mut.create.isPending || mut.update.isPending}
        destroyOnHidden
      >
        <Form form={form} layout="vertical">
          <Form.Item name="name" label={t('provider-detail:modals.form.fields.name')} rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="client_address" label={t('provider-detail:modals.form.fields.clientAddress')} rules={[{ required: true }]}>
            <Input placeholder="10.10.0.5/32" />
          </Form.Item>
          <Form.Item name="keepalive" label={t('provider-detail:modals.form.fields.keepalive')} initialValue={25}>
            <InputNumber min={0} style={{ width: '100%' }} />
          </Form.Item>
          {!editing && (
            <Form.Item name="expire_days" label={t('provider-detail:modals.form.fields.expireDays')} initialValue={0}>
              <InputNumber min={0} style={{ width: '100%' }} />
            </Form.Item>
          )}
          <Form.Item name="category" label={t('provider-detail:modals.form.fields.category')} initialValue="client">
            <Radio.Group>
              <Radio value="client">{t('provider-detail:modals.form.categoryOptions.client')}</Radio>
              <Radio value="site">{t('provider-detail:modals.form.categoryOptions.site')}</Radio>
            </Radio.Group>
          </Form.Item>
          {!editing && (
            <Form.Item name="own_public_key" label={t('provider-detail:modals.form.fields.ownPublicKey')}>
              <Input placeholder={t('provider-detail:modals.form.ownPublicKeyPlaceholder')} />
            </Form.Item>
          )}
        </Form>
      </Modal>

      <Modal
        title={t('provider-detail:modals.importPeer.title')}
        open={importOpen}
        onCancel={() => setImportOpen(false)}
        onOk={onImportPeer}
        confirmLoading={mut.importPeer.isPending}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          {t('provider-detail:modals.importPeer.description')}
        </Typography.Paragraph>
        <Form form={importForm} layout="vertical">
          <Form.Item name="cert_pem" label={t('provider-detail:modals.importPeer.certPem')} rules={[{ required: true }]}>
            <Input.TextArea rows={6} placeholder="-----BEGIN CERTIFICATE-----" />
          </Form.Item>
          <Form.Item name="key_pem" label={t('provider-detail:modals.importPeer.keyPem')} tooltip={t('provider-detail:modals.importPeer.keyPemTooltip')}>
            <Input.TextArea rows={6} placeholder="-----BEGIN PRIVATE KEY-----" />
          </Form.Item>
        </Form>
      </Modal>

      <QrModal peer={qrPeer} provider={provider} onClose={() => setQrPeer(null)} />
      <ManualSetupModal peer={manualPeer} provider={provider} onClose={() => setManualPeer(null)} />
    </PageShell>
  );
}

// Top clients by traffic (Rx+Tx) — a quick "who's using this VPN the most"
// glance without having to eyeball the full table and sort it mentally.
function TopClients({ peers }: { peers: Peer[] }) {
  const { t } = useTranslation(['provider-detail', 'common']);
  const ranked = peers
    .filter((p) => !p.Disabled)
    .map((p) => ({ peer: p, total: p.RxBytes + p.TxBytes }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 5);
  const max = ranked[0]?.total || 1;

  if (ranked.length === 0) return null;

  return (
    <Card title={t('provider-detail:overview.topClientsCardTitle')} style={{ marginBottom: 16 }}>
      <Space orientation="vertical" style={{ width: '100%' }} size={10}>
        {ranked.map(({ peer, total }) => (
          <div key={peer.URLID}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 2 }}>
              <span>{peer.Name}</span>
              <span style={{ color: 'var(--ant-color-text-tertiary)' }}>
                ↓{formatBytes(peer.RxBytes)} ↑{formatBytes(peer.TxBytes)}
              </span>
            </div>
            <Progress percent={Math.round((total / max) * 100)} showInfo={false} size="small" />
          </div>
        ))}
      </Space>
    </Card>
  );
}

function ManualSetupModal({ peer, provider, onClose }: { peer: Peer | null; provider: string; onClose: () => void }) {
  const { t } = useTranslation(['provider-detail', 'common']);
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!peer) return;
    setText('');
    setLoading(true);
    HttpUtil.get<{ text: string }>(`/api/providers/${encodeURIComponent(provider)}/peers/${peer.URLID}/config/text`)
      .then((res) => setText(res.text))
      .catch((e) => setText(e instanceof ApiError ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, [peer, provider]);

  return (
    <Modal
      title={peer ? t('provider-detail:modals.manualSetup.title', { name: peer.Name }) : ''}
      open={!!peer}
      onCancel={onClose}
      footer={<Button onClick={onClose}>{t('common:actions.close')}</Button>}
      width={640}
    >
      <Typography.Paragraph copyable={!loading ? { text } : false}>
        <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, fontSize: 13 }}>
          {loading ? t('common:actions.loading') : text}
        </pre>
      </Typography.Paragraph>
    </Modal>
  );
}

function QrModal({ peer, provider, onClose }: { peer: Peer | null; provider: string; onClose: () => void }) {
  const { t } = useTranslation(['provider-detail']);
  return (
    <Modal title={peer ? t('provider-detail:modals.qr.title', { name: peer.Name }) : ''} open={!!peer} onCancel={onClose} footer={null}>
      {peer && (
        <div style={{ textAlign: 'center' }}>
          <Image
            src={`/api/providers/${encodeURIComponent(provider)}/peers/${peer.URLID}/qr`}
            alt="QR"
            preview={false}
          />
        </div>
      )}
    </Modal>
  );
}

