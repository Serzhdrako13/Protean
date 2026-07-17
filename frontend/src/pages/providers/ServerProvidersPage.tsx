import { useState } from 'react';
import { Table, Tag, Button, Space, Modal, Form, Input, InputNumber, Select, Popconfirm, message, Typography, Switch } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { ArrowLeftOutlined, DownloadOutlined, PlusOutlined, DeleteOutlined, EditOutlined } from '@ant-design/icons';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import { PageShell } from '@/layouts/PageShell';
import { useProvidersQuery, useProviderSetupMutation } from '@/api/queries/providers';
import { useProviderSettingsMutations } from '@/api/queries/network';
import { useServerInstanceMutations } from '@/api/queries/serverInstances';
import { useInstallStatusQuery, useInstallMutation } from '@/api/queries/install';
import type { ProviderSummary } from '@/types/api';
import { HeaderTip } from '@/components/HeaderTip';
import { PageTitleBar } from '@/components/PageTitleBar';
import { ApiError, HttpUtil } from '@/api/http-init';
import { TableSearch } from '@/components/TableSearch';
import { useTableSearch } from '@/hooks/useTableSearch';
import { useHideDownProviders } from '@/hooks/useHideDownProviders';
import { textSorter } from '@/utils/tableSort';

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

const PROVIDER_TYPES = [
  { value: 'wireguard', label: 'WireGuard' },
  { value: 'amneziawg', label: 'AmneziaWG' },
  { value: 'openvpn', label: 'OpenVPN' },
  { value: 'ikev2', label: 'IKEv2' },
  { value: 'xray', label: 'Xray' },
];

// ikev2/xray are capped at one instance per server host-side (see
// singleInstanceTypes in the Go backend) — hide "Добавить" for them once
// one already exists, rather than let the request 400.
const SINGLE_INSTANCE_TYPES = new Set(['ikev2', 'xray']);

function splitKey(key: string): { server: string; local: string } {
  const i = key.indexOf(':');
  return i >= 0 ? { server: key.slice(0, i), local: key.slice(i + 1) } : { server: '', local: key };
}

// Clicking the status tag starts/stops the provider's service directly --
// no need to open the provider page just to restart something.
function StatusCell({ r }: { r: ProviderSummary }) {
  const { t } = useTranslation(['server-providers']);
  const { serviceAction } = useProviderSettingsMutations(r.key);
  const qc = useQueryClient();
  const up = r.status.Up;

  async function onToggle() {
    try {
      await serviceAction.mutateAsync(up ? 'stop' : 'start');
      await qc.invalidateQueries({ queryKey: ['providers'] });
      message.success(t(up ? 'messages.serviceStopped' : 'messages.serviceStarted'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  return (
    <Popconfirm title={t(up ? 'tooltips.confirmStop' : 'tooltips.confirmStart', { label: r.friendly_label || splitKey(r.key).local })} onConfirm={onToggle}>
      <Tag color={up ? 'success' : 'error'} style={{ cursor: 'pointer' }}>
        {up ? `● UP · ${r.status.PeersOnline}/${r.status.PeerCount}` : '● DOWN'}
      </Tag>
    </Popconfirm>
  );
}

// Rightmost per-row action: "Install/Setup" -- combines two layers an
// admin shouldn't need to know are separate (OS package install +
// interface/cert bring-up) into one click, shown only until the provider
// is actually up. Replaces the old page-level "Установить VPN" button,
// which always applied to the whole server rather than one specific row.
function ProviderSetupCell({
  r, installed, serviceActive, configExists, onInstall,
}: {
  r: ProviderSummary; installed: boolean; serviceActive: boolean; configExists: boolean;
  onInstall: (type: string) => Promise<unknown>;
}) {
  const { t } = useTranslation(['server-providers', 'common']);
  const setup = useProviderSetupMutation(r.key);
  const qc = useQueryClient();
  const [warnOpen, setWarnOpen] = useState(false);

  if (r.status.Up) return null;

  async function doSetup() {
    try {
      if (!installed) await onInstall(r.type);
      await setup.mutateAsync();
      await qc.invalidateQueries({ queryKey: ['providers'] });
      message.success(t('messages.setupDone'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  // Best-effort: the host already looks provisioned for this type (its own
  // service is active, or its conventional config file exists) -- "Set up"
  // would silently replace the CA/config, breaking every existing client
  // unless its CA/CRL was imported first (see the Settings tab CA card).
  function onClick() {
    if (serviceActive || configExists) {
      setWarnOpen(true);
      return;
    }
    void doSetup();
  }

  return (
    <>
      <Button
        size="small"
        icon={<DownloadOutlined />}
        onClick={onClick}
        loading={setup.isPending}
        title={t('tooltips.installVpn')}
      >
        {t('actions.installVpn')}
      </Button>
      <Modal
        title={t('modals.setupWarning.title')}
        open={warnOpen}
        onCancel={() => setWarnOpen(false)}
        onOk={() => { setWarnOpen(false); void doSetup(); }}
        okText={t('modals.setupWarning.confirmProceed')}
        okButtonProps={{ danger: true }}
      >
        <Typography.Paragraph>
          {t('modals.setupWarning.description', { label: r.friendly_label || splitKey(r.key).local })}
        </Typography.Paragraph>
        <Typography.Paragraph type="secondary">{t('modals.setupWarning.hint')}</Typography.Paragraph>
        <Link to={`/providers/${r.key}`}>{t('modals.setupWarning.goToCa')}</Link>
      </Modal>
    </>
  );
}

// Per-server scope of what used to be the flat /providers list — reached
// from a server row's "Провайдеры" button (ServersPage.tsx), since a bare
// list across every server just confused which instance belongs where.
export function ServerProvidersPage() {
  const { t } = useTranslation(['server-providers', 'common']);
  const { id = '' } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data, isLoading } = useProvidersQuery();
  const { create, remove, relabel, setVisibility, redescribe } = useServerInstanceMutations(id);
  const { data: installStatus } = useInstallStatusQuery(id);
  const installMut = useInstallMutation(id);
  const rows = (data ?? []).filter((p) => p.server_id === id);
  const { query, setQuery, filtered } = useTableSearch(rows, (r) => `${r.friendly_label || ''} ${splitKey(r.key).local}`);
  const [hideDown, setHideDown] = useHideDownProviders();
  const visibleRows = hideDown ? (filtered ?? []).filter((r) => r.status.Up) : (filtered ?? []);

  const [addOpen, setAddOpen] = useState(false);
  const [form] = Form.useForm();
  const selectedType = Form.useWatch('type', form);
  // Three-part add flow, deliberately ordered to never leave an orphaned
  // DB row behind a failed package install (explicit direction: verify
  // install FIRST, before anything is saved, so a failure never forces
  // re-entering the whole settings form or risks a local_name collision
  // on retry):
  //   "type"     -- pick just the type, verify/install its OS package.
  //                 Nothing is written to the DB yet -- a failure here is
  //                 a clean retry (or switch type), no row to clean up.
  //   "settings" -- full settings form (package already confirmed
  //                 present). Submitting creates the row AND immediately
  //                 bootstraps the interface in one go, since the
  //                 highest-risk step (package install) is already done.
  //                 A failure at THIS point is the rare/exceptional case
  //                 -- the row now exists and the per-row Install button
  //                 in the table is the fallback, matching how a failure
  //                 should surface.
  const [addStep, setAddStep] = useState<'type' | 'settings'>('type');
  const [checkingInstall, setCheckingInstall] = useState(false);
  const [pendingKey, setPendingKey] = useState('');
  const [settingsError, setSettingsError] = useState('');
  const [bootstrapping, setBootstrapping] = useState(false);
  const qc = useQueryClient();

  const [labelTarget, setLabelTarget] = useState<ProviderSummary | null>(null);
  const [labelForm] = Form.useForm();

  async function onRelabel() {
    if (!labelTarget) return;
    try {
      const { label } = await labelForm.validateFields();
      await relabel.mutateAsync({ localName: splitKey(labelTarget.key).local, label: label ?? '' });
      setLabelTarget(null);
      message.success(t('messages.labelSaved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  const [descriptionTarget, setDescriptionTarget] = useState<ProviderSummary | null>(null);
  const [descriptionForm] = Form.useForm();

  async function onRedescribe() {
    if (!descriptionTarget) return;
    try {
      const { description } = await descriptionForm.validateFields();
      await redescribe.mutateAsync({ localName: splitKey(descriptionTarget.key).local, description: description ?? '' });
      setDescriptionTarget(null);
      message.success(t('messages.descriptionSaved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  const usedTypes = new Set(rows.map((r) => r.type));
  const availableTypes = PROVIDER_TYPES.filter((t) => !SINGLE_INSTANCE_TYPES.has(t.value) || !usedTypes.has(t.value));

  function closeAddModal() {
    setAddOpen(false);
    setAddStep('type');
    setPendingKey('');
    setSettingsError('');
  }

  // Step 1: verify/install the OS package for the chosen type -- BEFORE
  // anything touches the DB, so a failure here (e.g. unsupported distro,
  // network hiccup fetching the package) is a clean retry, never an
  // orphaned server_instances row blocking a same-name retry.
  async function onCheckInstall() {
    try {
      const { type } = await form.validateFields(['type']);
      setCheckingInstall(true);
      const alreadyInstalled = installStatus?.providers.find((p) => p.name === type)?.installed ?? false;
      if (!alreadyInstalled) {
        await installMut.mutateAsync(type);
      }
      setAddStep('settings');
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    } finally {
      setCheckingInstall(false);
    }
  }

  // Step 2: create the row and immediately bootstrap the interface in one
  // go -- the package is already confirmed present, so this is now the
  // low-risk step (pure SSH file write + validated address/port). A
  // failure here is the genuine exceptional case: the row now exists, and
  // the per-row Install button in the table (ProviderSetupCell) is the
  // intended recovery path -- retryable from right here too, with no need
  // to re-enter any settings.
  async function onCreateAndBootstrap() {
    try {
      const values = await form.validateFields();
      const { local_name, type, label, ...rest } = values;
      // Config is a plain map[string]string on the backend -- AntD's
      // InputNumber fields (port/mtu/mssfix) come back as JS numbers,
      // which fail to decode into a Go map[string]string ("cannot
      // unmarshal number into ... of type string"). Stringify here rather
      // than widen the backend's Config type -- it's stored as text
      // either way.
      const config: Record<string, string> = {};
      for (const [k, v] of Object.entries(rest)) {
        if (v === undefined || v === null || v === '') continue;
        config[k] = String(v);
      }
      setSettingsError('');
      if (!pendingKey) {
        await create.mutateAsync({ local_name, type, label, config });
        setPendingKey(`${id}:${local_name}`);
      }
      await runBootstrap(`${id}:${local_name}`);
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function runBootstrap(key: string) {
    setBootstrapping(true);
    try {
      await HttpUtil.post(`/api/providers/${encodeURIComponent(key)}/setup`);
      await qc.invalidateQueries({ queryKey: ['providers'] });
      message.success(t('messages.setupDone'));
      closeAddModal();
    } catch (e) {
      setSettingsError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBootstrapping(false);
    }
  }

  async function onRemove(key: string) {
    try {
      await remove.mutateAsync(splitKey(key).local);
      message.success(t('messages.instanceRemoved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  const columns: ColumnsType<ProviderSummary> = [
    {
      title: t('columns.name'),
      key: 'label',
      sorter: textSorter((r: ProviderSummary) => r.friendly_label || splitKey(r.key).local),
      render: (_: unknown, r: ProviderSummary) => (
        <Link to={`/providers/${r.key}`}>{r.friendly_label || splitKey(r.key).local}</Link>
      ),
    },
    {
      title: t('columns.type'), dataIndex: 'type', key: 'type',
      filters: PROVIDER_TYPES.map((pt) => ({ text: pt.label, value: pt.value })),
      onFilter: (value, r) => r.type === value,
      render: (v: string) => <Tag color="purple">{v}</Tag>,
    },
    {
      title: t('columns.interface'),
      key: 'interface',
      render: (_: unknown, r: ProviderSummary) => (
        <Link to={`/providers/${r.key}`}><code>{splitKey(r.key).local}</code></Link>
      ),
    },
    {
      title: <HeaderTip label={t('columns.status.label')} tip={t('columns.status.tip')} />,
      key: 'status',
      render: (_: unknown, r: ProviderSummary) => <StatusCell r={r} />,
    },
    {
      title: t('columns.traffic'),
      key: 'traffic',
      render: (_: unknown, r: ProviderSummary) => (
        <span>↓{formatBytes(r.status.TotalRxBytes)} ↑{formatBytes(r.status.TotalTxBytes)}</span>
      ),
    },
    {
      title: t('columns.description'),
      key: 'description',
      render: (_: unknown, r: ProviderSummary) => (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>{r.description || '—'}</Typography.Text>
      ),
    },
    {
      title: <HeaderTip label={t('columns.portalVisible.label')} tip={t('columns.portalVisible.tip')} />,
      key: 'portal_visible',
      render: (_: unknown, r: ProviderSummary) => (
        <Switch
          size="small"
          checked={r.portal_visible}
          onChange={(visible) => setVisibility.mutate({ localName: splitKey(r.key).local, visible })}
        />
      ),
    },
    {
      title: '',
      key: 'actions',
      render: (_: unknown, r: ProviderSummary) => (
        <Space>
          <Button
            size="small"
            icon={<EditOutlined />}
            onClick={() => { labelForm.setFieldsValue({ label: r.label }); setLabelTarget(r); }}
            title={t('tooltips.editLabel')}
          />
          <Button
            size="small"
            icon={<EditOutlined />}
            onClick={() => { descriptionForm.setFieldsValue({ description: r.description }); setDescriptionTarget(r); }}
            title={t('tooltips.editDescription')}
          >
            {t('columns.description')}
          </Button>
          <Popconfirm
            title={t('tooltips.removeConfirmTitle', { label: r.label })}
            description={t('tooltips.removeConfirmDescription')}
            onConfirm={() => onRemove(r.key)}
          >
            <Button size="small" danger icon={<DeleteOutlined />} title={t('actions.removeFromPanel')} />
          </Popconfirm>
        </Space>
      ),
    },
    {
      title: '',
      key: 'setup',
      render: (_: unknown, r: ProviderSummary) => {
        const pi = installStatus?.providers.find((p) => p.name === r.type);
        return (
          <ProviderSetupCell
            r={r}
            installed={pi?.installed ?? false}
            serviceActive={pi?.service_active ?? false}
            configExists={pi?.config_exists ?? false}
            onInstall={(type) => installMut.mutateAsync(type)}
          />
        );
      },
    },
  ];

  return (
    <PageShell>
      <PageTitleBar
        prefix={<Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/servers')} title={t('tooltips.backToServers')} />}
        extra={
          <Button
            icon={<PlusOutlined />}
            onClick={() => { form.resetFields(); setAddStep('type'); setPendingKey(''); setSettingsError(''); setAddOpen(true); }}
            title={t('tooltips.addInstance')}
          >
            {t('actions.addInstance')}
          </Button>
        }
      >
        {t('title')} — <code>{id}</code>
      </PageTitleBar>
      <div style={{ marginBottom: 12, display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
        <TableSearch value={query} onChange={setQuery} placeholder={t('searchPlaceholder')} />
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <Switch size="small" checked={hideDown} onChange={setHideDown} />
          <span style={{ fontSize: 12, color: 'var(--ant-color-text-tertiary)' }}>{t('hideDownProviders')}</span>
        </span>
      </div>
      <Table rowKey="key" columns={columns} dataSource={visibleRows} loading={isLoading} pagination={{ pageSize: 20, showSizeChanger: true }} />

      <Modal
        title={addStep === 'type' ? t('modals.add.checkTitle') : t('modals.add.title')}
        open={addOpen}
        onCancel={closeAddModal}
        footer={addStep === 'type' ? (
          <>
            <Button onClick={closeAddModal}>{t('common:actions.cancel')}</Button>
            <Button type="primary" onClick={onCheckInstall} loading={checkingInstall}>{t('actions.checkInstall')}</Button>
          </>
        ) : (
          <>
            <Button onClick={closeAddModal}>{t('common:actions.close')}</Button>
            <Button type="primary" onClick={onCreateAndBootstrap} loading={create.isPending || bootstrapping}>
              {settingsError ? t('actions.retryInstall') : t('actions.addInstance')}
            </Button>
          </>
        )}
      >
        {addStep === 'type' ? (
          <>
            <Typography.Paragraph type="secondary">{t('modals.add.checkDescription')}</Typography.Paragraph>
            <Form form={form} layout="vertical">
              <Form.Item name="type" label={t('form.type')} rules={[{ required: true }]}>
                <Select options={availableTypes} placeholder={t('form.typePlaceholder')} />
              </Form.Item>
            </Form>
          </>
        ) : (
          <>
            <Typography.Paragraph type="secondary">
              {t('modals.add.description')}
            </Typography.Paragraph>
            {settingsError && <Typography.Paragraph type="danger">{settingsError}</Typography.Paragraph>}
            <Form form={form} layout="vertical">
              <Form.Item name="type" style={{ display: 'none' }}><Input /></Form.Item>
              <Form.Item
                name="local_name"
                label={t('form.localName')}
                rules={[{ required: true, pattern: /^[a-z][a-z0-9_-]*$/, message: t('form.localNamePattern') }]}
              >
                <Input placeholder={selectedType === 'wireguard' ? 'wg1' : selectedType === 'amneziawg' ? 'awg1' : 'my-instance'} disabled={!!pendingKey} />
              </Form.Item>
              <Form.Item
                name="label"
                label={t('form.label')}
                tooltip={t('form.labelTooltip')}
              >
                <Input placeholder={t('form.labelPlaceholder')} />
              </Form.Item>
              {(selectedType === 'wireguard' || selectedType === 'amneziawg') && (
                <>
                  <Form.Item
                    name="address"
                    label={t('form.address')}
                    tooltip={t('form.addressTooltip')}
                    rules={[{ required: true, message: t('form.addressRequired') }]}
                  >
                    <Input placeholder="10.10.0.1/24" disabled={!!pendingKey} />
                  </Form.Item>
                  <Form.Item name="listen_port" label={t('form.port')} tooltip={t('form.wgPortTooltip')}>
                    <InputNumber min={1} max={65535} style={{ width: '100%' }} placeholder="51820" disabled={!!pendingKey} />
                  </Form.Item>
                  <Form.Item name="dns" label={t('form.dns')}><Input placeholder="1.1.1.1" disabled={!!pendingKey} /></Form.Item>
                  <Form.Item name="mtu" label={t('form.mtu')}><InputNumber min={1} max={9000} style={{ width: '100%' }} placeholder="1420" disabled={!!pendingKey} /></Form.Item>
                </>
              )}
              {selectedType === 'openvpn' && (
                <>
                  <Form.Item name="listen_port" label={t('form.port')}><InputNumber min={1} max={65535} style={{ width: '100%' }} disabled={!!pendingKey} /></Form.Item>
                  <Form.Item name="proto" label={t('form.protocol')} initialValue="udp">
                    <Select options={[{ value: 'udp', label: 'UDP' }, { value: 'tcp', label: 'TCP' }]} disabled={!!pendingKey} />
                  </Form.Item>
                  <Form.Item name="server_net" label={t('form.serverNet')}><Input placeholder="10.8.0.0" disabled={!!pendingKey} /></Form.Item>
                  <Form.Item name="server_mask" label={t('form.mask')}><Input placeholder="255.255.255.0" disabled={!!pendingKey} /></Form.Item>
                  <Form.Item name="mtu" label={t('form.mtu')}><InputNumber min={1} max={9000} style={{ width: '100%' }} placeholder="1400" disabled={!!pendingKey} /></Form.Item>
                  <Form.Item name="mssfix" label={t('form.mssfix')}><InputNumber min={1} max={9000} style={{ width: '100%' }} placeholder="1350" disabled={!!pendingKey} /></Form.Item>
                </>
              )}
              {selectedType === 'ikev2' && (
                <>
                  <Form.Item name="pool" label={t('form.pool')}><Input placeholder="10.9.0.0/24" disabled={!!pendingKey} /></Form.Item>
                  <Form.Item name="dns" label={t('form.dns')}><Input placeholder="1.1.1.1" disabled={!!pendingKey} /></Form.Item>
                </>
              )}
            </Form>
          </>
        )}
      </Modal>

      <Modal
        title={t('modals.relabel.title')}
        open={!!labelTarget}
        onCancel={() => setLabelTarget(null)}
        onOk={onRelabel}
        confirmLoading={relabel.isPending}
      >
        <Typography.Paragraph type="secondary">
          {t('modals.relabel.description')}
        </Typography.Paragraph>
        <Form form={labelForm} layout="vertical">
          <Form.Item name="label" label={t('form.relabelLabel')}>
            <Input placeholder={t('form.labelPlaceholder')} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={t('modals.redescribe.title')}
        open={!!descriptionTarget}
        onCancel={() => setDescriptionTarget(null)}
        onOk={onRedescribe}
        confirmLoading={redescribe.isPending}
      >
        <Typography.Paragraph type="secondary">
          {t('modals.redescribe.description')}
        </Typography.Paragraph>
        <Form form={descriptionForm} layout="vertical">
          <Form.Item name="description" label={t('form.descriptionLabel')}>
            <Input.TextArea rows={3} placeholder={t('form.descriptionPlaceholder')} />
          </Form.Item>
        </Form>
      </Modal>
    </PageShell>
  );
}
