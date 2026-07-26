import { useEffect, useState } from 'react';
import { Card, Form, Input, InputNumber, Button, Switch, Space, message, Table, Popconfirm, Tag, Collapse, Typography, Modal } from 'antd';
import { SyncOutlined, HistoryOutlined, FileTextOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { useServerConfigQuery, useMeshSettingsQuery, useProviderSettingsMutations } from '@/api/queries/network';
import { useCAImportMutation, useCAInfoQuery } from '@/api/queries/ca';
import { useBackupsQuery, useRestoreBackupMutation, type Backup } from '@/api/queries/backups';
import { HeaderTip } from '@/components/HeaderTip';
import { NetworkGroupSelect } from '@/components/NetworkGroupSelect';
import { ApiError } from '@/api/http-init';

const AWG_OBFUSCATION_KEYS = ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'];

// "Настройки" tab on ProviderDetailPage — the 4 legacy-only surfaces ported
// to the SPA (backlog items 1/2/3/4): listen-port/address/DNS (+ AmneziaWG
// obfuscation), mesh/egress + service restart, CA import, config backups.
export function ProviderSettingsPanel({
  provider, type, certBased, supportsBackups,
}: { provider: string; type: string; certBased: boolean; supportsBackups: boolean }) {
  const isWGFamily = type === 'wireguard' || type === 'amneziawg';

  return (
    <Space direction="vertical" style={{ width: '100%' }} size={16}>
      {isWGFamily && <ServerConfigCard provider={provider} type={type} />}
      {type === 'openvpn' && <OpenVPNTuningCard provider={provider} />}
      <MeshSettingsCard provider={provider} />
      {certBased && <CACard provider={provider} />}
      {supportsBackups && <BackupsCard provider={provider} />}
    </Space>
  );
}

function ServerConfigCard({ provider, type }: { provider: string; type: string }) {
  const { t } = useTranslation(['provider-settings', 'common']);
  const { data, isLoading } = useServerConfigQuery(provider, true);
  const { updateServerConfig } = useProviderSettingsMutations(provider);
  const [form] = Form.useForm();

  useEffect(() => {
    if (data) form.setFieldsValue({ ...data, mtu: data.mtu || undefined, ...data.extra });
  }, [data, form]);

  async function onSave() {
    try {
      const values = await form.validateFields();
      const extra: Record<string, string> = {};
      if (type === 'amneziawg') {
        for (const k of AWG_OBFUSCATION_KEYS) if (values[k]) extra[k] = String(values[k]);
      }
      await updateServerConfig.mutateAsync({
        listen_port: values.listen_port, address: values.address, dns: values.dns, mtu: values.mtu || 0, extra,
      });
      message.success(t('common:actions.saved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  return (
    <Card title={t('provider-settings:serverConfig.title')} loading={isLoading}>
      <Form form={form} layout="vertical">
        <Form.Item name="listen_port" label={t('provider-settings:serverConfig.listenPort')} rules={[{ required: true }]}>
          <InputNumber min={1} max={65535} style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item
          name="address"
          label={
            <HeaderTip
              label={t('provider-settings:serverConfig.address')}
              tip={t('provider-settings:serverConfig.addressLockedTip')}
            />
          }
          rules={[{ required: true }]}
        >
          <Input disabled placeholder={t('provider-settings:serverConfig.addressPlaceholder')} />
        </Form.Item>
        <Form.Item name="dns" label={t('provider-settings:serverConfig.dns')}>
          <Input placeholder={t('provider-settings:serverConfig.dnsPlaceholder')} />
        </Form.Item>
        <Form.Item
          name="mtu"
          label={
            <HeaderTip
              label={t('provider-settings:serverConfig.mtu.label')}
              tip={t('provider-settings:serverConfig.mtu.tip')}
            />
          }
        >
          <InputNumber min={68} max={9000} style={{ width: '100%' }} placeholder="1420" />
        </Form.Item>
        {type === 'amneziawg' && (
          <Collapse
            items={[{
              key: 'obf',
              label: (
                <HeaderTip
                  label={t('provider-settings:serverConfig.obfuscation.label')}
                  tip={t('provider-settings:serverConfig.obfuscation.tip')}
                />
              ),
              children: (
                <Space wrap>
                  {AWG_OBFUSCATION_KEYS.map((k) => (
                    <Form.Item key={k} name={k} label={k} style={{ width: 100 }}>
                      <Input size="small" />
                    </Form.Item>
                  ))}
                </Space>
              ),
            }]}
          />
        )}
        <Button type="primary" onClick={onSave} loading={updateServerConfig.isPending} style={{ marginTop: 12 }}>
          {t('common:actions.save')}
        </Button>
      </Form>
    </Card>
  );
}

// OpenVPN doesn't share ServerConfigCard (listen-port/address/DNS editing
// isn't wired for it -- see api_network.go's openvpn branch, which only
// reads mtu/mssfix from the request and ignores the rest): its own card,
// mtu/mssfix only. Saving rebuilds the provider and re-provisions the
// server (rewrites the .conf, restarts the service) -- not a quick in-place
// edit like wg-family's.
function OpenVPNTuningCard({ provider }: { provider: string }) {
  const { t } = useTranslation(['provider-settings', 'common']);
  const { data, isLoading } = useServerConfigQuery(provider, true);
  const { updateServerConfig } = useProviderSettingsMutations(provider);
  const [form] = Form.useForm();

  useEffect(() => {
    if (data) form.setFieldsValue({ mtu: data.mtu || undefined, mssfix: data.mssfix || undefined });
  }, [data, form]);

  async function onSave() {
    try {
      const values = await form.validateFields();
      await updateServerConfig.mutateAsync({ mtu: values.mtu || 0, mssfix: values.mssfix || 0 });
      message.success(t('provider-settings:openvpnTuning.savedMessage'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  return (
    <Card title={t('provider-settings:openvpnTuning.title')} loading={isLoading}>
      <Typography.Paragraph type="secondary">
        {t('provider-settings:openvpnTuning.description')}
      </Typography.Paragraph>
      <Form form={form} layout="vertical">
        <Form.Item
          name="mtu"
          label={<HeaderTip label={t('provider-settings:openvpnTuning.tunMtu.label')} tip={t('provider-settings:openvpnTuning.tunMtu.tip')} />}
        >
          <InputNumber min={68} max={9000} style={{ width: '100%' }} placeholder="1500" />
        </Form.Item>
        <Form.Item
          name="mssfix"
          label={<HeaderTip label={t('provider-settings:openvpnTuning.mssfix.label')} tip={t('provider-settings:openvpnTuning.mssfix.tip')} />}
        >
          <InputNumber min={68} max={9000} style={{ width: '100%' }} placeholder="1450" />
        </Form.Item>
        <Button type="primary" onClick={onSave} loading={updateServerConfig.isPending}>{t('common:actions.save')}</Button>
      </Form>
    </Card>
  );
}

function MeshSettingsCard({ provider }: { provider: string }) {
  const { t } = useTranslation(['provider-settings', 'common']);
  const { data, isLoading } = useMeshSettingsQuery(provider, true);
  const { updateMeshSettings, serviceAction, fetchLogs } = useProviderSettingsMutations(provider);
  const [logsOpen, setLogsOpen] = useState(false);
  const [logs, setLogs] = useState('');
  const [rangeStart, setRangeStart] = useState('');
  const [rangeEnd, setRangeEnd] = useState('');

  useEffect(() => {
    if (data) {
      setRangeStart(data.auto_assign_start ?? '');
      setRangeEnd(data.auto_assign_end ?? '');
    }
  }, [data]);

  async function toggle(field: 'mesh_enabled' | 'internet_egress', value: boolean) {
    if (!data) return;
    try {
      await updateMeshSettings.mutateAsync({
        mesh_enabled: field === 'mesh_enabled' ? value : data.mesh_enabled,
        internet_egress: field === 'internet_egress' ? value : data.internet_egress,
        auto_assign_start: data.auto_assign_start,
        auto_assign_end: data.auto_assign_end,
      });
      message.success(t('common:actions.saved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function saveGroup(next: { group_id: number | null; new_group_name?: string }) {
    if (!data) return;
    try {
      await updateMeshSettings.mutateAsync({
        mesh_enabled: data.mesh_enabled,
        internet_egress: data.internet_egress,
        auto_assign_start: data.auto_assign_start,
        auto_assign_end: data.auto_assign_end,
        group_id: next.group_id,
        new_group_name: next.new_group_name,
      });
      message.success(t('common:actions.saved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function saveRange() {
    if (!data) return;
    try {
      await updateMeshSettings.mutateAsync({
        mesh_enabled: data.mesh_enabled,
        internet_egress: data.internet_egress,
        auto_assign_start: rangeStart,
        auto_assign_end: rangeEnd,
      });
      message.success(t('common:actions.saved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function restart() {
    try {
      await serviceAction.mutateAsync('restart');
      message.success(t('provider-settings:mesh.serviceRestarted'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function viewLogs() {
    setLogsOpen(true);
    try {
      const res = await fetchLogs.mutateAsync(200);
      setLogs(res.logs);
    } catch (e) {
      setLogs(e instanceof ApiError ? e.message : String(e));
    }
  }

  return (
    <Card title={t('provider-settings:mesh.title')} loading={isLoading}>
      <Space direction="vertical" style={{ width: '100%' }} size={10}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {t('provider-settings:mesh.meshEnabled')}
            <HeaderTip label="" tip={t('provider-settings:mesh.meshEnabledTip')} />
          </span>
          <Switch checked={data?.mesh_enabled} onChange={(v) => toggle('mesh_enabled', v)} disabled={!data?.mesh_capable} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {t('provider-settings:mesh.group')}
            <HeaderTip label="" tip={t('provider-settings:mesh.groupTip')} />
          </span>
          <NetworkGroupSelect
            value={data?.group_id}
            onChange={saveGroup}
            size="small"
            noGroupLabel={t('provider-settings:mesh.noGroup')}
            newGroupLabel={t('provider-settings:mesh.newGroupOption')}
            newGroupPlaceholder={t('provider-settings:mesh.newGroupPlaceholder')}
          />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {t('provider-settings:mesh.egress')}
            <HeaderTip label="" tip={t('provider-settings:mesh.egressTip')} />
          </span>
          <Switch checked={data?.internet_egress} onChange={(v) => toggle('internet_egress', v)} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {t('provider-settings:mesh.autoAssignRange')}
            <HeaderTip label="" tip={t('provider-settings:mesh.autoAssignRangeTip')} />
          </span>
          <Space>
            <Input
              size="small"
              style={{ width: 130 }}
              placeholder={t('provider-settings:mesh.rangeStartPlaceholder')}
              value={rangeStart}
              onChange={(e) => setRangeStart(e.target.value)}
            />
            <Input
              size="small"
              style={{ width: 130 }}
              placeholder={t('provider-settings:mesh.rangeEndPlaceholder')}
              value={rangeEnd}
              onChange={(e) => setRangeEnd(e.target.value)}
            />
            <Button size="small" onClick={saveRange} loading={updateMeshSettings.isPending}>{t('common:actions.save')}</Button>
          </Space>
        </div>
        {data?.service_unit && (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>
              {t('provider-settings:mesh.service')} <code>{data.service_unit}</code>
              {data.service_status && <Tag style={{ marginLeft: 8 }} color={data.service_status === 'active' ? 'success' : 'default'}>{data.service_status}</Tag>}
            </span>
            <Space>
              <Button size="small" icon={<FileTextOutlined />} onClick={viewLogs}>{t('provider-settings:mesh.viewLogs')}</Button>
              <Button size="small" icon={<SyncOutlined />} onClick={restart} loading={serviceAction.isPending}>{t('common:actions.restart')}</Button>
            </Space>
          </div>
        )}
      </Space>
      <Modal
        title={t('provider-settings:mesh.logsTitle', { unit: data?.service_unit })}
        open={logsOpen}
        onCancel={() => setLogsOpen(false)}
        footer={<Button onClick={() => setLogsOpen(false)}>{t('common:actions.close')}</Button>}
        width={800}
      >
        <pre style={{ maxHeight: 500, overflow: 'auto', margin: 0, fontSize: 12, background: 'var(--ant-color-fill-tertiary)', padding: 12, borderRadius: 4 }}>
          {fetchLogs.isPending ? t('common:actions.loading') : (logs || t('provider-settings:mesh.logsEmpty'))}
        </pre>
      </Modal>
    </Card>
  );
}

function CACard({ provider }: { provider: string }) {
  const { t } = useTranslation(['provider-settings', 'common']);
  const [form] = Form.useForm();
  const { data: caInfo, isLoading } = useCAInfoQuery(provider, true);
  const importCA = useCAImportMutation(provider);

  async function onImport() {
    try {
      const values = await form.validateFields();
      await importCA.mutateAsync(values);
      message.success(t('provider-settings:ca.importedMessage'));
      form.resetFields();
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  return (
    <Card title={t('provider-settings:ca.title')} loading={isLoading}>
      <Typography.Paragraph type="secondary">
        {t('provider-settings:ca.description')}
      </Typography.Paragraph>
      <Typography.Paragraph type="secondary">
        {t('provider-settings:ca.tlsCryptNote')}
      </Typography.Paragraph>
      <div style={{ marginBottom: 16 }}>
        {!caInfo?.configured ? (
          <Typography.Text type="secondary">{t('provider-settings:ca.status.notConfigured')}</Typography.Text>
        ) : (
          <Space>
            <Tag color={caInfo.source === 'external' ? 'blue' : 'default'}>
              {t(`provider-settings:ca.status.${caInfo.source === 'external' ? 'external' : 'internal'}`)}
            </Tag>
            {caInfo.created_at && (
              <Typography.Text type="secondary">
                {t('provider-settings:ca.status.createdAt', { date: caInfo.created_at })}
              </Typography.Text>
            )}
          </Space>
        )}
      </div>
      <Form form={form} layout="vertical">
        <Form.Item name="ca_cert" label={t('provider-settings:ca.caCert')} rules={[{ required: true }]}>
          <Input.TextArea rows={6} placeholder="-----BEGIN CERTIFICATE-----" />
        </Form.Item>
        <Form.Item name="ca_key" label={t('provider-settings:ca.caKey')} rules={[{ required: true }]}>
          <Input.TextArea rows={6} placeholder="-----BEGIN PRIVATE KEY-----" />
        </Form.Item>
        <Form.Item
          name="crl_pem"
          label={<HeaderTip label={t('provider-settings:ca.crlPem.label')} tip={t('provider-settings:ca.crlPem.tip')} />}
        >
          <Input.TextArea rows={4} placeholder="-----BEGIN X509 CRL-----" />
        </Form.Item>
        <Button type="primary" onClick={onImport} loading={importCA.isPending}>{t('provider-settings:ca.import')}</Button>
      </Form>
    </Card>
  );
}

function BackupsCard({ provider }: { provider: string }) {
  const { t } = useTranslation(['provider-settings', 'common']);
  const { data, isLoading } = useBackupsQuery(provider, true);
  const restore = useRestoreBackupMutation(provider);

  async function onRestore(id: number) {
    try {
      await restore.mutateAsync(id);
      message.success(t('provider-settings:backups.restoredMessage'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  return (
    <Card title={t('provider-settings:backups.title')} loading={isLoading}>
      <Table
        rowKey="id"
        size="small"
        pagination={false}
        dataSource={data ?? []}
        locale={{ emptyText: t('provider-settings:backups.emptyText') }}
        columns={[
          { title: t('provider-settings:backups.date'), dataIndex: 'saved_at', key: 'saved_at' },
          { title: t('provider-settings:backups.size'), dataIndex: 'bytes', key: 'bytes', render: (v: number) => t('provider-settings:backups.sizeBytes', { count: v }) },
          {
            title: (
              <HeaderTip label={t('provider-settings:backups.preview.label')} tip={t('provider-settings:backups.preview.tip')} />
            ),
            dataIndex: 'preview',
            key: 'preview',
            render: (v: string) => <code style={{ fontSize: 11 }}>{v}</code>,
          },
          {
            title: '',
            key: 'actions',
            render: (_: unknown, r: Backup) => (
              <Popconfirm title={t('provider-settings:backups.restoreConfirm', { date: r.saved_at })} onConfirm={() => onRestore(r.id)}>
                <Button size="small" icon={<HistoryOutlined />} loading={restore.isPending}>{t('provider-settings:backups.restore')}</Button>
              </Popconfirm>
            ),
          },
        ]}
      />
    </Card>
  );
}
