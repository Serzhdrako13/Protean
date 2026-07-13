import { useState } from 'react';
import { Table, Button, Modal, Form, Input, InputNumber, Tag, Popconfirm, Tabs, message, Space, Switch, Alert, Typography, Radio } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { PlusOutlined, DeleteOutlined, EditOutlined, ApiOutlined, WarningOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { Link, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { useServerMutations, useServersQuery, useProbeHostKeyMutation, type ProbeHostKeyResult } from '@/api/queries/servers';
import type { ServerRow } from '@/types/api';
import { ApiError } from '@/api/http-init';
import { ServerProviderBadges } from './ServerProviderBadges';
import { HeaderTip } from '@/components/HeaderTip';
import { PageTitleBar } from '@/components/PageTitleBar';
import { TableSearch } from '@/components/TableSearch';
import { useTableSearch } from '@/hooks/useTableSearch';
import { textSorter } from '@/utils/tableSort';

export function ServersPage() {
  const { t } = useTranslation(['servers', 'common']);
  const navigate = useNavigate();
  const { data, isLoading } = useServersQuery();
  const { create, update, remove, setEnabled } = useServerMutations();
  const { query, setQuery, filtered } = useTableSearch(data, (r) => `${r.id} ${r.label} ${r.host}`);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<ServerRow | null>(null);
  const [form] = Form.useForm();
  const probeHostKey = useProbeHostKeyMutation();
  const [probeResult, setProbeResult] = useState<ProbeHostKeyResult | null>(null);
  const [probeError, setProbeError] = useState('');
  const formHost = Form.useWatch('host', form);
  const formPort = Form.useWatch('port', form);
  const [bootstrapIdentity, setBootstrapIdentity] = useState<'root' | 'sudo'>('root');

  function openCreate() {
    setEditing(null);
    form.resetFields();
    setProbeResult(null);
    setProbeError('');
    setBootstrapIdentity('root');
    setModalOpen(true);
  }

  function openEdit(row: ServerRow) {
    setEditing(row);
    form.setFieldsValue({ ...row });
    setProbeResult(null);
    setProbeError('');
    setModalOpen(true);
  }

  async function onProbeHostKey() {
    setProbeResult(null);
    setProbeError('');
    try {
      const res = await probeHostKey.mutateAsync({ host: formHost, port: formPort || 22 });
      setProbeResult(res);
    } catch (e) {
      setProbeError(e instanceof ApiError ? e.message : String(e));
    }
  }

  function onAcceptProbedKey() {
    if (!probeResult) return;
    form.setFieldsValue({ host_key: probeResult.authorized_key });
    setProbeResult(null);
    message.success(t('servers:modal.form.hostKey.pinned'));
  }

  async function onSubmit() {
    try {
      const values = await form.validateFields();
      if (editing) {
        await update.mutateAsync({ id: editing.id, ...values });
      } else {
        // The identity radio drives bootstrap_user directly -- "root" needs
        // no separate username field, an existing sudo user's typed name is
        // used as-is. Harmless to set even when the "existing key" tab is
        // used instead: the backend tries ssh_key first.
        await create.mutateAsync({
          ...values,
          bootstrap_user: bootstrapIdentity === 'root' ? 'root' : (values.bootstrap_user ?? '').trim(),
        });
      }
      setModalOpen(false);
      message.success(t('common:actions.saved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  const columns: ColumnsType<ServerRow> = [
    {
      title: 'ID', dataIndex: 'id', key: 'id',
      sorter: textSorter((r: ServerRow) => r.id),
      render: (v: string) => <Link to={`/servers/${v}/providers`}><code>{v}</code></Link>,
    },
    {
      title: t('servers:table.label'), dataIndex: 'label', key: 'label',
      sorter: textSorter((r: ServerRow) => r.label),
      render: (v: string, r: ServerRow) => <Link to={`/servers/${r.id}/providers`}>{v}</Link>,
    },
    { title: t('servers:table.host'), key: 'host', render: (_: unknown, r: ServerRow) => `${r.host}:${r.port}` },
    { title: t('servers:table.sshUser'), dataIndex: 'ssh_user', key: 'ssh_user', responsive: ['lg'] },
    {
      title: <HeaderTip label={t('servers:table.publicHost.label')} tip={t('servers:table.publicHost.tip')} />,
      dataIndex: 'public_host',
      key: 'public_host',
      responsive: ['xl'],
    },
    {
      title: <HeaderTip label={t('servers:table.hostKey.label')} tip={t('servers:table.hostKey.tip')} />,
      dataIndex: 'host_key_set',
      key: 'host_key_set',
      responsive: ['lg'],
      render: (v: boolean) => (v ? <Tag color="success">{t('servers:table.hostKeyPinned')}</Tag> : <Tag color="error" icon={<WarningOutlined />}>{t('servers:table.hostKeyTofu')}</Tag>),
    },
    {
      title: <HeaderTip label={t('servers:table.providers.label')} tip={t('servers:table.providers.tip')} />,
      key: 'providers',
      render: (_: unknown, r: ServerRow) => <ServerProviderBadges serverId={r.id} />,
    },
    {
      title: <HeaderTip label={t('servers:table.enabled.label')} tip={t('servers:table.enabled.tip')} />,
      key: 'enabled',
      render: (_: unknown, r: ServerRow) => (
        r.enabled ? (
          <Popconfirm title={t('servers:actions.disableConfirm', { id: r.id })} onConfirm={() => setEnabled.mutate({ id: r.id, enabled: false })}>
            <Switch size="small" checked={r.enabled} />
          </Popconfirm>
        ) : (
          <Switch size="small" checked={r.enabled} onChange={(v) => setEnabled.mutate({ id: r.id, enabled: v })} />
        )
      ),
    },
    {
      title: '',
      key: 'actions',
      render: (_: unknown, r: ServerRow) => (
        <Space wrap>
          <Button size="small" icon={<ApiOutlined />} onClick={() => navigate(`/servers/${r.id}/providers`)} title={t('servers:actions.providersTitle')}>{t('servers:actions.providers')}</Button>
          <Button size="small" icon={<EditOutlined />} onClick={() => openEdit(r)} title={t('servers:actions.editTitle')} />
          <Popconfirm title={t('servers:actions.deleteConfirm', { id: r.id })} description={t('servers:actions.deleteConfirmDetail')} onConfirm={() => remove.mutate(r.id)}>
            <Button size="small" danger icon={<DeleteOutlined />} title={t('servers:actions.deleteTitle')} />
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <PageShell>
      <PageTitleBar extra={<Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>{t('servers:addServer')}</Button>}>
        {t('servers:title')}
      </PageTitleBar>
      <TableSearch value={query} onChange={setQuery} placeholder={t('servers:searchPlaceholder')} />
      <Table rowKey="id" columns={columns} dataSource={filtered ?? []} loading={isLoading} pagination={{ pageSize: 20, showSizeChanger: true }} scroll={{ x: 'max-content' }} />

      <Modal
        title={editing ? t('servers:modal.editTitle', { id: editing.id }) : t('servers:addServer')}
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        onOk={onSubmit}
        confirmLoading={create.isPending || update.isPending}
        destroyOnHidden
        width={560}
      >
        <Form form={form} layout="vertical">
          {!editing && (
            <Form.Item name="id" label={t('servers:modal.form.id.label')} rules={[{ required: true, pattern: /^[a-z0-9][a-z0-9_-]*$/, message: t('servers:modal.form.id.message') }]}>
              <Input placeholder="srv-msk" />
            </Form.Item>
          )}
          <Form.Item name="label" label={t('servers:modal.form.label.label')}>
            <Input placeholder={t('servers:modal.form.label.placeholder')} />
          </Form.Item>
          <Space.Compact block>
            <Form.Item
              name="host"
              label={
                <HeaderTip
                  label={t('servers:modal.form.host.label')}
                  tip={t('servers:modal.form.host.tip')}
                />
              }
              rules={[{ required: true }]}
              style={{ flex: 1 }}
            >
              <Input placeholder="10.0.0.5" />
            </Form.Item>
            <Form.Item name="port" label={t('servers:modal.form.port')} initialValue={22}>
              <InputNumber min={1} max={65535} />
            </Form.Item>
          </Space.Compact>
          <Form.Item
            name="ssh_user"
            label={
              <HeaderTip
                label={t('servers:modal.form.sshUser')}
                tip={t('servers:modal.form.serviceUser.tip')}
              />
            }
            initialValue="protean"
            rules={[{ required: true }]}
          >
            <Input placeholder={t('servers:modal.form.serviceUser.placeholder')} />
          </Form.Item>
          <Form.Item name="public_host" label={t('servers:modal.form.publicHost.label')}>
            <Input placeholder={t('servers:modal.form.publicHost.placeholder')} />
          </Form.Item>
          <Form.Item name="host_key" label={t('servers:modal.form.hostKey.label')}>
            <Input placeholder={t('servers:modal.form.hostKey.placeholder')} />
          </Form.Item>
          <Button
            size="small"
            icon={<SafetyCertificateOutlined />}
            onClick={onProbeHostKey}
            loading={probeHostKey.isPending}
            disabled={!formHost}
            style={{ marginBottom: 16 }}
          >
            {t('servers:modal.form.hostKey.probeButton')}
          </Button>
          {probeError && (
            <Alert type="error" showIcon style={{ marginBottom: 16 }} message={probeError} />
          )}
          {probeResult && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 16 }}
              message={t('servers:modal.form.hostKey.probeResultTitle')}
              description={
                <Space orientation="vertical" size={8} style={{ width: '100%' }}>
                  <Typography.Paragraph style={{ marginBottom: 0 }}>
                    {t('servers:modal.form.hostKey.probeWarning')}
                  </Typography.Paragraph>
                  <Typography.Text strong copyable>{probeResult.fingerprint}</Typography.Text>
                  <Typography.Paragraph code copyable style={{ marginBottom: 8, wordBreak: 'break-all' }}>
                    {probeResult.authorized_key}
                  </Typography.Paragraph>
                  <Button size="small" type="primary" onClick={onAcceptProbedKey}>
                    {t('servers:modal.form.hostKey.probeAccept')}
                  </Button>
                </Space>
              }
            />
          )}
          {!editing && (
            <Tabs
              items={[
                {
                  key: 'bootstrap',
                  label: t('servers:modal.form.bootstrap.tab'),
                  children: (
                    <>
                      <Form.Item label={t('servers:modal.form.bootstrap.identityLabel')}>
                        <Radio.Group
                          value={bootstrapIdentity}
                          onChange={(e) => setBootstrapIdentity(e.target.value)}
                        >
                          <Radio.Button value="root">{t('servers:modal.form.bootstrap.identityRoot')}</Radio.Button>
                          <Radio.Button value="sudo">{t('servers:modal.form.bootstrap.identitySudoUser')}</Radio.Button>
                        </Radio.Group>
                      </Form.Item>
                      {bootstrapIdentity === 'sudo' && (
                        <Form.Item
                          name="bootstrap_user"
                          label={t('servers:modal.form.bootstrap.bootstrapUser.label')}
                          rules={[{ required: true, message: t('servers:modal.form.bootstrap.bootstrapUser.label') }]}
                        >
                          <Input placeholder={t('servers:modal.form.bootstrap.bootstrapUser.placeholder')} />
                        </Form.Item>
                      )}
                      <Tabs
                        size="small"
                        items={[
                          {
                            key: 'password',
                            label: t('servers:modal.form.bootstrap.passwordTab'),
                            children: (
                              <Form.Item name="bootstrap_password" label={t('servers:modal.form.bootstrap.passwordLabel')}>
                                <Input.Password placeholder={t('servers:modal.form.bootstrap.passwordPlaceholder')} />
                              </Form.Item>
                            ),
                          },
                          {
                            key: 'key',
                            label: t('servers:modal.form.bootstrap.keyTab'),
                            children: (
                              <>
                                <Form.Item name="bootstrap_key" label={t('servers:modal.form.bootstrap.keyLabel')}>
                                  <Input.TextArea rows={4} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
                                </Form.Item>
                                {bootstrapIdentity === 'sudo' && (
                                  <Alert
                                    type="warning"
                                    showIcon
                                    style={{ marginBottom: 16 }}
                                    message={t('servers:modal.form.bootstrap.keyAuthSudoWarning')}
                                  />
                                )}
                              </>
                            ),
                          },
                        ]}
                      />
                    </>
                  ),
                },
                {
                  key: 'key',
                  label: t('servers:modal.form.keyTab'),
                  children: (
                    <Form.Item name="ssh_key" label={t('servers:modal.form.sshKey')}>
                      <Input.TextArea rows={4} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
                    </Form.Item>
                  ),
                },
              ]}
            />
          )}
          {editing && (
            <Form.Item name="ssh_key" label={t('servers:modal.form.sshKeyEdit')}>
              <Input.TextArea rows={4} />
            </Form.Item>
          )}
        </Form>
      </Modal>
    </PageShell>
  );
}
