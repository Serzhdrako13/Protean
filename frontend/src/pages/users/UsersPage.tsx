import { useState, type MouseEvent } from 'react';
import { Table, Button, Modal, Form, Input, Select, Tag, Popconfirm, message, Switch, Space, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { PlusOutlined, DeleteOutlined, LockOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { useUserMutations, useUsersQuery, useUserAccessQuery, useUserAccessMutations, type UserAccessRow } from '@/api/queries/users';
import type { PanelUser } from '@/types/api';
import { ApiError } from '@/api/http-init';
import { HeaderTip } from '@/components/HeaderTip';
import { PageTitleBar } from '@/components/PageTitleBar';
import { TableSearch } from '@/components/TableSearch';
import { useTableSearch } from '@/hooks/useTableSearch';
import { textSorter, dateSorter } from '@/utils/tableSort';

// Clicking anywhere in a user row expands the per-provider access panel
// (backlog item 15) -- EXCEPT the interactive controls (switches, buttons),
// which must stop the click from bubbling up to the row or every toggle/
// button press would also toggle the expand state.
function stopRowClick(e: MouseEvent) {
  e.stopPropagation();
}

const ACCESS_STATE_TAG: Record<UserAccessRow['state'], { color: string } | null> = {
  granted: null, // the switch itself already shows "on" -- no extra tag needed
  approved: { color: 'blue' },
  pending: { color: 'blue' },
  denied: { color: 'error' },
  none: null,
};

function UserAccessPanel({ user }: { user: PanelUser }) {
  const { t } = useTranslation(['users', 'common']);
  const { data, isLoading } = useUserAccessQuery(user.id, true);
  const { setAccess } = useUserAccessMutations(user.id);

  async function onToggle(row: UserAccessRow, v: boolean) {
    try {
      await setAccess.mutateAsync({ provider: row.provider, enabled: v });
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  const columns: ColumnsType<UserAccessRow> = [
    { title: t('access.name'), dataIndex: 'provider_label', key: 'provider_label' },
    { title: t('access.server'), dataIndex: 'server_id', key: 'server_id', render: (v: string) => <code>{v}</code> },
    { title: t('access.type'), dataIndex: 'type', key: 'type' },
    { title: t('access.interface'), dataIndex: 'interface', key: 'interface', render: (v: string) => <code>{v}</code> },
    {
      title: t('access.description'),
      dataIndex: 'description',
      key: 'description',
      render: (v?: string) => v || <Typography.Text type="secondary">—</Typography.Text>,
    },
    {
      title: t('access.access'),
      key: 'state',
      render: (_: unknown, row: UserAccessRow) => (
        <Space onClick={stopRowClick}>
          <Switch
            size="small"
            checked={row.state === 'granted' || row.state === 'approved'}
            onChange={(v) => onToggle(row, v)}
          />
          {ACCESS_STATE_TAG[row.state] && <Tag color={ACCESS_STATE_TAG[row.state]!.color}>{t(`access.state.${row.state}`)}</Tag>}
        </Space>
      ),
    },
  ];

  return (
    // No size="small" here: this table renders directly inside the outer
    // users Table's expanded row, so it must match that table's font size --
    // a smaller nested table made the font look inconsistent/jumpy between
    // the user row and its expanded panel.
    <Table
      rowKey="provider"
      loading={isLoading}
      dataSource={data ?? []}
      columns={columns}
      pagination={false}
    />
  );
}

export function UsersPage() {
  const { t } = useTranslation(['users', 'common']);
  const { data, isLoading } = useUsersQuery();
  const { create, remove, resetPassword, setEnabled, setPortalAccess } = useUserMutations();
  const [createOpen, setCreateOpen] = useState(false);
  const [form] = Form.useForm();
  const [resetTarget, setResetTarget] = useState<PanelUser | null>(null);
  const [resetForm] = Form.useForm();
  const { query, setQuery, filtered } = useTableSearch(data, (u) => u.username);

  async function onCreate() {
    try {
      const values = await form.validateFields();
      await create.mutateAsync(values);
      setCreateOpen(false);
      message.success(t('messages.created'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onResetPassword() {
    if (!resetTarget) return;
    try {
      const { newPassword } = await resetForm.validateFields();
      await resetPassword.mutateAsync({ id: resetTarget.id, newPassword });
      setResetTarget(null);
      message.success(t('messages.passwordReset'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  const columns: ColumnsType<PanelUser> = [
    { title: t('fields.username'), dataIndex: 'username', key: 'username', sorter: textSorter((u: PanelUser) => u.username) },
    {
      title: <HeaderTip label={t('fields.role')} tip={t('roleTip')} />,
      dataIndex: 'role',
      key: 'role',
      filters: [
        { text: t('roleLabels.admin'), value: 'admin' },
        { text: t('roleLabels.user'), value: 'user' },
      ],
      onFilter: (value, u) => u.role === value,
      render: (v: string) => <Tag color={v === 'admin' ? 'blue' : 'default'}>{v === 'admin' ? t('roleLabels.admin') : t('roleLabels.user')}</Tag>,
    },
    {
      title: t('fields.createdAt'), dataIndex: 'created_at', key: 'created_at',
      sorter: dateSorter((u: PanelUser) => u.created_at),
      render: (v: string) => new Date(v).toLocaleString(),
    },
    {
      title: t('fields.status'),
      key: 'enabled',
      filters: [
        { text: t('filters.active'), value: true },
        { text: t('filters.inactive'), value: false },
      ],
      onFilter: (value, u) => u.enabled === value,
      render: (_: unknown, u: PanelUser) => (
        <span onClick={stopRowClick}>
          {u.enabled ? (
            <Popconfirm title={t('confirmDisable', { username: u.username })} onConfirm={() => setEnabled.mutate({ id: u.id, enabled: false })}>
              <Switch size="small" checked={u.enabled} />
            </Popconfirm>
          ) : (
            <Switch size="small" checked={u.enabled} onChange={(v) => setEnabled.mutate({ id: u.id, enabled: v })} />
          )}
        </span>
      ),
    },
    {
      title: <HeaderTip label={t('fields.portalAccess')} tip={t('portalAccessTip')} />,
      key: 'portal_access_enabled',
      render: (_: unknown, u: PanelUser) => (
        <span onClick={stopRowClick}>
          {u.role !== 'user' ? '—' : (
            <Switch size="small" checked={u.portal_access_enabled} onChange={(v) => setPortalAccess.mutate({ id: u.id, enabled: v })} />
          )}
        </span>
      ),
    },
    {
      title: '',
      key: 'actions',
      render: (_: unknown, u: PanelUser) => (
        <span onClick={stopRowClick}>
          <Button size="small" icon={<LockOutlined />} onClick={() => { resetForm.resetFields(); setResetTarget(u); }} title={t('resetPasswordTooltip')} style={{ marginRight: 8 }} />
          <Popconfirm title={t('confirmDelete', { username: u.username })} onConfirm={() => remove.mutate(u.id)}>
            <Button size="small" danger icon={<DeleteOutlined />} title={t('common:actions.delete')} />
          </Popconfirm>
        </span>
      ),
    },
  ];

  return (
    <PageShell>
      <PageTitleBar
        extra={
          <Button type="primary" icon={<PlusOutlined />} onClick={() => { form.resetFields(); setCreateOpen(true); }}>
            {t('createButton')}
          </Button>
        }
      >
        {t('common:nav.users')}
      </PageTitleBar>
      <TableSearch value={query} onChange={setQuery} placeholder={t('searchPlaceholder')} />
      <Table
        rowKey="id"
        columns={columns}
        dataSource={filtered ?? []}
        loading={isLoading}
        pagination={{ pageSize: 20, showSizeChanger: true }}
        expandable={{
          expandRowByClick: true,
          rowExpandable: (u) => u.role === 'user',
          expandedRowRender: (u) => <UserAccessPanel user={u} />,
        }}
      />

      <Modal title={t('createModalTitle')} open={createOpen} onCancel={() => setCreateOpen(false)} onOk={onCreate} confirmLoading={create.isPending}>
        <Form form={form} layout="vertical">
          <Form.Item name="username" label={t('fields.username')} rules={[{ required: true }]}>
            <Input placeholder={t('fields.usernamePlaceholder')} />
          </Form.Item>
          <Form.Item name="password" label={t('fields.password')} rules={[{ required: true, min: 8, message: t('passwordMinLength') }]}>
            <Input.Password />
          </Form.Item>
          <Form.Item
            name="role"
            label={t('fields.role')}
            initialValue="user"
            tooltip={t('roleTooltip')}
          >
            <Select
              options={[
                { value: 'user', label: t('roleOptions.user') },
                { value: 'admin', label: t('roleOptions.admin') },
              ]}
            />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={t('resetModalTitle', { username: resetTarget?.username ?? '' })}
        open={!!resetTarget}
        onCancel={() => setResetTarget(null)}
        onOk={onResetPassword}
        confirmLoading={resetPassword.isPending}
      >
        <Form form={resetForm} layout="vertical">
          <Form.Item name="newPassword" label={t('fields.newPassword')} rules={[{ required: true, min: 8, message: t('passwordMinLength') }]}>
            <Input.Password autoFocus />
          </Form.Item>
        </Form>
      </Modal>
    </PageShell>
  );
}
