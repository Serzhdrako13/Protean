import { Table, Tag, Button, Space, Popconfirm, message } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { CheckOutlined, CloseOutlined, DeleteOutlined, ClearOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { useAccessRequestMutations, useAccessRequestsQuery, type AccessRequest } from '@/api/queries/access-requests';
import { ApiError } from '@/api/http-init';
import { HeaderTip } from '@/components/HeaderTip';
import { PageTitleBar } from '@/components/PageTitleBar';
import { TableSearch } from '@/components/TableSearch';
import { useTableSearch } from '@/hooks/useTableSearch';
import { textSorter, dateSorter } from '@/utils/tableSort';

export function AccessRequestsPage() {
  const { t } = useTranslation(['access-requests', 'common']);
  const { data, isLoading } = useAccessRequestsQuery();
  const { approve, deny, remove, clearDenied } = useAccessRequestMutations();
  const deniedCount = (data ?? []).filter((r) => r.status === 'denied').length;
  const { query, setQuery, filtered } = useTableSearch(data, (r) => `${r.username} ${r.provider_label}`);

  const STATUS_TAG: Record<AccessRequest['status'], { color: string; text: string }> = {
    pending: { color: 'blue', text: t('status.pending') },
    approved: { color: 'blue', text: t('status.approved') },
    granted: { color: 'success', text: t('status.granted') },
    denied: { color: 'error', text: t('status.denied') },
  };

  async function onApprove(id: number) {
    try {
      await approve.mutateAsync(id);
      message.success(t('messages.approveSuccess'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onDeny(id: number) {
    try {
      await deny.mutateAsync(id);
      message.success(t('messages.denySuccess'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onDelete(id: number) {
    try {
      await remove.mutateAsync(id);
      message.success(t('messages.deleteSuccess'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onClearDenied() {
    try {
      const res = await clearDenied.mutateAsync();
      message.success(t('messages.clearDeniedSuccess', { count: res.deleted }));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  const columns: ColumnsType<AccessRequest> = [
    { title: t('columns.username'), dataIndex: 'username', key: 'username', sorter: textSorter((r: AccessRequest) => r.username) },
    { title: t('columns.provider'), dataIndex: 'provider_label', key: 'provider_label', sorter: textSorter((r: AccessRequest) => r.provider_label) },
    { title: t('columns.server'), dataIndex: 'server_id', key: 'server_id', render: (v: string) => <code>{v}</code> },
    {
      title: <HeaderTip label={t('columns.status')} tip={t('columns.statusTip')} />,
      dataIndex: 'status',
      key: 'status',
      filters: (Object.keys(STATUS_TAG) as AccessRequest['status'][]).map((s) => ({ text: STATUS_TAG[s].text, value: s })),
      onFilter: (value, r) => r.status === value,
      render: (v: AccessRequest['status']) => <Tag color={STATUS_TAG[v].color}>{STATUS_TAG[v].text}</Tag>,
    },
    {
      title: t('columns.created'), dataIndex: 'created_at', key: 'created_at',
      sorter: dateSorter((r: AccessRequest) => r.created_at),
      defaultSortOrder: 'descend',
      render: (v: string) => new Date(v).toLocaleString(),
    },
    {
      title: '',
      key: 'actions',
      render: (_: unknown, r: AccessRequest) =>
        r.status === 'pending' ? (
          <Space>
            <Button size="small" type="primary" icon={<CheckOutlined />} onClick={() => onApprove(r.id)} loading={approve.isPending}>
              {t('common:actions.approve')}
            </Button>
            <Popconfirm title={t('confirm.deny', { username: r.username, label: r.provider_label })} onConfirm={() => onDeny(r.id)}>
              <Button size="small" danger icon={<CloseOutlined />}>{t('common:actions.deny')}</Button>
            </Popconfirm>
          </Space>
        ) : r.status === 'approved' ? (
          <Popconfirm title={t('confirm.revoke', { username: r.username })} onConfirm={() => onDeny(r.id)}>
            <Button size="small" danger icon={<CloseOutlined />}>{t('common:actions.deny')}</Button>
          </Popconfirm>
        ) : r.status === 'denied' ? (
          <Popconfirm title={t('confirm.delete', { username: r.username, label: r.provider_label })} onConfirm={() => onDelete(r.id)}>
            <Button size="small" danger icon={<DeleteOutlined />}>{t('common:actions.delete')}</Button>
          </Popconfirm>
        ) : null,
    },
  ];

  return (
    <PageShell>
      <PageTitleBar
        extra={
          <Popconfirm title={t('confirm.clearDenied', { count: deniedCount })} onConfirm={onClearDenied} disabled={!deniedCount}>
            <Button danger icon={<ClearOutlined />} disabled={!deniedCount} loading={clearDenied.isPending}>
              {t('clearDeniedButton', { count: deniedCount })}
            </Button>
          </Popconfirm>
        }
      >
        {t('title')}
      </PageTitleBar>
      <TableSearch value={query} onChange={setQuery} placeholder={t('searchPlaceholder')} />
      <Table rowKey="id" columns={columns} dataSource={filtered ?? []} loading={isLoading} pagination={{ pageSize: 20, showSizeChanger: true }} />
    </PageShell>
  );
}
