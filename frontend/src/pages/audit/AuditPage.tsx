import { useMemo } from 'react';
import { Table } from 'antd';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { useAuditQuery } from '@/api/queries/audit';
import type { AuditEntry } from '@/types/api';
import { HeaderTip } from '@/components/HeaderTip';
import { PageTitleBar } from '@/components/PageTitleBar';
import { TableSearch } from '@/components/TableSearch';
import { useTableSearch } from '@/hooks/useTableSearch';
import { textSorter, dateSorter } from '@/utils/tableSort';

export function AuditPage() {
  const { t } = useTranslation(['audit', 'common']);
  const { data, isLoading } = useAuditQuery();
  const { query, setQuery, filtered } = useTableSearch(
    data,
    (r) => `${r.username} ${r.action} ${r.target}`,
  );
  const actionFilters = useMemo(
    () => [...new Set((data ?? []).map((r) => r.action))].sort().map((a) => ({ text: a, value: a })),
    [data],
  );

  return (
    <PageShell>
      <PageTitleBar>{t('audit:heading')}</PageTitleBar>
      <p style={{ color: 'var(--ant-color-text-tertiary)', marginTop: -8 }}>
        {t('audit:description')}
      </p>
      <TableSearch value={query} onChange={setQuery} placeholder={t('audit:searchPlaceholder')} />
      <Table
        rowKey={(r: AuditEntry) => `${r.timestamp}-${r.action}-${r.target}`}
        loading={isLoading}
        dataSource={filtered ?? []}
        pagination={{ pageSize: 50 }}
        columns={[
          {
            title: t('audit:columns.timestamp'), dataIndex: 'timestamp', key: 'timestamp',
            sorter: dateSorter((r: AuditEntry) => r.timestamp),
            defaultSortOrder: 'descend',
            render: (v: string) => new Date(v).toLocaleString('ru-RU'),
          },
          { title: t('audit:columns.username'), dataIndex: 'username', key: 'username', sorter: textSorter((r: AuditEntry) => r.username) },
          {
            title: <HeaderTip label={t('audit:columns.action')} tip={t('audit:columns.actionTip')} />,
            dataIndex: 'action',
            key: 'action',
            filters: actionFilters,
            onFilter: (value, r) => r.action === value,
            render: (v: string) => <code>{v}</code>,
          },
          {
            title: <HeaderTip label={t('audit:columns.target')} tip={t('audit:columns.targetTip')} />,
            dataIndex: 'target',
            key: 'target',
            sorter: textSorter((r: AuditEntry) => r.target),
          },
        ]}
      />
    </PageShell>
  );
}
