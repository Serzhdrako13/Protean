import { useState } from 'react';
import { Table, Tag, Select, Input, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { useConnectionHistoryQuery, type ConnectionEvent } from '@/api/queries/connection-history';
import { PageTitleBar } from '@/components/PageTitleBar';
import { useTableSearch } from '@/hooks/useTableSearch';
import { textSorter, dateSorter } from '@/utils/tableSort';

export function ConnectionHistoryPage() {
  const { t } = useTranslation(['connection-history', 'common']);
  const [provider, setProvider] = useState('');
  const [sinceHours, setSinceHours] = useState(24);
  const { data, isLoading } = useConnectionHistoryQuery({ provider: provider || undefined, sinceHours });
  const { query, setQuery, filtered } = useTableSearch(data, (r) => r.peer_name || r.peer_id);

  return (
    <PageShell>
      <PageTitleBar>{t('title')}</PageTitleBar>
      <Typography.Paragraph type="secondary">{t('description')}</Typography.Paragraph>
      <Space style={{ marginBottom: 16 }}>
        <Input
          placeholder={t('filters.providerPlaceholder')}
          value={provider}
          onChange={(e) => setProvider(e.target.value)}
          style={{ width: 220 }}
          allowClear
        />
        <Select
          value={sinceHours}
          onChange={setSinceHours}
          style={{ width: 160 }}
          options={[
            { label: t('filters.hours', { count: 1 }), value: 1 },
            { label: t('filters.hours', { count: 24 }), value: 24 },
            { label: t('filters.hours', { count: 168 }), value: 168 },
            { label: t('filters.hours', { count: 720 }), value: 720 },
          ]}
        />
        <Input
          allowClear
          placeholder={t('filters.devicePlaceholder')}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ width: 220 }}
        />
      </Space>
      <Table<ConnectionEvent>
        rowKey={(r) => `${r.ts}-${r.provider}-${r.peer_id}-${r.event}`}
        loading={isLoading}
        dataSource={filtered ?? []}
        pagination={{ pageSize: 50 }}
        columns={[
          {
            title: t('columns.ts'), dataIndex: 'ts', key: 'ts',
            sorter: dateSorter((r: ConnectionEvent) => r.ts),
            defaultSortOrder: 'descend',
            render: (v: string) => new Date(v).toLocaleString(),
          },
          { title: t('columns.provider'), dataIndex: 'provider', key: 'provider', sorter: textSorter((r: ConnectionEvent) => r.provider), render: (v: string) => <code>{v}</code> },
          { title: t('columns.peer'), dataIndex: 'peer_name', key: 'peer_name', sorter: textSorter((r: ConnectionEvent) => r.peer_name || r.peer_id), render: (v: string, r) => v || r.peer_id },
          {
            title: t('columns.event'), dataIndex: 'event', key: 'event',
            filters: [
              { text: t('event.connect'), value: 'connect' },
              { text: t('event.disconnect'), value: 'disconnect' },
            ],
            onFilter: (value, r) => r.event === value,
            render: (v: 'connect' | 'disconnect') => (
              <Tag color={v === 'connect' ? 'success' : 'default'}>{t(`event.${v}`)}</Tag>
            ),
          },
        ]}
      />
    </PageShell>
  );
}
