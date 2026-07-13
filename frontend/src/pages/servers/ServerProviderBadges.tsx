import { Tooltip, Badge, Space, Skeleton } from 'antd';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useProvidersQuery } from '@/api/queries/providers';

// One dot per provider actually REGISTERED on this server (green = up,
// grey = down/not installed) -- NOT a preview of every possible provider
// type (that used to render 5 dots, mostly grey, on every server row
// regardless of what's actually in use). Click through to the providers
// page to see/add/install them.
export function ServerProviderBadges({ serverId }: { serverId: string }) {
  const { t } = useTranslation(['server-badges', 'common']);
  const { data, isLoading } = useProvidersQuery();

  if (isLoading) return <Skeleton.Button size="small" active style={{ width: 90 }} />;

  const rows = (data ?? []).filter((p) => p.server_id === serverId);
  const upCount = rows.filter((p) => p.status.Up).length;

  return (
    <Link to={`/servers/${serverId}/providers`}>
      <Space size={4}>
        {rows.map((p) => (
          <Tooltip key={p.key} title={t(p.status.Up ? 'installedTooltip' : 'notInstalledTooltip', { label: p.friendly_label || p.label })}>
            <Badge status={p.status.Up ? 'success' : 'default'} />
          </Tooltip>
        ))}
        <span style={{ fontSize: 12, color: 'var(--ant-color-text-tertiary)' }}>
          {t('providerCount', { count: rows.length, upCount })}
        </span>
      </Space>
    </Link>
  );
}
