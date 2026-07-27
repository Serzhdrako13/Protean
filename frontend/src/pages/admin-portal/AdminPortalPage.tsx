import { useState } from 'react';
import { Table, Tag, Button, Space, Modal, Image, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { DownloadOutlined, QrcodeOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { useAdminPortalQuery, type AdminPortalInstance, type AdminPortalPeer } from '@/api/queries/admin-portal';
import { PageTitleBar } from '@/components/PageTitleBar';

// Flattened row: one already-assigned peer, with its instance's info carried
// along -- this page is the admin's own "portal", showing every peer across
// every instance (including ones hidden from the self-service portal via
// portal_visible=false), not a per-user impersonation view. No password/
// theme/logout here: those already live in the normal admin panel (avatar
// menu), duplicating them here would just be a second place to maintain.
interface Row extends AdminPortalPeer {
  provider: string;
  server_id: string;
  provider_label: string;
  portal_visible: boolean;
}

function flatten(instances: AdminPortalInstance[]): Row[] {
  const rows: Row[] = [];
  for (const inst of instances) {
    for (const peer of inst.peers) {
      rows.push({
        ...peer,
        provider: inst.provider,
        server_id: inst.server_id,
        provider_label: inst.provider_label,
        portal_visible: inst.portal_visible,
      });
    }
  }
  return rows;
}

function downloadUrl(r: Row): string {
  return `/api/admin-portal/peers/${encodeURIComponent(r.provider)}/${encodeURIComponent(r.peer_key)}/config`;
}
function qrUrl(r: Row): string {
  return `/api/admin-portal/peers/${encodeURIComponent(r.provider)}/${encodeURIComponent(r.peer_key)}/qr`;
}

export function AdminPortalPage() {
  const { t } = useTranslation(['admin-portal', 'common']);
  const { data, isLoading } = useAdminPortalQuery();
  const [qrRow, setQrRow] = useState<Row | null>(null);
  const rows = flatten(data ?? []);

  const columns: ColumnsType<Row> = [
    { title: t('columns.username'), dataIndex: 'username', key: 'username' },
    { title: t('columns.device'), dataIndex: 'name', key: 'name' },
    { title: t('columns.provider'), dataIndex: 'provider_label', key: 'provider_label' },
    { title: t('columns.server'), dataIndex: 'server_id', key: 'server_id', render: (v: string) => <code>{v}</code> },
    {
      title: t('columns.visibility'),
      dataIndex: 'portal_visible',
      key: 'portal_visible',
      render: (v: boolean) => (v ? <Tag color="success">{t('visibility.visible')}</Tag> : <Tag color="default">{t('visibility.hidden')}</Tag>),
    },
    {
      title: t('columns.online'),
      dataIndex: 'online',
      key: 'online',
      render: (v: boolean) => (v ? <Tag color="success">{t('onlineStatus.online')}</Tag> : <Tag color="error">{t('onlineStatus.offline')}</Tag>),
    },
    {
      title: '',
      key: 'actions',
      render: (_: unknown, r: Row) => (
        <Space>
          <Button size="small" icon={<DownloadOutlined />} href={downloadUrl(r)}>{t('common:actions.download')}</Button>
          <Button size="small" icon={<QrcodeOutlined />} onClick={() => setQrRow(r)}>{t('actions.qr')}</Button>
        </Space>
      ),
    },
  ];

  return (
    <PageShell>
      <PageTitleBar>{t('title')}</PageTitleBar>
      <Typography.Paragraph type="secondary">
        {t('description')}
      </Typography.Paragraph>
      <Table
        rowKey={(r) => `${r.provider}/${r.peer_key}`}
        columns={columns}
        dataSource={rows}
        loading={isLoading}
        pagination={false}
      />

      <Modal title={t('qrModal.title')} open={!!qrRow} onCancel={() => setQrRow(null)} footer={null}>
        {qrRow && (
          <div style={{ textAlign: 'center' }}>
            <Image src={qrUrl(qrRow)} alt="QR" preview={false} />
          </div>
        )}
      </Modal>
    </PageShell>
  );
}
