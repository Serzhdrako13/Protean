import { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Card, Select, Table, Tag, Button, Alert, Typography, Space, message, Tooltip } from 'antd';
import { ArrowLeftOutlined, QuestionCircleOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { useInstallMutation, useInstallStatusQuery, type ProviderInstall } from '@/api/queries/install';
import { ApiError } from '@/api/http-init';
import { PageTitleBar } from '@/components/PageTitleBar';

export function InstallPage() {
  const { t } = useTranslation(['install', 'common']);
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [server, setServer] = useState<string | undefined>(params.get('server') ?? undefined);
  const { data, isLoading } = useInstallStatusQuery(server);
  const install = useInstallMutation(server ?? data?.server_id);
  const [output, setOutput] = useState<string | null>(null);

  async function onInstall(name: string) {
    setOutput(null);
    try {
      const res = await install.mutateAsync(name);
      setOutput(res.output);
      message.success(t('install:installSuccess', { name }));
    } catch (e) {
      if (e instanceof ApiError) {
        message.error(e.message);
        const obj = e.obj as { output?: string } | undefined;
        if (obj?.output) setOutput(obj.output);
      }
    }
  }

  const columns = [
    { title: t('install:table.provider'), dataIndex: 'label', key: 'label' },
    {
      title: t('install:table.installed'),
      dataIndex: 'installed',
      key: 'installed',
      render: (v: boolean) =>
        v ? <Tag color="success">{t('install:table.installedYes')}</Tag> : <Tag>{t('install:table.installedNo')}</Tag>,
    },
    {
      title: (
        <span>
          {t('install:table.afterInstall')}{' '}
          <Tooltip title={t('install:table.afterInstallTooltip')}>
            <QuestionCircleOutlined style={{ color: 'var(--ant-color-text-tertiary)' }} />
          </Tooltip>
        </span>
      ),
      dataIndex: 'managed',
      key: 'managed',
      render: (v: boolean) =>
        v ? (
          <Tag color="blue">{t('install:table.managedFull')}</Tag>
        ) : (
          <Tag>{t('install:table.managedInstallOnly')}</Tag>
        ),
    },
    {
      title: '',
      key: 'actions',
      render: (_: unknown, r: ProviderInstall) =>
        r.installed ? (
          <span>{t('install:table.alreadyInstalled')}</span>
        ) : r.installable ? (
          <Button size="small" type="primary" loading={install.isPending} onClick={() => onInstall(r.name)}>
            {t('install:table.install')}
          </Button>
        ) : (
          <span style={{ color: 'var(--ant-color-text-tertiary)' }}>{t('install:table.unsupported')}</span>
        ),
    },
  ];

  return (
    <PageShell>
      <PageTitleBar
        extra={
          data && data.servers.length > 1 ? (
            <Select
              value={server ?? data.server_id}
              options={data.servers.map((s) => ({ value: s, label: s }))}
              onChange={setServer}
              style={{ width: 200 }}
            />
          ) : undefined
        }
      >
        <Space>
          <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/servers')} title={t('install:backToServers')} />
          {t('install:title')}
        </Space>
      </PageTitleBar>

      {data?.detect_error ? (
        <Alert type="error" showIcon message={t('install:detectError')} description={data.detect_error} style={{ marginBottom: 16 }} />
      ) : (
        data && (
          <Card style={{ marginBottom: 16 }}>
            <Space>
              <span>{t('install:host')} <strong>{data.host_pretty}</strong></span>
              <span>{t('install:pkgManager')} <code>{data.pkg_manager}</code></span>
              {!data.systemd && <Tag color="error">{t('install:noSystemd')}</Tag>}
            </Space>
          </Card>
        )
      )}

      <Card>
        <Table rowKey="name" columns={columns} dataSource={data?.providers ?? []} loading={isLoading} pagination={false} />
      </Card>

      {output && (
        <Card title={t('install:outputTitle')} style={{ marginTop: 16 }}>
          <Typography.Paragraph>
            <pre style={{ maxHeight: 400, overflow: 'auto', margin: 0 }}>{output}</pre>
          </Typography.Paragraph>
        </Card>
      )}

      <Typography.Paragraph type="secondary" style={{ marginTop: 16 }}>
        {t('install:disclaimer')}
      </Typography.Paragraph>
    </PageShell>
  );
}
