import { useEffect, useState } from 'react';
import { Card, Collapse, Form, Input, Switch, Button, InputNumber, Space, message, Tag, Tooltip, Row, Col, Typography } from 'antd';
import { SendOutlined, QuestionCircleOutlined, DownloadOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { PageTitleBar } from '@/components/PageTitleBar';
import { useNotifyMutations, useNotifyQuery } from '@/api/queries/notify';
import type { NotifyChannel, NotifySettings } from '@/types/api';
import { ApiError } from '@/api/http-init';

// Switch + label + optional tooltip, on one row — replaces Checkbox (its
// thin border became nearly invisible in the dark theme after the pastel
// pass) and doubles as the place to explain what each toggle actually does.
function SwitchField({ name, label, tooltip }: { name: string; label: string; tooltip?: string }) {
  return (
    <Form.Item name={name} valuePropName="checked" noStyle>
      <SwitchRow label={label} tooltip={tooltip} />
    </Form.Item>
  );
}

function SwitchRow({
  label, tooltip, checked, onChange,
}: { label: string; tooltip?: string; checked?: boolean; onChange?: (v: boolean) => void }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0' }}>
      <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        {label}
        {tooltip && (
          <Tooltip title={tooltip}>
            <QuestionCircleOutlined style={{ color: 'var(--ant-color-text-tertiary)' }} />
          </Tooltip>
        )}
      </span>
      <Switch checked={checked} onChange={onChange} />
    </div>
  );
}

function ChannelPanel({ channel }: { channel: NotifyChannel }) {
  const { t } = useTranslation(['notifications', 'common']);
  const { saveChannel, testChannel } = useNotifyMutations();
  const [form] = Form.useForm();

  useEffect(() => {
    const values: Record<string, unknown> = { enabled: channel.Enabled };
    for (const f of channel.Fields) values[f.Key] = f.Secret ? '' : f.Value;
    form.setFieldsValue(values);
  }, [channel, form]);

  async function onSave() {
    try {
      const values = await form.validateFields();
      await saveChannel.mutateAsync({ kind: channel.Kind, ...values });
      message.success(t('notifications:channel.saveSuccess'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onTest() {
    try {
      await testChannel.mutateAsync(channel.Kind);
      message.success(t('notifications:channel.testSuccess'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  return (
    <Form form={form} layout="vertical">
      <Form.Item name="enabled" valuePropName="checked" noStyle>
        <SwitchRow label={t('notifications:channel.enabled')} />
      </Form.Item>
      {channel.Fields.map((f) => (
        <Form.Item
          key={f.Key}
          name={f.Key}
          label={f.Secret ? (f.Set ? t('notifications:channel.secretAlreadySet', { label: f.Label }) : f.Label) : f.Label}
          style={{ marginTop: 12 }}
        >
          {f.Secret ? <Input.Password placeholder={f.Set ? t('notifications:channel.passwordPlaceholderSet') : ''} /> : <Input />}
        </Form.Item>
      ))}
      <Space>
        <Button type="primary" onClick={onSave} loading={saveChannel.isPending}>{t('notifications:channel.save')}</Button>
        <Button icon={<SendOutlined />} onClick={onTest} loading={testChannel.isPending}>{t('notifications:channel.test')}</Button>
      </Space>
    </Form>
  );
}

export function NotificationsPage() {
  const { t } = useTranslation(['notifications', 'common']);
  const { data, isLoading } = useNotifyQuery();
  const { saveSettings } = useNotifyMutations();
  const [settingsForm] = Form.useForm<NotifySettings>();
  const [settingsLoaded, setSettingsLoaded] = useState(false);

  useEffect(() => {
    if (data && !settingsLoaded) {
      settingsForm.setFieldsValue(data.settings);
      setSettingsLoaded(true);
    }
  }, [data, settingsForm, settingsLoaded]);

  async function onSaveSettings() {
    try {
      const values = await settingsForm.validateFields();
      await saveSettings.mutateAsync(values);
      message.success(t('notifications:settings.saveSuccess'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  return (
    <PageShell>
      <PageTitleBar>
        {t('notifications:heading')} {data && data.pending_count > 0 && (
          <Tag color="processing">{t('notifications:pendingCount', { count: data.pending_count })}</Tag>
        )}
      </PageTitleBar>

      <Row gutter={20}>
        <Col xs={24} lg={9}>
          <Card title={t('notifications:settings.cardTitle')} loading={isLoading} style={{ marginBottom: 16 }}>
            <Form form={settingsForm} layout="vertical">
              <Form.Item label={t('notifications:settings.events.label')}>
                <SwitchField
                  name="ev_iface_updown"
                  label={t('notifications:settings.events.ifaceUpdown.label')}
                  tooltip={t('notifications:settings.events.ifaceUpdown.tooltip')}
                />
                <SwitchField
                  name="ev_site_connect"
                  label={t('notifications:settings.events.siteConnect.label')}
                  tooltip={t('notifications:settings.events.siteConnect.tooltip')}
                />
                <SwitchField
                  name="ev_site_disconnect"
                  label={t('notifications:settings.events.siteDisconnect.label')}
                  tooltip={t('notifications:settings.events.siteDisconnect.tooltip')}
                />
                <SwitchField
                  name="ev_client_connect"
                  label={t('notifications:settings.events.clientConnect.label')}
                  tooltip={t('notifications:settings.events.clientConnect.tooltip')}
                />
                <SwitchField
                  name="ev_client_disconnect"
                  label={t('notifications:settings.events.clientDisconnect.label')}
                  tooltip={t('notifications:settings.events.clientDisconnect.tooltip')}
                />
                <SwitchField
                  name="ev_unknown_peer"
                  label={t('notifications:settings.events.unknownPeer.label')}
                  tooltip={t('notifications:settings.events.unknownPeer.tooltip')}
                />
              </Form.Item>

              <Form.Item label={t('notifications:settings.report.label')}>
                <SwitchField
                  name="report_enabled"
                  label={t('notifications:settings.report.enable.label')}
                  tooltip={t('notifications:settings.report.enable.tooltip')}
                />
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0' }}>
                  <span>{t('notifications:settings.report.intervalHours')}</span>
                  <Form.Item name="report_interval_hours" noStyle>
                    <InputNumber min={1} max={168} size="small" controls={false} style={{ width: 52, flex: '0 0 auto', textAlign: 'center' }} />
                  </Form.Item>
                </div>
                <SwitchField
                  name="report_include_events"
                  label={t('notifications:settings.report.includeEvents.label')}
                  tooltip={t('notifications:settings.report.includeEvents.tooltip')}
                />
                <SwitchField
                  name="report_include_status"
                  label={t('notifications:settings.report.includeStatus.label')}
                  tooltip={t('notifications:settings.report.includeStatus.tooltip')}
                />
              </Form.Item>

              <Form.Item label={t('notifications:settings.content.label')}>
                <SwitchField
                  name="ctnt_provider"
                  label={t('notifications:settings.content.provider.label')}
                  tooltip={t('notifications:settings.content.provider.tooltip')}
                />
                <SwitchField
                  name="ctnt_endpoint"
                  label={t('notifications:settings.content.endpoint.label')}
                  tooltip={t('notifications:settings.content.endpoint.tooltip')}
                />
                <SwitchField
                  name="ctnt_address"
                  label={t('notifications:settings.content.address.label')}
                  tooltip={t('notifications:settings.content.address.tooltip')}
                />
                <SwitchField
                  name="ctnt_time"
                  label={t('notifications:settings.content.time.label')}
                  tooltip={t('notifications:settings.content.time.tooltip')}
                />
              </Form.Item>

              <Button type="primary" onClick={onSaveSettings} loading={saveSettings.isPending}>
                {t('notifications:settings.saveButton')}
              </Button>
            </Form>
          </Card>
        </Col>

        <Col xs={24} lg={15}>
          <Card title={t('notifications:channelsCard.title')} loading={isLoading}>
            <Collapse
              items={(data?.channels ?? []).map((ch) => ({
                key: ch.Kind,
                label: (
                  <Space>
                    {ch.Label}
                    {ch.Enabled ? (
                      <Tag color="success">{t('notifications:channel.statusEnabled')}</Tag>
                    ) : (
                      <Tag>{t('notifications:channel.statusDisabled')}</Tag>
                    )}
                  </Space>
                ),
                children: <ChannelPanel channel={ch} />,
              }))}
            />
          </Card>
        </Col>
      </Row>

      <Card title={t('notifications:zabbix.cardTitle')} style={{ marginTop: 16 }}>
        <Typography.Paragraph type="secondary">{t('notifications:zabbix.description')}</Typography.Paragraph>
        <Space wrap>
          <Button icon={<DownloadOutlined />} href="/api/zabbix/template?version=7.4">
            {t('notifications:zabbix.download74')}
          </Button>
          <Button icon={<DownloadOutlined />} href="/api/zabbix/template?version=8.0">
            {t('notifications:zabbix.download80')}
          </Button>
        </Space>
      </Card>
    </PageShell>
  );
}
