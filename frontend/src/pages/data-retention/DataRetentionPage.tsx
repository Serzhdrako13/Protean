import { useEffect, useState } from 'react';
import { Card, Form, InputNumber, Switch, Button, Row, Col, Typography, Popconfirm, message } from 'antd';
import { ClearOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { PageTitleBar } from '@/components/PageTitleBar';
import { HeaderTip } from '@/components/HeaderTip';
import { ApiError } from '@/api/http-init';
import {
  useDataRetentionSettingsQuery, useDataRetentionMutations, type DataRetentionSettings,
} from '@/api/queries/data-retention';

const CATEGORIES: { key: keyof DataRetentionSettings & string; daysKey: keyof DataRetentionSettings & string }[] = [
  { key: 'access_requests_enabled', daysKey: 'access_requests_days' },
  { key: 'audit_log_enabled', daysKey: 'audit_log_days' },
  { key: 'login_attempts_enabled', daysKey: 'login_attempts_days' },
  { key: 'login_bans_enabled', daysKey: 'login_bans_days' },
];

const LABEL_KEYS: Record<string, string> = {
  access_requests_enabled: 'accessRequests',
  audit_log_enabled: 'auditLog',
  login_attempts_enabled: 'loginAttempts',
  login_bans_enabled: 'loginBans',
};

export function DataRetentionPage() {
  const { t } = useTranslation(['data-retention', 'common']);
  const { data, isLoading } = useDataRetentionSettingsQuery();
  const { update, cleanupNow } = useDataRetentionMutations();
  const [form] = Form.useForm<DataRetentionSettings>();

  useEffect(() => {
    if (data) form.setFieldsValue(data);
  }, [data, form]);

  async function onSave() {
    try {
      const values = await form.validateFields();
      await update.mutateAsync(values);
      message.success(t('common:actions.saved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onCleanupNow() {
    try {
      const res = await cleanupNow.mutateAsync();
      message.success(t('data-retention:cleanupNow.result', {
        accessRequests: res.access_requests_deleted,
        auditLog: res.audit_log_deleted,
        loginAttempts: res.login_attempts_deleted,
        loginBans: res.login_bans_deleted,
        sessions: res.sessions_deleted,
      }));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  return (
    <PageShell>
      <PageTitleBar>{t('data-retention:title')}</PageTitleBar>
      <Typography.Paragraph type="secondary">{t('data-retention:intro')}</Typography.Paragraph>
      <Card title={t('data-retention:card.title')} loading={isLoading} style={{ marginBottom: 16 }}>
        <Form form={form} layout="vertical">
          {CATEGORIES.map(({ key, daysKey }) => (
            <Row gutter={16} key={key} align="middle">
              <Col span={12}>
                <Form.Item
                  name={key}
                  label={<HeaderTip label={t(`data-retention:categories.${LABEL_KEYS[key]}`)} tip={t(`data-retention:categories.${LABEL_KEYS[key]}Tip`)} />}
                  valuePropName="checked"
                >
                  <Switch />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name={daysKey} label={t('data-retention:card.days')} rules={[{ required: true }]}>
                  <InputNumber min={1} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
            </Row>
          ))}
          <Button type="primary" onClick={onSave} loading={update.isPending}>
            {t('common:actions.save')}
          </Button>
        </Form>
      </Card>
      <Popconfirm
        title={t('data-retention:cleanupNow.confirmTitle')}
        description={t('data-retention:cleanupNow.confirmContent')}
        onConfirm={onCleanupNow}
      >
        <Button danger icon={<ClearOutlined />} loading={cleanupNow.isPending}>
          {t('data-retention:cleanupNow.button')}
        </Button>
      </Popconfirm>
    </PageShell>
  );
}
