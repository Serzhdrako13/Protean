import { useEffect, useState, type ReactNode } from 'react';
import {
  Card, Form, InputNumber, Switch, Button, Table, Tag, Input, Select,
  Popconfirm, message, Typography, Statistic, Row, Col,
} from 'antd';
import { DeleteOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { HeaderTip } from '@/components/HeaderTip';
import { PageTitleBar } from '@/components/PageTitleBar';
import { ApiError } from '@/api/http-init';
import {
  useLoginSecuritySettingsQuery, useLoginIPRulesQuery, useLoginBansQuery, useLoginSecurityStatsQuery,
  useLoginSecurityMutations, type LoginSecuritySettings, type LoginIPRule, type LoginBan, type LoginAttempt,
} from '@/api/queries/login-security';
import { usePasswordPolicyQuery, usePasswordPolicyMutations, type PasswordPolicySettings } from '@/api/queries/password-policy';

// Shared column template for every field grid on this page -- both cards
// use the exact same track size, so rows line up visually whether they're
// side by side (desktop) or stacked (mobile), regardless of how many
// fields each card happens to have.
const FIELD_GRID_STYLE = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))',
  gap: 16,
  marginBottom: 16,
} as const;

// A label can be one word ("Мин. длина") or a HeaderTip-wrapped phrase with
// a tooltip icon that wraps to 2-3 lines -- left free-height, that ragged
// label row pushed each field's INPUT to a different y-position ("staircase").
// Clamping every label to exactly 2 lines (same height for all, short or
// long) means the inputs below always start at the same baseline.
function FieldLabel({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
        overflow: 'hidden', minHeight: '2.6em', lineHeight: '1.3em',
      }}
    >
      {children}
    </div>
  );
}

// Numeric settings on this page are all 1-6 char values (min length, days,
// hours, minutes...) -- a 100%-width InputNumber inside a half/third grid
// column was mostly empty space. Each cell is a grid track instead (see
// FIELD_GRID_STYLE), sized to content, not stretched.
function NumberField({ name, label, ...rest }: { name: string; label: ReactNode; min?: number; max?: number; step?: number }) {
  return (
    <Form.Item name={name} label={<FieldLabel>{label}</FieldLabel>} rules={[{ required: true }]} style={{ marginBottom: 0 }}>
      <InputNumber {...rest} style={{ width: '100%' }} />
    </Form.Item>
  );
}

// Switch labels on this page are all one short word/phrase (unlike the
// number fields' HeaderTip-wrapped ones) so they don't need the 2-line
// clamp -- kept as a plain label-above-control Form.Item.
function SwitchField({ name, label }: { name: string; label: ReactNode }) {
  return (
    <Form.Item name={name} label={label} valuePropName="checked" style={{ marginBottom: 0 }}>
      <Switch />
    </Form.Item>
  );
}

function PasswordPolicyCard() {
  const { t } = useTranslation(['login-security', 'common']);
  const { data, isLoading } = usePasswordPolicyQuery();
  const { update } = usePasswordPolicyMutations();
  const [form] = Form.useForm<PasswordPolicySettings>();

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

  return (
    <Card title={t('passwordPolicyCard.title')} loading={isLoading} style={{ height: '100%' }}>
      <Form form={form} layout="vertical">
        <div style={FIELD_GRID_STYLE}>
          <SwitchField name="require_upper" label={t('passwordPolicyCard.requireUpper')} />
          <SwitchField name="require_lower" label={t('passwordPolicyCard.requireLower')} />
          <SwitchField name="require_digit" label={t('passwordPolicyCard.requireDigit')} />
          <SwitchField name="require_symbol" label={t('passwordPolicyCard.requireSymbol')} />
        </div>
        <div style={FIELD_GRID_STYLE}>
          <NumberField name="min_length" label={t('passwordPolicyCard.minLength')} min={1} max={128} />
          <NumberField
            name="max_age_days"
            label={<HeaderTip label={t('passwordPolicyCard.maxAge')} tip={t('passwordPolicyCard.maxAgeTip')} />}
            min={0}
          />
          <NumberField
            name="session_ttl_hours"
            label={<HeaderTip label={t('passwordPolicyCard.sessionTTL')} tip={t('passwordPolicyCard.sessionTTLTip')} />}
            min={1}
          />
        </div>
        <Button type="primary" onClick={onSave} loading={update.isPending}>
          {t('common:actions.save')}
        </Button>
      </Form>
    </Card>
  );
}

function SettingsCard() {
  const { t } = useTranslation(['login-security', 'common']);
  const { data, isLoading } = useLoginSecuritySettingsQuery();
  const { updateSettings } = useLoginSecurityMutations();
  const [form] = Form.useForm<LoginSecuritySettings>();

  useEffect(() => {
    if (data) form.setFieldsValue(data);
  }, [data, form]);

  async function onSave() {
    try {
      const values = await form.validateFields();
      await updateSettings.mutateAsync(values);
      message.success(t('common:actions.saved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  return (
    <Card title={t('settingsCard.title')} loading={isLoading} style={{ height: '100%' }}>
      <Form form={form} layout="vertical">
        <div style={FIELD_GRID_STYLE}>
          <SwitchField name="enabled" label={t('settingsCard.enabled')} />
          <SwitchField name="track_by_username" label={t('settingsCard.trackByUsername')} />
          <SwitchField name="track_by_ip" label={t('settingsCard.trackByIP')} />
        </div>
        <div style={FIELD_GRID_STYLE}>
          <NumberField
            name="fail_threshold"
            label={<HeaderTip label={t('settingsCard.failThreshold')} tip={t('settingsCard.failThresholdTip')} />}
            min={1} max={100}
          />
          <NumberField
            name="count_window_minutes"
            label={<HeaderTip label={t('settingsCard.countWindow')} tip={t('settingsCard.countWindowTip')} />}
            min={1} max={1440}
          />
          <NumberField name="ban_base_minutes" label={t('settingsCard.banBase')} min={1} max={1440} />
          <NumberField
            name="escalation_factor"
            label={<HeaderTip label={t('settingsCard.escalationFactor')} tip={t('settingsCard.escalationFactorTip')} />}
            min={1} step={0.5}
          />
          <NumberField
            name="escalation_reset_minutes"
            label={<HeaderTip label={t('settingsCard.escalationReset')} tip={t('settingsCard.escalationResetTip')} />}
            min={1} max={10080}
          />
          <NumberField name="max_ban_minutes" label={t('settingsCard.maxBan')} min={1} />
        </div>
        <Button type="primary" onClick={onSave} loading={updateSettings.isPending}>
          {t('common:actions.save')}
        </Button>
      </Form>
    </Card>
  );
}

function IPRulesCard() {
  const { t } = useTranslation(['login-security', 'common']);
  const { data, isLoading } = useLoginIPRulesQuery();
  const { addIPRule, deleteIPRule } = useLoginSecurityMutations();
  const [form] = Form.useForm();

  async function onAdd() {
    try {
      const values = await form.validateFields();
      await addIPRule.mutateAsync(values);
      form.resetFields();
      message.success(t('common:actions.saved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onDelete(ip: string) {
    try {
      await deleteIPRule.mutateAsync(ip);
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  return (
    <Card title={t('ipRulesCard.title')} loading={isLoading} style={{ marginBottom: 16 }}>
      <Typography.Paragraph type="secondary">{t('ipRulesCard.description')}</Typography.Paragraph>
      <Table<LoginIPRule>
        rowKey="ip_or_cidr"
        size="small"
        pagination={false}
        dataSource={data ?? []}
        style={{ marginBottom: 16 }}
        columns={[
          { title: t('ipRulesCard.columns.ip'), dataIndex: 'ip_or_cidr', key: 'ip_or_cidr', render: (v: string) => <code>{v}</code> },
          {
            title: t('ipRulesCard.columns.kind'), dataIndex: 'kind', key: 'kind',
            render: (v: string) => <Tag color={v === 'deny' ? 'error' : 'success'}>{t(`ipRulesCard.kind.${v}`)}</Tag>,
          },
          { title: t('ipRulesCard.columns.note'), dataIndex: 'note', key: 'note' },
          {
            title: '', key: 'actions',
            render: (_: unknown, r: LoginIPRule) => (
              <Popconfirm title={t('ipRulesCard.confirmDelete', { ip: r.ip_or_cidr })} onConfirm={() => onDelete(r.ip_or_cidr)}>
                <Button size="small" danger icon={<DeleteOutlined />} />
              </Popconfirm>
            ),
          },
        ]}
      />
      <Form form={form} layout="inline" initialValues={{ kind: 'deny' }}>
        <Form.Item name="ip_or_cidr" rules={[{ required: true, message: t('ipRulesCard.form.ipRequired') }]}>
          <Input placeholder={t('ipRulesCard.form.ipPlaceholder')} style={{ width: 200 }} />
        </Form.Item>
        <Form.Item name="kind">
          <Select
            style={{ width: 120 }}
            options={[
              { label: t('ipRulesCard.kind.deny'), value: 'deny' },
              { label: t('ipRulesCard.kind.allow'), value: 'allow' },
            ]}
          />
        </Form.Item>
        <Form.Item name="note">
          <Input placeholder={t('ipRulesCard.form.notePlaceholder')} style={{ width: 200 }} />
        </Form.Item>
        <Form.Item>
          <Button onClick={onAdd} loading={addIPRule.isPending}>{t('common:actions.add')}</Button>
        </Form.Item>
      </Form>
    </Card>
  );
}

function BansCard() {
  const { t } = useTranslation(['login-security', 'common']);
  const { data, isLoading } = useLoginBansQuery();
  const { unban } = useLoginSecurityMutations();

  async function onUnban(b: LoginBan) {
    try {
      await unban.mutateAsync({ key_type: b.key_type, key_value: b.key_value });
      message.success(t('bansCard.unbanned'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  return (
    <Card title={t('bansCard.title')} loading={isLoading} style={{ marginBottom: 16 }}>
      <Table<LoginBan>
        rowKey={(b) => `${b.key_type}:${b.key_value}`}
        size="small"
        pagination={false}
        dataSource={data ?? []}
        locale={{ emptyText: t('bansCard.empty') }}
        columns={[
          { title: t('bansCard.columns.type'), dataIndex: 'key_type', key: 'key_type', render: (v: string) => t(`bansCard.type.${v}`) },
          { title: t('bansCard.columns.value'), dataIndex: 'key_value', key: 'key_value', render: (v: string) => <code>{v}</code> },
          { title: t('bansCard.columns.until'), dataIndex: 'banned_until', key: 'banned_until', render: (v: string) => new Date(v).toLocaleString() },
          { title: t('bansCard.columns.level'), dataIndex: 'escalation_level', key: 'escalation_level' },
          {
            title: '', key: 'actions',
            render: (_: unknown, b: LoginBan) => (
              <Popconfirm title={t('bansCard.confirmUnban', { value: b.key_value })} onConfirm={() => onUnban(b)}>
                <Button size="small">{t('bansCard.unban')}</Button>
              </Popconfirm>
            ),
          },
        ]}
      />
    </Card>
  );
}

function StatsCard() {
  const { t } = useTranslation(['login-security', 'common']);
  const { data, isLoading } = useLoginSecurityStatsQuery();

  return (
    <Card title={t('statsCard.title')} loading={isLoading}>
      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col span={12}><Statistic title={t('statsCard.total24h')} value={data?.total_attempts_24h ?? 0} /></Col>
        <Col span={12}><Statistic title={t('statsCard.failed24h')} value={data?.failed_attempts_24h ?? 0} /></Col>
      </Row>
      {!!data?.top_ips_24h.length && (
        <>
          <Typography.Title level={5}>{t('statsCard.topIPs')}</Typography.Title>
          <Table
            size="small"
            rowKey="ip"
            pagination={false}
            dataSource={data.top_ips_24h}
            style={{ marginBottom: 16 }}
            columns={[
              { title: t('ipRulesCard.columns.ip'), dataIndex: 'ip', key: 'ip', render: (v: string) => <code>{v}</code> },
              { title: t('statsCard.count'), dataIndex: 'count', key: 'count' },
            ]}
          />
        </>
      )}
      <Typography.Title level={5}>{t('statsCard.recent')}</Typography.Title>
      <Table<LoginAttempt>
        size="small"
        rowKey={(a) => `${a.ts}-${a.ip}-${a.username}`}
        pagination={{ pageSize: 10 }}
        dataSource={data?.recent ?? []}
        columns={[
          { title: t('statsCard.columns.ts'), dataIndex: 'ts', key: 'ts', render: (v: string) => new Date(v).toLocaleString() },
          { title: t('statsCard.columns.username'), dataIndex: 'username', key: 'username' },
          { title: t('statsCard.columns.ip'), dataIndex: 'ip', key: 'ip', render: (v: string) => <code>{v}</code> },
          {
            title: t('statsCard.columns.result'), dataIndex: 'success', key: 'success',
            render: (v: boolean, r: LoginAttempt) => (v
              ? <Tag color="success">{t('statsCard.success')}</Tag>
              : <Tag color="error">{r.reason ? t(`statsCard.reason.${r.reason}`, r.reason) : t('statsCard.failed')}</Tag>),
          },
        ]}
      />
    </Card>
  );
}

export function LoginSecurityPage() {
  const { t } = useTranslation('login-security');
  return (
    <PageShell>
      <PageTitleBar>{t('title')}</PageTitleBar>
      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col xs={24} lg={12}><PasswordPolicyCard /></Col>
        <Col xs={24} lg={12}><SettingsCard /></Col>
      </Row>
      <IPRulesCard />
      <BansCard />
      <StatsCard />
    </PageShell>
  );
}
