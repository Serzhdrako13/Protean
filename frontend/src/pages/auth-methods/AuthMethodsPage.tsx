import { useEffect, useState } from 'react';
import {
  Card, Form, Input, Switch, Button, Alert, Typography, Space, Tag, Table, Popconfirm, Select, message,
} from 'antd';
import { DeleteOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { HeaderTip } from '@/components/HeaderTip';
import { PageTitleBar } from '@/components/PageTitleBar';
import { ApiError } from '@/api/http-init';
import {
  useInternalAuthQuery, useLDAPSettingsQuery, useOIDCSettingsQuery, useAuthGroupRulesQuery,
  useAuthMethodsMutations, type LDAPSettingsInput, type OIDCSettingsInput, type AuthGroupRule,
} from '@/api/queries/auth-methods';

function GroupRulesEditor({ method }: { method: 'ldap' | 'oidc' }) {
  const { t } = useTranslation(['auth-methods', 'common']);
  const { data, isLoading } = useAuthGroupRulesQuery(method);
  const { addGroupRule, deleteGroupRule } = useAuthMethodsMutations();
  const [form] = Form.useForm<{ role: 'admin' | 'user'; group_value: string }>();

  async function onAdd() {
    try {
      const values = await form.validateFields();
      await addGroupRule.mutateAsync({ method, ...values });
      form.resetFields();
      message.success(t('common:actions.saved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onDelete(rule: AuthGroupRule) {
    try {
      await deleteGroupRule.mutateAsync(rule);
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  return (
    <>
      <Typography.Paragraph type="secondary">{t('groupRules.description')}</Typography.Paragraph>
      <Table<AuthGroupRule>
        rowKey={(r) => `${r.role}:${r.group_value}`}
        size="small"
        loading={isLoading}
        pagination={false}
        dataSource={data ?? []}
        style={{ marginBottom: 16 }}
        columns={[
          {
            title: t('groupRules.columns.role'), dataIndex: 'role', key: 'role',
            render: (v: string) => <Tag color={v === 'admin' ? 'gold' : 'blue'}>{t(`groupRules.role.${v}`)}</Tag>,
          },
          { title: t('groupRules.columns.value'), dataIndex: 'group_value', key: 'group_value', render: (v: string) => <code>{v}</code> },
          {
            title: '', key: 'actions',
            render: (_: unknown, r: AuthGroupRule) => (
              <Popconfirm title={t('groupRules.confirmDelete', { value: r.group_value })} onConfirm={() => onDelete(r)}>
                <Button size="small" danger icon={<DeleteOutlined />} />
              </Popconfirm>
            ),
          },
        ]}
      />
      <Form form={form} layout="inline" initialValues={{ role: 'user' }}>
        <Form.Item name="role">
          <Select
            style={{ width: 120 }}
            options={[
              { label: t('groupRules.role.admin'), value: 'admin' },
              { label: t('groupRules.role.user'), value: 'user' },
            ]}
          />
        </Form.Item>
        <Form.Item name="group_value" rules={[{ required: true, message: t('groupRules.form.valueRequired') }]}>
          <Input placeholder={t(`groupRules.form.valuePlaceholder.${method}`)} style={{ width: 320 }} />
        </Form.Item>
        <Form.Item>
          <Button onClick={onAdd} loading={addGroupRule.isPending}>{t('common:actions.add')}</Button>
        </Form.Item>
      </Form>
    </>
  );
}

function InternalAuthCard() {
  const { t } = useTranslation(['auth-methods', 'common']);
  const { data, isLoading } = useInternalAuthQuery();
  const { updateInternal } = useAuthMethodsMutations();

  return (
    <Card title={t('internal.title')} loading={isLoading} style={{ marginBottom: 16 }}>
      <Space align="center" size={12}>
        <Switch
          checked={data?.enabled ?? true}
          loading={updateInternal.isPending}
          onChange={(checked) => updateInternal.mutate({ enabled: checked })}
        />
        <span>{t('internal.enabledLabel')}</span>
      </Space>
      {data && !data.enabled && (
        <Alert type="warning" showIcon style={{ marginTop: 16 }} message={t('internal.disabledWarning')} />
      )}
      <Typography.Paragraph type="secondary" style={{ marginTop: 16, marginBottom: 0 }}>
        {t('internal.emergencyHint')}
      </Typography.Paragraph>
    </Card>
  );
}

function LDAPCard() {
  const { t } = useTranslation(['auth-methods', 'common']);
  const { data, isLoading } = useLDAPSettingsQuery();
  const { updateLDAP, testLDAP } = useAuthMethodsMutations();
  const [form] = Form.useForm<LDAPSettingsInput>();
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);

  useEffect(() => {
    if (!data) return;
    form.setFieldsValue({ ...data, bind_password: '' });
  }, [data, form]);

  async function onSave() {
    try {
      const values = await form.validateFields();
      await updateLDAP.mutateAsync(values);
      form.setFieldValue('bind_password', '');
      message.success(t('common:actions.saved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onTest() {
    setTestResult(null);
    try {
      const values = await form.validateFields();
      await testLDAP.mutateAsync(values);
      setTestResult({ ok: true, message: t('ldap.testOk') });
    } catch (e) {
      setTestResult({ ok: false, message: e instanceof ApiError ? e.message : String(e) });
    }
  }

  return (
    <Card title={t('ldap.title')} loading={isLoading} style={{ marginBottom: 16 }}>
      <Form form={form} layout="vertical" initialValues={{ user_filter: '(uid=%s)' }}>
        <Form.Item name="enabled" valuePropName="checked" label={t('ldap.enabledLabel')}>
          <Switch />
        </Form.Item>
        <Form.Item name="url" label={t('ldap.url.label')} rules={[{ required: true }]}>
          <Input placeholder="ldaps://ad.example.com:636" />
        </Form.Item>
        <Form.Item name="skip_tls_verify" valuePropName="checked" label={<HeaderTip label={t('ldap.skipTlsVerify.label')} tip={t('ldap.skipTlsVerify.tip')} />}>
          <Switch />
        </Form.Item>
        <Form.Item name="bind_dn" label={t('ldap.bindDn.label')}>
          <Input placeholder="cn=svc-protean,ou=service,dc=example,dc=com" />
        </Form.Item>
        <Form.Item name="bind_password" label={t('ldap.bindPassword.label')}>
          <Input.Password placeholder={data?.bind_password_set ? t('ldap.bindPassword.setPlaceholder') : ''} />
        </Form.Item>
        <Form.Item name="user_base_dn" label={t('ldap.userBaseDn.label')} rules={[{ required: true }]}>
          <Input placeholder="ou=people,dc=example,dc=com" />
        </Form.Item>
        <Form.Item name="user_filter" label={<HeaderTip label={t('ldap.userFilter.label')} tip={t('ldap.userFilter.tip')} />} rules={[{ required: true }]}>
          <Input placeholder="(uid=%s)" />
        </Form.Item>
        <Form.Item name="group_base_dn" label={<HeaderTip label={t('ldap.groupBaseDn.label')} tip={t('ldap.groupBaseDn.tip')} />}>
          <Input placeholder="ou=groups,dc=example,dc=com" />
        </Form.Item>
        <Space>
          <Button type="primary" onClick={onSave} loading={updateLDAP.isPending}>{t('common:actions.save')}</Button>
          <Button onClick={onTest} loading={testLDAP.isPending}>{t('common:actions.testConnection')}</Button>
        </Space>
        {testResult && (
          <Alert
            style={{ marginTop: 16 }}
            type={testResult.ok ? 'success' : 'error'}
            showIcon
            message={testResult.message}
          />
        )}
      </Form>
      <Typography.Title level={5} style={{ marginTop: 24 }}>{t('groupRules.title')}</Typography.Title>
      <GroupRulesEditor method="ldap" />
    </Card>
  );
}

function OIDCCard() {
  const { t } = useTranslation(['auth-methods', 'common']);
  const { data, isLoading } = useOIDCSettingsQuery();
  const { updateOIDC, testOIDC } = useAuthMethodsMutations();
  const [form] = Form.useForm<OIDCSettingsInput>();
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);

  useEffect(() => {
    if (!data) return;
    form.setFieldsValue({ ...data, client_secret: '' });
  }, [data, form]);

  async function onSave() {
    try {
      const values = await form.validateFields();
      await updateOIDC.mutateAsync(values);
      form.setFieldValue('client_secret', '');
      message.success(t('common:actions.saved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onTest() {
    setTestResult(null);
    try {
      const values = await form.validateFields();
      await testOIDC.mutateAsync({ issuer_url: values.issuer_url });
      setTestResult({ ok: true, message: t('oidc.testOk') });
    } catch (e) {
      setTestResult({ ok: false, message: e instanceof ApiError ? e.message : String(e) });
    }
  }

  const callbackURL = data?.redirect_base_url ? `${data.redirect_base_url}${data.callback_path}` : data?.callback_path;

  return (
    <Card title={t('oidc.title')} loading={isLoading} style={{ marginBottom: 16 }}>
      <Form form={form} layout="vertical" initialValues={{ scopes: 'openid profile email groups', username_claim: 'preferred_username', groups_claim: 'groups' }}>
        <Form.Item name="enabled" valuePropName="checked" label={t('oidc.enabledLabel')}>
          <Switch />
        </Form.Item>
        <Form.Item name="issuer_url" label={<HeaderTip label={t('oidc.issuerUrl.label')} tip={t('oidc.issuerUrl.tip')} />} rules={[{ required: true }]}>
          <Input placeholder="https://idp.example.com/realms/protean" />
        </Form.Item>
        <Form.Item name="client_id" label={t('oidc.clientId.label')} rules={[{ required: true }]}>
          <Input />
        </Form.Item>
        <Form.Item name="client_secret" label={t('oidc.clientSecret.label')}>
          <Input.Password placeholder={data?.client_secret_set ? t('oidc.clientSecret.setPlaceholder') : ''} />
        </Form.Item>
        <Form.Item name="redirect_base_url" label={<HeaderTip label={t('oidc.redirectBaseUrl.label')} tip={t('oidc.redirectBaseUrl.tip')} />} rules={[{ required: true }]}>
          <Input placeholder="https://vpn.example.com" />
        </Form.Item>
        {callbackURL && (
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
            message={t('oidc.callbackHint')}
            description={<Typography.Text code copyable>{callbackURL}</Typography.Text>}
          />
        )}
        <Form.Item name="scopes" label={t('oidc.scopes.label')}>
          <Input />
        </Form.Item>
        <Form.Item name="username_claim" label={<HeaderTip label={t('oidc.usernameClaim.label')} tip={t('oidc.usernameClaim.tip')} />}>
          <Input />
        </Form.Item>
        <Form.Item name="groups_claim" label={<HeaderTip label={t('oidc.groupsClaim.label')} tip={t('oidc.groupsClaim.tip')} />}>
          <Input />
        </Form.Item>
        <Space>
          <Button type="primary" onClick={onSave} loading={updateOIDC.isPending}>{t('common:actions.save')}</Button>
          <Button onClick={onTest} loading={testOIDC.isPending}>{t('common:actions.testConnection')}</Button>
        </Space>
        {testResult && (
          <Alert
            style={{ marginTop: 16 }}
            type={testResult.ok ? 'success' : 'error'}
            showIcon
            message={testResult.message}
          />
        )}
      </Form>
      <Typography.Title level={5} style={{ marginTop: 24 }}>{t('groupRules.title')}</Typography.Title>
      <GroupRulesEditor method="oidc" />
    </Card>
  );
}

export function AuthMethodsPage() {
  const { t } = useTranslation(['auth-methods', 'common']);

  return (
    <PageShell>
      <PageTitleBar>{t('title')}</PageTitleBar>
      <Typography.Paragraph type="secondary">{t('description')}</Typography.Paragraph>
      <InternalAuthCard />
      <LDAPCard />
      <OIDCCard />
    </PageShell>
  );
}
