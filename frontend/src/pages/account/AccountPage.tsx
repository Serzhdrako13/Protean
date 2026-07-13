import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, Form, Input, Button, message, Tag, Image, Space, Modal, Alert } from 'antd';
import { ArrowLeftOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import {
  useAccountQuery,
  useChangePasswordMutation,
  useTOTPSetupMutation,
  useTOTPEnableMutation,
  useTOTPDisableMutation,
} from '@/api/queries/account';
import { usePasswordPolicyQuery } from '@/api/queries/password-policy';
import { ApiError } from '@/api/http-init';
import { ProteanBrand } from '@/components/ProteanBrand';
import { PageTitleBar } from '@/components/PageTitleBar';
import { PasswordPolicyHint } from '@/components/PasswordPolicyHint';
import { passwordPolicyIssues } from '@/utils/passwordPolicy';

export function AccountPage() {
  const { t } = useTranslation(['account', 'common']);
  const navigate = useNavigate();
  const { data } = useAccountQuery();
  const { data: policy } = usePasswordPolicyQuery();
  const changePassword = useChangePasswordMutation();
  const totpSetup = useTOTPSetupMutation();
  const totpEnable = useTOTPEnableMutation();
  const totpDisable = useTOTPDisableMutation();

  const [pwForm] = Form.useForm();
  const [enrollOpen, setEnrollOpen] = useState(false);
  const [enroll, setEnroll] = useState<{ secret: string; qr_png: string } | null>(null);
  const [enrollForm] = Form.useForm();
  const [disableOpen, setDisableOpen] = useState(false);
  const [disableForm] = Form.useForm();

  async function onChangePassword() {
    try {
      const { current_password, new_password } = await pwForm.validateFields();
      await changePassword.mutateAsync({ current_password, new_password });
      pwForm.resetFields();
      message.success(t('account:password.changeSuccess'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onStartEnroll() {
    try {
      const res = await totpSetup.mutateAsync();
      setEnroll(res);
      setEnrollOpen(true);
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onConfirmEnroll() {
    if (!enroll) return;
    try {
      const { code } = await enrollForm.validateFields();
      await totpEnable.mutateAsync({ secret: enroll.secret, code });
      setEnrollOpen(false);
      message.success(t('account:totp.enableSuccess'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onDisable() {
    try {
      const { password } = await disableForm.validateFields();
      await totpDisable.mutateAsync({ password });
      setDisableOpen(false);
      message.success(t('account:totp.disableSuccess'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  return (
    <PageShell>
      <div style={{ textAlign: 'center', margin: '8px 0 24px' }}>
        <ProteanBrand size="md" />
      </div>
      <PageTitleBar>
        <Space align="center">
          <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/')} title={t('account:backToHome')} />
          {t('account:title')}
        </Space>
      </PageTitleBar>

      {data?.password_expired && (
        <Alert type="warning" showIcon message={t('account:password.expired')} style={{ marginBottom: 16 }} />
      )}

      <Card title={t('account:userCard.title', { username: data?.username ?? '' })} style={{ marginBottom: 16 }}>
        <PasswordPolicyHint policy={policy} />
        <Form form={pwForm} layout="vertical">
          <Form.Item name="current_password" label={t('account:password.currentPassword')} rules={[{ required: true }]}>
            <Input.Password />
          </Form.Item>
          <Form.Item
            name="new_password"
            label={t('account:password.newPassword')}
            dependencies={['confirm_password']}
            rules={[
              { required: true },
              {
                validator: (_, value: string) => {
                  if (!policy || !value) return Promise.resolve();
                  const issues = passwordPolicyIssues(policy, value);
                  if (issues.length === 0) return Promise.resolve();
                  return Promise.reject(new Error(t('common:passwordPolicy.missing', { list: issues.map((k) => t(`common:passwordPolicy.${k}`)).join(', ') })));
                },
              },
            ]}
          >
            <Input.Password />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            label={t('common:passwordPolicy.confirmPassword')}
            dependencies={['new_password']}
            rules={[
              { required: true, message: t('common:passwordPolicy.confirmRequired') },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue('new_password') === value) return Promise.resolve();
                  return Promise.reject(new Error(t('common:passwordPolicy.confirmMismatch')));
                },
              }),
            ]}
          >
            <Input.Password />
          </Form.Item>
          <Button type="primary" onClick={onChangePassword} loading={changePassword.isPending}>{t('account:password.changeButton')}</Button>
        </Form>
      </Card>

      <Card title={t('account:totp.cardTitle')}>
        <Space orientation="vertical" size="middle">
          <div>
            {t('account:totp.status')} {data?.totp_enabled ? <Tag color="success">{t('account:totp.enabled')}</Tag> : <Tag>{t('account:totp.disabled')}</Tag>}
          </div>
          {!data?.totp_enabled && (
            <Button onClick={onStartEnroll} loading={totpSetup.isPending}>{t('account:totp.enableButton')}</Button>
          )}
          {data?.totp_enabled && (
            <Button danger onClick={() => setDisableOpen(true)}>{t('account:totp.disableButton')}</Button>
          )}
        </Space>
      </Card>

      <Modal title={t('account:totp.enableModalTitle')} open={enrollOpen} onCancel={() => setEnrollOpen(false)} onOk={onConfirmEnroll} confirmLoading={totpEnable.isPending}>
        {enroll && (
          <Space orientation="vertical" align="center" style={{ width: '100%' }}>
            <Image src={enroll.qr_png} width={200} preview={false} />
            <code>{enroll.secret}</code>
            <Form form={enrollForm} layout="vertical" style={{ width: '100%' }}>
              <Form.Item name="code" label={t('account:totp.codeLabel')} rules={[{ required: true, len: 6 }]}>
                <Input maxLength={6} />
              </Form.Item>
            </Form>
          </Space>
        )}
      </Modal>

      <Modal title={t('account:totp.disableModalTitle')} open={disableOpen} onCancel={() => setDisableOpen(false)} onOk={onDisable} confirmLoading={totpDisable.isPending}>
        <Form form={disableForm} layout="vertical">
          <Form.Item name="password" label={t('account:totp.passwordLabel')} rules={[{ required: true }]}>
            <Input.Password />
          </Form.Item>
        </Form>
      </Modal>
    </PageShell>
  );
}
