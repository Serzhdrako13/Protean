import { useEffect, useState } from 'react';
import { Card, Form, Input, InputNumber, Select, Radio, Button, Alert, Typography, Space, Tag, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { HeaderTip } from '@/components/HeaderTip';
import { PageTitleBar } from '@/components/PageTitleBar';
import { useTLSQuery, useTLSMutations, type TLSSettings } from '@/api/queries/tls';
import { ApiError } from '@/api/http-init';

export function TLSPage() {
  const { t } = useTranslation(['tls', 'common']);
  const { data, isLoading } = useTLSQuery();
  const { update, reissueSelfSigned } = useTLSMutations();
  const [form] = Form.useForm<TLSSettings>();
  const mode = Form.useWatch('mode', form);
  const [acmePreset, setAcmePreset] = useState<string>('custom');

  const ACME_PRESETS = [
    { label: t('tls:acme.presets.letsEncryptProd'), value: 'https://acme-v02.api.letsencrypt.org/directory' },
    { label: t('tls:acme.presets.letsEncryptStaging'), value: 'https://acme-staging-v02.api.letsencrypt.org/directory' },
    { label: t('tls:acme.presets.custom'), value: 'custom' },
  ];

  const MODE_INFO: Record<TLSSettings['mode'], string> = {
    self_signed: t('tls:modeInfo.self_signed'),
    acme: t('tls:modeInfo.acme'),
    manual: t('tls:modeInfo.manual'),
    proxy: t('tls:modeInfo.proxy'),
  };

  useEffect(() => {
    if (!data) return;
    form.setFieldsValue(data.settings);
    const preset = ACME_PRESETS.find((p) => p.value === data.settings.acme_directory_url);
    setAcmePreset(preset ? preset.value : 'custom');
  }, [data, form]);

  async function onSave() {
    try {
      const values = await form.validateFields();
      await update.mutateAsync(values);
      message.success(t('tls:messages.saved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onReissue() {
    try {
      await reissueSelfSigned.mutateAsync();
      message.success(t('tls:messages.reissued'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  const status = data?.status;

  return (
    <PageShell>
      <PageTitleBar>{t('tls:title')}</PageTitleBar>

      <Card loading={isLoading} style={{ marginBottom: 16 }}>
        {status && (
          <Space direction="vertical" size={4}>
            <div>
              {t('tls:status.servingLabel')} <Tag color={status.degraded ? 'error' : 'success'}>{status.last_served || status.mode}</Tag>
              {status.degraded && <Tag color="warning">{t('tls:status.degradedTag', { mode: status.mode })}</Tag>}
            </div>
            {status.self_signed_expires_at && (
              <Typography.Text type="secondary">
                {t('tls:status.selfSignedExpires', { date: new Date(status.self_signed_expires_at).toLocaleString() })}
              </Typography.Text>
            )}
            {status.last_error && <Alert type="error" showIcon message={status.last_error} style={{ marginTop: 8 }} />}
          </Space>
        )}
      </Card>

      <Card title={t('tls:cardTitle')}>
        <Form form={form} layout="vertical">
          <Form.Item name="mode" label={t('tls:modeField.label')} rules={[{ required: true }]}>
            <Radio.Group
              options={[
                { label: t('tls:modeOptions.selfSigned'), value: 'self_signed' },
                { label: t('tls:modeOptions.acme'), value: 'acme' },
                { label: t('tls:modeOptions.manual'), value: 'manual' },
                { label: t('tls:modeOptions.proxy'), value: 'proxy' },
              ]}
            />
          </Form.Item>
          {mode && <Alert type="info" showIcon message={MODE_INFO[mode]} style={{ marginBottom: 16 }} />}

          {mode === 'self_signed' && (
            <>
              <Form.Item
                name="ss_key_algo"
                label={<HeaderTip label={t('tls:selfSigned.keyAlgo.label')} tip={t('tls:selfSigned.keyAlgo.tip')} />}
              >
                <Select
                  options={[
                    { label: t('tls:selfSigned.keyAlgoOptions.rsa2048'), value: 'rsa_2048' },
                    { label: t('tls:selfSigned.keyAlgoOptions.rsa4096'), value: 'rsa_4096' },
                    { label: t('tls:selfSigned.keyAlgoOptions.ecdsaP256'), value: 'ecdsa_p256' },
                    { label: t('tls:selfSigned.keyAlgoOptions.ecdsaP384'), value: 'ecdsa_p384' },
                  ]}
                />
              </Form.Item>
              <Form.Item name="ss_validity_days" label={t('tls:selfSigned.validityDays')} rules={[{ required: true }]}>
                <InputNumber min={1} max={3650} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item
                name="ss_renew_before_days"
                label={<HeaderTip label={t('tls:selfSigned.renewBefore.label')} tip={t('tls:selfSigned.renewBefore.tip')} />}
                rules={[{ required: true }]}
              >
                <InputNumber min={1} max={365} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item
                name="ss_sans"
                label={<HeaderTip label={t('tls:selfSigned.sans.label')} tip={t('tls:selfSigned.sans.tip')} />}
              >
                <Input placeholder="vpn.example.com, 203.0.113.10" />
              </Form.Item>
              <Button onClick={onReissue} loading={reissueSelfSigned.isPending} style={{ marginBottom: 12 }}>
                {t('tls:selfSigned.reissueButton')}
              </Button>
            </>
          )}

          {mode === 'acme' && (
            <>
              <Form.Item label={t('tls:acme.presetLabel')}>
                <Select
                  value={acmePreset}
                  options={ACME_PRESETS}
                  onChange={(v) => {
                    setAcmePreset(v);
                    if (v !== 'custom') form.setFieldValue('acme_directory_url', v);
                  }}
                />
              </Form.Item>
              <Form.Item
                name="acme_directory_url"
                label={<HeaderTip label={t('tls:acme.directoryUrl.label')} tip={t('tls:acme.directoryUrl.tip')} />}
                rules={[{ required: true }]}
              >
                <Input placeholder="https://acme.example.internal/acme/acme/directory" disabled={acmePreset !== 'custom'} />
              </Form.Item>
              <Form.Item name="acme_domains" label={t('tls:acme.domains')} rules={[{ required: true }]}>
                <Input placeholder="vpn.example.com" />
              </Form.Item>
              <Form.Item name="acme_email" label={t('tls:acme.email')}>
                <Input placeholder="admin@example.com" />
              </Form.Item>
              <Form.Item
                name="acme_challenge"
                label={<HeaderTip label={t('tls:acme.challenge.label')} tip={t('tls:acme.challenge.tip')} />}
              >
                <Radio.Group
                  options={[
                    { label: t('tls:acme.challengeOptions.tlsAlpn01'), value: 'tls-alpn-01' },
                    { label: t('tls:acme.challengeOptions.http01'), value: 'http-01' },
                  ]}
                />
              </Form.Item>
              <Form.Item
                name="acme_trust_root_pem"
                label={<HeaderTip label={t('tls:acme.trustRoot.label')} tip={t('tls:acme.trustRoot.tip')} />}
              >
                <Input.TextArea rows={4} placeholder="-----BEGIN CERTIFICATE-----" />
              </Form.Item>
            </>
          )}

          {mode === 'manual' && (
            <>
              {data?.settings.manual_has_key && (
                <Alert type="success" showIcon message={t('tls:manual.alreadyUploaded')} style={{ marginBottom: 12 }} />
              )}
              <Form.Item name="manual_cert_pem" label={t('tls:manual.certPem')} rules={[{ required: true }]}>
                <Input.TextArea rows={6} placeholder="-----BEGIN CERTIFICATE-----" />
              </Form.Item>
              <Form.Item
                name="manual_key_pem"
                label={<HeaderTip label={t('tls:manual.keyPem.label')} tip={t('tls:manual.keyPem.tip')} />}
              >
                <Input.TextArea rows={6} placeholder="-----BEGIN PRIVATE KEY-----" />
              </Form.Item>
            </>
          )}

          <Button type="primary" onClick={onSave} loading={update.isPending}>{t('common:actions.save')}</Button>
        </Form>
      </Card>
    </PageShell>
  );
}
