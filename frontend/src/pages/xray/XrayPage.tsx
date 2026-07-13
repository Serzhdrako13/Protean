import { useEffect, useState } from 'react';
import {
  Card, Space, Tag, Form, Select, Input, Button, Table, Modal, Image,
  Popconfirm, message, Skeleton, Empty, Typography,
} from 'antd';
import {
  PlusOutlined, CopyOutlined, QrcodeOutlined, DeleteOutlined, LinkOutlined,
  ArrowUpOutlined, ArrowDownOutlined,
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { useXrayQuery, useXrayMutations } from '@/api/queries/xray';
import { ApiError } from '@/api/http-init';
import type { XrayClient } from '@/types/api';

// Embedded into ProviderDetailPage when a provider's type is "xray" — Xray
// isn't peer-based like the wg-family providers (no AllowedIPs/handshake),
// it's one chosen strategy (transport+security+protocol combo) + a client
// list keyed by name/uuid, so it gets its own UI rather than reusing the
// peer table.
export function XrayPage({ provider }: { provider: string }) {
  const { t } = useTranslation(['xray', 'common']);
  const [strategy, setStrategy] = useState<string | undefined>(undefined);
  const { data, isLoading } = useXrayQuery(provider, strategy);
  const { apply, addClient, removeClient } = useXrayMutations(provider);
  const [form] = Form.useForm();
  const [qrClient, setQrClient] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [addForm] = Form.useForm();

  useEffect(() => {
    if (!data) return;
    if (!strategy) {
      const sel = data.strategies.find((s) => s.selected);
      if (sel) setStrategy(sel.name);
    }
    const values: Record<string, unknown> = {
      relay_links: data.relay_chain?.length ? data.relay_chain.map(() => '') : [],
    };
    for (const p of data.param_specs) values[p.key] = p.secret ? '' : p.value;
    form.setFieldsValue(values);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  async function onApply() {
    if (!strategy) return;
    try {
      const values = await form.validateFields();
      const { relay_links, ...params } = values;
      const links: string[] = (relay_links ?? []).filter((l: string) => l && l.trim() !== '');
      await apply.mutateAsync({ strategy, params, relay_links: links });
      message.success(t('xray:messages.applied'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onAddClient() {
    try {
      const { name } = await addForm.validateFields();
      await addClient.mutateAsync(name);
      setAddOpen(false);
      message.success(t('xray:messages.clientAdded'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  function copyLink(link: string) {
    navigator.clipboard.writeText(link);
    message.success(t('xray:messages.linkCopied'));
  }

  if (isLoading) return <Skeleton active />;
  if (!data) return <Empty description={t('xray:empty')} />;

  const canAddClient = data.multi_client || data.clients.length === 0;

  return (
    <>
      <Card style={{ marginBottom: 16 }}>
        <Space wrap>
          <span>{t('xray:status.label')}</span>
          {data.up ? <Tag color="success">● UP</Tag> : <Tag color="error">● DOWN</Tag>}
          {data.configured && <Tag color="blue">{t('xray:status.strategyTag', { name: data.current })}</Tag>}
          {data.has_relay && data.relay_chain && (
            <Tag color="purple" title={t('xray:status.relayTooltip')}>
              {t('xray:status.relayTag', { chain: data.relay_chain.map((h) => `${h.host} (${h.strategy})`).join(' → ') })}
            </Tag>
          )}
        </Space>
      </Card>

      <Card title={t('xray:strategy.cardTitle')} style={{ marginBottom: 16 }}>
        <Form form={form} layout="vertical">
          <Form.Item label={t('xray:strategy.selectLabel')}>
            <Select
              value={strategy}
              onChange={setStrategy}
              options={data.strategies.map((s) => ({ value: s.name, label: s.label }))}
              style={{ maxWidth: 360 }}
            />
          </Form.Item>
          {data.param_specs.map((p) => (
            <Form.Item key={p.key} name={p.key} label={p.label} rules={p.required ? [{ required: true }] : []}>
              {p.secret ? <Input.Password placeholder={p.placeholder} /> : <Input placeholder={p.placeholder} />}
            </Form.Item>
          ))}
          <Form.Item
            label={t('xray:relay.fieldLabel')}
            tooltip={t('xray:relay.fieldTooltip')}
          >
            <Form.List name="relay_links">
              {(fields, { add, remove, move }) => (
                <Space direction="vertical" style={{ width: '100%' }}>
                  {fields.map((field, idx) => (
                    <Space key={field.key} style={{ width: '100%' }} align="baseline">
                      <span style={{ color: 'var(--ant-color-text-tertiary)', minWidth: 48 }}>{t('xray:relay.hopLabel', { n: idx + 1 })}</span>
                      <Form.Item {...field} noStyle>
                        <Input style={{ width: 420 }} placeholder="vless://... / trojan://... / ss://..." />
                      </Form.Item>
                      <Button
                        size="small" icon={<ArrowUpOutlined />} disabled={idx === 0}
                        onClick={() => move(idx, idx - 1)} title={t('xray:relay.moveUpTitle')}
                      />
                      <Button
                        size="small" icon={<ArrowDownOutlined />} disabled={idx === fields.length - 1}
                        onClick={() => move(idx, idx + 1)} title={t('xray:relay.moveDownTitle')}
                      />
                      <Button size="small" danger icon={<DeleteOutlined />} onClick={() => remove(field.name)} title={t('xray:relay.removeTitle')} />
                    </Space>
                  ))}
                  <Button size="small" icon={<PlusOutlined />} onClick={() => add('')}>{t('xray:relay.addButton')}</Button>
                </Space>
              )}
            </Form.List>
          </Form.Item>
          <Button type="primary" onClick={onApply} loading={apply.isPending} disabled={!strategy}>
            {t('xray:strategy.applyButton')}
          </Button>
        </Form>
      </Card>

      <Card
        title={t('xray:clients.cardTitle')}
        style={{ marginBottom: 16 }}
        extra={
          canAddClient && (
            <Button size="small" icon={<PlusOutlined />} onClick={() => { addForm.resetFields(); setAddOpen(true); }}>
              {t('common:actions.add')}
            </Button>
          )
        }
      >
        <Table
          rowKey="name"
          pagination={false}
          dataSource={data.clients}
          locale={{ emptyText: t('xray:clients.emptyText') }}
          columns={[
            { title: t('xray:clients.name'), dataIndex: 'name', key: 'name' },
            {
              title: t('xray:clients.linkColumn'),
              key: 'link',
              render: (_: unknown, r: XrayClient) => (
                <Space>
                  <code style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', display: 'inline-block', whiteSpace: 'nowrap' }}>
                    {r.link}
                  </code>
                  <Button size="small" icon={<CopyOutlined />} onClick={() => copyLink(r.link)} title={t('xray:clients.copyLinkTitle')} />
                </Space>
              ),
            },
            {
              title: '',
              key: 'actions',
              render: (_: unknown, r: XrayClient) => (
                <Space>
                  <Button size="small" icon={<QrcodeOutlined />} onClick={() => setQrClient(r.name)} title={t('xray:clients.showQrTitle')} />
                  <Popconfirm title={t('xray:clients.deleteConfirmTitle', { name: r.name })} onConfirm={() => removeClient.mutate(r.name)}>
                    <Button size="small" danger icon={<DeleteOutlined />} title={t('common:actions.delete')} />
                  </Popconfirm>
                </Space>
              ),
            },
          ]}
        />
      </Card>

      <Card title={t('xray:subscription.cardTitle')}>
        <Button
          icon={<LinkOutlined />}
          onClick={() => window.open(`/api/providers/${encodeURIComponent(provider)}/xray/sub`, '_blank')}
        >
          {t('xray:subscription.openButton')}
        </Button>
        <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0 }}>
          {t('xray:subscription.description')}
        </Typography.Paragraph>
      </Card>

      <Modal title={t('xray:clients.qrModalTitle')} open={!!qrClient} onCancel={() => setQrClient(null)} footer={null}>
        {qrClient && (
          <div style={{ textAlign: 'center' }}>
            <Image
              src={`/api/providers/${encodeURIComponent(provider)}/xray/qr?client=${encodeURIComponent(qrClient)}`}
              alt="QR"
              preview={false}
            />
          </div>
        )}
      </Modal>

      <Modal title={t('xray:clients.addModalTitle')} open={addOpen} onCancel={() => setAddOpen(false)} onOk={onAddClient} confirmLoading={addClient.isPending}>
        <Form form={addForm} layout="vertical">
          <Form.Item name="name" label={t('xray:clients.name')} rules={[{ required: true }]}>
            <Input />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}
