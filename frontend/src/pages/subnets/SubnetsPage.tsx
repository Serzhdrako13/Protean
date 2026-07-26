import { useState } from 'react';
import { Table, Button, Modal, Form, Input, Popconfirm, Space, Switch, Tooltip, message } from 'antd';
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { useSubnetMutations, useSubnetsQuery } from '@/api/queries/subnets';
import type { Subnet } from '@/types/api';
import { ApiError } from '@/api/http-init';
import { HeaderTip } from '@/components/HeaderTip';
import { PageTitleBar } from '@/components/PageTitleBar';

export function SubnetsPage() {
  const { t } = useTranslation(['subnets', 'common']);
  const { data, isLoading } = useSubnetsQuery();
  const { create, remove, updateNAT } = useSubnetMutations();
  const [modalOpen, setModalOpen] = useState(false);
  const [form] = Form.useForm();

  async function onSubmit() {
    try {
      const values = await form.validateFields();
      await create.mutateAsync(values);
      setModalOpen(false);
      message.success(t('messages.created'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onToggleNAT(r: Subnet) {
    const nextMode = r.nat_mode === 'masquerade' ? 'passthrough' : 'masquerade';
    try {
      await updateNAT.mutateAsync({ id: r.id, nat_mode: nextMode });
      message.success(t('messages.natUpdated'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  const columns = [
    {
      title: <HeaderTip label={t('columns.cidr')} tip={t('columns.cidrTip')} />,
      dataIndex: 'cidr',
      key: 'cidr',
      render: (v: string) => <code>{v}</code>,
    },
    { title: t('columns.label'), dataIndex: 'label', key: 'label' },
    {
      title: t('columns.owner'),
      key: 'owner',
      render: (_: unknown, r: Subnet) => r.owner_node_name || '—',
    },
    {
      title: t('columns.natMode'),
      key: 'natMode',
      render: (_: unknown, r: Subnet) => {
        const toMasquerade = r.nat_mode !== 'masquerade';
        const sw = (
          <Switch
            size="small"
            checked={r.nat_mode === 'masquerade'}
            disabled={!r.nat_capable}
            checkedChildren={t('natMode.masquerade')}
            unCheckedChildren={t('natMode.passthrough')}
          />
        );
        if (!r.nat_capable) {
          return <Tooltip title={t('natMode.notCapableTip')}>{sw}</Tooltip>;
        }
        return (
          <Popconfirm
            title={t(toMasquerade ? 'natMode.toMasqueradeTitle' : 'natMode.toPassthroughTitle', { cidr: r.cidr })}
            description={t(toMasquerade ? 'natMode.toMasqueradeWarning' : 'natMode.toPassthroughWarning')}
            onConfirm={() => onToggleNAT(r)}
            okText={t('common:actions.confirm')}
          >
            {sw}
          </Popconfirm>
        );
      },
    },
    {
      title: '',
      key: 'actions',
      render: (_: unknown, r: Subnet) => (
        <Popconfirm title={t('deleteConfirm', { cidr: r.cidr })} onConfirm={() => remove.mutate(r.id)}>
          <Button size="small" danger icon={<DeleteOutlined />} title={t('deleteTitle')} />
        </Popconfirm>
      ),
    },
  ];

  return (
    <PageShell>
      <PageTitleBar
        extra={
          <Button type="primary" icon={<PlusOutlined />} onClick={() => { form.resetFields(); setModalOpen(true); }}>
            {t('addSubnet')}
          </Button>
        }
      >
        {t('title')}
      </PageTitleBar>
      <p style={{ color: 'var(--ant-color-text-tertiary)', marginTop: -8 }}>
        {t('description')}
      </p>
      <Table rowKey="id" columns={columns} dataSource={data ?? []} loading={isLoading} pagination={false} />

      <Modal title={t('addSubnet')} open={modalOpen} onCancel={() => setModalOpen(false)} onOk={onSubmit} confirmLoading={create.isPending}>
        <Form form={form} layout="vertical">
          <Form.Item name="cidr" label={t('form.cidrLabel')} rules={[{ required: true }]}>
            <Input placeholder={t('form.cidrPlaceholder')} />
          </Form.Item>
          <Form.Item name="label" label={t('form.labelLabel')}>
            <Input placeholder={t('form.labelPlaceholder')} />
          </Form.Item>
        </Form>
      </Modal>
    </PageShell>
  );
}
