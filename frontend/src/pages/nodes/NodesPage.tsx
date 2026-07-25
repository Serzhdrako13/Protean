import { useState, type MouseEvent } from 'react';
import {
  Table, Button, Modal, Form, Input, Select, Tag, Popconfirm, message, Space, Typography, Switch, Tabs, Card, Alert,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import {
  PlusOutlined, DeleteOutlined, EditOutlined, WifiOutlined, DesktopOutlined, QuestionCircleOutlined,
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { PageTitleBar } from '@/components/PageTitleBar';
import { HeaderTip } from '@/components/HeaderTip';
import { ApiError } from '@/api/http-init';
import {
  useNodesQuery, useNodeMutations, useNodeAccessQuery, useNodeAccessMutations, useClientsQuery,
  type Node, type NodeAccessRow, type Client,
} from '@/api/queries/nodes';
import { useMeshQuery, useMeshMutations } from '@/api/queries/mesh';
import type { MeshIface, MeshPeer } from '@/types/api';
import { TableSearch } from '@/components/TableSearch';
import { useTableSearch } from '@/hooks/useTableSearch';
import { textSorter, numSorter } from '@/utils/tableSort';

// Clicking anywhere in a node row expands the per-provider access panel --
// same pattern as UsersPage.tsx -- EXCEPT the interactive controls
// (switches, buttons), which must stop the click from bubbling up.
function stopRowClick(e: MouseEvent) {
  e.stopPropagation();
}

const KIND_ICON: Record<Node['kind'], React.ReactNode> = {
  router: <WifiOutlined />,
  device: <DesktopOutlined />,
  other: <QuestionCircleOutlined />,
};

function formatBytes(n: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function NodeAccessPanel({ node }: { node: Node }) {
  const { t } = useTranslation(['nodes', 'common']);
  const { data, isLoading } = useNodeAccessQuery(node.id, true);
  const { setAccess } = useNodeAccessMutations(node.id);

  async function onToggle(row: NodeAccessRow, v: boolean) {
    try {
      await setAccess.mutateAsync({ provider: row.provider, enabled: v });
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  const columns: ColumnsType<NodeAccessRow> = [
    { title: t('access.name'), dataIndex: 'provider_label', key: 'provider_label' },
    { title: t('access.server'), dataIndex: 'server_id', key: 'server_id', render: (v: string) => <code>{v}</code> },
    { title: t('access.type'), dataIndex: 'type', key: 'type' },
    { title: t('access.interface'), dataIndex: 'interface', key: 'interface', render: (v: string) => <code>{v}</code> },
    {
      title: t('access.address'),
      key: 'address',
      render: (_: unknown, row: NodeAccessRow) => (row.address ? <code>{row.address}</code> : '—'),
    },
    {
      title: t('access.status'),
      key: 'status',
      render: (_: unknown, row: NodeAccessRow) =>
        row.state !== 'granted' ? '—' : row.online ? (
          <Tag color="success">{t('common:status.online')}</Tag>
        ) : (
          <Tag>{t('common:status.offline')}</Tag>
        ),
    },
    {
      title: t('access.traffic'),
      key: 'traffic',
      render: (_: unknown, row: NodeAccessRow) =>
        row.state !== 'granted' ? '—' : (
          <span>
            <Tag color="blue">↓{formatBytes(row.rx_bytes)}</Tag>
            <Tag color="purple">↑{formatBytes(row.tx_bytes)}</Tag>
          </span>
        ),
    },
    {
      title: <HeaderTip label={t('access.nat.label')} tip={t('access.nat.tip')} />,
      key: 'nat',
      render: (_: unknown, row: NodeAccessRow) => (
        <Tag color={row.internet_egress ? 'success' : 'default'}>
          {row.internet_egress ? t('access.nat.on') : t('access.nat.off')}
        </Tag>
      ),
    },
    {
      title: t('access.access'),
      key: 'state',
      render: (_: unknown, row: NodeAccessRow) => (
        <Space onClick={stopRowClick}>
          <Switch size="small" checked={row.state === 'granted'} onChange={(v) => onToggle(row, v)} />
        </Space>
      ),
    },
  ];

  return (
    <Table rowKey="provider" loading={isLoading} dataSource={data ?? []} columns={columns} pagination={false} />
  );
}

function NodesTable() {
  const { t } = useTranslation(['nodes', 'common']);
  const { data, isLoading } = useNodesQuery();
  const { create, update, remove } = useNodeMutations();
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<Node | null>(null);
  const [form] = Form.useForm();

  function openCreate() {
    setEditing(null);
    form.resetFields();
    setModalOpen(true);
  }

  function openEdit(n: Node) {
    setEditing(n);
    form.setFieldsValue({ name: n.name, kind: n.kind, role: n.role, description: n.description });
    setModalOpen(true);
  }

  async function onSubmit() {
    try {
      const values = await form.validateFields();
      if (editing) {
        await update.mutateAsync({ id: editing.id, ...values });
      } else {
        await create.mutateAsync(values);
      }
      setModalOpen(false);
      message.success(t('common:actions.saved'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onDelete(n: Node) {
    try {
      await remove.mutateAsync(n.id);
      message.success(t('messages.deleted'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  const columns: ColumnsType<Node> = [
    {
      title: t('fields.name'),
      key: 'name',
      render: (_: unknown, n: Node) => (
        <Space>
          {KIND_ICON[n.kind]}
          {n.name}
        </Space>
      ),
    },
    {
      title: <HeaderTip label={t('fields.kind')} tip={t('kindTip')} />,
      key: 'kind',
      render: (_: unknown, n: Node) => t(`kindLabels.${n.kind}`),
    },
    {
      title: <HeaderTip label={t('fields.role')} tip={t('roleTip')} />,
      key: 'role',
      render: (_: unknown, n: Node) => (
        <Tag color={n.role === 'network_node' ? 'purple' : 'default'}>{t(`roleLabels.${n.role}`)}</Tag>
      ),
    },
    {
      title: t('fields.description'),
      dataIndex: 'description',
      key: 'description',
      render: (v?: string) => v || <Typography.Text type="secondary">—</Typography.Text>,
    },
    {
      title: t('fields.peersOnline'),
      key: 'peers',
      render: (_: unknown, n: Node) => `${n.peers_online}/${n.peers_total}`,
    },
    {
      title: '',
      key: 'actions',
      render: (_: unknown, n: Node) => (
        <span onClick={stopRowClick}>
          <Button size="small" icon={<EditOutlined />} onClick={() => openEdit(n)} title={t('common:actions.edit')} style={{ marginRight: 8 }} />
          <Popconfirm title={t('confirmDelete', { name: n.name })} onConfirm={() => onDelete(n)}>
            <Button size="small" danger icon={<DeleteOutlined />} title={t('common:actions.delete')} />
          </Popconfirm>
        </span>
      ),
    },
  ];

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>{t('createButton')}</Button>
      </div>
      <Table
        rowKey="id"
        columns={columns}
        dataSource={data ?? []}
        loading={isLoading}
        pagination={false}
        expandable={{ expandRowByClick: true, expandedRowRender: (n) => <NodeAccessPanel node={n} /> }}
      />

      <Modal
        title={editing ? t('modal.editTitle', { name: editing.name }) : t('modal.createTitle')}
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        onOk={onSubmit}
        confirmLoading={create.isPending || update.isPending}
        destroyOnHidden
      >
        <Form form={form} layout="vertical">
          <Form.Item name="name" label={t('fields.name')} rules={[{ required: true }]}>
            <Input placeholder={t('form.namePlaceholder')} />
          </Form.Item>
          <Form.Item name="kind" label={t('fields.kind')} tooltip={t('kindTip')} initialValue="router" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'router', label: t('kindLabels.router') },
                { value: 'device', label: t('kindLabels.device') },
                { value: 'other', label: t('kindLabels.other') },
              ]}
            />
          </Form.Item>
          <Form.Item name="role" label={t('fields.role')} tooltip={t('roleTip')} initialValue="member" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'member', label: t('roleLabels.member') },
                { value: 'network_node', label: t('roleLabels.network_node') },
              ]}
            />
          </Form.Item>
          <Form.Item name="description" label={t('fields.description')}>
            <Input.TextArea rows={3} placeholder={t('form.descriptionPlaceholder')} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}

// "Все клиенты" tab -- every real peer across every provider/server in one
// flat table, owner resolved whether it's a portal user or an equipment
// node. Deliberately duplicates data already reachable per-user (Users
// page) and per-node (the "Оборудование" tab above) -- explicit ask, given
// how many entities/relationships are now involved.
const OWNER_TAG_COLOR: Record<Client['owner_kind'], string> = { user: 'blue', node: 'purple', none: 'default' };

function AllClientsTab() {
  const { t } = useTranslation(['nodes', 'common']);
  const { data, isLoading } = useClientsQuery();
  const { query, setQuery, filtered } = useTableSearch(
    data,
    (c) => `${c.name} ${c.provider_label} ${c.owner_name ?? ''} ${c.address ?? ''}`,
  );

  const columns: ColumnsType<Client> = [
    {
      title: t('clients.columns.owner'),
      key: 'owner',
      filters: [
        { text: t('clients.ownerKind.user'), value: 'user' },
        { text: t('clients.ownerKind.node'), value: 'node' },
        { text: t('clients.ownerKind.none'), value: 'none' },
      ],
      onFilter: (value, c) => c.owner_kind === value,
      render: (_: unknown, c: Client) =>
        c.owner_kind === 'none' ? (
          <Typography.Text type="secondary">{t('clients.ownerKind.none')}</Typography.Text>
        ) : (
          <Tag color={OWNER_TAG_COLOR[c.owner_kind]}>{t(`clients.ownerKind.${c.owner_kind}`)}: {c.owner_name}</Tag>
        ),
    },
    { title: t('clients.columns.name'), dataIndex: 'name', key: 'name', sorter: textSorter((c: Client) => c.name) },
    { title: t('clients.columns.provider'), dataIndex: 'provider_label', key: 'provider_label', sorter: textSorter((c: Client) => c.provider_label) },
    { title: t('clients.columns.server'), dataIndex: 'server_id', key: 'server_id', render: (v: string) => <code>{v}</code> },
    { title: t('clients.columns.type'), dataIndex: 'type', key: 'type' },
    {
      title: t('clients.columns.address'),
      key: 'address',
      render: (_: unknown, c: Client) => (c.address ? <code>{c.address}</code> : '—'),
    },
    {
      title: t('clients.columns.category'),
      key: 'category',
      render: (_: unknown, c: Client) => (c.category === 'site' ? t('clients.categoryLabels.site') : t('clients.categoryLabels.client')),
    },
    {
      title: t('clients.columns.status'),
      key: 'status',
      filters: [
        { text: t('common:status.online'), value: true },
        { text: t('common:status.offline'), value: false },
      ],
      onFilter: (value, c) => c.online === value,
      render: (_: unknown, c: Client) => (c.online ? <Tag color="success">{t('common:status.online')}</Tag> : <Tag>{t('common:status.offline')}</Tag>),
    },
    {
      title: t('clients.columns.traffic'),
      key: 'traffic',
      sorter: numSorter((c: Client) => c.rx_bytes + c.tx_bytes),
      render: (_: unknown, c: Client) => (
        <span>
          <Tag color="blue">↓{formatBytes(c.rx_bytes)}</Tag>
          <Tag color="purple">↑{formatBytes(c.tx_bytes)}</Tag>
        </span>
      ),
    },
  ];

  return (
    <>
      <Typography.Paragraph type="secondary">{t('clients.description')}</Typography.Paragraph>
      <TableSearch value={query} onChange={setQuery} placeholder={t('clients.searchPlaceholder')} />
      <Table
        rowKey={(c) => `${c.provider}-${c.peer_id}`}
        columns={columns}
        dataSource={filtered ?? []}
        loading={isLoading}
        pagination={{ pageSize: 20, showSizeChanger: true }}
        scroll={{ x: true }}
      />
    </>
  );
}

// "Обзор сети" tab -- the former standalone /mesh page's content, moved in
// unchanged (same useMeshQuery/useMeshMutations, same tables) since it's
// read-only overview data that's directly relevant next to node management,
// not worth a separate nav entry (per explicit direction: "смысл в
// read-only нет, весь этот функционал и там будет виден").
function splitProviderKey(key: string): { server: string; local: string } {
  const i = key.indexOf(':');
  return i >= 0 ? { server: key.slice(0, i), local: key.slice(i + 1) } : { server: '', local: key };
}
function stripServerSuffix(label: string, server: string): string {
  return server ? label.replace(new RegExp(` @ ${server}$`), '') : label;
}

function NetworkOverviewTab() {
  const { t } = useTranslation(['mesh', 'common']);
  const [server, setServer] = useState<string | undefined>(undefined);
  const { data, isLoading } = useMeshQuery(server);
  const { enableForwarding } = useMeshMutations();
  const providerLabels: Record<string, string> = {};
  for (const iface of data?.interfaces ?? []) providerLabels[iface.provider] = iface.label;

  const ifaceColumns = [
    { title: t('mesh:columns.server'), key: 'server', render: (_: unknown, r: MeshIface) => <code>{splitProviderKey(r.provider).server}</code> },
    { title: t('mesh:columns.provider'), key: 'label', render: (_: unknown, r: MeshIface) => stripServerSuffix(r.label, splitProviderKey(r.provider).server) },
    { title: t('mesh:columns.status'), key: 'up', render: (_: unknown, r: MeshIface) => (r.up ? <Tag color="success">● UP</Tag> : <Tag color="error">● DOWN</Tag>) },
    { title: t('mesh:columns.port'), dataIndex: 'listen_port', key: 'listen_port' },
    { title: t('mesh:columns.peerCount'), dataIndex: 'peer_count', key: 'peer_count' },
    {
      title: <HeaderTip label={t('mesh:tunnelNetwork.label')} tip={t('mesh:tunnelNetwork.tip')} />,
      dataIndex: 'tunnel_cidr', key: 'tunnel_cidr', render: (v: string) => v || '—',
    },
    {
      title: <HeaderTip label={t('mesh:forwarding.label')} tip={t('mesh:forwarding.tip')} />,
      key: 'forwarding',
      render: (_: unknown, r: MeshIface) =>
        !r.supports_forward ? '—' : r.forwarding_enabled ? (
          <Tag color="success">{t('mesh:forwarding.enabled')}</Tag>
        ) : (
          <Button size="small" onClick={() => enableForwarding.mutate(r.provider)} loading={enableForwarding.isPending}>
            {t('mesh:forwarding.enable')}
          </Button>
        ),
    },
  ];

  return (
    <>
      {data && data.servers.length > 1 && (
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
          <Select value={server ?? data.server_id} options={data.servers.map((s) => ({ value: s, label: s }))} onChange={setServer} style={{ width: 200 }} />
        </div>
      )}
      {data?.warnings && data.warnings.length > 0 && (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message={t('mesh:warnings.title')}
          description={
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {data.warnings.map((w) => <li key={w}>{w}</li>)}
            </ul>
          }
        />
      )}
      <Card title={t('mesh:cards.interfaces')} style={{ marginBottom: 16 }}>
        <Table rowKey="provider" columns={ifaceColumns} dataSource={data?.interfaces ?? []} loading={isLoading} pagination={false} />
      </Card>
      <Card title={t('mesh:cards.subnets')} style={{ marginBottom: 16 }}>
        <Space wrap>
          {(data?.subnets ?? []).map((s) => <Tag key={s.cidr}>{s.cidr}{s.label ? ` — ${s.label}` : ''}</Tag>)}
          {(!data?.subnets || data.subnets.length === 0) && <span style={{ color: 'var(--ant-color-text-tertiary)' }}>{t('mesh:noSubnets')}</span>}
        </Space>
      </Card>
      <Card title={t('mesh:cards.peers')}>
        <Table
          rowKey={(r: MeshPeer) => `${r.provider}-${r.name}`}
          pagination={false}
          dataSource={data?.peers ?? []}
          columns={[
            { title: t('mesh:columns.server'), key: 'server', render: (_: unknown, r: MeshPeer) => <code>{splitProviderKey(r.provider).server}</code> },
            {
              title: t('mesh:columns.provider'), key: 'provider',
              render: (_: unknown, r: MeshPeer) => {
                const { server: srv, local } = splitProviderKey(r.provider);
                return stripServerSuffix(providerLabels[r.provider] ?? local, srv);
              },
            },
            { title: t('mesh:columns.name'), dataIndex: 'name', key: 'name' },
            { title: t('mesh:columns.address'), dataIndex: 'address', key: 'address' },
            {
              title: t('mesh:columns.status'), key: 'online',
              render: (_: unknown, r: MeshPeer) => (r.online ? <Tag color="success">{t('common:status.online')}</Tag> : <Tag>{t('common:status.offline')}</Tag>),
            },
          ]}
        />
      </Card>
    </>
  );
}

export function NodesPage() {
  const { t } = useTranslation(['nodes', 'common']);
  return (
    <PageShell>
      <PageTitleBar>{t('title')}</PageTitleBar>
      <Tabs
        defaultActiveKey="nodes"
        items={[
          { key: 'nodes', label: t('tabs.nodes'), children: <NodesTable /> },
          { key: 'clients', label: t('tabs.clients'), children: <AllClientsTab /> },
          { key: 'overview', label: t('tabs.overview'), children: <NetworkOverviewTab /> },
        ]}
      />
    </PageShell>
  );
}
