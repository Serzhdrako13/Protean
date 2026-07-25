import { useEffect, useMemo, useState } from 'react';
import { Modal, Select, Table, Switch, Input, Space, Button, Empty, Skeleton, Typography, Checkbox, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { useProvidersQuery } from '@/api/queries/providers';
import {
  useNetworkDetectionQuery, useNetworkDetectionApplyMutation,
  type DetectedItem, type DetectionDecision,
} from '@/api/queries/networkDetection';
import { ApiError } from '@/api/http-init';

const WG_FAMILY_TYPES = new Set(['wireguard', 'amneziawg']);

interface RowState {
  included: boolean; // create_node: act on it; anomaly: dismiss it
  nodeName: string;
  nodeKind: 'router' | 'device' | 'other';
  subnetChecked: Record<string, boolean>;
  subnetLabel: Record<string, string>;
  meshChecked: Record<string, boolean>;
}

function initialRowState(item: DetectedItem): RowState {
  const subnetChecked: Record<string, boolean> = {};
  const subnetLabel: Record<string, string> = {};
  const meshProviders = new Set((item.mesh_candidates ?? []).map((m) => m.provider));
  for (const cidr of item.routed_subnets ?? []) {
    // A CIDR that's a mesh candidate is handled by meshChecked instead --
    // never offered as a plain subnet too (keeps "subnet" and "mesh"
    // structurally separate, matching the backend's own separation).
    if ((item.mesh_candidates ?? []).some((m) => m.cidr === cidr)) continue;
    subnetChecked[cidr] = !item.existing_subnet_cidrs?.includes(cidr);
    subnetLabel[cidr] = `${item.name || item.peer_id} — ${cidr}`;
  }
  const meshChecked: Record<string, boolean> = {};
  for (const p of meshProviders) meshChecked[p] = true;
  return {
    included: item.suggested_action === 'create_node',
    nodeName: item.name,
    nodeKind: 'router',
    subnetChecked,
    subnetLabel,
    meshChecked,
  };
}

export function NetworkDetectionModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation(['nodes', 'common']);
  const { data: providers } = useProvidersQuery();
  const wgProviders = useMemo(() => (providers ?? []).filter((p) => WG_FAMILY_TYPES.has(p.type)), [providers]);
  const [provider, setProvider] = useState<string | undefined>();
  const [showHandled, setShowHandled] = useState(false);
  const { data, isLoading } = useNetworkDetectionQuery(provider);
  const apply = useNetworkDetectionApplyMutation(provider);
  const [rows, setRows] = useState<Record<string, RowState>>({});

  useEffect(() => {
    if (!data) return;
    const next: Record<string, RowState> = {};
    for (const item of data.items) next[item.peer_id] = initialRowState(item);
    setRows(next);
  }, [data]);

  function updateRow(peerID: string, patch: Partial<RowState>) {
    setRows((prev) => ({ ...prev, [peerID]: { ...prev[peerID], ...patch } }));
  }

  const createNodeItems = (data?.items ?? []).filter((i) => i.suggested_action === 'create_node');
  const anomalyItems = (data?.items ?? []).filter((i) => i.suggested_action === 'anomaly');
  const handledItems = (data?.items ?? []).filter((i) => i.suggested_action === 'already_handled');

  async function onApply() {
    if (!provider) return;
    const decisions: DetectionDecision[] = [];
    for (const item of createNodeItems) {
      const row = rows[item.peer_id];
      if (!row?.included) continue;
      decisions.push({
        peer_id: item.peer_id,
        action: 'create_node',
        node_name: row.nodeName.trim(),
        node_kind: row.nodeKind,
        subnets_to_create: Object.entries(row.subnetChecked)
          .filter(([, checked]) => checked)
          .map(([cidr]) => ({ cidr, label: row.subnetLabel[cidr] ?? cidr })),
        mesh_with: Object.entries(row.meshChecked).filter(([, checked]) => checked).map(([p]) => p),
      });
    }
    for (const item of anomalyItems) {
      const row = rows[item.peer_id];
      if (row?.included) decisions.push({ peer_id: item.peer_id, action: 'skip' });
    }
    if (decisions.length === 0) {
      message.info(t('nodes:networkDetection.nothingSelected'));
      return;
    }
    try {
      const summary = await apply.mutateAsync(decisions);
      message.success(
        t('nodes:networkDetection.applySummary', {
          nodes: summary.nodes_created, subnets: summary.subnets_created, mesh: summary.mesh_pairs_enabled,
        }),
      );
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  return (
    <Modal
      title={t('nodes:networkDetection.title')}
      open={open}
      onCancel={onClose}
      onOk={onApply}
      okText={t('nodes:networkDetection.apply')}
      confirmLoading={apply.isPending}
      width={900}
      destroyOnHidden
    >
      <Space direction="vertical" style={{ width: '100%' }} size={16}>
        <Select
          style={{ width: '100%' }}
          placeholder={t('nodes:networkDetection.selectProvider')}
          value={provider}
          onChange={setProvider}
          options={wgProviders.map((p) => ({ value: p.key, label: p.friendly_label || p.label }))}
        />

        {!provider && <Typography.Text type="secondary">{t('nodes:networkDetection.selectProviderHint')}</Typography.Text>}

        {provider && isLoading && <Skeleton active />}

        {provider && data && (
          <>
            <Typography.Text type="secondary">
              {t('nodes:networkDetection.scanned', { cidr: data.tunnel_cidr ?? '—', count: data.items.length })}
            </Typography.Text>

            {createNodeItems.length === 0 && anomalyItems.length === 0 ? (
              <Empty description={t('nodes:networkDetection.nothingToReview')} />
            ) : (
              <Table<DetectedItem>
                size="small"
                rowKey="peer_id"
                pagination={false}
                dataSource={[...createNodeItems, ...anomalyItems]}
                columns={[
                  {
                    title: t('nodes:networkDetection.columns.include'),
                    key: 'included',
                    width: 60,
                    render: (_: unknown, item: DetectedItem) => (
                      <Switch
                        size="small"
                        checked={rows[item.peer_id]?.included ?? false}
                        onChange={(v) => updateRow(item.peer_id, { included: v })}
                      />
                    ),
                  },
                  {
                    title: t('nodes:networkDetection.columns.peer'),
                    key: 'peer',
                    render: (_: unknown, item: DetectedItem) => (
                      <span>
                        {item.name || <Typography.Text type="secondary">{t('nodes:networkDetection.unnamed')}</Typography.Text>}
                        {item.own_address && <code style={{ marginLeft: 6, fontSize: 12 }}>{item.own_address}</code>}
                      </span>
                    ),
                  },
                  {
                    title: t('nodes:networkDetection.columns.details'),
                    key: 'details',
                    render: (_: unknown, item: DetectedItem) => {
                      if (item.suggested_action === 'anomaly') {
                        return (
                          <Space direction="vertical" size={2}>
                            {(item.anomalies ?? []).map((a, i) => (
                              <Typography.Text key={i} type="warning" style={{ fontSize: 12 }}>{a}</Typography.Text>
                            ))}
                          </Space>
                        );
                      }
                      const row = rows[item.peer_id];
                      if (!row) return null;
                      const subnetCIDRs = Object.keys(row.subnetChecked);
                      return (
                        <Space direction="vertical" size={8} style={{ width: '100%' }}>
                          <Space>
                            <Input
                              size="small"
                              value={row.nodeName}
                              onChange={(e) => updateRow(item.peer_id, { nodeName: e.target.value })}
                              style={{ width: 160 }}
                              placeholder={t('nodes:networkDetection.nodeNamePlaceholder')}
                            />
                            <Select
                              size="small"
                              value={row.nodeKind}
                              onChange={(v) => updateRow(item.peer_id, { nodeKind: v })}
                              style={{ width: 120 }}
                              options={[
                                { value: 'router', label: t('nodes:kindLabels.router') },
                                { value: 'device', label: t('nodes:kindLabels.device') },
                                { value: 'other', label: t('nodes:kindLabels.other') },
                              ]}
                            />
                          </Space>
                          {subnetCIDRs.length > 0 && (
                            <div>
                              <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('nodes:networkDetection.subnetsLabel')}</Typography.Text>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 4 }}>
                                {subnetCIDRs.map((cidr) => (
                                  <Checkbox
                                    key={cidr}
                                    checked={row.subnetChecked[cidr]}
                                    onChange={(e) => updateRow(item.peer_id, { subnetChecked: { ...row.subnetChecked, [cidr]: e.target.checked } })}
                                  >
                                    <code style={{ fontSize: 12 }}>{cidr}</code>
                                  </Checkbox>
                                ))}
                              </div>
                            </div>
                          )}
                          {/* Mesh candidates: a visually SEPARATE section from
                              plain subnets above -- this page is exactly the
                              place "subnet" and "mesh" must not blur together. */}
                          {(item.mesh_candidates ?? []).length > 0 && (
                            <div style={{ borderTop: '1px dashed var(--ant-color-border-secondary, rgba(128,128,128,.2))', paddingTop: 4 }}>
                              <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('nodes:networkDetection.meshLabel')}</Typography.Text>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 4 }}>
                                {(item.mesh_candidates ?? []).map((m) => (
                                  <Checkbox
                                    key={m.provider}
                                    checked={row.meshChecked[m.provider] ?? false}
                                    onChange={(e) => updateRow(item.peer_id, { meshChecked: { ...row.meshChecked, [m.provider]: e.target.checked } })}
                                  >
                                    {t('nodes:networkDetection.meshWith', { provider: m.provider })} <code style={{ fontSize: 12 }}>{m.cidr}</code>
                                  </Checkbox>
                                ))}
                              </div>
                            </div>
                          )}
                        </Space>
                      );
                    },
                  },
                ]}
              />
            )}

            {handledItems.length > 0 && (
              <div>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  <Switch size="small" checked={showHandled} onChange={setShowHandled} />
                  <span style={{ fontSize: 12, color: 'var(--ant-color-text-tertiary)' }}>
                    {t('nodes:networkDetection.showHandled', { count: handledItems.length })}
                  </span>
                </span>
                {showHandled && (
                  <div style={{ marginTop: 8 }}>
                    {handledItems.map((item) => (
                      <div key={item.peer_id} style={{ fontSize: 12, color: 'var(--ant-color-text-tertiary)', padding: '2px 0' }}>
                        {item.name || item.peer_id} — {item.already_node_owned ? t('nodes:networkDetection.alreadyOwned') : t('nodes:networkDetection.alreadyDismissed')}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </Space>
    </Modal>
  );
}

export function NetworkDetectionButton() {
  const { t } = useTranslation('nodes');
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button onClick={() => setOpen(true)}>{t('networkDetection.button')}</Button>
      <NetworkDetectionModal open={open} onClose={() => setOpen(false)} />
    </>
  );
}
