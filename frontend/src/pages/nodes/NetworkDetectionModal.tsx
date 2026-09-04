import { useEffect, useMemo, useState } from 'react';
import { Modal, Select, Table, Switch, Input, Space, Button, Empty, Skeleton, Typography, Checkbox, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { useProvidersQuery } from '@/api/queries/providers';
import {
  useNetworkDetectionQuery, useNetworkDetectionApplyMutation,
  type DetectedItem, type DetectionDecision, type MeshCandidate,
} from '@/api/queries/networkDetection';
import { ApiError } from '@/api/http-init';

const WG_FAMILY_TYPES = new Set(['wireguard', 'amneziawg']);

// A peer with a routed subnet can become equipment (a Node) even if it
// showed up as "anomaly" -- the most common anomaly reason in practice is
// simply that the hand-written conf never named the peer, which doesn't
// stop applyNetworkDetection from creating a Node once the admin types a
// name here. Only anomalies with NO routed subnet at all (malformed
// entries, ambiguous own-address candidates) have nothing to create and
// stay dismiss-only.
function isPromotable(item: DetectedItem): boolean {
  return (item.routed_subnets ?? []).length > 0;
}

interface RowState {
  included: boolean; // promotable row (routed subnet found): create it; otherwise: dismiss it
  nodeName: string;
  nodeKind: 'router' | 'device' | 'other';
  subnetChecked: Record<string, boolean>;
  meshChecked: Record<string, boolean>;
}

// subnetLabel: the equipment name if we have one, never the CIDR again
// (already its own column/value everywhere this is shown) and never the
// raw peer_id (an encoded key, not human text -- was leaking through here
// for unnamed adopted peers).
function subnetLabel(row: RowState, item: DetectedItem): string {
  return (row.nodeName || item.name || '').trim();
}

function initialRowState(item: DetectedItem): RowState {
  const subnetChecked: Record<string, boolean> = {};
  const meshProviders = new Set((item.mesh_candidates ?? []).map((m) => m.provider));
  for (const cidr of item.routed_subnets ?? []) {
    // A CIDR that's a mesh candidate is handled by meshChecked instead --
    // never offered as a plain subnet too (keeps "subnet" and "mesh"
    // structurally separate, matching the backend's own separation).
    if ((item.mesh_candidates ?? []).some((m) => m.cidr === cidr)) continue;
    subnetChecked[cidr] = !item.existing_subnet_cidrs?.includes(cidr);
  }
  const meshChecked: Record<string, boolean> = {};
  for (const p of meshProviders) meshChecked[p] = true;
  return {
    included: item.suggested_action === 'create_node',
    nodeName: item.name,
    nodeKind: 'router',
    subnetChecked,
    meshChecked,
  };
}

// Shared by both the main review table (create_node/anomaly rows) and the
// "already handled" section below (a Node-owned peer picking up a
// newly-relevant subnet/mesh pairing later) -- same checkboxes, same
// subnet-vs-mesh separation, so the two paths never drift apart.
function SubnetMeshCheckboxes({
  row, onChange, t, meshCandidates,
}: {
  row: RowState;
  onChange: (patch: Partial<RowState>) => void;
  t: (key: string, opts?: Record<string, unknown>) => string;
  meshCandidates?: MeshCandidate[];
}) {
  const subnetCIDRs = Object.keys(row.subnetChecked);
  const meshProviders = Object.keys(row.meshChecked);
  const cidrByProvider = Object.fromEntries((meshCandidates ?? []).map((m) => [m.provider, m.cidr]));
  if (subnetCIDRs.length === 0 && meshProviders.length === 0) return null;
  return (
    <>
      {subnetCIDRs.length > 0 && (
        <div>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('nodes:networkDetection.subnetsLabel')}</Typography.Text>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 4 }}>
            {subnetCIDRs.map((cidr) => (
              <Checkbox
                key={cidr}
                checked={row.subnetChecked[cidr]}
                onChange={(e) => onChange({ subnetChecked: { ...row.subnetChecked, [cidr]: e.target.checked } })}
              >
                <code style={{ fontSize: 12 }}>{cidr}</code>
              </Checkbox>
            ))}
          </div>
        </div>
      )}
      {/* Mesh candidates: a visually SEPARATE section from plain subnets
          above -- this is exactly the place "subnet" and "mesh" must
          never blur together. */}
      {meshProviders.length > 0 && (
        <div style={{ borderTop: '1px dashed var(--ant-color-border-secondary, rgba(128,128,128,.2))', paddingTop: 4 }}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('nodes:networkDetection.meshLabel')}</Typography.Text>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 4 }}>
            {meshProviders.map((p) => (
              <Checkbox
                key={p}
                checked={row.meshChecked[p]}
                onChange={(e) => onChange({ meshChecked: { ...row.meshChecked, [p]: e.target.checked } })}
              >
                {t('nodes:networkDetection.meshWith', { provider: p })}{' '}
                {cidrByProvider[p] && <code style={{ fontSize: 12 }}>{cidrByProvider[p]}</code>}
              </Checkbox>
            ))}
          </div>
        </div>
      )}
    </>
  );
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
    const missingName: DetectedItem[] = [];
    for (const item of [...createNodeItems, ...anomalyItems]) {
      const row = rows[item.peer_id];
      if (!row?.included) continue;
      if (!isPromotable(item)) {
        decisions.push({ peer_id: item.peer_id, action: 'skip' });
        continue;
      }
      const name = row.nodeName.trim();
      if (!name) {
        missingName.push(item);
        continue;
      }
      decisions.push({
        peer_id: item.peer_id,
        action: 'create_node',
        node_name: name,
        node_kind: row.nodeKind,
        subnets_to_create: Object.entries(row.subnetChecked)
          .filter(([, checked]) => checked)
          .map(([cidr]) => ({ cidr, label: subnetLabel(row, item) || cidr })),
        mesh_with: Object.entries(row.meshChecked).filter(([, checked]) => checked).map(([p]) => p),
      });
    }
    if (missingName.length > 0) {
      message.error(
        t('nodes:networkDetection.missingName', {
          peers: missingName.map((i) => i.name || i.peer_id).join(', '),
        }),
      );
      return;
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
      // Soft failures (e.g. mesh was enabled in the DB but turning on
      // IPv4 forwarding on the host failed) used to be visible only in
      // container logs -- the success toast above would be the whole
      // story otherwise.
      for (const w of summary.warnings ?? []) {
        message.warning(w, 8);
      }
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  async function onUndismiss(item: DetectedItem) {
    try {
      await apply.mutateAsync([{ peer_id: item.peer_id, action: 'undismiss' }]);
      message.success(t('nodes:networkDetection.undismissed'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  // A peer that's already a Node can still gain a newly-relevant subnet or
  // mesh pairing later (e.g. a second mesh-capable provider was only added
  // to this server after the peer first became equipment) -- applying here
  // never creates a duplicate Node, only adds what's checked.
  async function onApplyExtra(item: DetectedItem) {
    const row = rows[item.peer_id];
    if (!row) return;
    const subnetsToCreate = Object.entries(row.subnetChecked)
      .filter(([, checked]) => checked)
      .map(([cidr]) => ({ cidr, label: subnetLabel(row, item) || cidr }));
    const meshWith = Object.entries(row.meshChecked).filter(([, checked]) => checked).map(([p]) => p);
    if (subnetsToCreate.length === 0 && meshWith.length === 0) {
      message.info(t('nodes:networkDetection.nothingSelected'));
      return;
    }
    try {
      await apply.mutateAsync([{ peer_id: item.peer_id, action: 'create_node', subnets_to_create: subnetsToCreate, mesh_with: meshWith }]);
      message.success(t('nodes:networkDetection.extraApplied'));
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
                      const anomalyNotes = (item.anomalies ?? []).length > 0 && (
                        <Space direction="vertical" size={2}>
                          {(item.anomalies ?? []).map((a, i) => (
                            <Typography.Text key={i} type="warning" style={{ fontSize: 12 }}>{a}</Typography.Text>
                          ))}
                        </Space>
                      );
                      if (item.suggested_action === 'anomaly' && !isPromotable(item)) {
                        return anomalyNotes;
                      }
                      const row = rows[item.peer_id];
                      if (!row) return null;
                      return (
                        <Space direction="vertical" size={8} style={{ width: '100%' }}>
                          {anomalyNotes}
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
                          <SubnetMeshCheckboxes
                            row={row}
                            meshCandidates={item.mesh_candidates}
                            t={t}
                            onChange={(patch) => updateRow(item.peer_id, patch)}
                          />
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
                  <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {handledItems.map((item) => {
                      const row = rows[item.peer_id];
                      const hasExtra = item.already_node_owned && row && (
                        Object.keys(row.subnetChecked).length > 0 || Object.keys(row.meshChecked).length > 0
                      );
                      return (
                        <div key={item.peer_id} style={{ fontSize: 12, color: 'var(--ant-color-text-tertiary)', padding: '2px 0' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span>
                              {item.name || item.peer_id} — {item.already_node_owned ? t('nodes:networkDetection.alreadyOwned') : t('nodes:networkDetection.alreadyDismissed')}
                            </span>
                            {!item.already_node_owned && item.already_dismissed && (
                              <Button size="small" onClick={() => onUndismiss(item)}>{t('nodes:networkDetection.undismiss')}</Button>
                            )}
                          </div>
                          {hasExtra && row && (
                            <div style={{ marginTop: 4, marginLeft: 16 }}>
                              <Typography.Text style={{ fontSize: 12 }}>{t('nodes:networkDetection.extraHint')}</Typography.Text>
                              <Space direction="vertical" size={4} style={{ width: '100%', marginTop: 4 }}>
                                <SubnetMeshCheckboxes
                                  row={row}
                                  meshCandidates={item.mesh_candidates}
                                  t={t}
                                  onChange={(patch) => updateRow(item.peer_id, patch)}
                                />
                                <Button size="small" type="primary" onClick={() => onApplyExtra(item)}>
                                  {t('nodes:networkDetection.applyExtra')}
                                </Button>
                              </Space>
                            </div>
                          )}
                        </div>
                      );
                    })}
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
