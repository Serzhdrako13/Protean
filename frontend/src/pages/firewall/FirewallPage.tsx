import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  Button, Card, Select, InputNumber, Switch, Space, Table, Input, Tag, Modal, Alert, Typography, Popconfirm, message,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { ArrowLeftOutlined, PlusOutlined, DeleteOutlined, SafetyOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { PageTitleBar } from '@/components/PageTitleBar';
import { ApiError } from '@/api/http-init';
import {
  useFirewallQuery, useFirewallMutations, useFirewallStatusQuery, type FirewallRuleInput, type FirewallDryRunResp,
} from '@/api/queries/firewall';

const emptyRule: FirewallRuleInput = { action: 'accept', proto: 'tcp', port_spec: '', source_cidr: '', comment: '', enabled: true };

export function FirewallPage() {
  const { t } = useTranslation(['firewall', 'common']);
  const { id = '' } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data, isLoading } = useFirewallQuery(id);
  const { savePolicy, saveRules, dryRun, apply, confirm, rollback } = useFirewallMutations(id);

  const [enabled, setEnabled] = useState(false);
  const [defaultIncoming, setDefaultIncoming] = useState<'drop' | 'accept'>('drop');
  const [windowSecs, setWindowSecs] = useState(300);
  const [rules, setRules] = useState<FirewallRuleInput[]>([]);
  const [dryRunResult, setDryRunResult] = useState<FirewallDryRunResp | null>(null);
  const [applyConfirmOpen, setApplyConfirmOpen] = useState(false);
  const [justApplied, setJustApplied] = useState<{ panelReachable: boolean } | null>(null);

  useEffect(() => {
    if (!data) return;
    setEnabled(data.policy.enabled);
    setDefaultIncoming(data.policy.default_incoming);
    setWindowSecs(data.policy.rollback_window_secs);
    setRules(data.rules.map((r) => ({
      action: r.action, proto: r.proto, port_spec: r.port_spec, source_cidr: r.source_cidr, comment: r.comment, enabled: r.enabled,
    })));
  }, [data]);

  const pending = data?.status?.pending ?? false;
  const statusPoll = useFirewallStatusQuery(id, pending);
  const remaining = statusPoll.data?.remaining_secs ?? data?.status?.remaining_secs ?? 0;

  async function onSavePolicy() {
    try {
      await savePolicy.mutateAsync({ enabled, default_incoming: defaultIncoming, rollback_window_secs: windowSecs });
      void message.success(t('common:actions.saved'));
    } catch (err) {
      void message.error(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function onSaveRules() {
    try {
      await saveRules.mutateAsync(rules);
      void message.success(t('common:actions.saved'));
    } catch (err) {
      void message.error(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function onDryRun() {
    try {
      const res = await dryRun.mutateAsync();
      setDryRunResult(res);
    } catch (err) {
      void message.error(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function onApply() {
    setApplyConfirmOpen(false);
    try {
      const res = await apply.mutateAsync();
      setJustApplied({ panelReachable: res.panel_reachable });
    } catch (err) {
      void message.error(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function onConfirm() {
    try {
      await confirm.mutateAsync();
      setJustApplied(null);
      void message.success(t('confirmed'));
    } catch (err) {
      void message.error(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function onRollback() {
    try {
      await rollback.mutateAsync();
      setJustApplied(null);
      void message.success(t('rolledBack'));
    } catch (err) {
      void message.error(err instanceof ApiError ? err.message : String(err));
    }
  }

  const baselineColumns: ColumnsType<{ proto: string; port: number; label: string }> = [
    { title: t('table.proto'), dataIndex: 'proto', width: 80 },
    { title: t('table.port'), dataIndex: 'port', width: 100 },
    { title: t('table.label'), dataIndex: 'label' },
  ];

  function updateRule(i: number, patch: Partial<FirewallRuleInput>) {
    setRules((rs) => rs.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));
  }

  return (
    <PageShell>
      <PageTitleBar prefix={<Button icon={<ArrowLeftOutlined />} onClick={() => navigate(`/servers/${id}/providers`)} />}>
        {t('title')} — <code>{id}</code>
      </PageTitleBar>

      {pending && (
        <Alert
          type="warning"
          showIcon
          icon={<SafetyOutlined />}
          style={{ marginBottom: 16 }}
          message={t('countdown.title', { secs: remaining })}
          description={(
            <Space direction="vertical">
              {justApplied && (
                <Typography.Text>
                  {justApplied.panelReachable ? t('countdown.panelReachableOk') : t('countdown.panelReachableFailed')}
                </Typography.Text>
              )}
              <Space>
                <Button type="primary" onClick={onConfirm} loading={confirm.isPending}>{t('actions.confirm')}</Button>
                <Popconfirm title={t('actions.rollbackConfirmTitle')} onConfirm={onRollback} okButtonProps={{ danger: true }}>
                  <Button danger loading={rollback.isPending}>{t('actions.rollbackNow')}</Button>
                </Popconfirm>
              </Space>
            </Space>
          )}
        />
      )}

      {data?.warnings.map((w) => (
        <Alert key={w} type="error" showIcon message={w} style={{ marginBottom: 12 }} />
      ))}

      <Card size="small" title={t('policy.title')} loading={isLoading} style={{ marginBottom: 16 }}>
        <Space direction="vertical" size="middle" style={{ width: '100%' }}>
          <Space>
            <Switch checked={enabled} onChange={setEnabled} />
            <span>{t('policy.enabled')}</span>
          </Space>
          <Space>
            <span>{t('policy.defaultIncoming')}:</span>
            <Select
              value={defaultIncoming}
              style={{ width: 140 }}
              onChange={setDefaultIncoming}
              options={[
                { value: 'drop', label: t('policy.drop') },
                { value: 'accept', label: t('policy.accept') },
              ]}
            />
          </Space>
          <Space>
            <span>{t('policy.rollbackWindow')}:</span>
            <InputNumber min={30} max={3600} value={windowSecs} onChange={(v) => setWindowSecs(v ?? 300)} addonAfter={t('policy.seconds')} />
          </Space>
          <Button onClick={onSavePolicy} loading={savePolicy.isPending}>{t('common:actions.save')}</Button>
        </Space>
      </Card>

      <Card size="small" title={t('baseline.title')} style={{ marginBottom: 16 }}>
        <Typography.Paragraph type="secondary">{t('baseline.description')}</Typography.Paragraph>
        <Table
          size="small"
          rowKey={(r) => `${r.proto}:${r.port}:${r.label}`}
          columns={baselineColumns}
          dataSource={data?.baseline ?? []}
          pagination={false}
        />
      </Card>

      <Card
        size="small"
        title={t('rules.title')}
        style={{ marginBottom: 16 }}
        extra={<Button size="small" icon={<PlusOutlined />} onClick={() => setRules((rs) => [...rs, { ...emptyRule }])}>{t('rules.add')}</Button>}
      >
        <Space direction="vertical" style={{ width: '100%' }}>
          {rules.map((rule, i) => (
            <Space key={i} wrap style={{ width: '100%' }}>
              <Select
                value={rule.action}
                style={{ width: 100 }}
                onChange={(v) => updateRule(i, { action: v })}
                options={[
                  { value: 'accept', label: t('rules.accept') },
                  { value: 'drop', label: t('rules.drop') },
                  { value: 'reject', label: t('rules.reject') },
                ]}
              />
              <Select
                value={rule.proto}
                style={{ width: 90 }}
                onChange={(v) => updateRule(i, { proto: v })}
                options={[{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }, { value: 'any', label: t('rules.any') }]}
              />
              <Input placeholder={t('rules.portSpecPlaceholder')} style={{ width: 140 }} value={rule.port_spec} onChange={(e) => updateRule(i, { port_spec: e.target.value })} />
              <Input placeholder={t('rules.sourceCidrPlaceholder')} style={{ width: 180 }} value={rule.source_cidr} onChange={(e) => updateRule(i, { source_cidr: e.target.value })} />
              <Input placeholder={t('rules.commentPlaceholder')} style={{ width: 160 }} value={rule.comment} onChange={(e) => updateRule(i, { comment: e.target.value })} />
              <Switch size="small" checked={rule.enabled} onChange={(v) => updateRule(i, { enabled: v })} />
              <Button size="small" danger icon={<DeleteOutlined />} onClick={() => setRules((rs) => rs.filter((_, idx) => idx !== i))} />
            </Space>
          ))}
          <Button onClick={onSaveRules} loading={saveRules.isPending}>{t('common:actions.save')}</Button>
        </Space>
      </Card>

      <Space>
        <Button onClick={onDryRun} loading={dryRun.isPending}>{t('actions.dryRun')}</Button>
        <Button type="primary" onClick={() => setApplyConfirmOpen(true)} loading={apply.isPending} disabled={!enabled}>
          {t('actions.apply')}
        </Button>
      </Space>

      <Modal title={t('dryRun.title')} open={!!dryRunResult} onCancel={() => setDryRunResult(null)} footer={<Button onClick={() => setDryRunResult(null)}>{t('common:actions.close')}</Button>}>
        {dryRunResult && (
          <>
            <Tag color={dryRunResult.valid ? 'success' : 'error'}>{dryRunResult.valid ? t('dryRun.valid') : t('dryRun.invalid')}</Tag>
            {dryRunResult.error && <Alert type="error" message={dryRunResult.error} style={{ marginTop: 8 }} />}
            <Typography.Title level={5} style={{ marginTop: 12 }}>{t('dryRun.added')}</Typography.Title>
            <pre style={{ background: 'var(--ant-color-fill-tertiary, #f5f5f5)', padding: 8, borderRadius: 6, maxHeight: 160, overflow: 'auto' }}>
              {dryRunResult.added.length ? dryRunResult.added.join('\n') : t('dryRun.none')}
            </pre>
            <Typography.Title level={5}>{t('dryRun.removed')}</Typography.Title>
            <pre style={{ background: 'var(--ant-color-fill-tertiary, #f5f5f5)', padding: 8, borderRadius: 6, maxHeight: 160, overflow: 'auto' }}>
              {dryRunResult.removed.length ? dryRunResult.removed.join('\n') : t('dryRun.none')}
            </pre>
            <Typography.Text type="secondary">{t('dryRun.note')}</Typography.Text>
          </>
        )}
      </Modal>

      <Modal
        title={t('applyConfirm.title')}
        open={applyConfirmOpen}
        onCancel={() => setApplyConfirmOpen(false)}
        onOk={onApply}
        okButtonProps={{ danger: true }}
        okText={t('actions.apply')}
      >
        <Typography.Paragraph>{t('applyConfirm.description', { secs: windowSecs })}</Typography.Paragraph>
      </Modal>
    </PageShell>
  );
}
