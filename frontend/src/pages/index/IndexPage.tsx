import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Card, Row, Col, Tag, Empty, Button, Skeleton, Progress, Badge, Tooltip, Radio, Switch, Space, Popconfirm, message, Tabs, Table } from 'antd';
import { ArrowDownOutlined, ArrowUpOutlined, PlusOutlined, QuestionCircleOutlined } from '@ant-design/icons';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useQueryClient, useQueries } from '@tanstack/react-query';
import { PageShell } from '@/layouts/PageShell';
import { PageTitleBar } from '@/components/PageTitleBar';
import { useDashboardQuery } from '@/api/queries/dashboard';
import { useAggregateTrafficQuery, useServerTrafficQuery } from '@/api/queries/providers';
import { useProviderSettingsMutations } from '@/api/queries/network';
import { useClientsQuery, type Client } from '@/api/queries/nodes';
import type { Home, HomeServer, TrafficPoint, XrayView } from '@/types/api';
import { Sparkline } from '@/components/viz/Sparkline';
import { PollIntervalSelect, POLL_INTERVALS } from '@/components/viz/PollIntervalSelect';
import { ApiError, HttpUtil } from '@/api/http-init';
import { useHideDownProviders } from '@/hooks/useHideDownProviders';

const RANGES = ['1h', '6h', '24h', '3d'] as const;

// providerLabel (backend) appends " @ <server>" when >1 server is registered
// — redundant here since each provider is already listed under its own
// server's card.
function stripServerSuffix(label: string, server: string): string {
  return label.replace(new RegExp(` @ ${server}$`), '');
}

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

// Clicking the status tag starts/stops the provider's service directly,
// same as ServerProvidersPage's StatusCell -- no need to leave the
// dashboard just to restart something.
function ProviderStatusTag({ p, label }: { p: HomeServer['providers'][number]; label: string }) {
  const { t } = useTranslation(['dashboard']);
  const { serviceAction } = useProviderSettingsMutations(p.key);
  const qc = useQueryClient();
  const up = p.up;

  async function onToggle() {
    try {
      await serviceAction.mutateAsync(up ? 'stop' : 'start');
      await qc.invalidateQueries({ queryKey: ['dashboard'] });
      message.success(t(up ? 'providerStatus.stopped' : 'providerStatus.started'));
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  return (
    <Popconfirm title={t(up ? 'providerStatus.confirmStop' : 'providerStatus.confirmStart', { label })} onConfirm={onToggle}>
      <Tag color={up ? 'success' : 'error'} style={{ cursor: 'pointer' }}>
        {up ? t('dashboard:providerStatus.up', { online: p.peers_online, total: p.peers }) : t('dashboard:providerStatus.down')}
      </Tag>
    </Popconfirm>
  );
}

// Each chart's time range is its own independent setting -- every card
// below gets its own RangeSelect + local state, not one shared control for
// the whole page.
function RangeSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const { t } = useTranslation(['dashboard']);
  return (
    <Radio.Group size="small" value={value} onChange={(e) => onChange(e.target.value)}>
      {RANGES.map((r) => (
        <Radio.Button key={r} value={r}>{t(`dashboard:trafficCard.ranges.${r}`)}</Radio.Button>
      ))}
    </Radio.Group>
  );
}

// Compact mode's gauge: no Card wrapper (that's most of the wasted space --
// the point of compact mode) and the value/label sit beside the ring, not
// below it, so the ring itself can shrink a lot without the text clipping.
function MiniGauge({ percent, color, value, label }: { percent: number; color: string; value: ReactNode; label: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <Progress type="circle" size={32} percent={percent} strokeColor={color} showInfo={false} />
      <div style={{ lineHeight: 1.3, minWidth: 0 }}>
        <div style={{ fontWeight: 600, fontSize: 13 }}>{value}</div>
        <div style={{ color: 'var(--ant-color-text-tertiary)', fontSize: 11, whiteSpace: 'nowrap' }}>{label}</div>
      </div>
    </div>
  );
}

// One visual family for every top-row tile: a circular Progress ring (real
// ratio for servers/peers, a static "always full" ring for byte totals —
// there's no ratio for those, but the ring shape + accent color keeps them
// visually part of the same set instead of looking like a different widget).
function GaugeTile({
  percent, color, format, label, tooltip, size = 90,
}: {
  percent: number; color: string; format: () => ReactNode; label: string; tooltip?: string; size?: number;
}) {
  return (
    <Card styles={{ body: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 } }}>
      <Progress type="dashboard" size={size} percent={percent} strokeColor={color} format={format} />
      <span style={{ color: 'var(--ant-color-text-tertiary)', fontSize: 13, display: 'flex', alignItems: 'center', gap: 4 }}>
        {label}
        {tooltip && (
          <Tooltip title={tooltip}>
            <QuestionCircleOutlined />
          </Tooltip>
        )}
      </span>
    </Card>
  );
}

// The compact density's shared 3-column body: a list on the left (servers
// for the overall card, providers for a per-server card), 3 stacked
// MiniGauges in the middle, and the traffic graph on the right -- one
// layout reused at both levels instead of two near-duplicate ones. Has its
// own independent time-range control, like every other chart on this page.
function CompactCard({
  title, items, serversOnline, serversTotal, peersOnline, peersTotal, rxBytes, txBytes, trafficPoints, range, onRangeChange, narrow,
}: {
  title: ReactNode;
  items: ReactNode;
  // Only the overview card passes these (there's no "servers online" concept
  // for a single per-server card) -- when present, an extra gauge is shown
  // first, matching the expanded mode's overview tile order.
  serversOnline?: number;
  serversTotal?: number;
  peersOnline: number;
  peersTotal: number;
  rxBytes: number;
  txBytes: number;
  trafficPoints: TrafficPoint[];
  range: string;
  onRangeChange: (v: string) => void;
  // narrow: the half-width 2-per-row server card layout -- there's no room
  // for items/gauges/graph side by side at half width, so the graph drops
  // to its own row below instead of being a 3rd column.
  narrow?: boolean;
}) {
  const { t } = useTranslation(['dashboard']);
  const legendRef = useRef<HTMLDivElement>(null);
  const gauges = (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {serversTotal !== undefined && (
        <MiniGauge
          percent={serversTotal ? Math.round(((serversOnline ?? 0) / serversTotal) * 100) : 0}
          color="var(--ant-color-success)"
          value={`${serversOnline ?? 0}/${serversTotal}`}
          label={t('dashboard:tiles.serversOnline.label')}
        />
      )}
      <MiniGauge
        percent={peersTotal ? Math.round((peersOnline / peersTotal) * 100) : 0}
        color="var(--ant-color-primary)"
        value={`${peersOnline}/${peersTotal}`}
        label={t('dashboard:tiles.peersOnline.label')}
      />
      <MiniGauge
        percent={100}
        color="var(--ant-color-info)"
        value={formatBytes(rxBytes)}
        label={t('dashboard:tiles.totalRx.label')}
      />
      <MiniGauge
        percent={100}
        color="#9575cd"
        value={formatBytes(txBytes)}
        label={t('dashboard:tiles.totalTx.label')}
      />
    </div>
  );

  if (narrow) {
    // Tile mode puts 2 cards side by side (see IndexPage's Row/Col around
    // CompactServerCard) and a server with more providers makes a taller
    // items list than its neighbor -- antd's Row already stretches both
    // Cols to the taller one's height, but the Card itself didn't fill
    // that height, so the two cards still looked mismatched. height:
    // '100%' + a flex column body pins items/gauges to the top and the
    // graph to the bottom, so any extra height lands as empty space above
    // the graph instead of a visibly shorter card.
    return (
      <Card
        title={title}
        extra={<RangeSelect value={range} onChange={onRangeChange} />}
        style={{ height: '100%', display: 'flex', flexDirection: 'column' }}
        styles={{ body: { display: 'flex', flexDirection: 'column', flex: '1 1 auto', minHeight: 0 } }}
      >
        <Row gutter={16} style={{ marginBottom: 16 }}>
          <Col xs={24} sm={14}>{items}</Col>
          <Col xs={24} sm={10}>{gauges}</Col>
        </Row>
        <div style={{ marginTop: 'auto' }}>
          <Sparkline points={trafficPoints} />
        </div>
      </Card>
    );
  }

  // Row mode: items/gauges narrowed (shifted left) to give the graph most
  // of the width, and uPlot's own Time/RX/TX legend is physically moved
  // (not redrawn -- see Sparkline's legendContainerRef) into its own column
  // between the gauges and the graph, instead of sitting below the chart.
  return (
    <Card title={title} extra={<RangeSelect value={range} onChange={onRangeChange} />}>
      <Row gutter={16}>
        <Col xs={24} md={6}>{items}</Col>
        <Col xs={24} md={3}>{gauges}</Col>
        <Col xs={24} md={3}><div ref={legendRef} /></Col>
        <Col xs={24} md={12}>
          <Sparkline points={trafficPoints} legendContainerRef={legendRef} />
        </Col>
      </Row>
    </Card>
  );
}

// Full-width per-server panel: nobody realistically runs more than a
// handful of VPN servers, so there's no reason to cram this into a small
// 1/3-width card -- each server gets the same depth of traffic detail as
// the page's overall chart above it (peer counts + a live rx/tx sparkline),
// with its own independent time-range control.
function ServerCard({ srv, pollMs, hideDown }: { srv: HomeServer; pollMs: number; hideDown: boolean }) {
  const { t } = useTranslation(['dashboard']);
  const [range, setRange] = useState('1h');
  const { data: traffic } = useServerTrafficQuery(srv.id, range, pollMs);
  // A peer can't actually be "online" through a provider that isn't up
  // (e.g. a stopped Xray instance can still report a configured peer as
  // online by its own tracking, independent of service state) -- only
  // count peers_online from providers that are actually up, matching how
  // api_dashboard.go's own home-level total already gates on st.Up.
  const peersOnline = srv.providers.reduce((sum, p) => sum + (p.up ? p.peers_online : 0), 0);
  const peersTotal = srv.providers.reduce((sum, p) => sum + p.peers, 0);
  // hideDown only hides rows from the list below -- summary counts above
  // always reflect the true total, so hiding down providers never makes
  // the peer/online numbers look inconsistent with what's actually there.
  const visibleProviders = hideDown ? srv.providers.filter((p) => p.up) : srv.providers;

  return (
    <Card title={<Link to={`/servers/${srv.id}/providers`}>{srv.label || srv.id}</Link>} extra={<RangeSelect value={range} onChange={setRange} />}>
      <div style={{ color: 'var(--ant-color-text-tertiary)', fontSize: 12, marginBottom: 12 }}>
        <code>{srv.id}</code> · {srv.host} · {t('dashboard:serverPeersSummary', { online: peersOnline, total: peersTotal })}
      </div>
      {srv.providers.length === 0 ? (
        <Empty description={t('dashboard:noProviders')} />
      ) : visibleProviders.length === 0 ? (
        <Empty description={t('dashboard:allProvidersHidden')} />
      ) : (
        <>
          <Sparkline points={traffic ?? []} />
          <div style={{ marginTop: 12 }}>
            {visibleProviders.map((p) => {
              const label = stripServerSuffix(p.label, srv.id);
              return (
                <div key={p.key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0' }}>
                  <Link to={`/providers/${p.key}`}>{label}</Link>
                  <ProviderStatusTag p={p} label={label} />
                </div>
              );
            })}
          </div>
        </>
      )}
    </Card>
  );
}

// Compact per-server card: same 3-column body as CompactOverviewCard, with
// the providers list on the left instead of the servers list.
function CompactServerCard({ srv, pollMs, narrow, hideDown }: { srv: HomeServer; pollMs: number; narrow?: boolean; hideDown: boolean }) {
  const { t } = useTranslation(['dashboard']);
  const [range, setRange] = useState('1h');
  const { data: traffic } = useServerTrafficQuery(srv.id, range, pollMs);
  // See ServerCard's identical comment: only providers that are actually
  // up can contribute a real "online" peer.
  const peersOnline = srv.providers.reduce((sum, p) => sum + (p.up ? p.peers_online : 0), 0);
  const peersTotal = srv.providers.reduce((sum, p) => sum + p.peers, 0);
  const visibleProviders = hideDown ? srv.providers.filter((p) => p.up) : srv.providers;

  return (
    <CompactCard
      title={<Link to={`/servers/${srv.id}/providers`}>{srv.label || srv.id}</Link>}
      narrow={narrow}
      range={range}
      onRangeChange={setRange}
      peersOnline={peersOnline}
      peersTotal={peersTotal}
      rxBytes={srv.rx_bytes}
      txBytes={srv.tx_bytes}
      trafficPoints={traffic ?? []}
      items={
        visibleProviders.length === 0 ? (
          <Empty description={t(srv.providers.length === 0 ? 'dashboard:noProviders' : 'dashboard:allProvidersHidden')} />
        ) : (
          visibleProviders.map((p) => {
            const label = stripServerSuffix(p.label, srv.id);
            return (
              <div key={p.key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0' }}>
                <Link to={`/providers/${p.key}`}>{label}</Link>
                <ProviderStatusTag p={p} label={label} />
              </div>
            );
          })
        )
      }
    />
  );
}

// Compact overview card: same 3-column body, one level up -- a server list
// (instead of a provider list) on the left, whole-dashboard totals in the
// middle/right. Lets the density toggle apply "for everything at once",
// not just the per-server cards below it.
function CompactOverviewCard({ data, pollMs }: { data: Home; pollMs: number }) {
  const { t } = useTranslation(['dashboard']);
  const [range, setRange] = useState('1h');
  const { data: traffic } = useAggregateTrafficQuery(range, pollMs);

  return (
    <CompactCard
      title={t('dashboard:heading')}
      range={range}
      onRangeChange={setRange}
      serversOnline={data.servers_up}
      serversTotal={data.servers_total}
      peersOnline={data.peers_online}
      peersTotal={data.peers_total}
      rxBytes={data.total_rx_bytes}
      txBytes={data.total_tx_bytes}
      trafficPoints={traffic ?? []}
      items={data.servers.map((srv) => {
        const up = srv.providers.filter((p) => p.up).length;
        return (
          <div key={srv.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0' }}>
            <Link to={`/servers/${srv.id}/providers`}>{srv.label || srv.id}</Link>
            <Tag color={up > 0 ? 'success' : 'error'}>
              {t('dashboard:serverProvidersSummary', { up, total: srv.providers.length })}
            </Tag>
          </div>
        );
      })}
    />
  );
}

// Expanded mode's overall traffic chart -- its own range, independent of
// every server card's own range below it.
function AggregateTrafficCard({ pollMs }: { pollMs: number }) {
  const { t } = useTranslation(['dashboard']);
  const [range, setRange] = useState('1h');
  const { data: aggTraffic } = useAggregateTrafficQuery(range, pollMs);
  return (
    <Card
      title={t('dashboard:trafficCard.title')}
      style={{ marginBottom: 20 }}
      extra={<RangeSelect value={range} onChange={setRange} />}
    >
      <Sparkline points={aggTraffic ?? []} />
    </Card>
  );
}

// The shield+monogram pictograms turned out illegible at table-row size --
// a colored text abbreviation reads instantly instead. Color per type is
// each project's own real brand color (checked, not guessed): WireGuard
// #88171A is literally the RGB value from wireguard.com's own trademark
// policy page; OpenVPN #AF231D and strongSwan/IKEv2 #646B52 are Simple
// Icons' recorded brand hex for those projects; AmneziaWG #1F69FF is
// en.amnezia.org's own site accent (by far the most frequent hex on the
// page). Xray has no brand color anywhere -- yellow per explicit request.
const PROVIDER_TYPE_ABBR: Record<string, string> = {
  wireguard: 'wg',
  amneziawg: 'awg',
  openvpn: 'ovpn',
  ikev2: 'ikev',
  xray: 'xray',
};
const PROVIDER_TYPE_COLOR: Record<string, string> = {
  wireguard: '#88171A',
  amneziawg: '#1F69FF',
  openvpn: '#AF231D',
  ikev2: '#646B52',
  xray: 'var(--ant-color-warning)',
};
const PROVIDER_TYPE_LABEL: Record<string, string> = {
  wireguard: 'WireGuard',
  amneziawg: 'AmneziaWG',
  openvpn: 'OpenVPN',
  ikev2: 'IKEv2',
  xray: 'Xray',
};

function ProviderTypeIcon({ type }: { type: string }) {
  const abbr = PROVIDER_TYPE_ABBR[type];
  if (!abbr) return null;
  return (
    <Tooltip title={PROVIDER_TYPE_LABEL[type] ?? type}>
      <span style={{ color: PROVIDER_TYPE_COLOR[type], fontWeight: 700, fontSize: 12 }}>{abbr}</span>
    </Tooltip>
  );
}

// Groups the flat /api/clients rows (one row per raw VPN connection) by
// real owner (a Node/User, or the peer itself if unowned) into one row per
// real client -- same grouping "Клиенты" → "Все клиенты" leaves flat on
// purpose (that page's job is the per-connection detail); the dashboard's
// job is "who's connected, at a glance," so one row per real device/person
// is the right shape here instead.
interface ClientGroup {
  key: string;
  name: string;
  addresses: string[];
  online: boolean;
  connections: Client[];
  rxTotal: number;
  txTotal: number;
  // Xray clients merged in by name -- see mergeXrayEntries. Never comes
  // from groupClients itself: Xray is structurally absent from
  // /api/clients (its client model isn't peer-key-addressable the same
  // way as the other four protocols), so this is populated separately.
  xrayEntries: XrayEntry[];
}

interface XrayEntry {
  providerLabel: string;
  link: string;
}

function groupClients(clients: Client[]): ClientGroup[] {
  const groups = new Map<string, ClientGroup>();
  for (const c of clients) {
    // An unowned peer (no Node/User formally attached) is still the SAME
    // real client across every provider it connects through -- grouping by
    // provider+peer_id here (instead of by name) was a real bug: it split
    // one real device's WireGuard/OpenVPN/IKEv2/AmneziaWG connections into
    // as many separate rows as it has providers, each showing a dropdown
    // with exactly one connection, which defeated the entire point of this
    // view. The peer's own name is the only signal available for "same
    // device" once there's no formal owner -- an admin naming multiple
    // peers identically (e.g. "dev-node" on every provider, as done here)
    // is exactly that signal.
    const key = c.owner_kind !== 'none' ? `${c.owner_kind}:${c.owner_name}` : `peer:${c.name}`;
    let g = groups.get(key);
    if (!g) {
      g = {
        key,
        name: c.owner_kind !== 'none' ? (c.owner_name ?? c.name) : c.name,
        addresses: [],
        online: false,
        connections: [],
        rxTotal: 0,
        txTotal: 0,
        xrayEntries: [],
      };
      groups.set(key, g);
    }
    g.connections.push(c);
    if (c.address && !g.addresses.includes(c.address)) g.addresses.push(c.address);
    if (c.online) g.online = true;
    g.rxTotal += c.rx_bytes;
    g.txTotal += c.tx_bytes;
  }
  return Array.from(groups.values());
}

// Merges each Xray provider's clients (name + subscription link only --
// there's no online/traffic data for them anywhere in the backend) into
// the client groups by matching name, same as an admin naming a WireGuard
// and an OpenVPN peer identically to mean "the same device". An Xray
// client whose name matches no other group still gets its own row --
// otherwise it would just vanish, which is the exact complaint this whole
// merge exists to fix ("xray в компактном виде не отмечен вообще").
function mergeXrayEntries(groups: ClientGroup[], xrayByName: Map<string, XrayEntry[]>): ClientGroup[] {
  const byName = new Map(groups.map((g) => [g.name, g]));
  for (const [name, entries] of xrayByName) {
    let g = byName.get(name);
    if (!g) {
      g = { key: `xray-only:${name}`, name, addresses: [], online: false, connections: [], rxTotal: 0, txTotal: 0, xrayEntries: [] };
      groups.push(g);
      byName.set(name, g);
    }
    g.xrayEntries = entries;
  }
  return groups;
}

// One badge per distinct protocol type present, with a ×N count when a
// client has more than one connection of the same type -- answers "how
// many/which kind of connections does this client have" at a glance,
// without needing to expand.
function providerTypeCounts(connections: Client[]): { type: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const c of connections) counts.set(c.type, (counts.get(c.type) ?? 0) + 1);
  return Array.from(counts.entries()).map(([type, count]) => ({ type, count }));
}

// A connection row is either a real /api/clients connection (with real
// status/traffic) or an Xray entry (name + subscription link only -- no
// online/traffic data for it exists anywhere in the backend, so those
// columns are honestly "—" rather than a fabricated guess).
type ConnectionRow = { kind: 'client'; c: Client } | ({ kind: 'xray' } & XrayEntry);

// Per-connection detail table shown beneath a client row in expanded mode --
// same columns/style as NodesPage's NodeAccessPanel (provider/server/type/
// category/address/status/traffic). Always available (any client can
// expand, even with a single connection) so the address -- deliberately
// dropped from the collapsed row, since it can't be represented by one
// value once a client has more than one provider -- has exactly one place
// it always lives, uniformly, instead of sometimes being on the collapsed
// row and sometimes not.
function ClientConnectionsTable({ connections, xrayEntries }: { connections: Client[]; xrayEntries: XrayEntry[] }) {
  const { t } = useTranslation(['dashboard', 'common']);
  const rows: ConnectionRow[] = [
    ...connections.map((c): ConnectionRow => ({ kind: 'client', c })),
    ...xrayEntries.map((x): ConnectionRow => ({ kind: 'xray', ...x })),
  ];
  return (
    <Table
      size="small"
      rowKey={(r) => (r.kind === 'client' ? `${r.c.provider}-${r.c.peer_id}` : `xray-${r.providerLabel}`)}
      pagination={false}
      dataSource={rows}
      columns={[
        {
          title: t('dashboard:clientsCard.columns.provider'),
          key: 'provider_label',
          render: (_: unknown, r: ConnectionRow) => (
            <Space size={6}>
              <ProviderTypeIcon type={r.kind === 'client' ? r.c.type : 'xray'} />
              {r.kind === 'client' ? r.c.provider_label : r.providerLabel}
            </Space>
          ),
        },
        {
          title: t('dashboard:clientsCard.columns.server'),
          key: 'server_id',
          render: (_: unknown, r: ConnectionRow) => (r.kind === 'client' ? <code>{r.c.server_id}</code> : '—'),
        },
        {
          title: t('dashboard:clientsCard.columns.type'),
          key: 'type',
          render: (_: unknown, r: ConnectionRow) => (r.kind === 'client' ? r.c.type : 'xray'),
        },
        {
          title: t('dashboard:clientsCard.columns.category'),
          key: 'category',
          render: (_: unknown, r: ConnectionRow) =>
            r.kind === 'client' && r.c.category ? t(`dashboard:clientsCard.categoryLabels.${r.c.category}`) : '—',
        },
        {
          title: t('dashboard:clientsCard.columns.address'),
          key: 'address',
          render: (_: unknown, r: ConnectionRow) => (r.kind === 'client' && r.c.address ? <code>{r.c.address}</code> : '—'),
        },
        {
          title: t('dashboard:clientsCard.columns.status'),
          key: 'status',
          render: (_: unknown, r: ConnectionRow) => {
            if (r.kind !== 'client') return '—';
            return r.c.online ? <Tag color="success">{t('common:status.online')}</Tag> : <Tag color="error">{t('common:status.offline')}</Tag>;
          },
        },
        {
          title: t('dashboard:clientsCard.columns.traffic'),
          key: 'traffic',
          render: (_: unknown, r: ConnectionRow) =>
            r.kind === 'client' ? (
              <span>
                <Tag color="blue">↓{formatBytes(r.c.rx_bytes)}</Tag>
                <Tag color="purple">↑{formatBytes(r.c.tx_bytes)}</Tag>
              </span>
            ) : (
              '—'
            ),
        },
      ]}
    />
  );
}

// Xray clients are structurally absent from GET /api/clients (their model
// isn't peer-key-addressable the same way as the other four protocols --
// see api_clients.go), and unlike every other protocol an Xray client has
// no online/traffic data anywhere in the backend at all (XrayClient is
// just {name, link}). Rather than a separate floating status row (tried
// first, but it sat above the table attached to no client -- exactly the
// wrong shape), each Xray provider's clients are fetched here and merged
// into the same per-client rows as every other protocol by name (see
// mergeXrayEntries) -- whether the Xray SERVICE itself is up/down is
// already visible on the Обзор tab's server cards at all times, so this
// tab's job stays "which client has which connections."
function useXrayClientsByName(home: Home | undefined): Map<string, XrayEntry[]> {
  const xrayProviders = home?.servers.flatMap((srv) => srv.providers.filter((p) => p.type === 'xray')) ?? [];
  const results = useQueries({
    queries: xrayProviders.map((p) => ({
      queryKey: ['xray', p.key, ''],
      queryFn: () => HttpUtil.get<XrayView>(`/api/providers/${encodeURIComponent(p.key)}/xray`),
    })),
  });
  const byName = new Map<string, XrayEntry[]>();
  results.forEach((r, i) => {
    const p = xrayProviders[i];
    for (const c of r.data?.clients ?? []) {
      const list = byName.get(c.name) ?? [];
      list.push({ providerLabel: p.label, link: c.link });
      byName.set(c.name, list);
    }
  });
  return byName;
}

// Compact "who's connected right now" list -- an AntD Table (size="small"),
// same widget every other entity list in this app uses. The switch is a
// bulk expand-all/collapse-all action; independently, every row also gets
// its own standard AntD expand arrow so one specific client can be
// expanded or collapsed on its own without touching the rest -- the two
// controls are orthogonal, not the same state.
function ClientsCard({ data: home }: { data: Home | undefined }) {
  const { t } = useTranslation(['dashboard', 'common']);
  const { data, isLoading } = useClientsQuery();
  const [expanded, setExpanded] = useState(
    () => localStorage.getItem('protean-dashboard-clients-expanded') === 'true',
  );
  const xrayByName = useXrayClientsByName(home);
  const groups = mergeXrayEntries(groupClients(data ?? []), xrayByName);
  const [expandedKeys, setExpandedKeys] = useState<string[]>([]);

  // Re-apply the bulk preference whenever the client list (re)loads --
  // covers both first load and any later refetch, not just the toggle click.
  useEffect(() => {
    setExpandedKeys(expanded ? groups.map((g) => g.key) : []);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  function onExpandedChange(v: boolean) {
    setExpanded(v);
    localStorage.setItem('protean-dashboard-clients-expanded', String(v));
    setExpandedKeys(v ? groups.map((g) => g.key) : []);
  }

  const columns = [
    {
      title: t('dashboard:clientsCard.columns.name'),
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: t('dashboard:clientsCard.columns.providers'),
      key: 'providers',
      render: (_: unknown, g: ClientGroup) => (
        <div style={{ display: 'flex', flexWrap: 'nowrap', alignItems: 'center', gap: 12, whiteSpace: 'nowrap' }}>
          {providerTypeCounts(g.connections).map(({ type, count }) => (
            <span key={type} style={{ display: 'inline-flex', alignItems: 'center', gap: 3, flexShrink: 0 }}>
              <ProviderTypeIcon type={type} />
              {count > 1 && <span style={{ fontSize: 12, color: 'var(--ant-color-text-tertiary)' }}>×{count}</span>}
            </span>
          ))}
          {g.xrayEntries.length > 0 && (
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, flexShrink: 0 }}>
              <ProviderTypeIcon type="xray" />
              {g.xrayEntries.length > 1 && <span style={{ fontSize: 12, color: 'var(--ant-color-text-tertiary)' }}>×{g.xrayEntries.length}</span>}
            </span>
          )}
        </div>
      ),
    },
    {
      title: t('dashboard:clientsCard.columns.traffic'),
      key: 'traffic',
      render: (_: unknown, g: ClientGroup) =>
        g.connections.length === 0 ? (
          '—'
        ) : (
          <span>
            <Tag color="blue">↓{formatBytes(g.rxTotal)}</Tag>
            <Tag color="purple">↑{formatBytes(g.txTotal)}</Tag>
          </span>
        ),
    },
    {
      title: t('dashboard:clientsCard.columns.status'),
      key: 'status',
      render: (_: unknown, g: ClientGroup) => {
        if (g.connections.length === 0) return '—';
        return g.online ? <Tag color="success">{t('common:status.online')}</Tag> : <Tag color="error">{t('common:status.offline')}</Tag>;
      },
    },
  ];

  return (
    <Card
      title={t('dashboard:clientsCard.title')}
      style={{ marginTop: 20 }}
      extra={
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <Switch size="small" checked={expanded} onChange={onExpandedChange} />
          <span style={{ fontSize: 12, color: 'var(--ant-color-text-tertiary)' }}>
            {expanded ? t('dashboard:clientsCard.expanded') : t('dashboard:clientsCard.collapsed')}
          </span>
        </span>
      }
    >
      {isLoading ? (
        <Skeleton active />
      ) : groups.length === 0 ? (
        <Empty description={t('dashboard:clientsCard.empty')} />
      ) : (
        <Table
          size="small"
          rowKey="key"
          columns={columns}
          dataSource={groups}
          pagination={groups.length > 20 ? { pageSize: 20, showSizeChanger: true } : false}
          scroll={{ x: true }}
          expandable={{
            expandedRowKeys: expandedKeys,
            onExpandedRowsChange: (keys) => setExpandedKeys(keys as string[]),
            expandedRowRender: (g: ClientGroup) => <ClientConnectionsTable connections={g.connections} xrayEntries={g.xrayEntries} />,
          }}
        />
      )}
    </Card>
  );
}

// The pre-existing dashboard content (poll controls, gauge tiles, traffic
// chart, server cards) -- now the "Обзор" tab's content, unchanged except
// for living in its own component so it can sit inside a Tabs item instead
// of the page's only content.
function OverviewTab({ data, pollMs, setPollMs }: { data: Home; pollMs: number; setPollMs: (v: number) => void }) {
  const { t } = useTranslation(['dashboard']);
  // Density applies to this tab's content as a whole (overview block +
  // every server card) -- persisted like the other small per-browser UI
  // prefs (sidebar collapse, theme, language).
  const [density, setDensity] = useState<'expanded' | 'compact'>(
    () => (localStorage.getItem('protean-dashboard-density') === 'compact' ? 'compact' : 'expanded'),
  );
  function onDensityChange(compact: boolean) {
    const v = compact ? 'compact' : 'expanded';
    setDensity(v);
    localStorage.setItem('protean-dashboard-density', v);
  }
  // Only meaningful in compact mode -- 2 half-width cards per row instead
  // of 1 full-width one, graph drops below items+gauges instead of beside
  // them. The overview card is untouched by this either way.
  const [narrowServers, setNarrowServers] = useState(
    () => localStorage.getItem('protean-dashboard-narrow-servers') === 'true',
  );
  function onNarrowServersChange(v: boolean) {
    setNarrowServers(v);
    localStorage.setItem('protean-dashboard-narrow-servers', String(v));
  }
  const [hideDown, setHideDown] = useHideDownProviders();

  return (
    <>
      <div style={{ marginBottom: 16, display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
        <Badge
          status="processing"
          text={
            <span style={{ color: 'var(--ant-color-text-tertiary)', fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              {t('dashboard:pollBadge', {
                interval: (() => {
                  const found = POLL_INTERVALS.find((p) => p.value === pollMs);
                  return found ? t(`poll-interval:${found.key}`) : t('poll-interval:customSeconds', { s: pollMs / 1000 });
                })(),
              })}
              <Tooltip title={t('dashboard:pollTooltip')}>
                <QuestionCircleOutlined />
              </Tooltip>
            </span>
          }
        />
        <PollIntervalSelect value={pollMs} onChange={setPollMs} />
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <Switch size="small" checked={density === 'compact'} onChange={onDensityChange} />
          <span style={{ fontSize: 12, color: 'var(--ant-color-text-tertiary)' }}>
            {density === 'compact' ? t('dashboard:density.compact') : t('dashboard:density.expanded')}
          </span>
        </span>
        {density === 'compact' && (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <Switch size="small" checked={narrowServers} onChange={onNarrowServersChange} />
            <span style={{ fontSize: 12, color: 'var(--ant-color-text-tertiary)' }}>
              {narrowServers ? t('dashboard:density.tileView') : t('dashboard:density.rowView')}
            </span>
          </span>
        )}
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <Switch size="small" checked={hideDown} onChange={setHideDown} />
          <span style={{ fontSize: 12, color: 'var(--ant-color-text-tertiary)' }}>
            {t('dashboard:hideDownProviders')}
          </span>
        </span>
      </div>
      {density === 'expanded' && (
        <>
          <Row gutter={[20, 20]} style={{ marginBottom: 20 }}>
            <Col xs={12} sm={6}>
              <GaugeTile
                percent={data.servers_total ? Math.round((data.servers_up / data.servers_total) * 100) : 0}
                color="var(--ant-color-success)"
                format={() => `${data.servers_up}/${data.servers_total}`}
                label={t('dashboard:tiles.serversOnline.label')}
                tooltip={t('dashboard:tiles.serversOnline.tooltip')}
              />
            </Col>
            <Col xs={12} sm={6}>
              <GaugeTile
                percent={data.peers_total ? Math.round((data.peers_online / data.peers_total) * 100) : 0}
                color="var(--ant-color-primary)"
                format={() => `${data.peers_online}/${data.peers_total}`}
                label={t('dashboard:tiles.peersOnline.label')}
                tooltip={t('dashboard:tiles.peersOnline.tooltip')}
              />
            </Col>
            <Col xs={12} sm={6}>
              <GaugeTile
                percent={100}
                color="var(--ant-color-info)"
                format={() => (
                  <span style={{ fontSize: 15 }}><ArrowDownOutlined /> {formatBytes(data.total_rx_bytes)}</span>
                )}
                label={t('dashboard:tiles.totalRx.label')}
                tooltip={t('dashboard:tiles.totalRx.tooltip')}
              />
            </Col>
            <Col xs={12} sm={6}>
              <GaugeTile
                percent={100}
                color="#9575cd"
                format={() => (
                  <span style={{ fontSize: 15 }}><ArrowUpOutlined /> {formatBytes(data.total_tx_bytes)}</span>
                )}
                label={t('dashboard:tiles.totalTx.label')}
                tooltip={t('dashboard:tiles.totalTx.tooltip')}
              />
            </Col>
          </Row>

          <AggregateTrafficCard pollMs={pollMs} />

          <Row gutter={[20, 20]}>
            {data.servers.map((srv) => (
              <Col key={srv.id} xs={24}>
                <ServerCard srv={srv} pollMs={pollMs} hideDown={hideDown} />
              </Col>
            ))}
          </Row>
        </>
      )}
      {density === 'compact' && (
        <>
          <div style={{ marginBottom: 20 }}>
            <CompactOverviewCard data={data} pollMs={pollMs} />
          </div>
          <Row gutter={[20, 20]}>
            {data.servers.map((srv) => (
              <Col key={srv.id} xs={24} md={narrowServers ? 12 : 24}>
                <CompactServerCard srv={srv} pollMs={pollMs} narrow={narrowServers} hideDown={hideDown} />
              </Col>
            ))}
          </Row>
        </>
      )}
    </>
  );
}

export function IndexPage() {
  const { t } = useTranslation(['dashboard', 'common']);
  // One shared interval for the whole page (tiles + server list + chart) —
  // previously the tiles polled a hardcoded 5s regardless of this control,
  // so picking a slower chart interval didn't actually reduce backend load.
  const [pollMs, setPollMs] = useState(60_000);
  const { data, isLoading } = useDashboardQuery(pollMs);

  return (
    <PageShell>
      <PageTitleBar>{t('dashboard:heading')}</PageTitleBar>
      {isLoading && <Skeleton active />}
      {!isLoading && data && !data.has_servers && (
        <Card>
          <Empty description={t('dashboard:emptyServers')}>
            <Link to="/servers">
              <Button type="primary" icon={<PlusOutlined />}>{t('dashboard:addFirstServer')}</Button>
            </Link>
          </Empty>
        </Card>
      )}
      {!isLoading && data && data.has_servers && (
        <Tabs
          items={[
            { key: 'overview', label: t('dashboard:tabs.overview'), children: <OverviewTab data={data} pollMs={pollMs} setPollMs={setPollMs} /> },
            { key: 'clients', label: t('dashboard:tabs.clients'), children: <ClientsCard data={data} /> },
          ]}
        />
      )}
    </PageShell>
  );
}
