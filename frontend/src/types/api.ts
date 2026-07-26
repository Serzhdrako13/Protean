// Mirrors of the Go backend's JSON DTOs (internal/api/api_*.go, types.go).
// Most new endpoints use snake_case (hand-written json tags); two reused
// pre-existing Go structs (vpn.ServerStatus, PeerView) have no json tags and
// so serialize as plain Go field names (PascalCase) — kept as-is here rather
// than adding tags backend-side purely for frontend taste.

export interface ServerStatus {
  Provider: string;
  Up: boolean;
  PublicKey: string;
  ListenPort: number;
  Endpoint: string;
  Address: string;
  DNS: string;
  PeerCount: number;
  PeersOnline: number;
  TotalRxBytes: number;
  TotalTxBytes: number;
  Extra: Record<string, string> | null;
}

export interface Peer {
  URLID: string;
  Name: string;
  Online: boolean;
  Disabled: boolean;
  Endpoint: string;
  AllowedIPs: string[] | null;
  LastHandshake: string; // RFC3339
  RxBytes: number;
  TxBytes: number;
  PersistentKeepalive: number;
  P12Password: string;
  ExpiresAt: string; // RFC3339, zero value when unset
  Muted: boolean;
  Category: string;
  OwnerUserID: number;
  OwnerUsername: string;
  NodeOwnerID: number;
  NodeOwnerName: string;
}

export interface HomeProvider {
  key: string;
  type: string;
  label: string;
  up: boolean;
  peers: number;
  peers_online: number;
}

export interface HomeServer {
  id: string;
  label: string;
  host: string;
  providers: HomeProvider[];
  rx_bytes: number;
  tx_bytes: number;
}

export interface Home {
  has_servers: boolean;
  servers: HomeServer[];
  servers_up: number;
  servers_total: number;
  peers_online: number;
  peers_total: number;
  total_rx_bytes: number;
  total_tx_bytes: number;
}

export interface ServerRow {
  id: string;
  label: string;
  host: string;
  port: number;
  ssh_user: string;
  public_host: string;
  host_key_set: boolean;
  enabled: boolean;
  panel_host: boolean;
}

export interface ProviderSummary {
  key: string;
  type: string;
  label: string;
  friendly_label?: string;
  server_id: string;
  status: ServerStatus;
  cert_based: boolean;
  portal_visible: boolean;
  description?: string;
}

export interface PendingApprovedRequest {
  request_id: number;
  username: string;
}

export interface ProviderDetail {
  provider: string;
  provider_label: string;
  type: string;
  status: ServerStatus;
  peers: Peer[] | null;
  not_implemented: boolean;
  cert_based: boolean;
  profile_formats?: string[];
  needs_setup: boolean;
  peers_unavailable: boolean;
  supports_backups: boolean;
  pending_approved_request?: PendingApprovedRequest;
}

export interface Account {
  username: string;
  totp_enabled: boolean;
  password_expired: boolean;
  language?: string;
}

export interface TrafficPoint {
  t: number; // unix seconds
  rx: number; // bytes/sec
  tx: number; // bytes/sec
}

export interface MeshIface {
  provider: string;
  label: string;
  up: boolean;
  listen_port: number;
  peer_count: number;
  tunnel_cidr?: string;
  supports_forward: boolean;
  forwarding_enabled: boolean;
  group_name?: string;
}

export interface MeshPeer {
  provider: string;
  name: string;
  address: string;
  online: boolean;
}

export interface MeshSubnet {
  cidr: string;
  label: string;
  group_name?: string;
}

export interface Mesh {
  server_id: string;
  servers: string[];
  interfaces: MeshIface[] | null;
  peers: MeshPeer[] | null;
  subnets: MeshSubnet[] | null;
  warnings: string[] | null;
}

export interface Subnet {
  id: number;
  cidr: string;
  label: string;
  provider?: string;
  owner_node_id?: number | null;
  owner_node_name?: string;
  nat_mode: 'passthrough' | 'masquerade';
  nat_capable: boolean;
  group_id?: number | null;
  group_name?: string;
}

export interface NetworkGroup {
  id: number;
  name: string;
}

export interface AuditEntry {
  timestamp: string; // RFC3339
  username: string;
  action: string;
  target: string;
}

// Reused Go view structs (no json tags) -> PascalCase, same convention as
// ServerStatus/Peer above.
export interface NotifyField {
  Key: string;
  Label: string;
  Value: string;
  Secret: boolean;
  Set: boolean;
}

export interface NotifyChannel {
  Kind: string;
  Label: string;
  Enabled: boolean;
  Fields: NotifyField[];
}

export interface NotifySettings {
  ev_iface_updown: boolean;
  ev_site_connect: boolean;
  ev_site_disconnect: boolean;
  ev_client_connect: boolean;
  ev_client_disconnect: boolean;
  ev_unknown_peer: boolean;
  report_enabled: boolean;
  report_interval_hours: number;
  report_include_events: boolean;
  report_include_status: boolean;
  ctnt_provider: boolean;
  ctnt_endpoint: boolean;
  ctnt_address: boolean;
  ctnt_time: boolean;
}

export interface Notify {
  channels: NotifyChannel[];
  settings: NotifySettings;
  pending_count: number;
}

export interface XrayStrategyOpt {
  name: string;
  label: string;
  selected: boolean;
}

export interface XrayParam {
  key: string;
  label: string;
  placeholder: string;
  value: string;
  required: boolean;
  secret: boolean;
}

export interface XrayClient {
  name: string;
  link: string;
}

export interface XrayRelayHop {
  host: string;
  strategy: string;
}

export interface XrayView {
  provider: string;
  provider_label: string;
  up: boolean;
  configured: boolean;
  current: string;
  has_relay: boolean;
  relay_chain?: XrayRelayHop[];
  strategies: XrayStrategyOpt[];
  multi_client: boolean;
  param_specs: XrayParam[];
  clients: XrayClient[];
}

export interface PanelUser {
  id: number;
  username: string;
  role: 'admin' | 'user';
  created_at: string;
  enabled: boolean;
  portal_access_enabled: boolean;
}
