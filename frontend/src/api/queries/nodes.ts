import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

// "Узел" -- a non-portal, non-login equipment identity (router, or an
// external server that's just a VPN client peer). See the plan doc for why
// this is a separate table/entity from PanelUser rather than another role.
export interface Node {
  id: number;
  name: string;
  kind: 'router' | 'device' | 'other';
  role: 'member' | 'network_node';
  description?: string;
  created_at: string;
  peers_online: number;
  peers_total: number;
}

export function useNodesQuery() {
  return useQuery({
    queryKey: ['nodes'],
    queryFn: () => HttpUtil.get<Node[]>('/api/nodes'),
  });
}

export interface NodeWriteInput {
  name: string;
  kind: Node['kind'];
  role: Node['role'];
  description?: string;
}

export function useNodeMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['nodes'] });

  const create = useMutation({
    mutationFn: (input: NodeWriteInput) => HttpUtil.post<Node>('/api/nodes', input),
    onSuccess: invalidate,
  });
  const update = useMutation({
    mutationFn: ({ id, ...input }: NodeWriteInput & { id: number }) =>
      HttpUtil.put<null>(`/api/nodes/${id}`, input),
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: (id: number) => HttpUtil.delete<null>(`/api/nodes/${id}`),
    onSuccess: invalidate,
  });

  return { create, update, remove };
}

// One provider instance + this node's current state on it -- backs the
// Nodes page's expandable per-node access panel. Richer than
// UserAccessRow: no login/portal here, so only "granted"/"none" states
// exist, but an admin needs more operational detail per row -- notably
// internet_egress, shown prominently so a NAT misconfiguration for a
// network_node is visible at a glance, not buried on a settings tab.
export interface NodeAccessRow {
  provider: string;
  provider_label: string;
  type: string;
  interface: string;
  server_id: string;
  description?: string;
  state: 'granted' | 'none';
  address?: string;
  online: boolean;
  last_handshake?: string;
  rx_bytes: number;
  tx_bytes: number;
  internet_egress: boolean;
}

export function useNodeAccessQuery(nodeId: number, enabled: boolean) {
  return useQuery({
    queryKey: ['node-access', nodeId],
    queryFn: () => HttpUtil.get<NodeAccessRow[]>(`/api/nodes/${nodeId}/access`),
    enabled,
  });
}

export function useNodeAccessMutations(nodeId: number) {
  const qc = useQueryClient();
  const setAccess = useMutation({
    mutationFn: ({ provider, enabled }: { provider: string; enabled: boolean }) =>
      HttpUtil.post<null>(`/api/nodes/${nodeId}/access/${encodeURIComponent(provider)}`, { enabled }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['node-access', nodeId] });
      qc.invalidateQueries({ queryKey: ['nodes'] });
    },
  });
  return { setAccess };
}

// One real peer anywhere in the system, owner resolved across both
// ownership tables -- backs the "Клиенты сети → Все клиенты" unified
// overview (GET /api/clients).
export interface Client {
  provider: string;
  provider_label: string;
  server_id: string;
  type: string;
  peer_id: string;
  name: string;
  address?: string;
  category?: string;
  online: boolean;
  last_handshake?: string;
  rx_bytes: number;
  tx_bytes: number;
  owner_kind: 'user' | 'node' | 'none';
  owner_name?: string;
}

export function useClientsQuery() {
  return useQuery({
    queryKey: ['clients'],
    queryFn: () => HttpUtil.get<Client[]>('/api/clients'),
  });
}

// Assigns/clears a node as a peer's owner -- the manual-creation fallback
// for cert-based providers (OpenVPN/IKEv2), where a client is created via
// the normal "Add client" form first, then handed to a node here instead
// of a portal user. newNodeName/newNodeKind (nodeId: 0 + a name) create
// the node and assign it in the same request, mirroring
// useNetworkGroupsQuery's create-on-the-fly group picker -- lets this
// picker create a brand-new piece of equipment without a trip to the
// separate Nodes/"Оборудование" page, which has no way to link a peer
// at all (a real gap: a node created there could only ever be linked via
// this same endpoint anyway).
export function useNodeOwnerMutation(provider: string) {
  const qc = useQueryClient();
  const base = `/api/providers/${encodeURIComponent(provider)}/peers`;
  return useMutation({
    mutationFn: ({ peerId, nodeId, newNodeName, newNodeKind }: {
      peerId: string; nodeId: number; newNodeName?: string; newNodeKind?: string;
    }) =>
      HttpUtil.post<null>(`${base}/${encodeURIComponent(peerId)}/node-owner`, {
        node_id: nodeId, new_node_name: newNodeName, new_node_kind: newNodeKind,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['providers', provider] });
      qc.invalidateQueries({ queryKey: ['nodes'] });
    },
  });
}
