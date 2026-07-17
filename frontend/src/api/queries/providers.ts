import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';
import type { ProviderDetail, ProviderSummary, TrafficPoint } from '@/types/api';

export function useProvidersQuery() {
  return useQuery({
    queryKey: ['providers'],
    queryFn: () => HttpUtil.get<ProviderSummary[]>('/api/providers'),
    refetchInterval: 7_000,
  });
}

export function useProviderDetailQuery(provider: string) {
  return useQuery({
    queryKey: ['providers', provider],
    queryFn: () => HttpUtil.get<ProviderDetail>(`/api/providers/${encodeURIComponent(provider)}`),
    refetchInterval: 7_000,
    enabled: !!provider,
  });
}

export function useProviderSetupMutation(provider: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => HttpUtil.post<null>(`/api/providers/${encodeURIComponent(provider)}/setup`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['providers', provider] }),
  });
}

// pollMs controls how often the chart re-fetches, NOT how often the backend
// actually samples (that's a fixed server-side interval, default 60s — see
// TRAFFIC_SAMPLE_INTERVAL_SECONDS). Polling faster than the real sample rate
// just shows a freshly-landed point sooner; it doesn't manufacture new data.
export function useTrafficQuery(provider: string, range: string, pollMs = 60_000) {
  return useQuery({
    queryKey: ['traffic', provider, range],
    queryFn: () => HttpUtil.get<TrafficPoint[]>(`/api/providers/${encodeURIComponent(provider)}/traffic?range=${range}`),
    refetchInterval: pollMs,
    enabled: !!provider,
  });
}

export function useAggregateTrafficQuery(range: string, pollMs = 60_000) {
  return useQuery({
    queryKey: ['traffic-aggregate', range],
    queryFn: () => HttpUtil.get<TrafficPoint[]>(`/api/traffic/aggregate?range=${range}`),
    refetchInterval: pollMs,
  });
}

// Same rate chart as useAggregateTrafficQuery, summed across only one
// server's providers -- backs the Index page's per-server traffic card.
export function useServerTrafficQuery(serverId: string, range: string, pollMs = 60_000) {
  return useQuery({
    queryKey: ['traffic-server', serverId, range],
    queryFn: () => HttpUtil.get<TrafficPoint[]>(`/api/servers/${encodeURIComponent(serverId)}/traffic?range=${range}`),
    refetchInterval: pollMs,
    enabled: !!serverId,
  });
}

export interface PeerCreateInput {
  name: string;
  client_address: string;
  keepalive: number;
  expire_days: number;
  subnet_ids: number[];
  own_public_key: string;
  client_csr: string;
  category: string;
  // access_request_id links this new peer to a portal user's already-
  // approved access request (see AccessRequestsPage) -- the backend
  // assigns ownership + marks the request granted once the peer checks out.
  access_request_id?: number;
}

export type PeerUpdateInput = Pick<PeerCreateInput, 'name' | 'client_address' | 'keepalive' | 'subnet_ids' | 'category'>;

export function usePeerMutations(provider: string) {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['providers', provider] });
  const base = `/api/providers/${encodeURIComponent(provider)}/peers`;

  const create = useMutation({
    mutationFn: (input: PeerCreateInput) => HttpUtil.post<{ url_id: string }>(base, input),
    onSuccess: invalidate,
  });
  const update = useMutation({
    mutationFn: ({ id, ...input }: PeerUpdateInput & { id: string }) =>
      HttpUtil.put<null>(`${base}/${encodeURIComponent(id)}`, input),
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: (id: string) => HttpUtil.delete<null>(`${base}/${encodeURIComponent(id)}`),
    onSuccess: invalidate,
  });
  const enable = useMutation({
    mutationFn: (id: string) => HttpUtil.post<null>(`${base}/${encodeURIComponent(id)}/enable`),
    onSuccess: invalidate,
  });
  const disable = useMutation({
    mutationFn: (id: string) => HttpUtil.post<null>(`${base}/${encodeURIComponent(id)}/disable`),
    onSuccess: invalidate,
  });
  const rotate = useMutation({
    mutationFn: (id: string) => HttpUtil.post<{ url_id: string }>(`${base}/${encodeURIComponent(id)}/rotate`),
    onSuccess: invalidate,
  });
  const toggleMute = useMutation({
    mutationFn: (id: string) => HttpUtil.post<{ muted: boolean }>(`${base}/${encodeURIComponent(id)}/mute`),
    onSuccess: invalidate,
  });
  // Adopts an already-issued client certificate (e.g. from a VPN server
  // being taken over by the panel) instead of issuing a new one -- only
  // works once the provider's CA is the one that actually signed it (see
  // useCAImportMutation in api/queries/ca.ts).
  const importPeer = useMutation({
    mutationFn: (input: { cert_pem: string; key_pem?: string }) =>
      HttpUtil.post<{ url_id: string }>(`${base}/import`, input),
    onSuccess: invalidate,
  });

  return { create, update, remove, enable, disable, rotate, toggleMute, importPeer };
}
