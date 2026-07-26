import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface ServerConfig {
  // listen_port/address/dns are wg-family-only today (see ServerConfigCard);
  // optional so the OpenVPN mtu/mssfix-only card can PUT without them.
  listen_port?: number;
  address?: string;
  dns?: string;
  // mtu: 0 = not set (OS/wg-quick/OpenVPN default).
  mtu: number;
  // mssfix: OpenVPN-only, tun-mtu's sibling (clamps TCP MSS instead). 0 = not set.
  mssfix?: number;
  extra?: Record<string, string>;
}

export function useServerConfigQuery(provider: string, enabled: boolean) {
  return useQuery({
    queryKey: ['server-config', provider],
    queryFn: () => HttpUtil.get<ServerConfig>(`/api/providers/${encodeURIComponent(provider)}/server-config`),
    enabled: enabled && !!provider,
  });
}

export interface MeshSettings {
  mesh_enabled: boolean;
  internet_egress: boolean;
  // auto_assign_start/end: bounds auto-provisioning (portal access grants,
  // node grants) to a sub-range of the subnet -- empty means no restriction.
  auto_assign_start?: string;
  auto_assign_end?: string;
  mesh_capable: boolean;
  service_unit?: string;
  service_status?: string;
  group_id?: number | null;
  group_name?: string;
}

export function useMeshSettingsQuery(provider: string, enabled: boolean) {
  return useQuery({
    queryKey: ['mesh-settings', provider],
    queryFn: () => HttpUtil.get<MeshSettings>(`/api/providers/${encodeURIComponent(provider)}/mesh-settings`),
    enabled: enabled && !!provider,
  });
}

export function useProviderSettingsMutations(provider: string) {
  const qc = useQueryClient();
  const base = `/api/providers/${encodeURIComponent(provider)}`;

  const updateServerConfig = useMutation({
    mutationFn: (input: ServerConfig) => HttpUtil.put<ServerConfig>(`${base}/server-config`, input),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['server-config', provider] }),
  });
  const updateMeshSettings = useMutation({
    mutationFn: (input: {
      mesh_enabled: boolean; internet_egress: boolean; auto_assign_start?: string; auto_assign_end?: string;
      group_id?: number | null; new_group_name?: string;
    }) => HttpUtil.put<MeshSettings>(`${base}/mesh-settings`, input),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['mesh-settings', provider] }),
  });
  const serviceAction = useMutation({
    mutationFn: (action: string) => HttpUtil.post<null>(`${base}/service`, { action }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['mesh-settings', provider] }),
  });
  // A mutation (not a query) -- logs are fetched on demand when the admin
  // opens the "View logs" modal, not kept live/cached in the background.
  const fetchLogs = useMutation({
    mutationFn: (lines: number) =>
      HttpUtil.get<{ logs: string }>(`${base}/logs?lines=${lines}`),
  });

  return { updateServerConfig, updateMeshSettings, serviceAction, fetchLogs };
}
