import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface MeshCandidate {
  provider: string;
  cidr: string;
}

// One peer's classification result from the read-only detection preview
// -- see internal/api/network_detect.go's DetectedItem doc comment for
// the full reasoning behind each field.
export interface DetectedItem {
  peer_id: string;
  name: string;
  has_name: boolean;
  own_address?: string;
  routed_subnets?: string[];
  full_tunnel: boolean;
  anomalies?: string[];
  already_node_owned: boolean;
  already_dismissed: boolean;
  existing_subnet_cidrs?: string[];
  mesh_candidates?: MeshCandidate[];
  suggested_action: 'create_node' | 'none' | 'already_handled' | 'anomaly';
}

export interface NetworkDetectionPreview {
  provider: string;
  tunnel_cidr?: string;
  items: DetectedItem[];
}

export function useNetworkDetectionQuery(provider: string | undefined) {
  return useQuery({
    queryKey: ['network-detection', provider],
    queryFn: () => HttpUtil.get<NetworkDetectionPreview>(`/api/providers/${encodeURIComponent(provider!)}/network-detection`),
    enabled: !!provider,
  });
}

export interface DetectionDecision {
  peer_id: string;
  action: 'create_node' | 'skip' | 'undismiss';
  node_name?: string;
  node_kind?: 'router' | 'device' | 'other';
  subnets_to_create?: { cidr: string; label: string }[];
  mesh_with?: string[];
}

export interface DetectionSummary {
  nodes_created: number;
  subnets_created: number;
  mesh_pairs_enabled: number;
  skipped: number;
  already_handled: number;
  undismissed: number;
  // Soft (non-aborting) failures applying the batch, e.g. enabling mesh
  // succeeded in the DB but turning on IPv4 forwarding on the host failed.
  warnings?: string[];
}

export function useNetworkDetectionApplyMutation(provider: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (decisions: DetectionDecision[]) =>
      HttpUtil.post<DetectionSummary>(`/api/providers/${encodeURIComponent(provider!)}/network-detection/apply`, { decisions }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['network-detection', provider] });
      qc.invalidateQueries({ queryKey: ['nodes'] });
      qc.invalidateQueries({ queryKey: ['subnets'] });
      qc.invalidateQueries({ queryKey: ['mesh'] });
      qc.invalidateQueries({ queryKey: ['clients'] });
    },
  });
}
