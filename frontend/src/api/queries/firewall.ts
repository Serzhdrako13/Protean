import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface FirewallRule {
  id: number;
  ordering: number;
  action: 'accept' | 'drop' | 'reject';
  proto: 'tcp' | 'udp' | 'any';
  port_spec: string;
  source_cidr: string;
  comment: string;
  enabled: boolean;
}

export interface FirewallBaselinePort {
  proto: string;
  port: number;
  label: string;
}

export interface FirewallPolicy {
  enabled: boolean;
  default_incoming: 'drop' | 'accept';
  rollback_window_secs: number;
  last_applied_at?: string;
  last_confirmed_at?: string;
}

export interface FirewallStatus {
  pending: boolean;
  remaining_secs: number;
  confirmed_state_saved: boolean;
}

export interface FirewallGetResp {
  policy: FirewallPolicy;
  rules: FirewallRule[];
  baseline: FirewallBaselinePort[];
  warnings: string[];
  status?: FirewallStatus;
}

export function useFirewallQuery(serverId: string) {
  return useQuery({
    queryKey: ['firewall', serverId],
    queryFn: () => HttpUtil.get<FirewallGetResp>(`/api/servers/${encodeURIComponent(serverId)}/firewall`),
    enabled: !!serverId,
  });
}

export function useFirewallStatusQuery(serverId: string, enabled: boolean) {
  return useQuery({
    queryKey: ['firewall', serverId, 'status'],
    queryFn: () => HttpUtil.get<FirewallStatus>(`/api/servers/${encodeURIComponent(serverId)}/firewall/status`),
    enabled,
    refetchInterval: enabled ? 2000 : false,
  });
}

export interface FirewallRuleInput {
  action: 'accept' | 'drop' | 'reject';
  proto: 'tcp' | 'udp' | 'any';
  port_spec: string;
  source_cidr: string;
  comment: string;
  enabled: boolean;
}

export interface FirewallPolicyInput {
  enabled: boolean;
  default_incoming: 'drop' | 'accept';
  rollback_window_secs: number;
}

export interface FirewallDryRunResp {
  valid: boolean;
  error?: string;
  added: string[];
  removed: string[];
}

export interface FirewallApplyResp {
  rollback_window_secs: number;
  panel_reachable: boolean;
}

export function useFirewallMutations(serverId: string) {
  const qc = useQueryClient();
  const invalidate = () => void qc.invalidateQueries({ queryKey: ['firewall', serverId] });

  const savePolicy = useMutation({
    mutationFn: (input: FirewallPolicyInput) => HttpUtil.put<null>(`/api/servers/${encodeURIComponent(serverId)}/firewall/policy`, input),
    onSuccess: invalidate,
  });
  const saveRules = useMutation({
    mutationFn: (rules: FirewallRuleInput[]) => HttpUtil.put<null>(`/api/servers/${encodeURIComponent(serverId)}/firewall/rules`, rules),
    onSuccess: invalidate,
  });
  const dryRun = useMutation({
    mutationFn: () => HttpUtil.post<FirewallDryRunResp>(`/api/servers/${encodeURIComponent(serverId)}/firewall/dry-run`),
  });
  const apply = useMutation({
    mutationFn: () => HttpUtil.post<FirewallApplyResp>(`/api/servers/${encodeURIComponent(serverId)}/firewall/apply`),
    onSuccess: invalidate,
  });
  const confirm = useMutation({
    mutationFn: () => HttpUtil.post<null>(`/api/servers/${encodeURIComponent(serverId)}/firewall/confirm`),
    onSuccess: invalidate,
  });
  const rollback = useMutation({
    mutationFn: () => HttpUtil.post<null>(`/api/servers/${encodeURIComponent(serverId)}/firewall/rollback`),
    onSuccess: invalidate,
  });

  return { savePolicy, saveRules, dryRun, apply, confirm, rollback };
}
