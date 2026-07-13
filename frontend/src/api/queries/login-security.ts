import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface LoginSecuritySettings {
  enabled: boolean;
  track_by_username: boolean;
  track_by_ip: boolean;
  fail_threshold: number;
  count_window_minutes: number;
  ban_base_minutes: number;
  escalation_factor: number;
  escalation_reset_minutes: number;
  max_ban_minutes: number;
}

export interface LoginIPRule {
  ip_or_cidr: string;
  kind: 'allow' | 'deny';
  note: string;
  created_at: string;
}

export interface LoginBan {
  key_type: 'username' | 'ip';
  key_value: string;
  banned_until: string;
  escalation_level: number;
}

export interface LoginAttempt {
  ts: string;
  username: string;
  ip: string;
  success: boolean;
  reason: string;
}

export interface LoginSecurityStats {
  total_attempts_24h: number;
  failed_attempts_24h: number;
  top_ips_24h: { ip: string; count: number }[];
  recent: LoginAttempt[];
}

export function useLoginSecuritySettingsQuery() {
  return useQuery({
    queryKey: ['login-security-settings'],
    queryFn: () => HttpUtil.get<LoginSecuritySettings>('/api/login-security/settings'),
  });
}

export function useLoginIPRulesQuery() {
  return useQuery({
    queryKey: ['login-ip-rules'],
    queryFn: () => HttpUtil.get<LoginIPRule[]>('/api/login-security/ip-rules'),
  });
}

export function useLoginBansQuery() {
  return useQuery({
    queryKey: ['login-bans'],
    queryFn: () => HttpUtil.get<LoginBan[]>('/api/login-security/bans'),
    refetchInterval: 15_000,
  });
}

export function useLoginSecurityStatsQuery() {
  return useQuery({
    queryKey: ['login-security-stats'],
    queryFn: () => HttpUtil.get<LoginSecurityStats>('/api/login-security/stats'),
    refetchInterval: 15_000,
  });
}

export function useLoginSecurityMutations() {
  const qc = useQueryClient();

  const updateSettings = useMutation({
    mutationFn: (input: LoginSecuritySettings) => HttpUtil.put<null>('/api/login-security/settings', input),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['login-security-settings'] }),
  });
  const addIPRule = useMutation({
    mutationFn: (input: { ip_or_cidr: string; kind: 'allow' | 'deny'; note?: string }) =>
      HttpUtil.post<null>('/api/login-security/ip-rules', input),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['login-ip-rules'] }),
  });
  const deleteIPRule = useMutation({
    mutationFn: (ip_or_cidr: string) =>
      HttpUtil.delete<null>(`/api/login-security/ip-rules?ip_or_cidr=${encodeURIComponent(ip_or_cidr)}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['login-ip-rules'] }),
  });
  const unban = useMutation({
    mutationFn: (input: { key_type: string; key_value: string }) => HttpUtil.post<null>('/api/login-security/bans/unban', input),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['login-bans'] }),
  });

  return { updateSettings, addIPRule, deleteIPRule, unban };
}
