import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface DataRetentionSettings {
  access_requests_enabled: boolean;
  access_requests_days: number;
  audit_log_enabled: boolean;
  audit_log_days: number;
  login_attempts_enabled: boolean;
  login_attempts_days: number;
  login_bans_enabled: boolean;
  login_bans_days: number;
}

export interface DataRetentionCleanupResult {
  access_requests_deleted: number;
  audit_log_deleted: number;
  login_attempts_deleted: number;
  login_bans_deleted: number;
  sessions_deleted: number;
}

export function useDataRetentionSettingsQuery() {
  return useQuery({
    queryKey: ['data-retention'],
    queryFn: () => HttpUtil.get<DataRetentionSettings>('/api/data-retention/settings'),
  });
}

export function useDataRetentionMutations() {
  const qc = useQueryClient();
  const update = useMutation({
    mutationFn: (input: DataRetentionSettings) => HttpUtil.put<null>('/api/data-retention/settings', input),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['data-retention'] }),
  });
  const cleanupNow = useMutation({
    mutationFn: () => HttpUtil.post<DataRetentionCleanupResult>('/api/data-retention/cleanup', {}),
  });
  return { update, cleanupNow };
}
