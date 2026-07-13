import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface Backup {
  id: number;
  saved_at: string;
  bytes: number;
  preview: string;
}

export function useBackupsQuery(provider: string, enabled: boolean) {
  return useQuery({
    queryKey: ['backups', provider],
    queryFn: () => HttpUtil.get<Backup[]>(`/api/providers/${encodeURIComponent(provider)}/backups`),
    enabled: enabled && !!provider,
  });
}

export function useRestoreBackupMutation(provider: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => HttpUtil.post<null>(`/api/providers/${encodeURIComponent(provider)}/backups/${id}/restore`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['providers', provider] }),
  });
}
