import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface UpdatesInfo {
  count: number;
  reboot_required: boolean;
  output: string;
}

export function useUpdatesCheckQuery(serverId: string, enabled: boolean) {
  return useQuery({
    queryKey: ['updates', serverId],
    queryFn: () => HttpUtil.get<UpdatesInfo>(`/api/servers/${encodeURIComponent(serverId)}/updates`),
    enabled,
  });
}

export interface UpdatesApplySession {
  ticket: string;
  ws_url: string;
  target_label: string;
}

export function useStartUpdatesApplyMutation(serverId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => HttpUtil.post<UpdatesApplySession>(`/api/servers/${encodeURIComponent(serverId)}/updates/apply`),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['updates', serverId] }); },
  });
}
