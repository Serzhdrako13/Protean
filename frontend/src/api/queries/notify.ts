import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';
import type { Notify, NotifySettings } from '@/types/api';

export function useNotifyQuery() {
  return useQuery({
    queryKey: ['notifications'],
    queryFn: () => HttpUtil.get<Notify>('/api/notifications'),
  });
}

export function useNotifyMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['notifications'] });

  const saveSettings = useMutation({
    mutationFn: (input: NotifySettings) => HttpUtil.post<null>('/api/notifications/settings', input),
    onSuccess: invalidate,
  });
  const saveChannel = useMutation({
    mutationFn: ({ kind, ...input }: { kind: string; enabled: boolean; [field: string]: unknown }) =>
      HttpUtil.post<null>(`/api/notifications/channel/${encodeURIComponent(kind)}`, input),
    onSuccess: invalidate,
  });
  const testChannel = useMutation({
    mutationFn: (kind: string) => HttpUtil.post<null>(`/api/notifications/channel/${encodeURIComponent(kind)}/test`),
  });

  return { saveSettings, saveChannel, testChannel };
}
