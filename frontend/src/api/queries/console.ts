import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface ConsoleTarget {
  target: string; // "server:<id>"
  label: string;
  kind: 'panel-host' | 'node';
}

export function useConsoleTargetsQuery() {
  return useQuery({
    queryKey: ['console', 'targets'],
    queryFn: () => HttpUtil.get<ConsoleTarget[]>('/api/console/targets'),
  });
}

export interface ConsoleSessionResp {
  ticket: string;
  ws_url: string;
  target_label: string;
  kind: 'panel-host' | 'node';
}

export function useCreateConsoleSessionMutation() {
  return useMutation({
    mutationFn: (target: string) => HttpUtil.post<ConsoleSessionResp>('/api/console/sessions', { target }),
  });
}

export interface PanelHostInfo {
  server_id: string;
  label: string;
}

export function usePanelHostQuery() {
  return useQuery({
    queryKey: ['console', 'panel-host'],
    queryFn: () => HttpUtil.get<PanelHostInfo | null>('/api/console/panel-host'),
  });
}

export function usePanelHostMutations() {
  const qc = useQueryClient();
  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ['console', 'panel-host'] });
    void qc.invalidateQueries({ queryKey: ['console', 'targets'] });
    void qc.invalidateQueries({ queryKey: ['servers'] });
  };
  const set = useMutation({
    mutationFn: (serverId: string) => HttpUtil.put<null>('/api/console/panel-host', { server_id: serverId }),
    onSuccess: invalidate,
  });
  const clear = useMutation({
    mutationFn: () => HttpUtil.put<null>('/api/console/panel-host', { server_id: '' }),
    onSuccess: invalidate,
  });
  return { set, clear };
}
