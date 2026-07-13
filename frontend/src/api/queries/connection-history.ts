import { useQuery } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface ConnectionEvent {
  ts: string;
  provider: string;
  peer_id: string;
  peer_name: string;
  event: 'connect' | 'disconnect';
}

export interface ConnectionHistoryFilter {
  provider?: string;
  sinceHours: number;
}

export function useConnectionHistoryQuery(filter: ConnectionHistoryFilter) {
  return useQuery({
    queryKey: ['connection-history', filter],
    queryFn: () => {
      const params = new URLSearchParams();
      if (filter.provider) params.set('provider', filter.provider);
      params.set('since_hours', String(filter.sinceHours));
      return HttpUtil.get<ConnectionEvent[]>(`/api/connection-history?${params.toString()}`);
    },
    refetchInterval: 30_000,
  });
}
