import { useQuery } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';
import type { Home } from '@/types/api';

// pollMs is shared with the traffic chart on the same page (IndexPage) — one
// interval for the whole "Панель" view, so picking a slower value actually
// cuts backend load instead of the tiles quietly still polling every 5s
// underneath a slower-looking chart control.
export function useDashboardQuery(pollMs = 60_000) {
  return useQuery({
    queryKey: ['dashboard'],
    queryFn: () => HttpUtil.get<Home>('/api/dashboard'),
    refetchInterval: pollMs,
  });
}
