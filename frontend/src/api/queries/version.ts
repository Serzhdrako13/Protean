import { useQuery } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export function useVersionQuery() {
  return useQuery({
    queryKey: ['version'],
    queryFn: () => HttpUtil.get<{ version: string }>('/api/version'),
    staleTime: Infinity,
  });
}
