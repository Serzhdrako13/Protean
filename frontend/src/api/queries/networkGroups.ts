import { useQuery } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';
import type { NetworkGroup } from '@/types/api';

export function useNetworkGroupsQuery() {
  return useQuery({
    queryKey: ['network-groups'],
    queryFn: () => HttpUtil.get<NetworkGroup[]>('/api/network-groups'),
  });
}
