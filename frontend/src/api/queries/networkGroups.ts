import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';
import type { NetworkGroup } from '@/types/api';

export function useNetworkGroupsQuery() {
  return useQuery({
    queryKey: ['network-groups'],
    queryFn: () => HttpUtil.get<NetworkGroup[]>('/api/network-groups'),
  });
}

// Shared across every page that shows a group name (Subnets, Обзор сети,
// provider mesh settings) via the ['network-groups'] query key -- a
// rename made from any one of them is immediately visible everywhere else
// too.
export function useNetworkGroupRenameMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, name }: { id: number; name: string }) =>
      HttpUtil.put<NetworkGroup>(`/api/network-groups/${id}`, { name }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['network-groups'] });
      qc.invalidateQueries({ queryKey: ['subnets'] });
      qc.invalidateQueries({ queryKey: ['mesh'] });
      qc.invalidateQueries({ queryKey: ['mesh-settings'] });
    },
  });
}
