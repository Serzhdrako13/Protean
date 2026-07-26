import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';
import type { Subnet } from '@/types/api';

export function useSubnetsQuery() {
  return useQuery({
    queryKey: ['subnets'],
    queryFn: () => HttpUtil.get<Subnet[]>('/api/subnets'),
  });
}

export function useSubnetMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['subnets'] });

  const create = useMutation({
    mutationFn: (input: { cidr: string; label: string }) => HttpUtil.post<Subnet>('/api/subnets', input),
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: (id: number) => HttpUtil.delete<null>(`/api/subnets/${id}`),
    onSuccess: invalidate,
  });
  const updateNAT = useMutation({
    mutationFn: ({ id, nat_mode }: { id: number; nat_mode: 'passthrough' | 'masquerade' }) =>
      HttpUtil.put<Subnet>(`/api/subnets/${id}`, { nat_mode }),
    onSuccess: invalidate,
  });

  return { create, remove, updateNAT };
}
