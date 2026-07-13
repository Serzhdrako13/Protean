import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';
import type { Mesh } from '@/types/api';

export function useMeshQuery(server?: string) {
  return useQuery({
    queryKey: ['mesh', server ?? ''],
    queryFn: () => HttpUtil.get<Mesh>(`/api/mesh${server ? `?server=${encodeURIComponent(server)}` : ''}`),
    refetchInterval: 10_000,
  });
}

export function useMeshMutations() {
  const qc = useQueryClient();
  const enableForwarding = useMutation({
    mutationFn: (provider: string) =>
      HttpUtil.post<null>(`/api/mesh/providers/${encodeURIComponent(provider)}/forwarding`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['mesh'] }),
  });
  return { enableForwarding };
}
