import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface AccessRequest {
  id: number;
  username: string;
  provider: string;
  server_id: string;
  provider_label: string;
  status: 'pending' | 'approved' | 'granted' | 'denied';
  created_at: string;
}

export function useAccessRequestsQuery() {
  return useQuery({
    queryKey: ['access-requests'],
    queryFn: () => HttpUtil.get<AccessRequest[]>('/api/access-requests'),
    refetchInterval: 15_000,
  });
}

export function useAccessRequestMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['access-requests'] });

  const approve = useMutation({
    mutationFn: (id: number) => HttpUtil.post<null>(`/api/access-requests/${id}/approve`),
    onSuccess: invalidate,
  });
  const deny = useMutation({
    mutationFn: (id: number) => HttpUtil.post<null>(`/api/access-requests/${id}/deny`),
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: (id: number) => HttpUtil.delete<null>(`/api/access-requests/${id}`),
    onSuccess: invalidate,
  });
  const clearDenied = useMutation({
    mutationFn: () => HttpUtil.post<{ deleted: number }>('/api/access-requests/clear-denied'),
    onSuccess: invalidate,
  });

  return { approve, deny, remove, clearDenied };
}
