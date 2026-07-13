import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';
import type { XrayView } from '@/types/api';

export function useXrayQuery(provider: string, strategy?: string) {
  return useQuery({
    queryKey: ['xray', provider, strategy ?? ''],
    queryFn: () =>
      HttpUtil.get<XrayView>(
        `/api/providers/${encodeURIComponent(provider)}/xray${strategy ? `?strategy=${encodeURIComponent(strategy)}` : ''}`,
      ),
    enabled: !!provider,
  });
}

export interface XrayApplyInput {
  strategy: string;
  params: Record<string, string>;
  relay_links: string[];
}

export function useXrayMutations(provider: string) {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['xray', provider] });
  const base = `/api/providers/${encodeURIComponent(provider)}/xray`;

  const apply = useMutation({
    mutationFn: (input: XrayApplyInput) => HttpUtil.post<null>(base, input),
    onSuccess: invalidate,
  });
  const addClient = useMutation({
    mutationFn: (name: string) => HttpUtil.post<null>(`${base}/clients`, { name }),
    onSuccess: invalidate,
  });
  const removeClient = useMutation({
    mutationFn: (name: string) => HttpUtil.post<null>(`${base}/clients/remove`, { name }),
    onSuccess: invalidate,
  });

  return { apply, addClient, removeClient };
}
