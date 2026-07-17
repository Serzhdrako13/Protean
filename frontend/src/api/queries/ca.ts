import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface CAInfo {
  configured: boolean;
  source?: 'internal' | 'external';
  created_at?: string;
}

export function useCAInfoQuery(provider: string, enabled: boolean) {
  return useQuery({
    queryKey: ['ca-info', provider],
    queryFn: () => HttpUtil.get<CAInfo>(`/api/providers/${encodeURIComponent(provider)}/ca`),
    enabled: enabled && !!provider,
  });
}

export function useCAImportMutation(provider: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { ca_cert: string; ca_key: string; crl_pem?: string }) =>
      HttpUtil.post<null>(`/api/providers/${encodeURIComponent(provider)}/ca`, input),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ca-info', provider] }),
  });
}
