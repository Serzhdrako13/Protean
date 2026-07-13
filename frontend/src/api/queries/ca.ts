import { useMutation } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export function useCAImportMutation(provider: string) {
  return useMutation({
    mutationFn: (input: { ca_cert: string; ca_key: string }) =>
      HttpUtil.post<null>(`/api/providers/${encodeURIComponent(provider)}/ca`, input),
  });
}
