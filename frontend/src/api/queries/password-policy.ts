import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';
import type { PasswordPolicySettings } from '@/types/passwordPolicy';

export type { PasswordPolicySettings };

export function usePasswordPolicyQuery() {
  return useQuery({
    queryKey: ['password-policy'],
    queryFn: () => HttpUtil.get<PasswordPolicySettings>('/api/password-policy/settings'),
  });
}

export function usePasswordPolicyMutations() {
  const qc = useQueryClient();
  const update = useMutation({
    mutationFn: (input: PasswordPolicySettings) => HttpUtil.put<null>('/api/password-policy/settings', input),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['password-policy'] }),
  });
  return { update };
}
