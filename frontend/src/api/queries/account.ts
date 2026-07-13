import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';
import type { Account } from '@/types/api';

export function useAccountQuery() {
  return useQuery({
    queryKey: ['account'],
    queryFn: () => HttpUtil.get<Account>('/api/account'),
  });
}

export function useLogoutMutation() {
  return useMutation({
    mutationFn: () => HttpUtil.post<null>('/api/logout'),
    onSuccess: () => {
      window.location.href = '/login';
    },
  });
}

export function useChangePasswordMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { current_password: string; new_password: string }) =>
      HttpUtil.post<null>('/api/account', input),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['account'] }),
  });
}

export function useTOTPSetupMutation() {
  return useMutation({
    mutationFn: () => HttpUtil.post<{ secret: string; qr_png: string }>('/api/account/2fa/setup'),
  });
}

export function useTOTPEnableMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { secret: string; code: string }) => HttpUtil.post<null>('/api/account/2fa/enable', input),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['account'] }),
  });
}

export function useTOTPDisableMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { password: string }) => HttpUtil.post<null>('/api/account/2fa/disable', input),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['account'] }),
  });
}

// Persists the UI language choice to the account so it follows the user
// across devices/browsers instead of resetting on every new machine
// (previously localStorage-only). Fire-and-forget from the caller's point
// of view -- the local i18n switch already happened via setLang/toggleLang
// before this is called, so a network hiccup here doesn't block the UI.
export function useSetLanguageMutation() {
  return useMutation({
    mutationFn: (language: string) => HttpUtil.put<null>('/api/account/language', { language }),
  });
}
