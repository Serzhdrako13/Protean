import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';
import type { PanelUser } from '@/types/api';

export function useUsersQuery() {
  return useQuery({
    queryKey: ['users'],
    queryFn: () => HttpUtil.get<PanelUser[]>('/api/users'),
  });
}

export interface UserCreateInput {
  username: string;
  password: string;
  role: 'admin' | 'user';
}

export function useUserMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['users'] });

  const create = useMutation({
    mutationFn: (input: UserCreateInput) => HttpUtil.post<PanelUser>('/api/users', input),
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: (id: number) => HttpUtil.delete<null>(`/api/users/${id}`),
    onSuccess: invalidate,
  });
  const resetPassword = useMutation({
    mutationFn: ({ id, newPassword }: { id: number; newPassword: string }) =>
      HttpUtil.post<null>(`/api/users/${id}/reset-password`, { new_password: newPassword }),
  });
  const setEnabled = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) =>
      HttpUtil.post<null>(`/api/users/${id}/enabled`, { enabled }),
    onSuccess: invalidate,
  });
  const setPortalAccess = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) =>
      HttpUtil.post<null>(`/api/users/${id}/portal-access`, { enabled }),
    onSuccess: invalidate,
  });

  return { create, remove, resetPassword, setEnabled, setPortalAccess };
}

// One provider instance + this user's current state on it -- backs the
// Users page's expandable per-user access panel (grant/revoke directly,
// no need to wait for the user to request it -- backlog item 15).
export interface UserAccessRow {
  provider: string;
  provider_label: string;
  type: string;
  interface: string;
  server_id: string;
  description?: string;
  state: 'granted' | 'approved' | 'pending' | 'denied' | 'none';
}

export function useUserAccessQuery(userId: number, enabled: boolean) {
  return useQuery({
    queryKey: ['user-access', userId],
    queryFn: () => HttpUtil.get<UserAccessRow[]>(`/api/users/${userId}/access`),
    enabled,
  });
}

export function useUserAccessMutations(userId: number) {
  const qc = useQueryClient();
  const setAccess = useMutation({
    mutationFn: ({ provider, enabled }: { provider: string; enabled: boolean }) =>
      HttpUtil.post<null>(`/api/users/${userId}/access/${encodeURIComponent(provider)}`, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['user-access', userId] }),
  });
  return { setAccess };
}

// Only "user"-role accounts can own peers -- used to populate the assignment
// Select on a provider's peer table.
export function usePortalUsersQuery() {
  return useQuery({
    queryKey: ['users'],
    queryFn: () => HttpUtil.get<PanelUser[]>('/api/users'),
    select: (users) => users.filter((u) => u.role === 'user'),
  });
}

export function usePeerOwnerMutation(provider: string) {
  const qc = useQueryClient();
  const base = `/api/providers/${encodeURIComponent(provider)}/peers`;
  return useMutation({
    mutationFn: ({ peerId, userId }: { peerId: string; userId: number }) =>
      HttpUtil.post<null>(`${base}/${encodeURIComponent(peerId)}/owner`, { user_id: userId }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['providers', provider] }),
  });
}
