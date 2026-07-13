import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';
import type { ServerRow } from '@/types/api';

export function useServersQuery() {
  return useQuery({
    queryKey: ['servers'],
    queryFn: () => HttpUtil.get<ServerRow[]>('/api/servers'),
  });
}

export interface ServerCreateInput {
  id: string;
  label: string;
  host: string;
  port: number;
  ssh_user: string;
  public_host: string;
  host_key: string;
  // Existing-key path: paste a private key for an account that's already
  // fully set up on the host as-is.
  ssh_key: string;
  // Bootstrap path: connect once as bootstrap_user ("root" or an existing
  // sudo user) via bootstrap_password or bootstrap_key (exactly one) to
  // create-or-reuse ssh_user and grant it narrow rights.
  bootstrap_user: string;
  bootstrap_password: string;
  bootstrap_key: string;
}

export type ServerUpdateInput = Omit<ServerCreateInput, 'id' | 'bootstrap_user' | 'bootstrap_password' | 'bootstrap_key'>;

export function useServerMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['servers'] });

  const create = useMutation({
    mutationFn: (input: ServerCreateInput) => HttpUtil.post<ServerRow>('/api/servers', input),
    onSuccess: invalidate,
  });
  const update = useMutation({
    mutationFn: ({ id, ...input }: ServerUpdateInput & { id: string }) =>
      HttpUtil.put<ServerRow>(`/api/servers/${encodeURIComponent(id)}`, input),
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: (id: string) => HttpUtil.delete<null>(`/api/servers/${encodeURIComponent(id)}`),
    onSuccess: invalidate,
  });
  const setEnabled = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      HttpUtil.post<null>(`/api/servers/${encodeURIComponent(id)}/enabled`, { enabled }),
    onSuccess: invalidate,
  });

  return { create, update, remove, setEnabled };
}

export interface ProbeHostKeyResult {
  authorized_key: string;
  fingerprint: string;
}

// Fetches the SSH host key currently presented by a host, so it can be
// pinned without running ssh-keyscan by hand. Host/port only -- no server
// id needed, works from the create form too.
export function useProbeHostKeyMutation() {
  return useMutation({
    mutationFn: (input: { host: string; port: number }) =>
      HttpUtil.post<ProbeHostKeyResult>('/api/ssh/probe-host-key', input),
  });
}
