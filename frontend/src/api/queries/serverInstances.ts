import { useMutation, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface ServerInstanceInput {
  local_name: string;
  type: string;
  config?: Record<string, string>;
  label?: string;
}

// No dedicated list query — ServerProvidersPage already gets the registered
// instances via useProvidersQuery() (/api/providers, filtered by server_id);
// this only needs create/delete/relabel.
export function useServerInstanceMutations(serverId: string) {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['providers'] });
  const base = `/api/servers/${encodeURIComponent(serverId)}/instances`;

  const create = useMutation({
    mutationFn: (input: ServerInstanceInput) => HttpUtil.post<ServerInstanceInput>(base, input),
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: (localName: string) => HttpUtil.delete<null>(`${base}/${encodeURIComponent(localName)}`),
    onSuccess: invalidate,
  });
  const relabel = useMutation({
    mutationFn: ({ localName, label }: { localName: string; label: string }) =>
      HttpUtil.put<null>(`${base}/${encodeURIComponent(localName)}`, { label }),
    onSuccess: invalidate,
  });
  const setVisibility = useMutation({
    mutationFn: ({ localName, visible }: { localName: string; visible: boolean }) =>
      HttpUtil.put<null>(`${base}/${encodeURIComponent(localName)}/visibility`, { visible }),
    onSuccess: invalidate,
  });
  const redescribe = useMutation({
    mutationFn: ({ localName, description }: { localName: string; description: string }) =>
      HttpUtil.put<null>(`${base}/${encodeURIComponent(localName)}/description`, { description }),
    onSuccess: invalidate,
  });

  return { create, remove, relabel, setVisibility, redescribe };
}
