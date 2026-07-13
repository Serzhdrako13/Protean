import { useQuery } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface AdminPortalPeer {
  username: string;
  peer_key: string;
  name: string;
  online: boolean;
}

export interface AdminPortalInstance {
  provider: string;
  server_id: string;
  provider_label: string;
  portal_visible: boolean;
  peers: AdminPortalPeer[];
}

export function useAdminPortalQuery() {
  return useQuery({
    queryKey: ['admin-portal'],
    queryFn: () => HttpUtil.get<AdminPortalInstance[]>('/api/admin-portal'),
  });
}
