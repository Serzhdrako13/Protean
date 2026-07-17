import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface ProviderInstall {
  name: string;
  label: string;
  managed: boolean;
  installed: boolean;
  installable: boolean;
  // service_active/config_exists: best-effort signal that the host already
  // looks provisioned for this provider TYPE (checked against the panel's
  // own conventional service unit/config path) -- only meaningful for
  // openvpn/ikev2 today. Used to warn before "Set up" would silently
  // replace an existing CA/config.
  service_active: boolean;
  config_exists: boolean;
}

export interface InstallStatus {
  server_id: string;
  servers: string[];
  host_pretty: string;
  pkg_manager: string;
  systemd: boolean;
  supported: boolean;
  detect_error?: string;
  providers: ProviderInstall[];
}

export function useInstallStatusQuery(server?: string) {
  return useQuery({
    queryKey: ['install', server ?? ''],
    queryFn: () => HttpUtil.get<InstallStatus>(`/api/install${server ? `?server=${encodeURIComponent(server)}` : ''}`),
  });
}

export function useInstallMutation(server?: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (providerType: string) =>
      HttpUtil.post<{ output: string; status: InstallStatus }>(
        `/api/install/${encodeURIComponent(providerType)}${server ? `?server=${encodeURIComponent(server)}` : ''}`,
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['install'] }),
  });
}
