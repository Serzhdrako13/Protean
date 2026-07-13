import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface ProviderInstall {
  name: string;
  label: string;
  managed: boolean;
  installed: boolean;
  installable: boolean;
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
