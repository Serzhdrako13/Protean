import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface TLSSettings {
  mode: 'self_signed' | 'acme' | 'manual' | 'proxy';

  ss_key_algo: 'rsa_2048' | 'rsa_4096' | 'ecdsa_p256' | 'ecdsa_p384';
  ss_validity_days: number;
  ss_renew_before_days: number;
  ss_sans: string;

  acme_directory_url: string;
  acme_domains: string;
  acme_email: string;
  acme_challenge: 'tls-alpn-01' | 'http-01';
  acme_trust_root_pem?: string;

  manual_cert_pem?: string;
  manual_key_pem?: string;
  manual_has_key: boolean;
}

export interface TLSStatus {
  mode: string;
  self_signed_expires_at?: string;
  last_served: string;
  last_error?: string;
  degraded: boolean;
}

export interface TLSResponse {
  settings: TLSSettings;
  status: TLSStatus;
}

export function useTLSQuery() {
  return useQuery({
    queryKey: ['tls'],
    queryFn: () => HttpUtil.get<TLSResponse>('/api/tls'),
    refetchInterval: 30_000,
  });
}

export function useTLSMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['tls'] });

  const update = useMutation({
    mutationFn: (input: TLSSettings) => HttpUtil.put<null>('/api/tls', input),
    onSuccess: invalidate,
  });
  const reissueSelfSigned = useMutation({
    mutationFn: () => HttpUtil.post<null>('/api/tls/self-signed/reissue'),
    onSuccess: invalidate,
  });

  return { update, reissueSelfSigned };
}
