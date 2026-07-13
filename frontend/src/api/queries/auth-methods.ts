import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';

export interface InternalAuthSettings {
  enabled: boolean;
}

export interface LDAPSettings {
  enabled: boolean;
  url: string;
  skip_tls_verify: boolean;
  bind_dn: string;
  bind_password_set: boolean;
  user_base_dn: string;
  user_filter: string;
  group_base_dn: string;
}

export interface LDAPSettingsInput {
  enabled: boolean;
  url: string;
  skip_tls_verify: boolean;
  bind_dn: string;
  bind_password?: string;
  user_base_dn: string;
  user_filter: string;
  group_base_dn: string;
}

export interface OIDCSettings {
  enabled: boolean;
  issuer_url: string;
  client_id: string;
  client_secret_set: boolean;
  scopes: string;
  username_claim: string;
  groups_claim: string;
  redirect_base_url: string;
  callback_path: string;
}

export interface OIDCSettingsInput {
  enabled: boolean;
  issuer_url: string;
  client_id: string;
  client_secret?: string;
  scopes: string;
  username_claim: string;
  groups_claim: string;
  redirect_base_url: string;
}

export interface AuthGroupRule {
  method: 'ldap' | 'oidc';
  role: 'admin' | 'user';
  group_value: string;
}

export function useAuthMethodsEnabledQuery() {
  return useQuery({
    queryKey: ['auth-methods-enabled'],
    queryFn: () => HttpUtil.get<{ internal: boolean; ldap: boolean; oidc: boolean }>('/api/auth-methods/enabled'),
  });
}

export function useInternalAuthQuery() {
  return useQuery({
    queryKey: ['auth-methods-internal'],
    queryFn: () => HttpUtil.get<InternalAuthSettings>('/api/auth-methods/internal'),
  });
}

export function useLDAPSettingsQuery() {
  return useQuery({
    queryKey: ['auth-methods-ldap'],
    queryFn: () => HttpUtil.get<LDAPSettings>('/api/auth-methods/ldap'),
  });
}

export function useOIDCSettingsQuery() {
  return useQuery({
    queryKey: ['auth-methods-oidc'],
    queryFn: () => HttpUtil.get<OIDCSettings>('/api/auth-methods/oidc'),
  });
}

export function useAuthGroupRulesQuery(method: 'ldap' | 'oidc') {
  return useQuery({
    queryKey: ['auth-group-rules', method],
    queryFn: () => HttpUtil.get<AuthGroupRule[]>(`/api/auth-methods/groups?method=${method}`),
  });
}

export function useAuthMethodsMutations() {
  const qc = useQueryClient();
  const invalidateEnabled = () => qc.invalidateQueries({ queryKey: ['auth-methods-enabled'] });

  const updateInternal = useMutation({
    mutationFn: (input: InternalAuthSettings) => HttpUtil.put<null>('/api/auth-methods/internal', input),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['auth-methods-internal'] });
      invalidateEnabled();
    },
  });
  const updateLDAP = useMutation({
    mutationFn: (input: LDAPSettingsInput) => HttpUtil.put<null>('/api/auth-methods/ldap', input),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['auth-methods-ldap'] });
      invalidateEnabled();
    },
  });
  const testLDAP = useMutation({
    mutationFn: (input: LDAPSettingsInput) => HttpUtil.post<null>('/api/auth-methods/ldap/test', input),
  });
  const updateOIDC = useMutation({
    mutationFn: (input: OIDCSettingsInput) => HttpUtil.put<null>('/api/auth-methods/oidc', input),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['auth-methods-oidc'] });
      invalidateEnabled();
    },
  });
  const testOIDC = useMutation({
    mutationFn: (input: { issuer_url: string }) => HttpUtil.post<null>('/api/auth-methods/oidc/test', input),
  });
  const addGroupRule = useMutation({
    mutationFn: (input: AuthGroupRule) => HttpUtil.post<null>('/api/auth-methods/groups', input),
    onSuccess: (_data, vars) => qc.invalidateQueries({ queryKey: ['auth-group-rules', vars.method] }),
  });
  const deleteGroupRule = useMutation({
    mutationFn: (input: AuthGroupRule) =>
      HttpUtil.delete<null>(
        `/api/auth-methods/groups?method=${input.method}&role=${input.role}&group_value=${encodeURIComponent(input.group_value)}`,
      ),
    onSuccess: (_data, vars) => qc.invalidateQueries({ queryKey: ['auth-group-rules', vars.method] }),
  });

  return { updateInternal, updateLDAP, testLDAP, updateOIDC, testOIDC, addGroupRule, deleteGroupRule };
}
