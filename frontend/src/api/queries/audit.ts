import { useQuery } from '@tanstack/react-query';
import { HttpUtil } from '../http-init';
import type { AuditEntry } from '@/types/api';

export function useAuditQuery() {
  return useQuery({
    queryKey: ['audit'],
    queryFn: () => HttpUtil.get<AuditEntry[]>('/api/audit'),
  });
}
