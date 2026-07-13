import { Alert } from 'antd';
import { useTranslation } from 'react-i18next';
import { useTLSQuery } from '@/api/queries/tls';

// Admin-only (uses the admin-gated GET /api/tls): shown on every admin
// page, not just the "Сертификаты" settings page, when the configured TLS
// mode isn't actually the one serving traffic right now (e.g. ACME renewal
// failed and the permanent self-signed fallback stepped in) -- the whole
// point of that fallback is the connection never drops to plain HTTP, but
// an admin still needs to know something needs fixing.
export function TLSStatusBanner() {
  const { t } = useTranslation('tls-banner');
  const { data } = useTLSQuery();
  if (!data?.status.degraded) return null;
  return (
    <Alert
      type="error"
      showIcon
      banner
      message={t('degraded', { mode: data.status.mode, error: data.status.last_error || t('detailsFallback') })}
      style={{ marginBottom: 16 }}
    />
  );
}
