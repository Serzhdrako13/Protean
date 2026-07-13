import { useEffect, useState } from 'react';
import { Alert } from 'antd';
import { useTranslation } from 'react-i18next';
import { getConnInfo } from '@/api/http-init';

// Rendered at the top of every app root (admin SPA, login, self-service
// portal) -- shows even to a not-yet-authenticated visitor, since "you're
// about to type your password over plain HTTP" is exactly when this matters
// most. Never blocks anything (see the admin's "принудительный HTTPS"
// design note: only the mode itself can prevent plain HTTP, this is just a
// visibility signal for whichever mode allows it, i.e. "proxy" mode).
export function InsecureConnectionBanner() {
  const { t } = useTranslation('insecure-banner');
  const [insecure, setInsecure] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getConnInfo().then((info) => {
      if (!cancelled) setInsecure(!info.https);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!insecure) return null;
  return (
    <Alert
      type="warning"
      showIcon
      banner
      message={t('message')}
      style={{ marginBottom: 16 }}
    />
  );
}
