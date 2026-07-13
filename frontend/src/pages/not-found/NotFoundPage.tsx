import { Button, Result } from 'antd';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';

// Rendered for any path the admin SPA's router doesn't recognize (see the
// wildcard route in routes.tsx) -- notably /login and /portal reaching this
// router at all (they're meant to be server-side-only entries, see
// internal/api/server.go) if a trailing-slash variant or similar ever
// bypasses the exact-match server route. Without this, react-router's data
// router shows its own bare developer-facing "Unexpected Application Error!
// 404" screen instead.
export function NotFoundPage() {
  const { t } = useTranslation('common');
  const navigate = useNavigate();

  return (
    <PageShell>
      <Result
        status="404"
        title="404"
        subTitle={t('notFound.subtitle')}
        extra={
          <Button type="primary" onClick={() => navigate('/')}>
            {t('notFound.backHome')}
          </Button>
        }
      />
    </PageShell>
  );
}
