import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@/i18n';
import { setUnauthorizedRedirect } from '@/api/http-init';
import { ThemeProvider } from '@/hooks/useTheme';
import { PortalApp } from '@/pages/portal/PortalApp';

// A role=="user" session is confined server-side to /api/portal/*,
// /api/account* and /api/logout (see requireAuthAPI's role gate) -- an
// expired session here must bounce back to this same entry, not the admin
// login.
setUnauthorizedRedirect('/portal');

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider>
      <PortalApp />
    </ThemeProvider>
  </StrictMode>,
);
