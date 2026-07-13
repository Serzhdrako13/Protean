import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@/i18n';
import { ThemeProvider } from '@/hooks/useTheme';
import { LoginPage } from '@/pages/login/LoginPage';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider>
      <LoginPage />
    </ThemeProvider>
  </StrictMode>,
);
