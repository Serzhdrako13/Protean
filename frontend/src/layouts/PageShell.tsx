import type { ReactNode } from 'react';
import { ConfigProvider, Layout } from 'antd';
import { useTheme } from '@/hooks/useTheme';
import { useLang } from '@/hooks/useLang';
import { AppSidebar } from './AppSidebar';
import { InsecureConnectionBanner } from '@/components/InsecureConnectionBanner';
import { TLSStatusBanner } from '@/components/TLSStatusBanner';

// Each top-level page wraps itself in this shell — same composition 3x-ui
// uses per-page (ConfigProvider > Layout > Sider + Content) rather than one
// shared layout route, so a page can render standalone (e.g. inside a modal
// preview) without dragging in a router-level wrapper.
export function PageShell({ children }: { children: ReactNode }) {
  const { antdThemeConfig } = useTheme();
  const { antdLocale } = useLang();
  return (
    <ConfigProvider theme={antdThemeConfig} locale={antdLocale}>
      <Layout style={{ minHeight: '100vh' }}>
        <AppSidebar />
        <Layout>
          <Layout.Content style={{ padding: '24px 28px', maxWidth: 1400, width: '100%', margin: '0 auto' }}>
            <InsecureConnectionBanner />
            <TLSStatusBanner />
            {children}
          </Layout.Content>
        </Layout>
      </Layout>
    </ConfigProvider>
  );
}
