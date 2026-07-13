import { ConfigProvider, Layout, Card } from 'antd';
import { useTheme } from '@/hooks/useTheme';
import { useLang } from '@/hooks/useLang';
import { InsecureConnectionBanner } from '@/components/InsecureConnectionBanner';
import { ProteanBrand } from '@/components/ProteanBrand';
import { LoginForm } from '@/components/LoginForm';

export function LoginPage() {
  const { antdThemeConfig } = useTheme();
  const { antdLocale } = useLang();

  return (
    <ConfigProvider theme={antdThemeConfig} locale={antdLocale}>
      <Layout style={{ minHeight: '100vh', alignItems: 'center', justifyContent: 'center' }}>
        <Card style={{ width: 360 }}>
          <div style={{ textAlign: 'center', marginBottom: 20 }}>
            <ProteanBrand size="xl" />
          </div>
          <InsecureConnectionBanner />
          <LoginForm i18nNamespace="login" onLoggedIn={() => { window.location.href = '/'; }} />
        </Card>
      </Layout>
    </ConfigProvider>
  );
}
