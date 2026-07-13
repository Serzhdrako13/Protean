import { useEffect, useState } from 'react';
import { Form, Input, Button, Alert, Segmented } from 'antd';
import { LockOutlined, UserOutlined, SafetyOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { HttpUtil, ApiError } from '@/api/http-init';

interface LoginResult {
  need_totp: boolean;
  pending?: string;
}

interface EnabledMethods {
  internal: boolean;
  ldap: boolean;
  oidc: boolean;
}

type Method = 'local' | 'ldap' | 'oidc';

const METHOD_COOKIE = 'protean_login_method';

function readMethodCookie(): string | null {
  const m = document.cookie.match(/(?:^|; )protean_login_method=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}

function writeMethodCookie(method: Method) {
  document.cookie = `${METHOD_COOKIE}=${encodeURIComponent(method)}; path=/; max-age=31536000; SameSite=Lax`;
}

// Shared by the admin login page and the portal's login screen -- both used
// to be near-identical copies of the same username/password/TOTP form.
// Fetches which login methods are currently enabled and renders: a plain
// form if only "local" is on (today's behavior, unchanged), just an SSO
// button if only "oidc" is on, or a method selector above the fields when
// more than one is enabled -- the choice is remembered in a cookie so it's
// preselected on the next visit.
export function LoginForm({ i18nNamespace, onLoggedIn }: { i18nNamespace: string; onLoggedIn: () => void }) {
  const { t } = useTranslation([i18nNamespace, 'common']);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [pending, setPending] = useState<string | null>(null);
  const [enabled, setEnabled] = useState<EnabledMethods | null>(null);
  const [method, setMethod] = useState<Method>('local');
  const [form] = Form.useForm();

  useEffect(() => {
    if (new URLSearchParams(window.location.search).get('oidc_error')) {
      setError(t(`${i18nNamespace}:loginForm.oidcError`));
    }
    HttpUtil.get<EnabledMethods>('/api/auth-methods/enabled')
      .then((res) => {
        setEnabled(res);
        const available: Method[] = [
          ...(res.internal ? (['local'] as Method[]) : []),
          ...(res.ldap ? (['ldap'] as Method[]) : []),
          ...(res.oidc ? (['oidc'] as Method[]) : []),
        ];
        const saved = readMethodCookie() as Method | null;
        if (saved && available.includes(saved)) {
          setMethod(saved);
        } else if (available.length > 0) {
          setMethod(available[0]);
        }
      })
      .catch(() => setEnabled({ internal: true, ldap: false, oidc: false }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function selectMethod(m: Method) {
    setMethod(m);
    writeMethodCookie(m);
  }

  async function onFinish(values: { username: string; password: string; code?: string }) {
    setError('');
    setLoading(true);
    try {
      if (pending) {
        await HttpUtil.post('/api/login/2fa', { pending, code: values.code });
      } else {
        const res = await HttpUtil.post<LoginResult>('/api/login', {
          username: values.username,
          password: values.password,
          method: method === 'ldap' ? 'ldap' : undefined,
        });
        if (res.need_totp) {
          setPending(res.pending ?? null);
          setLoading(false);
          return;
        }
      }
      onLoggedIn();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t(`${i18nNamespace}:loginForm.loginError`));
      setLoading(false);
    }
  }

  if (!enabled) return null;

  const availableCount = [enabled.internal, enabled.ldap, enabled.oidc].filter(Boolean).length;
  const methodOptions = [
    ...(enabled.internal ? [{ label: t(`${i18nNamespace}:loginForm.methodLocal`), value: 'local' as Method }] : []),
    ...(enabled.ldap ? [{ label: t(`${i18nNamespace}:loginForm.methodLdap`), value: 'ldap' as Method }] : []),
    ...(enabled.oidc ? [{ label: t(`${i18nNamespace}:loginForm.methodOidc`), value: 'oidc' as Method }] : []),
  ];

  return (
    <>
      {availableCount > 1 && (
        <Segmented
          block
          options={methodOptions}
          value={method}
          onChange={(v) => selectMethod(v as Method)}
          style={{ marginBottom: 16 }}
        />
      )}
      {error && <Alert type="error" message={error} showIcon style={{ marginBottom: 16 }} />}
      {method === 'oidc' ? (
        <Button
          type="primary"
          block
          onClick={() => {
            window.location.href = '/api/auth/oidc/start';
          }}
        >
          {t(`${i18nNamespace}:loginForm.oidcButton`)}
        </Button>
      ) : (
        <Form form={form} layout="vertical" onFinish={onFinish} disabled={loading}>
          {!pending && (
            <>
              <Form.Item name="username" rules={[{ required: true, message: t(`${i18nNamespace}:loginForm.usernameRequired`) }]}>
                <Input prefix={<UserOutlined />} placeholder={t(`${i18nNamespace}:loginForm.usernamePlaceholder`)} autoFocus />
              </Form.Item>
              <Form.Item name="password" rules={[{ required: true, message: t(`${i18nNamespace}:loginForm.passwordRequired`) }]}>
                <Input.Password prefix={<LockOutlined />} placeholder={t(`${i18nNamespace}:loginForm.passwordPlaceholder`)} />
              </Form.Item>
            </>
          )}
          {pending && (
            <Form.Item name="code" rules={[{ required: true, message: t(`${i18nNamespace}:loginForm.totpRequired`) }]}>
              <Input prefix={<SafetyOutlined />} placeholder={t(`${i18nNamespace}:loginForm.totpPlaceholder`)} autoFocus />
            </Form.Item>
          )}
          <Form.Item>
            <Button type="primary" htmlType="submit" block loading={loading}>
              {pending ? t('common:actions.confirm') : t('common:actions.login')}
            </Button>
          </Form.Item>
        </Form>
      )}
    </>
  );
}
