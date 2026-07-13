// Thin fetch wrapper matching the Go backend's /api envelope
// ({success, msg, obj}) and its cookie-session + double-submit-CSRF scheme
// (see internal/auth/csrf.go). Same shape as 3x-ui's http-init.ts, minus the
// base-path-prefix machinery (this panel isn't served behind a
// configurable sub-path).

import { getLang } from '@/i18n';

export class ApiError extends Error {
  status: number;
  // obj: the envelope's payload even on success:false (e.g. install output
  // alongside a failure message) — most callers ignore it.
  obj?: unknown;
  constructor(message: string, status: number, obj?: unknown) {
    super(message);
    this.status = status;
    this.obj = obj;
  }
}

interface Envelope<T> {
  success: boolean;
  msg?: string;
  obj?: T;
}

// Where an expired/missing session redirects to — '/login' for the admin
// SPA, '/portal' for the self-service portal entry (each entry's bootstrap
// calls setUnauthorizedRedirect once, before rendering). Must match a real
// server route (internal/api/server.go's Routes()) exactly -- an
// unregistered path (e.g. the old '/login.html'/'.html'-suffixed values)
// falls through to the SPA catch-all, which re-serves the admin bundle and
// immediately re-triggers this same redirect: an infinite loop that never
// reaches an actual login form.
let unauthorizedRedirectPath = '/login';
export function setUnauthorizedRedirect(path: string): void {
  unauthorizedRedirectPath = path;
}

let csrfToken: string | null = null;

// connInfo.https reflects whether THIS request reached the panel encrypted
// (see internal/api's isSecure) -- optimistic `true` default before the
// first /api/csrf round-trip resolves, so the banner doesn't flash on a
// perfectly fine HTTPS connection while loading.
export interface ConnInfo { https: boolean }
let connInfo: ConnInfo = { https: true };

async function fetchCSRFToken(): Promise<string> {
  const res = await fetch('/api/csrf', { credentials: 'same-origin' });
  const env = (await res.json()) as Envelope<{ csrf_token: string; https: boolean }>;
  const token = env.obj?.csrf_token ?? '';
  csrfToken = token;
  connInfo = { https: env.obj?.https ?? true };
  return token;
}

async function ensureCSRFToken(): Promise<string> {
  if (csrfToken) return csrfToken;
  return fetchCSRFToken();
}

// getConnInfo primes/reuses the same CSRF fetch (no extra round-trip) and
// returns the connection-security flag for the insecure-connection banner.
export async function getConnInfo(): Promise<ConnInfo> {
  await ensureCSRFToken();
  return connInfo;
}

function isUnsafe(method: string): boolean {
  return method !== 'GET' && method !== 'HEAD';
}

export async function httpRequest<T>(method: string, url: string, body?: unknown): Promise<T> {
  // Backend-generated strings (writeErr/writeOKMsg messages) match whatever
  // language the UI is currently set to -- see internal/api/i18n.go's
  // requestLang, which reads this same header.
  const headers: Record<string, string> = { 'Accept-Language': getLang() };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (isUnsafe(method)) headers['X-CSRF-Token'] = await ensureCSRFToken();

  let res = await fetch(url, {
    method,
    credentials: 'same-origin',
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  // A stale/missing CSRF token: refetch once and retry (mirrors 3x-ui's
  // one-shot 403 retry).
  if (res.status === 403 && isUnsafe(method)) {
    csrfToken = null;
    headers['X-CSRF-Token'] = await ensureCSRFToken();
    res = await fetch(url, {
      method,
      credentials: 'same-origin',
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  }

  // A role=="user" (portal-only) session that reached an admin-only route:
  // the backend 403s and flags it so we bounce to the portal instead of
  // showing a bare "forbidden" error (only ever fires from the admin SPA —
  // the portal entry never calls admin-only routes).
  if (res.headers.get('X-Portal-Redirect')) {
    window.location.href = '/portal';
    return new Promise<T>(() => {});
  }

  // The account's password is past its configured max age (see
  // internal/api/api_common.go's requireAuthAPI) -- every route except
  // /api/account and /api/logout (and, for a portal session, /api/portal/*)
  // 403s with this header until it's changed. The admin SPA has a dedicated
  // /account route to land on; the portal SPA is one page and instead
  // surfaces this via GET /api/portal/me's own password_expired field (its
  // own session probe stays reachable, see the prefix reuse note above), so
  // this redirect only fires for the admin bundle in practice.
  if (res.headers.get('X-Password-Expired')) {
    window.location.href = '/account';
    return new Promise<T>(() => {});
  }

  // The login endpoints themselves return 401 for a plain "wrong username/
  // password/code" -- NOT an expired session -- so they must be excluded
  // from the auto-redirect below, or the caller's catch block (which would
  // show that error to the user) never runs: the redirect fires first,
  // returns a promise that never resolves, and the login form just silently
  // reloads with no feedback at all (a real bug this comment is here to
  // prevent regressing back into).
  const isLoginEndpoint = url === '/api/login' || url === '/api/login/2fa';
  if (res.status === 401 && !isLoginEndpoint) {
    // Session expired/absent: bounce to the login page. The thrown error
    // never resolves into a caller that would render stale UI on top of it.
    window.location.href = unauthorizedRedirectPath;
    return new Promise<T>(() => {});
  }

  const env = (await res.json().catch(() => ({ success: false, msg: 'invalid response' }))) as Envelope<T>;
  if (!env.success) {
    throw new ApiError(env.msg || `request failed (${res.status})`, res.status, env.obj);
  }
  return env.obj as T;
}

export const HttpUtil = {
  get: <T>(url: string) => httpRequest<T>('GET', url),
  post: <T>(url: string, body?: unknown) => httpRequest<T>('POST', url, body ?? {}),
  put: <T>(url: string, body?: unknown) => httpRequest<T>('PUT', url, body ?? {}),
  delete: <T>(url: string) => httpRequest<T>('DELETE', url),
};
