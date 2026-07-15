import { Suspense, useEffect, useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Spin } from 'antd';
import { HttpUtil } from '@/api/http-init';

// Renders nothing until a lightweight session probe resolves, then renders
// the actual routed page. Without this, every admin route mounted its full
// UI (sidebar, dashboard skeleton) immediately on load, THEN redirected to
// /login or /portal only once the first API call's response came back --
// visibly flashing the admin shell first, worst of all for a portal-role
// user briefly seeing the admin nav before being bounced away. PortalApp.tsx
// already had the equivalent gate (its `checked` state); this is the same
// pattern for the admin SPA's router, which never got one.
//
// Probes /api/servers, not /api/account: account is reachable by BOTH
// roles (it's in portalRoleAllowedPrefixes), so it would report success for
// a portal-role session too and defeat the whole point here -- /api/servers
// is admin-only, so a portal-role session correctly gets the 403 +
// X-Portal-Redirect (and bounces to /portal) before anything renders.
// http-init's own interceptor already handles that redirect (and the plain
// 401-to-/login case) and never resolves the promise when it fires -- so
// this component doesn't need to duplicate that logic, just wait for a
// genuine 200 before rendering anything.
export function AuthGate() {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    HttpUtil.get('/api/servers')
      .then(() => setReady(true))
      .catch(() => setReady(true)); // some other error: let the route render and handle it itself, rather than staying blank forever
  }, []);

  if (!ready) return null;
  return (
    <Suspense fallback={<div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin size="large" /></div>}>
      <Outlet />
    </Suspense>
  );
}
