import { lazy } from 'react';
import { createBrowserRouter } from 'react-router-dom';
import { AuthGate } from '@/components/AuthGate';

// Route-level code splitting: each page is its own chunk, fetched on
// first navigation instead of all being bundled into the one huge SPA
// chunk vite build kept warning about (600-800kB). Named exports need the
// `.then(m => ({ default: m.XPage }))` wrapper since React.lazy only
// understands a default export.
const IndexPage = lazy(() => import('@/pages/index/IndexPage').then((m) => ({ default: m.IndexPage })));
const ServersPage = lazy(() => import('@/pages/servers/ServersPage').then((m) => ({ default: m.ServersPage })));
const ServerProvidersPage = lazy(() => import('@/pages/providers/ServerProvidersPage').then((m) => ({ default: m.ServerProvidersPage })));
const ProviderDetailPage = lazy(() => import('@/pages/providers/ProviderDetailPage').then((m) => ({ default: m.ProviderDetailPage })));
const InstallPage = lazy(() => import('@/pages/install/InstallPage').then((m) => ({ default: m.InstallPage })));
const NodesPage = lazy(() => import('@/pages/nodes/NodesPage').then((m) => ({ default: m.NodesPage })));
const SubnetsPage = lazy(() => import('@/pages/subnets/SubnetsPage').then((m) => ({ default: m.SubnetsPage })));
const NotificationsPage = lazy(() => import('@/pages/notifications/NotificationsPage').then((m) => ({ default: m.NotificationsPage })));
const AuditPage = lazy(() => import('@/pages/audit/AuditPage').then((m) => ({ default: m.AuditPage })));
const AccountPage = lazy(() => import('@/pages/account/AccountPage').then((m) => ({ default: m.AccountPage })));
const HelpPage = lazy(() => import('@/pages/help/HelpPage').then((m) => ({ default: m.HelpPage })));
const UsersPage = lazy(() => import('@/pages/users/UsersPage').then((m) => ({ default: m.UsersPage })));
const AccessRequestsPage = lazy(() => import('@/pages/access-requests/AccessRequestsPage').then((m) => ({ default: m.AccessRequestsPage })));
const AdminPortalPage = lazy(() => import('@/pages/admin-portal/AdminPortalPage').then((m) => ({ default: m.AdminPortalPage })));
const TLSPage = lazy(() => import('@/pages/tls/TLSPage').then((m) => ({ default: m.TLSPage })));
const LoginSecurityPage = lazy(() => import('@/pages/login-security/LoginSecurityPage').then((m) => ({ default: m.LoginSecurityPage })));
const AuthMethodsPage = lazy(() => import('@/pages/auth-methods/AuthMethodsPage').then((m) => ({ default: m.AuthMethodsPage })));
const DataRetentionPage = lazy(() => import('@/pages/data-retention/DataRetentionPage').then((m) => ({ default: m.DataRetentionPage })));
const ConnectionHistoryPage = lazy(() => import('@/pages/connection-history/ConnectionHistoryPage').then((m) => ({ default: m.ConnectionHistoryPage })));
const NotFoundPage = lazy(() => import('@/pages/not-found/NotFoundPage').then((m) => ({ default: m.NotFoundPage })));

export const router = createBrowserRouter([
  {
    // Every route below waits on AuthGate's session probe before rendering
    // anything -- see that component for why (prevents a flash of the
    // admin shell before an unauthenticated/portal-role session redirects
    // away). AuthGate also wraps its <Outlet/> in the one <Suspense/>
    // boundary these lazy chunks need.
    element: <AuthGate />,
    children: [
      { path: '/', element: <IndexPage /> },
      { path: '/servers', element: <ServersPage /> },
      { path: '/servers/:id/providers', element: <ServerProvidersPage /> },
      { path: '/providers/:provider', element: <ProviderDetailPage /> },
      { path: '/install', element: <InstallPage /> },
      { path: '/nodes', element: <NodesPage /> },
      { path: '/subnets', element: <SubnetsPage /> },
      { path: '/notifications', element: <NotificationsPage /> },
      { path: '/audit', element: <AuditPage /> },
      { path: '/users', element: <UsersPage /> },
      { path: '/access-requests', element: <AccessRequestsPage /> },
      { path: '/admin-portal', element: <AdminPortalPage /> },
      { path: '/tls', element: <TLSPage /> },
      { path: '/login-security', element: <LoginSecurityPage /> },
      { path: '/auth-methods', element: <AuthMethodsPage /> },
      { path: '/data-retention', element: <DataRetentionPage /> },
      { path: '/connection-history', element: <ConnectionHistoryPage /> },
      { path: '/account', element: <AccountPage /> },
      { path: '/help', element: <HelpPage /> },
      // Catches any path the admin SPA is asked to render that isn't one of
      // the above -- notably /login and /portal reaching this router at all
      // (they're meant to be server-side-only entries, see
      // internal/api/server.go) if a trailing-slash variant or similar ever
      // bypasses the exact-match server route. Without this, react-router's
      // data router shows its own bare developer-facing "Unexpected
      // Application Error! 404" screen instead.
      { path: '*', element: <NotFoundPage /> },
    ],
  },
]);
