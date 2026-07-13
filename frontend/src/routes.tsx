import { createBrowserRouter } from 'react-router-dom';
import { AuthGate } from '@/components/AuthGate';
import { IndexPage } from '@/pages/index/IndexPage';
import { ServersPage } from '@/pages/servers/ServersPage';
import { ServerProvidersPage } from '@/pages/providers/ServerProvidersPage';
import { ProviderDetailPage } from '@/pages/providers/ProviderDetailPage';
import { InstallPage } from '@/pages/install/InstallPage';
import { NodesPage } from '@/pages/nodes/NodesPage';
import { SubnetsPage } from '@/pages/subnets/SubnetsPage';
import { NotificationsPage } from '@/pages/notifications/NotificationsPage';
import { AuditPage } from '@/pages/audit/AuditPage';
import { AccountPage } from '@/pages/account/AccountPage';
import { HelpPage } from '@/pages/help/HelpPage';
import { UsersPage } from '@/pages/users/UsersPage';
import { AccessRequestsPage } from '@/pages/access-requests/AccessRequestsPage';
import { AdminPortalPage } from '@/pages/admin-portal/AdminPortalPage';
import { TLSPage } from '@/pages/tls/TLSPage';
import { LoginSecurityPage } from '@/pages/login-security/LoginSecurityPage';
import { AuthMethodsPage } from '@/pages/auth-methods/AuthMethodsPage';
import { DataRetentionPage } from '@/pages/data-retention/DataRetentionPage';
import { ConnectionHistoryPage } from '@/pages/connection-history/ConnectionHistoryPage';
import { NotFoundPage } from '@/pages/not-found/NotFoundPage';

export const router = createBrowserRouter([
  {
    // Every route below waits on AuthGate's session probe before rendering
    // anything -- see that component for why (prevents a flash of the
    // admin shell before an unauthenticated/portal-role session redirects
    // away).
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
