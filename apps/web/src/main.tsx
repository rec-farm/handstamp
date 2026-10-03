import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { createBrowserRouter, RouterProvider } from 'react-router';
import '@fontsource-variable/archivo/wdth.css';
import '@fontsource-variable/figtree/wght.css';
import '@fontsource-variable/geist-mono/wght.css';
import './styles.css';
import { serverView } from './api.ts';
import { Interaction } from './pages/Interaction.tsx';
import { ErrorView, Logout, SignedOut } from './pages/ServerViews.tsx';
import { CardPage, Title } from './components/ui.tsx';
import { Account } from './pages/Account.tsx';
import { Root, Setup } from './pages/Root.tsx';
import { EnrollLink } from './pages/Enroll.tsx';
import { AdminOverview } from './pages/admin/Overview.tsx';
import { AdminUsers } from './pages/admin/Users.tsx';
import { AdminUser } from './pages/admin/User.tsx';
import { AdminGroup, AdminGroups } from './pages/admin/Groups.tsx';
import { AdminApp, AdminApps, AdminNewApp } from './pages/admin/Apps.tsx';
import { AdminProviders } from './pages/admin/Providers.tsx';
import { AdminKeys } from './pages/admin/Keys.tsx';
import { AdminAudit } from './pages/admin/Audit.tsx';

function NotFound() {
  return (
    <CardPage>
      <Title>Nothing here</Title>
      <p className="mt-3 text-body text-fg-muted">
        Check the address, or go back to the app you came from.
      </p>
    </CardPage>
  );
}

// Views rendered for oidc-provider (logout, errors) take priority over the URL.
function ServerView({ view, data }: NonNullable<ReturnType<typeof serverView>>) {
  if (view === 'logout')
    return <Logout xsrf={data.xsrf ?? ''} action={data.action ?? ''} client={data.client ?? ''} />;
  if (view === 'signed-out') return <SignedOut client={data.client ?? ''} />;
  return <ErrorView code={data.code ?? 'server_error'} />;
}

const router = createBrowserRouter([
  { path: '/', element: <Root /> },
  { path: '/setup', element: <Setup /> },
  { path: '/account', element: <Account /> },
  { path: '/enroll', element: <EnrollLink /> },
  { path: '/admin', element: <AdminOverview /> },
  { path: '/admin/users', element: <AdminUsers /> },
  { path: '/admin/users/:id', element: <AdminUser /> },
  { path: '/admin/groups', element: <AdminGroups /> },
  { path: '/admin/groups/:id', element: <AdminGroup /> },
  { path: '/admin/apps', element: <AdminApps /> },
  { path: '/admin/apps/new', element: <AdminNewApp /> },
  { path: '/admin/apps/:id', element: <AdminApp /> },
  { path: '/admin/providers', element: <AdminProviders /> },
  { path: '/admin/keys', element: <AdminKeys /> },
  { path: '/admin/audit', element: <AdminAudit /> },
  { path: '/signed-out', element: <SignedOut client="" /> },
  { path: '/interaction/:uid', element: <Interaction /> },
  {
    path: '/error',
    element: <ErrorView code={new URLSearchParams(location.search).get('code') ?? ''} />,
  },
  { path: '*', element: <NotFound /> },
]);

const fromServer = serverView();
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {fromServer ? <ServerView {...fromServer} /> : <RouterProvider router={router} />}
  </StrictMode>,
);
