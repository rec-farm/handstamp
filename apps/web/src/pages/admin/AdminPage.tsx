import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { AppShell } from '../../components/AppShell.tsx';
import { NoticeLine } from '../../components/admin.tsx';
import { CardPage, Loading, Title } from '../../components/ui.tsx';
import { useConsole } from '../../lib/console.tsx';

export type Console = ReturnType<typeof useConsole>;

// Every admin page: signed-in admin check, the shell, a breadcrumb and the notice line.
export function AdminPage({
  crumbs,
  children,
}: {
  crumbs: [string, string?][];
  children: (c: Console) => ReactNode;
}) {
  const c = useConsole();
  if (!c.me)
    return (
      <div className="grid min-h-dvh place-items-center">
        {c.notice ? <NoticeLine notice={c.notice} /> : <Loading label="Loading…" />}
      </div>
    );
  if (!c.me.user.isAdmin)
    return (
      <CardPage>
        <Title>Admins only</Title>
        <p className="mt-3 text-body text-fg-muted">
          This part of Handstamp is for admins. Go to{' '}
          <Link className="text-link hover:underline" to="/account">
            your account
          </Link>{' '}
          instead.
        </p>
      </CardPage>
    );
  const crumb = (
    <>
      <span>Admin</span>
      {crumbs.map(([label, to], i) => (
        <span key={label}>
          <span className="px-2 text-fg-subtle">/</span>
          {to && i < crumbs.length - 1 ? (
            <Link to={to} className="hover:text-fg">
              {label}
            </Link>
          ) : (
            <span className="text-fg">{label}</span>
          )}
        </span>
      ))}
    </>
  );
  return (
    <AppShell user={c.me.user} instance={c.me.instance} crumb={crumb}>
      {children(c)}
    </AppShell>
  );
}
