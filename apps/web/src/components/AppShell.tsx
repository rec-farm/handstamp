import type { ReactNode } from 'react';
import { Link, useLocation } from 'react-router';
import {
  AppWindow,
  CircleUserRound,
  KeyRound,
  LayoutGrid,
  LogIn,
  LogOut,
  ScrollText,
  Users,
  UsersRound,
} from 'lucide-react';

type Nav = { href: string; label: string; icon: ReactNode; exact?: boolean };

const YOU: Nav[] = [
  { href: '/account', label: 'Account', icon: <CircleUserRound className="size-5" aria-hidden /> },
];
const ADMIN: Nav[] = [
  {
    href: '/admin',
    label: 'Overview',
    icon: <LayoutGrid className="size-5" aria-hidden />,
    exact: true,
  },
  { href: '/admin/users', label: 'Users', icon: <Users className="size-5" aria-hidden /> },
  { href: '/admin/groups', label: 'Groups', icon: <UsersRound className="size-5" aria-hidden /> },
  { href: '/admin/apps', label: 'Apps', icon: <AppWindow className="size-5" aria-hidden /> },
  {
    href: '/admin/providers',
    label: 'Sign-in providers',
    icon: <LogIn className="size-5" aria-hidden />,
  },
  { href: '/admin/keys', label: 'Signing keys', icon: <KeyRound className="size-5" aria-hidden /> },
  { href: '/admin/audit', label: 'Audit log', icon: <ScrollText className="size-5" aria-hidden /> },
];

function useActive() {
  const { pathname } = useLocation();
  return (item: Nav) =>
    item.exact
      ? pathname === item.href
      : pathname === item.href || pathname.startsWith(`${item.href}/`);
}

// The console layout (DESIGN §5.3, §10.3): sidebar with the wordmark and one loud accent block
// for the active place; below md a compact top bar and a scrollable row of links.
export function AppShell({
  user,
  crumb,
  children,
}: {
  user: { displayName: string; isAdmin?: boolean };
  crumb: ReactNode;
  children: ReactNode;
}) {
  const active = useActive();
  const groups: [string, Nav[]][] = [
    ['You', YOU],
    ...(user.isAdmin ? ([['Admin', ADMIN]] as [string, Nav[]][]) : []),
  ];

  return (
    <div className="min-h-dvh md:flex">
      <aside className="sticky top-0 hidden h-dvh w-sidebar shrink-0 flex-col border-r border-border bg-sidebar text-sidebar-fg md:flex light:border-r-0">
        <div className="flex h-16 items-center gap-3 px-5">
          {/* TODO(brand): the Handstamp mark comes from rec-brand/build.py (§2.10). */}
          <span
            aria-hidden
            className="size-6 rounded-xs border border-dashed border-sidebar-fg-muted"
          />
          <span className="wordmark">Handstamp</span>
        </div>
        <nav aria-label="Main" className="mt-2 flex-1 overflow-y-auto px-3">
          {groups.map(([label, items]) => (
            <div key={label} className="mt-4">
              <p className="eyebrow mb-2 px-2 text-sidebar-fg-muted">{label}</p>
              <ul className="space-y-1">
                {items.map((item) => (
                  <li key={item.href}>
                    <Link
                      to={item.href}
                      aria-current={active(item) ? 'page' : undefined}
                      className={
                        active(item)
                          ? 'press flex h-10 items-center gap-3 rounded-sm border-[1.5px] border-border-strong bg-accent px-3 text-body font-semibold text-accent-fg shadow-hard'
                          : 'flex h-10 items-center gap-3 rounded-sm px-3 text-body font-medium text-sidebar-fg/85 hover:bg-sidebar-hover'
                      }
                    >
                      {item.icon}
                      {item.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
        <div className="px-3 pb-5">
          <a
            href="/console/logout"
            className="flex h-10 items-center gap-3 rounded-sm px-3 text-body font-medium text-sidebar-fg/85 hover:bg-sidebar-hover"
          >
            <LogOut className="size-5" aria-hidden />
            Sign out
          </a>
          <div className="my-4 border-t border-border light:border-deep-700" />
          <p className="px-3 text-caption text-sidebar-fg-muted">
            <span className="label-stamp">Handstamp</span> · by R.E.C.
          </p>
          <p className="mt-1 px-3 font-mono text-mono-sm text-sidebar-fg-muted">
            Handstamp v{__HANDSTAMP_VERSION__}
          </p>
        </div>
      </aside>

      <div className="min-w-0 flex-1">
        <header className="flex h-topbar items-center justify-between border-b border-border px-4 md:px-8">
          <span className="wordmark text-fg md:hidden">Handstamp</span>
          <p className="hidden text-body-sm text-fg-muted md:block">{crumb}</p>
          <div className="flex items-center gap-3">
            <span
              aria-hidden
              className="grid size-8 place-items-center rounded-xs bg-lilac-300 font-bold text-deep-900"
            >
              {user.displayName.trim().charAt(0).toUpperCase() || '?'}
            </span>
            <a href="/console/logout" className="label-stamp text-fg-muted hover:text-fg md:hidden">
              Sign out
            </a>
          </div>
        </header>
        <nav
          aria-label="Main"
          className="flex gap-1 overflow-x-auto border-b border-border px-4 py-2 md:hidden"
        >
          {groups
            .flatMap(([, items]) => items)
            .map((item) => (
              <Link
                key={item.href}
                to={item.href}
                aria-current={active(item) ? 'page' : undefined}
                className={`shrink-0 rounded-sm px-3 py-1.5 text-body-sm font-medium ${active(item) ? 'bg-accent text-accent-fg' : 'text-fg-muted hover:bg-surface-2'}`}
              >
                {item.label}
              </Link>
            ))}
        </nav>
        <main className="mx-auto max-w-content px-4 pb-16 md:px-8 xl:px-12">{children}</main>
      </div>
    </div>
  );
}
