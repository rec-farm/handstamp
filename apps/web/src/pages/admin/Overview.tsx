import { useState } from 'react';
import { Link } from 'react-router';
import { Activity, AppWindow, ArrowDownRight, ArrowUpRight, Plus, Users } from 'lucide-react';
import { NoticeLine, PageHeader, ShownOnce, When } from '../../components/admin.tsx';
import { Button, Loading } from '../../components/ui.tsx';
import { useResource } from '../../lib/console.tsx';
import { AdminPage } from './AdminPage.tsx';

type Overview = {
  users: number;
  disabledUsers: number;
  sessions: number;
  clients: number;
  providers: number;
  signIns24h: number;
  refusals24h: number;
  signingKey: { kid: string; activatedAt: string; staged: boolean } | null;
};

// One tile of the stat group (DESIGN §10.6): label, corner icon, number, caption.
function Tile({
  to,
  label,
  value,
  caption,
  icon,
  tone,
}: {
  to: string;
  label: string;
  value: number;
  caption: string;
  icon: React.ReactNode;
  tone: 'neutral' | 'success' | 'info' | 'danger';
}) {
  const bg = {
    neutral: 'bg-surface-1',
    success: 'bg-success-tile',
    info: 'bg-info-tile',
    danger: 'bg-danger-tile',
  }[tone];
  return (
    <Link
      to={to}
      aria-label={`${label}: ${value}. ${caption}`}
      className={`group relative min-h-34 p-6 text-tile-fg hover:outline-[1.5px] hover:-outline-offset-[1.5px] hover:outline-border-strong ${bg}`}
    >
      <div className="flex items-start justify-between">
        <span className="text-body font-medium dark:label-stamp">{label}</span>
        <span className="transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5">
          {icon}
        </span>
      </div>
      <p className="stat-num mt-4 text-stat">{value}</p>
      <p className="mt-2 text-body-sm text-tile-fg-muted">{caption}</p>
    </Link>
  );
}

export function AdminOverview() {
  return <AdminPage crumbs={[['Overview']]}>{(c) => <OverviewBody c={c} />}</AdminPage>;
}

function OverviewBody({ c }: { c: import('./AdminPage.tsx').Console }) {
  const { data } = useResource<Overview>('/api/admin/overview');
  const [invite, setInvite] = useState<string>();
  return (
    <>
      <PageHeader
        eyebrow="Your instance, at a glance"
        title="Overview"
        subtitle="Who can sign in, where, and what changed lately."
        action={
          <Button
            variant="primary"
            size="md"
            icon={<Plus className="size-4" aria-hidden />}
            busy={c.busy === 'invite'}
            onClick={async () => {
              const result = await c.act('invite', () =>
                c.write<{ link: string }>('/api/admin/invites'),
              );
              if (result) setInvite(result.link);
            }}
          >
            Invite someone
          </Button>
        }
      />
      <NoticeLine notice={c.notice} />
      {invite && (
        <ShownOnce title="Invite link, valid for 7 days" value={invite}>
          Send it to the person you're inviting. It works once, and we won't show it again.
        </ShownOnce>
      )}
      {!data ? (
        <div className="mt-10">
          <Loading label="Counting…" />
        </div>
      ) : (
        <>
          <div className="mt-8 grid grid-cols-1 divide-y divide-border-strong border-[1.5px] border-border-strong shadow-hard-lg sm:grid-cols-2 sm:divide-x lg:grid-cols-4 lg:divide-y-0">
            <Tile
              to="/admin/users"
              label="People"
              value={data.users}
              caption={data.disabledUsers ? `${data.disabledUsers} turned off` : 'All active'}
              icon={<Users className="size-5 text-fg-muted" aria-hidden />}
              tone="neutral"
            />
            <Tile
              to="/admin/users"
              label="Signed in now"
              value={data.sessions}
              caption="Active sessions"
              icon={<Activity className="size-5 text-success-icon" aria-hidden />}
              tone="success"
            />
            <Tile
              to="/admin/audit?action=auth.sign_in.succeeded"
              label="Sign-ins"
              value={data.signIns24h}
              caption="In the last 24 hours"
              icon={<ArrowUpRight className="size-5 text-info-icon" aria-hidden />}
              tone="info"
            />
            <Tile
              to="/admin/audit?action=auth.sign_in."
              label="Refused"
              value={data.refusals24h}
              caption={
                data.refusals24h ? 'Failed or refused, last 24 hours' : 'Nothing refused today'
              }
              icon={
                <ArrowDownRight
                  className={`size-5 ${data.refusals24h ? 'text-danger-icon' : 'text-fg-muted'}`}
                  aria-hidden
                />
              }
              tone={data.refusals24h ? 'danger' : 'neutral'}
            />
          </div>
          <p className="mt-4 font-mono text-mono-sm text-fg-subtle">
            {data.clients} apps · {data.providers} sign-in providers
            {data.signingKey && (
              <>
                {' · '}signing key{' '}
                <span className="text-fg">{data.signingKey.kid.slice(0, 12)}…</span> since{' '}
                <When iso={data.signingKey.activatedAt} />
                {data.signingKey.staged && ' · new key waiting'}
              </>
            )}
          </p>
          <div className="mt-10 grid gap-4 sm:grid-cols-2">
            <Link
              to="/admin/apps"
              className="group flex items-start gap-4 border border-border bg-surface-2 p-4 hover:border-border-strong light:bg-surface-1"
            >
              <AppWindow className="mt-0.5 size-5 text-accent-text" aria-hidden />
              <span>
                <span className="block text-body font-semibold text-fg">Connect an app</span>
                <span className="mt-0.5 block text-body-sm text-fg-muted">
                  Register a client and get the settings it needs.
                </span>
              </span>
            </Link>
            <Link
              to="/admin/groups"
              className="group flex items-start gap-4 border border-border bg-surface-2 p-4 hover:border-border-strong light:bg-surface-1"
            >
              <Users className="mt-0.5 size-5 text-accent-text" aria-hidden />
              <span>
                <span className="block text-body font-semibold text-fg">
                  Organise people into groups
                </span>
                <span className="mt-0.5 block text-body-sm text-fg-muted">
                  Apps see them in the groups claim, and can require one.
                </span>
              </span>
            </Link>
          </div>
        </>
      )}
    </>
  );
}
