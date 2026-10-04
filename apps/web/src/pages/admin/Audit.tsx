import { Fragment, useEffect, useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import { CircleAlert, Download, Search, X } from 'lucide-react';
import { api } from '../../api.ts';
import { NoticeLine, PageHeader, Panel } from '../../components/admin.tsx';
import { Button, Field, Select } from '../../components/ui.tsx';
import { relative } from '../../lib/time.ts';
import { AdminPage, type Console } from './AdminPage.tsx';

type Entry = {
  id: number;
  at: string;
  action: string;
  actorType: string;
  actorUserId: string | null;
  actorName: string | null;
  targetType: string | null;
  targetId: string | null;
  clientId: string | null;
  ipPrefix: string | null;
  metadata: Record<string, unknown>;
};

type Filters = { action: string; target: string; from: string; to: string };

const ACTIONS: [string, string][] = [
  ['', 'Everything'],
  ['auth.', 'Sign-ins'],
  ['auth.sign_in.failed', 'Failed passkey sign-ins'],
  ['auth.sign_in.refused', 'Refused sign-ins'],
  ['user.', 'Users'],
  ['passkey.', 'Passkeys'],
  ['identity.', 'Linked accounts'],
  ['group.', 'Groups'],
  ['client.', 'Apps'],
  ['provider.', 'Sign-in providers'],
  ['key.', 'Signing keys'],
  ['invite.', 'Invites'],
  ['recovery.', 'Recovery links'],
  ['session.', 'Sessions'],
];

// What each action means in words. The raw action stays visible under it, in mono.
const LABELS: Record<string, string> = {
  'auth.sign_in.succeeded': 'Signed in',
  'auth.sign_in.failed': 'Passkey sign-in failed',
  'auth.sign_in.refused': 'Sign-in refused',
  'auth.consent.granted': 'Allowed an app',
  'instance.started': 'Handstamp started',
  'instance.claimed': 'Instance claimed',
  'setup.code_issued': 'Setup code issued',
  'client.created': 'App added',
  'client.updated': 'App updated',
  'client.synced': 'App synced from file',
  'client.secret_rotated': 'App secret rotated',
  'client.enabled': 'App turned on',
  'client.disabled': 'App turned off',
  'key.staged': 'Signing key staged',
  'key.activated': 'Signing key activated',
  'key.retired': 'Signing key retired',
  'passkey.added': 'Passkey added',
  'passkey.renamed': 'Passkey renamed',
  'passkey.removed': 'Passkey removed',
  'session.revoked': 'Signed out',
  'session.revoked_all': 'Signed out everywhere',
  'admin.sessions_revoked': 'Sessions ended by an admin',
  'provider.created': 'Provider added',
  'provider.updated': 'Provider updated',
  'provider.enabled': 'Provider turned on',
  'provider.disabled': 'Provider turned off',
  'user.created': 'User created',
  'user.updated': 'User updated',
  'user.enabled': 'User turned on',
  'user.disabled': 'User turned off',
  'user.admin_granted': 'Made an admin',
  'user.admin_revoked': 'No longer an admin',
  'user.email_conflict': 'Email already in use',
  'identity.linked': 'Account linked',
  'identity.unlinked': 'Account unlinked',
  'identity.link_refused': 'Account link refused',
  'invite.created': 'Invite created',
  'invite.used': 'Invite used',
  'invite.revoked': 'Invite revoked',
  'recovery.issued': 'Recovery link issued',
  'recovery.used': 'Recovery link used',
  'group.created': 'Group created',
  'group.updated': 'Group updated',
  'group.deleted': 'Group deleted',
  'group.member_added': 'Added to a group',
  'group.member_removed': 'Removed from a group',
};

// Things that went wrong get the danger icon next to their label (color plus icon, §16).
const PROBLEMS = new Set([
  'auth.sign_in.failed',
  'auth.sign_in.refused',
  'identity.link_refused',
  'user.email_conflict',
]);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Target types as an admin would name them.
const TYPES: Record<string, string> = {
  user: 'user',
  group: 'group',
  passkey: 'passkey',
  identity: 'account',
  enrollment: 'link',
  signing_key: 'key',
};

const readFilters = (): Filters => {
  const q = new URLSearchParams(window.location.search);
  return {
    action: q.get('action') ?? '',
    target: q.get('target') ?? '',
    from: q.get('from') ?? '',
    to: q.get('to') ?? '',
  };
};

const time = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
});
const date = new Intl.DateTimeFormat(undefined, {
  weekday: 'short',
  day: 'numeric',
  month: 'short',
  year: 'numeric',
});

function dayLabel(iso: string) {
  const day = new Date(iso);
  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(today.getDate() - 1);
  if (day.toDateString() === today.toDateString()) return `Today · ${date.format(day)}`;
  if (day.toDateString() === yesterday.toDateString()) return `Yesterday · ${date.format(day)}`;
  return date.format(day);
}

export function AdminAudit() {
  return <AdminPage crumbs={[['Audit log']]}>{(c) => <AuditBody c={c} />}</AdminPage>;
}

function AuditBody({ c }: { c: Console }) {
  const [filters, setFilters] = useState(readFilters);
  const [entries, setEntries] = useState<Entry[]>();
  const [next, setNext] = useState<number | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string>();
  const latest = useRef(0);

  const filtered = Object.values(filters).some(Boolean);

  const query = (before?: number) => {
    const q = new URLSearchParams();
    if (filters.action) q.set('action', filters.action);
    if (filters.target.trim()) q.set('target', filters.target.trim());
    if (filters.from) q.set('from', new Date(filters.from).toISOString());
    if (filters.to) q.set('to', new Date(filters.to).toISOString());
    if (before) q.set('before', String(before));
    return q.toString();
  };

  async function load(before?: number) {
    // Only the newest request may update the table, so a slow one can't overwrite a fresh one.
    const request = ++latest.current;
    try {
      const page = await api<{ entries: Entry[]; next: number | null }>(
        `/api/admin/audit?${query(before)}`,
      );
      if (request !== latest.current) return;
      setEntries((shown) => (before ? [...(shown ?? []), ...page.entries] : page.entries));
      setNext(page.next);
      setError(undefined);
    } catch (e) {
      if (request === latest.current) setError((e as Error).message);
    }
  }

  // Filters apply as you change them (typing waits a moment), and stay in the URL so a view
  // can be shared or reloaded.
  useEffect(() => {
    const url = new URLSearchParams(
      Object.entries(filters).filter(([, value]) => value) as [string, string][],
    ).toString();
    window.history.replaceState(window.history.state, '', url ? `?${url}` : location.pathname);
    const timer = setTimeout(() => void load(), filters.target ? 300 : 0);
    return () => clearTimeout(timer);
  }, [filters]); // eslint-disable-line react-hooks/exhaustive-deps

  const set = (patch: Partial<Filters>) => setFilters({ ...filters, ...patch });

  return (
    <>
      <PageHeader
        eyebrow="Who did what, when"
        title="Audit log"
        subtitle="Every sign-in, every change to people, apps and keys. Never any secrets."
        action={
          <a
            href={`/api/admin/audit.csv?${query()}`}
            className="inline-flex h-9 items-center gap-2 rounded-sm border border-border-input bg-surface-1 px-3.5 text-body font-semibold text-fg hover:bg-surface-2 focus-visible:ring-3 focus-visible:ring-primary/25 focus-visible:outline-none"
          >
            <Download className="size-4" aria-hidden /> Export CSV
          </a>
        }
      />
      <NoticeLine notice={error ? { tone: 'error', text: error } : c.notice} />
      <Panel
        label="Filter"
        action={
          filtered && (
            <Button
              size="md"
              variant="ghost"
              icon={<X className="size-4" aria-hidden />}
              onClick={() => setFilters({ action: '', target: '', from: '', to: '' })}
            >
              Clear filters
            </Button>
          )
        }
      >
        <form
          role="search"
          className="grid gap-x-4 gap-y-5 px-6 py-5 sm:grid-cols-2 lg:grid-cols-[1fr_1.4fr_1fr_1fr]"
          onSubmit={(e) => {
            e.preventDefault();
            void load();
          }}
        >
          <Field label="What">
            {(id) => (
              <Select
                id={id}
                value={filters.action}
                onChange={(e) => set({ action: e.target.value })}
              >
                {ACTIONS.map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="About">
            {(id) => (
              <div className="relative">
                <Search
                  className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-fg-subtle"
                  aria-hidden
                />
                <input
                  id={id}
                  type="search"
                  className="input pl-9 font-mono"
                  placeholder="Sub, client ID or key ID"
                  spellCheck={false}
                  value={filters.target}
                  onChange={(e) => set({ target: e.target.value })}
                />
              </div>
            )}
          </Field>
          <Field label="From">
            {(id) => (
              <input
                id={id}
                type="datetime-local"
                className="input font-mono"
                value={filters.from}
                max={filters.to || undefined}
                onChange={(e) => set({ from: e.target.value })}
              />
            )}
          </Field>
          <Field label="To">
            {(id) => (
              <input
                id={id}
                type="datetime-local"
                className="input font-mono"
                value={filters.to}
                min={filters.from || undefined}
                onChange={(e) => set({ to: e.target.value })}
              />
            )}
          </Field>
        </form>
      </Panel>
      <Panel
        label="Entries"
        action={
          entries && (
            <span className="font-mono text-mono-sm text-fg-subtle tabular-nums">
              {entries.length}
              {next ? '+' : ''} {entries.length === 1 ? 'entry' : 'entries'}
            </span>
          )
        }
      >
        <EntryTable entries={entries} filtered={filtered} />
        {next && (
          <div className="border-t border-border px-6 py-3">
            <Button
              size="md"
              variant="ghost"
              busy={loadingMore}
              onClick={async () => {
                setLoadingMore(true);
                await load(next);
                setLoadingMore(false);
              }}
            >
              Show older entries
            </Button>
          </div>
        )}
      </Panel>
    </>
  );
}

const HEAD = ['Time', 'What', 'Who', 'About', 'From', 'Details'];

function EntryTable({ entries, filtered }: { entries?: Entry[]; filtered: boolean }) {
  if (!entries) return <p className="px-6 py-6 text-body-sm text-fg-muted">Reading the log…</p>;
  if (entries.length === 0)
    return (
      <p className="px-6 py-6 text-body-sm text-fg-muted">
        {filtered
          ? 'Nothing matches these filters. Try a wider time range, or clear them.'
          : 'Nothing logged yet. Sign-ins and changes will show up here.'}
      </p>
    );

  let day = '';
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[880px] border-collapse text-left text-body">
        <thead>
          <tr className="h-10 bg-surface-2 light:bg-surface-1">
            {HEAD.map((h) => (
              <th
                key={h}
                scope="col"
                className="label-stamp px-4 font-bold text-fg-subtle first:pl-6 last:pr-6"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => {
            const label = dayLabel(e.at);
            const newDay = label !== day;
            day = label;
            return (
              <Fragment key={e.id}>
                {newDay && (
                  <tr className="border-t border-border">
                    <th
                      colSpan={HEAD.length}
                      scope="colgroup"
                      className="label-stamp px-6 pt-5 pb-2 text-left font-bold text-fg-muted"
                    >
                      {label}
                    </th>
                  </tr>
                )}
                <EntryRow entry={e} />
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function EntryRow({ entry: e }: { entry: Entry }) {
  const problem = PROBLEMS.has(e.action);
  const details = Object.entries(e.metadata);
  return (
    <tr className="border-t border-border align-top hover:bg-surface-2/60">
      <td className="py-3 pr-4 pl-6 whitespace-nowrap">
        <time
          dateTime={e.at}
          title={`${e.at} · ${relative(e.at)}`}
          className="font-mono text-mono text-fg-muted tabular-nums"
        >
          {time.format(new Date(e.at))}
        </time>
      </td>
      <td className="px-4 py-3">
        <span className="flex items-center gap-1.5 font-semibold text-fg">
          {problem && <CircleAlert className="size-4 shrink-0 text-danger-icon" aria-hidden />}
          {LABELS[e.action] ?? e.action}
        </span>
        <span className="mt-0.5 block font-mono text-mono-sm text-fg-subtle">{e.action}</span>
      </td>
      <td className="px-4 py-3 whitespace-nowrap">
        {e.actorUserId ? (
          <Link to={`/admin/users/${e.actorUserId}`} className="text-fg hover:underline">
            {e.actorName ?? <Id value={e.actorUserId} />}
          </Link>
        ) : (
          <span className="font-mono text-mono-sm text-fg-subtle">{e.actorType}</span>
        )}
      </td>
      <td className="px-4 py-3">
        <About entry={e} />
      </td>
      <td className="px-4 py-3 font-mono text-mono-sm whitespace-nowrap text-fg-muted tabular-nums">
        {e.ipPrefix ?? <span className="text-fg-subtle">—</span>}
      </td>
      <td className="py-3 pr-6 pl-4">
        {details.length > 0 && (
          <dl className="flex flex-wrap gap-x-3 gap-y-1 font-mono text-mono-sm">
            {details.map(([key, value]) => (
              <div key={key} className="flex gap-1 whitespace-nowrap">
                <dt className="text-fg-subtle">{key}</dt>
                <dd className="text-fg-muted">
                  <Value name={key} value={value} />
                </dd>
              </div>
            ))}
          </dl>
        )}
      </td>
    </tr>
  );
}

// The thing an entry is about, linked when the console has a page for it.
function About({ entry: e }: { entry: Entry }) {
  const target = e.targetId && <Target type={e.targetType} id={e.targetId} />;
  const app = e.clientId && (
    <Link to={`/admin/apps/${e.clientId}`} className="font-mono text-mono text-fg hover:underline">
      {e.clientId}
    </Link>
  );
  if (!target && !app) return <span className="text-fg-subtle">—</span>;
  if (!target || !app || (e.targetType === 'client' && e.targetId === e.clientId))
    return <>{target || app}</>;
  return (
    <>
      {target}
      <span className="mt-0.5 block font-mono text-mono-sm text-fg-subtle">via {app}</span>
    </>
  );
}

function Target({ type, id }: { type: string | null; id: string }) {
  const to =
    type === 'user'
      ? `/admin/users/${id}`
      : type === 'group'
        ? `/admin/groups/${id}`
        : type === 'client'
          ? `/admin/apps/${id}`
          : type === 'signing_key'
            ? '/admin/keys'
            : undefined;
  const label = (
    <>
      {type && type !== 'client' && <span className="text-fg-subtle">{TYPES[type] ?? type} </span>}
      <Id value={id} />
    </>
  );
  return (
    <span className="font-mono text-mono">
      {to ? (
        <Link to={to} className="text-fg hover:underline">
          {label}
        </Link>
      ) : (
        <span className="text-fg-muted">{label}</span>
      )}
    </span>
  );
}

// Long IDs shortened (UUIDs to their first block), with the full value on hover.
function Id({ value }: { value: string }) {
  const short = UUID.test(value) ? value.slice(0, 8) : value.length > 24 ? value.slice(0, 12) : '';
  if (!short) return <>{value}</>;
  return (
    <abbr title={value} className="no-underline">
      {short}…
    </abbr>
  );
}

function Value({ name, value }: { name: string; value: unknown }): ReactNode {
  if (typeof value === 'string' && UUID.test(value) && (name === 'user' || name === 'held_by'))
    return (
      <Link to={`/admin/users/${value}`} className="hover:text-fg hover:underline">
        <Id value={value} />
      </Link>
    );
  if (typeof value === 'string') return <Id value={value} />;
  if (Array.isArray(value)) return value.length ? value.join(' ') : '—';
  return JSON.stringify(value);
}
