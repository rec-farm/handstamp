import { useEffect, useState } from 'react';
import { Download } from 'lucide-react';
import { api } from '../../api.ts';
import {
  Cell,
  Empty,
  NoticeLine,
  PageHeader,
  Panel,
  Row,
  Table,
  When,
} from '../../components/admin.tsx';
import { Button, Field } from '../../components/ui.tsx';
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

export function AdminAudit() {
  return <AdminPage crumbs={[['Audit log']]}>{(c) => <AuditBody c={c} />}</AdminPage>;
}

function AuditBody({ c }: { c: Console }) {
  const initial = new URLSearchParams(window.location.search);
  const [filters, setFilters] = useState({
    action: initial.get('action') ?? '',
    target: '',
    from: '',
    to: '',
  });
  const [entries, setEntries] = useState<Entry[]>([]);
  const [next, setNext] = useState<number | null>(null);
  const [error, setError] = useState<string>();

  const query = (before?: number) => {
    const q = new URLSearchParams();
    if (filters.action) q.set('action', filters.action);
    if (filters.target) q.set('target', filters.target.trim());
    if (filters.from) q.set('from', new Date(filters.from).toISOString());
    if (filters.to) q.set('to', new Date(filters.to).toISOString());
    if (before) q.set('before', String(before));
    return q.toString();
  };

  async function load(before?: number) {
    try {
      const page = await api<{ entries: Entry[]; next: number | null }>(
        `/api/admin/audit?${query(before)}`,
      );
      setEntries(before ? [...entries, ...page.entries] : page.entries);
      setNext(page.next);
      setError(undefined);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  useEffect(() => void load(), []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <>
      <PageHeader
        eyebrow="Who did what, when"
        title="Audit log"
        subtitle="Every sign-in, every change to people, apps and keys. Never any secrets."
        action={
          <a
            href={`/api/admin/audit.csv?${query()}`}
            className="inline-flex h-9 items-center gap-2 rounded-sm border border-border-input bg-surface-1 px-3.5 text-body font-semibold text-fg hover:bg-surface-2"
          >
            <Download className="size-4" aria-hidden /> Export CSV
          </a>
        }
      />
      <NoticeLine notice={error ? { tone: 'error', text: error } : c.notice} />
      <Panel label="Filter">
        <form
          className="grid gap-6 px-6 py-5 sm:grid-cols-2 lg:grid-cols-4"
          onSubmit={(e) => {
            e.preventDefault();
            void load();
          }}
        >
          <Field label="What">
            {(id) => (
              <select
                id={id}
                className="input"
                value={filters.action}
                onChange={(e) => setFilters({ ...filters, action: e.target.value })}
              >
                {ACTIONS.map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <Field label="About" hint="A user sub, client ID or key ID.">
            {(id) => (
              <input
                id={id}
                className="input font-mono"
                value={filters.target}
                onChange={(e) => setFilters({ ...filters, target: e.target.value })}
              />
            )}
          </Field>
          <Field label="From">
            {(id) => (
              <input
                id={id}
                type="datetime-local"
                className="input font-mono"
                value={filters.from}
                onChange={(e) => setFilters({ ...filters, from: e.target.value })}
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
                onChange={(e) => setFilters({ ...filters, to: e.target.value })}
              />
            )}
          </Field>
          <div>
            <Button type="submit" size="md" variant="secondary">
              Apply
            </Button>
          </div>
        </form>
      </Panel>
      <Panel label="Entries">
        <Table
          head={['When', 'What', 'Who', 'About', 'From', 'Details']}
          empty={entries.length === 0 && <Empty>Nothing matches.</Empty>}
        >
          {entries.map((e) => (
            <Row key={e.id}>
              <Cell muted>
                <When iso={e.at} />
              </Cell>
              <Cell mono>{e.action}</Cell>
              <Cell>{e.actorName ?? <span className="text-fg-muted">{e.actorType}</span>}</Cell>
              <Cell mono muted>
                {e.clientId ?? e.targetId?.slice(0, 24) ?? '—'}
              </Cell>
              <Cell mono muted>
                {e.ipPrefix ?? '—'}
              </Cell>
              <Cell mono muted>
                {Object.keys(e.metadata).length ? JSON.stringify(e.metadata) : ''}
              </Cell>
            </Row>
          ))}
        </Table>
        {next && (
          <div className="border-t border-border px-6 py-3">
            <Button size="md" variant="ghost" onClick={() => load(next)}>
              Show older entries
            </Button>
          </div>
        )}
      </Panel>
    </>
  );
}
