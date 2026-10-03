import { useState } from 'react';
import { Plus, Search } from 'lucide-react';
import {
  Cell,
  Empty,
  NoticeLine,
  PageHeader,
  Panel,
  Row,
  RowLink,
  ShownOnce,
  Status,
  Table,
  When,
} from '../../components/admin.tsx';
import { Button, Tag } from '../../components/ui.tsx';
import { useResource } from '../../lib/console.tsx';
import { AdminPage, type Console } from './AdminPage.tsx';

type UserRow = {
  id: string;
  displayName: string;
  email: string | null;
  isAdmin: boolean;
  status: 'active' | 'disabled';
  createdAt: string;
  lastSignInAt: string | null;
  methods: number;
};
type Invite = { id: string; createdAt: string; expiresAt: string; createdBy: string | null };

export function AdminUsers() {
  return <AdminPage crumbs={[['Users']]}>{(c) => <UsersBody c={c} />}</AdminPage>;
}

function UsersBody({ c }: { c: Console }) {
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const users = useResource<UserRow[]>(
    `/api/admin/users${search ? `?q=${encodeURIComponent(search)}` : ''}`,
  );
  const invites = useResource<Invite[]>('/api/admin/invites');
  const [link, setLink] = useState<string>();

  return (
    <>
      <PageHeader
        eyebrow="People"
        title="Users"
        subtitle="Everyone who can sign in through this Handstamp."
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
              if (result) {
                setLink(result.link);
                void invites.reload();
              }
            }}
          >
            Invite someone
          </Button>
        }
      />
      <NoticeLine notice={c.notice} />
      {link && (
        <ShownOnce title="Invite link, valid for 7 days" value={link}>
          Send it to the person you're inviting. It works once, and we won't show it again.
        </ShownOnce>
      )}

      <Panel
        label="Everyone"
        action={
          <form
            role="search"
            className="relative w-full sm:w-60"
            onSubmit={(e) => {
              e.preventDefault();
              setSearch(q.trim());
            }}
          >
            <Search
              className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-fg-subtle"
              aria-hidden
            />
            <label htmlFor="user-search" className="sr-only">
              Search users
            </label>
            <input
              id="user-search"
              className="input h-9 pl-9"
              placeholder="Name, email or sub"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </form>
        }
      >
        <Table
          head={['Name', 'Email', 'Status', 'Sign-in methods', 'Last sign-in']}
          empty={users.data?.length === 0 && <Empty>No one matches “{search}”.</Empty>}
        >
          {users.data?.map((u) => (
            <Row key={u.id} to={`/admin/users/${u.id}`}>
              <Cell>
                <span className="flex items-center gap-2">
                  <RowLink to={`/admin/users/${u.id}`}>{u.displayName}</RowLink>
                  {u.isAdmin && <Tag tone="info">Admin</Tag>}
                </span>
              </Cell>
              <Cell muted>{u.email ?? '—'}</Cell>
              <Cell>
                <Status ok={u.status === 'active'} yes="Active" no="Turned off" />
              </Cell>
              <Cell mono>{u.methods}</Cell>
              <Cell muted>
                <When iso={u.lastSignInAt} />
              </Cell>
            </Row>
          ))}
        </Table>
      </Panel>

      <Panel label="Pending invites">
        {invites.data?.length ? (
          <ul className="divide-y divide-border">
            {invites.data.map((invite) => (
              <li key={invite.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-6 py-3">
                <span className="min-w-0 flex-1 text-body text-fg">
                  Created <When iso={invite.createdAt} /> by{' '}
                  {invite.createdBy ?? 'the command line'} · expires <When iso={invite.expiresAt} />
                </span>
                <Button
                  size="md"
                  variant="ghost"
                  busy={c.busy === invite.id}
                  onClick={async () => {
                    await c.act(
                      invite.id,
                      () => c.write(`/api/admin/invites/${invite.id}`, 'DELETE'),
                      'Invite revoked. The link no longer works.',
                    );
                    void invites.reload();
                  }}
                >
                  Revoke
                </Button>
              </li>
            ))}
          </ul>
        ) : (
          <Empty>No invites waiting. Invite links work once and expire after 7 days.</Empty>
        )}
      </Panel>
    </>
  );
}
