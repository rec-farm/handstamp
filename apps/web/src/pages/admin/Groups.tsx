import { useState } from 'react';
import { useNavigate, useParams } from 'react-router';
import {
  Cell,
  Empty,
  NoticeLine,
  PageHeader,
  Panel,
  Row,
  RowLink,
  Table,
  When,
} from '../../components/admin.tsx';
import { Button, Field } from '../../components/ui.tsx';
import { useResource } from '../../lib/console.tsx';
import { AdminPage, type Console } from './AdminPage.tsx';

type GroupRow = {
  id: string;
  slug: string;
  name: string;
  description: string;
  members: number;
  apps: number;
};
type GroupDetail = {
  group: { id: string; slug: string; name: string; description: string };
  members: { id: string; displayName: string; email: string | null; addedAt: string }[];
  apps: { clientId: string; name: string }[];
};
type UserRow = { id: string; displayName: string; email: string | null };

function GroupForm({
  c,
  initial,
  submit,
  label,
}: {
  c: Console;
  initial: { slug: string; name: string; description: string };
  submit: (value: typeof initial) => Promise<unknown>;
  label: string;
}) {
  const [value, setValue] = useState(initial);
  return (
    <form
      className="grid max-w-[720px] gap-6 px-6 py-6 sm:grid-cols-2"
      onSubmit={async (e) => {
        e.preventDefault();
        await submit(value);
      }}
    >
      <Field label="Name" required>
        {(id) => (
          <input
            id={id}
            className="input"
            value={value.name}
            onChange={(e) => setValue({ ...value, name: e.target.value })}
            required
          />
        )}
      </Field>
      <Field label="Claim value" required hint="What apps see in the groups claim.">
        {(id) => (
          <input
            id={id}
            className="input font-mono"
            value={value.slug}
            placeholder="paramtune-admins"
            onChange={(e) => setValue({ ...value, slug: e.target.value.toLowerCase() })}
            required
          />
        )}
      </Field>
      <div className="sm:col-span-2">
        <Field label="Description">
          {(id) => (
            <input
              id={id}
              className="input"
              value={value.description}
              onChange={(e) => setValue({ ...value, description: e.target.value })}
            />
          )}
        </Field>
      </div>
      <div>
        <Button type="submit" variant="primary" size="md" busy={c.busy === 'group'}>
          {label}
        </Button>
      </div>
    </form>
  );
}

export function AdminGroups() {
  return <AdminPage crumbs={[['Groups']]}>{(c) => <GroupsBody c={c} />}</AdminPage>;
}

function GroupsBody({ c }: { c: Console }) {
  const { data, reload } = useResource<GroupRow[]>('/api/admin/groups');
  const [creating, setCreating] = useState(false);
  return (
    <>
      <PageHeader
        eyebrow="Who belongs together"
        title="Groups"
        subtitle="Apps see a person's groups in the groups claim, and can let only one group in."
        action={
          !creating && (
            <Button variant="primary" size="md" onClick={() => setCreating(true)}>
              Create group
            </Button>
          )
        }
      />
      <NoticeLine notice={c.notice} />
      {creating && (
        <Panel label="New group">
          <GroupForm
            c={c}
            label="Create group"
            initial={{ slug: '', name: '', description: '' }}
            submit={async (value) => {
              const ok = await c.act(
                'group',
                () => c.write('/api/admin/groups', 'POST', value),
                `Created ${value.name}.`,
              );
              if (ok) {
                setCreating(false);
                void reload();
              }
            }}
          />
        </Panel>
      )}
      <Panel label="All groups">
        <Table
          head={['Name', 'Claim value', 'Members', 'Apps requiring it']}
          empty={data?.length === 0 && <Empty>No groups yet.</Empty>}
        >
          {data?.map((g) => (
            <Row key={g.id} to={`/admin/groups/${g.id}`}>
              <Cell>
                <RowLink to={`/admin/groups/${g.id}`}>{g.name}</RowLink>
              </Cell>
              <Cell mono>{g.slug}</Cell>
              <Cell mono>{g.members}</Cell>
              <Cell mono>{g.apps}</Cell>
            </Row>
          ))}
        </Table>
      </Panel>
    </>
  );
}

export function AdminGroup() {
  const { id = '' } = useParams();
  return (
    <AdminPage crumbs={[['Groups', '/admin/groups'], ['Group']]}>
      {(c) => <GroupBody c={c} id={id} />}
    </AdminPage>
  );
}

function GroupBody({ c, id }: { c: Console; id: string }) {
  const navigate = useNavigate();
  const { data, reload } = useResource<GroupDetail>(`/api/admin/groups/${id}`);
  const users = useResource<UserRow[]>('/api/admin/users');
  const [adding, setAdding] = useState('');
  const [confirm, setConfirm] = useState(false);
  if (!data) return null;
  const outside = (users.data ?? []).filter((u) => !data.members.some((m) => m.id === u.id));

  return (
    <>
      <PageHeader eyebrow="Group" title={data.group.slug} identifier subtitle={data.group.name} />
      <NoticeLine notice={c.notice} />
      <Panel label="Details">
        <GroupForm
          key={data.group.slug}
          c={c}
          label="Save"
          initial={{
            slug: data.group.slug,
            name: data.group.name,
            description: data.group.description,
          }}
          submit={async (value) => {
            if (
              await c.act(
                'group',
                () => c.write(`/api/admin/groups/${id}`, 'PATCH', value),
                'Saved.',
              )
            )
              void reload();
          }}
        />
      </Panel>

      <Panel
        label={`Members (${data.members.length})`}
        action={
          outside.length > 0 && (
            <form
              className="flex gap-2"
              onSubmit={async (e) => {
                e.preventDefault();
                if (!adding) return;
                if (
                  await c.act(
                    'add',
                    () => c.write(`/api/admin/groups/${id}/members/${adding}`, 'PUT'),
                    'Added.',
                  )
                ) {
                  setAdding('');
                  void reload();
                }
              }}
            >
              <label htmlFor="add-member" className="sr-only">
                Person to add
              </label>
              <select
                id="add-member"
                className="input h-9 w-56"
                value={adding}
                onChange={(e) => setAdding(e.target.value)}
              >
                <option value="">Choose someone…</option>
                {outside.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.displayName}
                    {u.email ? ` (${u.email})` : ''}
                  </option>
                ))}
              </select>
              <Button
                type="submit"
                size="md"
                variant="secondary"
                disabled={!adding}
                busy={c.busy === 'add'}
              >
                Add
              </Button>
            </form>
          )
        }
      >
        {data.members.length ? (
          <ul className="divide-y divide-border">
            {data.members.map((m) => (
              <li key={m.id} className="flex flex-wrap items-center gap-4 px-6 py-3">
                <span className="min-w-0 flex-1 text-body text-fg">
                  <RowLink to={`/admin/users/${m.id}`}>{m.displayName}</RowLink>{' '}
                  <span className="text-body-sm text-fg-muted">
                    · added <When iso={m.addedAt} />
                  </span>
                </span>
                <Button
                  size="md"
                  variant="ghost"
                  busy={c.busy === m.id}
                  onClick={async () => {
                    if (
                      await c.act(
                        m.id,
                        () => c.write(`/api/admin/groups/${id}/members/${m.id}`, 'DELETE'),
                        `Removed ${m.displayName}.`,
                      )
                    )
                      void reload();
                  }}
                >
                  Remove
                </Button>
              </li>
            ))}
          </ul>
        ) : (
          <Empty>No members yet.</Empty>
        )}
      </Panel>

      <Panel label="Apps that require it">
        {data.apps.length ? (
          <ul className="divide-y divide-border">
            {data.apps.map((a) => (
              <li key={a.clientId} className="px-6 py-3 text-body">
                <RowLink to={`/admin/apps/${a.clientId}`}>{a.name}</RowLink>{' '}
                <code className="font-mono text-mono-sm text-fg-muted">{a.clientId}</code>
              </li>
            ))}
          </ul>
        ) : (
          <Empty>No app requires this group. Anyone can still see it in their groups claim.</Empty>
        )}
      </Panel>

      <div className="mt-10 flex flex-wrap items-center gap-3">
        {confirm ? (
          <>
            <span className="text-body text-fg">
              Delete {data.group.slug}? Members lose it from their groups claim.
            </span>
            <Button
              size="md"
              variant="danger"
              busy={c.busy === 'delete'}
              onClick={async () => {
                if (await c.act('delete', () => c.write(`/api/admin/groups/${id}`, 'DELETE')))
                  navigate('/admin/groups');
                setConfirm(false);
              }}
            >
              Delete group
            </Button>
            <Button size="md" variant="ghost" onClick={() => setConfirm(false)}>
              Keep
            </Button>
          </>
        ) : (
          <Button size="md" variant="secondary" onClick={() => setConfirm(true)}>
            Delete group…
          </Button>
        )}
      </div>
    </>
  );
}
