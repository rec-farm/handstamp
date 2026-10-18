import { useState } from 'react';
import { useParams } from 'react-router';
import {
  Empty,
  KeyValues,
  NoticeLine,
  PageHeader,
  Panel,
  ShownOnce,
  Status,
  When,
} from '../../components/admin.tsx';
import { Button, Field, Tag } from '../../components/ui.tsx';
import { useResource } from '../../lib/console.tsx';
import { AdminPage, type Console } from './AdminPage.tsx';

type Detail = {
  user: {
    id: string;
    displayName: string;
    email: string | null;
    emailVerified: boolean;
    isAdmin: boolean;
    status: 'active' | 'disabled';
    createdAt: string;
    lastSignInAt: string | null;
    kind: 'person' | 'agent';
  };
  passkeys: {
    id: string;
    name: string;
    createdAt: string;
    lastUsedAt: string | null;
    synced: boolean;
  }[];
  identities: {
    id: string;
    providerName: string;
    loginHint: string | null;
    email: string | null;
    linkedAt: string;
    owner: { subject: string | null; name: string | null; email: string | null } | null;
  }[];
  groups: { id: string; slug: string; name: string }[];
  sessions: { uid: string; signedInAt: string | null; method: string; apps: { name: string }[] }[];
};
type Group = { id: string; slug: string; name: string };

export function AdminUser() {
  const { id = '' } = useParams();
  return (
    <AdminPage crumbs={[['Users', '/admin/users'], ['Person']]}>
      {(c) => <UserBody c={c} id={id} />}
    </AdminPage>
  );
}

function UserBody({ c, id }: { c: Console; id: string }) {
  const { data, error, reload } = useResource<Detail>(`/api/admin/users/${id}`);
  const allGroups = useResource<Group[]>('/api/admin/groups');
  const [editing, setEditing] = useState<{ displayName: string; email: string }>();
  const [link, setLink] = useState<string>();
  const [revoke, setRevoke] = useState(false);
  const [confirm, setConfirm] = useState<string>();

  if (!data) return error ? <NoticeLine notice={{ tone: 'error', text: error }} /> : null;
  const { user } = data;
  const self = user.id === c.me!.user.sub;

  const change = async (
    name: string,
    path: string,
    method: string,
    body: unknown,
    done: string,
  ) => {
    const result = await c.act(name, () => c.write(path, method, body), done);
    setConfirm(undefined);
    if (result !== undefined) void reload();
    return result;
  };

  return (
    <>
      <PageHeader
        eyebrow={user.isAdmin ? 'Admin' : user.kind === 'agent' ? 'Agent' : 'Person'}
        title={user.displayName}
        name
        subtitle={
          <span className="flex flex-wrap items-center gap-3">
            <Status ok={user.status === 'active'} yes="Active" no="Turned off" />
            {user.isAdmin && <Tag tone="info">Admin</Tag>}
            {user.kind === 'agent' && <Tag>Agent</Tag>}
            {self && <Tag>You</Tag>}
          </span>
        }
      />
      <NoticeLine notice={c.notice} />
      {link && (
        <ShownOnce title="Recovery link, valid for 30 minutes" value={link}>
          Give it to {user.displayName} yourself, after checking it's really them. It works once.
        </ShownOnce>
      )}

      <Panel
        label="Profile"
        action={
          !editing && (
            <Button
              size="md"
              variant="secondary"
              onClick={() => setEditing({ displayName: user.displayName, email: user.email ?? '' })}
            >
              Edit
            </Button>
          )
        }
      >
        {editing ? (
          <form
            className="max-w-[560px] space-y-6 px-6 py-6"
            onSubmit={async (e) => {
              e.preventDefault();
              const ok = await change(
                'profile',
                `/api/admin/users/${id}`,
                'PATCH',
                editing,
                'Saved.',
              );
              if (ok !== undefined) setEditing(undefined);
            }}
          >
            <Field label="Name" required>
              {(fid) => (
                <input
                  id={fid}
                  className="input"
                  value={editing.displayName}
                  onChange={(e) => setEditing({ ...editing, displayName: e.target.value })}
                  required
                />
              )}
            </Field>
            <Field
              label="Email"
              hint="An email you enter here counts as verified: you're vouching for it. Leave empty to remove it."
            >
              {(fid) => (
                <input
                  id={fid}
                  type="email"
                  className="input"
                  value={editing.email}
                  onChange={(e) => setEditing({ ...editing, email: e.target.value })}
                />
              )}
            </Field>
            <div className="flex gap-3">
              <Button type="submit" variant="primary" size="md" busy={c.busy === 'profile'}>
                Save
              </Button>
              <Button type="button" variant="ghost" size="md" onClick={() => setEditing(undefined)}>
                Cancel
              </Button>
            </div>
          </form>
        ) : (
          <KeyValues
            items={[
              ['Subject (sub)', <code className="font-mono text-mono">{user.id}</code>],
              [
                'Email',
                user.email ? (
                  <>
                    {user.email} {user.emailVerified && <Tag tone="success">Verified</Tag>}
                  </>
                ) : (
                  <span className="text-fg-subtle">Not set</span>
                ),
              ],
              ['Member since', <When iso={user.createdAt} />],
              ['Last sign-in', <When iso={user.lastSignInAt} />],
            ]}
          />
        )}
      </Panel>

      <Panel label="Access">
        <ul className="divide-y divide-border">
          <li className="flex flex-wrap items-center gap-4 px-6 py-4">
            <p className="min-w-0 flex-1 text-body text-fg">
              {user.isAdmin ? 'Can manage this Handstamp instance.' : 'Not an admin.'}
            </p>
            {!self && (
              <Button
                size="md"
                variant="secondary"
                busy={c.busy === 'admin'}
                onClick={() =>
                  change(
                    'admin',
                    `/api/admin/users/${id}`,
                    'PATCH',
                    { isAdmin: !user.isAdmin },
                    user.isAdmin ? 'Admin access removed.' : `${user.displayName} is now an admin.`,
                  )
                }
              >
                {user.isAdmin ? 'Remove admin access' : 'Make admin'}
              </Button>
            )}
          </li>
          <li className="flex flex-wrap items-center gap-4 px-6 py-4">
            <p className="min-w-0 flex-1 text-body text-fg">
              {user.status === 'active'
                ? 'Turning the account off signs them out everywhere at once.'
                : 'This account is turned off. They cannot sign in to anything.'}
            </p>
            {!self &&
              (confirm === 'status' || user.status === 'disabled' ? (
                <span className="flex gap-2">
                  <Button
                    size="md"
                    variant={user.status === 'active' ? 'danger' : 'secondary'}
                    busy={c.busy === 'status'}
                    onClick={() =>
                      change(
                        'status',
                        `/api/admin/users/${id}`,
                        'PATCH',
                        { status: user.status === 'active' ? 'disabled' : 'active' },
                        user.status === 'active'
                          ? `${user.displayName} is turned off and signed out.`
                          : 'Turned back on.',
                      )
                    }
                  >
                    {user.status === 'active' ? 'Yes, turn off' : 'Turn on again'}
                  </Button>
                  {user.status === 'active' && (
                    <Button size="md" variant="ghost" onClick={() => setConfirm(undefined)}>
                      Cancel
                    </Button>
                  )}
                </span>
              ) : (
                <Button size="md" variant="secondary" onClick={() => setConfirm('status')}>
                  Turn off account
                </Button>
              ))}
          </li>
          {user.status === 'active' && (
            <li className="flex flex-wrap items-center gap-4 px-6 py-4">
              <div className="min-w-0 flex-1">
                <p className="text-body text-fg">
                  Lost their way in? Send a one-time recovery link.
                </p>
                <label className="mt-2 flex items-center gap-2 text-body-sm text-fg-muted">
                  <input
                    type="checkbox"
                    className="size-4 accent-primary"
                    checked={revoke}
                    onChange={(e) => setRevoke(e.target.checked)}
                  />
                  A device was lost or stolen: remove their passkeys and sign them out when they use
                  it
                </label>
              </div>
              <Button
                size="md"
                variant="secondary"
                busy={c.busy === 'recovery'}
                onClick={async () => {
                  const result = await c.act('recovery', () =>
                    c.write<{ link: string }>(`/api/admin/users/${id}/recovery`, 'POST', {
                      revokeOtherMethods: revoke,
                    }),
                  );
                  if (result) setLink(result.link);
                }}
              >
                Create recovery link
              </Button>
            </li>
          )}
        </ul>
      </Panel>

      <Panel label="Groups">
        <fieldset className="flex flex-wrap gap-x-6 gap-y-3 px-6 py-5">
          <legend className="sr-only">Group memberships</legend>
          {allGroups.data?.length ? (
            allGroups.data.map((g) => {
              const member = data.groups.some((m) => m.id === g.id);
              return (
                <label key={g.id} className="flex items-center gap-2 text-body text-fg">
                  <input
                    type="checkbox"
                    className="size-4 accent-primary"
                    checked={member}
                    disabled={!!c.busy}
                    onChange={() =>
                      change(
                        `group-${g.id}`,
                        `/api/admin/groups/${g.id}/members/${id}`,
                        member ? 'DELETE' : 'PUT',
                        {},
                        member ? `Removed from ${g.name}.` : `Added to ${g.name}.`,
                      )
                    }
                  />
                  {g.name} <code className="font-mono text-mono-sm text-fg-subtle">{g.slug}</code>
                </label>
              );
            })
          ) : (
            <p className="text-body-sm text-fg-muted">No groups yet.</p>
          )}
        </fieldset>
      </Panel>

      <Panel label="Passkeys">
        {data.passkeys.length ? (
          <ul className="divide-y divide-border">
            {data.passkeys.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center gap-4 px-6 py-3">
                <span className="min-w-0 flex-1 text-body text-fg">
                  {p.name} {p.synced ? <Tag tone="info">Synced</Tag> : <Tag>This device only</Tag>}{' '}
                  <span className="text-body-sm text-fg-muted">
                    · last used <When iso={p.lastUsedAt} />
                  </span>
                </span>
                <Button
                  size="md"
                  variant="ghost"
                  busy={c.busy === p.id}
                  onClick={() =>
                    change(
                      p.id,
                      `/api/admin/users/${id}/passkeys/${p.id}`,
                      'DELETE',
                      {},
                      `Removed “${p.name}”.`,
                    )
                  }
                >
                  Remove
                </Button>
              </li>
            ))}
          </ul>
        ) : (
          <Empty>No passkeys.</Empty>
        )}
      </Panel>

      <Panel label="Linked accounts">
        {data.identities.length ? (
          <ul className="divide-y divide-border">
            {data.identities.map((i) => (
              <li key={i.id} className="flex flex-wrap items-center gap-4 px-6 py-3">
                <span className="min-w-0 flex-1 text-body text-fg">
                  {i.providerName}{' '}
                  <code className="font-mono text-mono-sm text-fg-muted">
                    {i.loginHint ?? i.email}
                  </code>
                  {i.owner && (
                    <span className="mt-0.5 block text-body-sm text-fg-muted">
                      Owned by {i.owner.name ?? i.owner.email ?? 'someone'}
                      {i.owner.name && i.owner.email && (
                        <>
                          {' '}
                          <code className="font-mono text-mono-sm">{i.owner.email}</code>
                        </>
                      )}
                      {i.owner.subject && (
                        <>
                          {' · '}
                          <code className="font-mono text-mono-sm break-all">
                            {i.owner.subject}
                          </code>
                        </>
                      )}
                    </span>
                  )}
                </span>
                <Button
                  size="md"
                  variant="ghost"
                  busy={c.busy === i.id}
                  onClick={() =>
                    change(
                      i.id,
                      `/api/admin/users/${id}/identities/${i.id}`,
                      'DELETE',
                      {},
                      `Unlinked ${i.providerName}.`,
                    )
                  }
                >
                  Unlink
                </Button>
              </li>
            ))}
          </ul>
        ) : (
          <Empty>No linked accounts.</Empty>
        )}
      </Panel>

      <Panel
        label="Sessions"
        action={
          data.sessions.length > 0 && (
            <Button
              size="md"
              variant="secondary"
              busy={c.busy === 'sessions'}
              onClick={() =>
                change(
                  'sessions',
                  `/api/admin/users/${id}/sessions`,
                  'DELETE',
                  {},
                  'Signed out everywhere. Their apps were told.',
                )
              }
            >
              Sign out everywhere
            </Button>
          )
        }
      >
        {data.sessions.length ? (
          <ul className="divide-y divide-border">
            {data.sessions.map((s) => (
              <li key={s.uid} className="px-6 py-3 text-body text-fg">
                Signed in <When iso={s.signedInAt} />{' '}
                <span className="text-body-sm text-fg-muted">
                  · with a {s.method === 'passkey' ? 'passkey' : 'linked account'} ·{' '}
                  {s.apps.map((a) => a.name).join(', ')}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <Empty>Not signed in anywhere.</Empty>
        )}
      </Panel>
    </>
  );
}
