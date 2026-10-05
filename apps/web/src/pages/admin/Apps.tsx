import { useState } from 'react';
import { useNavigate, useParams } from 'react-router';
import { MonitorSmartphone, Plus, Server, ServerCog } from 'lucide-react';
import {
  Cell,
  CopyButton,
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
import {
  Button,
  Callout,
  Check,
  Choices,
  Field,
  FormActions,
  Section,
  Select,
  Tag,
  type Choice,
} from '../../components/ui.tsx';
import { useResource } from '../../lib/console.tsx';
import { AdminPage, type Console } from './AdminPage.tsx';

type App = {
  clientId: string;
  name: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  scopes: string[];
  tokenEndpointAuthMethod: 'client_secret_basic' | 'client_secret_post' | 'none';
  firstParty: boolean;
  requirePkce: boolean;
  backchannelLogoutUri?: string;
  requiredGroup?: string;
  source: 'db' | 'file' | 'builtin';
  enabled: boolean;
  hasSecret: boolean;
  secretRotatedAt: string | null;
  createdAt: string;
};
type Group = { slug: string; name: string };

const SCOPES = ['openid', 'profile', 'email', 'groups', 'offline_access'];
const SOURCE: Record<App['source'], string> = {
  db: 'Managed here',
  file: 'Clients file',
  builtin: 'Built in',
};

export function AdminApps() {
  return <AdminPage crumbs={[['Apps']]}>{(c) => <AppsBody c={c} />}</AdminPage>;
}

function AppsBody({ c }: { c: Console }) {
  const navigate = useNavigate();
  const { data } = useResource<App[]>('/api/admin/clients');
  return (
    <>
      <PageHeader
        eyebrow="Relying parties"
        title="Apps"
        subtitle="Every app that signs people in through Handstamp."
        action={
          <Button
            variant="primary"
            size="md"
            icon={<Plus className="size-4" aria-hidden />}
            onClick={() => navigate('/admin/apps/new')}
          >
            Add an app
          </Button>
        }
      />
      <NoticeLine notice={c.notice} />
      <Panel label="All apps">
        <Table
          head={['Name', 'Client ID', 'Access', 'Source', 'Status']}
          empty={data?.length === 0 && <Empty>No apps yet.</Empty>}
        >
          {data?.map((a) => (
            <Row key={a.clientId} to={`/admin/apps/${a.clientId}`}>
              <Cell>
                <RowLink to={`/admin/apps/${a.clientId}`}>{a.name}</RowLink>
              </Cell>
              <Cell mono>{a.clientId}</Cell>
              <Cell muted>
                {a.requiredGroup ? (
                  <code className="font-mono text-mono">{a.requiredGroup}</code>
                ) : (
                  'Everyone'
                )}
              </Cell>
              <Cell muted>{SOURCE[a.source]}</Cell>
              <Cell>
                <Status ok={a.enabled} yes="On" no="Off" />
              </Cell>
            </Row>
          ))}
        </Table>
      </Panel>
    </>
  );
}

type Form = Omit<App, 'source' | 'enabled' | 'hasSecret' | 'secretRotatedAt' | 'createdAt'>;
const lines = (text: string) =>
  text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);

const CLIENT_TYPES: Choice<Form['tokenEndpointAuthMethod']>[] = [
  {
    value: 'client_secret_basic',
    label: 'Server app',
    hint: 'Secret in the Authorization header. Most apps.',
    icon: <Server className="size-5" aria-hidden />,
  },
  {
    value: 'client_secret_post',
    label: 'Server app, body',
    hint: "Secret in the request body, for libraries that can't send the header.",
    icon: <ServerCog className="size-5" aria-hidden />,
  },
  {
    value: 'none',
    label: 'Public app',
    hint: 'No secret. Browser and mobile apps, PKCE always on.',
    icon: <MonitorSmartphone className="size-5" aria-hidden />,
  },
];

const SCOPE_HINT: Record<string, string> = {
  openid: 'Sign-in. Always on.',
  profile: 'Name and picture.',
  email: 'Email address.',
  groups: 'Group slugs.',
  offline_access: 'Refresh tokens.',
};

function AppForm({
  c,
  initial,
  isNew,
  readOnly,
  onSaved,
}: {
  c: Console;
  initial: Form;
  isNew: boolean;
  readOnly: boolean;
  onSaved: (secret?: string, clientId?: string) => void;
}) {
  const navigate = useNavigate();
  const groups = useResource<Group[]>('/api/admin/groups');
  const [v, setV] = useState(initial);
  const [uris, setUris] = useState(initial.redirectUris.join('\n'));
  const [logoutUris, setLogoutUris] = useState(initial.postLogoutRedirectUris.join('\n'));
  const set = (patch: Partial<Form>) => setV({ ...v, ...patch });
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        const body = {
          ...v,
          redirectUris: lines(uris),
          postLogoutRedirectUris: lines(logoutUris),
          backchannelLogoutUri: v.backchannelLogoutUri || undefined,
          requiredGroup: v.requiredGroup || undefined,
        };
        const result = await c.act(
          'save',
          () =>
            isNew
              ? c.write<{ secret?: string }>('/api/admin/clients', 'POST', body)
              : c.write<{ secret?: string }>(`/api/admin/clients/${v.clientId}`, 'PUT', body),
          isNew ? undefined : 'Saved.',
        );
        if (result) onSaved(result.secret, v.clientId);
      }}
    >
      <fieldset disabled={readOnly}>
        <Section label="App" subtitle="How people and Handstamp know it.">
          <div className="grid gap-6 sm:grid-cols-2">
            <Field label="Name" required hint="Shown on the sign-in card.">
              {(id) => (
                <input
                  id={id}
                  className="input"
                  value={v.name}
                  onChange={(e) => set({ name: e.target.value })}
                  placeholder="Paramtune"
                  required
                />
              )}
            </Field>
            <Field
              label="Client ID"
              required
              hint={
                isNew ? 'Lowercase, no spaces. Cannot change later.' : "Can't change once added."
              }
            >
              {(id) => (
                <input
                  id={id}
                  className="input font-mono"
                  value={v.clientId}
                  disabled={!isNew}
                  onChange={(e) => set({ clientId: e.target.value.toLowerCase() })}
                  placeholder="paramtune"
                  required
                />
              )}
            </Field>
          </div>
        </Section>

        <Section label="Redirects" subtitle="Where Handstamp may send people back to.">
          <Field
            label="Redirect URIs"
            required
            hint="One per line, exact match. https:// only, except for localhost."
          >
            {(id) => (
              <textarea
                id={id}
                rows={3}
                className="input h-auto py-2 font-mono text-mono"
                value={uris}
                onChange={(e) => setUris(e.target.value)}
                placeholder="https://paramtune.example.com/api/auth/oauth2/callback/oidc"
                required
              />
            )}
          </Field>
          <Field
            label="Post-logout redirect URIs"
            hint="Where people may land after signing out. One per line."
          >
            {(id) => (
              <textarea
                id={id}
                rows={2}
                className="input h-auto py-2 font-mono text-mono"
                value={logoutUris}
                onChange={(e) => setLogoutUris(e.target.value)}
                placeholder="https://paramtune.example.com/"
              />
            )}
          </Field>
          <Field
            label="Back-channel logout URI"
            hint="Optional. Handstamp tells the app here when someone signs out."
          >
            {(id) => (
              <input
                id={id}
                className="input font-mono"
                value={v.backchannelLogoutUri ?? ''}
                onChange={(e) => set({ backchannelLogoutUri: e.target.value })}
                placeholder="https://paramtune.example.com/api/auth/backchannel-logout"
              />
            )}
          </Field>
        </Section>

        <Section label="Access" subtitle="What it may ask for and who gets in.">
          <fieldset>
            <legend className="label-stamp text-fg">Scopes</legend>
            <p className="mt-1 text-body-sm text-fg-muted">What the app may ask to see.</p>
            <div className="mt-2 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
              {SCOPES.map((s) => (
                <label
                  key={s}
                  className="flex cursor-pointer items-start gap-3 rounded-sm border border-border-input bg-surface-2 px-3 py-2.5 transition-colors duration-150 hover:border-border-strong has-checked:border-primary has-checked:bg-primary-soft has-focus-visible:ring-3 has-focus-visible:ring-primary/25 has-disabled:cursor-not-allowed has-disabled:hover:border-border-input light:bg-surface-1 light:has-checked:bg-primary-soft"
                >
                  <input
                    type="checkbox"
                    className="mt-0.5 size-4 accent-primary"
                    checked={v.scopes.includes(s)}
                    disabled={s === 'openid'}
                    onChange={(e) =>
                      set({
                        scopes: e.target.checked
                          ? [...v.scopes, s]
                          : v.scopes.filter((x) => x !== s),
                      })
                    }
                  />
                  <span className="min-w-0">
                    <code className="block font-mono text-mono text-fg">{s}</code>
                    <span className="block text-body-sm text-fg-muted">{SCOPE_HINT[s]}</span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>
          <Field label="Who may sign in" hint="Limit the app to one group. Others are turned away.">
            {(id) => (
              <Select
                id={id}
                value={v.requiredGroup ?? ''}
                onChange={(e) => set({ requiredGroup: e.target.value || undefined })}
              >
                <option value="">Everyone with a Handstamp account</option>
                {groups.data?.map((g) => (
                  <option key={g.slug} value={g.slug}>
                    Only members of {g.name} ({g.slug})
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Check
            checked={v.firstParty}
            onChange={(firstParty) => set({ firstParty })}
            label="One of your own apps"
            hint="Skips the “Allow this app?” screen."
          />
        </Section>

        <Section label="Security" subtitle="How the app proves who it is.">
          <Choices
            label="Client type"
            hint="Where the app runs decides whether it can keep a secret."
            value={v.tokenEndpointAuthMethod}
            options={CLIENT_TYPES}
            onChange={(method) =>
              set({
                tokenEndpointAuthMethod: method,
                requirePkce: method === 'none' ? true : v.requirePkce,
              })
            }
          />
          <Check
            checked={v.requirePkce}
            disabled={v.tokenEndpointAuthMethod === 'none'}
            onChange={(requirePkce) => set({ requirePkce })}
            label="Require PKCE"
            hint={
              v.tokenEndpointAuthMethod === 'none'
                ? 'Always on for public apps.'
                : "Leave on. Turn off only for a client that truly can't send it."
            }
          />
        </Section>
      </fieldset>
      {!readOnly && (
        <FormActions>
          <Button type="submit" variant="primary" size="md" busy={c.busy === 'save'}>
            {isNew ? 'Add app' : 'Save changes'}
          </Button>
          <Button type="button" variant="ghost" size="md" onClick={() => navigate('/admin/apps')}>
            Cancel
          </Button>
        </FormActions>
      )}
    </form>
  );
}

export function AdminNewApp() {
  return (
    <AdminPage crumbs={[['Apps', '/admin/apps'], ['New app']]}>
      {(c) => <NewAppBody c={c} />}
    </AdminPage>
  );
}

function NewAppBody({ c }: { c: Console }) {
  const navigate = useNavigate();
  return (
    <>
      <PageHeader
        eyebrow="Apps"
        title="Add an app"
        subtitle="Register a relying party. You'll get its client secret once, at the end."
      />
      <NoticeLine notice={c.notice} />
      <Panel label="App">
        <AppForm
          c={c}
          isNew
          readOnly={false}
          initial={{
            clientId: '',
            name: '',
            redirectUris: [],
            postLogoutRedirectUris: [],
            scopes: ['openid', 'profile', 'email', 'groups'],
            tokenEndpointAuthMethod: 'client_secret_basic',
            firstParty: true,
            requirePkce: true,
          }}
          onSaved={(secret, clientId) => navigate(`/admin/apps/${clientId}`, { state: { secret } })}
        />
      </Panel>
    </>
  );
}

export function AdminApp() {
  const { id = '' } = useParams();
  return (
    <AdminPage crumbs={[['Apps', '/admin/apps'], [id]]}>
      {(c) => <AppBody c={c} id={id} />}
    </AdminPage>
  );
}

function AppBody({ c, id }: { c: Console; id: string }) {
  const { data, reload } = useResource<App>(`/api/admin/clients/${id}`);
  // A brand-new app arrives with its secret in navigation state, exactly once.
  const [secret, setSecret] = useState<string | undefined>(() => {
    const handed = window.history.state?.usr?.secret as string | undefined;
    // Shown once means once: drop it from history so a reload or Back can't bring it back.
    if (handed) window.history.replaceState({ ...window.history.state, usr: {} }, '');
    return handed;
  });
  if (!data) return null;
  const readOnly = data.source !== 'db';
  const env = [
    `OIDC_ISSUER=${window.location.origin}`,
    `OIDC_CLIENT_ID=${data.clientId}`,
    `OIDC_CLIENT_SECRET=${secret ?? (data.hasSecret ? '<the secret you saved>' : '')}`,
    `OIDC_SCOPES=${data.scopes.join(' ')}`,
    'OIDC_ROLES_CLAIM=groups',
    'OIDC_ADMIN_GROUP=',
    'OIDC_DISPLAY_NAME=Handstamp',
  ].join('\n');

  return (
    <>
      <PageHeader
        eyebrow="App"
        title={data.clientId}
        identifier
        subtitle={
          <span className="flex flex-wrap items-center gap-3">
            {data.name} <Status ok={data.enabled} yes="On" no="Off" />{' '}
            <Tag>{SOURCE[data.source]}</Tag>
          </span>
        }
      />
      <NoticeLine notice={c.notice} />
      {secret && <ShownOnce title="Client secret" value={secret} />}
      {readOnly && (
        <div className="mt-8">
          <Callout tone="warning">
            {data.source === 'file'
              ? 'This app comes from the clients file (HANDSTAMP_CLIENTS_FILE). Change it there and restart Handstamp.'
              : "This is Handstamp's own console. It can't be changed."}
          </Callout>
        </div>
      )}

      <Panel label="Connect your app" action={<CopyButton value={env} label="Copy settings" />}>
        <div className="px-6 py-5">
          <p className="text-body-sm text-fg-muted">
            Any OIDC client library works. With the R.E.C. app conventions, set:
          </p>
          <pre className="mt-3 overflow-x-auto rounded-sm border border-border bg-surface-2 p-4 font-mono text-code text-fg">
            {env}
          </pre>
        </div>
      </Panel>

      <Panel label="Settings">
        <AppForm
          key={data.clientId + data.requiredGroup}
          c={c}
          initial={data}
          isNew={false}
          readOnly={readOnly}
          onSaved={(s) => {
            if (s) setSecret(s);
            void reload();
          }}
        />
      </Panel>

      {!readOnly && (
        <Panel label="Secret and status">
          <ul className="divide-y divide-border">
            {data.hasSecret && (
              <li className="flex flex-wrap items-center gap-4 px-6 py-4">
                <p className="min-w-0 flex-1 text-body text-fg">
                  Rotating creates a new secret and stops the old one immediately.{' '}
                  {data.secretRotatedAt && (
                    <span className="text-fg-muted">
                      Last rotated <When iso={data.secretRotatedAt} />.
                    </span>
                  )}
                </p>
                <Button
                  size="md"
                  variant="secondary"
                  busy={c.busy === 'rotate'}
                  onClick={async () => {
                    const result = await c.act(
                      'rotate',
                      () => c.write<{ secret: string }>(`/api/admin/clients/${id}/secret`),
                      'New secret created. Update the app now: the old one has stopped working.',
                    );
                    if (result) setSecret(result.secret);
                  }}
                >
                  Rotate secret
                </Button>
              </li>
            )}
            <li className="flex flex-wrap items-center gap-4 px-6 py-4">
              <p className="min-w-0 flex-1 text-body text-fg">
                {data.enabled
                  ? 'Turning the app off stops new sign-ins to it at once.'
                  : 'This app is off. Nobody can sign in to it.'}
              </p>
              <Button
                size="md"
                variant="secondary"
                busy={c.busy === 'enabled'}
                onClick={async () => {
                  if (
                    await c.act(
                      'enabled',
                      () =>
                        c.write(`/api/admin/clients/${id}/enabled`, 'POST', {
                          enabled: !data.enabled,
                        }),
                      data.enabled ? 'App turned off.' : 'App turned on.',
                    )
                  )
                    void reload();
                }}
              >
                {data.enabled ? 'Turn off' : 'Turn on'}
              </Button>
            </li>
          </ul>
        </Panel>
      )}
    </>
  );
}
