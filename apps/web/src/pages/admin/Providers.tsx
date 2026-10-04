import { useId, useState, type ReactNode } from 'react';
import { Globe, Plus } from 'lucide-react';
import {
  CopyButton,
  Empty,
  NoticeLine,
  PageHeader,
  Panel,
  Status,
} from '../../components/admin.tsx';
import { GitHubMark, GoogleMark } from '../../components/brand-icons.tsx';
import { Button, Choices, Field, Tag, type Choice } from '../../components/ui.tsx';
import { useResource } from '../../lib/console.tsx';
import { AdminPage, type Console } from './AdminPage.tsx';

type Provider = {
  slug: string;
  kind: 'github' | 'google' | 'oidc';
  displayName: string;
  issuer: string;
  apiUrl: string | null;
  clientId: string;
  allowSignup: boolean;
  allowedEmailDomains: string[];
  githubAllowedOrgs: string[];
  trustEmailVerified: boolean;
  enabled: boolean;
  source: 'env' | 'db';
};

const KIND = { github: 'GitHub', google: 'Google', oidc: 'OIDC' };
const KIND_ICON = {
  github: (cls: string) => <GitHubMark className={cls} />,
  google: (cls: string) => <GoogleMark className={cls} />,
  oidc: (cls: string) => <Globe className={cls} aria-hidden />,
};
const KINDS: Choice<Provider['kind']>[] = [
  {
    value: 'github',
    label: 'GitHub',
    hint: 'github.com or GitHub Enterprise.',
    icon: KIND_ICON.github('size-5'),
  },
  {
    value: 'google',
    label: 'Google',
    hint: 'Google accounts and Workspace.',
    icon: KIND_ICON.google('size-5'),
  },
  {
    value: 'oidc',
    label: 'OIDC',
    hint: 'Okta, Entra ID, Keycloak or any issuer.',
    icon: KIND_ICON.oidc('size-5'),
  },
];
// The button label we fill in for each kind, so switching kinds doesn't keep a stale one.
const DEFAULT_LABEL = { github: 'GitHub', google: 'Google', oidc: '' };

const list = (s: string) =>
  s
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);

// One block of the form: a stamp and a line of context on the left, the fields on the right
// (DESIGN §10.7 card header, §11.3 sections with a divider).
function Section({
  label,
  subtitle,
  children,
}: {
  label: string;
  subtitle: string;
  children: ReactNode;
}) {
  const id = useId();
  return (
    <div
      role="group"
      aria-labelledby={id}
      className="grid gap-x-10 gap-y-5 border-b border-border px-6 py-6 lg:grid-cols-[14rem_minmax(0,1fr)]"
    >
      <div>
        <h3 id={id} className="label-stamp text-fg">
          {label}
        </h3>
        <p className="mt-1 text-body-sm text-fg-muted">{subtitle}</p>
      </div>
      <div className="space-y-6">{children}</div>
    </div>
  );
}

function Check({
  checked,
  onChange,
  label,
  hint,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  hint: string;
}) {
  return (
    <label className="flex items-start gap-3 text-body text-fg">
      <input
        type="checkbox"
        className="mt-0.5 size-4 accent-primary"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        {label}
        <span className="mt-0.5 block text-body-sm text-fg-muted">{hint}</span>
      </span>
    </label>
  );
}

function ProviderForm({
  c,
  initial,
  isNew,
  onSaved,
  onCancel,
}: {
  c: Console;
  initial: Provider;
  isNew: boolean;
  onSaved: () => void;
  onCancel: () => void;
}) {
  const [v, setV] = useState({
    ...initial,
    clientSecret: '',
    domains: initial.allowedEmailDomains.join(', '),
    orgs: initial.githubAllowedOrgs.join(', '),
  });
  const set = (patch: Partial<typeof v>) => setV({ ...v, ...patch });
  const callback = `${window.location.origin}/upstream/${v.slug || '<slug>'}/callback`;
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        const body = {
          slug: v.slug,
          kind: v.kind,
          displayName: v.displayName,
          issuer: v.issuer,
          clientId: v.clientId,
          clientSecret: v.clientSecret || undefined,
          allowSignup: v.allowSignup,
          allowedEmailDomains: list(v.domains),
          githubAllowedOrgs: list(v.orgs),
          trustEmailVerified: v.trustEmailVerified,
        };
        const ok = await c.act(
          'save',
          () =>
            isNew
              ? c.write('/api/admin/providers', 'POST', body)
              : c.write(`/api/admin/providers/${v.slug}`, 'PUT', body),
          isNew ? `Added ${v.displayName}.` : 'Saved.',
        );
        if (ok) onSaved();
      }}
    >
      <Section label="Provider" subtitle="Where people already have an account.">
        <Choices
          label="Kind"
          hint={isNew ? 'Pick where the accounts live.' : "Can't change once added."}
          value={v.kind}
          options={KINDS}
          disabled={!isNew}
          onChange={(kind) =>
            set({
              kind,
              issuer: '',
              orgs: kind === 'github' ? v.orgs : '',
              trustEmailVerified: kind === 'oidc' && v.trustEmailVerified,
              displayName:
                v.displayName === DEFAULT_LABEL[v.kind] ? DEFAULT_LABEL[kind] : v.displayName,
            })
          }
        />
        <div className="grid gap-6 sm:grid-cols-2">
          <Field label="Button label" required hint="Shown on the sign-in page.">
            {(id) => (
              <input
                id={id}
                className="input"
                value={v.displayName}
                onChange={(e) => set({ displayName: e.target.value })}
                placeholder="Corp SSO"
                required
              />
            )}
          </Field>
          <Field
            label="Short name"
            required
            hint={isNew ? 'Lowercase. Part of the callback URL.' : "Can't change once added."}
          >
            {(id) => (
              <input
                id={id}
                className="input font-mono"
                value={v.slug}
                disabled={!isNew}
                onChange={(e) => set({ slug: e.target.value.toLowerCase() })}
                placeholder="corp-sso"
                required
              />
            )}
          </Field>
        </div>
        {v.kind !== 'google' && (
          <Field
            label={v.kind === 'github' ? 'GitHub URL' : 'Issuer'}
            required={v.kind === 'oidc'}
            hint={
              v.kind === 'github'
                ? 'Only for GitHub Enterprise. Empty: github.com.'
                : 'Handstamp reads its settings from /.well-known/openid-configuration.'
            }
          >
            {(id) => (
              <input
                id={id}
                className="input font-mono"
                value={v.issuer}
                onChange={(e) => set({ issuer: e.target.value })}
                placeholder={v.kind === 'github' ? 'https://github.com' : 'https://sso.example.com'}
                required={v.kind === 'oidc'}
              />
            )}
          </Field>
        )}
      </Section>

      <Section label="Credentials" subtitle="From the app you register at the provider.">
        <div>
          <p className="label-stamp text-fg">Callback URL</p>
          <p className="mt-1 text-body-sm text-fg-muted">Register this at the provider first.</p>
          <div className="mt-2 flex flex-wrap items-center gap-3">
            <code className="min-w-0 flex-1 rounded-xs border border-border-input bg-surface-2 px-3 py-2 font-mono text-mono break-all text-fg light:bg-surface-1">
              {callback}
            </code>
            <CopyButton value={callback} />
          </div>
        </div>
        <div className="grid gap-6 sm:grid-cols-2">
          <Field label="Client ID" required hint="Public, shown in the provider's app.">
            {(id) => (
              <input
                id={id}
                className="input font-mono"
                value={v.clientId}
                onChange={(e) => set({ clientId: e.target.value })}
                required
              />
            )}
          </Field>
          <Field
            label="Client secret"
            required={isNew}
            hint={isNew ? 'Stored encrypted, never shown again.' : 'Empty: keep the current one.'}
          >
            {(id) => (
              <input
                id={id}
                type="password"
                autoComplete="off"
                className="input font-mono"
                value={v.clientSecret}
                onChange={(e) => set({ clientSecret: e.target.value })}
                required={isNew}
              />
            )}
          </Field>
        </div>
      </Section>

      <Section label="Who can sign up" subtitle="Who this provider lets in.">
        <Check
          checked={v.allowSignup}
          onChange={(allowSignup) => set({ allowSignup })}
          label="New people may create an account with it"
          hint="Off: only people who already have an account (or an invite) can use it."
        />
        <div className="grid gap-6 sm:grid-cols-2">
          <Field label="Only these email domains" hint="Comma-separated. Empty: any.">
            {(id) => (
              <input
                id={id}
                className="input font-mono"
                value={v.domains}
                onChange={(e) => set({ domains: e.target.value })}
                placeholder="example.com"
              />
            )}
          </Field>
          {v.kind === 'github' && (
            <Field label="Only these GitHub orgs" hint="Comma-separated. Empty: any.">
              {(id) => (
                <input
                  id={id}
                  className="input font-mono"
                  value={v.orgs}
                  onChange={(e) => set({ orgs: e.target.value })}
                  placeholder="my-org"
                />
              )}
            </Field>
          )}
        </div>
        {v.kind === 'oidc' && (
          <Check
            checked={v.trustEmailVerified}
            onChange={(trustEmailVerified) => set({ trustEmailVerified })}
            label="Trust its verified emails"
            hint="Only if this issuer really checks email ownership. Apps then see the email as verified."
          />
        )}
      </Section>

      <div className="flex flex-wrap gap-3 px-6 py-5 lg:pl-[calc(14rem+4rem)]">
        <Button type="submit" variant="primary" size="md" busy={c.busy === 'save'}>
          {isNew ? 'Add provider' : 'Save changes'}
        </Button>
        <Button type="button" variant="ghost" size="md" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

export function AdminProviders() {
  return <AdminPage crumbs={[['Sign-in providers']]}>{(c) => <ProvidersBody c={c} />}</AdminPage>;
}

function ProvidersBody({ c }: { c: Console }) {
  const { data, reload } = useResource<Provider[]>('/api/admin/providers');
  const [editing, setEditing] = useState<string>();
  const blank: Provider = {
    slug: '',
    kind: 'github',
    displayName: 'GitHub',
    issuer: '',
    apiUrl: null,
    clientId: '',
    allowSignup: false,
    allowedEmailDomains: [],
    githubAllowedOrgs: [],
    trustEmailVerified: false,
    enabled: true,
    source: 'db',
  };
  return (
    <>
      <PageHeader
        eyebrow="Continue with…"
        title="Sign-in providers"
        subtitle="Accounts people already have elsewhere. Matched by that account's id, never by email."
        action={
          editing !== 'new' && (
            <Button
              variant="primary"
              size="md"
              icon={<Plus className="size-4" aria-hidden />}
              onClick={() => setEditing('new')}
            >
              Add provider
            </Button>
          )
        }
      />
      <NoticeLine notice={c.notice} />
      {editing === 'new' && (
        <Panel label="New provider">
          <ProviderForm
            c={c}
            initial={blank}
            isNew
            onSaved={() => {
              setEditing(undefined);
              void reload();
            }}
            onCancel={() => setEditing(undefined)}
          />
        </Panel>
      )}
      {data?.length === 0 && editing !== 'new' && (
        <Panel label="Providers">
          <Empty>No sign-in providers yet. People sign in with passkeys only.</Empty>
        </Panel>
      )}
      {data?.map((p) => (
        <Panel
          key={p.slug}
          label={p.displayName}
          action={
            <span className="flex items-center gap-3">
              <Tag>
                {KIND_ICON[p.kind]('size-3.5')}
                {KIND[p.kind]}
              </Tag>
              <Status ok={p.enabled} yes="On" no="Off" />
              {p.source === 'db' && editing !== p.slug && (
                <>
                  <Button size="md" variant="ghost" onClick={() => setEditing(p.slug)}>
                    Edit
                  </Button>
                  <Button
                    size="md"
                    variant="secondary"
                    busy={c.busy === p.slug}
                    onClick={async () => {
                      if (
                        await c.act(
                          p.slug,
                          () =>
                            c.write(`/api/admin/providers/${p.slug}/enabled`, 'POST', {
                              enabled: !p.enabled,
                            }),
                          p.enabled
                            ? `${p.displayName} turned off.`
                            : `${p.displayName} turned on.`,
                        )
                      )
                        void reload();
                    }}
                  >
                    {p.enabled ? 'Turn off' : 'Turn on'}
                  </Button>
                </>
              )}
            </span>
          }
        >
          {editing === p.slug ? (
            <ProviderForm
              c={c}
              initial={p}
              isNew={false}
              onSaved={() => {
                setEditing(undefined);
                void reload();
              }}
              onCancel={() => setEditing(undefined)}
            />
          ) : (
            <div className="space-y-2 px-6 py-4 text-body-sm text-fg-muted">
              <p>
                <code className="font-mono text-mono text-fg">{p.issuer}</code> · client{' '}
                <code className="font-mono text-mono text-fg">{p.clientId}</code>
              </p>
              <p>
                {p.allowSignup ? 'New people can sign up' : 'Existing accounts only'}
                {p.allowedEmailDomains.length > 0 &&
                  ` · emails @${p.allowedEmailDomains.join(', @')}`}
                {p.githubAllowedOrgs.length > 0 && ` · orgs ${p.githubAllowedOrgs.join(', ')}`}
                {p.kind === 'oidc' &&
                  (p.trustEmailVerified ? ' · verified emails trusted' : ' · emails not trusted')}
              </p>
              {p.source === 'env' && (
                <p>Configured through environment variables, so it's read-only here.</p>
              )}
            </div>
          )}
        </Panel>
      ))}
    </>
  );
}
