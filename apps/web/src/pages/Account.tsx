import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { KeyRound, LogOut, Pencil, Plus, ShieldCheck, Trash2 } from 'lucide-react';
import { api, ApiError } from '../api.ts';
import { AppShell } from '../components/AppShell.tsx';
import { Button, Callout, Loading, Tag } from '../components/ui.tsx';
import { createPasskey, defaultPasskeyName, passkeyErrorMessage } from '../lib/passkey.ts';
import { relative } from '../lib/time.ts';

type Me = {
  user: {
    sub: string;
    displayName: string;
    email: string | null;
    isAdmin: boolean;
    createdAt: string;
  };
  session: { uid: string; authTime: string; recentlyAuthenticated: boolean };
  instance: { name: string; issuer: string };
  csrf: string;
};
type Passkey = {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
  synced: boolean;
};
type Session = {
  uid: string;
  signedInAt: string | null;
  method: string;
  apps: { clientId: string; name: string }[];
  current: boolean;
};

// fresh: confirm it's you again (step-up); passkey: and do it with a passkey.
const signIn = (fresh = false, passkey = false) =>
  window.location.assign(
    `/console/login?returnTo=/account${fresh ? '&fresh=1' : ''}${passkey ? '&passkey=1' : ''}`,
  );

type Identity = {
  id: string;
  provider: string;
  providerName: string;
  loginHint: string | null;
  email: string | null;
  linkedAt: string;
  lastUsedAt: string | null;
};
type Provider = { slug: string; displayName: string };
type Activity = {
  at: string;
  action: string;
  metadata: Record<string, unknown>;
  ipPrefix: string | null;
};

const ACTIVITY_LABELS: Record<string, string> = {
  'auth.sign_in.succeeded': 'Signed in',
  'auth.sign_in.failed': 'A passkey sign-in failed',
  'passkey.added': 'Passkey added',
  'passkey.removed': 'Passkey removed',
  'identity.linked': 'Account linked',
  'identity.unlinked': 'Account unlinked',
  'recovery.issued': 'Recovery link created',
  'recovery.used': 'Recovery link used',
  'session.revoked_all': 'Signed out everywhere',
  'instance.claimed': 'Claimed this Handstamp instance',
};

const LINK_ERRORS: Record<string, string> = {
  identity_taken:
    'That account is already connected to a different Handstamp account, so we did not link it.',
  link_expired: 'That took too long, or you signed out meanwhile. Try linking again.',
  upstream_cancelled: 'Linking was cancelled.',
  upstream_failed: "We couldn't finish linking with that provider. Try again.",
  provider_unavailable: 'That sign-in option is no longer available.',
};

// Mono timestamp with the exact time on hover (DESIGN §12.3).
function When({ iso }: { iso: string | null }) {
  return (
    <time dateTime={iso ?? undefined} title={iso ?? undefined} className="font-mono text-mono-sm">
      {relative(iso)}
    </time>
  );
}

function Section({
  label,
  action,
  children,
}: {
  label: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="mt-10 rounded-sm border border-border bg-surface-1">
      <div className="flex min-h-14 items-center justify-between gap-4 border-b border-border px-6 py-3">
        <h2 className="label-stamp text-fg">{label}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}

export function Account() {
  const [me, setMe] = useState<Me>();
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [identities, setIdentities] = useState<{ linked: Identity[]; available: Provider[] }>({
    linked: [],
    available: [],
  });
  const [activity, setActivity] = useState<Activity[]>([]);
  const [busy, setBusy] = useState<string>();
  const [notice, setNotice] = useState<{ tone: 'ok' | 'error'; text: string }>();
  const [editing, setEditing] = useState<{ id: string; name: string }>();
  const [confirming, setConfirming] = useState<string>();

  const load = useCallback(async () => {
    try {
      const [m, p, s, i, a] = await Promise.all([
        api<Me>('/api/me'),
        api<Passkey[]>('/api/me/passkeys'),
        api<Session[]>('/api/me/sessions'),
        api<{ linked: Identity[]; available: Provider[] }>('/api/me/identities'),
        api<Activity[]>('/api/me/activity'),
      ]);
      setMe(m);
      setPasskeys(p);
      setSessions(s);
      setIdentities(i);
      setActivity(a);
    } catch (error) {
      if (error instanceof ApiError && error.code === 'signed_out') signIn();
      else setNotice({ tone: 'error', text: (error as Error).message });
    }
  }, []);

  useEffect(() => void load(), [load]);

  // Coming back from linking an account (?linked=github or ?error=identity_taken).
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const linked = params.get('linked');
    const error = params.get('error');
    if (linked)
      setNotice({ tone: 'ok', text: 'Linked. You can now sign in with that account too.' });
    if (error)
      setNotice({ tone: 'error', text: LINK_ERRORS[error] ?? LINK_ERRORS.upstream_failed });
    if (linked || error) window.history.replaceState(null, '', '/account');
  }, []);

  async function act(name: string, step: () => Promise<string | void>, reload = true) {
    setBusy(name);
    setNotice(undefined);
    try {
      const text = await step();
      if (reload) await load();
      if (text) setNotice({ tone: 'ok', text });
    } catch (error) {
      if (error instanceof ApiError && error.code === 'step_up_required')
        return signIn(true, error.data.method === 'passkey');
      if (error instanceof ApiError && error.code === 'signed_out') return signIn();
      setNotice({
        tone: 'error',
        text: error instanceof ApiError ? error.message : passkeyErrorMessage(error),
      });
    } finally {
      setBusy(undefined);
      setConfirming(undefined);
    }
  }

  const write = <T,>(path: string, method: string, body?: unknown) =>
    api<T>(path, { method, csrf: me!.csrf, body: body ?? {} });

  if (!me)
    return (
      <div className="grid min-h-dvh place-items-center">
        {notice ? (
          <Callout tone="danger">{notice.text}</Callout>
        ) : (
          <Loading label="Loading your account…" />
        )}
      </div>
    );

  const addPasskey = () =>
    act('add', async () => {
      const options = await write<Parameters<typeof createPasskey>[0]>(
        '/api/me/passkeys/options',
        'POST',
      );
      const response = await createPasskey(options);
      await write('/api/me/passkeys', 'POST', { response, name: defaultPasskeyName() });
      return 'Passkey added. You can now sign in with it.';
    });

  return (
    <AppShell
      user={me.user}
      instance={me.instance}
      crumb={<span className="text-fg">Account</span>}
    >
      <header className="pt-10 pb-8 md:pt-16">
        <p className="eyebrow">Your account</p>
        <h1 className="mt-2 text-[2.5rem] leading-none font-extrabold tracking-[-0.035em] text-fg md:text-title-1">
          Account<span className="text-primary">.</span>
        </h1>
        <p className="mt-3 max-w-[45ch] text-body-lg text-fg-muted">
          How you sign in, and everywhere you're signed in.
        </p>
      </header>
      <hr className="border-t-2 border-border-strong" />

      <div aria-live="polite">
        {notice && (
          <div className="mt-8">
            {notice.tone === 'error' ? (
              <Callout tone="danger">{notice.text}</Callout>
            ) : (
              <p className="flex items-center gap-2 text-body text-success-text">
                <ShieldCheck className="size-4" aria-hidden /> {notice.text}
              </p>
            )}
          </div>
        )}
      </div>

      {passkeys.length + identities.linked.length === 1 && (
        <div className="mt-8">
          <Callout tone="warning">
            {passkeys.length === 1
              ? "You have one passkey. Add a second one (another device, or your phone) so losing this one doesn't lock you out."
              : 'You can only sign in with one linked account. Add a passkey so losing access to that account doesn’t lock you out.'}
          </Callout>
        </div>
      )}

      <Section label="Profile">
        <dl className="grid gap-x-8 gap-y-5 px-6 py-6 sm:grid-cols-2">
          {[
            ['Name', <span className="text-body text-fg">{me.user.displayName}</span>],
            [
              'Email',
              me.user.email ? (
                <span className="text-body text-fg">{me.user.email}</span>
              ) : (
                <span className="text-body text-fg-subtle">Not set</span>
              ),
            ],
            ['Subject (sub)', <code className="text-mono break-all text-fg">{me.user.sub}</code>],
            ['Member since', <When iso={me.user.createdAt} />],
          ].map(([label, value]) => (
            <div key={label as string}>
              <dt className="label-stamp text-fg-subtle">{label}</dt>
              <dd className="mt-1.5 text-fg">{value}</dd>
            </div>
          ))}
        </dl>
      </Section>

      <Section
        label="Passkeys"
        action={
          <Button
            variant="primary"
            size="md"
            icon={<Plus className="size-4" aria-hidden />}
            busy={busy === 'add'}
            disabled={!!busy}
            onClick={addPasskey}
          >
            Add a passkey
          </Button>
        }
      >
        {passkeys.length === 0 && (
          <p className="px-6 py-5 text-body-sm text-fg-muted">
            No passkeys yet. A passkey is the quickest and safest way to sign in: nothing to type,
            nothing to phish.
          </p>
        )}
        <ul className="divide-y divide-border">
          {passkeys.map((passkey) => (
            <li key={passkey.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-6 py-4">
              <KeyRound className="size-5 text-fg-muted" aria-hidden />
              <div className="min-w-0 flex-1">
                {editing?.id === passkey.id ? (
                  <form
                    className="flex gap-2"
                    onSubmit={(e) => {
                      e.preventDefault();
                      void act('rename', async () => {
                        await write(`/api/me/passkeys/${passkey.id}`, 'PATCH', {
                          name: editing.name,
                        });
                        setEditing(undefined);
                      });
                    }}
                  >
                    <label className="sr-only" htmlFor={`name-${passkey.id}`}>
                      Passkey name
                    </label>
                    <input
                      id={`name-${passkey.id}`}
                      className="input h-9"
                      value={editing.name}
                      maxLength={60}
                      autoFocus
                      onChange={(e) => setEditing({ id: passkey.id, name: e.target.value })}
                    />
                    <Button type="submit" size="md" busy={busy === 'rename'}>
                      Save
                    </Button>
                    <Button
                      type="button"
                      size="md"
                      variant="ghost"
                      onClick={() => setEditing(undefined)}
                    >
                      Cancel
                    </Button>
                  </form>
                ) : (
                  <>
                    <p className="flex flex-wrap items-center gap-2 text-body font-semibold text-fg">
                      {passkey.name}
                      {passkey.synced ? <Tag tone="info">Synced</Tag> : <Tag>This device only</Tag>}
                    </p>
                    <p className="mt-0.5 text-body-sm text-fg-muted">
                      Added <When iso={passkey.createdAt} /> · last used{' '}
                      <When iso={passkey.lastUsedAt} />
                    </p>
                  </>
                )}
              </div>
              {editing?.id !== passkey.id &&
                (confirming === passkey.id ? (
                  <div className="flex items-center gap-2">
                    <span className="text-body-sm text-fg">Remove “{passkey.name}”?</span>
                    <Button
                      size="md"
                      variant="danger"
                      busy={busy === 'remove'}
                      onClick={() =>
                        act('remove', async () => {
                          await write(`/api/me/passkeys/${passkey.id}`, 'DELETE');
                          return `Removed “${passkey.name}”. It can't sign in any more.`;
                        })
                      }
                    >
                      Remove
                    </Button>
                    <Button size="md" variant="ghost" onClick={() => setConfirming(undefined)}>
                      Keep
                    </Button>
                  </div>
                ) : (
                  <div className="flex gap-1">
                    <Button
                      size="md"
                      variant="ghost"
                      aria-label={`Rename ${passkey.name}`}
                      icon={<Pencil className="size-4" aria-hidden />}
                      onClick={() => setEditing({ id: passkey.id, name: passkey.name })}
                    >
                      <span className="hidden sm:inline">Rename</span>
                    </Button>
                    <Button
                      size="md"
                      variant="ghost"
                      aria-label={`Remove ${passkey.name}`}
                      icon={<Trash2 className="size-4" aria-hidden />}
                      onClick={() => setConfirming(passkey.id)}
                    >
                      <span className="hidden sm:inline">Remove</span>
                    </Button>
                  </div>
                ))}
            </li>
          ))}
        </ul>
      </Section>

      <Section label="Linked accounts">
        {identities.linked.length === 0 && identities.available.length === 0 ? (
          <p className="px-6 py-5 text-body-sm text-fg-muted">
            No other sign-in providers are set up on this instance.
          </p>
        ) : (
          <ul className="divide-y divide-border">
            {identities.linked.map((identity) => (
              <li
                key={identity.id}
                className="flex flex-wrap items-center gap-x-4 gap-y-2 px-6 py-4"
              >
                <div className="min-w-0 flex-1">
                  <p className="text-body font-semibold text-fg">
                    {identity.providerName}{' '}
                    <span className="font-mono text-mono-sm font-normal text-fg-muted">
                      {identity.loginHint ?? identity.email}
                    </span>
                  </p>
                  <p className="mt-0.5 text-body-sm text-fg-muted">
                    Linked <When iso={identity.linkedAt} /> · last used{' '}
                    <When iso={identity.lastUsedAt} />
                  </p>
                </div>
                {confirming === identity.id ? (
                  <div className="flex items-center gap-2">
                    <span className="text-body-sm text-fg">Unlink {identity.providerName}?</span>
                    <Button
                      size="md"
                      variant="danger"
                      busy={busy === 'unlink'}
                      onClick={() =>
                        act('unlink', async () => {
                          await write(`/api/me/identities/${identity.id}`, 'DELETE');
                          return `${identity.providerName} is unlinked. It can't sign you in any more.`;
                        })
                      }
                    >
                      Unlink
                    </Button>
                    <Button size="md" variant="ghost" onClick={() => setConfirming(undefined)}>
                      Keep
                    </Button>
                  </div>
                ) : (
                  <Button size="md" variant="ghost" onClick={() => setConfirming(identity.id)}>
                    Unlink
                  </Button>
                )}
              </li>
            ))}
            {identities.available.map((provider) => (
              <li
                key={provider.slug}
                className="flex flex-wrap items-center gap-x-4 gap-y-2 px-6 py-4"
              >
                <p className="min-w-0 flex-1 text-body text-fg-muted">
                  {provider.displayName} <span className="text-fg-subtle">· not linked</span>
                </p>
                <Button
                  size="md"
                  variant="secondary"
                  busy={busy === provider.slug}
                  disabled={!!busy}
                  onClick={() =>
                    act(
                      provider.slug,
                      async () => {
                        const { redirectTo } = await write<{ redirectTo: string }>(
                          `/api/me/identities/link/${provider.slug}`,
                          'POST',
                        );
                        window.location.assign(redirectTo);
                      },
                      false,
                    )
                  }
                >
                  Link {provider.displayName}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section label="Where you're signed in">
        <ul className="divide-y divide-border">
          {sessions.map((session) => (
            <li key={session.uid} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-6 py-4">
              <div className="min-w-0 flex-1">
                <p className="flex flex-wrap items-center gap-2 text-body font-semibold text-fg">
                  Signed in <When iso={session.signedInAt} />
                  {session.current && <Tag tone="success">This browser</Tag>}
                </p>
                <p className="mt-0.5 text-body-sm text-fg-muted">
                  With a {session.method === 'passkey' ? 'passkey' : 'linked account'} ·{' '}
                  {session.apps.map((a) => a.name).join(', ') || 'no apps yet'}
                </p>
              </div>
              {!session.current && (
                <Button
                  size="md"
                  variant="ghost"
                  busy={busy === session.uid}
                  disabled={!!busy}
                  onClick={() =>
                    act(session.uid, async () => {
                      await write(`/api/me/sessions/${session.uid}`, 'DELETE');
                      return 'Signed out of that session.';
                    })
                  }
                >
                  Sign out
                </Button>
              )}
            </li>
          ))}
        </ul>
        <div className="flex flex-wrap items-center justify-between gap-4 border-t border-border px-6 py-4">
          <p className="max-w-[60ch] text-body-sm text-fg-muted">
            Lost a device? Signing out everywhere ends every session above and tells your apps right
            away.
          </p>
          {confirming === 'everywhere' ? (
            <div className="flex gap-2">
              <Button
                size="md"
                variant="danger"
                icon={<LogOut className="size-4" aria-hidden />}
                busy={busy === 'everywhere'}
                onClick={() =>
                  act(
                    'everywhere',
                    async () => {
                      await write('/api/me/sign-out-everywhere', 'POST');
                      window.location.assign('/signed-out');
                    },
                    false, // this session is gone too: don't reload, just leave
                  )
                }
              >
                Yes, sign out everywhere
              </Button>
              <Button size="md" variant="ghost" onClick={() => setConfirming(undefined)}>
                Cancel
              </Button>
            </div>
          ) : (
            <Button size="md" variant="secondary" onClick={() => setConfirming('everywhere')}>
              Sign out everywhere
            </Button>
          )}
        </div>
      </Section>

      <Section label="Recent security activity">
        {activity.length === 0 ? (
          <p className="px-6 py-5 text-body-sm text-fg-muted">Nothing yet.</p>
        ) : (
          <ul className="divide-y divide-border">
            {activity.map((event, index) => (
              <li key={index} className="flex flex-wrap items-baseline gap-x-4 gap-y-1 px-6 py-3">
                <span className="min-w-0 flex-1 text-body text-fg">
                  {ACTIVITY_LABELS[event.action] ?? event.action}
                  {typeof event.metadata.method === 'string' && (
                    <span className="text-fg-muted">
                      {' '}
                      · {String(event.metadata.method).replace(/_/g, ' ')}
                    </span>
                  )}
                </span>
                <span className="font-mono text-mono-sm text-fg-subtle">
                  {event.ipPrefix ?? ''}
                </span>
                <When iso={event.at} />
              </li>
            ))}
          </ul>
        )}
      </Section>
    </AppShell>
  );
}
