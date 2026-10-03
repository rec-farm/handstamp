import { useEffect, useState, type ReactNode } from 'react';
import { useParams } from 'react-router';
import { FlaskConical, KeyRound } from 'lucide-react';
import { api, ApiError } from '../api.ts';
import { Button, Callout, CardPage, Field, Loading, Title } from '../components/ui.tsx';
import {
  createPasskey,
  defaultPasskeyName,
  passkeyErrorMessage,
  passkeysSupported,
  signWithPasskey,
} from '../lib/passkey.ts';

type Details = {
  uid: string;
  prompt: { name: 'login' | 'consent' | 'access'; reasons: string[]; missingScopes: string[] };
  client: { clientId: string; name: string };
  instanceName: string;
  issuer: string;
  devLogin: boolean;
  mode: 'sign-in' | 'claim' | 'invite' | 'recovery';
  setupVerified: boolean;
  enrollingAs?: string;
  passkeyOnly: boolean;
  providers: { slug: string; kind: string; displayName: string }[];
  requiredGroup?: { slug: string; name: string };
  csrf: string;
};

// Why an upstream sign-in came back to the card (?error=…). Same message whether or not the
// email exists here, so the card never confirms who has an account (§3.3).
const RETURN_ERRORS: Record<string, string> = {
  unlinked_identity:
    "That account isn't connected to Handstamp yet. Sign in another way and link it from your account page, or ask your admin for an invite.",
  email_domain:
    "Sign-up here is limited to certain email domains, and this account's email isn't one of them. Ask your admin for an invite.",
  org: 'Sign-up here is limited to members of certain GitHub organizations. Ask your admin for an invite.',
  identity_taken: 'That account is already connected to a different Handstamp account.',
  account_disabled: 'This account is turned off. Ask your admin.',
  upstream_cancelled: 'Sign-in was cancelled. Pick a way to sign in when you are ready.',
  upstream_failed: "We couldn't finish signing in with that provider. Try again, or use a passkey.",
  upstream_expired: 'That took too long. Try again.',
  provider_unavailable: 'That sign-in option is no longer available. Pick another one.',
  enrollment_expired: 'This link has expired or was already used. Ask your admin for a new one.',
};

type Post = <T = { redirectTo: string }>(path: string, body?: unknown) => Promise<T>;
type Run = (name: string, step: () => Promise<void>) => Promise<void>;

const SCOPE_LABELS: Record<string, string> = {
  profile: 'See your name and username',
  email: 'See your email address',
  groups: 'See which groups you belong to',
  offline_access: 'Stay signed in while you are away',
};

// The eyebrow names the instance, unless that would just repeat the wordmark above the card.
function Eyebrow({ name }: { name: string }) {
  return name.toLowerCase() === 'handstamp' ? null : <p className="eyebrow mb-2">{name}</p>;
}

const go = ({ redirectTo }: { redirectTo: string }) => window.location.assign(redirectTo);

export function Interaction() {
  const { uid = '' } = useParams();
  const [details, setDetails] = useState<Details>();
  const [problem, setProblem] = useState<string | undefined>(() => {
    const code = new URLSearchParams(window.location.search).get('error');
    return code ? (RETURN_ERRORS[code] ?? RETURN_ERRORS.upstream_failed) : undefined;
  });
  const [busy, setBusy] = useState<string>();

  useEffect(() => {
    // Don't show an old error again on reload.
    if (window.location.search) window.history.replaceState(null, '', window.location.pathname);
    api<Details>(`/interaction/${encodeURIComponent(uid)}/details`)
      .then(setDetails)
      .catch((error: ApiError) => setProblem(error.message));
  }, [uid]);

  const post: Post = (path, body = {}) =>
    api(`/interaction/${encodeURIComponent(uid)}/${path}`, {
      method: 'POST',
      csrf: details!.csrf,
      body,
    });

  // Runs one step; on failure shows the server's (or browser's) message and stays on the card.
  const run: Run = async (name, step) => {
    setBusy(name);
    setProblem(undefined);
    try {
      await step();
    } catch (error) {
      setProblem(error instanceof ApiError ? error.message : passkeyErrorMessage(error));
      setBusy(undefined);
    }
  };

  const footer = details && (
    <>
      {details.client.clientId} · {new URL(details.issuer).host}
    </>
  );
  const error = problem && (
    <div className="mt-4">
      <Callout tone="danger">{problem}</Callout>
    </div>
  );

  if (!details)
    return (
      <CardPage>
        {problem ? (
          <div className="space-y-4">
            <Title>This sign-in has ended</Title>
            <Callout tone="danger">{problem}</Callout>
          </div>
        ) : (
          <Loading label="Getting your sign-in ready…" />
        )}
      </CardPage>
    );

  const upstreamButtons = (verb: string) =>
    details.providers.map((p) => (
      <Button
        key={p.slug}
        variant="secondary"
        disabled={!!busy}
        onClick={() => {
          setBusy(p.slug);
          window.location.assign(`/interaction/${encodeURIComponent(uid)}/upstream/${p.slug}`);
        }}
        busy={busy === p.slug}
      >
        {verb} {p.displayName}
      </Button>
    ));

  if (details.mode === 'invite' || details.mode === 'recovery')
    return (
      <Enroll
        details={details}
        post={post}
        run={run}
        busy={busy}
        error={error}
        footer={footer}
        upstream={upstreamButtons(details.mode === 'invite' ? 'Join with' : 'Use')}
      />
    );

  if (details.mode === 'claim')
    return (
      <Claim
        details={details}
        post={post}
        run={run}
        busy={busy}
        error={error}
        onVerified={() => setDetails({ ...details, setupVerified: true })}
        footer={footer}
      />
    );

  // The app only lets one group in, and this person isn't in it (R7).
  if (details.prompt.name === 'access')
    return (
      <CardPage footer={footer}>
        <Eyebrow name={details.instanceName} />
        <Title>No access to {details.client.name}</Title>
        <p className="mt-3 text-body text-fg-muted">
          Only members of {details.requiredGroup?.name ?? 'a certain group'} can use{' '}
          {details.client.name}. If you should have access, ask your admin to add you to{' '}
          <code className="font-mono text-mono text-fg">{details.requiredGroup?.slug}</code>.
        </p>
        {error}
        <div className="mt-6">
          <Button
            variant="secondary"
            busy={busy === 'abort'}
            disabled={!!busy}
            onClick={() => run('abort', async () => go(await post('abort')))}
          >
            Back to {details.client.name}
          </Button>
        </div>
      </CardPage>
    );

  if (details.prompt.name === 'consent') {
    const scopes = details.prompt.missingScopes.filter((scope) => SCOPE_LABELS[scope]);
    return (
      <CardPage footer={footer}>
        <Eyebrow name={details.instanceName} />
        <Title>Allow {details.client.name}</Title>
        <p className="mt-3 text-body text-fg-muted">
          {details.client.name} wants to know who you are{scopes.length ? ', and to:' : '.'}
        </p>
        {scopes.length > 0 && (
          <ul className="mt-3 space-y-2 text-body text-fg">
            {scopes.map((scope) => (
              <li key={scope} className="flex items-baseline gap-2">
                <span aria-hidden className="text-fg-subtle">
                  ·
                </span>
                {SCOPE_LABELS[scope]}
              </li>
            ))}
          </ul>
        )}
        {error}
        <div className="mt-6 space-y-3">
          <Button
            variant="primary"
            busy={busy === 'consent'}
            disabled={!!busy}
            onClick={() => run('consent', async () => go(await post('consent')))}
          >
            Allow
          </Button>
          <Button
            variant="ghost"
            busy={busy === 'abort'}
            disabled={!!busy}
            onClick={() => run('abort', async () => go(await post('abort')))}
          >
            Cancel
          </Button>
        </div>
      </CardPage>
    );
  }

  return (
    <CardPage footer={footer}>
      <Eyebrow name={details.instanceName} />
      <Title>
        {details.passkeyOnly ? "Confirm it's you" : `Sign in to ${details.client.name}`}
      </Title>
      <p className="mt-3 text-body text-fg-muted">
        {details.passkeyOnly
          ? 'You are about to change how you sign in, so we need your passkey once more.'
          : 'Use the passkey on this device, or on your phone.'}
      </p>
      <div className="mt-6 space-y-3">
        {passkeysSupported() ? (
          <Button
            variant="primary"
            icon={<KeyRound className="size-[18px]" aria-hidden />}
            busy={busy === 'passkey'}
            disabled={!!busy}
            onClick={() =>
              run('passkey', async () => {
                const options =
                  await post<Parameters<typeof signWithPasskey>[0]>('passkey/options');
                go(await post('passkey/verify', { response: await signWithPasskey(options) }));
              })
            }
          >
            Continue with a passkey
          </Button>
        ) : (
          <Callout tone="warning">
            This browser can't use passkeys. Open this page in an up-to-date browser.
          </Callout>
        )}
        {details.providers.length > 0 && (
          <div className="flex items-center gap-3 py-1 text-caption text-fg-subtle">
            <span className="h-px flex-1 bg-border" />
            or
            <span className="h-px flex-1 bg-border" />
          </div>
        )}
        {upstreamButtons('Continue with')}
        {details.devLogin && !details.passkeyOnly && (
          <Button
            variant="secondary"
            icon={<FlaskConical className="size-[18px]" aria-hidden />}
            busy={busy === 'dev-login'}
            disabled={!!busy}
            onClick={() => run('dev-login', async () => go(await post('dev-login')))}
          >
            Continue as test user
          </Button>
        )}
      </div>
      {details.devLogin && (
        <p className="mt-3 text-body-sm text-fg-muted">
          Development sign-in is on. Anyone can use the test account.
        </p>
      )}
      {error}
      <div className="mt-3">
        <Button
          variant="ghost"
          busy={busy === 'abort'}
          disabled={!!busy}
          onClick={() => run('abort', async () => go(await post('abort')))}
        >
          Cancel and go back
        </Button>
      </div>
    </CardPage>
  );
}

// First-run setup: whoever holds the code from the server logs becomes the first admin.
function Claim(props: {
  details: Details;
  post: Post;
  run: Run;
  busy?: string;
  error: ReactNode;
  onVerified: () => void;
  footer: ReactNode;
}) {
  const { details, post, run, busy, error, onVerified, footer } = props;
  const [code, setCode] = useState('');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');

  function verify(event: { preventDefault(): void }) {
    event.preventDefault();
    void run('verify', async () => {
      await post('setup/verify', { code });
      onVerified();
    });
  }

  function claim(event: { preventDefault(): void }) {
    event.preventDefault();
    void run('claim', async () => {
      const options = await post<Parameters<typeof createPasskey>[0]>('setup/passkey/options', {
        displayName: name,
        email,
      });
      const response = await createPasskey(options);
      go(await post('setup/passkey/verify', { response, name: defaultPasskeyName() }));
    });
  }

  return (
    <CardPage footer={footer}>
      <p className="eyebrow mb-2">First-run setup</p>
      <Title>Claim this instance</Title>
      {!details.setupVerified ? (
        <form onSubmit={verify} className="mt-3">
          <p className="text-body text-fg-muted">
            Handstamp printed a one-time setup code in its server logs. Enter it to become the first
            admin.
          </p>
          <div className="mt-6">
            <Field label="Setup code" required>
              {(id) => (
                <input
                  id={id}
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  placeholder="HS-XXXXX-XXXXX-XXXXX-XXXXX"
                  autoComplete="one-time-code"
                  spellCheck={false}
                  autoFocus
                  required
                  className="input font-mono uppercase"
                />
              )}
            </Field>
          </div>
          {error}
          <div className="mt-6">
            <Button
              type="submit"
              variant="primary"
              busy={busy === 'verify'}
              disabled={!code.trim()}
            >
              Continue
            </Button>
          </div>
        </form>
      ) : (
        <form onSubmit={claim} className="mt-3">
          <p className="text-body text-fg-muted">
            Code accepted. Tell us who you are, then create the passkey you'll sign in with.
          </p>
          <div className="mt-6 space-y-6">
            <Field label="Your name" required>
              {(id) => (
                <input
                  id={id}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  autoComplete="name"
                  autoFocus
                  required
                  className="input"
                />
              )}
            </Field>
            <Field label="Email" hint="Optional. Apps only see it if you let them.">
              {(id) => (
                <input
                  id={id}
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email"
                  className="input"
                />
              )}
            </Field>
          </div>
          {error}
          <div className="mt-6">
            <Button
              type="submit"
              variant="primary"
              icon={<KeyRound className="size-[18px]" aria-hidden />}
              busy={busy === 'claim'}
              disabled={!name.trim()}
            >
              Create passkey and finish
            </Button>
          </div>
        </form>
      )}
    </CardPage>
  );
}

// An invite ("join") or recovery link in progress: create a new passkey, or use an upstream account.
function Enroll(props: {
  details: Details;
  post: Post;
  run: Run;
  busy?: string;
  error: ReactNode;
  footer: ReactNode;
  upstream: ReactNode[];
}) {
  const { details, post, run, busy, error, footer, upstream } = props;
  const invite = details.mode === 'invite';
  const [name, setName] = useState('');

  function create(event: { preventDefault(): void }) {
    event.preventDefault();
    void run('enroll', async () => {
      const options = await post<Parameters<typeof createPasskey>[0]>('enroll/passkey/options', {
        displayName: name,
      });
      const response = await createPasskey(options);
      go(await post('enroll/passkey/verify', { response, name: defaultPasskeyName() }));
    });
  }

  return (
    <CardPage footer={footer}>
      <p className="eyebrow mb-2">{invite ? 'Invitation' : 'Account recovery'}</p>
      <Title>{invite ? `Join ${details.instanceName}` : 'Recover your account'}</Title>
      <p className="mt-3 text-body text-fg-muted">
        {invite
          ? 'Create the passkey you will sign in with. It stays on this device, or syncs with your password manager.'
          : `Create a new passkey for ${details.enrollingAs ?? 'your account'}. You'll be signed in right after.`}
      </p>
      <form onSubmit={create} className="mt-6 space-y-6">
        {invite && (
          <Field label="Your name" required>
            {(id) => (
              <input
                id={id}
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoComplete="name"
                autoFocus
                required
                className="input"
              />
            )}
          </Field>
        )}
        <Button
          type="submit"
          variant="primary"
          icon={<KeyRound className="size-[18px]" aria-hidden />}
          busy={busy === 'enroll'}
          disabled={!!busy || (invite && !name.trim())}
        >
          {invite ? 'Create passkey and join' : 'Create a new passkey'}
        </Button>
      </form>
      {upstream.length > 0 && (
        <div className="mt-3 space-y-3">
          <div className="flex items-center gap-3 py-1 text-caption text-fg-subtle">
            <span className="h-px flex-1 bg-border" />
            or
            <span className="h-px flex-1 bg-border" />
          </div>
          {upstream}
        </div>
      )}
      {error}
    </CardPage>
  );
}
