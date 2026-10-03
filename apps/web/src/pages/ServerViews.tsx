import { useState } from 'react';
import { Button, CardPage, Title } from '../components/ui.tsx';

// Rendered by oidc-provider hooks with their data on <html data-hs-*> (see apps/server/src/http/shell.ts).

export function Logout({ xsrf, action, client }: { xsrf: string; action: string; client: string }) {
  const [everywhere, setEverywhere] = useState(true);
  const [busy, setBusy] = useState(false);
  return (
    <CardPage>
      <Title>{client ? `Sign out of ${client}` : 'Sign out'}</Title>
      <p className="mt-3 text-body text-fg-muted">You can sign back in any time.</p>
      <form method="post" action={action} className="mt-6 space-y-5" onSubmit={() => setBusy(true)}>
        <input type="hidden" name="xsrf" value={xsrf} />
        <label className="flex items-start gap-3 text-body text-fg">
          <input
            type="checkbox"
            name="logout"
            value="yes"
            checked={everywhere}
            onChange={(event) => setEverywhere(event.target.checked)}
            className="mt-0.5 size-4 accent-primary"
          />
          <span>
            Also sign out of Handstamp
            <span className="block text-body-sm text-fg-muted">
              Other apps will ask you to sign in again.
            </span>
          </span>
        </label>
        <Button type="submit" variant="primary" busy={busy}>
          Sign out
        </Button>
      </form>
    </CardPage>
  );
}

export function SignedOut({ client }: { client: string }) {
  return (
    <CardPage>
      <Title>You're signed out</Title>
      <p className="mt-3 text-body text-fg-muted">
        {client ? `You've signed out of ${client}. ` : ''}You can close this tab, or{' '}
        <a
          className="text-link underline-offset-2 hover:underline"
          href="/console/login?returnTo=/account"
        >
          sign in again
        </a>
        .
      </p>
    </CardPage>
  );
}

const ERRORS: Record<string, [string, string]> = {
  invalid_request: [
    "This sign-in link isn't right",
    'Go back to the app and sign in again. If it keeps happening, tell whoever runs the app.',
  ],
  invalid_client: [
    "We don't recognise this app",
    "It isn't registered with this Handstamp instance, or it was turned off. Tell whoever runs the app.",
  ],
  unauthorized_client: [
    "This app can't sign you in this way",
    'Its Handstamp settings need a change. Tell whoever runs the app.',
  ],
  invalid_redirect_uri: [
    "This app's return address isn't registered",
    'For your safety we only send you back to addresses the app registered. Tell whoever runs the app.',
  ],
  access_denied: ['Sign-in was cancelled', 'Go back to the app whenever you are ready.'],
  session_not_found: ['This sign-in has expired', 'Go back to the app and sign in again.'],
  server_error: ['Something went wrong on our side', 'Try again in a moment.'],
};

export function ErrorView({ code }: { code: string }) {
  const [title, body] = ERRORS[code] ?? ERRORS.server_error;
  return (
    <CardPage footer={<>error: {code || 'server_error'}</>}>
      <Title>{title}</Title>
      <p className="mt-3 text-body text-fg-muted">{body}</p>
    </CardPage>
  );
}
