import { useEffect, useState } from 'react';
import { api, ApiError } from '../api.ts';
import { CardPage, Loading, Title } from '../components/ui.tsx';

const toConsole = () => window.location.replace('/console/login?returnTo=/account');

// `/` is a redirect, not a page (R17): unclaimed → setup, signed out → sign in, else → account.
export function Root() {
  const [problem, setProblem] = useState<string>();
  useEffect(() => {
    (async () => {
      const { claimed } = await api<{ claimed: boolean }>('/api/instance');
      if (!claimed) return window.location.replace('/setup');
      await api('/api/me');
      window.location.replace('/account');
    })().catch((error: ApiError) =>
      error.code === 'signed_out' ? toConsole() : setProblem(error.message),
    );
  }, []);
  return (
    <CardPage>
      {problem ? (
        <>
          <Title>We couldn't load Handstamp</Title>
          <p className="mt-3 text-body text-fg-muted">{problem}</p>
        </>
      ) : (
        <Loading label="One moment…" />
      )}
    </CardPage>
  );
}

// `/setup` (the address printed with the setup code). Claiming happens on the sign-in card.
export function Setup() {
  const [claimed, setClaimed] = useState<boolean>();
  useEffect(() => {
    api<{ claimed: boolean }>('/api/instance').then(({ claimed }) =>
      claimed ? setClaimed(true) : toConsole(),
    );
  }, []);
  return (
    <CardPage>
      {claimed ? (
        <>
          <Title>Already set up</Title>
          <p className="mt-3 text-body text-fg-muted">
            This Handstamp instance already has an admin.{' '}
            <a
              className="text-link underline-offset-2 hover:underline"
              href="/console/login?returnTo=/account"
            >
              Sign in
            </a>{' '}
            instead.
          </p>
        </>
      ) : (
        <Loading label="Starting setup…" />
      )}
    </CardPage>
  );
}
