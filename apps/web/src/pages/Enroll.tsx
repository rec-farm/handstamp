import { useEffect, useState } from 'react';
import { api, ApiError } from '../api.ts';
import { Button, Callout, CardPage, Loading, Title } from '../components/ui.tsx';

// /enroll#<token>: an invite or recovery link. The token lives in the fragment so it never
// reaches server logs; we hand it over once, then continue to the sign-in card.
export function EnrollLink() {
  const [state, setState] = useState<
    { purpose: 'invite' | 'recovery'; name?: string } | { problem: string } | undefined
  >();

  useEffect(() => {
    const token = window.location.hash.slice(1);
    window.history.replaceState(null, '', window.location.pathname);
    if (!token) {
      setState({
        problem: 'This link is incomplete. Copy the whole link from your admin and try again.',
      });
      return;
    }
    api<{ purpose: 'invite' | 'recovery'; name?: string }>('/api/enroll', {
      method: 'POST',
      body: { token },
    })
      .then(setState)
      .catch((error: ApiError) => setState({ problem: error.message }));
  }, []);

  const go = () => window.location.assign('/console/login?returnTo=/account');

  return (
    <CardPage>
      {!state ? (
        <Loading label="Checking your link…" />
      ) : 'problem' in state ? (
        <>
          <Title>This link didn't work</Title>
          <div className="mt-4">
            <Callout tone="danger">{state.problem}</Callout>
          </div>
        </>
      ) : state.purpose === 'invite' ? (
        <>
          <p className="eyebrow mb-2">Invitation</p>
          <Title>You're invited</Title>
          <p className="mt-3 text-body text-fg-muted">
            Next, create a passkey (or use an account you already have) and you're in.
          </p>
          <div className="mt-6">
            <Button variant="primary" onClick={go}>
              Continue
            </Button>
          </div>
        </>
      ) : (
        <>
          <p className="eyebrow mb-2">Account recovery</p>
          <Title>Let's get you back in</Title>
          <p className="mt-3 text-body text-fg-muted">
            This link lets {state.name ?? 'you'} add a new way to sign in. It works once.
          </p>
          <div className="mt-6">
            <Button variant="primary" onClick={go}>
              Continue
            </Button>
          </div>
        </>
      )}
    </CardPage>
  );
}
