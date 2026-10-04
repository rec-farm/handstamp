import { useCallback, useEffect, useState } from 'react';
import { api, ApiError } from '../api.ts';

export type Me = {
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

const here = () => window.location.pathname + window.location.search;

// Back through Handstamp's own sign-in. fresh: confirm it's you; passkey: with a passkey.
export function signInAgain(fresh = false, passkey = false) {
  const returnTo = encodeURIComponent(here());
  window.location.assign(
    `/console/login?returnTo=${returnTo}${fresh ? '&fresh=1' : ''}${passkey ? '&passkey=1' : ''}`,
  );
}

export type Notice = { tone: 'ok' | 'error'; text: string };

// The signed-in console user, plus a helper for changes that handles CSRF and step-up.
export function useConsole() {
  const [me, setMe] = useState<Me>();
  const [notice, setNotice] = useState<Notice>();
  const [busy, setBusy] = useState<string>();

  useEffect(() => {
    api<Me>('/api/me')
      .then(setMe)
      .catch((error: ApiError) =>
        error.code === 'signed_out'
          ? signInAgain()
          : setNotice({ tone: 'error', text: error.message }),
      );
  }, []);

  const write = useCallback(
    <T,>(path: string, method = 'POST', body: unknown = {}) =>
      api<T>(path, { method, csrf: me?.csrf, body }),
    [me],
  );

  // Runs a change. Returns undefined when it failed (the notice says why) or left the page.
  const act = useCallback(
    async <T,>(
      name: string,
      step: () => Promise<T>,
      success?: string | ((result: T) => string),
    ) => {
      setBusy(name);
      setNotice(undefined);
      try {
        const result = await step();
        if (success)
          setNotice({ tone: 'ok', text: typeof success === 'string' ? success : success(result) });
        return result;
      } catch (error) {
        if (error instanceof ApiError && error.code === 'step_up_required') {
          signInAgain(true, error.data.method === 'passkey');
          return undefined;
        }
        if (error instanceof ApiError && error.code === 'signed_out') {
          signInAgain();
          return undefined;
        }
        setNotice({ tone: 'error', text: (error as Error).message });
        return undefined;
      } finally {
        setBusy(undefined);
      }
    },
    [],
  );

  return { me, notice, setNotice, busy, write, act };
}

// Loads one admin resource and reloads it on demand.
export function useResource<T>(path: string | undefined) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string>();
  const load = useCallback(async () => {
    if (!path) return;
    try {
      setData(await api<T>(path));
      setError(undefined);
    } catch (e) {
      if (e instanceof ApiError && e.code === 'signed_out') return signInAgain();
      setError((e as Error).message);
    }
  }, [path]);
  useEffect(() => void load(), [load]);
  return { data, error, reload: load };
}
