import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import Provider from 'oidc-provider';

export type MockAccount = {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  // AgentID's claims.
  actor_type?: string;
  owner_sub?: string;
  owner_name?: string;
  owner_email?: string;
};

// A real OIDC issuer (oidc-provider) that signs in whichever account the test picks, with no UI.
// `agentid` makes it behave like AgentID: ES256-only ID tokens, actor_type and owner claims.
export async function mockOidcIssuer(
  port: number,
  redirectUri: string,
  secret: string,
  { agentid = false }: { agentid?: boolean } = {},
) {
  const accounts = new Map<string, MockAccount>();
  const state = { next: '' };
  const issuer = `http://127.0.0.1:${port}`;
  const es256 = agentid
    ? {
        jwks: {
          keys: [
            {
              ...generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({
                format: 'jwk',
              }),
              alg: 'ES256',
              use: 'sig',
              kid: 'agentid-test',
            },
          ],
        },
        enabledJWA: { idTokenSigningAlgValues: ['ES256' as const] },
      }
    : {};
  const scope = agentid ? 'openid email profile owner_profile owner_email' : 'openid email profile';
  const provider = new Provider(issuer, {
    ...es256,
    clients: [
      {
        client_id: 'handstamp',
        client_secret: secret,
        redirect_uris: [redirectUri],
        ...(agentid ? { id_token_signed_response_alg: 'ES256' } : {}),
      },
    ],
    claims: {
      openid: agentid ? ['sub', 'actor_type'] : ['sub'],
      email: ['email', 'email_verified'],
      profile: ['name'],
      ...(agentid
        ? { owner_profile: ['owner_sub', 'owner_name'], owner_email: ['owner_email'] }
        : {}),
    },
    findAccount: (_ctx, sub) => {
      const account = accounts.get(sub);
      return account ? { accountId: sub, claims: () => account } : undefined;
    },
    cookies: { keys: ['mock-issuer-cookie-key'] },
    features: { devInteractions: { enabled: false } },
  });
  // Auto-login as `state.next` and auto-consent: no screens in tests.
  provider.use(async (ctx, next) => {
    if (!ctx.path.startsWith('/interaction/')) return next();
    const details = await provider.interactionDetails(ctx.req, ctx.res);
    ctx.respond = false;
    if (details.prompt.name === 'login')
      return provider.interactionFinished(ctx.req, ctx.res, { login: { accountId: state.next } });
    const grant = new provider.Grant({
      accountId: details.session!.accountId,
      clientId: details.params.client_id as string,
    });
    grant.addOIDCScope(scope);
    return provider.interactionFinished(
      ctx.req,
      ctx.res,
      { consent: { grantId: await grant.save() } },
      { mergeWithLastSubmission: true },
    );
  });
  const server = provider.listen(port, '127.0.0.1');
  return {
    issuer,
    signInAs(account: MockAccount) {
      accounts.set(account.sub, account);
      state.next = account.sub;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

export type GitHubUser = {
  id: number;
  login: string;
  name?: string;
  emails: { email: string; primary: boolean; verified: boolean }[];
  orgs?: string[];
};

// Just enough of GitHub's OAuth app flow and REST API, including PKCE.
export function mockGitHub(port: number) {
  const codes = new Map<string, { user: GitHubUser; challenge: string }>();
  const tokens = new Map<string, GitHubUser>();
  const state: { next?: GitHubUser } = {};
  const server: Server = createServer(async (req, res) => {
    const url = new URL(req.url!, `http://127.0.0.1:${port}`);
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (url.pathname === '/login/oauth/authorize') {
      const code = randomBytes(8).toString('hex');
      codes.set(code, { user: state.next!, challenge: url.searchParams.get('code_challenge')! });
      const back = new URL(url.searchParams.get('redirect_uri')!);
      back.searchParams.set('code', code);
      back.searchParams.set('state', url.searchParams.get('state')!);
      res.writeHead(302, { location: back.href }).end();
      return;
    }
    if (url.pathname === '/login/oauth/access_token') {
      let body = '';
      for await (const chunk of req) body += chunk;
      const form = new URLSearchParams(body);
      const entry = codes.get(form.get('code') ?? '');
      codes.delete(form.get('code') ?? '');
      const verifier = form.get('code_verifier') ?? '';
      const challenge = createHash('sha256').update(verifier).digest('base64url');
      if (!entry || entry.challenge !== challenge)
        return json(200, { error: 'bad_verification_code' });
      const token = randomBytes(8).toString('hex');
      tokens.set(token, entry.user);
      return json(200, {
        access_token: token,
        token_type: 'bearer',
        scope: 'read:user,user:email',
      });
    }
    const user = tokens.get((req.headers.authorization ?? '').replace(/^Bearer /, ''));
    if (!user) return json(401, { message: 'Bad credentials' });
    if (url.pathname === '/api/v3/user')
      return json(200, { id: user.id, login: user.login, name: user.name ?? null });
    if (url.pathname === '/api/v3/user/emails') return json(200, user.emails);
    if (url.pathname === '/api/v3/user/orgs')
      return json(
        200,
        (user.orgs ?? []).map((login) => ({ login })),
      );
    json(404, { message: 'Not Found' });
  }).listen(port, '127.0.0.1');
  return {
    url: `http://127.0.0.1:${port}`,
    signInAs(user: GitHubUser) {
      state.next = user;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
