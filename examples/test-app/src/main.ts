// A tiny relying party for trying Handstamp by hand: http://localhost:4000
// It is an ordinary OIDC client (openid-client, code flow + PKCE), the same thing a REC app does.
// Not part of the product: in-memory sessions, no hardening.
import { randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import * as oidc from 'openid-client';

const PORT = 4000;
const BASE = `http://localhost:${PORT}`;
const ISSUER = process.env.HANDSTAMP_ISSUER ?? 'http://localhost:3000';
const CLIENT_ID = 'local-rp';
const SECRET = process.env.LOCAL_RP_CLIENT_SECRET;
if (!SECRET) throw new Error('LOCAL_RP_CLIENT_SECRET is missing from .env');

type Session = {
  pending?: { verifier: string; state: string; nonce: string };
  tokens?: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers;
  userinfo?: oidc.UserInfoResponse;
  message?: { tone: 'ok' | 'error'; text: string };
};
const sessions = new Map<string, Session>();

let config: oidc.Configuration | undefined;
async function client() {
  config ??= await oidc.discovery(
    new URL(ISSUER),
    CLIENT_ID,
    SECRET,
    oidc.ClientSecretBasic(SECRET),
    new URL(ISSUER).protocol === 'http:' ? { execute: [oidc.allowInsecureRequests] } : {},
  );
  return config;
}

function session(req: IncomingMessage, res: ServerResponse) {
  const sid = /(?:^|;\s*)example_sid=([\w-]+)/.exec(req.headers.cookie ?? '')?.[1];
  if (sid && sessions.has(sid)) return sessions.get(sid)!;
  const id = randomBytes(16).toString('base64url');
  const fresh: Session = {};
  sessions.set(id, fresh);
  res.setHeader('set-cookie', `example_sid=${id}; Path=/; HttpOnly; SameSite=Lax`);
  return fresh;
}

const esc = (value: unknown) => String(value).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const json = (value: unknown) => `<pre>${esc(JSON.stringify(value, null, 2))}</pre>`;
const decode = (jwt: string, part: number) =>
  JSON.parse(Buffer.from(jwt.split('.')[part], 'base64url').toString());

function page(s: Session) {
  const message = s.message ? `<p class="msg ${s.message.tone}">${esc(s.message.text)}</p>` : '';
  s.message = undefined;
  const body = s.tokens
    ? `<p>Signed in as <b>${esc(s.userinfo?.name ?? s.tokens.claims()?.sub)}</b>
         <code>sub ${esc(s.tokens.claims()?.sub)}</code></p>
       <div class="row">
         <form method="post" action="/refresh"><button ${s.tokens.refresh_token ? '' : 'disabled title="No refresh token was issued"'}>Refresh tokens</button></form>
         <form method="post" action="/logout"><button>Sign out</button></form>
       </div>
       <h2>ID token claims</h2>${json(s.tokens.claims())}
       <h2>ID token header</h2>${json(decode(s.tokens.id_token!, 0))}
       <h2>Userinfo (GET /me)</h2>${json(s.userinfo)}
       <h2>Token response</h2>${json({
         token_type: s.tokens.token_type,
         expires_in: s.tokens.expires_in,
         scope: s.tokens.scope,
         refresh_token: s.tokens.refresh_token ? '(issued)' : '(none)',
       })}`
    : `<form method="get" action="/login">
         <fieldset><legend>Scopes</legend>
           <label><input type="checkbox" checked disabled> openid</label>
           ${['profile', 'email', 'groups', 'offline_access']
             .map(
               (s) =>
                 `<label><input type="checkbox" name="scope" value="${s}" ${s === 'offline_access' ? '' : 'checked'}> ${s}</label>`,
             )
             .join('')}
         </fieldset>
         <label><input type="checkbox" name="prompt" value="consent"> Ask for consent again (prompt=consent)</label>
         <label><input type="checkbox" name="prompt" value="login"> Force a fresh sign-in (prompt=login)</label>
         <button class="primary">Sign in with Handstamp</button>
       </form>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Example app</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body{font:15px/1.5 system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;color:#222;background:#fafafa}
  h1{margin:0 0 4px} h2{font-size:14px;margin:24px 0 6px;color:#555;text-transform:uppercase;letter-spacing:.05em}
  pre{background:#fff;border:1px solid #ddd;border-radius:4px;padding:12px;overflow:auto;font-size:13px}
  code{background:#eee;padding:1px 6px;border-radius:3px;font-size:13px;margin-left:6px}
  fieldset{border:1px solid #ddd;border-radius:4px;margin:16px 0} label{display:block;margin:4px 0}
  button{font:inherit;padding:8px 14px;border-radius:4px;border:1px solid #aaa;background:#fff;cursor:pointer}
  button.primary{background:#222;color:#fff;border-color:#222;margin-top:12px} button[disabled]{opacity:.4}
  .row{display:flex;gap:8px} .msg{padding:8px 12px;border-radius:4px} .ok{background:#e6f4ea} .error{background:#fde7e9}
  .muted{color:#777}
</style></head><body>
<h1>Example app</h1>
<p class="muted">A pretend R.E.C. app signing in through Handstamp at <code>${esc(ISSUER)}</code> as client <code>${CLIENT_ID}</code>.</p>
${message}${body}
</body></html>`;
}

async function handle(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url ?? '/', BASE);
  const s = session(req, res);
  const redirect = (to: string) => {
    res.writeHead(303, { location: to });
    res.end();
  };

  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(page(s));
  }

  if (req.method === 'GET' && url.pathname === '/login') {
    const verifier = oidc.randomPKCECodeVerifier();
    s.pending = { verifier, state: oidc.randomState(), nonce: oidc.randomNonce() };
    const scopes = ['openid', ...url.searchParams.getAll('scope')];
    const prompt = url.searchParams.getAll('prompt').join(' ');
    return redirect(
      oidc
        .buildAuthorizationUrl(await client(), {
          redirect_uri: `${BASE}/callback`,
          scope: scopes.join(' '),
          state: s.pending.state,
          nonce: s.pending.nonce,
          code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
          code_challenge_method: 'S256',
          ...(prompt ? { prompt } : {}),
        })
        .toString(),
    );
  }

  if (req.method === 'GET' && url.pathname === '/callback') {
    if (url.searchParams.has('error')) {
      s.message = {
        tone: 'error',
        text: `Handstamp returned ${url.searchParams.get('error')}: ${url.searchParams.get('error_description') ?? ''}`,
      };
      return redirect('/');
    }
    if (!s.pending) {
      s.message = { tone: 'error', text: 'No sign-in in progress. Start again.' };
      return redirect('/');
    }
    const { verifier, state, nonce } = s.pending;
    s.pending = undefined;
    const c = await client();
    s.tokens = await oidc.authorizationCodeGrant(c, url, {
      pkceCodeVerifier: verifier,
      expectedState: state,
      expectedNonce: nonce,
    });
    s.userinfo = await oidc.fetchUserInfo(c, s.tokens.access_token, s.tokens.claims()!.sub);
    s.message = {
      tone: 'ok',
      text: 'Signed in. The ID token signature, issuer, audience and nonce were verified.',
    };
    return redirect('/');
  }

  if (req.method === 'POST' && url.pathname === '/refresh' && s.tokens?.refresh_token) {
    const c = await client();
    const sub = s.tokens.claims()!.sub;
    s.tokens = await oidc.refreshTokenGrant(c, s.tokens.refresh_token);
    s.userinfo = await oidc.fetchUserInfo(c, s.tokens.access_token, sub);
    s.message = {
      tone: 'ok',
      text: 'Refreshed. The refresh token rotated, so the old one is now dead.',
    };
    return redirect('/');
  }

  if (req.method === 'POST' && url.pathname === '/logout' && s.tokens) {
    const hint = s.tokens.id_token!;
    s.tokens = s.userinfo = undefined;
    s.message = { tone: 'ok', text: 'Signed out.' };
    return redirect(
      oidc
        .buildEndSessionUrl(await client(), {
          id_token_hint: hint,
          post_logout_redirect_uri: `${BASE}/`,
        })
        .toString(),
    );
  }

  res.writeHead(404).end('Not found');
}

createServer((req, res) => {
  handle(req, res).catch((error: Error & { error?: string }) => {
    console.error(error);
    const s = session(req, res);
    s.message = { tone: 'error', text: `${error.error ?? error.name}: ${error.message}` };
    res.writeHead(303, { location: '/' });
    res.end();
  });
}).listen(PORT, 'localhost', () => console.log(`Example app ready at ${BASE}`));
