// A demo upstream identity provider for trying "Continue with …" locally: http://localhost:4100
// A real OIDC issuer (oidc-provider) with a pick-a-person page instead of passwords.
// Not part of the product, not secure, dev only.
import Provider from 'oidc-provider';

const PORT = 4100;
const ISSUER = `http://localhost:${PORT}`;
const HANDSTAMP = process.env.HANDSTAMP_ISSUER ?? 'http://localhost:3000';
const SECRET = process.env.HANDSTAMP_UPSTREAM_OIDC_DEMO_CLIENT_SECRET;
if (!SECRET) throw new Error('HANDSTAMP_UPSTREAM_OIDC_DEMO_CLIENT_SECRET is missing from .env');

const PEOPLE = [
  { sub: 'demo-ada', name: 'Ada Lovelace', email: 'ada@demo.example' },
  { sub: 'demo-grace', name: 'Grace Hopper', email: 'grace@demo.example' },
  { sub: 'demo-mallory', name: 'Mallory (outsider)', email: 'mallory@elsewhere.example' },
];

const provider = new Provider(ISSUER, {
  clients: [
    {
      client_id: 'handstamp-dev',
      client_secret: SECRET,
      redirect_uris: [`${HANDSTAMP}/upstream/demo/callback`],
    },
  ],
  claims: { openid: ['sub'], email: ['email', 'email_verified'], profile: ['name'] },
  findAccount: (_ctx, sub) => {
    const person = PEOPLE.find((p) => p.sub === sub);
    return person
      ? { accountId: sub, claims: () => ({ ...person, email_verified: true }) }
      : undefined;
  },
  cookies: { keys: ['demo-idp-only'] },
  features: { devInteractions: { enabled: false } },
});

const page = (body: string) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Demo SSO</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:420px;margin:60px auto;padding:0 16px;color:#222}
button{display:block;width:100%;text-align:left;font:inherit;padding:12px 14px;margin:8px 0;border:1px solid #bbb;border-radius:6px;background:#fff;cursor:pointer}
button:hover{background:#f3f3f3}small{color:#777}</style></head><body>${body}</body></html>`;

provider.use(async (ctx, next) => {
  const match = /^\/interaction\/([^/]+)(\/pick)?$/.exec(ctx.path);
  if (!match) return next();
  const details = await provider.interactionDetails(ctx.req, ctx.res);
  if (match[2] && ctx.method === 'POST') {
    let body = '';
    for await (const chunk of ctx.req) body += chunk;
    const sub = new URLSearchParams(body).get('sub') ?? '';
    ctx.respond = false;
    return provider.interactionFinished(ctx.req, ctx.res, { login: { accountId: sub } });
  }
  if (details.prompt.name === 'consent') {
    const grant = new provider.Grant({
      accountId: details.session!.accountId,
      clientId: details.params.client_id as string,
    });
    grant.addOIDCScope('openid email profile');
    ctx.respond = false;
    return provider.interactionFinished(
      ctx.req,
      ctx.res,
      { consent: { grantId: await grant.save() } },
      { mergeWithLastSubmission: true },
    );
  }
  ctx.type = 'html';
  ctx.body =
    page(`<h1>Demo SSO</h1><p>Who do you want to be? <small>(dev only, no passwords)</small></p>
<form method="post" action="/interaction/${details.uid}/pick">
${PEOPLE.map((p) => `<button name="sub" value="${p.sub}">${p.name}<br><small>${p.email}</small></button>`).join('')}
</form>`);
});

provider.listen(PORT, 'localhost', () => console.log(`Demo identity provider ready at ${ISSUER}`));
