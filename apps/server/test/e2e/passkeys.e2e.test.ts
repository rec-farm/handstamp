import { afterAll, beforeAll, expect, it } from 'vitest';
import {
  chromium,
  type Browser,
  type BrowserContext,
  type CDPSession,
  type Page,
} from 'playwright';
import * as oidc from 'openid-client';
import { createServer, type Server } from 'node:http';
import { freePort, SECRETS, startTestServer } from '../harness.ts';

// The real UI in real Chromium, with Chrome's virtual WebAuthn authenticator standing in for a
// device: claim the instance, manage passkeys, sign in to an app, sign out everywhere.

let server: Awaited<ReturnType<typeof startTestServer>>;
let browser: Browser;
let context: BrowserContext;
let page: Page;
let cdp: CDPSession;
let app: Server;
let callbackUrl: string;
const errors: string[] = [];

const AUTHENTICATOR = {
  protocol: 'ctap2',
  transport: 'internal',
  hasResidentKey: true,
  hasUserVerification: true,
  isUserVerified: true,
  automaticPresenceSimulation: true,
} as const;

async function newDevice() {
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: AUTHENTICATOR,
  });
  return authenticatorId;
}

beforeAll(async () => {
  // A real (tiny) relying-party callback, so the browser lands somewhere that exists.
  const port = await freePort();
  callbackUrl = `http://127.0.0.1:${port}/cb`;
  app = createServer((_req, res) => res.end('signed in')).listen(port, '127.0.0.1');
  server = await startTestServer('e2e', {
    web: 'static',
    clients: [
      {
        clientId: 'rp-e2e',
        name: 'E2E App',
        redirectUris: [callbackUrl],
        scopes: ['openid', 'profile', 'offline_access'],
        firstParty: true,
        secretEnv: 'RP_FIRST_SECRET',
      },
    ],
  });
  browser = await chromium.launch();
  context = await browser.newContext();
  page = await context.newPage();
  page.on('pageerror', (error) => errors.push(error.message));
  cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
});

afterAll(async () => {
  await browser?.close();
  app?.close();
  await server?.close();
});

it('claims the instance, manages passkeys, signs in to an app and signs out everywhere', async () => {
  const laptop = await newDevice();
  const code = (await server.setup.issueCode())!;

  // `/` on a fresh instance lands on the claim card.
  await page.goto(server.issuer);
  await page.getByRole('heading', { name: 'Claim this instance.' }).waitFor();
  await page.getByLabel('Setup code').fill(code);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Your name').fill('First Admin');
  await page.getByRole('button', { name: 'Create passkey and finish' }).click();
  await page.waitForURL('**/account');
  await page.getByRole('heading', { name: 'Account.' }).waitFor();
  await page.getByText(/You have one passkey/).waitFor();

  // The same device can't hold two passkeys for one account; a second device can.
  await page.getByRole('button', { name: 'Add a passkey' }).click();
  await expect(page.getByRole('alert').textContent()).resolves.toMatch(/already has a passkey/);
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: laptop });
  await newDevice();
  await page.getByRole('button', { name: 'Add a passkey' }).click();
  await page.getByText(/Passkey added. You can now sign in with it/).waitFor();
  expect(await page.getByText(/^Passkey on /).count()).toBe(2);

  // An app sign-in with a fresh passkey ceremony (prompt=login skips the SSO shortcut).
  const config = await oidc.discovery(
    new URL(server.issuer),
    'rp-e2e',
    SECRETS.RP_FIRST_SECRET,
    oidc.ClientSecretBasic(SECRETS.RP_FIRST_SECRET),
    { execute: [oidc.allowInsecureRequests] },
  );
  const verifier = oidc.randomPKCECodeVerifier();
  await page.goto(
    oidc.buildAuthorizationUrl(config, {
      redirect_uri: callbackUrl,
      scope: 'openid profile',
      prompt: 'login',
      code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
      code_challenge_method: 'S256',
    }).href,
  );
  await page.getByRole('button', { name: 'Continue with a passkey' }).click();
  await page.waitForURL(`${callbackUrl}**`);
  const tokens = await oidc.authorizationCodeGrant(config, new URL(page.url()), {
    pkceCodeVerifier: verifier,
  });
  expect(tokens.claims()!.amr).toEqual(['pop', 'user', 'mfa']);

  // Sign out everywhere ends the console session and the app's refresh token.
  await page.goto(`${server.issuer}/account`);
  await page.getByRole('button', { name: 'Sign out everywhere' }).click();
  await page.getByRole('button', { name: 'Yes, sign out everywhere' }).click();
  await page.waitForURL('**/signed-out');
  expect(await page.evaluate(() => fetch('/api/me').then((r) => r.status))).toBe(401);
  await expect(oidc.refreshTokenGrant(config, tokens.refresh_token!)).rejects.toMatchObject({
    error: 'invalid_grant',
  });

  expect(errors).toEqual([]);
});
