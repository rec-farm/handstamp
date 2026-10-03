import { afterAll, beforeAll, expect, it } from 'vitest';
import { chromium, type Browser, type BrowserContext, type Page } from 'playwright';
import { startTestServer } from '../harness.ts';

// The admin console in real Chromium. Set SCREENSHOT_DIR to keep screenshots for design review.

let server: Awaited<ReturnType<typeof startTestServer>>;
let browser: Browser;
let context: BrowserContext;
let page: Page;
const errors: string[] = [];
const shots = process.env.SCREENSHOT_DIR;

async function shot(name: string) {
  if (!shots) return;
  for (const theme of ['dark', 'light'] as const) {
    await page.evaluate((t) => (document.documentElement.dataset.theme = t), theme);
    await page.waitForTimeout(300); // let colour transitions finish
    await page.screenshot({ path: `${shots}/admin-${name}-${theme}.png`, fullPage: true });
  }
  await page.evaluate(() => (document.documentElement.dataset.theme = 'dark'));
}

beforeAll(async () => {
  server = await startTestServer('e2e_admin', { web: 'static', env: { HANDSTAMP_DEV_LOGIN: '0' } });
  browser = await chromium.launch();
  context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  page = await context.newPage();
  page.on('pageerror', (error) => errors.push(error.message));
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
});

afterAll(async () => {
  await browser?.close();
  await server?.close();
});

it('runs the instance from the admin console', async () => {
  const code = (await server.setup.issueCode())!;
  await page.goto(server.issuer);
  await page.getByLabel('Setup code').fill(code);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Your name').fill('Admin');
  await page.getByRole('button', { name: 'Create passkey and finish' }).click();
  await page.waitForURL('**/account');

  // Overview, via the sidebar's Admin section.
  await page.getByRole('link', { name: 'Overview' }).first().click();
  await page.getByRole('heading', { name: 'Overview.' }).waitFor();
  await page.getByRole('button', { name: 'Invite someone' }).click();
  await expect(
    page.getByText(/^http:\/\/localhost:\d+\/enroll#/).textContent(),
  ).resolves.toBeTruthy();
  await shot('overview');

  // A group, then an app that requires it.
  await page.getByRole('link', { name: 'Groups' }).first().click();
  await page.getByRole('button', { name: 'Create group' }).click();
  await page.getByLabel(/^Name/).fill('Paramtune admins');
  await page.getByLabel('Claim value').fill('paramtune-admins');
  await page.getByRole('button', { name: 'Create group' }).click();
  await page.getByText('Created Paramtune admins.').waitFor();
  await shot('groups');

  await page.getByRole('link', { name: 'Apps' }).first().click();
  await page.getByRole('button', { name: 'Add an app' }).click();
  await page.getByLabel(/^Name/).fill('Paramtune');
  await page.getByLabel('Client ID').fill('paramtune');
  await page
    .getByLabel(/^Redirect URIs/)
    .fill('https://paramtune.example.com/api/auth/oauth2/callback/oidc');
  await page.getByLabel('Who may sign in').selectOption('paramtune-admins');
  await page.getByRole('button', { name: 'Add app' }).click();
  await page.getByText('Client secret', { exact: true }).waitFor();
  const secret = await page
    .locator('code')
    .filter({ hasText: /^hs_sec_/ })
    .textContent();
  expect(secret).toMatch(/^hs_sec_/);
  await expect(page.locator('pre').textContent()).resolves.toContain('OIDC_CLIENT_ID=paramtune');
  await shot('app');
  // Shown once: a reload no longer has it.
  await page.reload();
  await page.locator('pre').waitFor();
  expect(
    await page
      .locator('code')
      .filter({ hasText: /^hs_sec_/ })
      .count(),
  ).toBe(0);

  await page.getByRole('link', { name: 'Users' }).first().click();
  const row = page.getByRole('table').getByRole('link', { name: 'Admin' });
  await row.waitFor();
  await shot('users');
  await row.click();
  await page.getByRole('heading', { name: 'Access' }).waitFor();
  await shot('user');

  await page.getByRole('link', { name: 'Signing keys' }).first().click();
  await page.getByRole('button', { name: 'Rotate key' }).click();
  await page.getByText(/New key published/).waitFor();
  await page.getByRole('button', { name: 'Start signing with the new key now' }).waitFor();
  await shot('keys');

  await page.getByRole('link', { name: 'Audit log' }).first().click();
  await page.getByRole('cell', { name: 'client.created' }).waitFor();
  await shot('audit');

  await page.getByRole('link', { name: 'Sign-in providers' }).first().click();
  await page.getByText(/No sign-in providers yet/).waitFor();

  // Phone width keeps the admin reachable.
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto(`${server.issuer}/admin`);
  await page.getByRole('heading', { name: 'Overview.' }).waitFor();
  if (shots) await page.screenshot({ path: `${shots}/admin-overview-375.png`, fullPage: true });

  expect(errors).toEqual([]);
});
