import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { deleteExpiredPayloads } from '@handstamp/db';
import { buildApp, type WebMode } from './app.ts';
import { bootstrap, rotationPolicy } from './runtime.ts';
import { createLogger } from './log.ts';

const SCHEDULER_LOCK = 4_26_19_78;
const webRoot = fileURLToPath(new URL('../../web/', import.meta.url));
const distDir = fileURLToPath(new URL('../../web/dist/', import.meta.url));

const boot = createLogger();
let runtime: Awaited<ReturnType<typeof bootstrap>>;
try {
  runtime = await bootstrap();
} catch (error) {
  boot.fatal((error as Error).message);
  process.exit(1);
}
const { env, pool, db, keys } = runtime;

const web: WebMode =
  env.NODE_ENV === 'development'
    ? { mode: 'vite', root: webRoot }
    : existsSync(distDir)
      ? { mode: 'static', distDir }
      : { mode: 'none' };

const { app, reloadKeys } = await buildApp({ ...runtime, web });
if (runtime.migrations.length)
  app.log.info({ migrations: runtime.migrations }, 'migrations applied');
if (runtime.declaredClients.length)
  app.log.info({ clients: runtime.declaredClients }, 'declared clients synced');
if (runtime.testUserId)
  app.log.warn('HANDSTAMP_DEV_LOGIN is on: anyone can sign in as the test user');
// The setup code is the only secret Handstamp ever prints, once, outside request logging.
const setupCode = await runtime.setup.issueCode();
if (setupCode)
  process.stdout.write(
    `\n  Handstamp has no admin yet. Open ${env.HANDSTAMP_ISSUER.origin}/setup and enter this code:\n\n` +
      `      ${setupCode}\n\n  It works for 60 minutes. Restart Handstamp or run "handstamp setup-code" for a new one.\n\n`,
  );
if (web.mode === 'none') app.log.warn('apps/web/dist is missing: run pnpm build to get the UI');

// Key lifecycle and cleanup. The advisory lock keeps it to one process if several run.
async function tick() {
  const client = await pool.connect();
  try {
    const { rows } = await client.query('SELECT pg_try_advisory_lock($1) AS locked', [
      SCHEDULER_LOCK,
    ]);
    if (rows[0].locked) {
      try {
        await keys.tick(rotationPolicy(env));
        const removed = await deleteExpiredPayloads(db);
        if (removed) app.log.debug({ removed }, 'expired oidc payloads removed');
      } finally {
        await client.query('SELECT pg_advisory_unlock($1)', [SCHEDULER_LOCK]);
      }
    }
    // Every process picks up key changes, including ones made by the CLI.
    await reloadKeys();
  } catch (error) {
    app.log.error({ err: error }, 'scheduled maintenance failed');
  } finally {
    client.release();
  }
}
const timer = setInterval(tick, 60_000);
timer.unref();

async function shutdown(signal: string) {
  app.log.info({ signal }, 'shutting down');
  clearInterval(timer);
  await app.close();
  await pool.end();
  process.exit(0);
}
process.once('SIGTERM', () => void shutdown('SIGTERM'));
process.once('SIGINT', () => void shutdown('SIGINT'));

await app.listen({ host: env.HOST, port: env.PORT });
app.log.info({ issuer: env.HANDSTAMP_ISSUER.origin }, 'Handstamp is ready');
