import { connectDatabase, migrate } from '@handstamp/db';
import { parseEnv, type Env } from './env.ts';
import { ClientStore } from './clients.ts';
import { KeyStore, type RotationPolicy } from './keys.ts';
import { ensureTestUser } from './dev/test-account.ts';
import { consoleClient, consoleSecret } from './console/session.ts';
import { PasskeyStore } from './passkeys.ts';
import { Setup } from './setup.ts';
import { Enrollments } from './enrollment.ts';
import { ProviderStore } from './upstream/providers.ts';

export function rotationPolicy(env: Env): RotationPolicy {
  return {
    stageHours: env.KEY_STAGE_HOURS,
    rotationDays: env.KEY_ROTATION_DAYS,
    // Retiring keys stay published while any ID token they signed can still be valid.
    retireAfterSeconds: env.ID_TOKEN_MINUTES * 60 + 60 * 60,
  };
}

// Shared by the server, the CLI and the integration tests.
export async function bootstrap(source: Record<string, string | undefined> = process.env) {
  const env = parseEnv(source);
  const { pool, db } = connectDatabase(env.DATABASE_URL);
  const migrations = await migrate(pool);
  const keys = new KeyStore(db, env.secretKey);
  await keys.ensure();
  const clients = new ClientStore(db, env.secretKey);
  const declaredClients = env.HANDSTAMP_CLIENTS_FILE
    ? await clients.syncFile(env.HANDSTAMP_CLIENTS_FILE, source)
    : [];
  // Handstamp's own UI signs in through Handstamp (docs/PLAN.md §1.3).
  await clients.upsert(
    consoleClient(env.HANDSTAMP_ISSUER),
    consoleSecret(env.secretKey),
    'builtin',
  );
  const upstreamProviders = await new ProviderStore(db, env.secretKey).syncEnv(source);
  const testUserId = env.HANDSTAMP_DEV_LOGIN ? await ensureTestUser(db) : undefined;
  const setup = new Setup(db, new PasskeyStore(db));
  const enrollments = new Enrollments(db, env.HANDSTAMP_ISSUER);
  return {
    env,
    pool,
    db,
    keys,
    clients,
    testUserId,
    migrations,
    declaredClients,
    setup,
    enrollments,
    upstreamProviders,
  };
}
