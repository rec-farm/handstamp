import { eq } from 'drizzle-orm';
import { users, type Database } from '@handstamp/db';

export const TEST_USERNAME = 'test';

// The account behind "Continue as test user". Only reachable when HANDSTAMP_DEV_LOGIN passes the
// checks in env.ts (S17). It has no credential of any kind.
export async function ensureTestUser(db: Database) {
  const [existing] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.preferredUsername, TEST_USERNAME));
  if (existing) return existing.id;
  const [created] = await db
    .insert(users)
    .values({
      displayName: 'Test User',
      preferredUsername: TEST_USERNAME,
      email: 'test@handstamp.test',
      emailVerified: true,
    })
    .returning({ id: users.id });
  return created.id;
}
