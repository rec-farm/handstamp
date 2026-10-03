import { and, eq } from 'drizzle-orm';
import { groupMembers, groups, users, type Database } from '@handstamp/db';

// The `groups` claim: the slugs of every group the user belongs to, sorted.
export async function groupSlugs(db: Database, userId: string) {
  const rows = await db
    .select({ slug: groups.slug })
    .from(groupMembers)
    .innerJoin(groups, eq(groups.id, groupMembers.groupId))
    .where(eq(groupMembers.userId, userId));
  return rows.map((r) => r.slug).sort();
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Disabled users simply stop existing for the provider: no tokens, no userinfo (S18).
export async function findAccount(db: Database, sub: string) {
  if (!UUID.test(sub)) return undefined;
  const [user] = await db
    .select()
    .from(users)
    .where(and(eq(users.id, sub), eq(users.status, 'active')));
  if (!user) return undefined;
  return {
    accountId: user.id,
    // `scope` is the space-separated list of granted scopes for this token or userinfo call.
    async claims(_use: string, scope: string) {
      const granted = new Set(scope.split(' '));
      return {
        sub: user.id,
        name: user.displayName,
        ...(user.preferredUsername ? { preferred_username: user.preferredUsername } : {}),
        ...(user.email ? { email: user.email, email_verified: user.emailVerified } : {}),
        updated_at: Math.floor(user.updatedAt.getTime() / 1000),
        ...(granted.has('groups') ? { groups: await groupSlugs(db, user.id) } : {}),
      };
    },
  };
}
