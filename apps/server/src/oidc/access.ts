import { interactionPolicy } from 'oidc-provider';
import { and, eq } from 'drizzle-orm';
import { groupMembers, type Database } from '@handstamp/db';

const { base, Check, Prompt } = interactionPolicy;

export async function isMember(db: Database, userId: string, groupId: string) {
  const [row] = await db
    .select({ userId: groupMembers.userId })
    .from(groupMembers)
    .where(and(eq(groupMembers.groupId, groupId), eq(groupMembers.userId, userId)));
  return Boolean(row);
}

// login → access → consent. The access prompt runs on every authorization, SSO included, so an
// app that requires a group never gets a code for someone outside it (R7). Instead of a bare
// access_denied the person sees a card that says which group they need.
export function interactionPolicyWithAccess(db: Database) {
  const policy = base();
  policy.add(
    new Prompt(
      { name: 'access', requestable: false },
      (ctx) => ({ requiredGroup: ctx.oidc.client?.metadata().handstamp_required_group ?? null }),
      new Check(
        'group_required',
        'End-User is not a member of the group this client requires',
        async (ctx) => {
          const groupId = ctx.oidc.client?.metadata().handstamp_required_group as
            string | null | undefined;
          const accountId = ctx.oidc.session?.accountId;
          if (!groupId || !accountId) return Check.NO_NEED_TO_PROMPT;
          return (await isMember(db, accountId, groupId))
            ? Check.NO_NEED_TO_PROMPT
            : Check.REQUEST_PROMPT;
        },
      ),
    ),
    1,
  );
  return policy;
}
