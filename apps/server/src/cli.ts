import { eq, sql } from 'drizzle-orm';
import { users } from '@handstamp/db';
import { bootstrap, rotationPolicy } from './runtime.ts';

const USAGE = `Usage: handstamp <command>

Commands:
  keys list       Show signing keys and their state
  keys rotate     Stage a new signing key. It is published now and starts
                  signing after KEY_STAGE_HOURS (or run "keys promote")
  keys promote    Start signing with the staged key now
  setup-code      Print a new first-run setup code (only before the instance is claimed)
  invite          Print a one-time invite link (7 days)
  recovery <user> Print a one-time recovery link (30 minutes) for a user, by sub or email.
                  Add --revoke to remove their other passkeys and sessions ("I lost my device").
  migrate         Apply database migrations
`;

const [group, command] = process.argv.slice(2);
if (!group || ['help', '--help', '-h'].includes(group)) {
  console.log(USAGE);
  process.exit(0);
}
const runtime = await bootstrap();
const { keys, env, pool } = runtime;

try {
  if (group === 'migrate') {
    console.log(
      runtime.migrations.length
        ? `Applied ${runtime.migrations.join(', ')}`
        : 'Already up to date.',
    );
  } else if (group === 'setup-code') {
    const code = await runtime.setup.issueCode();
    console.log(code ? `Setup code (60 minutes): ${code}` : 'This instance already has an admin.');
  } else if (group === 'invite') {
    const { link, expiresInDays } = await runtime.enrollments.createInvite({ actorType: 'cli' });
    console.log(`Invite link (works once, for ${expiresInDays} days):\n\n  ${link}\n`);
  } else if (group === 'recovery' && command) {
    const [user] = await runtime.db
      .select({ id: users.id, name: users.displayName })
      .from(users)
      .where(
        /^[0-9a-f-]{36}$/i.test(command)
          ? eq(users.id, command)
          : sql`lower(${users.email}) = ${command.toLowerCase()}`,
      );
    if (!user) {
      console.error(`No user matches ${command}. Use their sub (from the account page) or email.`);
      process.exitCode = 1;
    } else {
      const revoke = process.argv.includes('--revoke');
      const { link, expiresInMinutes } = await runtime.enrollments.createRecovery(user.id, {
        revokeOtherMethods: revoke,
        actorType: 'cli',
      });
      console.log(
        `Recovery link for ${user.name} (works once, for ${expiresInMinutes} minutes):\n\n  ${link}\n\n` +
          (revoke
            ? 'Using it removes their other passkeys and signs them out everywhere.'
            : 'Their existing passkeys keep working. Use --revoke if a device was lost or stolen.'),
      );
    }
  } else if (group === 'keys' && command === 'list') {
    for (const key of await keys.list())
      console.log(
        [
          key.kid,
          key.alg,
          key.state.padEnd(8),
          key.createdAt.toISOString(),
          key.retireAfter?.toISOString() ?? '',
        ].join('  '),
      );
  } else if (group === 'keys' && command === 'rotate') {
    const kid = await keys.stage('cli');
    console.log(
      `Staged ${kid}. It is published now and starts signing in ${env.KEY_STAGE_HOURS}h.`,
    );
  } else if (group === 'keys' && command === 'promote') {
    const kid = await keys.promote(rotationPolicy(env), 'cli');
    console.log(
      kid
        ? `${kid} is now signing. The previous key stays published until it retires.`
        : 'No staged key. Run "keys rotate" first.',
    );
  } else {
    console.log(USAGE);
    process.exitCode = 1;
  }
} finally {
  await pool.end();
}
