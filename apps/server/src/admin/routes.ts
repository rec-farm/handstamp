import type { FastifyInstance, FastifyRequest } from 'fastify';
import {
  and,
  asc,
  count,
  desc,
  eq,
  gte,
  ilike,
  inArray,
  isNull,
  lt,
  lte,
  or,
  sql,
  type SQL,
} from 'drizzle-orm';
import { z } from 'zod';
import {
  clientDefinitionSchema,
  groupSchema,
  ipPrefix,
  type AuditEntry,
  type ClientDefinition,
} from '@handstamp/core';
import {
  auditLog,
  enrollmentTokens,
  groupMembers,
  groups,
  oidcClients,
  oidcPayloads,
  upstreamProviders,
  users,
  writeAudit,
} from '@handstamp/db';
import { ApiProblem, apiErrorHandler, consoleAuth, type AuthDeps } from '../console/auth.ts';
import { definitionOf, ReadOnlyClientError, type ClientStore } from '../clients.ts';
import type { Enrollments } from '../enrollment.ts';
import { LastMethodError, type IdentityStore } from '../identities.ts';
import type { KeyStore, RotationPolicy } from '../keys.ts';
import type { PasskeyStore } from '../passkeys.ts';
import type { Sessions } from '../sessions.ts';
import {
  ReadOnlyProviderError,
  upstreamUrlProblem,
  type ProviderAdmin,
} from '../upstream/providers.ts';

export type AdminDeps = AuthDeps & {
  clients: ClientStore;
  providers: ProviderAdmin;
  identities: IdentityStore;
  enrollments: Enrollments;
  keys: KeyStore;
  rotation: RotationPolicy;
  reloadKeys: () => Promise<unknown>;
  passkeys: PasskeyStore;
  sessions: Sessions;
};

const notFound = (what: string) =>
  new ApiProblem(404, 'not_found', `That ${what} no longer exists.`);
const readOnly = (what: string, where: string) =>
  new ApiProblem(
    409,
    'read_only',
    `This ${what} comes from ${where}, so it can only be changed there.`,
  );

function parse<T extends z.ZodType>(schema: T, body: unknown): z.output<T> {
  const result = schema.safeParse(body ?? {});
  if (result.success) return result.data;
  const issue = result.error.issues[0];
  throw new ApiProblem(400, 'invalid', issue.message, { field: issue.path.join('.') });
}

const userPatch = z.object({
  displayName: z.string().trim().min(1).max(80).optional(),
  email: z
    .union([z.literal(''), z.email('That email address needs an @ and a domain.')])
    .optional(),
  isAdmin: z.boolean().optional(),
  status: z.enum(['active', 'disabled']).optional(),
});

const providerInput = z
  .object({
    slug: z
      .string()
      .regex(/^[a-z0-9][a-z0-9-]{0,31}$/, 'Use lowercase letters, digits and dashes.'),
    kind: z.enum(['github', 'google', 'oidc']),
    displayName: z.string().trim().min(1).max(40),
    issuer: z.string().trim().optional(),
    apiUrl: z.string().trim().optional(),
    clientId: z.string().trim().min(1, 'Add the client ID from the provider.'),
    clientSecret: z.string().optional(),
    scopes: z.array(z.string()).default([]),
    allowSignup: z.boolean().default(false),
    allowedEmailDomains: z.array(z.string().trim().toLowerCase()).default([]),
    githubAllowedOrgs: z.array(z.string().trim()).default([]),
    trustEmailVerified: z.boolean().default(false),
  })
  .transform((p) => ({
    ...p,
    issuer:
      p.kind === 'google'
        ? 'https://accounts.google.com'
        : (p.issuer || (p.kind === 'github' ? 'https://github.com' : '')).replace(/\/$/, ''),
    apiUrl:
      p.kind === 'github'
        ? p.apiUrl ||
          (p.issuer && p.issuer !== 'https://github.com'
            ? `${p.issuer.replace(/\/$/, '')}/api/v3`
            : 'https://api.github.com')
        : undefined,
    // GitHub and Google only report verified emails.
    trustEmailVerified: p.kind === 'oidc' ? p.trustEmailVerified : true,
    scopes: p.kind === 'github' ? [] : p.scopes.length ? p.scopes : ['openid', 'email', 'profile'],
  }))
  .superRefine((p, ctx) => {
    const problem = upstreamUrlProblem(p.issuer);
    if (problem)
      ctx.addIssue({ code: 'custom', path: ['issuer'], message: `The issuer ${problem}.` });
  });

const auditQuery = z.object({
  action: z.string().max(64).optional(),
  actor: z.uuid().optional(),
  target: z.string().max(200).optional(),
  from: z.iso.datetime({ offset: true }).optional(),
  to: z.iso.datetime({ offset: true }).optional(),
  before: z.coerce.number().int().positive().optional(),
});

// The admin console API (docs/PLAN.md M4). Every route needs a signed-in admin; every change
// also needs a CSRF token, a recent passkey step-up, and leaves an audit row (S19).
export async function adminRoutes(app: FastifyInstance, deps: AdminDeps) {
  apiErrorHandler(app);
  const { signedIn } = consoleAuth(deps);
  const read = (req: FastifyRequest) => signedIn(req, { admin: true });
  const write = (req: FastifyRequest) => signedIn(req, { admin: true, write: true, stepUp: true });
  const audit = (
    req: FastifyRequest,
    admin: { id: string },
    entry: Omit<AuditEntry, 'actorType' | 'actorUserId'>,
  ) =>
    writeAudit(deps.db, {
      ...entry,
      actorType: 'admin',
      actorUserId: admin.id,
      ipPrefix: ipPrefix(req.ip),
      userAgent: req.headers['user-agent'],
    });

  async function activeAdmins() {
    const [row] = await deps.db
      .select({ n: count() })
      .from(users)
      .where(and(eq(users.isAdmin, true), eq(users.status, 'active')));
    return row.n;
  }

  // ── overview ──
  app.get('/api/admin/overview', async (req) => {
    await read(req);
    const since = sql`now() - interval '24 hours'`;
    const [[u], [d], [s], [c], [p], [ok], [failed]] = await Promise.all([
      deps.db.select({ n: count() }).from(users).where(eq(users.status, 'active')),
      deps.db.select({ n: count() }).from(users).where(eq(users.status, 'disabled')),
      deps.db
        .select({ n: count() })
        .from(oidcPayloads)
        .where(
          and(
            eq(oidcPayloads.kind, 'Session'),
            or(isNull(oidcPayloads.expiresAt), sql`${oidcPayloads.expiresAt} > now()`),
          ),
        ),
      deps.db.select({ n: count() }).from(oidcClients).where(eq(oidcClients.enabled, true)),
      deps.db
        .select({ n: count() })
        .from(upstreamProviders)
        .where(eq(upstreamProviders.enabled, true)),
      deps.db
        .select({ n: count() })
        .from(auditLog)
        .where(and(eq(auditLog.action, 'auth.sign_in.succeeded'), gte(auditLog.at, since))),
      deps.db
        .select({ n: count() })
        .from(auditLog)
        .where(
          and(
            inArray(auditLog.action, ['auth.sign_in.failed', 'auth.sign_in.refused']),
            gte(auditLog.at, since),
          ),
        ),
    ]);
    const keys = await deps.keys.list();
    const active = keys.find((k) => k.state === 'active');
    return {
      users: u.n,
      disabledUsers: d.n,
      sessions: s.n,
      clients: c.n,
      providers: p.n,
      signIns24h: ok.n,
      refusals24h: failed.n,
      signingKey: active
        ? {
            kid: active.kid,
            activatedAt: active.activatedAt,
            staged: keys.some((k) => k.state === 'staged'),
          }
        : null,
    };
  });

  // ── users ──
  app.get<{ Querystring: { q?: string } }>('/api/admin/users', async (req) => {
    await read(req);
    const q = req.query.q?.trim();
    // Qualified by hand: inside a raw subquery Drizzle would render users.id as a bare "id".
    const methods = sql<number>`(SELECT count(*) FROM passkeys p WHERE p.user_id = "users"."id") + (SELECT count(*) FROM identities i WHERE i.user_id = "users"."id")`;
    return deps.db
      .select({
        id: users.id,
        displayName: users.displayName,
        email: users.email,
        isAdmin: users.isAdmin,
        status: users.status,
        createdAt: users.createdAt,
        lastSignInAt: users.lastSignInAt,
        methods: methods.mapWith(Number),
      })
      .from(users)
      .where(
        q
          ? or(
              ilike(users.displayName, `%${q}%`),
              ilike(users.email, `%${q}%`),
              sql`${users.id}::text = ${q}`,
            )
          : undefined,
      )
      .orderBy(asc(users.displayName))
      .limit(500);
  });

  app.get<{ Params: { id: string } }>('/api/admin/users/:id', async (req) => {
    await read(req);
    const [user] = await deps.db.select().from(users).where(eq(users.id, req.params.id));
    if (!user) throw notFound('user');
    const [keys, linked, memberOf, sessions] = await Promise.all([
      deps.passkeys.listForUser(user.id),
      deps.identities.listForUser(user.id),
      deps.db
        .select({ id: groups.id, slug: groups.slug, name: groups.name })
        .from(groupMembers)
        .innerJoin(groups, eq(groups.id, groupMembers.groupId))
        .where(eq(groupMembers.userId, user.id))
        .orderBy(asc(groups.slug)),
      deps.sessions.list(user.id),
    ]);
    return {
      user: {
        id: user.id,
        displayName: user.displayName,
        email: user.email,
        emailVerified: user.emailVerified,
        isAdmin: user.isAdmin,
        status: user.status,
        createdAt: user.createdAt,
        lastSignInAt: user.lastSignInAt,
      },
      passkeys: keys.map((k) => ({
        id: k.id,
        name: k.name,
        createdAt: k.createdAt,
        lastUsedAt: k.lastUsedAt,
        synced: k.backedUp,
      })),
      identities: linked,
      groups: memberOf,
      sessions,
    };
  });

  app.patch<{ Params: { id: string } }>('/api/admin/users/:id', async (req) => {
    const { user: admin } = await write(req);
    const patch = parse(userPatch, req.body);
    const [user] = await deps.db.select().from(users).where(eq(users.id, req.params.id));
    if (!user) throw notFound('user');
    const self = user.id === admin.id;
    const losesAdmin =
      user.isAdmin &&
      user.status === 'active' &&
      (patch.isAdmin === false || patch.status === 'disabled');
    if (self && (patch.isAdmin === false || patch.status === 'disabled'))
      throw new ApiProblem(
        409,
        'self',
        "You can't remove your own admin access or turn off your own account. Ask another admin.",
      );
    if (losesAdmin && (await activeAdmins()) <= 1)
      throw new ApiProblem(
        409,
        'last_admin',
        'This is the last admin. Make someone else an admin first.',
      );
    const changes: Partial<typeof users.$inferInsert> = { updatedAt: new Date() };
    if (patch.displayName !== undefined) changes.displayName = patch.displayName;
    if (patch.email !== undefined) {
      // An admin-entered email is vouched for by the admin, so it counts as verified.
      changes.email = patch.email || null;
      changes.emailVerified = Boolean(patch.email);
      changes.emailIdentityId = null;
    }
    if (patch.isAdmin !== undefined) changes.isAdmin = patch.isAdmin;
    if (patch.status !== undefined) changes.status = patch.status;
    try {
      await deps.db.update(users).set(changes).where(eq(users.id, user.id));
    } catch (error) {
      if (
        (error as { cause?: { code?: string } }).cause?.code === '23505' ||
        (error as { code?: string }).code === '23505'
      )
        throw new ApiProblem(409, 'email_taken', 'Another user already has that email address.');
      throw error;
    }
    const target = { targetType: 'user', targetId: user.id } as const;
    if (patch.displayName !== undefined || patch.email !== undefined)
      await audit(req, admin, {
        action: 'user.updated',
        ...target,
        metadata: {
          fields: Object.keys(patch).filter((k) => k === 'displayName' || k === 'email'),
        },
      });
    if (patch.isAdmin !== undefined && patch.isAdmin !== user.isAdmin)
      await audit(req, admin, {
        action: patch.isAdmin ? 'user.admin_granted' : 'user.admin_revoked',
        ...target,
      });
    if (patch.status !== undefined && patch.status !== user.status) {
      await audit(req, admin, {
        action: patch.status === 'disabled' ? 'user.disabled' : 'user.enabled',
        ...target,
      });
      // Disabling ends everything at once: sessions, tokens, and a back-channel logout to apps.
      if (patch.status === 'disabled') await deps.sessions.end(user.id);
    }
    return { ok: true };
  });

  app.post<{ Params: { id: string }; Body: { revokeOtherMethods?: boolean } }>(
    '/api/admin/users/:id/recovery',
    async (req) => {
      const { user: admin } = await write(req);
      const [user] = await deps.db
        .select({ id: users.id, status: users.status })
        .from(users)
        .where(eq(users.id, req.params.id));
      if (!user) throw notFound('user');
      if (user.status !== 'active')
        throw new ApiProblem(
          409,
          'disabled',
          'Turn this account back on before sending a recovery link.',
        );
      return deps.enrollments.createRecovery(user.id, {
        revokeOtherMethods: req.body?.revokeOtherMethods === true,
        createdBy: admin.id,
        actorType: 'admin',
      });
    },
  );

  app.delete<{ Params: { id: string } }>('/api/admin/users/:id/sessions', async (req) => {
    const { user: admin } = await write(req);
    const ended = await deps.sessions.end(req.params.id);
    await audit(req, admin, {
      action: 'admin.sessions_revoked',
      targetType: 'user',
      targetId: req.params.id,
      metadata: { sessions: ended },
    });
    return { ended };
  });

  app.delete<{ Params: { id: string; passkeyId: string } }>(
    '/api/admin/users/:id/passkeys/:passkeyId',
    async (req, reply) => {
      const { user: admin } = await write(req);
      try {
        if (!(await deps.passkeys.remove(req.params.id, req.params.passkeyId)))
          throw notFound('passkey');
      } catch (error) {
        if (error instanceof LastMethodError)
          throw new ApiProblem(
            409,
            'last_method',
            'This is their only way to sign in. Send a recovery link, or turn the account off instead.',
          );
        throw error;
      }
      await audit(req, admin, {
        action: 'passkey.removed',
        targetType: 'passkey',
        targetId: req.params.passkeyId,
        metadata: { user: req.params.id },
      });
      return reply.code(204).send();
    },
  );

  app.delete<{ Params: { id: string; identityId: string } }>(
    '/api/admin/users/:id/identities/:identityId',
    async (req, reply) => {
      const { user: admin } = await write(req);
      try {
        if (!(await deps.identities.unlink(req.params.id, req.params.identityId)))
          throw notFound('linked account');
      } catch (error) {
        if (error instanceof LastMethodError)
          throw new ApiProblem(
            409,
            'last_method',
            'This is their only way to sign in. Send a recovery link, or turn the account off instead.',
          );
        throw error;
      }
      await audit(req, admin, {
        action: 'identity.unlinked',
        targetType: 'identity',
        targetId: req.params.identityId,
        metadata: { user: req.params.id },
      });
      return reply.code(204).send();
    },
  );

  // ── invites ──
  app.get('/api/admin/invites', async (req) => {
    await read(req);
    return deps.db
      .select({
        id: enrollmentTokens.id,
        createdAt: enrollmentTokens.createdAt,
        expiresAt: enrollmentTokens.expiresAt,
        createdBy: users.displayName,
      })
      .from(enrollmentTokens)
      .leftJoin(users, eq(users.id, enrollmentTokens.createdBy))
      .where(
        and(
          eq(enrollmentTokens.purpose, 'invite'),
          isNull(enrollmentTokens.consumedAt),
          sql`${enrollmentTokens.expiresAt} > now()`,
        ),
      )
      .orderBy(desc(enrollmentTokens.createdAt));
  });

  app.post('/api/admin/invites', async (req) => {
    const { user: admin } = await write(req);
    return deps.enrollments.createInvite({ userId: admin.id, actorType: 'admin' });
  });

  app.delete<{ Params: { id: string } }>('/api/admin/invites/:id', async (req, reply) => {
    const { user: admin } = await write(req);
    const rows = await deps.db
      .update(enrollmentTokens)
      .set({ expiresAt: sql`now()` })
      .where(
        and(
          eq(enrollmentTokens.id, req.params.id),
          eq(enrollmentTokens.purpose, 'invite'),
          isNull(enrollmentTokens.consumedAt),
        ),
      )
      .returning({ id: enrollmentTokens.id });
    if (!rows.length) throw notFound('invite');
    await audit(req, admin, {
      action: 'invite.revoked',
      targetType: 'enrollment',
      targetId: req.params.id,
    });
    return reply.code(204).send();
  });

  // ── groups ──
  app.get('/api/admin/groups', async (req) => {
    await read(req);
    return deps.db
      .select({
        id: groups.id,
        slug: groups.slug,
        name: groups.name,
        description: groups.description,
        members:
          sql<number>`(SELECT count(*) FROM group_members m WHERE m.group_id = "groups"."id")`.mapWith(
            Number,
          ),
        apps: sql<number>`(SELECT count(*) FROM oidc_clients c WHERE c.required_group_id = "groups"."id")`.mapWith(
          Number,
        ),
      })
      .from(groups)
      .orderBy(asc(groups.slug));
  });

  app.post('/api/admin/groups', async (req, reply) => {
    const { user: admin } = await write(req);
    const input = parse(groupSchema, req.body);
    const [group] = await deps.db
      .insert(groups)
      .values(input)
      .onConflictDoNothing()
      .returning({ id: groups.id });
    if (!group) throw new ApiProblem(409, 'exists', `A group called ${input.slug} already exists.`);
    await audit(req, admin, {
      action: 'group.created',
      targetType: 'group',
      targetId: group.id,
      metadata: { slug: input.slug },
    });
    return reply.code(201).send(group);
  });

  app.get<{ Params: { id: string } }>('/api/admin/groups/:id', async (req) => {
    await read(req);
    const [group] = await deps.db.select().from(groups).where(eq(groups.id, req.params.id));
    if (!group) throw notFound('group');
    const members = await deps.db
      .select({
        id: users.id,
        displayName: users.displayName,
        email: users.email,
        addedAt: groupMembers.addedAt,
      })
      .from(groupMembers)
      .innerJoin(users, eq(users.id, groupMembers.userId))
      .where(eq(groupMembers.groupId, group.id))
      .orderBy(asc(users.displayName));
    const apps = await deps.db
      .select({ clientId: oidcClients.clientId, name: oidcClients.name })
      .from(oidcClients)
      .where(eq(oidcClients.requiredGroupId, group.id));
    return { group, members, apps };
  });

  app.patch<{ Params: { id: string } }>('/api/admin/groups/:id', async (req) => {
    const { user: admin } = await write(req);
    const input = parse(groupSchema, req.body);
    try {
      const rows = await deps.db
        .update(groups)
        .set(input)
        .where(eq(groups.id, req.params.id))
        .returning({ id: groups.id });
      if (!rows.length) throw notFound('group');
    } catch (error) {
      if ((error as { cause?: { code?: string } }).cause?.code === '23505')
        throw new ApiProblem(409, 'exists', `A group called ${input.slug} already exists.`);
      throw error;
    }
    await audit(req, admin, {
      action: 'group.updated',
      targetType: 'group',
      targetId: req.params.id,
      metadata: { slug: input.slug },
    });
    return { ok: true };
  });

  app.delete<{ Params: { id: string } }>('/api/admin/groups/:id', async (req, reply) => {
    const { user: admin } = await write(req);
    const [used] = await deps.db
      .select({ n: count() })
      .from(oidcClients)
      .where(eq(oidcClients.requiredGroupId, req.params.id));
    if (used.n > 0)
      throw new ApiProblem(
        409,
        'in_use',
        'Apps require this group. Change their access settings first.',
      );
    const rows = await deps.db
      .delete(groups)
      .where(eq(groups.id, req.params.id))
      .returning({ slug: groups.slug });
    if (!rows.length) throw notFound('group');
    await audit(req, admin, {
      action: 'group.deleted',
      targetType: 'group',
      targetId: req.params.id,
      metadata: { slug: rows[0].slug },
    });
    return reply.code(204).send();
  });

  app.put<{ Params: { id: string; userId: string } }>(
    '/api/admin/groups/:id/members/:userId',
    async (req, reply) => {
      const { user: admin } = await write(req);
      const rows = await deps.db
        .insert(groupMembers)
        .values({ groupId: req.params.id, userId: req.params.userId, addedBy: admin.id })
        .onConflictDoNothing()
        .returning({ userId: groupMembers.userId });
      if (rows.length)
        await audit(req, admin, {
          action: 'group.member_added',
          targetType: 'group',
          targetId: req.params.id,
          metadata: { user: req.params.userId },
        });
      return reply.code(204).send();
    },
  );

  app.delete<{ Params: { id: string; userId: string } }>(
    '/api/admin/groups/:id/members/:userId',
    async (req, reply) => {
      const { user: admin } = await write(req);
      const rows = await deps.db
        .delete(groupMembers)
        .where(
          and(eq(groupMembers.groupId, req.params.id), eq(groupMembers.userId, req.params.userId)),
        )
        .returning({ userId: groupMembers.userId });
      if (rows.length)
        await audit(req, admin, {
          action: 'group.member_removed',
          targetType: 'group',
          targetId: req.params.id,
          metadata: { user: req.params.userId },
        });
      return reply.code(204).send();
    },
  );

  // ── clients ("apps") ──
  const groupSlug = async (id: string | null) =>
    id
      ? (await deps.db.select({ slug: groups.slug }).from(groups).where(eq(groups.id, id)))[0]?.slug
      : undefined;
  const clientView = async (row: Awaited<ReturnType<ClientStore['get']>> & object) => ({
    ...definitionOf(row, await groupSlug(row.requiredGroupId)),
    source: row.source,
    enabled: row.enabled,
    hasSecret: Boolean(row.clientSecretEnc),
    secretRotatedAt: row.secretRotatedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  });

  app.get('/api/admin/clients', async (req) => {
    await read(req);
    return Promise.all((await deps.clients.list()).map(clientView));
  });

  app.get<{ Params: { id: string } }>('/api/admin/clients/:id', async (req) => {
    await read(req);
    const row = await deps.clients.get(req.params.id);
    if (!row) throw notFound('app');
    return clientView(row);
  });

  async function requireGroupExists(definition: ClientDefinition) {
    if (
      definition.requiredGroup &&
      !(await deps.db.select().from(groups).where(eq(groups.slug, definition.requiredGroup))).length
    )
      throw new ApiProblem(
        400,
        'invalid',
        `There is no group called ${definition.requiredGroup}.`,
        { field: 'requiredGroup' },
      );
  }

  app.post('/api/admin/clients', async (req, reply) => {
    const { user: admin } = await write(req);
    const definition = parse(clientDefinitionSchema, req.body);
    await requireGroupExists(definition);
    const created = await deps.clients.create(definition);
    if (!created)
      throw new ApiProblem(
        409,
        'exists',
        `An app with the client ID ${definition.clientId} already exists.`,
      );
    await audit(req, admin, {
      action: 'client.created',
      targetType: 'client',
      targetId: definition.clientId,
      clientId: definition.clientId,
    });
    // The secret is shown exactly once, here.
    return reply.code(201).send({ clientId: definition.clientId, secret: created.secret });
  });

  app.put<{ Params: { id: string } }>('/api/admin/clients/:id', async (req) => {
    const { user: admin } = await write(req);
    const definition = parse(clientDefinitionSchema, {
      ...(req.body as object),
      clientId: req.params.id,
    });
    await requireGroupExists(definition);
    let result;
    try {
      result = await deps.clients.update(definition);
    } catch (error) {
      if (error instanceof ReadOnlyClientError)
        throw readOnly('app', 'the clients file or Handstamp itself');
      throw error;
    }
    if (!result) throw notFound('app');
    await audit(req, admin, {
      action: 'client.updated',
      targetType: 'client',
      targetId: definition.clientId,
      clientId: definition.clientId,
    });
    return { secret: result.secret };
  });

  app.post<{ Params: { id: string } }>('/api/admin/clients/:id/secret', async (req) => {
    const { user: admin } = await write(req);
    let secret;
    try {
      secret = await deps.clients.rotateSecret(req.params.id);
    } catch (error) {
      if (error instanceof ReadOnlyClientError)
        throw readOnly('app', 'the clients file or Handstamp itself');
      throw error;
    }
    if (!secret) throw new ApiProblem(409, 'no_secret', 'This app has no secret to rotate.');
    await audit(req, admin, {
      action: 'client.secret_rotated',
      targetType: 'client',
      targetId: req.params.id,
      clientId: req.params.id,
    });
    return { secret };
  });

  app.post<{ Params: { id: string }; Body: { enabled?: boolean } }>(
    '/api/admin/clients/:id/enabled',
    async (req) => {
      const { user: admin } = await write(req);
      const enabled = req.body?.enabled === true;
      try {
        if (!(await deps.clients.setEnabled(req.params.id, enabled))) throw notFound('app');
      } catch (error) {
        if (error instanceof ReadOnlyClientError)
          throw readOnly('app', 'the clients file or Handstamp itself');
        throw error;
      }
      await audit(req, admin, {
        action: enabled ? 'client.enabled' : 'client.disabled',
        targetType: 'client',
        targetId: req.params.id,
        clientId: req.params.id,
      });
      return { enabled };
    },
  );

  // ── upstream providers ──
  app.get('/api/admin/providers', async (req) => {
    await read(req);
    return deps.providers.list();
  });

  app.post('/api/admin/providers', async (req, reply) => {
    const { user: admin } = await write(req);
    const input = parse(providerInput, req.body);
    if (!input.clientSecret)
      throw new ApiProblem(400, 'invalid', 'Add the client secret from the provider.', {
        field: 'clientSecret',
      });
    if (!(await deps.providers.create(input)))
      throw new ApiProblem(409, 'exists', `A provider called ${input.slug} already exists.`);
    await audit(req, admin, {
      action: 'provider.created',
      targetType: 'provider',
      targetId: input.slug,
      metadata: { kind: input.kind },
    });
    return reply.code(201).send({ slug: input.slug });
  });

  app.put<{ Params: { slug: string } }>('/api/admin/providers/:slug', async (req) => {
    const { user: admin } = await write(req);
    const input = parse(providerInput, { ...(req.body as object), slug: req.params.slug });
    try {
      if (!(await deps.providers.update(input))) throw notFound('provider');
    } catch (error) {
      if (error instanceof ReadOnlyProviderError)
        throw readOnly('provider', 'environment variables');
      throw error;
    }
    await audit(req, admin, {
      action: 'provider.updated',
      targetType: 'provider',
      targetId: input.slug,
      metadata: { secret_changed: Boolean(input.clientSecret) },
    });
    return { ok: true };
  });

  app.post<{ Params: { slug: string }; Body: { enabled?: boolean } }>(
    '/api/admin/providers/:slug/enabled',
    async (req) => {
      const { user: admin } = await write(req);
      const enabled = req.body?.enabled === true;
      try {
        if (!(await deps.providers.setEnabled(req.params.slug, enabled)))
          throw notFound('provider');
      } catch (error) {
        if (error instanceof ReadOnlyProviderError)
          throw readOnly('provider', 'environment variables');
        throw error;
      }
      await audit(req, admin, {
        action: enabled ? 'provider.enabled' : 'provider.disabled',
        targetType: 'provider',
        targetId: req.params.slug,
      });
      return { enabled };
    },
  );

  // ── signing keys ──
  app.get('/api/admin/keys', async (req) => {
    await read(req);
    return { keys: await deps.keys.list(), policy: deps.rotation };
  });

  app.post('/api/admin/keys/rotate', async (req) => {
    const { user: admin } = await write(req);
    const kid = await deps.keys.stage('admin', admin.id);
    await deps.reloadKeys();
    return { kid };
  });

  app.post('/api/admin/keys/promote', async (req) => {
    const { user: admin } = await write(req);
    const kid = await deps.keys.promote(deps.rotation, 'admin', admin.id);
    if (!kid)
      throw new ApiProblem(409, 'nothing_staged', 'There is no new key waiting. Rotate first.');
    await deps.reloadKeys();
    return { kid };
  });

  // ── audit log ──
  function auditWhere(query: z.output<typeof auditQuery>) {
    const where: SQL[] = [];
    if (query.action)
      where.push(
        query.action.endsWith('.')
          ? sql`${auditLog.action} LIKE ${`${query.action}%`}`
          : eq(auditLog.action, query.action),
      );
    if (query.actor) where.push(eq(auditLog.actorUserId, query.actor));
    if (query.target)
      where.push(or(eq(auditLog.targetId, query.target), eq(auditLog.clientId, query.target))!);
    if (query.from) where.push(gte(auditLog.at, new Date(query.from)));
    if (query.to) where.push(lte(auditLog.at, new Date(query.to)));
    if (query.before) where.push(lt(auditLog.id, query.before));
    return where.length ? and(...where) : undefined;
  }

  const auditColumns = {
    id: auditLog.id,
    at: auditLog.at,
    action: auditLog.action,
    actorType: auditLog.actorType,
    actorUserId: auditLog.actorUserId,
    actorName: users.displayName,
    targetType: auditLog.targetType,
    targetId: auditLog.targetId,
    clientId: auditLog.clientId,
    ipPrefix: auditLog.ipPrefix,
    userAgent: auditLog.userAgent,
    metadata: auditLog.metadata,
  };

  app.get('/api/admin/audit', async (req) => {
    await read(req);
    const query = parse(auditQuery, req.query);
    const rows = await deps.db
      .select(auditColumns)
      .from(auditLog)
      .leftJoin(users, eq(users.id, auditLog.actorUserId))
      .where(auditWhere(query))
      .orderBy(desc(auditLog.id))
      .limit(51);
    return { entries: rows.slice(0, 50), next: rows.length > 50 ? rows[49].id : null };
  });

  app.get('/api/admin/audit.csv', async (req, reply) => {
    await read(req);
    const query = parse(auditQuery, req.query);
    const rows = await deps.db
      .select(auditColumns)
      .from(auditLog)
      .leftJoin(users, eq(users.id, auditLog.actorUserId))
      .where(auditWhere(query))
      .orderBy(desc(auditLog.id))
      .limit(10_000);
    const cell = (v: unknown) => {
      const text =
        v == null
          ? ''
          : v instanceof Date
            ? v.toISOString()
            : typeof v === 'object'
              ? JSON.stringify(v)
              : String(v);
      // Quote everything and neutralise spreadsheet formulas.
      return `"${(/^[=+\-@]/.test(text) ? `'${text}` : text).replace(/"/g, '""')}"`;
    };
    const header = Object.keys(auditColumns);
    const body = rows
      .map((r) => header.map((k) => cell(r[k as keyof typeof r])).join(','))
      .join('\n');
    return reply
      .header('content-type', 'text/csv; charset=utf-8')
      .header(
        'content-disposition',
        `attachment; filename="handstamp-audit-${new Date().toISOString().slice(0, 10)}.csv"`,
      )
      .header('cache-control', 'no-store')
      .send(`${header.join(',')}\n${body}\n`);
  });
}
