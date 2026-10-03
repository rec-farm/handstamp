import {
  bigint,
  bigserial,
  boolean,
  customType,
  inet,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';

// Columns mirror packages/db/migrations/*.sql, which is the source of truth for constraints.
const bytea = customType<{ data: Buffer }>({ dataType: () => 'bytea' });
const at = () => timestamp({ withTimezone: true, mode: 'date' });

export const users = pgTable('users', {
  id: uuid().primaryKey().defaultRandom(),
  displayName: text().notNull(),
  preferredUsername: text(),
  email: text(),
  emailVerified: boolean().notNull().default(false),
  isAdmin: boolean().notNull().default(false),
  status: text().$type<'active' | 'disabled'>().notNull().default('active'),
  createdAt: at().notNull().defaultNow(),
  updatedAt: at().notNull().defaultNow(),
  lastSignInAt: at(),
  webauthnUserHandle: text(),
  emailIdentityId: uuid(),
});

export type ClientSource = 'db' | 'file' | 'builtin';

export const oidcClients = pgTable('oidc_clients', {
  clientId: text().primaryKey(),
  source: text().$type<ClientSource>().notNull().default('db'),
  name: text().notNull(),
  clientSecretEnc: bytea(),
  tokenEndpointAuthMethod: text().notNull(),
  redirectUris: text().array().notNull(),
  postLogoutRedirectUris: text().array().notNull().default([]),
  allowedScopes: text().array().notNull(),
  firstParty: boolean().notNull().default(false),
  requirePkce: boolean().notNull().default(true),
  backchannelLogoutUri: text(),
  requiredGroupId: uuid(),
  enabled: boolean().notNull().default(true),
  secretRotatedAt: at(),
  createdAt: at().notNull().defaultNow(),
  updatedAt: at().notNull().defaultNow(),
});

export type SigningKeyState = 'staged' | 'active' | 'retiring' | 'retired';

export const signingKeys = pgTable('signing_keys', {
  kid: text().primaryKey(),
  alg: text().notNull(),
  privateJwkEnc: bytea(),
  publicJwk: jsonb().$type<Record<string, unknown>>().notNull(),
  state: text().$type<SigningKeyState>().notNull(),
  createdAt: at().notNull().defaultNow(),
  activatedAt: at(),
  retireAfter: at(),
  retiredAt: at(),
});

export const cookieKeys = pgTable('cookie_keys', {
  id: uuid().primaryKey().defaultRandom(),
  keyEnc: bytea().notNull(),
  state: text().$type<'active' | 'retiring' | 'retired'>().notNull(),
  createdAt: at().notNull().defaultNow(),
});

export const oidcPayloads = pgTable(
  'oidc_payloads',
  {
    kind: text().notNull(),
    id: text().notNull(),
    payload: jsonb().$type<Record<string, unknown>>().notNull(),
    grantId: text(),
    uid: text(),
    userCode: text(),
    accountId: text(),
    expiresAt: at(),
    consumedAt: at(),
  },
  (t) => [primaryKey({ columns: [t.kind, t.id] })],
);

export type AuditActorType = 'user' | 'admin' | 'system' | 'cli';

export const auditLog = pgTable('audit_log', {
  id: bigserial({ mode: 'number' }).primaryKey(),
  at: at().notNull().defaultNow(),
  actorType: text().$type<AuditActorType>().notNull(),
  actorUserId: uuid(),
  action: text().notNull(),
  targetType: text(),
  targetId: text(),
  clientId: text(),
  ipPrefix: inet(),
  userAgent: text(),
  metadata: jsonb().$type<Record<string, unknown>>().notNull().default({}),
});

export const instanceSettings = pgTable('instance_settings', {
  id: integer().primaryKey().default(1),
  instanceName: text().notNull().default('Handstamp'),
  setupCompletedAt: at(),
  requireTwoMethods: boolean().notNull().default(false),
  updatedAt: at().notNull().defaultNow(),
});

export const passkeys = pgTable('passkeys', {
  id: uuid().primaryKey().defaultRandom(),
  userId: uuid().notNull(),
  credentialId: text().notNull(),
  publicKey: bytea().notNull(),
  signCount: bigint({ mode: 'number' }).notNull().default(0),
  transports: text().array().notNull().default([]),
  aaguid: uuid(),
  deviceType: text().$type<'singleDevice' | 'multiDevice'>().notNull(),
  backedUp: boolean().notNull().default(false),
  name: text().notNull(),
  createdAt: at().notNull().defaultNow(),
  lastUsedAt: at(),
});

export type ChallengePurpose = 'authenticate' | 'register' | 'setup' | 'enroll';

export const webauthnChallenges = pgTable('webauthn_challenges', {
  id: uuid().primaryKey().defaultRandom(),
  challenge: text().notNull(),
  purpose: text().$type<ChallengePurpose>().notNull(),
  binding: text().notNull(),
  userId: uuid(),
  pending: jsonb().$type<Record<string, string>>().notNull().default({}),
  expiresAt: at().notNull(),
  consumedAt: at(),
});

export const enrollmentTokens = pgTable('enrollment_tokens', {
  id: uuid().primaryKey().defaultRandom(),
  tokenHash: bytea().notNull(),
  purpose: text().$type<'setup' | 'invite' | 'recovery'>().notNull(),
  userId: uuid(),
  boundTo: text(),
  createdBy: uuid(),
  createdAt: at().notNull().defaultNow(),
  expiresAt: at().notNull(),
  consumedAt: at(),
  consumedByUserId: uuid(),
  revokeOtherMethods: boolean().notNull().default(false),
});

export type UpstreamKind = 'github' | 'google' | 'oidc';

export const upstreamProviders = pgTable('upstream_providers', {
  id: uuid().primaryKey().defaultRandom(),
  slug: text().notNull(),
  kind: text().$type<UpstreamKind>().notNull(),
  displayName: text().notNull(),
  issuer: text().notNull(),
  apiUrl: text(),
  clientId: text().notNull(),
  clientSecretEnc: bytea().notNull(),
  scopes: text().array().notNull().default([]),
  allowSignup: boolean().notNull().default(false),
  allowedEmailDomains: text().array().notNull().default([]),
  githubAllowedOrgs: text().array().notNull().default([]),
  trustEmailVerified: boolean().notNull().default(false),
  enabled: boolean().notNull().default(true),
  source: text().$type<'env' | 'db'>().notNull().default('db'),
  sortOrder: integer().notNull().default(0),
  createdAt: at().notNull().defaultNow(),
  updatedAt: at().notNull().defaultNow(),
});

export const identities = pgTable('identities', {
  id: uuid().primaryKey().defaultRandom(),
  userId: uuid().notNull(),
  providerId: uuid().notNull(),
  issuer: text().notNull(),
  subject: text().notNull(),
  email: text(),
  emailVerified: boolean().notNull().default(false),
  loginHint: text(),
  linkedAt: at().notNull().defaultNow(),
  lastUsedAt: at(),
});

export const groups = pgTable('groups', {
  id: uuid().primaryKey().defaultRandom(),
  slug: text().notNull(),
  name: text().notNull(),
  description: text().notNull().default(''),
  createdAt: at().notNull().defaultNow(),
});

export const groupMembers = pgTable(
  'group_members',
  {
    groupId: uuid().notNull(),
    userId: uuid().notNull(),
    addedBy: uuid(),
    addedAt: at().notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.groupId, t.userId] })],
);
