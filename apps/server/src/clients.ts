import { readFile } from 'node:fs/promises';
import { and, asc, eq, notInArray } from 'drizzle-orm';
import { z } from 'zod';
import {
  clientDefinitionSchema,
  deriveKey,
  open,
  randomToken,
  seal,
  toProviderMetadata,
  type ClientDefinition,
} from '@handstamp/core';
import { groups, oidcClients, writeAudit, type Database } from '@handstamp/db';

export type ClientRow = typeof oidcClients.$inferSelect;
export class ReadOnlyClientError extends Error {}

// Client secrets are generated, never chosen: 32 random bytes, shown once (S10).
export const newClientSecret = () => `hs_sec_${randomToken(32)}`;

export function definitionOf(row: ClientRow, requiredGroup?: string): ClientDefinition {
  return {
    clientId: row.clientId,
    name: row.name,
    redirectUris: row.redirectUris,
    postLogoutRedirectUris: row.postLogoutRedirectUris,
    scopes: row.allowedScopes as ClientDefinition['scopes'],
    tokenEndpointAuthMethod:
      row.tokenEndpointAuthMethod as ClientDefinition['tokenEndpointAuthMethod'],
    firstParty: row.firstParty,
    requirePkce: row.requirePkce,
    backchannelLogoutUri: row.backchannelLogoutUri ?? undefined,
    requiredGroup,
  };
}

const fileSchema = z.object({
  clients: z.array(
    z.intersection(
      clientDefinitionSchema,
      // The file names the env var holding the secret; the secret itself never lives in the file.
      z.object({
        secretEnv: z
          .string()
          .regex(/^[A-Z][A-Z0-9_]*$/)
          .optional(),
      }),
    ),
  ),
});

export class ClientStore {
  readonly #key: Buffer;

  constructor(
    private readonly db: Database,
    secretKey: Buffer,
  ) {
    this.#key = deriveKey(secretKey, 'client-secrets');
  }

  // Metadata for oidc-provider. Disabled or unknown clients don't exist as far as it's concerned.
  load = async (clientId: string) => {
    const [row] = await this.db
      .select()
      .from(oidcClients)
      .where(and(eq(oidcClients.clientId, clientId), eq(oidcClients.enabled, true)));
    if (!row) return undefined;
    const secret = row.clientSecretEnc
      ? open(this.#key, row.clientSecretEnc, row.clientId).toString()
      : undefined;
    return toProviderMetadata(definitionOf(row), secret, row.requiredGroupId);
  };

  // A declared client may name a group that doesn't exist yet; create it so a config file works
  // on a fresh instance.
  async #groupId(slug: string | undefined) {
    if (!slug) return null;
    await this.db.insert(groups).values({ slug, name: slug }).onConflictDoNothing();
    const [group] = await this.db
      .select({ id: groups.id })
      .from(groups)
      .where(eq(groups.slug, slug));
    return group.id;
  }

  async upsert(
    definition: ClientDefinition,
    secret: string | undefined,
    source: 'file' | 'db' | 'builtin',
  ) {
    const isPublic = definition.tokenEndpointAuthMethod === 'none';
    if (!isPublic && (!secret || secret.length < 32))
      throw new Error(`Client ${definition.clientId} needs a secret of at least 32 characters`);
    const columns = {
      source,
      name: definition.name,
      clientSecretEnc: isPublic ? null : seal(this.#key, secret!, definition.clientId),
      tokenEndpointAuthMethod: definition.tokenEndpointAuthMethod,
      redirectUris: definition.redirectUris,
      postLogoutRedirectUris: definition.postLogoutRedirectUris,
      allowedScopes: definition.scopes,
      firstParty: definition.firstParty,
      requirePkce: definition.requirePkce,
      backchannelLogoutUri: definition.backchannelLogoutUri ?? null,
      requiredGroupId: await this.#groupId(definition.requiredGroup),
      enabled: true,
      updatedAt: new Date(),
    };
    await this.db
      .insert(oidcClients)
      .values({ clientId: definition.clientId, ...columns })
      .onConflictDoUpdate({ target: oidcClients.clientId, set: columns });
  }

  // ── admin ──
  list() {
    return this.db.select().from(oidcClients).orderBy(asc(oidcClients.name));
  }

  async get(clientId: string) {
    const [row] = await this.db
      .select()
      .from(oidcClients)
      .where(eq(oidcClients.clientId, clientId));
    return row;
  }

  // Admins edit only clients they created here; file and built-in clients are read-only.
  async #editable(clientId: string) {
    const row = await this.get(clientId);
    if (row && row.source !== 'db') throw new ReadOnlyClientError();
    return row;
  }

  async create(definition: ClientDefinition) {
    if (await this.get(definition.clientId)) return undefined;
    const secret = definition.tokenEndpointAuthMethod === 'none' ? undefined : newClientSecret();
    await this.upsert(definition, secret, 'db');
    return { secret };
  }

  // Keeps the current secret unless the auth method changes to or from public.
  async update(definition: ClientDefinition) {
    const row = await this.#editable(definition.clientId);
    if (!row) return undefined;
    const wasPublic = row.tokenEndpointAuthMethod === 'none';
    const isPublic = definition.tokenEndpointAuthMethod === 'none';
    let secret: string | undefined;
    let newSecret: string | undefined;
    if (!isPublic)
      secret = wasPublic
        ? (newSecret = newClientSecret())
        : open(this.#key, row.clientSecretEnc!, row.clientId).toString();
    await this.upsert(definition, secret, 'db');
    if (!row.enabled) await this.setEnabled(definition.clientId, false);
    return { secret: newSecret };
  }

  // Replaces the secret at once: the old one stops working immediately.
  async rotateSecret(clientId: string) {
    const row = await this.#editable(clientId);
    if (!row || row.tokenEndpointAuthMethod === 'none') return undefined;
    const secret = newClientSecret();
    await this.db
      .update(oidcClients)
      .set({
        clientSecretEnc: seal(this.#key, secret, clientId),
        secretRotatedAt: new Date(),
        updatedAt: new Date(),
      })
      .where(eq(oidcClients.clientId, clientId));
    return secret;
  }

  async setEnabled(clientId: string, enabled: boolean) {
    await this.#editable(clientId);
    const rows = await this.db
      .update(oidcClients)
      .set({ enabled, updatedAt: new Date() })
      .where(eq(oidcClients.clientId, clientId))
      .returning({ clientId: oidcClients.clientId });
    return rows.length > 0;
  }

  // Declared clients are synced at boot and read-only in the UI. A client removed from the file
  // is disabled rather than deleted, so its audit trail stays intact.
  async syncFile(path: string, env: Record<string, string | undefined>) {
    const parsed = fileSchema.safeParse(JSON.parse(await readFile(path, 'utf8')));
    if (!parsed.success)
      throw new Error(
        `HANDSTAMP_CLIENTS_FILE is invalid:\n${parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n')}`,
      );
    const ids: string[] = [];
    for (const { secretEnv, ...definition } of parsed.data.clients) {
      const secret = secretEnv ? env[secretEnv] : undefined;
      if (definition.tokenEndpointAuthMethod !== 'none' && !secret)
        throw new Error(
          `Client ${definition.clientId} reads its secret from ${secretEnv ?? '(no secretEnv)'}, which is not set`,
        );
      await this.upsert(definition, secret, 'file');
      ids.push(definition.clientId);
      await writeAudit(this.db, {
        action: 'client.synced',
        actorType: 'system',
        targetType: 'client',
        targetId: definition.clientId,
        clientId: definition.clientId,
      });
    }
    const removed = await this.db
      .update(oidcClients)
      .set({ enabled: false, updatedAt: new Date() })
      .where(
        and(
          eq(oidcClients.source, 'file'),
          eq(oidcClients.enabled, true),
          ids.length ? notInArray(oidcClients.clientId, ids) : undefined,
        ),
      )
      .returning({ clientId: oidcClients.clientId });
    for (const { clientId } of removed)
      await writeAudit(this.db, {
        action: 'client.disabled',
        actorType: 'system',
        targetType: 'client',
        targetId: clientId,
        clientId,
        metadata: { reason: 'removed_from_file' },
      });
    return ids;
  }
}
