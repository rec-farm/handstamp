import type { AuditEntry } from '@handstamp/core';
import type { Database } from './index.ts';
import { auditLog } from './schema.ts';

export async function writeAudit(db: Pick<Database, 'insert'>, entry: AuditEntry) {
  await db.insert(auditLog).values({
    action: entry.action,
    actorType: entry.actorType,
    actorUserId: entry.actorUserId,
    targetType: entry.targetType,
    targetId: entry.targetId,
    clientId: entry.clientId,
    ipPrefix: entry.ipPrefix,
    userAgent: entry.userAgent?.slice(0, 256),
    metadata: entry.metadata ?? {},
  });
}
