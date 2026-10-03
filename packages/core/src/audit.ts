// Every action the audit log can record. Adding a row here is the only way to log something new,
// which keeps the log searchable and its metadata reviewable (S19).
export type AuditAction =
  | 'auth.sign_in.succeeded'
  | 'auth.sign_in.failed'
  | 'auth.consent.granted'
  | 'client.synced'
  | 'client.disabled'
  | 'key.staged'
  | 'key.activated'
  | 'key.retired'
  | 'instance.started'
  | 'instance.claimed'
  | 'setup.code_issued'
  | 'passkey.added'
  | 'passkey.renamed'
  | 'passkey.removed'
  | 'session.revoked'
  | 'session.revoked_all'
  | 'provider.disabled'
  | 'user.created'
  | 'user.email_conflict'
  | 'identity.linked'
  | 'identity.unlinked'
  | 'identity.link_refused'
  | 'auth.sign_in.refused'
  | 'invite.created'
  | 'invite.used'
  | 'recovery.issued'
  | 'recovery.used'
  | 'user.updated'
  | 'user.disabled'
  | 'user.enabled'
  | 'user.admin_granted'
  | 'user.admin_revoked'
  | 'group.created'
  | 'group.updated'
  | 'group.deleted'
  | 'group.member_added'
  | 'group.member_removed'
  | 'client.created'
  | 'client.updated'
  | 'client.secret_rotated'
  | 'client.enabled'
  | 'provider.created'
  | 'provider.updated'
  | 'provider.enabled'
  | 'admin.sessions_revoked'
  | 'invite.revoked';

export type AuditEntry = {
  action: AuditAction;
  actorType: 'user' | 'admin' | 'system' | 'cli';
  actorUserId?: string;
  targetType?: string;
  targetId?: string;
  clientId?: string;
  ipPrefix?: string;
  userAgent?: string;
  // Allowlisted, non-secret facts only (IDs, counts, reasons).
  metadata?: Record<string, string | number | boolean | string[] | null>;
};

// Store a network prefix, not the full address: enough to spot patterns, less personal data.
export function ipPrefix(ip: string | undefined): string | undefined {
  if (!ip) return undefined;
  if (ip === '::1') return '::1/128';
  const v4 = ip.replace(/^::ffff:/, '');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(v4)) return `${v4.split('.').slice(0, 3).join('.')}.0/24`;
  if (ip.includes(':')) {
    const groups = ip.split('::')[0].split(':').filter(Boolean).slice(0, 3);
    while (groups.length < 3) groups.push('0');
    return `${groups.join(':')}::/48`;
  }
  return undefined;
}
