import type { ServerResponse } from 'node:http';

export type HeaderOptions = { https: boolean; scriptHashes: string[]; dev: boolean };

// Applied to every response, including the ones oidc-provider writes directly (S15).
export function baseHeaders({ https }: HeaderOptions): Record<string, string> {
  return {
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'x-frame-options': 'DENY',
    'cross-origin-opener-policy': 'same-origin',
    ...(https ? { 'strict-transport-security': 'max-age=31536000' } : {}),
  };
}

// For HTML pages. No form-action: the logout form posts to us and we 303 to the RP's
// post_logout_redirect_uri, which Chrome would block under form-action 'self'.
export function htmlCsp({ scriptHashes, dev }: HeaderOptions) {
  if (dev) return undefined; // Vite's dev client needs inline scripts and eval.
  return [
    "default-src 'self'",
    `script-src 'self' ${scriptHashes.join(' ')}`.trim(),
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
  ].join('; ');
}

export function applyRaw(res: ServerResponse, headers: Record<string, string | undefined>) {
  for (const [name, value] of Object.entries(headers)) if (value) res.setHeader(name, value);
}
