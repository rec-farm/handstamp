const BASE = 'http://handstamp.invalid';

// The only way an internal `returnTo` may become a redirect target. Accepts same-origin paths only;
// anything that could leave the origin (`//host`, `/\host`, schemes, control characters) falls back.
export function safeReturnPath(value: unknown, fallback = '/account'): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) return fallback;
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return fallback;
  if (/[\u0000-\u001f\u007f]/.test(value)) return fallback;
  try {
    const url = new URL(value, BASE);
    if (url.origin !== BASE) return fallback;
    return url.pathname + url.search + url.hash;
  } catch {
    return fallback;
  }
}
