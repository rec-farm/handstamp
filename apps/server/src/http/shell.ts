import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

export type ShellView = Record<string, string>;

export interface ShellRenderer {
  render(url: string, view?: ShellView): Promise<string>;
  // sha256 hashes of inline <script> blocks, for the CSP.
  scriptHashes(): string[];
}

const ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};
const escape = (value: string) => value.replace(/[&<>"']/g, (c) => ESCAPES[c]);

// Server-rendered views (logout confirm, signed out, errors) reuse the SPA's index.html and pass
// their data as escaped data-hs-* attributes on <html>. No inline script, no extra cookie.
export function injectView(html: string, view: ShellView | undefined) {
  if (!view) return html;
  const attributes = Object.entries(view)
    .filter(([key]) => /^[a-z][a-z-]*$/.test(key))
    .map(([key, value]) => ` data-hs-${key}="${escape(value)}"`)
    .join('');
  return html.replace(/<html\b/i, (tag) => tag + attributes);
}

export function inlineScriptHashes(html: string) {
  return [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)].map(
    ([, body]) => `'sha256-${createHash('sha256').update(body).digest('base64')}'`,
  );
}

export async function createStaticShell(indexPath: string): Promise<ShellRenderer> {
  const html = await readFile(indexPath, 'utf8');
  const hashes = inlineScriptHashes(html);
  return { render: async (_url, view) => injectView(html, view), scriptHashes: () => hashes };
}

type ViteLike = { transformIndexHtml(url: string, html: string): Promise<string> };

// Dev only: Vite runs in middleware mode inside Fastify, so dev is one process and one origin too.
export function createViteShell(vite: ViteLike, indexPath: string): ShellRenderer {
  return {
    render: async (url, view) =>
      injectView(await vite.transformIndexHtml(url, await readFile(indexPath, 'utf8')), view),
    scriptHashes: () => [],
  };
}
