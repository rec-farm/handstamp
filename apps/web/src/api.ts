export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly data: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

const FALLBACK = "We couldn't reach Handstamp. Check your connection and try again.";

export async function api<T>(
  path: string,
  init: { method?: string; csrf?: string; body?: unknown } = {},
) {
  let response: Response;
  try {
    response = await fetch(path, {
      method: init.method ?? 'GET',
      credentials: 'same-origin',
      headers: {
        accept: 'application/json',
        ...(init.body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(init.csrf ? { 'x-handstamp-csrf': init.csrf } : {}),
      },
      body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
    });
  } catch {
    throw new ApiError(0, 'network', FALLBACK);
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok)
    throw new ApiError(response.status, data.error ?? 'unknown', data.message ?? FALLBACK, data);
  return data as T;
}

// Data a server-rendered view (logout, signed out, error) passes on <html data-hs-*>.
export function serverView() {
  const { hsView, ...rest } = document.documentElement.dataset;
  if (!hsView) return undefined;
  const data: Record<string, string> = {};
  for (const [key, value] of Object.entries(rest))
    if (key.startsWith('hs') && value !== undefined) data[key.slice(2).toLowerCase()] = value;
  return { view: hsView, data };
}
