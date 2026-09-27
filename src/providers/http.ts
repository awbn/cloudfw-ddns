import { AuthError, ProviderError } from "./types";

/** Redirect status codes that carry a `Location` header (304 is not one). */
const REDIRECT_STATUSES = [301, 302, 303, 307, 308];

export interface AuthorizedFetchOptions {
  /**
   * HTTP status codes that indicate an authentication/authorization failure
   * and should be surfaced as an {@link AuthError}. Defaults to `[401]`.
   * (Hetzner, for example, also returns `403` for bad tokens.)
   */
  authFailureStatuses?: number[];
}

/**
 * Shared fetch helper for firewall providers.
 *
 * Adds a `Bearer` token and JSON headers, refuses to follow redirects (so a
 * bearer token can never be replayed to an unexpected host), and converts the
 * provider's auth-failure responses into an {@link AuthError}. Every provider
 * that authenticates with a bearer token should build on this rather than
 * hand-rolling its own `fetch` wrapper.
 *
 * Note: the Workers runtime only accepts `redirect: "follow"` or `"manual"` —
 * `"error"` throws a `TypeError` from `fetch` itself — so redirects are taken
 * in `"manual"` mode and rejected here instead.
 */
export async function authorizedFetch(
  url: string,
  token: string,
  options: RequestInit = {},
  { authFailureStatuses = [401] }: AuthorizedFetchOptions = {}
): Promise<Response> {
  const resp = await fetch(url, {
    ...options,
    redirect: "manual",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json",
      ...(options.headers as Record<string, string> | undefined),
    },
  });

  if (REDIRECT_STATUSES.includes(resp.status)) {
    throw new ProviderError(`Unexpected redirect (${resp.status}) from ${new URL(url).host}`);
  }

  if (authFailureStatuses.includes(resp.status)) {
    throw new AuthError();
  }

  return resp;
}

/** Matches a canonical UUID, e.g. a DigitalOcean or UpCloud resource id. */
export function looksLikeUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}
