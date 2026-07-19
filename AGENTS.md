# AGENTS.md

Guidance for AI coding assistants and contributors working in this repo.

## What this is

`cloudfw-ddns` is a stateless Cloudflare Worker that updates a cloud provider's
firewall rules to a new dynamic IPv4 address, for INADYN/dyndns clients. Entry
point: `src/index.ts`. Providers live in `src/providers/`.

## Architecture in one screen

- `src/index.ts` — routing (`/update`, `/nic/update`), Basic Auth parsing, IP
  validation, provider dispatch, and error → HTTP mapping.
- `src/validation.ts` — rejects IPv6 and RFC 1918; providers only ever see a
  public IPv4 string.
- `src/providers/registry.ts` — the single source of truth for supported
  providers. Add one entry to register a provider.
- `src/providers/types.ts` — the `FirewallProvider` interface and the
  `AuthError` / `UpdateError` / `ProviderError` taxonomy.
- `src/providers/http.ts` — `authorizedFetch` (Bearer auth, no redirects, auth
  errors) and `looksLikeUuid`. Build providers on these, not raw `fetch`.

## Runtime constraints

- Runs on the Cloudflare Workers runtime — no Node-only APIs. Only add an SDK
  after verifying it is Workers-compatible; otherwise hand-wrap the REST API.
- The service is stateless and IPv4-only.

## Commands

```bash
npm test           # vitest
npx tsc --noEmit   # typecheck
npm run dev        # local worker (wrangler)
npx wrangler deploy
```

## Common tasks

- **Add a new firewall provider** → follow the skill in
  [`docs/adding-a-provider.md`](docs/adding-a-provider.md).
