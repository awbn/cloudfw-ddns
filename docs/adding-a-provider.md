# Skill: Add a new firewall provider

A step-by-step playbook for adding support for another cloud firewall provider to
`cloudfw-ddns`. It is written to be followed by a human contributor or any coding
assistant — nothing here is tool-specific.

Read this whole file before writing code, then work top to bottom. Every claim
below is grounded in the current source; if the code has drifted, trust the code
and update this file.

## What a provider does

The worker (`src/index.ts`) is a stateless proxy. For each request it:

1. Parses `hostname`, `myip`/`ip`, and Basic Auth (`username` = provider, `password` = token).
2. Looks the provider up by name/alias in `src/providers/registry.ts`.
3. Validates the IP — **your provider only ever receives a public IPv4 string**
   (IPv6 and RFC 1918 addresses are rejected in `src/validation.ts` before you're
   called), with no CIDR suffix.
4. Calls `provider.updateFirewall(token, hostname, ip)` and maps thrown errors to
   HTTP status codes (see [Error taxonomy](#error-taxonomy)).

A provider is a single class implementing one method
(`src/providers/types.ts`):

```ts
export interface FirewallProvider {
  updateFirewall(token: string, firewallNameOrId: string, ip: string): Promise<void>;
}
```

The contract: point **every inbound rule** on the identified firewall at `ip`
(across all ports/services), leave **outbound rules untouched**, ignore IPv6
rules, and either return (success) or throw a typed error. Format the IP the way
the provider's API expects it (`${ip}/32` for DigitalOcean/Hetzner, a
`start == end == ip` range for UpCloud).

## Before you start: SDK vs. hand-wrapped REST

Prefer an official provider SDK **only if it runs on the Cloudflare Workers
runtime** — i.e. it is `fetch`-based and pulls in no Node-only APIs (`net`,
`fs`, `tls`, streams, etc.). Many do not. Vet it before committing: skim its
dependencies and its transport layer. If it isn't Workers-compatible, hand-wrap
the REST API with the shared `authorizedFetch` helper — that is why the existing
three providers are hand-wrapped. Do not add a dependency you haven't verified
loads under `nodejs_compat`.

## Step 1 — Implement the provider

Create `src/providers/<name>.ts`. Build on the shared helpers in
`src/providers/http.ts` rather than calling `fetch` directly:

- `authorizedFetch(url, token, options?, opts?)` — adds the `Bearer` token and
  JSON headers, refuses redirects (so the token can't be replayed to another
  host), and throws `AuthError` on an auth-failure status. The default
  auth-failure status is `401`; pass `{ authFailureStatuses: [401, 403] }` if the
  provider also uses `403` for bad tokens (Hetzner does).
- `looksLikeUuid(value)` — use it (or a numeric/id check) to skip a name→id
  lookup when the caller already passed an id.

Typical shape (adapt to the provider's API):

```ts
import { FirewallProvider, UpdateError, ProviderError } from "./types";
import { authorizedFetch, looksLikeUuid } from "./http";

const API_BASE = "https://api.example.com/v1";

function exFetch(url: string, token: string, options: RequestInit = {}): Promise<Response> {
  return authorizedFetch(url, token, options);
}

async function resolveFirewallId(token: string, nameOrId: string): Promise<string> {
  if (looksLikeUuid(nameOrId)) return nameOrId;            // already an id
  const resp = await exFetch(`${API_BASE}/firewalls`, token);
  if (!resp.ok) throw new ProviderError(`Failed to list firewalls: ${resp.status}`);
  const data = (await resp.json()) as { firewalls: { id: string; name: string }[] };
  const fw = data.firewalls.find((f) => f.name === nameOrId);
  if (!fw) throw new UpdateError(`Firewall not found: ${nameOrId}`);
  return fw.id;
}

export class ExampleProvider implements FirewallProvider {
  async updateFirewall(token: string, firewallNameOrId: string, ip: string): Promise<void> {
    const id = await resolveFirewallId(token, firewallNameOrId);

    const resp = await exFetch(`${API_BASE}/firewalls/${id}`, token);
    if (resp.status === 404) throw new UpdateError(`Firewall not found: ${firewallNameOrId}`);
    if (!resp.ok) throw new ProviderError(`Failed to get firewall: ${resp.status}`);
    const { firewall } = (await resp.json()) as { firewall: { inbound_rules: any[]; outbound_rules: any[] } };

    // Rewrite inbound sources; leave outbound rules verbatim.
    const inbound = firewall.inbound_rules.map((rule) => ({ ...rule, sources: [`${ip}/32`] }));

    const put = await exFetch(`${API_BASE}/firewalls/${id}`, token, {
      method: "PUT",
      body: JSON.stringify({ inbound_rules: inbound, outbound_rules: firewall.outbound_rules }),
    });
    if (!put.ok) {
      const body = await put.text();
      throw new ProviderError(`Failed to update firewall: ${put.status} ${body}`);
    }
  }
}
```

### Scoping: which rules do you rewrite?

- **The provider has separate firewall objects you can attach to a server**
  (DigitalOcean, Hetzner): the firewall *is* the scope — rewrite all its inbound
  rules. Document the "dedicate a firewall to DDNS" pattern (see the README).
- **One firewall per server, shared with app traffic** (UpCloud): you cannot
  scope by object, so scope *within* the rule chain — e.g. only rewrite rules an
  operator opted into with a comment tag like `#ddns` — and fail with an
  `UpdateError` if nothing matches, rather than clobbering the whole chain. See
  `src/providers/upcloud.ts` for the reference implementation.

## Step 2 — Register it

Add one entry to the `registrations` array in `src/providers/registry.ts`. The
lookup table and the list of valid provider names are derived from it
automatically — nothing else needs to change.

```ts
{ name: "example", aliases: ["ex"], provider: new ExampleProvider() },
```

Names and aliases are matched case-insensitively.

## Step 3 — Error taxonomy

Throw the right type from `src/providers/types.ts`; `src/index.ts` maps each to a
status code:

| Throw | HTTP | Use it when |
|-------|------|-------------|
| `AuthError` | 401 `unauthorized` | Bad/insufficient token. Usually raised for you by `authorizedFetch`. |
| `UpdateError` | 400 `Failed to update firewall` | Caller-fixable: firewall/server not found, bad selector, nothing matched to update. |
| `ProviderError` | 500 `Internal server error` | Unexpected upstream failure: a non-OK list/get/set response. |
| anything else | 500 | Bugs; avoid relying on this. |

Do not put sensitive data (tokens, full upstream bodies with secrets) into error
messages — they may be logged.

## Step 4 — Tests

Add `test/<name>.test.ts`, mirroring the queue-based `mockFetch` pattern in the
existing provider tests (`test/digitalocean.test.ts`, `test/hetzner.test.ts`,
`test/upcloud.test.ts`). Cover at least:

- Happy path: every inbound rule's source becomes the new IP; the PUT/POST body
  is asserted.
- Name → id resolution (and the id-passed-directly shortcut).
- Outbound and IPv6 rules are left unchanged.
- `401` (or `403` where applicable) → `AuthError`.
- Firewall/server not found → `UpdateError`.
- Any provider-specific scoping (e.g. a tag/label/selector) and its
  "nothing matched" case.

Run `npm test` — all suites must pass. Run `npx tsc --noEmit` for a clean
typecheck.

## Step 5 — Documentation

Update `README.md`:

- **Supported Providers** — add the display name and its `name`/aliases.
- **Usage** — add the aliases to the `Username` row/param table, and add a
  `curl` example.
- **Provider API Tokens** — how to create a token and the scopes it needs.
- **How It Works** — only if your provider's rule-selection behavior differs from
  "all inbound rules on the firewall" (as UpCloud's does).

## Definition of done

- [ ] `src/providers/<name>.ts` implements `FirewallProvider`, built on
      `authorizedFetch`, IPv4-only, inbound-only, all-ports.
- [ ] One `ProviderRegistration` added to `registry.ts`.
- [ ] Errors use `AuthError` / `UpdateError` / `ProviderError` per the taxonomy.
- [ ] Any bundled SDK is confirmed Workers-compatible (else hand-wrapped REST).
- [ ] `test/<name>.test.ts` added; `npm test` and `npx tsc --noEmit` pass.
- [ ] `README.md` updated (providers, usage, tokens, and behavior if it differs).
