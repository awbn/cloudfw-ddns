export interface FirewallProvider {
  updateFirewall(token: string, firewallNameOrId: string, ip: string): Promise<void>;
}

/**
 * How a provider is exposed to callers. To add a new provider, implement
 * {@link FirewallProvider} and add a single {@link ProviderRegistration} to the
 * list in `registry.ts` — nothing else needs to change.
 */
export interface ProviderRegistration {
  /** Canonical, human-readable name, e.g. `"hetzner"`. */
  name: string;
  /** Short aliases callers may use instead, e.g. `["hz"]`. */
  aliases: string[];
  /** The provider implementation. */
  provider: FirewallProvider;
}

export class AuthError extends Error {
  constructor(message = "unauthorized") {
    super(message);
    this.name = "AuthError";
  }
}

export class UpdateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UpdateError";
  }
}

export class ProviderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProviderError";
  }
}
