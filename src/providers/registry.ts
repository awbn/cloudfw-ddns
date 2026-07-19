import { FirewallProvider, ProviderRegistration } from "./types";
import { DigitalOceanProvider } from "./digitalocean";
import { HetznerProvider } from "./hetzner";
import { UpCloudProvider } from "./upcloud";

/**
 * The single source of truth for supported providers. Add a new provider by
 * appending one entry here; the lookup table and the list of valid names are
 * derived from it automatically.
 */
const registrations: ProviderRegistration[] = [
  { name: "digitalocean", aliases: ["do"], provider: new DigitalOceanProvider() },
  { name: "hetzner", aliases: ["hz"], provider: new HetznerProvider() },
  { name: "upcloud", aliases: ["uc"], provider: new UpCloudProvider() },
];

const byName = new Map<string, FirewallProvider>();
for (const { name, aliases, provider } of registrations) {
  for (const key of [name, ...aliases]) {
    byName.set(key.toLowerCase(), provider);
  }
}

export function getProvider(name: string): FirewallProvider | undefined {
  return byName.get(name.toLowerCase());
}

export function getValidProviderNames(): string[] {
  return registrations.flatMap(({ name, aliases }) => [name, ...aliases]);
}
