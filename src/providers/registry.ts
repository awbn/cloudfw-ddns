import { FirewallProvider } from "./types";
import { DigitalOceanProvider } from "./digitalocean";
import { HetznerProvider } from "./hetzner";

const providers: Record<string, FirewallProvider> = {
  digitalocean: new DigitalOceanProvider(),
  do: new DigitalOceanProvider(),
  hetzner: new HetznerProvider(),
  hz: new HetznerProvider(),
};

export function getProvider(name: string): FirewallProvider | undefined {
  return providers[name.toLowerCase()];
}

export function getValidProviderNames(): string[] {
  return Object.keys(providers);
}
