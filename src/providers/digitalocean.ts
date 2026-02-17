import { FirewallProvider, AuthError, UpdateError, ProviderError } from "./types";

const API_BASE = "https://api.digitalocean.com/v2";

interface DOFirewall {
  id: string;
  name: string;
  inbound_rules: DOInboundRule[];
  outbound_rules: DOOutboundRule[];
  droplet_ids: number[];
  tags: string[];
  [key: string]: unknown;
}

interface DOInboundRule {
  protocol: string;
  ports: string;
  sources: { addresses: string[]; [key: string]: unknown };
}

interface DOOutboundRule {
  protocol: string;
  ports: string;
  destinations: { addresses: string[]; [key: string]: unknown };
}

async function doFetch(url: string, token: string, options: RequestInit = {}): Promise<Response> {
  const resp = await fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...(options.headers as Record<string, string> | undefined),
    },
  });

  if (resp.status === 401) {
    throw new AuthError();
  }

  return resp;
}

function looksLikeUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

async function resolveFirewallId(token: string, nameOrId: string): Promise<string> {
  if (looksLikeUuid(nameOrId)) {
    return nameOrId;
  }

  const resp = await doFetch(`${API_BASE}/firewalls`, token);
  if (!resp.ok) {
    throw new ProviderError(`Failed to list firewalls: ${resp.status}`);
  }

  const data = (await resp.json()) as { firewalls: DOFirewall[] };
  const fw = data.firewalls.find((f) => f.name === nameOrId);
  if (!fw) {
    throw new UpdateError(`Firewall not found: ${nameOrId}`);
  }

  return fw.id;
}

export class DigitalOceanProvider implements FirewallProvider {
  async updateFirewall(token: string, firewallNameOrId: string, ip: string): Promise<void> {
    const id = await resolveFirewallId(token, firewallNameOrId);

    const resp = await doFetch(`${API_BASE}/firewalls/${id}`, token);
    if (resp.status === 404) {
      throw new UpdateError(`Firewall not found: ${firewallNameOrId}`);
    }
    if (!resp.ok) {
      throw new ProviderError(`Failed to get firewall: ${resp.status}`);
    }

    const data = (await resp.json()) as { firewall: DOFirewall };
    const firewall = data.firewall;

    const updatedInbound = firewall.inbound_rules.map((rule) => ({
      ...rule,
      sources: { ...rule.sources, addresses: [`${ip}/32`] },
    }));

    const putResp = await doFetch(`${API_BASE}/firewalls/${id}`, token, {
      method: "PUT",
      body: JSON.stringify({
        name: firewall.name,
        inbound_rules: updatedInbound,
        outbound_rules: firewall.outbound_rules,
        droplet_ids: firewall.droplet_ids,
        tags: firewall.tags,
      }),
    });

    if (!putResp.ok) {
      const body = await putResp.text();
      throw new ProviderError(`Failed to update firewall: ${putResp.status} ${body}`);
    }
  }
}
