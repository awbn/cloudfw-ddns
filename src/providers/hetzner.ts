import { FirewallProvider, AuthError, UpdateError, ProviderError } from "./types";

const API_BASE = "https://api.hetzner.cloud/v1";

interface HetznerFirewall {
  id: number;
  name: string;
  labels: Record<string, string>;
}

interface HetznerRule {
  direction: string;
  protocol: string;
  port?: string;
  source_ips?: string[];
  destination_ips?: string[];
  description?: string;
}

async function hetznerFetch(url: string, token: string, options: RequestInit = {}): Promise<Response> {
  const resp = await fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...(options.headers as Record<string, string> | undefined),
    },
  });

  if (resp.status === 401 || resp.status === 403) {
    throw new AuthError();
  }

  return resp;
}

function isNumericId(value: string): boolean {
  return /^\d+$/.test(value);
}

function parseLabelSelector(input: string): string | null {
  let selector: string | null = null;
  if (input.startsWith("label:")) {
    selector = input.slice(6);
  } else if (input.startsWith("l:")) {
    selector = input.slice(2);
  }
  if (selector !== null && !/^[a-zA-Z0-9_.\/\-]+(=[a-zA-Z0-9_.\/\-]+)?(,[a-zA-Z0-9_.\/\-]+(=[a-zA-Z0-9_.\/\-]+)?)*$/.test(selector)) {
    throw new UpdateError("Invalid label selector format");
  }
  return selector;
}

interface ResolvedFirewall {
  id: number;
  name: string;
}

async function resolveFirewalls(token: string, nameOrId: string): Promise<ResolvedFirewall[]> {
  const labelSelector = parseLabelSelector(nameOrId);
  if (labelSelector) {
    const resp = await hetznerFetch(
      `${API_BASE}/firewalls?label_selector=${labelSelector}`,
      token
    );
    if (!resp.ok) {
      throw new ProviderError(`Failed to list firewalls: ${resp.status}`);
    }
    const data = (await resp.json()) as { firewalls: HetznerFirewall[] };
    if (data.firewalls.length === 0) {
      throw new UpdateError(`No firewalls found with label: ${labelSelector}`);
    }
    const firewalls = data.firewalls.map((f) => ({ id: f.id, name: f.name }));
    console.log(`Label "${labelSelector}" matched ${firewalls.length} firewall(s): ${firewalls.map((f) => `${f.name} (${f.id})`).join(", ")}`);
    return firewalls;
  }

  if (isNumericId(nameOrId)) {
    return [{ id: parseInt(nameOrId, 10), name: nameOrId }];
  }

  const resp = await hetznerFetch(`${API_BASE}/firewalls?name=${encodeURIComponent(nameOrId)}`, token);
  if (!resp.ok) {
    throw new ProviderError(`Failed to list firewalls: ${resp.status}`);
  }

  const data = (await resp.json()) as { firewalls: HetznerFirewall[] };
  const fw = data.firewalls.find((f) => f.name === nameOrId);
  if (!fw) {
    throw new UpdateError(`Firewall not found: ${nameOrId}`);
  }

  return [{ id: fw.id, name: fw.name }];
}

async function updateSingleFirewall(token: string, id: number, ip: string, label: string): Promise<void> {
  const resp = await hetznerFetch(`${API_BASE}/firewalls/${id}`, token);
  if (resp.status === 404) {
    throw new UpdateError(`Firewall not found: ${label}`);
  }
  if (!resp.ok) {
    throw new ProviderError(`Failed to get firewall: ${resp.status}`);
  }

  const data = (await resp.json()) as { firewall: { id: number; name: string; rules: HetznerRule[] } };
  const rules = data.firewall.rules;

  const updatedRules = rules.map((rule) => {
    if (rule.direction === "in" && rule.source_ips) {
      return { ...rule, source_ips: [`${ip}/32`] };
    }
    return rule;
  });

  const postResp = await hetznerFetch(`${API_BASE}/firewalls/${id}/actions/set_rules`, token, {
    method: "POST",
    body: JSON.stringify({ rules: updatedRules }),
  });

  if (!postResp.ok) {
    const body = await postResp.text();
    throw new ProviderError(`Failed to update firewall: ${postResp.status} ${body}`);
  }
}

export class HetznerProvider implements FirewallProvider {
  async updateFirewall(token: string, firewallNameOrId: string, ip: string): Promise<void> {
    const firewalls = await resolveFirewalls(token, firewallNameOrId);

    for (const fw of firewalls) {
      await updateSingleFirewall(token, fw.id, ip, fw.name);
    }
  }
}
