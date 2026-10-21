import { FirewallProvider, UpdateError, ProviderError } from "./types";
import { authorizedFetch, looksLikeUuid } from "./http";
import { parseLabelSelector } from "./labels";
import { updateEach } from "./batch";

const API_BASE = "https://api.upcloud.com/1.3";

// Unlike DigitalOcean/Hetzner, an UpCloud server has exactly one firewall: a
// single flat chain of rules. There is no separate firewall object to scope a
// DDNS update to, so instead of rewriting every inbound rule (which would also
// clobber rules that serve public traffic, e.g. HTTP from 0.0.0.0/0), we only
// touch rules the operator has opted in by tagging with a hashtag in the rule's
// `comment` field. The default tag is `#ddns`.
//
// The caller's "hostname" therefore identifies a server (by UUID, or by its
// hostname/title) or a set of servers (by label selector, as for Hetzner), and
// may optionally carry a custom tag after a `#` delimiter:
//
//   ssh-box                    -> server "ssh-box",          rules tagged #ddns
//   ssh-box#ddns               -> server "ssh-box",          rules tagged #ddns
//   ssh-box#home               -> server "ssh-box",          rules tagged #home
//   <uuid>#home                -> server <uuid>,             rules tagged #home
//   l:env=prod                 -> servers labelled env=prod, rules tagged #ddns
//   label:env=prod,role=x#home -> servers with both labels,  rules tagged #home

const DEFAULT_TAG = "ddns";

interface UpCloudFirewallRule {
  direction: string;
  family: string;
  comment?: string;
  source_address_start?: string;
  source_address_end?: string;
  [key: string]: unknown;
}

interface UpCloudServer {
  uuid: string;
  hostname: string;
  title: string;
  [key: string]: unknown;
}

type UpCloudTarget =
  /** Server UUID, hostname, or title. */
  | { kind: "server"; serverNameOrId: string; tag: string }
  /** Label selector terms (`key` or `key=value`), all of which must match. */
  | { kind: "labels"; selectors: string[]; tag: string };

interface ResolvedServer {
  uuid: string;
  /** Human-readable identifier for logs and errors. */
  name: string;
}

/** A server whose rule chain has been fetched and rewritten, ready to PUT. */
interface PlannedUpdate {
  server: ResolvedServer;
  rules: UpCloudFirewallRule[];
}

function ucFetch(url: string, token: string, options: RequestInit = {}): Promise<Response> {
  return authorizedFetch(url, token, options);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Splits an optional `#<tag>` suffix off the target, then interprets the rest
// as either a label selector (`l:`/`label:` prefix) or a server identifier. The
// `#` character is reserved as the tag delimiter (server hostnames can't
// contain it, label selectors reject it, and titles rarely do).
function parseTarget(hostname: string): UpCloudTarget {
  const hashIdx = hostname.indexOf("#");
  const base = hashIdx === -1 ? hostname : hostname.slice(0, hashIdx);
  const tag = (hashIdx === -1 ? "" : hostname.slice(hashIdx + 1).trim()) || DEFAULT_TAG;

  const selector = parseLabelSelector(base);
  if (selector !== null) {
    return { kind: "labels", selectors: selector.split(","), tag };
  }
  return { kind: "server", serverNameOrId: base, tag };
}

// True when `comment` contains the hashtag `#<tag>` as a complete token, so
// `#ddns` matches "SSH from home #ddns" but not "#ddnsbackup". Case-insensitive.
function commentHasTag(comment: unknown, tag: string): boolean {
  if (typeof comment !== "string") {
    return false;
  }
  return new RegExp(`#${escapeRegExp(tag)}(?![\\w-])`, "i").test(comment);
}

async function listServers(token: string, selectors: string[] = []): Promise<UpCloudServer[]> {
  // UpCloud ANDs repeated `label` parameters, e.g. `?label=env%3Dprod&label=v2`.
  const query = new URLSearchParams();
  for (const selector of selectors) {
    query.append("label", selector);
  }
  const qs = query.toString();

  const resp = await ucFetch(`${API_BASE}/server${qs ? `?${qs}` : ""}`, token);
  if (!resp.ok) {
    throw new ProviderError(`Failed to list servers: ${resp.status}`);
  }

  const data = (await resp.json()) as { servers?: { server?: UpCloudServer[] } };
  return data.servers?.server ?? [];
}

async function resolveServers(token: string, target: UpCloudTarget): Promise<ResolvedServer[]> {
  if (target.kind === "labels") {
    const selector = target.selectors.join(",");
    const servers = await listServers(token, target.selectors);
    if (servers.length === 0) {
      throw new UpdateError(`No servers found with label: ${selector}`);
    }
    const resolved = servers.map((s) => ({ uuid: s.uuid, name: s.hostname || s.uuid }));
    console.log(`Label "${selector}" matched ${resolved.length} server(s): ${resolved.map((s) => `${s.name} (${s.uuid})`).join(", ")}`);
    return resolved;
  }

  const nameOrId = target.serverNameOrId;
  if (looksLikeUuid(nameOrId)) {
    return [{ uuid: nameOrId, name: nameOrId }];
  }

  const servers = await listServers(token);
  const match = servers.find((s) => s.hostname === nameOrId || s.title === nameOrId);
  if (!match) {
    throw new UpdateError(`Server not found: ${nameOrId}`);
  }

  return [{ uuid: match.uuid, name: nameOrId }];
}

function rulesUrl(uuid: string): string {
  return `${API_BASE}/server/${uuid}/firewall_rule`;
}

// Fetches a server's rule chain and rewrites the tagged rules in memory,
// without writing anything back.
async function planServerUpdate(
  token: string,
  server: ResolvedServer,
  tag: string,
  ip: string
): Promise<PlannedUpdate> {
  const resp = await ucFetch(rulesUrl(server.uuid), token);
  if (resp.status === 404) {
    throw new UpdateError(`Server not found: ${server.name}`);
  }
  if (!resp.ok) {
    throw new ProviderError(`Failed to get firewall rules: ${resp.status}`);
  }

  const data = (await resp.json()) as {
    firewall_rules?: { firewall_rule?: UpCloudFirewallRule[] };
  };
  const rules = data.firewall_rules?.firewall_rule ?? [];

  // Point only inbound IPv4 rules tagged `#<tag>` at the new address. Every
  // other rule — untagged rules serving public traffic, outbound rules, and
  // IPv6 rules (this service is IPv4-only) — is left untouched.
  let matched = 0;
  const updatedRules = rules.map((rule) => {
    if (rule.direction === "in" && rule.family === "IPv4" && commentHasTag(rule.comment, tag)) {
      matched++;
      return { ...rule, source_address_start: ip, source_address_end: ip };
    }
    return rule;
  });

  if (matched === 0) {
    throw new UpdateError(`No inbound IPv4 rules tagged #${tag} on server: ${server.name}`);
  }
  console.log(`Tag "#${tag}" matched ${matched} inbound IPv4 rule(s) on server ${server.uuid}`);

  return { server, rules: updatedRules };
}

async function applyServerUpdate(token: string, { server, rules }: PlannedUpdate): Promise<void> {
  // PUT atomically overwrites the server's entire firewall rule chain, so we
  // send back every rule (tagged ones rewritten, the rest verbatim).
  const putResp = await ucFetch(rulesUrl(server.uuid), token, {
    method: "PUT",
    body: JSON.stringify({ firewall_rules: { firewall_rule: rules } }),
  });

  if (!putResp.ok) {
    const body = await putResp.text();
    throw new ProviderError(`Failed to update firewall: ${putResp.status} ${body}`);
  }
}

export class UpCloudProvider implements FirewallProvider {
  async updateFirewall(token: string, firewallNameOrId: string, ip: string): Promise<void> {
    const target = parseTarget(firewallNameOrId);
    const servers = await resolveServers(token, target);

    // Plan every server before writing to any of them, so a misconfigured
    // server (e.g. labelled but missing the tag) fails the request without
    // leaving the group half-updated.
    const plans: PlannedUpdate[] = [];
    for (const server of servers) {
      plans.push(await planServerUpdate(token, server, target.tag, ip));
    }

    await updateEach(
      plans,
      ({ server }) => `server ${server.name} (${server.uuid})`,
      (plan) => applyServerUpdate(token, plan)
    );
  }
}
