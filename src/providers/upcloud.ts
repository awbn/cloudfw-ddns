import { FirewallProvider, UpdateError, ProviderError } from "./types";
import { authorizedFetch, looksLikeUuid } from "./http";

const API_BASE = "https://api.upcloud.com/1.3";

// Unlike DigitalOcean/Hetzner, an UpCloud server has exactly one firewall: a
// single flat chain of rules. There is no separate firewall object to scope a
// DDNS update to, so instead of rewriting every inbound rule (which would also
// clobber rules that serve public traffic, e.g. HTTP from 0.0.0.0/0), we only
// touch rules the operator has opted in by tagging with a hashtag in the rule's
// `comment` field. The default tag is `#ddns`.
//
// The caller's "hostname" therefore identifies a server (by UUID, or by its
// hostname/title) and may optionally carry a custom tag after a `#` delimiter:
//
//   ssh-box            -> server "ssh-box",   rules tagged #ddns
//   ssh-box#ddns       -> server "ssh-box",   rules tagged #ddns
//   ssh-box#home       -> server "ssh-box",   rules tagged #home
//   <uuid>#home        -> server <uuid>,      rules tagged #home

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

interface UpCloudTarget {
  /** Server UUID, hostname, or title. */
  serverNameOrId: string;
  /** Bare tag name to look for as `#<tag>` in rule comments, e.g. `ddns`. */
  tag: string;
}

function ucFetch(url: string, token: string, options: RequestInit = {}): Promise<Response> {
  return authorizedFetch(url, token, options);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Splits an optional `#<tag>` suffix off the server identifier. The `#`
// character is reserved as the tag delimiter (server hostnames can't contain
// it; titles rarely do).
function parseTarget(hostname: string): UpCloudTarget {
  const hashIdx = hostname.indexOf("#");
  if (hashIdx === -1) {
    return { serverNameOrId: hostname, tag: DEFAULT_TAG };
  }
  const serverNameOrId = hostname.slice(0, hashIdx);
  const tag = hostname.slice(hashIdx + 1).trim() || DEFAULT_TAG;
  return { serverNameOrId, tag };
}

// True when `comment` contains the hashtag `#<tag>` as a complete token, so
// `#ddns` matches "SSH from home #ddns" but not "#ddnsbackup". Case-insensitive.
function commentHasTag(comment: unknown, tag: string): boolean {
  if (typeof comment !== "string") {
    return false;
  }
  return new RegExp(`#${escapeRegExp(tag)}(?![\\w-])`, "i").test(comment);
}

async function resolveServerUuid(token: string, nameOrId: string): Promise<string> {
  if (looksLikeUuid(nameOrId)) {
    return nameOrId;
  }

  const resp = await ucFetch(`${API_BASE}/server`, token);
  if (!resp.ok) {
    throw new ProviderError(`Failed to list servers: ${resp.status}`);
  }

  const data = (await resp.json()) as { servers?: { server?: UpCloudServer[] } };
  const servers = data.servers?.server ?? [];
  const match = servers.find((s) => s.hostname === nameOrId || s.title === nameOrId);
  if (!match) {
    throw new UpdateError(`Server not found: ${nameOrId}`);
  }

  return match.uuid;
}

export class UpCloudProvider implements FirewallProvider {
  async updateFirewall(token: string, firewallNameOrId: string, ip: string): Promise<void> {
    const { serverNameOrId, tag } = parseTarget(firewallNameOrId);
    const uuid = await resolveServerUuid(token, serverNameOrId);
    const rulesUrl = `${API_BASE}/server/${uuid}/firewall_rule`;

    const resp = await ucFetch(rulesUrl, token);
    if (resp.status === 404) {
      throw new UpdateError(`Server not found: ${serverNameOrId}`);
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
      throw new UpdateError(`No inbound IPv4 rules tagged #${tag} on server: ${serverNameOrId}`);
    }
    console.log(`Tag "#${tag}" matched ${matched} inbound IPv4 rule(s) on server ${uuid}`);

    // PUT atomically overwrites the server's entire firewall rule chain, so we
    // send back every rule (tagged ones rewritten, the rest verbatim).
    const putResp = await ucFetch(rulesUrl, token, {
      method: "PUT",
      body: JSON.stringify({ firewall_rules: { firewall_rule: updatedRules } }),
    });

    if (!putResp.ok) {
      const body = await putResp.text();
      throw new ProviderError(`Failed to update firewall: ${putResp.status} ${body}`);
    }
  }
}
