# cloudfw-ddns

A Cloudflare Worker that updates cloud firewall rules with a dynamic IP address. Compatible with INADYN and dyndns clients.

Use this to restrict firewall access (e.g., SSH) to a home IP that changes periodically. When your IP changes, your router's DDNS client calls this worker, which updates the firewall rules on your cloud provider.

The worker itself is effectively a stateless proxy. It uses the credentials (an API Key) passed in by the DDNS client to call into the provider's firewall API and update the specified rule(s).

## Supported Providers

- **DigitalOcean** Cloud Firewalls (`digitalocean` or `do`)
- **Hetzner** Firewalls (`hetzner` or `hz`)
- **UpCloud** server firewalls (`upcloud` or `uc`)

Adding another provider? Follow the playbook in [`docs/adding-a-provider.md`](docs/adding-a-provider.md).

## How It Works

1. Your router (or other DDNS client) detects an IP change and sends a request to the worker
2. The worker validates the IP (must be public IPv4)
3. The worker authenticates with the cloud provider using the API token supplied by the DDNS client via basic auth
4. Inbound rules are updated to allow only the new IP. For DigitalOcean and Hetzner, **all** inbound rules on the specified firewall are updated. For UpCloud — where a server has a single firewall shared with application traffic — only inbound rules tagged `#ddns` in their comment are updated (see below). Outbound rules always remain unchanged.

## Deployment

```bash
npm install
npx wrangler deploy
```

## Usage

The worker accepts requests on `/update` (and `/nic/update` to retain ddclient compatibility) with the following parameters:

| Parameter | Source | Description |
|-----------|--------|-------------|
| `hostname` | Query string | Firewall name/ID, a Hetzner label selector (see below), or — for UpCloud — a server UUID, hostname, or title, optionally suffixed with `#<tag>` (see below) |
| `myip` or `ip` | Query string | The new IPv4 address |
| Username | Basic Auth | Provider name (`digitalocean`, `do`, `hetzner`, `hz`, `upcloud`, or `uc`) |
| Password | Basic Auth | API token for the provider |

### Best Practice for Providers that support it: Dedicate a Firewall to DDNS

For DigitalOcean and Hetzner, the worker rewrites **every** inbound rule on the firewall you target, replacing each rule's source with your current IP. So don't point it at a firewall that also carries public application traffic — you'd lock the world out of your app.

The recommended pattern uses these providers' ability to attach **multiple firewalls** to one server, keeping DDNS-managed rules separate from public ones:

1. Create a dedicated firewall (e.g. `ddns-ssh`) holding only the rules that should follow your dynamic IP — typically just SSH (tcp/22). The rules' sources can start as any placeholder; the worker overwrites them.
2. Keep your public/application rules (HTTP/HTTPS from `0.0.0.0/0`, etc.) in a **separate** firewall (e.g. `app-public`).
3. Attach **both** firewalls to the server. Cloud firewall rules are additive, so traffic is permitted if any attached firewall allows it.
4. Point the worker at the dedicated firewall only (`hostname=ddns-ssh`). Your public firewall is never touched.

- **DigitalOcean**: a Droplet can have multiple Cloud Firewalls applied — put SSH in the DDNS firewall and web ports in another.
- **Hetzner**: a server can have multiple firewalls attached — and you can update several DDNS firewalls at once with a [label selector](#hetzner-label-selector).

> [!TIP]
> On UpCloud this separation isn't possible — a server has a single firewall — so the worker instead scopes updates with per-rule tags (see below).

For **UpCloud**, firewall rules live on a server, so `hostname` identifies the server: pass its UUID, or its hostname/title (which is resolved to a UUID). See the UpCloud section below for how rules are selected.

### UpCloud Rule Tags

An UpCloud server has a single firewall — one flat chain of rules — with no separate firewall object to scope a DDNS update to. To avoid rewriting rules that serve public traffic (e.g. HTTPS from `0.0.0.0/0`), the worker only updates inbound IPv4 rules whose **comment** contains the hashtag `#ddns`. Everything else — untagged rules, outbound rules, and IPv6 rules — is left untouched. If no rule carries the tag, the request fails with a 400 rather than changing anything.

Tag the rule(s) you want DDNS-managed by adding `#ddns` anywhere in the rule's comment (e.g. `SSH from home #ddns`).

To use a different tag, suffix the `hostname` with `#<tag>`; the worker then matches `#<tag>` instead of `#ddns`:

```bash
# Default: updates inbound IPv4 rules commented with #ddns on server "ssh-box"
curl "https://your-worker.workers.dev/update?hostname=ssh-box&myip=1.2.3.4" \
  -u "uc:ucat_your_api_token"

# Custom tag: updates rules commented with #home instead
curl "https://your-worker.workers.dev/update?hostname=ssh-box%23home&myip=1.2.3.4" \
  -u "uc:ucat_your_api_token"
```

> [!NOTE]
> The `#` character in the `hostname` field is reserved as the tag delimiter, so remember to URL-encode it as `%23` in query strings.

### Hetzner Label Selector

For Hetzner, you can target multiple firewalls by label instead of name or ID. Prefix the hostname with `l:` or `label:` followed by a label selector. All matching firewalls will be updated.

```bash
# Update all firewalls with label env=prod
curl "https://your-worker.workers.dev/update?hostname=l:env=prod&myip=1.2.3.4" \
  -u "hetzner:your_api_token"

# Equivalent using the full prefix
curl "https://your-worker.workers.dev/update?hostname=label:env=prod&myip=1.2.3.4" \
  -u "hz:your_api_token"
```

### curl Example

```bash
# DigitalOcean / Hetzner: hostname is the firewall name or ID
curl "https://your-worker.workers.dev/update?hostname=my-firewall&myip=1.2.3.4" \
  -u "digitalocean:dop_v1_your_api_token"

# UpCloud: hostname is the server UUID (or its hostname/title);
# updates inbound IPv4 rules tagged #ddns in their comment
curl "https://your-worker.workers.dev/update?hostname=ssh-box&myip=1.2.3.4" \
  -u "uc:ucat_your_api_token"
```

### INADYN Configuration

```conf
provider default@cloudflare-ddns {
    hostname = my-firewall
    username = digitalocean
    password = dop_v1_your_api_token
    ddns-server = your-worker.workers.dev
    ddns-path = "/update?hostname=%h&ip=%i"
}
```
> [!TIP]
> Some routers may combine the server and path. In that case, enter `your-worker.workers.dev/update?hostname=%h&ip=%i`

### ddclient Configuration

```conf
protocol=dyndns2
server=your-worker.workers.dev
ssl=yes
login=hetzner
password='your_hetzner_api_token'
my-firewall
```

## API Responses

| Status | Body | Meaning |
|--------|------|---------|
| 200 | `success` | Firewall updated |
| 400 | Error details | Missing fields, invalid provider, invalid IP, or update failure |
| 401 | `unauthorized` | Invalid API token |
| 500 | `Internal server error` | Unexpected error |

## Development

```bash
npm install
npm run dev        # Start local dev server
npm test           # Run tests
```

Test the flow against the local dev server (note: this WILL update the firewall rule):

```bash
curl "http://localhost:8787/update?hostname=my-firewall&ip=1.2.3.4" \
  -u "digitalocean:dop_v1_your_api_token"
```

## Provider API Tokens

**DigitalOcean**: Generate a personal access token at https://cloud.digitalocean.com/account/api/tokens. Must have at least `firewall:read` and `firewall:update` scopes.

**Hetzner**: Generate an API token in your Hetzner Cloud project under Security > API Tokens

**UpCloud**: Create an API token (value begins with `ucat_`) in the UpCloud Control Panel under your account's API access settings. The worker uses UpCloud's Bearer-token authentication.
