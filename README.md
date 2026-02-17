# cloudfw-ddns

A Cloudflare Worker that updates cloud firewall rules with a dynamic IP address. Compatible with INADYN and dyndns clients.

Use this to restrict firewall access (e.g., SSH) to a home IP that changes periodically. When your IP changes, your router's DDNS client calls this worker, which updates the firewall rules on your cloud provider.

## Supported Providers

- **DigitalOcean** Cloud Firewalls (`digitalocean` or `do`)
- **Hetzner** Firewalls (`hetzner` or `hz`)

## How It Works

1. Your router detects an IP change and sends a request to the worker
2. The worker validates the IP (must be public IPv4)
3. The worker authenticates with the cloud provider using the supplied API token
4. All **inbound** rules on the specified firewall are updated to allow only the new IP. Outbound rules remain unchanged.

## Deployment

```bash
npm install
npx wrangler deploy
```

## Usage

The worker accepts requests on any path with the following parameters:

| Parameter | Source | Description |
|-----------|--------|-------------|
| `hostname` | Query string | Firewall name, ID, or label selector (Hetzner only, see below) |
| `myip` or `ip` | Query string | The new IPv4 address |
| Username | Basic Auth | Provider name (`digitalocean`, `do`, `hetzner`, or `hz`) |
| Password | Basic Auth | API token for the provider |

### Hetzner Label Selector

For Hetzner, you can target multiple firewalls by label instead of name or ID. Prefix the hostname with `l:` or `label:` followed by a label selector. All matching firewalls will be updated.

```bash
# Update all firewalls with label env=prod
curl "https://your-worker.workers.dev/cfwd/update?hostname=l:env=prod&myip=1.2.3.4" \
  -u "hetzner:your_api_token"

# Equivalent using the full prefix
curl "https://your-worker.workers.dev/cfwd/update?hostname=label:env=prod&myip=1.2.3.4" \
  -u "hz:your_api_token"
```

### curl Example

```bash
curl "https://your-worker.workers.dev/update?hostname=my-firewall&myip=1.2.3.4" \
  -u "digitalocean:dop_v1_your_api_token"
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

## Provider API Tokens

**DigitalOcean**: Generate a personal access token at https://cloud.digitalocean.com/account/api/tokens. Must have at least `firewall:read` and `firewall:update` scopes.

**Hetzner**: Generate an API token in your Hetzner Cloud project under Security > API Tokens
