import { describe, it, expect, vi, beforeEach } from "vitest";
import { DigitalOceanProvider } from "../src/providers/digitalocean";
import { AuthError, UpdateError } from "../src/providers/types";

const provider = new DigitalOceanProvider();

function mockFetch(responses: Array<{ status: number; body?: unknown }>): void {
  const queue = [...responses];
  vi.stubGlobal(
    "fetch",
    vi.fn(() => {
      const resp = queue.shift()!;
      return Promise.resolve({
        ok: resp.status >= 200 && resp.status < 300,
        status: resp.status,
        json: () => Promise.resolve(resp.body),
        text: () => Promise.resolve(JSON.stringify(resp.body ?? "")),
      });
    })
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("DigitalOceanProvider", () => {
  it("updates firewall by ID", async () => {
    const firewall = {
      id: "abc-123",
      name: "my-fw",
      inbound_rules: [
        { protocol: "tcp", ports: "22", sources: { addresses: ["old-ip/32"] } },
      ],
      outbound_rules: [],
      droplet_ids: [1],
      tags: [],
    };

    mockFetch([
      { status: 200, body: { firewall } },
      { status: 200, body: { firewall } },
    ]);

    await provider.updateFirewall("token", "abc12345-1234-1234-1234-abc123456789", "1.2.3.4");

    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
    expect(calls).toHaveLength(2);

    // GET firewall
    expect(calls[0][0]).toContain("/firewalls/abc12345-1234-1234-1234-abc123456789");

    // PUT with updated IP
    const putBody = JSON.parse(calls[1][1].body);
    expect(putBody.inbound_rules[0].sources.addresses).toEqual(["1.2.3.4/32"]);
  });

  it("resolves firewall by name", async () => {
    const firewall = {
      id: "fw-id-456",
      name: "my-firewall",
      inbound_rules: [
        { protocol: "tcp", ports: "22", sources: { addresses: [] } },
      ],
      outbound_rules: [],
      droplet_ids: [],
      tags: [],
    };

    mockFetch([
      { status: 200, body: { firewalls: [firewall] } },
      { status: 200, body: { firewall } },
      { status: 200, body: { firewall } },
    ]);

    await provider.updateFirewall("token", "my-firewall", "5.6.7.8");

    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
    // First call: list firewalls, second: GET by ID, third: PUT
    expect(calls[0][0]).toContain("/firewalls");
    expect(calls[1][0]).toContain("/firewalls/fw-id-456");
  });

  it("throws AuthError on 401", async () => {
    mockFetch([{ status: 401 }]);

    await expect(provider.updateFirewall("bad-token", "123", "1.2.3.4")).rejects.toThrow(AuthError);
  });

  it("throws UpdateError when firewall not found by name", async () => {
    mockFetch([{ status: 200, body: { firewalls: [] } }]);

    await expect(provider.updateFirewall("token", "nonexistent", "1.2.3.4")).rejects.toThrow(UpdateError);
  });

  it("throws UpdateError when firewall not found by ID (404)", async () => {
    mockFetch([{ status: 404 }]);

    await expect(
      provider.updateFirewall("token", "abc12345-1234-1234-1234-abc123456789", "1.2.3.4")
    ).rejects.toThrow(UpdateError);
  });
});
