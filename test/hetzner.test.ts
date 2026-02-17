import { describe, it, expect, vi, beforeEach } from "vitest";
import { HetznerProvider } from "../src/providers/hetzner";
import { AuthError, UpdateError } from "../src/providers/types";

const provider = new HetznerProvider();

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

describe("HetznerProvider", () => {
  it("updates firewall by numeric ID", async () => {
    const firewall = {
      id: 12345,
      name: "my-fw",
      rules: [
        { direction: "in", protocol: "tcp", port: "22", source_ips: ["old-ip/32"] },
        { direction: "out", protocol: "tcp", port: "80", destination_ips: ["0.0.0.0/0"] },
      ],
    };

    mockFetch([
      { status: 200, body: { firewall } },
      { status: 200, body: { actions: [] } },
    ]);

    await provider.updateFirewall("token", "12345", "1.2.3.4");

    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
    expect(calls).toHaveLength(2);

    expect(calls[0][0]).toContain("/firewalls/12345");

    const postBody = JSON.parse(calls[1][1].body);
    // Inbound rule should have updated IP
    expect(postBody.rules[0].source_ips).toEqual(["1.2.3.4/32"]);
    // Outbound rule should be unchanged
    expect(postBody.rules[1].destination_ips).toEqual(["0.0.0.0/0"]);
  });

  it("resolves firewall by name", async () => {
    const firewall = {
      id: 999,
      name: "ssh-firewall",
      rules: [
        { direction: "in", protocol: "tcp", port: "22", source_ips: ["0.0.0.0/0"] },
      ],
    };

    mockFetch([
      { status: 200, body: { firewalls: [firewall] } },
      { status: 200, body: { firewall } },
      { status: 200, body: { actions: [] } },
    ]);

    await provider.updateFirewall("token", "ssh-firewall", "5.6.7.8");

    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
    expect(calls[0][0]).toContain("/firewalls?name=ssh-firewall");
    expect(calls[1][0]).toContain("/firewalls/999");
  });

  it("throws AuthError on 401", async () => {
    mockFetch([{ status: 401 }]);

    await expect(provider.updateFirewall("bad-token", "12345", "1.2.3.4")).rejects.toThrow(AuthError);
  });

  it("throws AuthError on 403", async () => {
    mockFetch([{ status: 403 }]);

    await expect(provider.updateFirewall("bad-token", "12345", "1.2.3.4")).rejects.toThrow(AuthError);
  });

  it("throws UpdateError when firewall not found by name", async () => {
    mockFetch([{ status: 200, body: { firewalls: [] } }]);

    await expect(provider.updateFirewall("token", "nonexistent", "1.2.3.4")).rejects.toThrow(UpdateError);
  });

  it("resolves firewalls by label with l: prefix", async () => {
    const fw1 = {
      id: 10,
      name: "fw-a",
      rules: [{ direction: "in", protocol: "tcp", port: "22", source_ips: ["old/32"] }],
    };
    const fw2 = {
      id: 20,
      name: "fw-b",
      rules: [{ direction: "in", protocol: "tcp", port: "443", source_ips: ["old/32"] }],
    };

    mockFetch([
      { status: 200, body: { firewalls: [{ id: 10, name: "fw-a" }, { id: 20, name: "fw-b" }] } },
      { status: 200, body: { firewall: fw1 } },
      { status: 200, body: { actions: [] } },
      { status: 200, body: { firewall: fw2 } },
      { status: 200, body: { actions: [] } },
    ]);

    await provider.updateFirewall("token", "l:env=prod", "1.2.3.4");

    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
    expect(calls[0][0]).toContain("/firewalls?label_selector=env=prod");
    expect(calls[1][0]).toContain("/firewalls/10");
    expect(calls[3][0]).toContain("/firewalls/20");

    const post1 = JSON.parse(calls[2][1].body);
    expect(post1.rules[0].source_ips).toEqual(["1.2.3.4/32"]);
    const post2 = JSON.parse(calls[4][1].body);
    expect(post2.rules[0].source_ips).toEqual(["1.2.3.4/32"]);
  });

  it("resolves firewalls by label with label: prefix", async () => {
    const fw = {
      id: 30,
      name: "fw-c",
      rules: [{ direction: "in", protocol: "tcp", port: "22", source_ips: ["old/32"] }],
    };

    mockFetch([
      { status: 200, body: { firewalls: [{ id: 30, name: "fw-c" }] } },
      { status: 200, body: { firewall: fw } },
      { status: 200, body: { actions: [] } },
    ]);

    await provider.updateFirewall("token", "label:env=staging", "5.6.7.8");

    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
    expect(calls[0][0]).toContain("/firewalls?label_selector=env=staging");
  });

  it("throws UpdateError when no firewalls match label", async () => {
    mockFetch([{ status: 200, body: { firewalls: [] } }]);

    await expect(provider.updateFirewall("token", "l:env=nope", "1.2.3.4")).rejects.toThrow(UpdateError);
  });

  it("throws UpdateError for invalid label selector format", async () => {
    await expect(provider.updateFirewall("token", "l:env=prod&malicious=true", "1.2.3.4")).rejects.toThrow(UpdateError);
    await expect(provider.updateFirewall("token", "l:", "1.2.3.4")).rejects.toThrow(UpdateError);
    await expect(provider.updateFirewall("token", "label:has spaces", "1.2.3.4")).rejects.toThrow(UpdateError);
  });
});
