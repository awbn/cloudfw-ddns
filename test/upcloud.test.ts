import { describe, it, expect, vi, beforeEach } from "vitest";
import { UpCloudProvider } from "../src/providers/upcloud";
import { AuthError, ProviderError, UpdateError } from "../src/providers/types";

const provider = new UpCloudProvider();

const UUID = "00798b85-efdc-41ca-8021-f6ef457b8531";
const UUID2 = "0063f3a4-4c5e-4d1b-9b0e-1f2a3b4c5d6e";

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

function rules(...rules: object[]) {
  return { firewall_rules: { firewall_rule: rules } };
}

// Convenience: the inbound SSH rule an operator would tag for DDNS management.
function sshRule(overrides: object = {}) {
  return {
    direction: "in",
    family: "IPv4",
    protocol: "tcp",
    comment: "SSH from home #ddns",
    source_address_start: "9.9.9.9",
    source_address_end: "9.9.9.9",
    ...overrides,
  };
}

// A public HTTPS rule (0.0.0.0/0) that must never be rewritten.
function publicRule(overrides: object = {}) {
  return {
    direction: "in",
    family: "IPv4",
    protocol: "tcp",
    comment: "Public HTTPS",
    source_address_start: "0.0.0.0",
    source_address_end: "255.255.255.255",
    ...overrides,
  };
}

function serverList(...servers: object[]) {
  return { servers: { server: servers } };
}

function putRulesOf(calls: any[], index: number) {
  return JSON.parse(calls[index][1].body).firewall_rules.firewall_rule;
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("UpCloudProvider", () => {
  it("updates only the #ddns-tagged inbound IPv4 rule by server UUID", async () => {
    mockFetch([
      { status: 200, body: rules(sshRule(), publicRule()) },
      { status: 204 },
    ]);

    await provider.updateFirewall("ucat_token", UUID, "1.2.3.4");

    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
    expect(calls).toHaveLength(2);

    // No name lookup when a UUID is supplied — first call is the rule list.
    expect(calls[0][0]).toBe(`https://api.upcloud.com/1.3/server/${UUID}/firewall_rule`);
    expect(calls[1][1].method).toBe("PUT");

    const putRules = putRulesOf(calls, 1);
    // Tagged rule points at the new IP.
    expect(putRules[0].source_address_start).toBe("1.2.3.4");
    expect(putRules[0].source_address_end).toBe("1.2.3.4");
    // Untagged public rule is left completely untouched.
    expect(putRules[1].source_address_start).toBe("0.0.0.0");
    expect(putRules[1].source_address_end).toBe("255.255.255.255");
  });

  it("leaves untagged inbound rules unchanged", async () => {
    mockFetch([
      { status: 200, body: rules(publicRule(), sshRule({ comment: "just an SSH rule, no tag" })) },
      { status: 204 },
    ]);

    // Neither rule carries #ddns, so there is nothing to update.
    await expect(provider.updateFirewall("ucat_token", UUID, "1.2.3.4")).rejects.toThrow(
      UpdateError
    );
  });

  it("does not match a hashtag that is only a prefix (#ddns != #ddnsbackup)", async () => {
    mockFetch([
      { status: 200, body: rules(sshRule({ comment: "#ddnsbackup only" })) },
    ]);

    await expect(provider.updateFirewall("ucat_token", UUID, "1.2.3.4")).rejects.toThrow(
      UpdateError
    );
  });

  it("leaves IPv6 rules unchanged even when tagged", async () => {
    mockFetch([
      {
        status: 200,
        body: rules(
          sshRule({ family: "IPv6", source_address_start: "2001:db8::1", source_address_end: "2001:db8::1" }),
          sshRule()
        ),
      },
      { status: 204 },
    ]);

    await provider.updateFirewall("ucat_token", UUID, "1.2.3.4");

    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
    const putRules = putRulesOf(calls, 1);
    // Tagged IPv6 rule untouched...
    expect(putRules[0].source_address_start).toBe("2001:db8::1");
    // ...tagged IPv4 rule rewritten.
    expect(putRules[1].source_address_start).toBe("1.2.3.4");
  });

  it("supports a custom tag via the server#tag hostname syntax", async () => {
    mockFetch([
      {
        status: 200,
        body: rules(sshRule({ comment: "home #home" }), sshRule()),
      },
      { status: 204 },
    ]);

    await provider.updateFirewall("ucat_token", `${UUID}#home`, "5.6.7.8");

    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
    // A UUID with a #tag suffix still resolves without a name lookup.
    expect(calls[0][0]).toBe(`https://api.upcloud.com/1.3/server/${UUID}/firewall_rule`);

    const putRules = putRulesOf(calls, 1);
    // Only the #home rule is rewritten; the #ddns rule is left alone.
    expect(putRules[0].source_address_start).toBe("5.6.7.8");
    expect(putRules[1].source_address_start).toBe("9.9.9.9");
  });

  it("resolves server by hostname, then updates the tagged rule", async () => {
    mockFetch([
      {
        status: 200,
        body: {
          servers: {
            server: [
              { uuid: "other-uuid", hostname: "web", title: "Web" },
              { uuid: UUID, hostname: "ssh-box", title: "SSH Box" },
            ],
          },
        },
      },
      { status: 200, body: rules(sshRule()) },
      { status: 204 },
    ]);

    await provider.updateFirewall("ucat_token", "ssh-box", "5.6.7.8");

    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
    expect(calls[0][0]).toBe("https://api.upcloud.com/1.3/server");
    expect(calls[1][0]).toBe(`https://api.upcloud.com/1.3/server/${UUID}/firewall_rule`);
    expect(calls[2][1].method).toBe("PUT");
    expect(putRulesOf(calls, 2)[0].source_address_start).toBe("5.6.7.8");
  });

  it("resolves server by name and honors a custom tag together (name#tag)", async () => {
    mockFetch([
      {
        status: 200,
        body: { servers: { server: [{ uuid: UUID, hostname: "ssh-box", title: "SSH Box" }] } },
      },
      { status: 200, body: rules(sshRule({ comment: "home #home" })) },
      { status: 204 },
    ]);

    await provider.updateFirewall("ucat_token", "ssh-box#home", "5.6.7.8");

    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
    // The server lookup uses the name without the #tag suffix.
    expect(calls[0][0]).toBe("https://api.upcloud.com/1.3/server");
    expect(calls[1][0]).toBe(`https://api.upcloud.com/1.3/server/${UUID}/firewall_rule`);
    expect(putRulesOf(calls, 2)[0].source_address_start).toBe("5.6.7.8");
  });

  it("throws AuthError on 401", async () => {
    mockFetch([{ status: 401 }]);
    await expect(provider.updateFirewall("bad", UUID, "1.2.3.4")).rejects.toThrow(AuthError);
  });

  it("throws UpdateError when server not found by name", async () => {
    mockFetch([{ status: 200, body: { servers: { server: [] } } }]);
    await expect(provider.updateFirewall("ucat_token", "nope", "1.2.3.4")).rejects.toThrow(
      UpdateError
    );
  });

  it("throws UpdateError when server not found by UUID (404)", async () => {
    mockFetch([{ status: 404 }]);
    await expect(provider.updateFirewall("ucat_token", UUID, "1.2.3.4")).rejects.toThrow(
      UpdateError
    );
  });

  describe("label selectors", () => {
    const boxA = { uuid: UUID, hostname: "box-a", title: "Box A" };
    const boxB = { uuid: UUID2, hostname: "box-b", title: "Box B" };

    it("updates the tagged rules on every server matching an l: selector", async () => {
      mockFetch([
        { status: 200, body: serverList(boxA, boxB) },
        { status: 200, body: rules(sshRule(), publicRule()) },
        { status: 200, body: rules(publicRule(), sshRule()) },
        { status: 204 },
        { status: 204 },
      ]);

      await provider.updateFirewall("ucat_token", "l:env=prod", "1.2.3.4");

      const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
      expect(calls).toHaveLength(5);
      expect(calls[0][0]).toBe("https://api.upcloud.com/1.3/server?label=env%3Dprod");
      // Both servers are planned (GET) before either is written (PUT).
      expect(calls[1][0]).toBe(`https://api.upcloud.com/1.3/server/${UUID}/firewall_rule`);
      expect(calls[2][0]).toBe(`https://api.upcloud.com/1.3/server/${UUID2}/firewall_rule`);
      expect(calls[3][0]).toBe(`https://api.upcloud.com/1.3/server/${UUID}/firewall_rule`);
      expect(calls[3][1].method).toBe("PUT");
      expect(calls[4][0]).toBe(`https://api.upcloud.com/1.3/server/${UUID2}/firewall_rule`);
      expect(calls[4][1].method).toBe("PUT");

      const putA = putRulesOf(calls, 3);
      expect(putA[0].source_address_start).toBe("1.2.3.4");
      expect(putA[1].source_address_start).toBe("0.0.0.0");
      const putB = putRulesOf(calls, 4);
      expect(putB[0].source_address_start).toBe("0.0.0.0");
      expect(putB[1].source_address_start).toBe("1.2.3.4");
    });

    it("sends each selector term as its own label parameter and honors a #tag suffix", async () => {
      mockFetch([
        { status: 200, body: serverList(boxA) },
        { status: 200, body: rules(sshRule({ comment: "home #home" }), sshRule()) },
        { status: 204 },
      ]);

      await provider.updateFirewall("ucat_token", "label:env=prod,bastion#home", "5.6.7.8");

      const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
      expect(calls[0][0]).toBe("https://api.upcloud.com/1.3/server?label=env%3Dprod&label=bastion");

      const putRules = putRulesOf(calls, 2);
      // Only the #home rule is rewritten; the #ddns rule is left alone.
      expect(putRules[0].source_address_start).toBe("5.6.7.8");
      expect(putRules[1].source_address_start).toBe("9.9.9.9");
    });

    it("throws UpdateError when no servers match the label", async () => {
      mockFetch([{ status: 200, body: serverList() }]);

      await expect(provider.updateFirewall("ucat_token", "l:env=nope", "1.2.3.4")).rejects.toThrow(
        UpdateError
      );
      expect(fetch).toHaveBeenCalledTimes(1);
    });

    it("writes nothing when any matched server lacks a tagged rule", async () => {
      mockFetch([
        { status: 200, body: serverList(boxA, boxB) },
        { status: 200, body: rules(sshRule()) },
        { status: 200, body: rules(publicRule()) },
      ]);

      await expect(provider.updateFirewall("ucat_token", "l:env=prod", "1.2.3.4")).rejects.toThrow(
        /No inbound IPv4 rules tagged #ddns on server: box-b/
      );

      const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
      expect(calls).toHaveLength(3);
      expect(calls.some((c: any[]) => c[1]?.method === "PUT")).toBe(false);
    });

    it("keeps updating remaining servers when one PUT fails, then reports it", async () => {
      mockFetch([
        { status: 200, body: serverList(boxA, boxB) },
        { status: 200, body: rules(sshRule()) },
        { status: 200, body: rules(sshRule()) },
        { status: 500, body: "boom" },
        { status: 204 },
      ]);
      vi.spyOn(console, "error").mockImplementation(() => {});

      const err = await provider.updateFirewall("ucat_token", "l:env=prod", "1.2.3.4").catch((e) => e);
      expect(err).toBeInstanceOf(ProviderError);
      expect(err.message).toContain("1 of 2 update(s) failed");
      expect(err.message).toContain("box-a");

      const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
      // The second server is still written despite the first PUT failing.
      expect(calls).toHaveLength(5);
      expect(calls[4][0]).toBe(`https://api.upcloud.com/1.3/server/${UUID2}/firewall_rule`);
      expect(calls[4][1].method).toBe("PUT");
    });

    it("throws UpdateError for an invalid label selector without calling the API", async () => {
      mockFetch([]);
      await expect(provider.updateFirewall("ucat_token", "l:env=prod&x=y", "1.2.3.4")).rejects.toThrow(
        UpdateError
      );
      await expect(provider.updateFirewall("ucat_token", "l:#home", "1.2.3.4")).rejects.toThrow(
        UpdateError
      );
      expect(fetch).not.toHaveBeenCalled();
    });
  });
});
