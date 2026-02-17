import { describe, it, expect, vi, beforeEach } from "vitest";
import handler from "../src/index";

function makeRequest(
  params: Record<string, string> = {},
  auth?: { username: string; password: string }
): Request {
  const url = new URL("https://example.com/update");
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }

  const headers: Record<string, string> = {};
  if (auth) {
    headers["Authorization"] = `Basic ${btoa(`${auth.username}:${auth.password}`)}`;
  }

  return new Request(url.toString(), { headers });
}

// Stub console.log/error to reduce test noise
beforeEach(() => {
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("Worker handler", () => {
  it("returns 400 for requests not matching /update or /nic/update path", async () => {
    const resp = await handler.fetch(new Request("https://example.com/"));
    expect(resp.status).toBe(400);
    expect(await resp.text()).toBe("Bad Request");

    const resp2 = await handler.fetch(new Request("https://example.com/other"));
    expect(resp2.status).toBe(400);
    expect(await resp2.text()).toBe("Bad Request");
  });

  it("accepts requests on /nic/update path", async () => {
    const resp = await handler.fetch(new Request("https://example.com/nic/update"));
    expect(resp.status).toBe(400);
    const body = await resp.text();
    // Should pass path check and fail on missing fields, not "Bad Request"
    expect(body).toContain("hostname");
  });

  it("returns 400 with missing fields when no params", async () => {
    const resp = await handler.fetch(new Request("https://example.com/update"));
    expect(resp.status).toBe(400);
    const body = await resp.text();
    expect(body).toContain("hostname");
    expect(body).toContain("myip");
  });

  it("returns 400 when auth is missing", async () => {
    const resp = await handler.fetch(
      makeRequest({ hostname: "fw", myip: "1.2.3.4" })
    );
    expect(resp.status).toBe(400);
    const body = await resp.text();
    expect(body).toContain("Basic Auth");
  });

  it("returns 400 for invalid provider", async () => {
    const resp = await handler.fetch(
      makeRequest(
        { hostname: "fw", myip: "1.2.3.4" },
        { username: "aws", password: "token" }
      )
    );
    expect(resp.status).toBe(400);
    const body = await resp.text();
    expect(body).toContain("Invalid provider");
    expect(body).toContain("digitalocean");
    expect(body).toContain("hetzner");
  });

  it("returns 400 with malformed base64 auth", async () => {
    const req = new Request("https://example.com/update?hostname=fw&myip=1.2.3.4", {
      headers: { Authorization: "Basic %%%invalid-base64%%%" },
    });
    const resp = await handler.fetch(req);
    expect(resp.status).toBe(400);
    const body = await resp.text();
    expect(body).toContain("Basic Auth");
  });

  it("returns 400 for private IP", async () => {
    const resp = await handler.fetch(
      makeRequest(
        { hostname: "fw", myip: "192.168.1.1" },
        { username: "digitalocean", password: "token" }
      )
    );
    expect(resp.status).toBe(400);
    const body = await resp.text();
    expect(body).toContain("Private");
  });

  it("returns 400 for IPv6", async () => {
    const resp = await handler.fetch(
      makeRequest(
        { hostname: "fw", myip: "::1" },
        { username: "digitalocean", password: "token" }
      )
    );
    expect(resp.status).toBe(400);
    const body = await resp.text();
    expect(body).toContain("IPv6");
  });

  it("accepts ip param as alias for myip", async () => {
    // Use an invalid provider to short-circuit before hitting the API
    // but after IP parsing succeeds
    const resp = await handler.fetch(
      makeRequest(
        { hostname: "fw", ip: "1.2.3.4" },
        { username: "badprovider", password: "token" }
      )
    );
    expect(resp.status).toBe(400);
    const body = await resp.text();
    // Should fail on provider, not on missing IP
    expect(body).toContain("Invalid provider");
  });

  it("returns 200 success on successful update", async () => {
    const fwId = "abc12345-1234-1234-1234-abc123456789";
    const firewall = {
      id: fwId,
      name: "test",
      inbound_rules: [
        { protocol: "tcp", ports: "22", sources: { addresses: [] } },
      ],
      outbound_rules: [],
      droplet_ids: [],
      tags: [],
    };

    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ firewall }),
          text: () => Promise.resolve(""),
        })
      )
    );

    const resp = await handler.fetch(
      makeRequest(
        { hostname: fwId, myip: "1.2.3.4" },
        { username: "do", password: "token" }
      )
    );

    expect(resp.status).toBe(200);
    expect(await resp.text()).toBe("success");

    vi.restoreAllMocks();
  });

  it("returns 401 on auth failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve({
          ok: false,
          status: 401,
          json: () => Promise.resolve({}),
          text: () => Promise.resolve(""),
        })
      )
    );

    const resp = await handler.fetch(
      makeRequest(
        { hostname: "abc12345-1234-1234-1234-abc123456789", myip: "1.2.3.4" },
        { username: "do", password: "bad-token" }
      )
    );

    expect(resp.status).toBe(401);
    expect(await resp.text()).toBe("unauthorized");

    vi.restoreAllMocks();
  });
});
