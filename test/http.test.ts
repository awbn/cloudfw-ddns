import { describe, it, expect, vi, beforeEach } from "vitest";
import { authorizedFetch } from "../src/providers/http";
import { AuthError, ProviderError } from "../src/providers/types";

function mockFetch(status: number): ReturnType<typeof vi.fn> {
  const fn = vi.fn(() => Promise.resolve({ ok: status >= 200 && status < 300, status }));
  vi.stubGlobal("fetch", fn);
  return fn;
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("authorizedFetch", () => {
  it("sets bearer auth, JSON headers and a redirect mode the Workers runtime accepts", async () => {
    const fn = mockFetch(200);

    await authorizedFetch("https://api.example.com/v2/firewalls", "tok");

    const init = fn.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok");
    // The runtime rejects `redirect: "error"` with a TypeError from fetch itself.
    expect(init.redirect).toBe("manual");
    expect(["follow", "manual"]).toContain(init.redirect);
  });

  it("does not let callers opt into following redirects", async () => {
    const fn = mockFetch(200);

    await authorizedFetch("https://api.example.com/v2/firewalls", "tok", { redirect: "follow" });

    expect((fn.mock.calls[0][1] as RequestInit).redirect).toBe("manual");
  });

  for (const status of [301, 302, 303, 307, 308]) {
    it(`rejects a ${status} redirect rather than replaying the token`, async () => {
      mockFetch(status);

      await expect(authorizedFetch("https://api.example.com/v2/firewalls", "tok")).rejects.toThrow(
        ProviderError
      );
    });
  }

  it("maps configured auth-failure statuses to AuthError", async () => {
    mockFetch(403);

    await expect(
      authorizedFetch("https://api.example.com/v1/firewalls", "tok", {}, { authFailureStatuses: [401, 403] })
    ).rejects.toThrow(AuthError);
  });

  it("returns non-redirect, non-auth responses untouched", async () => {
    mockFetch(404);

    const resp = await authorizedFetch("https://api.example.com/v2/firewalls", "tok");
    expect(resp.status).toBe(404);
  });
});
