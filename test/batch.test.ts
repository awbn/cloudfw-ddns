import { describe, it, expect, vi, beforeEach } from "vitest";
import { updateEach } from "../src/providers/batch";
import { AuthError, ProviderError, UpdateError } from "../src/providers/types";

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(console, "error").mockImplementation(() => {});
});

const name = (n: number) => `target ${n}`;

describe("updateEach", () => {
  it("runs every target in order", async () => {
    const seen: number[] = [];
    await updateEach([1, 2, 3], name, async (n) => {
      seen.push(n);
    });
    expect(seen).toEqual([1, 2, 3]);
  });

  it("rethrows a single target's error unchanged", async () => {
    const original = new UpdateError("nope");
    await expect(updateEach([1], name, () => Promise.reject(original))).rejects.toBe(original);
  });

  it("continues past failures and summarizes them", async () => {
    const seen: number[] = [];
    const err = await updateEach([1, 2, 3], name, async (n) => {
      seen.push(n);
      if (n !== 2) throw new ProviderError(`bad ${n}`);
    }).catch((e) => e);

    expect(seen).toEqual([1, 2, 3]);
    expect(err).toBeInstanceOf(ProviderError);
    expect(err.message).toBe("2 of 3 update(s) failed: target 1: bad 1; target 3: bad 3");
  });

  it("reports UpdateError only when every failure is an UpdateError", async () => {
    await expect(
      updateEach([1, 2], name, (n) => Promise.reject(new UpdateError(`bad ${n}`)))
    ).rejects.toBeInstanceOf(UpdateError);

    await expect(
      updateEach([1, 2], name, (n) =>
        Promise.reject(n === 1 ? new UpdateError("bad") : new ProviderError("worse"))
      )
    ).rejects.toBeInstanceOf(ProviderError);
  });

  it("aborts immediately on AuthError", async () => {
    const seen: number[] = [];
    await expect(
      updateEach([1, 2, 3], name, async (n) => {
        seen.push(n);
        throw new AuthError();
      })
    ).rejects.toBeInstanceOf(AuthError);
    expect(seen).toEqual([1]);
  });
});
