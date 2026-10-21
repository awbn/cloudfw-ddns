import { describe, it, expect } from "vitest";
import { parseLabelSelector } from "../src/providers/labels";
import { UpdateError } from "../src/providers/types";

describe("parseLabelSelector", () => {
  it("returns null when there is no label prefix", () => {
    expect(parseLabelSelector("my-firewall")).toBeNull();
    expect(parseLabelSelector("labels")).toBeNull();
  });

  it("strips the l: and label: prefixes", () => {
    expect(parseLabelSelector("l:env=prod")).toBe("env=prod");
    expect(parseLabelSelector("label:env=prod")).toBe("env=prod");
  });

  it("accepts key-only terms and comma-separated lists", () => {
    expect(parseLabelSelector("l:bastion")).toBe("bastion");
    expect(parseLabelSelector("l:env=prod,role=ssh,bastion")).toBe("env=prod,role=ssh,bastion");
  });

  it("rejects malformed selectors", () => {
    expect(() => parseLabelSelector("l:")).toThrow(UpdateError);
    expect(() => parseLabelSelector("l:has spaces")).toThrow(UpdateError);
    expect(() => parseLabelSelector("l:env=prod&x=y")).toThrow(UpdateError);
    expect(() => parseLabelSelector("l:env=prod,")).toThrow(UpdateError);
    expect(() => parseLabelSelector("l:a#b")).toThrow(UpdateError);
  });
});
