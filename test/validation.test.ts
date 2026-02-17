import { describe, it, expect } from "vitest";
import { validateIPv4 } from "../src/validation";

describe("validateIPv4", () => {
  it("accepts valid public IPv4 addresses", () => {
    expect(validateIPv4("1.2.3.4")).toEqual({ valid: true });
    expect(validateIPv4("8.8.8.8")).toEqual({ valid: true });
    expect(validateIPv4("203.0.113.1")).toEqual({ valid: true });
    expect(validateIPv4("255.255.255.255")).toEqual({ valid: true });
    expect(validateIPv4("0.0.0.0")).toEqual({ valid: true });
  });

  it("rejects RFC 1918 10.0.0.0/8", () => {
    expect(validateIPv4("10.0.0.1").valid).toBe(false);
    expect(validateIPv4("10.255.255.255").valid).toBe(false);
    expect(validateIPv4("10.0.0.1").error).toContain("Private");
  });

  it("rejects RFC 1918 172.16.0.0/12", () => {
    expect(validateIPv4("172.16.0.1").valid).toBe(false);
    expect(validateIPv4("172.31.255.255").valid).toBe(false);
    expect(validateIPv4("172.15.0.1").valid).toBe(true);
    expect(validateIPv4("172.32.0.1").valid).toBe(true);
  });

  it("rejects RFC 1918 192.168.0.0/16", () => {
    expect(validateIPv4("192.168.0.1").valid).toBe(false);
    expect(validateIPv4("192.168.255.255").valid).toBe(false);
    expect(validateIPv4("192.169.0.1").valid).toBe(true);
  });

  it("rejects IPv6 addresses", () => {
    expect(validateIPv4("::1").valid).toBe(false);
    expect(validateIPv4("2001:db8::1").valid).toBe(false);
    expect(validateIPv4("::1").error).toContain("IPv6");
  });

  it("rejects malformed addresses", () => {
    expect(validateIPv4("").valid).toBe(false);
    expect(validateIPv4("1.2.3").valid).toBe(false);
    expect(validateIPv4("1.2.3.4.5").valid).toBe(false);
    expect(validateIPv4("256.1.1.1").valid).toBe(false);
    expect(validateIPv4("abc.def.ghi.jkl").valid).toBe(false);
    expect(validateIPv4("1.2.3.04").valid).toBe(false);
  });
});
