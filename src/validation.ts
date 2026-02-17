export function validateIPv4(ip: string): { valid: boolean; error?: string } {
  if (ip.includes(":")) {
    return { valid: false, error: "IPv6 addresses are not supported" };
  }

  const parts = ip.split(".");
  if (parts.length !== 4) {
    return { valid: false, error: "Invalid IPv4 address format" };
  }

  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) {
      return { valid: false, error: "Invalid IPv4 address format" };
    }
    const num = parseInt(part, 10);
    if (num < 0 || num > 255) {
      return { valid: false, error: "Invalid IPv4 address format" };
    }
    if (part.length > 1 && part.startsWith("0")) {
      return { valid: false, error: "Invalid IPv4 address format" };
    }
  }

  const octets = parts.map((p) => parseInt(p, 10));

  // RFC 1918 private ranges
  if (octets[0] === 10) {
    return { valid: false, error: "Private IP addresses (RFC 1918) are not allowed" };
  }
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) {
    return { valid: false, error: "Private IP addresses (RFC 1918) are not allowed" };
  }
  if (octets[0] === 192 && octets[1] === 168) {
    return { valid: false, error: "Private IP addresses (RFC 1918) are not allowed" };
  }

  return { valid: true };
}
