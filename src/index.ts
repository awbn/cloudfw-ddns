import { validateIPv4 } from "./validation";
import { getProvider, getValidProviderNames } from "./providers/registry";
import { AuthError, UpdateError } from "./providers/types";

function parseBasicAuth(header: string | null): { username: string; password: string } | null {
  if (!header || !header.startsWith("Basic ")) {
    return null;
  }

  let decoded: string;
  try {
    decoded = atob(header.slice(6));
  } catch {
    return null;
  }
  const colon = decoded.indexOf(":");
  if (colon === -1) {
    return null;
  }

  return {
    username: decoded.slice(0, colon),
    password: decoded.slice(colon + 1),
  };
}

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Drop requests not targeting the /update path to reduce logging noise
    if (url.pathname !== "/update") {
      return new Response("Bad Request", { status: 400 });
    }

    const params = url.searchParams;

    const callerIp = request.headers.get("CF-Connecting-IP") || "unknown";
    const hostname = params.get("hostname");
    const ip = params.get("myip") || params.get("ip");
    const auth = parseBasicAuth(request.headers.get("Authorization"));

    // Check for missing fields
    const missing: string[] = [];
    if (!hostname) missing.push("hostname");
    if (!ip) missing.push("myip");
    if (!auth) missing.push("username, password (Basic Auth)");

    if (missing.length > 0) {
      console.log(`[${callerIp}] Request missing fields: ${missing.join(", ")}`);
      return new Response(`Missing required fields: ${missing.join(", ")}`, { status: 400 });
    }

    const providerName = auth!.username;
    const token = auth!.password;

    // Validate provider
    const provider = getProvider(providerName);
    if (!provider) {
      const valid = getValidProviderNames().join(", ");
      console.log(`[${callerIp}] Invalid provider: ${providerName}`);
      return new Response(`Invalid provider: ${providerName}. Valid providers: ${valid}`, { status: 400 });
    }

    // Validate IP
    const ipResult = validateIPv4(ip!);
    if (!ipResult.valid) {
      console.log(`[${callerIp}] Invalid IP: ${ip} - ${ipResult.error}`);
      return new Response(ipResult.error!, { status: 400 });
    }

    // Update firewall
    try {
      console.log(`[${callerIp}] Updating ${providerName} firewall "${hostname}" with IP ${ip}`);
      await provider.updateFirewall(token, hostname!, ip!);
      console.log(`[${callerIp}] Successfully updated ${providerName} firewall "${hostname}"`);
      return new Response("success", { status: 200 });
    } catch (err) {
      if (err instanceof AuthError) {
        console.log(`[${callerIp}] Auth failure for ${providerName}: ${err.message}`);
        return new Response("unauthorized", { status: 401 });
      }
      if (err instanceof UpdateError) {
        console.log(`[${callerIp}] Update error for ${providerName}: ${err.message}`);
        return new Response("Failed to update firewall", { status: 400 });
      }
      console.error(`[${callerIp}] Provider error for ${providerName}:`, err);
      return new Response("Internal server error", { status: 500 });
    }
  },
};
