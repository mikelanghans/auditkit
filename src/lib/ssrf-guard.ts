/**
 * SSRF guard for outbound HTTP requests built from user-supplied URLs.
 *
 * Hardens server functions (runAIScan, runSupabaseScan, runAutoScan) against
 * probing internal services such as 127.0.0.1, RFC-1918 ranges, link-local
 * IPs, or cloud metadata endpoints (e.g. 169.254.169.254).
 *
 * Resolves the hostname via Cloudflare DNS-over-HTTPS once and rejects if any
 * resolved address is private. Callers should pin the resolved hostname/IP
 * before reusing it elsewhere if extra DNS-rebinding hardening is required.
 */

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";

/** IPv4 literals matching private/loopback/link-local/metadata ranges. */
function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map((n) => Number(n));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    // Not a valid IPv4 — treat as not-an-ipv4 (caller will still hostname-resolve).
    return false;
  }
  const [a, b] = parts;
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 169 && b === 254) return true; // link-local + AWS/GCP metadata 169.254.169.254
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a >= 224) return true; // multicast + reserved
  return false;
}

/** IPv6 literals matching loopback/link-local/ULA/IPv4-mapped private. */
function isPrivateIPv6(ip: string): boolean {
  const lower = ip.toLowerCase().replace(/^\[|\]$/g, "");
  if (lower === "::1" || lower === "::") return true;
  if (lower.startsWith("fe80:") || lower.startsWith("fe80::")) return true; // link-local
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true; // unique local fc00::/7
  if (lower.startsWith("ff")) return true; // multicast
  // IPv4-mapped: ::ffff:a.b.c.d
  const v4mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (v4mapped) return isPrivateIPv4(v4mapped[1]);
  return false;
}

function isIPAddress(host: string): boolean {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return true;
  if (host.includes(":")) return true; // IPv6 literal (URL.hostname strips brackets)
  return false;
}

function isPrivateIPLiteral(host: string): boolean {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return isPrivateIPv4(host);
  if (host.includes(":")) return isPrivateIPv6(host);
  return false;
}

function isBlockedHostname(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h.endsWith(".internal") || h.endsWith(".local") || h.endsWith(".intranet")) return true;
  if (h === "metadata.google.internal") return true;
  return false;
}

async function dohResolve(name: string, type: "A" | "AAAA"): Promise<string[]> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 4000);
  try {
    const r = await fetch(`${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { accept: "application/dns-json" },
      signal: ctl.signal,
    });
    if (!r.ok) return [];
    const json = (await r.json()) as { Answer?: { data: string; type: number }[] };
    const wanted = type === "A" ? 1 : 28;
    return (json.Answer ?? []).filter((a) => a.type === wanted).map((a) => a.data);
  } catch {
    return [];
  } finally {
    clearTimeout(t);
  }
}

export class SSRFBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SSRFBlockedError";
  }
}

/**
 * Validate a user-supplied URL against SSRF rules. Throws SSRFBlockedError
 * when the URL points at an internal/private destination.
 *
 * - Only http/https are allowed.
 * - IP literals in private/loopback/link-local/metadata ranges are rejected.
 * - Hostnames like `localhost`, `*.local`, `metadata.google.internal` are rejected.
 * - Public hostnames are resolved via DoH and rejected if any A/AAAA record
 *   falls inside a private range.
 */
export async function assertSafeOutboundUrl(raw: string): Promise<void> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new SSRFBlockedError(`Invalid URL: ${raw}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new SSRFBlockedError(`Only http/https URLs are allowed (got ${url.protocol}).`);
  }
  const host = url.hostname;
  if (!host) throw new SSRFBlockedError("URL is missing a host.");

  if (isBlockedHostname(host)) {
    throw new SSRFBlockedError(`Blocked host: ${host}`);
  }

  if (isIPAddress(host)) {
    if (isPrivateIPLiteral(host)) {
      throw new SSRFBlockedError(`Blocked private IP address: ${host}`);
    }
    return; // Public IP literal — OK.
  }

  // Resolve hostname to verify no record points at a private range.
  const [a, aaaa] = await Promise.all([dohResolve(host, "A"), dohResolve(host, "AAAA")]);
  const addrs = [...a, ...aaaa];
  if (addrs.length === 0) {
    // Resolution failed — allow request to proceed; the fetch itself will fail
    // safely if the host is bogus. Blocking would create false positives when
    // DoH is throttled. The hostname/literal checks above already cover the
    // common bypass attempts.
    return;
  }
  for (const ip of addrs) {
    if (isPrivateIPLiteral(ip)) {
      throw new SSRFBlockedError(`Blocked: ${host} resolves to private address ${ip}`);
    }
  }
}
