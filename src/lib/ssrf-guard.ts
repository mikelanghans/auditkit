/**
 * SSRF guard for outbound HTTP requests built from user-supplied URLs.
 *
 * Hardens server functions (runAIScan, runSupabaseScan, runAutoScan) against
 * probing internal services such as 127.0.0.1, RFC-1918 ranges, link-local
 * IPs, or cloud metadata endpoints (e.g. 169.254.169.254).
 *
 * Resolves the hostname via DNS-over-HTTPS (Cloudflare, falling back to Google)
 * and rejects if any resolved address is private.
 *
 * IMPORTANT: validating a URL is not enough on its own. HTTP redirects are the
 * standard bypass — an attacker-controlled public host can 302 to
 * http://169.254.169.254/. Always issue requests through `safeFetch`, which
 * re-validates every hop, rather than calling `fetch` with `redirect: "follow"`.
 *
 * Known residual risk: DNS rebinding. We resolve the name to check it, then the
 * runtime resolves it again to connect, and the answer can change in between.
 * Fully closing this requires connecting to a pinned IP with an explicit Host
 * header, which the Workers fetch API does not expose. Treat scan output as
 * untrusted input, not as proof an internal service was unreachable.
 */

const DOH_ENDPOINTS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
];

/**
 * Escape hatch for deployments where outbound DoH is blocked and every scan
 * would otherwise fail closed. Set AUDITKIT_ALLOW_UNRESOLVED_HOSTS=true only if
 * you understand that it re-opens the resolution-failure bypass.
 */
function allowUnresolvedHosts(): boolean {
  try {
    return String(process.env.AUDITKIT_ALLOW_UNRESOLVED_HOSTS ?? "").toLowerCase() === "true";
  } catch {
    return false;
  }
}

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

async function dohResolveVia(
  endpoint: string,
  name: string,
  type: "A" | "AAAA",
): Promise<string[] | null> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 4000);
  try {
    const r = await fetch(`${endpoint}?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { accept: "application/dns-json" },
      signal: ctl.signal,
      redirect: "error",
    });
    // null = resolver unusable (throttled / errored); [] = resolver answered "no such record".
    if (!r.ok) return null;
    const json = (await r.json()) as { Answer?: { data: string; type: number }[]; Status?: number };
    if (typeof json.Status === "number" && json.Status !== 0 && json.Status !== 3) return null;
    const wanted = type === "A" ? 1 : 28;
    return (json.Answer ?? []).filter((a) => a.type === wanted).map((a) => a.data);
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

/**
 * Resolve a name across the configured DoH endpoints.
 * Returns null only when every resolver was unusable — distinct from an
 * authoritative "this name has no records", which returns [].
 */
async function dohResolve(name: string, type: "A" | "AAAA"): Promise<string[] | null> {
  let sawResolver = false;
  const collected: string[] = [];
  for (const endpoint of DOH_ENDPOINTS) {
    const res = await dohResolveVia(endpoint, name, type);
    if (res === null) continue;
    sawResolver = true;
    collected.push(...res);
    if (res.length > 0) break;
  }
  return sawResolver ? collected : null;
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

  if (a === null && aaaa === null) {
    // Every resolver was unusable, so we cannot prove the host is external.
    // Fail closed: a name that silently resolves internally is exactly the case
    // this guard exists to stop.
    if (allowUnresolvedHosts()) return;
    throw new SSRFBlockedError(
      `Could not verify ${host} via DNS-over-HTTPS (all resolvers unavailable). ` +
        `Refusing to send the request. If outbound DoH is blocked in this environment, ` +
        `set AUDITKIT_ALLOW_UNRESOLVED_HOSTS=true to override.`,
    );
  }

  const addrs = [...(a ?? []), ...(aaaa ?? [])];
  for (const ip of addrs) {
    if (isPrivateIPLiteral(ip)) {
      throw new SSRFBlockedError(`Blocked: ${host} resolves to private address ${ip}`);
    }
  }
}

/** Hostname matches an allowlist entry exactly, or is a subdomain of one. */
function hostAllowed(host: string, allowHosts: string[]): boolean {
  const h = host.toLowerCase();
  return allowHosts.some((entry) => {
    const e = entry.toLowerCase();
    return h === e || h.endsWith(`.${e}`);
  });
}

/**
 * GitHub hosts a repo scan may legitimately touch. `raw.githubusercontent.com`
 * redirects blobs to `objects.githubusercontent.com`, so the allowlist has to
 * cover the whole family rather than a single API host.
 */
export const GITHUB_HOSTS = ["github.com", "githubusercontent.com"];

/** Public npm registry hosts used by the dependency scan. */
export const NPM_HOSTS = ["registry.npmjs.org", "npmjs.org", "npmjs.com"];

export type SafeFetchOptions = {
  timeoutMs?: number;
  /** Max redirect hops to follow. Default 5. */
  maxRedirects?: number;
  /**
   * When set, every hop's hostname must match one of these (exact or subdomain).
   * Use for fixed-host integrations (api.github.com, registry.npmjs.org) so a
   * redirect can never walk the request off the intended provider.
   */
  allowHosts?: string[];
};

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function sameOrigin(a: URL, b: URL): boolean {
  return a.protocol === b.protocol && a.host === b.host;
}

/**
 * fetch() with SSRF validation applied to the initial URL *and every redirect
 * hop*. Never use `redirect: "follow"` on a user-influenced URL — the guard only
 * sees the first URL in that case, so a 302 to a private address goes through.
 *
 * Credential-bearing headers are stripped on cross-origin hops, matching what
 * the fetch spec does for automatic redirects. Without this, manually following
 * a redirect from raw.githubusercontent.com would forward the caller's GitHub
 * PAT to whatever host the redirect names.
 */
export async function safeFetch(
  rawUrl: string,
  init: RequestInit = {},
  opts: SafeFetchOptions = {},
): Promise<Response> {
  const { timeoutMs = 15_000, maxRedirects = 5, allowHosts } = opts;

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  const externalSignal = init.signal;
  if (externalSignal) {
    if (externalSignal.aborted) ctl.abort();
    else externalSignal.addEventListener("abort", () => ctl.abort(), { once: true });
  }

  try {
    let currentUrl = rawUrl;
    let method = (init.method ?? "GET").toUpperCase();
    let body = init.body;
    let headers = new Headers(init.headers ?? {});

    for (let hop = 0; hop <= maxRedirects; hop++) {
      await assertSafeOutboundUrl(currentUrl);
      if (allowHosts) {
        const host = new URL(currentUrl).hostname;
        if (!hostAllowed(host, allowHosts)) {
          throw new SSRFBlockedError(
            `Blocked: ${host} is not in the allowed host list for this request.`,
          );
        }
      }

      const res = await fetch(currentUrl, {
        ...init,
        method,
        body,
        headers,
        signal: ctl.signal,
        redirect: "manual",
      });

      const location = res.headers.get("location");
      if (!REDIRECT_STATUSES.has(res.status) || !location) return res;

      if (hop === maxRedirects) {
        throw new SSRFBlockedError(
          `Blocked: too many redirects (>${maxRedirects}) starting from ${rawUrl}.`,
        );
      }

      const from = new URL(currentUrl);
      let next: URL;
      try {
        next = new URL(location, from);
      } catch {
        throw new SSRFBlockedError(`Blocked: unparseable redirect target "${location}".`);
      }

      // Drop credentials when the redirect leaves the current origin.
      if (!sameOrigin(from, next)) {
        headers = new Headers(headers);
        headers.delete("authorization");
        headers.delete("cookie");
        headers.delete("proxy-authorization");
        headers.delete("apikey");
      }

      // Per fetch spec: 303 always becomes GET; 301/302 downgrade POST to GET.
      if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === "POST")) {
        method = "GET";
        body = undefined;
        headers.delete("content-type");
        headers.delete("content-length");
      }

      currentUrl = next.toString();
    }

    // Unreachable — the loop either returns or throws.
    throw new SSRFBlockedError(`Blocked: redirect handling failed for ${rawUrl}.`);
  } finally {
    clearTimeout(timer);
  }
}
