/**
 * SSRF guard for outbound HTTP requests built from user-supplied URLs.
 *
 * Hardens server functions (runAIScan, runSupabaseScan, runAutoScan) against
 * probing internal services such as 127.0.0.1, RFC-1918 ranges, link-local
 * IPs, or cloud metadata endpoints (e.g. 169.254.169.254).
 *
 * Resolves the hostname via DNS-over-HTTPS (Cloudflare, falling back to Google)
 * and rejects if any resolved address is private, if public DNS has no address
 * for it, or if the lookup could not be completed (fail closed).
 *
 * safeFetch also bounds the response: the timeout covers reading the body, and
 * bodies over maxBodyBytes error instead of being read in full.
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
  "https://1.1.1.1/dns-query",
  "https://8.8.8.8/resolve",
  "https://dns.alidns.com/resolve",
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

/** IPv4 literals matching private/loopback/link-local/metadata/reserved ranges. */
function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map((n) => Number(n));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    // Not something we can classify. Treat it as unsafe rather than guessing.
    return true;
  }
  const [a, b, c] = parts;
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 169 && b === 254) return true; // link-local + AWS/GCP metadata 169.254.169.254
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a === 192 && b === 0 && c === 0) return true; // IETF protocol assignments 192.0.0.0/24
  if (a === 192 && b === 0 && c === 2) return true; // TEST-NET-1
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking 198.18.0.0/15
  if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3
  if (a >= 224) return true; // multicast + reserved + broadcast
  return false;
}

/**
 * Parse an IPv6 literal (optionally bracketed, optionally with a trailing
 * dotted IPv4 part or zone id) into eight 16-bit groups. Returns null when the
 * text is not a valid IPv6 address.
 */
export function parseIPv6(input: string): number[] | null {
  let s = input.toLowerCase().replace(/^\[|\]$/g, "");
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);

  let tail: number[] = [];
  const dotted = /^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);
  if (dotted) {
    const p = dotted[2].split(".").map(Number);
    if (p.some((n) => n > 255)) return null;
    tail = [(p[0] << 8) | p[1], (p[2] << 8) | p[3]];
    s = dotted[1].endsWith("::") ? dotted[1] : dotted[1].slice(0, -1);
  }

  const halves = s.split("::");
  if (halves.length > 2) return null;
  const groups = (h: string) =>
    h === ""
      ? []
      : h.split(":").map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : Number.NaN));
  const head = groups(halves[0]);
  const rest = halves.length === 2 ? groups(halves[1]) : [];
  if ([...head, ...rest].some((n) => Number.isNaN(n))) return null;

  const need = 8 - tail.length;
  let body: number[];
  if (halves.length === 2) {
    const fill = need - head.length - rest.length;
    if (fill < 1) return null;
    body = [...head, ...new Array(fill).fill(0), ...rest];
  } else {
    if (head.length !== need) return null;
    body = head;
  }
  return [...body, ...tail];
}

function v4At(g: number[], i: number, xor = 0): string {
  const hi = g[i] ^ xor;
  const lo = g[i + 1] ^ xor;
  return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
}

/**
 * IPv6 literals that are loopback, link-local, ULA, multicast, reserved, or
 * that embed an IPv4 address in a private range. WHATWG URL serialises
 * `[::ffff:127.0.0.1]` as `::ffff:7f00:1`, so embedded IPv4 has to be decoded
 * from the groups rather than matched as dotted text.
 */
function isPrivateIPv6(ip: string): boolean {
  const g = parseIPv6(ip);
  if (!g) return true; // unparseable: fail closed
  const zeros = (n: number) => g.slice(0, n).every((x) => x === 0);

  if (zeros(5) && g[5] === 0xffff) return isPrivateIPv4(v4At(g, 6)); // ::ffff:a.b.c.d (mapped)
  if (zeros(4) && g[4] === 0xffff && g[5] === 0) return isPrivateIPv4(v4At(g, 6)); // ::ffff:0:a.b.c.d
  if (g[0] === 0) return true; // ::/8 reserved: ::, ::1, IPv4-compatible ::a.b.c.d
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0) {
    return isPrivateIPv4(v4At(g, 6)); // NAT64 well-known prefix 64:ff9b::/96
  }
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) return true; // local-use NAT64 64:ff9b:1::/48
  if (g[0] === 0x2002) return isPrivateIPv4(v4At(g, 1)); // 6to4 2002::/16
  if (g[0] === 0x2001 && g[1] === 0) {
    // Teredo 2001::/32: server IPv4 in groups 2-3, client IPv4 obfuscated in 6-7.
    return isPrivateIPv4(v4At(g, 2)) || isPrivateIPv4(v4At(g, 6, 0xffff));
  }
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true; // documentation
  if (g[0] === 0x0100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return true; // discard 100::/64
  if ((g[0] & 0xffc0) === 0xfe80) return true; // link-local fe80::/10
  if ((g[0] & 0xffc0) === 0xfec0) return true; // deprecated site-local fec0::/10
  if ((g[0] & 0xfe00) === 0xfc00) return true; // unique local fc00::/7
  if ((g[0] & 0xff00) === 0xff00) return true; // multicast
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
  return true; // not an address we recognise: fail closed
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
  const t = setTimeout(() => ctl.abort(), 6000);
  try {
    const r = await fetch(`${endpoint}?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { accept: "application/dns-json" },
      signal: ctl.signal,
      // Cloudflare Workers rejects redirect: "error" outright (a TypeError on
      // every call), which made every resolver look unavailable. "manual"
      // works everywhere; a redirect response is simply treated as unusable.
      redirect: "manual",
    });
    // null = resolver unusable (throttled / errored / redirected); [] = resolver answered "no such record".
    if (!r.ok) {
      await r.body?.cancel().catch(() => {});
      return null;
    }
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

/**
 * A user-facing reason for a blocked URL. A name that simply doesn't exist in
 * public DNS (a typo, or a record lost in a DNS move) is not an attack, so it
 * shouldn't be reported as "refusing to probe an internal destination".
 */
export function describeBlockedUrl(e: { message: string }): string {
  const m = /Blocked: (\S+) has no public A\/AAAA records/.exec(e.message);
  if (m) return `${m[1]} doesn't exist in public DNS, so there's nothing to scan. Check the address, or add its DNS record if it should be live.`;
  if (/Could not verify .* via DNS-over-HTTPS/.test(e.message)) return e.message;
  return `Refusing to probe internal/private destination: ${e.message}`;
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

  if (a === null || aaaa === null) {
    // At least one record type could not be looked up by any resolver. The
    // runtime may connect over the family we could not see, so we cannot prove
    // the host is external. Fail closed.
    if (allowUnresolvedHosts()) return;
    throw new SSRFBlockedError(
      `Could not verify ${host} via DNS-over-HTTPS (resolvers unavailable for ` +
        `${a === null && aaaa === null ? "A and AAAA" : a === null ? "A" : "AAAA"} records). ` +
        `Refusing to send the request. If outbound DoH is blocked in this environment, ` +
        `set AUDITKIT_ALLOW_UNRESOLVED_HOSTS=true to override.`,
    );
  }

  const addrs = [...a, ...aaaa];
  if (addrs.length === 0) {
    // Public DNS says the name has no addresses. If the runtime's own resolver
    // can still reach it, it is an internal-only name, which is exactly what
    // this guard exists to block.
    throw new SSRFBlockedError(`Blocked: ${host} has no public A/AAAA records.`);
  }
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
  /**
   * Largest response body the caller may read, in bytes. A body that goes past
   * it errors instead of being silently cut short, so a scanner can report the
   * check as inconclusive rather than judging a partial page. Default 16 MB.
   */
  maxBodyBytes?: number;
};

export const DEFAULT_MAX_BODY_BYTES = 16 * 1024 * 1024;

export class ResponseTooLargeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ResponseTooLargeError";
  }
}

const NULL_BODY_STATUSES = new Set([101, 103, 204, 205, 304]);

/**
 * Wrap a response so its body is read under the same deadline as the request
 * and cannot grow past maxBytes. `finish` clears the deadline once the body is
 * fully read, errors, or is cancelled.
 */
function guardBody(
  res: Response,
  maxBytes: number,
  ctl: AbortController,
  timeoutMs: number,
  finish: () => void,
): Response {
  if (!res.body || NULL_BODY_STATUSES.has(res.status) || res.status < 200 || res.status > 599) {
    finish();
    return res;
  }
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    finish();
    ctl.abort();
    throw new ResponseTooLargeError(
      `Response body is ${declared} bytes, over the ${maxBytes}-byte limit for this request.`,
    );
  }
  const reader = res.body.getReader();
  let total = 0;
  // Race every read against the deadline. Aborting the fetch should end the
  // body stream by itself, but not every runtime (or stream) honours that.
  const timedOut = new Promise<never>((_, reject) => {
    const fire = () =>
      reject(new Error(`Timed out reading the response body after ${timeoutMs}ms.`));
    if (ctl.signal.aborted) fire();
    else ctl.signal.addEventListener("abort", fire, { once: true });
  });
  timedOut.catch(() => {});
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { value, done } = await Promise.race([reader.read(), timedOut]);
        if (done) {
          finish();
          controller.close();
          return;
        }
        total += value.byteLength;
        if (total > maxBytes) {
          finish();
          ctl.abort();
          reader.cancel().catch(() => {});
          controller.error(
            new ResponseTooLargeError(
              `Response body exceeded the ${maxBytes}-byte limit for this request.`,
            ),
          );
          return;
        }
        controller.enqueue(value);
      } catch (e) {
        finish();
        reader.cancel().catch(() => {});
        controller.error(
          ctl.signal.aborted && !(e instanceof ResponseTooLargeError)
            ? new Error(`Timed out reading the response body after ${timeoutMs}ms.`)
            : e,
        );
      }
    },
    cancel(reason) {
      finish();
      return reader.cancel(reason).catch(() => {});
    },
  });
  return new Response(stream, {
    status: res.status,
    statusText: res.statusText,
    headers: res.headers,
  });
}

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
  const {
    timeoutMs = 15_000,
    maxRedirects = 5,
    allowHosts,
    maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
  } = opts;

  // One deadline covers every hop *and* reading the final body. It is cleared
  // when the body finishes, not when the headers arrive.
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  let handedOff = false;
  const finish = () => clearTimeout(timer);
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
      if (!REDIRECT_STATUSES.has(res.status) || !location) {
        handedOff = true;
        return guardBody(res, maxBodyBytes, ctl, timeoutMs, finish);
      }
      // Not reading this hop's body; release the connection.
      res.body?.cancel().catch(() => {});

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
    if (!handedOff) clearTimeout(timer);
  }
}
