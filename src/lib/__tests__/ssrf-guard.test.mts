import { safeFetch, SSRFBlockedError, ResponseTooLargeError, assertSafeOutboundUrl } from "../ssrf-guard.ts";

let fail = 0;
const check = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond ? "" : "  <<< " + extra}`);
  if (!cond) fail++;
};

// DNS map used by the stubbed DoH resolver.
const DNS = {
  "evil.example": "93.184.216.34",     // public
  "good.example": "93.184.216.34",     // public
  "cdn.example":  "93.184.216.34",     // public
  "internal.example": "10.0.0.5",      // private -> must be blocked
};

let requests = [];

function stubFetch(routes) {
  requests = [];
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    // DoH resolver stub
    if (["cloudflare-dns.com", "dns.google", "1.1.1.1", "8.8.8.8", "dns.alidns.com"].includes(u.hostname)) {
      const name = u.searchParams.get("name");
      const type = u.searchParams.get("type");
      const ip = DNS[name];
      const answer = ip && type === "A" ? [{ data: ip, type: 1 }] : [];
      return new Response(JSON.stringify({ Status: 0, Answer: answer }), { status: 200 });
    }
    requests.push({ url: String(url), headers: new Headers(init.headers ?? {}), method: init.method ?? "GET" });
    const r = routes[u.origin + u.pathname];
    if (!r) return new Response("ok", { status: 200 });
    return r();
  };
}

const redirect = (to, status = 302) => () => new Response(null, { status, headers: { location: to } });
const ok = () => () => new Response("final", { status: 200 });

// 1. Direct private IP is blocked
stubFetch({});
try {
  await safeFetch("http://169.254.169.254/latest/meta-data/");
  check("blocks direct link-local metadata IP", false, "no error thrown");
} catch (e) {
  check("blocks direct link-local metadata IP", e instanceof SSRFBlockedError, e.message);
}

// 2. THE BUG THIS FIXES: public host 302s to metadata IP
stubFetch({ "https://evil.example/": redirect("http://169.254.169.254/latest/meta-data/") });
try {
  await safeFetch("https://evil.example/");
  check("blocks redirect to metadata IP", false, "redirect was followed!");
} catch (e) {
  check("blocks redirect to metadata IP", e instanceof SSRFBlockedError, e.message);
}

// 3. Redirect to a hostname that RESOLVES private is blocked
stubFetch({ "https://evil.example/": redirect("https://internal.example/admin") });
try {
  await safeFetch("https://evil.example/");
  check("blocks redirect to privately-resolving hostname", false, "followed!");
} catch (e) {
  check("blocks redirect to privately-resolving hostname", e instanceof SSRFBlockedError, e.message);
}

// 4. Legitimate same-origin redirect still works, Authorization preserved
stubFetch({ "https://good.example/a": redirect("https://good.example/b"), "https://good.example/b": ok() });
let res = await safeFetch("https://good.example/a", { headers: { authorization: "Bearer TOKEN123" } });
check("follows same-origin redirect", res.status === 200);
check("keeps Authorization on same-origin hop", requests[1]?.headers.get("authorization") === "Bearer TOKEN123", requests[1]?.headers.get("authorization"));

// 5. Cross-origin redirect STRIPS Authorization (the PAT-leak guard)
stubFetch({ "https://good.example/a": redirect("https://cdn.example/blob"), "https://cdn.example/blob": ok() });
res = await safeFetch("https://good.example/a", { headers: { authorization: "Bearer TOKEN123", cookie: "s=1" } });
check("follows cross-origin redirect", res.status === 200);
check("STRIPS Authorization cross-origin", requests[1]?.headers.get("authorization") === null, requests[1]?.headers.get("authorization"));
check("STRIPS Cookie cross-origin", requests[1]?.headers.get("cookie") === null);

// 6. Host allowlist blocks an off-provider redirect
stubFetch({ "https://good.example/a": redirect("https://cdn.example/blob"), "https://cdn.example/blob": ok() });
try {
  await safeFetch("https://good.example/a", {}, { allowHosts: ["good.example"] });
  check("allowlist blocks off-provider redirect", false, "followed!");
} catch (e) {
  check("allowlist blocks off-provider redirect", e instanceof SSRFBlockedError, e.message);
}

// 7. 303 downgrades POST to GET
stubFetch({ "https://good.example/a": redirect("https://good.example/b", 303), "https://good.example/b": ok() });
await safeFetch("https://good.example/a", { method: "POST", body: "x" });
check("303 downgrades POST to GET", requests[1]?.method === "GET", requests[1]?.method);

// 8. Redirect loop terminates
const loop = { "https://good.example/a": redirect("https://good.example/a") };
stubFetch(loop);
try {
  await safeFetch("https://good.example/a");
  check("redirect loop is capped", false, "no error");
} catch (e) {
  check("redirect loop is capped", e instanceof SSRFBlockedError && /too many redirects/.test(e.message), e.message);
}

// 9. Fails closed when every resolver is unusable
requests = [];
globalThis.fetch = async (url) => {
  const u = new URL(String(url));
  if (u.hostname.includes("dns") || u.hostname === "1.1.1.1" || u.hostname === "8.8.8.8")
    return new Response("nope", { status: 500 });
  return new Response("ok", { status: 200 });
};
try {
  // Single-label / non-public-looking name still fails closed when DoH is down.
  await assertSafeOutboundUrl("https://unknownhost/");
  check("fails closed when DoH unavailable", false, "allowed through");
} catch (e) {
  check("fails closed when DoH unavailable", e instanceof SSRFBlockedError, e.message);
}

// 9b. Public-looking FQDNs no longer get a pass when every resolver is down
try {
  await assertSafeOutboundUrl("https://unknown.example.com/");
  check("public-looking FQDN still fails closed when DoH unavailable", false, "allowed through");
} catch (e) {
  check("public-looking FQDN still fails closed when DoH unavailable", e instanceof SSRFBlockedError, e.message);
}

// 9c. A lookups fail but AAAA answers public: runtime could connect over IPv4, so block
globalThis.fetch = async (url) => {
  const u = new URL(String(url));
  if (u.searchParams.get("type") === "A") return new Response("nope", { status: 500 });
  return new Response(JSON.stringify({ Status: 0, Answer: [{ data: "2606:4700::1111", type: 28 }] }), { status: 200 });
};
try {
  await assertSafeOutboundUrl("https://half.example.com/");
  check("blocks when only one record family could be checked", false, "allowed through");
} catch (e) {
  check("blocks when only one record family could be checked", e instanceof SSRFBlockedError, e.message);
}

// 10. Escape hatch re-opens it deliberately
process.env.AUDITKIT_ALLOW_UNRESOLVED_HOSTS = "true";
try {
  await assertSafeOutboundUrl("https://unknown.example/");
  check("escape hatch allows unresolved host", true);
} catch (e) {
  check("escape hatch allows unresolved host", false, e.message);
}
delete process.env.AUDITKIT_ALLOW_UNRESOLVED_HOSTS;

// 11. Empty public DNS answer (NXDOMAIN / NODATA) is blocked
stubFetch({});
try {
  await assertSafeOutboundUrl("https://only-internal.corp.example/");
  check("blocks name with no public A/AAAA records", false, "allowed through");
} catch (e) {
  check("blocks name with no public A/AAAA records", e instanceof SSRFBlockedError, e.message);
}

// 12. IPv6 literals that embed private IPv4 (URL serialises them in hex)
const blockedV6 = [
  "http://[::ffff:127.0.0.1]/",
  "http://[::ffff:169.254.169.254]/",
  "http://[::ffff:10.0.0.1]/",
  "http://[::127.0.0.1]/",
  "http://[::ffff:0:127.0.0.1]/",
  "http://[64:ff9b::169.254.169.254]/",
  "http://[2002:a9fe:a9fe::1]/",
  "http://[2001:0:4136:e378:8000:63bf:80ff:fffe]/", // Teredo, client 127.0.0.1
  "http://[fe90::1]/",
  "http://[fec0::1]/",
  "http://[fd00::1]/",
  "http://[::1]/",
  "http://[::]/",
  "http://[2001:db8::1]/",
];
for (const u of blockedV6) {
  try {
    await assertSafeOutboundUrl(u);
    check(`blocks ${u}`, false, `allowed (hostname ${new URL(u).hostname})`);
  } catch (e) {
    check(`blocks ${u}`, e instanceof SSRFBlockedError, e.message);
  }
}
for (const u of ["http://[2606:4700:4700::1111]/", "http://[::ffff:93.184.216.34]/", "http://[2002:5db8:d822::1]/"]) {
  try {
    await assertSafeOutboundUrl(u);
    check(`allows public ${u}`, true);
  } catch (e) {
    check(`allows public ${u}`, false, e.message);
  }
}

// 13. Hostname whose AAAA record is an IPv4-mapped private address
globalThis.fetch = async (url) => {
  const u = new URL(String(url));
  const type = u.searchParams.get("type");
  const Answer = type === "A" ? [{ data: "93.184.216.34", type: 1 }] : [{ data: "::ffff:a9fe:a9fe", type: 28 }];
  return new Response(JSON.stringify({ Status: 0, Answer }), { status: 200 });
};
try {
  await assertSafeOutboundUrl("https://sneaky.example.com/");
  check("blocks host whose AAAA maps to 169.254.169.254", false, "allowed through");
} catch (e) {
  check("blocks host whose AAAA maps to 169.254.169.254", e instanceof SSRFBlockedError, e.message);
}

// 14. Body size cap: streamed body past the limit errors instead of being read in full
stubFetch({
  "https://good.example/big": () =>
    new Response(new ReadableStream({
      start(c) { for (let i = 0; i < 20; i++) c.enqueue(new Uint8Array(1024)); c.close(); },
    }), { status: 200 }),
});
res = await safeFetch("https://good.example/big", {}, { maxBodyBytes: 4096 });
try {
  await res.text();
  check("body over maxBodyBytes errors", false, "read in full");
} catch (e) {
  check("body over maxBodyBytes errors", e instanceof ResponseTooLargeError, e.message);
}

// 15. Declared Content-Length over the cap is refused before reading
stubFetch({ "https://good.example/declared": () => new Response("x", { status: 200, headers: { "content-length": "999999999" } }) });
try {
  await safeFetch("https://good.example/declared", {}, { maxBodyBytes: 4096 });
  check("declared oversize body refused", false, "no error");
} catch (e) {
  check("declared oversize body refused", e instanceof ResponseTooLargeError, e.message);
}

// 16. Deadline covers the body: headers arrive, body never finishes
stubFetch({
  "https://good.example/slow": () =>
    new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode("partial")); } }), { status: 200 }),
});
{
  const started = Date.now();
  res = await safeFetch("https://good.example/slow", {}, { timeoutMs: 300 });
  const body = res.text();
  const outcome = await Promise.race([
    body.then(() => "resolved", (e) => `rejected: ${e.message}`),
    new Promise((r) => setTimeout(() => r("hung"), 3000)),
  ]);
  // A stub stream does not observe the abort signal, so a rejection comes from
  // our wrapper cancelling it; real fetch bodies abort directly.
  check("stalled body read is cut off by the deadline", outcome !== "hung" && outcome !== "resolved", `${outcome} after ${Date.now() - started}ms`);
}

// 17. Normal bodies still read fine
stubFetch({ "https://good.example/ok": () => new Response("hello world", { status: 200 }) });
res = await safeFetch("https://good.example/ok", {}, { maxBodyBytes: 4096 });
check("small body reads normally", (await res.text()) === "hello world");

console.log(fail === 0 ? "\nALL PASS" : `\n${fail} FAILURE(S)`);
process.exit(fail === 0 ? 0 : 1);
