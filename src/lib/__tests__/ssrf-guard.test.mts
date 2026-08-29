import { safeFetch, SSRFBlockedError, assertSafeOutboundUrl } from "../ssrf-guard.ts";

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
    if (u.hostname === "cloudflare-dns.com" || u.hostname === "dns.google") {
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

// 9b. Clearly public FQDNs are allowed through when every resolver is down
try {
  await assertSafeOutboundUrl("https://unknown.example.com/");
  check("public FQDN allowed when DoH unavailable", true);
} catch (e) {
  check("public FQDN allowed when DoH unavailable", false, e.message);
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

console.log(fail === 0 ? "\nALL PASS" : `\n${fail} FAILURE(S)`);
process.exit(fail === 0 ? 0 : 1);
