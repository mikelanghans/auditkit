// Extra website checks: source maps, cookies, exposed files, third-party
// scripts, open redirects, header roll-up. Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  checkCookieFlags,
  checkExposedFiles,
  checkOpenRedirect,
  checkSecurityHeadersRollup,
  checkSourceMaps,
  checkThirdPartyScripts,
  clientRedirectHints,
  looksLikeSourceMap,
  redirectProbeUrls,
  sourceMapCandidates,
  REDIRECT_SENTINEL,
} from "../web-checks.ts";

const BASE = "https://app.example.com";
const INDEX = "<!doctype html><html><head><title>App</title></head><body><div id=root></div></body></html>";

test("source maps: candidates from the comment and <file>.map, same origin only", () => {
  const { candidates, inline } = sourceMapCandidates(
    [
      { url: BASE, body: INDEX },
      { url: `${BASE}/assets/index-abc.js`, body: "console.log(1)\n//# sourceMappingURL=index-abc.js.map" },
      { url: `${BASE}/assets/vendor-def.js?v=2`, body: "x()" },
      { url: `${BASE}/assets/inline.js`, body: "y()\n//# sourceMappingURL=data:application/json;base64,eyJ9" },
      { url: "https://cdn.other.com/lib.js", body: "z()\n//# sourceMappingURL=lib.js.map" },
    ],
    BASE,
  );
  assert.deepEqual(candidates, [
    `${BASE}/assets/index-abc.js.map`,
    `${BASE}/assets/vendor-def.js.map`,
  ]);
  assert.deepEqual(inline, [`${BASE}/assets/inline.js`]);
});

test("source maps: a real map fails, the SPA's index.html at the .map URL does not", () => {
  assert.ok(looksLikeSourceMap('{"version":3,"sources":["src/App.tsx"],"mappings":"AAAA"}'));
  assert.ok(!looksLikeSourceMap(INDEX));
  const fail = checkSourceMaps([{ url: `${BASE}/a.js.map`, status: 200, head: '{"version":3,"file":"a.js","mappings":";;AAAA"' }], [], 2);
  assert.equal(fail.status, "fail");
  const pass = checkSourceMaps(
    [
      { url: `${BASE}/a.js.map`, status: 200, head: INDEX },
      { url: `${BASE}/b.js.map`, status: 404, head: "" },
    ],
    [],
    2,
  );
  assert.equal(pass.status, "pass");
  assert.equal(checkSourceMaps([], [], 0).status, "inconclusive");
  assert.equal(checkSourceMaps([{ url: "x", error: "timeout" }], [], 1).status, "inconclusive");
  assert.equal(checkSourceMaps([], [`${BASE}/inline.js`], 1).status, "fail");
});

test("cookies: session cookie without HttpOnly/Secure fails; no cookies is not a pass", () => {
  assert.equal(checkCookieFlags([], true).status, "inconclusive");
  const bad = checkCookieFlags(["session_id=abc; Path=/; SameSite=Lax"], true);
  assert.equal(bad.status, "fail");
  assert.match(bad.notes, /HttpOnly/);
  assert.match(bad.notes, /Secure/);
  const good = checkCookieFlags(["session_id=abc; Path=/; Secure; HttpOnly; SameSite=Lax", "theme=dark; Secure"], true);
  assert.equal(good.status, "pass");
  assert.match(good.notes, /theme: no SameSite/);
  assert.equal(checkCookieFlags(["pref=1; SameSite=None"], true).status, "fail");
});

test("exposed files: real .env / .git content fails; SPA fallback 200s pass", () => {
  const probe = (path: string, status: number, head: string) => ({ path, url: `${BASE}${path}`, status, head });
  const fail = checkExposedFiles([
    probe("/.env", 200, "# prod\nSUPABASE_URL=https://x.supabase.co\nSTRIPE_SECRET_KEY=sk_live_123\n"),
    probe("/.git/HEAD", 200, "ref: refs/heads/main\n"),
    probe("/.DS_Store", 200, INDEX),
  ]);
  assert.equal(fail.status, "fail");
  assert.match(fail.notes, /\.env/);
  assert.match(fail.notes, /\.git\/HEAD/);
  assert.doesNotMatch(fail.notes, /DS_Store \(/);

  const pass = checkExposedFiles([probe("/.env", 200, INDEX), probe("/.git/config", 404, "Not found"), probe("/.git/HEAD", 200, INDEX)]);
  assert.equal(pass.status, "pass");
  assert.equal(checkExposedFiles([{ path: "/.env", url: `${BASE}/.env`, error: "timeout" }]).status, "inconclusive");
  assert.equal(
    checkExposedFiles([probe("/.env", 404, ""), { path: "/.git/HEAD", url: `${BASE}/.git/HEAD`, error: "reset" }]).status,
    "inconclusive",
  );
  assert.equal(checkExposedFiles([probe("/.git/config", 200, "[core]\n\trepositoryformatversion = 0\n")]).status, "fail");
});

test("third-party scripts: none passes, pinned passes, unpinned needs review", () => {
  assert.equal(checkThirdPartyScripts(`<script type=module src="/assets/index.js"></script>`, BASE).status, "pass");
  const pinned = `<script src="https://cdn.jsdelivr.net/npm/x@1/x.min.js" integrity="sha384-abc" crossorigin="anonymous"></script>`;
  assert.equal(checkThirdPartyScripts(pinned, BASE).status, "pass");
  const r = checkThirdPartyScripts(`${pinned}<script async src="https://js.stripe.com/v3"></script><script src="//www.googletagmanager.com/gtag/js?id=G-1"></script>`, BASE);
  assert.equal(r.status, "inconclusive");
  assert.match(r.notes, /js\.stripe\.com/);
  assert.match(r.notes, /googletagmanager/);
});

test("open redirect: server redirect to the probe host fails; client hint needs review", () => {
  const urls = redirectProbeUrls(BASE, ["/", "/login"]);
  assert.equal(urls.length, 8);
  assert.ok(urls.every((u) => u.includes(encodeURIComponent(REDIRECT_SENTINEL))));
  const fail = checkOpenRedirect([{ url: urls[1], status: 302, location: REDIRECT_SENTINEL }], []);
  assert.equal(fail.status, "fail");
  // Redirecting to its own login page is fine.
  assert.equal(checkOpenRedirect([{ url: urls[0], status: 302, location: "/login" }], []).status, "pass");
  const hints = clientRedirectHints([
    { url: `${BASE}/assets/a.js`, body: 'const n=new URLSearchParams(location.search);window.location.href=n.get("redirect")||"/"' },
  ]);
  assert.equal(hints.length, 1);
  assert.equal(checkOpenRedirect([{ url: urls[0], status: 200 }], hints).status, "inconclusive");
  assert.equal(checkOpenRedirect([{ url: urls[0], error: "x" }], []).status, "inconclusive");
  assert.deepEqual(clientRedirectHints([{ url: "a", body: 'navigate("/dashboard")' }]), []);
});

test("security headers roll-up", () => {
  const all = ["csp_header", "hsts_header", "xframe_header", "xcontent_type", "referrer_policy", "permissions_policy"];
  assert.equal(checkSecurityHeadersRollup(all.map((key) => ({ key, status: "pass" as const }))).status, "pass");
  assert.equal(
    checkSecurityHeadersRollup(all.map((key) => ({ key, status: key === "csp_header" ? ("fail" as const) : ("pass" as const) }))).status,
    "fail",
  );
  assert.equal(checkSecurityHeadersRollup(all.slice(1).map((key) => ({ key, status: "pass" as const }))).status, "inconclusive");
});
