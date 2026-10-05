// Repo URL parsing, repo ↔ website matching, threat-feed lookback.
// Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
import { judgeSiteMatch, parseGithubRepo, siteHost } from "../github-repo.ts";

test("parseGithubRepo: GitHub forms accepted, anything else rejected", () => {
  const ok = { owner: "mikelanghans", repo: "auditkit" };
  assert.deepEqual(parseGithubRepo("https://github.com/mikelanghans/auditkit"), ok);
  assert.deepEqual(parseGithubRepo("https://github.com/mikelanghans/auditkit.git"), ok);
  assert.deepEqual(parseGithubRepo("https://github.com/mikelanghans/auditkit/tree/main/src"), ok);
  assert.deepEqual(parseGithubRepo("github.com/mikelanghans/auditkit"), ok);
  assert.deepEqual(parseGithubRepo("git@github.com:mikelanghans/auditkit.git"), ok);
  assert.deepEqual(parseGithubRepo("mikelanghans/auditkit"), ok);
  for (const bad of ["https://gitlab.com/a/b", "https://mikelanghans.com/about", "mikelanghans.com/about", "auditkit", "https://github.com/mikelanghans", "https://notgithub.com/a/b", ""])
    assert.equal(parseGithubRepo(bad), null, bad);
});

test("site match: homepage, CNAME, code mention or search hit count; nothing found warns", () => {
  const site = "https://www.MikeLanghans.com/";
  assert.equal(siteHost(site), "mikelanghans.com");
  assert.equal(judgeSiteMatch({ siteUrl: site, homepage: "https://mikelanghans.com" }).match, "yes");
  assert.equal(judgeSiteMatch({ siteUrl: site, cname: "www.mikelanghans.com\n" }).match, "yes");
  assert.equal(judgeSiteMatch({ siteUrl: site, texts: ["see mikelanghans.com"] }).match, "yes");
  assert.equal(judgeSiteMatch({ siteUrl: site, searchHits: 3 }).match, "yes");
  const no = judgeSiteMatch({ siteUrl: site, homepage: "https://other.com", searchHits: 0 });
  assert.equal(no.match, "no");
  assert.match(no.note, /mikelanghans\.com/);
  assert.equal(judgeSiteMatch({ siteUrl: site, searchHits: null }).match, "unknown");
  // A confirmed repo is a match even with no evidence in the code.
  assert.equal(judgeSiteMatch({ siteUrl: site, searchHits: 0, confirmed: true }).match, "yes");
  assert.equal(judgeSiteMatch({ siteUrl: site, confirmed: true }).match, "yes");
  assert.equal(judgeSiteMatch({ siteUrl: null }).match, "unknown");
});

test("threat feed lookback: 14 days when empty, from the newest item otherwise, capped at 30", async () => {
  const { computeLookback } = await import("../threat-feed.server.ts");
  const now = Date.parse("2026-09-30T12:00:00Z");
  const day = 86_400_000;
  assert.equal(computeLookback(null, now), new Date(now - 14 * day).toISOString());
  assert.equal(computeLookback("2026-09-28T12:00:00Z", now), "2026-09-27T12:00:00.000Z");
  assert.equal(computeLookback("2026-09-30T11:00:00Z", now), "2026-09-29T11:00:00.000Z");
  assert.equal(computeLookback("2026-01-01T00:00:00Z", now), new Date(now - 30 * day).toISOString());
});

test("blocked-URL messages: a missing DNS name isn't called an internal destination", async () => {
  const { describeBlockedUrl } = await import("../ssrf-guard.ts");
  const missing = describeBlockedUrl({ message: "Blocked: app.example.com has no public A/AAAA records." });
  assert.match(missing, /app\.example\.com doesn't exist in public DNS/);
  assert.doesNotMatch(missing, /internal/);
  assert.match(describeBlockedUrl({ message: "Blocked private IP address: 10.0.0.1" }), /Refusing to probe internal/);
});
