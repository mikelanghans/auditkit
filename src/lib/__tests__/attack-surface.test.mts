// Attack surface map (3.7). Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";

test("surface: domains, crt.sh parsing, SPF, DMARC, takeover", async () => {
  const m = await import("../attack-surface.ts");
  assert.equal(m.registrableDomain("app.eu.example.com"), "example.com");
  assert.equal(m.registrableDomain("shop.example.co.uk"), "example.co.uk");
  assert.deepEqual(
    m.subdomainsFromCrtSh([{ name_value: "*.example.com\nexample.com" }, { name_value: "api.example.com\nmail.other.com" }, { name_value: "Staging.Example.com." }], "example.com"),
    ["example.com", "api.example.com", "staging.example.com"],
  );
  assert.equal(m.checkSpf([], "x.com").status, "fail");
  assert.equal(m.checkSpf(["v=spf1 include:_spf.google.com -all"], "x.com").status, "pass");
  assert.equal(m.checkSpf(["v=spf1 +all"], "x.com").status, "fail");
  assert.equal(m.checkSpf(["v=spf1 a", "v=spf1 mx -all"], "x.com").status, "fail");
  assert.equal(m.checkSpf(null, "x.com").status, "inconclusive");
  assert.equal(m.checkDmarc(["v=DMARC1; p=reject; rua=mailto:d@x.com"], "x.com").status, "pass");
  assert.equal(m.checkDmarc(["v=DMARC1; p=none"], "x.com").status, "fail");
  assert.equal(m.checkDmarc([], "x.com").status, "fail");
  assert.equal(m.takeoverService("acme-old.herokuapp.com."), "Heroku");
  assert.equal(m.takeoverService("cname.vercel-dns.com"), null);
  const t = m.checkTakeover([{ host: "old.example.com", cname: "acme-old.herokuapp.com", targetStatus: 3 }, { host: "www.example.com", cname: "acme.netlify.app", targetStatus: 0 }], 2, 2);
  assert.equal(t.status, "fail");
  assert.match(t.notes, /old\.example\.com/);
  assert.doesNotMatch(t.notes, /www\.example\.com/);
  assert.equal(m.checkTakeover([{ host: "a.example.com", cname: undefined }], 1, 1).status, "pass");
  assert.equal(m.checkTakeover([{ host: "a.example.com", cname: undefined }], 1, 80).status, "inconclusive");
  assert.equal(m.checkTakeover(null, 0, 0).status, "inconclusive");
});

import { FakeDb, stubFetch, json, text } from "./harness/fakes.mts";

test("surface scan end to end: missing DMARC and a dangling Heroku CNAME fail; SPF passes", async () => {
  const db = new FakeDb({
    audits: [{ id: "a1", created_by: "u1", website_url: "https://app.acme.test" }],
    checklist_items: [
      { id: "spf", checklist_key: "email_spf" },
      { id: "dmarc", checklist_key: "email_dmarc" },
      { id: "tko", checklist_key: "subdomain_takeover" },
    ],
  });
  const c = { supabase: db.client(), userId: "u1" };
  (globalThis as any).__TEST_CONTEXT__ = c;
  const dns: Record<string, any> = {
    "acme.test|TXT": { Status: 0, Answer: [{ name: "acme.test", type: 16, data: '"v=spf1 include:_spf.google.com " "-all"' }] },
    "_dmarc.acme.test|TXT": { Status: 3 },
    "old.acme.test|CNAME": { Status: 0, Answer: [{ name: "old.acme.test", type: 5, data: "acme-old.herokuapp.com." }] },
    "acme-old.herokuapp.com|A": { Status: 3 },
    "app.acme.test|CNAME": { Status: 0, Answer: [] },
  };
  stubFetch((url) => {
    const u = new URL(url);
    if (u.host === "crt.sh") return json([{ name_value: "app.acme.test\nold.acme.test\n*.acme.test" }]);
    if (u.host === "cloudflare-dns.com" || u.host === "dns.google") {
      const key = `${u.searchParams.get("name")}|${u.searchParams.get("type")}`;
      return dns[key] ? json(dns[key]) : json({ Status: 0, Answer: [] });
    }
    return text("nf", 404);
  }, { answersDns: true });
  const { runSurfaceScan } = await import("../attack-surface.functions.ts");
  const res: any = await runSurfaceScan({ data: { auditId: "a1" }, context: c } as any);
  assert.equal(res.ok, true, res.error);
  assert.equal(res.domain, "acme.test");
  assert.equal(db.finding("a1", "spf")?.status, "pass");
  assert.equal(db.finding("a1", "dmarc")?.status, "fail");
  assert.equal(db.finding("a1", "tko")?.status, "fail");
  assert.match(String(db.finding("a1", "tko")?.notes), /old\.acme\.test → acme-old\.herokuapp\.com/);
  assert.equal(db.rows("scan_runs")[0].scanner, "surface");
});
