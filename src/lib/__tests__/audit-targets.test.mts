// Target normalization. Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";

test("targets are normalized per kind and junk is refused", async () => {
  const { normalizeTarget } = await import("../audit-targets.ts");
  const ok = (k: any, raw: string) => {
    const r = normalizeTarget(k, raw);
    assert.ok(r.ok, `${k} ${raw}: ${(r as any).error}`);
    return (r as any).value;
  };
  const bad = (k: any, raw: string) => assert.equal(normalizeTarget(k, raw).ok, false, `${k} ${raw}`);

  assert.equal(ok("website", "app.example.com/login?x=1"), "https://app.example.com");
  assert.equal(ok("website", "http://example.com:8080/"), "http://example.com:8080");
  bad("website", "localhost");
  bad("website", "ftp://example.com");
  bad("website", "https://user:pw@example.com");

  assert.equal(ok("repo", "github.com/acme/app.git"), "https://github.com/acme/app");
  assert.equal(ok("repo", "https://github.com/acme/app/"), "https://github.com/acme/app");
  bad("repo", "https://gitlab.com/acme/app");
  bad("repo", "https://github.com/acme/app/tree/main");

  assert.equal(ok("supabase", "https://ABCDEFGHIJKLMNOPQRST.supabase.co/"), "https://abcdefghijklmnopqrst.supabase.co");
  bad("supabase", "http://abcdefghijklmnopqrst.supabase.co");
  bad("supabase", "https://db.example.com");

  assert.equal(ok("ai_endpoint", "https://app.example.com/api/chat/"), "https://app.example.com/api/chat");
  bad("api", "");
});
