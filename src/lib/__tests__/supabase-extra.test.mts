// Supabase settings grading: JWT expiry, redirect URLs, providers, reset flow,
// backups, Security Advisor, sensitive columns. Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
import { FakeDb, stubFetch, json, text } from "./harness/fakes.mts";
import {
  checkAuthProviders,
  checkBackups,
  checkJwtExpiry,
  checkPasswordResetFlow,
  checkRedirectUrls,
  checkSecurityAdvisor,
  checkSensitiveColumns,
  classifyRedirectEntry,
} from "../supabase-extra-checks.ts";

test("no PAT / no config is inconclusive, never a pass", () => {
  for (const f of [checkJwtExpiry, checkRedirectUrls, checkAuthProviders, checkPasswordResetFlow]) {
    assert.equal(f(undefined, false).status, "inconclusive");
    assert.equal(f(undefined, true).status, "inconclusive");
  }
  assert.equal(checkBackups(null).status, "inconclusive");
  assert.equal(checkSecurityAdvisor(null).status, "inconclusive");
  assert.equal(checkSensitiveColumns(null).status, "inconclusive");
});

test("JWT expiry: ≤1h passes, up to a day needs review, longer fails", () => {
  assert.equal(checkJwtExpiry({ jwt_exp: 3600 }, true).status, "pass");
  assert.equal(checkJwtExpiry({ jwt_exp: 7200 }, true).status, "inconclusive");
  assert.equal(checkJwtExpiry({ jwt_exp: 604800 }, true).status, "fail");
  assert.equal(checkJwtExpiry({}, true).status, "inconclusive");
});

test("redirect URLs: shared-host wildcards, * and http fail; own wildcard subdomain needs review", () => {
  assert.equal(classifyRedirectEntry("https://app.example.com/**").level, "ok");
  assert.equal(classifyRedirectEntry("https://*.vercel.app/**").level, "bad");
  assert.equal(classifyRedirectEntry("https://*-myteam.vercel.app/**").level, "bad");
  assert.equal(classifyRedirectEntry("**").level, "bad");
  assert.equal(classifyRedirectEntry("https://*").level, "bad");
  assert.equal(classifyRedirectEntry("http://app.example.com").level, "bad");
  assert.equal(classifyRedirectEntry("https://*.example.com/**").level, "minor");
  assert.equal(classifyRedirectEntry("http://localhost:3000/**").level, "minor");

  const ok = checkRedirectUrls({ site_url: "https://app.example.com", uri_allow_list: "https://app.example.com/**" }, true);
  assert.equal(ok.status, "pass");
  const bad = checkRedirectUrls({ site_url: "https://app.example.com", uri_allow_list: "https://app.example.com/**,https://*.lovable.app/**" }, true);
  assert.equal(bad.status, "fail");
  assert.match(bad.notes, /lovable\.app/);
  assert.equal(checkRedirectUrls({ site_url: "http://localhost:3000", uri_allow_list: "" }, true).status, "fail");
  assert.equal(checkRedirectUrls({ site_url: "https://a.com", uri_allow_list: "http://localhost:3000" }, true).status, "inconclusive");
});

test("providers: anonymous sign-ins need review; SMS auto-confirm fails", () => {
  const base = { external_email_enabled: true, external_google_enabled: true, external_github_enabled: false, disable_signup: false };
  const p = checkAuthProviders(base, true);
  assert.equal(p.status, "pass");
  assert.match(p.notes, /email, google|google, email/);
  assert.doesNotMatch(p.notes, /github/);
  assert.equal(checkAuthProviders({ ...base, external_anonymous_users_enabled: true }, true).status, "inconclusive");
  assert.equal(checkAuthProviders({ ...base, external_phone_enabled: true, sms_autoconfirm: true }, true).status, "fail");
});

test("reset flow: long link expiry or insecure email change fails", () => {
  assert.equal(checkPasswordResetFlow({ mailer_otp_exp: 3600, mailer_secure_email_change_enabled: true }, true).status, "pass");
  assert.equal(checkPasswordResetFlow({ mailer_otp_exp: 86400, mailer_secure_email_change_enabled: true }, true).status, "fail");
  assert.equal(checkPasswordResetFlow({ mailer_otp_exp: 3600, mailer_secure_email_change_enabled: false }, true).status, "fail");
  assert.match(checkPasswordResetFlow({ mailer_otp_exp: 600, mailer_secure_email_change_enabled: true }, true).notes, /reauthentication/i);
});

test("backups: PITR or recent daily passes; none or stale fails; API error inconclusive", () => {
  const now = Date.parse("2026-09-30T12:00:00Z");
  assert.equal(checkBackups({ ok: true, data: { pitr_enabled: true } }, now).status, "pass");
  assert.equal(
    checkBackups({ ok: true, data: { pitr_enabled: false, backups: [{ status: "COMPLETED", inserted_at: "2026-09-30T02:00:00Z" }] } }, now).status,
    "pass",
  );
  assert.equal(checkBackups({ ok: true, data: { pitr_enabled: false, backups: [] } }, now).status, "fail");
  assert.equal(
    checkBackups({ ok: true, data: { backups: [{ status: "COMPLETED", inserted_at: "2026-09-20T02:00:00Z" }] } }, now).status,
    "fail",
  );
  assert.equal(checkBackups({ ok: false, error: "HTTP 403" }, now).status, "inconclusive");
});

test("security advisor: ERROR/WARN security lints fail; performance and INFO don't", () => {
  const lints = [
    { name: "rls_disabled_in_public", title: "RLS Disabled in Public", level: "ERROR", categories: ["SECURITY"], metadata: { schema: "public", name: "orders" } },
    { name: "unindexed_foreign_keys", title: "Unindexed foreign keys", level: "INFO", categories: ["PERFORMANCE"] },
  ];
  const r = checkSecurityAdvisor({ ok: true, lints });
  assert.equal(r.status, "fail");
  assert.match(r.notes, /public\.orders/);
  assert.doesNotMatch(r.notes, /Unindexed/);
  assert.equal(checkSecurityAdvisor({ ok: true, lints: [lints[1]] }).status, "pass");
  assert.equal(checkSecurityAdvisor({ ok: false, error: "HTTP 404" }).status, "inconclusive");
});

test("sensitive columns: plain password fails; hashed/reference columns ignored; others need review", () => {
  const rows = (xs: [string, string, string][]) => ({ ok: true, rows: xs.map(([table, column, type]) => ({ table, column, type })) });
  assert.equal(checkSensitiveColumns(rows([["users", "password_hash", "text"], ["cards", "card_last4", "text"], ["users", "password_changed_at", "timestamp with time zone"]])).status, "pass");
  assert.equal(checkSensitiveColumns(rows([["users", "password", "text"]])).status, "fail");
  const r = checkSensitiveColumns(rows([["integrations", "api_key", "text"], ["patients", "diagnosis", "text"]]));
  assert.equal(r.status, "inconclusive");
  assert.match(r.notes, /integrations\.api_key/);
  assert.equal(checkSensitiveColumns(rows([])).status, "pass");
});

// End to end through the Supabase scan: the new items are written by title.
const AUDIT = "audit-1";
const USER = "user-1";
const HOST = "abcdefghijklmnopqrst.supabase.co";
const TITLES = [
  "JWT expiry set appropriately",
  "OAuth redirect URIs locked down",
  "Database backups configured",
  "Supabase Security Advisor reports no issues",
  "Sensitive columns encrypted at rest",
];

test("supabase scan writes the new items from the Management API", async () => {
  const d = new FakeDb({
    audits: [{ id: AUDIT, created_by: USER, client_id: "c1" }],
    checklist_items: TITLES.map((t, i) => ({ id: `x${i}`, title: t })),
  });
  const c = { supabase: d.client(), userId: USER };
  (globalThis as any).__TEST_CONTEXT__ = c;
  stubFetch((url, init) => {
    const u = new URL(url);
    const h = new Headers(init.headers as any);
    if (u.host === HOST) {
      if (u.pathname === "/rest/v1/") return h.get("authorization") === "Bearer SERVICE" ? json({}) : json({ paths: {} });
      if (u.pathname === "/storage/v1/bucket") return json([]);
      if (u.pathname === "/auth/v1/recover") return json({});
    }
    if (u.host === "api.supabase.com") {
      if (u.pathname.endsWith("/config/auth"))
        return json({ jwt_exp: 3600, site_url: "https://app.example.com", uri_allow_list: "https://*.vercel.app/**", password_min_length: 8, password_hibp_enabled: true });
      if (u.pathname.endsWith("/advisors/security")) return json({ lints: [{ name: "x", title: "Security Definer View", level: "ERROR", categories: ["SECURITY"] }] });
      if (u.pathname.endsWith("/database/backups")) return json({ pitr_enabled: true, backups: [] });
      if (u.pathname.endsWith("/database/query")) {
        const q = String(JSON.parse(String(init.body)).query);
        if (q.includes("information_schema.columns")) return json([{ table: "users", column: "password", type: "text" }]);
        return json([]);
      }
      if (u.pathname.endsWith("/functions")) return json([]);
    }
    return text("nf", 404);
  });
  const { runSupabaseScan } = await import("../supabase-scan.functions.ts");
  const res: any = await runSupabaseScan({
    data: { auditId: AUDIT, projectUrl: `https://${HOST}`, anonKey: "ANON", serviceRoleKey: "SERVICE", managementPat: "sbp" },
    context: c,
  } as any);
  assert.equal(res.ok, true, res.error);
  const st = (i: number) => d.finding(AUDIT, `x${i}`)?.status;
  assert.equal(st(0), "pass");
  assert.equal(st(1), "fail");
  assert.equal(st(2), "pass");
  assert.equal(st(3), "fail");
  assert.equal(st(4), "fail");
});
