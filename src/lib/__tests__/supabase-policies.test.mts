// Database policy review (3.1). Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";

const P = (o: any) => ({ schema: "public", table: "t", policy: "p", permissive: "PERMISSIVE", roles: ["public"], cmd: "SELECT", qual: null, with_check: null, ...o });

test("policies: blanket access fails, own-row policies pass, auth-only reads need review", async () => {
  const { checkPolicies, isAuthOnly } = await import("../supabase-policy-checks.ts");
  assert.equal(checkPolicies([P({ qual: "true" })]).status, "fail", "USING (true) to public");
  assert.equal(checkPolicies([P({ roles: ["anon"], cmd: "INSERT", with_check: "true" })]).status, "fail", "anon insert anything");
  assert.equal(checkPolicies([P({ roles: ["authenticated"], cmd: "UPDATE", qual: "true" })]).status, "fail", "any user updates every row");
  assert.equal(checkPolicies([P({ roles: ["authenticated"], cmd: "DELETE", qual: "(auth.uid() IS NOT NULL)" })]).status, "fail", "auth-only delete");
  assert.equal(checkPolicies([P({ roles: ["authenticated"], qual: "((auth.jwt() -> 'user_metadata'::text) ->> 'role'::text) = 'admin'::text" })]).status, "fail", "user_metadata");
  assert.equal(checkPolicies([P({ schema: "storage", table: "objects", roles: ["public"], qual: "true" })]).status, "fail", "storage open");

  const r = checkPolicies([P({ roles: ["authenticated"], qual: "true" })]);
  assert.equal(r.status, "inconclusive", "signed-in users read everything: review, not auto-fail");
  assert.equal(checkPolicies([P({ roles: ["authenticated"], qual: "(( SELECT auth.uid() AS uid) IS NOT NULL)" })]).status, "inconclusive");

  const own = [
    P({ roles: ["authenticated"], qual: "(user_id = auth.uid())" }),
    P({ roles: ["authenticated"], cmd: "INSERT", with_check: "(user_id = ( SELECT auth.uid() AS uid))" }),
    P({ roles: ["public"], permissive: "RESTRICTIVE", qual: "true" }),
  ];
  assert.equal(checkPolicies(own).status, "pass");
  assert.equal(checkPolicies(null).status, "inconclusive");
  assert.equal(isAuthOnly("(auth.role() = 'authenticated'::text)"), true);
  assert.equal(isAuthOnly("(user_id = auth.uid())"), false);
});

test("definer search_path and exposed views", async () => {
  const { checkDefinerSearchPath, checkExposedViews } = await import("../supabase-policy-checks.ts");
  assert.equal(checkDefinerSearchPath([{ name: "f", args: "", config: "search_path=public, pg_temp" }]).status, "pass");
  assert.equal(checkDefinerSearchPath([{ name: "f", args: "", config: "" }]).status, "fail");
  assert.equal(checkDefinerSearchPath([]).status, "pass");
  assert.equal(checkExposedViews([{ view: "v", security_invoker: "false", anon_select: true, auth_select: true }]).status, "fail");
  assert.equal(checkExposedViews([{ view: "v", security_invoker: "true", anon_select: true, auth_select: true }]).status, "pass");
  assert.equal(checkExposedViews([{ view: "v", security_invoker: "false", anon_select: false, auth_select: false }]).status, "pass");
  assert.equal(checkExposedViews(null, "HTTP 401").status, "inconclusive");
});
