// Fix prompts for header, secret and database items follow a playbook.
// Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
import { FakeDb, stubFetch, json } from "./harness/fakes.mts";
import { playbookFor } from "../fix-playbooks.ts";

const AUDIT = "audit-1";
const USER = "user-1";

test("playbooks: matched by checklist key or title; unrelated items get none", () => {
  assert.equal(playbookFor({ checklist_key: "csp_header" })?.id, "csp");
  assert.equal(playbookFor({ title: "Content Security Policy set" })?.id, "csp");
  assert.equal(playbookFor({ checklist_key: "vite_exposure" })?.id, "secret");
  assert.equal(playbookFor({ title: "RLS enabled on all tables" })?.id, "rls");
  assert.equal(playbookFor({ title: "Database backups configured" }), null);
});

test("CSP playbook: nonce for server-rendered apps, no unsafe-inline scripts, Report-Only rollout, preview exemption", () => {
  const t = playbookFor({ checklist_key: "csp_header" })!.text;
  assert.match(t, /nonce/);
  assert.match(t, /must not contain 'unsafe-inline'/);
  assert.match(t, /Report-Only/);
  assert.match(t, /object-src 'none'/);
  assert.match(t, /frame-ancestors/);
  assert.match(t, /production/i);
  assert.match(t, /If the app uses Supabase/); // conditional, not assumed
});

test("secret playbook: rotate before code changes", () => {
  const t = playbookFor({ checklist_key: "bundle_secrets" })!.text;
  assert.ok(t.indexOf("Rotate") < t.indexOf("server-side code"));
  assert.match(t, /Public-by-design keys/);
});

async function generate(item: Record<string, unknown>) {
  process.env.ANTHROPIC_API_KEY = "test-key";
  const db = new FakeDb({
    audits: [{ id: AUDIT, created_by: USER, built_with: "lovable" }],
    checklist_items: [{ id: "ci1", ...item }],
    audit_findings: [{ audit_id: AUDIT, checklist_item_id: "ci1", status: "fail", notes: "No Content-Security-Policy header on https://app.example.com" }],
  });
  const c = { supabase: db.client(), userId: USER };
  (globalThis as any).__TEST_CONTEXT__ = c;
  let body: any = null;
  stubFetch((url, init) => {
    if (url.startsWith("https://api.anthropic.com/")) {
      body = JSON.parse(String(init.body));
      return json({ content: [{ type: "text", text: "the prompt" }] });
    }
    return undefined;
  });
  const { generateFixPrompt } = await import("../fix-prompt.functions.ts");
  const res: any = await generateFixPrompt({ data: { auditId: AUDIT, checklistItemId: "ci1", target: "lovable" }, context: c } as any);
  assert.equal(res.ok, true, res.error);
  return body;
}

test("fix prompt: a CSP finding sends the playbook and the rule to follow it", async () => {
  const body = await generate({ title: "Content Security Policy set", category: "Frontend Security", checklist_key: "csp_header" });
  const user = body.messages[0].content as string;
  assert.match(user, /REMEDIATION PLAYBOOK \(csp\)/);
  assert.match(user, /nonce/);
  assert.match(body.system, /MUST follow every requirement/);
});

test("fix prompt: items without a playbook are unchanged", async () => {
  const body = await generate({ title: "Database backups configured", category: "Database Security", checklist_key: null });
  assert.doesNotMatch(body.messages[0].content, /REMEDIATION PLAYBOOK/);
});
