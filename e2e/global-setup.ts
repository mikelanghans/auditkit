// Creates the test owner (allowlisted, email confirmed, TOTP enrolled) and
// one client + audit in the LOCAL Supabase, then signs in through the real
// sign-in and two-factor pages and saves the session for the tests.
import { chromium, type FullConfig } from "@playwright/test";
import { createClient } from "@supabase/supabase-js";
import { mkdirSync, writeFileSync } from "node:fs";
import { ANON_KEY, APP_URL, CANARY_SITE, OWNER_EMAIL, OWNER_PASSWORD, SERVICE_KEY, STATE_DIR, SUPABASE_URL, assertLocal } from "./env";
import { freshTotp } from "./totp";
import { blockNonLocal } from "./guard";

export default async function globalSetup(_config: FullConfig) {
  assertLocal();
  mkdirSync(STATE_DIR, { recursive: true });
  const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });

  // 1. Owner account on the allowlist.
  const { error: ownerErr } = await admin.from("app_owners").upsert({ email: OWNER_EMAIL });
  if (ownerErr) throw new Error(`app_owners: ${ownerErr.message}`);
  const { data: list } = await admin.auth.admin.listUsers();
  let user = list?.users.find((u) => u.email === OWNER_EMAIL) ?? null;
  if (!user) {
    const { data, error } = await admin.auth.admin.createUser({ email: OWNER_EMAIL, password: OWNER_PASSWORD, email_confirm: true });
    if (error || !data.user) throw new Error(`createUser: ${error?.message}`);
    user = data.user;
  }

  // 2. Enroll a TOTP factor with a known secret.
  const anon = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
  const { error: siErr } = await anon.auth.signInWithPassword({ email: OWNER_EMAIL, password: OWNER_PASSWORD });
  if (siErr) throw new Error(`signIn: ${siErr.message}`);
  const { data: factors } = await anon.auth.mfa.listFactors();
  for (const f of factors?.all ?? []) await anon.auth.mfa.unenroll({ factorId: f.id });
  const { data: enrolled, error: enErr } = await anon.auth.mfa.enroll({ factorType: "totp", friendlyName: `e2e-${Date.now()}` });
  if (enErr || !enrolled) throw new Error(`enroll: ${enErr?.message}`);
  const secret = enrolled.totp.secret;
  const { error: vErr } = await anon.auth.mfa.challengeAndVerify({ factorId: enrolled.id, code: await freshTotp(secret) });
  if (vErr) throw new Error(`verify: ${vErr.message}`);
  await anon.auth.signOut();

  // 3. A client and an audit of a site on a reserved, unresolvable domain.
  const { data: client, error: cErr } = await admin.from("clients").insert({ name: "E2E Canary Co", created_by: user.id }).select("id").single();
  if (cErr) throw new Error(`client: ${cErr.message}`);
  const { data: audit, error: aErr } = await admin
    .from("audits")
    .insert({ title: `E2E ${new Date().toISOString()}`, client_id: client.id, created_by: user.id, website_url: CANARY_SITE })
    .select("id")
    .single();
  if (aErr) throw new Error(`audit: ${aErr.message}`);
  writeFileSync(`${STATE_DIR}/run.json`, JSON.stringify({ auditId: audit.id, clientId: client.id, totpSecret: secret }));

  // 4. Sign in through the real pages.
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await blockNonLocal(page.context());
  await page.goto(`${APP_URL}/auth`);
  await page.locator("#email1").fill(OWNER_EMAIL);
  await page.locator("#pw1").fill(OWNER_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL(/\/mfa/);
  await page.locator("#code").fill(await freshTotp(secret));
  await page.locator("form").getByRole("button").first().click();
  await page.waitForURL(/\/dashboard/);
  await page.context().storageState({ path: `${STATE_DIR}/owner.json` });
  await browser.close();
}
