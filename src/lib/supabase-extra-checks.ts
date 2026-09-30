// Pure grading for Supabase settings the scan already has access to: JWT
// expiry, redirect allow-list, auth providers, password reset/email change,
// backups, Supabase's own Security Advisor, and sensitive-looking columns.
// No imports, so tests can load it directly.

export type ExtraResult = { status: "pass" | "fail" | "na" | "inconclusive"; notes: string };
type Cfg = Record<string, unknown> | undefined;

const NEED_PAT = "Not checked. Reading this requires a Management API PAT.";

function noCfg(cfg: Cfg, patGiven: boolean): ExtraResult | null {
  if (cfg) return null;
  return {
    status: "inconclusive",
    notes: patGiven ? "Could not read the auth configuration from the Management API." : NEED_PAT,
  };
}

// ---------------------------------------------------------------------------
// JWT expiry
// ---------------------------------------------------------------------------

export function checkJwtExpiry(cfg: Cfg, patGiven: boolean): ExtraResult {
  const missing = noCfg(cfg, patGiven);
  if (missing) return missing;
  const exp = cfg!["jwt_exp"];
  if (typeof exp !== "number") return { status: "inconclusive", notes: "The auth configuration did not include jwt_exp." };
  const human = exp % 3600 === 0 ? `${exp / 3600} hour(s)` : `${Math.round(exp / 60)} minute(s)`;
  if (exp <= 3600)
    return { status: "pass", notes: `Access tokens expire after ${human} (jwt_exp = ${exp}s), Supabase's recommended maximum.` };
  if (exp <= 86_400)
    return {
      status: "inconclusive",
      notes: `Access tokens live for ${human} (jwt_exp = ${exp}s), longer than Supabase's recommended 1 hour. A stolen token stays usable that long and can't be revoked. Confirm there's a reason, or lower it under Authentication → Sessions / JWT settings.`,
    };
  return {
    status: "fail",
    notes: `Access tokens live for ${human} (jwt_exp = ${exp}s). A leaked token stays valid for over a day and can't be revoked. Set it to 3600 seconds or less; refresh tokens keep users signed in.`,
  };
}

// ---------------------------------------------------------------------------
// Redirect URLs
// ---------------------------------------------------------------------------

/** Hosting platforms where anyone can publish a subdomain. */
const SHARED_HOST_SUFFIXES = [
  "vercel.app",
  "netlify.app",
  "lovable.app",
  "lovableproject.com",
  "pages.dev",
  "workers.dev",
  "github.io",
  "onrender.com",
  "herokuapp.com",
  "web.app",
  "firebaseapp.com",
  "replit.app",
  "repl.co",
  "fly.dev",
  "railway.app",
  "surge.sh",
];

export function classifyRedirectEntry(entry: string): { level: "bad" | "minor" | "ok"; why?: string } {
  const e = entry.trim();
  if (!e) return { level: "ok" };
  if (/^\*+$/.test(e) || /^https?:\/\/\*+(\/|$)/.test(e) || /^https?:\/\/\*\*/.test(e))
    return { level: "bad", why: "matches any website" };
  const host = e.replace(/^[a-z]+:\/\//i, "").split(/[/?#]/)[0].toLowerCase();
  if (host.includes("*")) {
    const labels = host.split(".");
    let last = -1;
    labels.forEach((l, i) => {
      if (l.includes("*")) last = i;
    });
    const fixed = labels.slice(last + 1).join(".").replace(/:\d+$/, "");
    if (!fixed || SHARED_HOST_SUFFIXES.includes(fixed))
      return { level: "bad", why: `wildcard on ${fixed || "any host"}, where anyone can create a site and receive users' login tokens` };
    return { level: "minor", why: "wildcard subdomain; make sure every subdomain is yours" };
  }
  if (/^(localhost|127\.0\.0\.1|0\.0\.0\.0)(:|$)/.test(host)) return { level: "minor", why: "localhost entry left in production" };
  if (/^http:\/\//i.test(e)) return { level: "bad", why: "plain http, so tokens in the redirect can be intercepted" };
  return { level: "ok" };
}

export function checkRedirectUrls(cfg: Cfg, patGiven: boolean): ExtraResult {
  const missing = noCfg(cfg, patGiven);
  if (missing) return missing;
  const siteUrl = typeof cfg!["site_url"] === "string" ? (cfg!["site_url"] as string) : "";
  const raw = typeof cfg!["uri_allow_list"] === "string" ? (cfg!["uri_allow_list"] as string) : "";
  const entries = raw.split(",").map((s) => s.trim()).filter(Boolean);
  const bad: string[] = [];
  const minor: string[] = [];
  for (const e of entries) {
    const c = classifyRedirectEntry(e);
    if (c.level === "bad") bad.push(`${e}: ${c.why}`);
    else if (c.level === "minor") minor.push(`${e}: ${c.why}`);
  }
  if (/localhost|127\.0\.0\.1/.test(siteUrl)) bad.push(`Site URL is ${siteUrl}: sign-up and reset emails will link to localhost`);
  else if (/^http:\/\//i.test(siteUrl)) bad.push(`Site URL is plain http (${siteUrl})`);
  const listing = `Site URL: ${siteUrl || "(not set)"}\nRedirect allow-list:\n${entries.length ? entries.map((e) => `- ${e}`).join("\n") : "- (empty)"}`;
  if (bad.length)
    return {
      status: "fail",
      notes: `After sign-in, magic-link or OAuth login, Supabase sends the user (with tokens in the URL) to a redirect address checked against this list. These entries are too broad:\n${bad
        .map((b) => `- ${b}`)
        .join("\n")}${minor.length ? `\n\nAlso review:\n${minor.map((m) => `- ${m}`).join("\n")}` : ""}\n\n${listing}\n\nList exact production URLs (a path wildcard like https://app.example.com/** is fine).`,
    };
  if (minor.length)
    return { status: "inconclusive", notes: `No dangerous entries, but review:\n${minor.map((m) => `- ${m}`).join("\n")}\n\n${listing}` };
  return { status: "pass", notes: `Redirect URLs are limited to specific HTTPS addresses.\n\n${listing}` };
}

// ---------------------------------------------------------------------------
// Auth providers
// ---------------------------------------------------------------------------

export function checkAuthProviders(cfg: Cfg, patGiven: boolean): ExtraResult {
  const missing = noCfg(cfg, patGiven);
  if (missing) return missing;
  const c = cfg!;
  const providers = Object.keys(c)
    .map((k) => /^external_([a-z0-9_]+)_enabled$/.exec(k)?.[1])
    .filter((p): p is string => !!p && c[`external_${p}_enabled`] === true && p !== "anonymous_users");
  const anonymous = c["external_anonymous_users_enabled"] === true;
  const signupsOpen = c["disable_signup"] === false;
  const phoneAutoconfirm = c["external_phone_enabled"] === true && c["sms_autoconfirm"] === true;
  const summary = [
    `Enabled sign-in providers: ${providers.length ? providers.join(", ") : "none besides email"}`,
    `Anonymous sign-ins: ${anonymous ? "ON" : "off"}`,
    `New sign-ups: ${c["disable_signup"] === true ? "closed" : signupsOpen ? "open" : "unknown"}`,
  ].join("\n");
  const issues: string[] = [];
  if (phoneAutoconfirm) issues.push("Phone sign-in auto-confirms numbers without an SMS code, so anyone can register any number.");
  if (issues.length) return { status: "fail", notes: `${issues.join("\n")}\n\n${summary}` };
  if (anonymous)
    return {
      status: "inconclusive",
      notes: `Anonymous sign-ins are on. Anonymous users get the "authenticated" role, so any RLS policy written as "to authenticated" or "auth.uid() is not null" lets them in too. Confirm that's intended and that policies check (auth.jwt()->>'is_anonymous')::boolean where it matters, and that CAPTCHA is on to stop mass sign-ups.\n\n${summary}`,
    };
  return {
    status: "pass",
    notes: `${summary}\n\nEach enabled provider should use the project's own OAuth app credentials and the redirect allow-list checked under "OAuth redirect URIs locked down".`,
  };
}

// ---------------------------------------------------------------------------
// Password reset / email change
// ---------------------------------------------------------------------------

export function checkPasswordResetFlow(cfg: Cfg, patGiven: boolean): ExtraResult {
  const missing = noCfg(cfg, patGiven);
  if (missing) return missing;
  const c = cfg!;
  const otpExp = typeof c["mailer_otp_exp"] === "number" ? (c["mailer_otp_exp"] as number) : null;
  const secureChange = c["mailer_secure_email_change_enabled"];
  const reauth = c["security_update_password_require_reauthentication"];
  const problems: string[] = [];
  const advice: string[] = [];
  if (otpExp !== null && otpExp > 3600)
    problems.push(`Reset and magic links stay valid for ${Math.round(otpExp / 60)} minutes (mailer_otp_exp = ${otpExp}s). Supabase recommends 1 hour or less.`);
  if (secureChange === false)
    problems.push("Secure email change is off: an attacker with a stolen session can move the account to their own email with one confirmation.");
  if (reauth !== true)
    advice.push("Consider turning on \"Require reauthentication to update password\" (security_update_password_require_reauthentication) so a stolen session can't silently change the password.");
  const facts = `mailer_otp_exp: ${otpExp ?? "unknown"}\nSecure email change: ${secureChange === true ? "on" : secureChange === false ? "off" : "unknown"}\nReauthentication for password change: ${reauth === true ? "on" : reauth === false ? "off" : "unknown"}`;
  if (problems.length)
    return { status: "fail", notes: `${problems.map((p) => `- ${p}`).join("\n")}${advice.length ? `\n\n${advice.join("\n")}` : ""}\n\n${facts}` };
  if (otpExp === null && secureChange === undefined)
    return { status: "inconclusive", notes: `The auth configuration didn't include the reset settings.\n\n${facts}` };
  return {
    status: "pass",
    notes: `Reset links expire within an hour and email changes need confirmation.${advice.length ? `\n\n${advice.join("\n")}` : ""}\n\n${facts}\n\nThe app's own reset page (session handling after the link) still needs a manual walkthrough.`,
  };
}

// ---------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------

export type BackupsResponse = {
  pitr_enabled?: boolean;
  walg_enabled?: boolean;
  backups?: { status?: string; inserted_at?: string; is_physical_backup?: boolean }[];
};

export function checkBackups(
  res: { ok: boolean; data?: BackupsResponse; error?: string; http?: number } | null,
  now = Date.now(),
): ExtraResult {
  if (!res) return { status: "inconclusive", notes: NEED_PAT };
  if (!res.ok || !res.data)
    return { status: "inconclusive", notes: `Could not read the project's backups: ${res.error ?? "unknown error"}.` };
  const d = res.data;
  if (d.pitr_enabled)
    return { status: "pass", notes: "Point-in-time recovery is enabled: the database can be restored to any second in the retention window." };
  const done = (d.backups ?? [])
    .filter((b) => (b.status ?? "").toUpperCase() === "COMPLETED" && b.inserted_at)
    .map((b) => Date.parse(b.inserted_at!))
    .filter((t) => !Number.isNaN(t))
    .sort((a, b) => b - a);
  if (done.length === 0)
    return {
      status: "fail",
      notes:
        "The project has no completed backups. Supabase's Free plan doesn't include downloadable daily backups, so a bad migration or deleted table can't be undone. Upgrade to Pro (daily backups, 7 days) or schedule your own pg_dump to separate storage.",
    };
  const ageH = Math.round((now - done[0]) / 3_600_000);
  if (ageH > 48)
    return { status: "fail", notes: `The newest completed backup is ${ageH} hours old. Daily backups have stopped; check the project's plan and backup status.` };
  return {
    status: "pass",
    notes: `Daily backups are running: ${done.length} completed, newest ${ageH} hour(s) ago. Point-in-time recovery is off, so up to a day of data can be lost; enable PITR if that's too much. Restores still need to be tested (see "Backup and restore process is tested").`,
  };
}

// ---------------------------------------------------------------------------
// Supabase Security Advisor
// ---------------------------------------------------------------------------

export type Lint = {
  name?: string;
  title?: string;
  level?: string;
  categories?: string[];
  detail?: string;
  remediation?: string;
  metadata?: { schema?: string; name?: string };
};

export function checkSecurityAdvisor(res: { ok: boolean; lints?: Lint[]; error?: string } | null): ExtraResult {
  if (!res) return { status: "inconclusive", notes: NEED_PAT };
  if (!res.ok || !res.lints)
    return { status: "inconclusive", notes: `Could not run Supabase's Security Advisor: ${res.error ?? "unknown error"}.` };
  const security = res.lints.filter((l) => !l.categories || l.categories.some((c) => c.toUpperCase() === "SECURITY"));
  const serious = security.filter((l) => ["ERROR", "WARN", "WARNING"].includes((l.level ?? "").toUpperCase()));
  const fmt = (l: Lint) =>
    `- [${(l.level ?? "?").toUpperCase()}] ${l.title ?? l.name}${l.metadata?.name ? ` (${l.metadata.schema ? `${l.metadata.schema}.` : ""}${l.metadata.name})` : ""}${l.detail ? `: ${l.detail}` : ""}${l.remediation ? `\n  Fix: ${l.remediation}` : ""}`;
  if (serious.length === 0)
    return {
      status: "pass",
      notes: `Supabase's Security Advisor reports no errors or warnings.${security.length ? `\n\nInformational:\n${security.slice(0, 20).map(fmt).join("\n")}` : ""}`,
    };
  const order = (l: Lint) => ((l.level ?? "").toUpperCase() === "ERROR" ? 0 : 1);
  const sorted = [...serious].sort((a, b) => order(a) - order(b));
  return {
    status: "fail",
    notes: `Supabase's Security Advisor reports ${serious.length} issue(s):\n${sorted.slice(0, 40).map(fmt).join("\n")}${sorted.length > 40 ? `\n- …and ${sorted.length - 40} more` : ""}`,
  };
}

// ---------------------------------------------------------------------------
// Sensitive columns
// ---------------------------------------------------------------------------

export const SENSITIVE_COLUMN_SQL = `
  select c.table_name as "table", c.column_name as "column", c.data_type as "type"
  from information_schema.columns c
  join information_schema.tables t
    on t.table_schema = c.table_schema and t.table_name = c.table_name and t.table_type = 'BASE TABLE'
  where c.table_schema = 'public'
    and c.column_name ~* '(ssn|social_security|tax_id|national_id|passport|driver_?licen|card_?number|cc_?num|cvv|cvc|iban|account_?number|routing_?number|bank_?account|password|passwd|pwd|secret|api_?key|access_?token|refresh_?token|private_?key|dob|date_of_birth|diagnos|medical)'
  order by 1, 2
  limit 200;`;

export type ColumnRow = { table: string; column: string; type: string };

const PROTECTED_SUFFIX = /(_hash|_hashed|_digest|_enc|_encrypted|_cipher|_ciphertext|_hint|_last4|_last_four|_masked|_id|_ref|_vault_id|_set|_at|_updated|_changed|_required|_expires?)$/i;
const PLAINTEXT_TYPES = /^(text|character varying|character|json|jsonb)$/i;

export function checkSensitiveColumns(res: { ok: boolean; rows?: ColumnRow[]; error?: string } | null): ExtraResult {
  if (!res) return { status: "inconclusive", notes: NEED_PAT };
  if (!res.ok || !res.rows) return { status: "inconclusive", notes: `Could not list columns: ${res.error ?? "unknown error"}.` };
  const candidates = res.rows.filter((r) => !PROTECTED_SUFFIX.test(r.column) && PLAINTEXT_TYPES.test(r.type));
  const plainPasswords = candidates.filter((r) => /^(password|passwd|pwd|user_password)$/i.test(r.column));
  if (candidates.length === 0)
    return {
      status: "pass",
      notes: `No plain-text columns in the public schema have names suggesting secrets, card, ID or health data.${res.rows.length ? ` (${res.rows.length} matching name(s) are hashed, encrypted or reference columns.)` : ""}`,
    };
  const listing = candidates.slice(0, 40).map((r) => `- ${r.table}.${r.column} (${r.type})`).join("\n");
  if (plainPasswords.length)
    return {
      status: "fail",
      notes: `A password column is stored as plain text in a public table:\n${plainPasswords.map((r) => `- ${r.table}.${r.column}`).join("\n")}\n\nNever store passwords yourself; use Supabase Auth, or at minimum a slow hash (bcrypt/argon2).\n\nOther columns to check:\n${listing}`,
    };
  return {
    status: "inconclusive",
    notes: `These columns hold data that sounds sensitive and are stored as plain text. Confirm each is encrypted (Supabase Vault / pgsodium, or app-side encryption), tokenised by the provider, or not actually sensitive:\n${listing}${candidates.length > 40 ? `\n- …and ${candidates.length - 40} more` : ""}`,
  };
}
