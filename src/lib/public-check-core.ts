// Core of the public "Is your app leaking keys?" check. Kept free of the
// TanStack runtime so tests can run it with an in-memory database.
//
// What a visitor can learn from this tool is limited on purpose:
// - Only public, internet-facing pages are fetched (SSRF guard, fail closed).
// - Before an email is given: counts by severity and the kind of key only.
// - After: the masked key, where it was found, and how to fix it. The full
//   secret value is never stored or returned, so the tool can't be used to
//   harvest working keys from other people's sites.

import { collectBundles } from "./bundle-collect";
import {
  countBySeverity,
  scanForSecrets,
  type SecretFinding,
  type Severity,
} from "./bundle-secrets";
import { assertSafeOutboundUrl, SSRFBlockedError, safeFetch } from "./ssrf-guard";
import { buildOwnerAlert, buildReportEmail, type OutgoingEmail } from "./public-check-email";
import type { CrmNotifier } from "./crm-intake";

export const PUBLIC_CHECK_UA =
  "AuditKit-PublicCheck/1.0 (security check requested by a site visitor)";

export type PublicCheckSummary = {
  hostname: string;
  counts: Record<Severity, number>;
  total: number;
  filesScanned: number;
  filesFound: number;
  complete: boolean;
  checkedAt: string;
};

export type PublicCheckTeaser = { label: string; severity: Severity }[];

export type StartResult =
  | { ok: true; id: string; summary: PublicCheckSummary; teaser: PublicCheckTeaser }
  | { ok: false; error: string };

export type ReportResult =
  | {
      ok: true;
      emailed?: false;
      summary: PublicCheckSummary;
      findings: SecretFinding[];
      coverageNote: string;
    }
  | { ok: true; emailed: true }
  | { ok: false; error: string };

/** Optional email delivery. When present, the full report is only emailed. */
export type ReportMailer = {
  send: (msg: OutgoingEmail) => Promise<{ ok: true } | { ok: false; error: string }>;
  ownerEmail?: string | null;
  bookingUrl?: string | null;
};

// Minimal surface of the Supabase client we use, so tests can pass a fake.
type Db = {
  rpc: (fn: string, args: Record<string, unknown>) => PromiseLike<{ data: any; error: any }>;
  from: (table: string) => any;
};

const LIMIT_MESSAGES: Record<string, string> = {
  ip_limit: "You've run several checks recently. Please try again in an hour.",
  host_limit: "This site has been checked many times today. Please try again tomorrow.",
  global_limit: "The free checker is at capacity for today. Please try again tomorrow.",
  invalid: "That URL couldn't be checked.",
};

export function normalizePublicUrl(raw: string): URL | null {
  const trimmed = String(raw ?? "").trim();
  if (!trimmed || trimmed.length > 2048) return null;
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let u: URL;
  try {
    u = new URL(withScheme);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  if (!u.hostname.includes(".")) return null;
  if (u.username || u.password) return null;
  u.hash = "";
  return u;
}

export async function runPublicCheck(
  rawUrl: string,
  deps: { db: Db; ipHash: string },
): Promise<StartResult> {
  const url = normalizePublicUrl(rawUrl);
  if (!url) return { ok: false, error: "Enter a full website address, like https://yourapp.com." };
  try {
    await assertSafeOutboundUrl(url.toString());
  } catch (e) {
    if (e instanceof SSRFBlockedError)
      return {
        ok: false,
        error: /no public A\/AAAA records/.test(e.message)
          ? `We couldn't find ${url.hostname}. Check the address is spelled right and the site is live.`
          : "We can only check public websites.",
      };
    throw e;
  }

  const { data: slot, error: slotErr } = await deps.db.rpc("begin_public_check", {
    p_ip_hash: deps.ipHash,
    p_url: url.toString(),
    p_hostname: url.hostname,
  });
  if (slotErr || !slot)
    return { ok: false, error: "The checker is unavailable right now. Please try again shortly." };
  if (!slot.allowed)
    return { ok: false, error: LIMIT_MESSAGES[slot.reason] ?? LIMIT_MESSAGES.invalid };
  const id = String(slot.id);

  const fail = async (message: string): Promise<StartResult> => {
    await deps.db
      .from("public_checks")
      .update({ status: "failed", error: message.slice(0, 500) })
      .eq("id", id);
    return { ok: false, error: message };
  };

  let html: string;
  const base = url.toString().replace(/\/+$/, "");
  try {
    const res = await safeFetch(
      url.toString(),
      { headers: { "user-agent": PUBLIC_CHECK_UA, accept: "text/html" } },
      { timeoutMs: 10_000, maxBodyBytes: 2_000_000 },
    );
    if (!res.ok) {
      await res.body?.cancel().catch(() => {});
      return await fail(
        `${url.hostname} returned HTTP ${res.status}, so there was nothing to check.`,
      );
    }
    html = await res.text();
  } catch (e: any) {
    const msg =
      e instanceof SSRFBlockedError
        ? "We can only check public websites."
        : `Couldn't load ${url.hostname}: ${e?.message ?? "request failed"}`;
    return await fail(msg);
  }

  const { sources, coverage } = await collectBundles(base, html, {
    maxBundles: 30,
    timeoutMs: 8_000,
    maxBytesPerFile: 8_000_000,
    userAgent: PUBLIC_CHECK_UA,
    totalBudgetMs: 40_000,
  });
  const findings = scanForSecrets(sources);
  const counts = countBySeverity(findings);
  const summary: PublicCheckSummary = {
    hostname: url.hostname,
    counts,
    total: findings.length,
    filesScanned: coverage.fetched,
    filesFound: coverage.discovered,
    complete: coverage.complete,
    checkedAt: new Date().toISOString(),
  };

  await deps.db
    .from("public_checks")
    .update({ status: "done", summary: { ...summary, coverageNote: coverage.summary }, findings })
    .eq("id", id);

  return {
    ok: true,
    id,
    summary,
    teaser: findings.map((f) => ({ label: f.label, severity: f.severity })),
  };
}

const EMAIL_RE =
  /^[^\s@<>()[\]\\,;:"]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isValidEmail(email: string): boolean {
  return typeof email === "string" && email.length <= 254 && EMAIL_RE.test(email.trim());
}

export async function unlockPublicReport(
  input: { id: string; email: string; marketingConsent?: boolean },
  deps: { db: Db; mailer?: ReportMailer | null; crm?: CrmNotifier | null },
): Promise<ReportResult> {
  if (!UUID_RE.test(String(input.id ?? "")))
    return { ok: false, error: "That report link isn't valid." };
  if (!isValidEmail(input.email)) return { ok: false, error: "Enter a valid email address." };

  const { data: row, error } = await deps.db
    .from("public_checks")
    .select("id, url, status, summary, findings, email, report_sent_at")
    .eq("id", input.id)
    .maybeSingle();
  if (error || !row || row.status !== "done")
    return { ok: false, error: "That report isn't available." };

  const email = input.email.trim().toLowerCase();
  const consent = input.marketingConsent === true;
  const { coverageNote = "", ...summaryRest } = (row.summary ?? {}) as PublicCheckSummary & {
    coverageNote?: string;
  };
  const summary = summaryRest as PublicCheckSummary;
  const findings = (row.findings ?? []) as SecretFinding[];

  if (!row.email) {
    await deps.db
      .from("public_checks")
      .update({ email, email_captured_at: new Date().toISOString(), marketing_consent: consent })
      .eq("id", input.id);

    // First capture only, so a re-submit can't push a second address into the
    // CRM. A CRM outage never blocks the visitor's report.
    if (deps.crm) {
      const c = summary.counts ?? { critical: 0, high: 0, medium: 0, low: 0 };
      const hostname = String(summary.hostname ?? "").slice(0, 200);
      const crm = await deps.crm.send({
        name: email,
        email,
        external_id: input.id,
        marketing_consent: consent,
        notes: `Checked ${hostname}: ${summary.total ?? 0} exposed key(s) (${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low)`,
        metadata: {
          hostname,
          url: String(row.url ?? "").slice(0, 500),
          total: summary.total ?? 0,
          critical: c.critical,
          high: c.high,
          medium: c.medium,
          low: c.low,
          complete: summary.complete === true,
        },
      });
      if (!crm.ok) console.error("[public-check] Connect Hub intake failed", crm.error);
    }
  }

  const mailer = deps.mailer;
  if (!mailer) {
    // No email delivery configured (local development): show it on the page.
    return { ok: true, summary, findings, coverageNote };
  }

  // One report email per check, to the first address given, so the form
  // can't be used to send repeated mail to someone.
  if (row.report_sent_at) return { ok: true, emailed: true };
  const to = row.email ?? email;
  const sent = await mailer.send(
    buildReportEmail({ to, summary, findings, coverageNote, bookingUrl: mailer.bookingUrl }),
  );
  if (!sent.ok) {
    console.error("[public-check] report email failed", sent.error);
    return {
      ok: false,
      error: "We couldn't send the report email. Please check the address and try again.",
    };
  }
  await deps.db
    .from("public_checks")
    .update({ report_sent_at: new Date().toISOString() })
    .eq("id", input.id);

  if (mailer.ownerEmail) {
    const alert = await mailer.send(
      buildOwnerAlert({
        to: mailer.ownerEmail,
        leadEmail: to,
        summary,
        findings,
        url: String(row.url ?? ""),
        marketingConsent: consent,
      }),
    );
    if (alert.ok)
      await deps.db
        .from("public_checks")
        .update({ owner_notified_at: new Date().toISOString() })
        .eq("id", input.id);
    else console.error("[public-check] owner alert failed", alert.error);
  }
  return { ok: true, emailed: true };
}
