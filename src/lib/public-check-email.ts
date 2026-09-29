// Email bodies for the public /check report and the owner's lead alert.
// No imports beyond types, so tests can load it directly.
//
// Everything that comes from the scanned site (hostnames, script URLs) is
// attacker-influenced, so it is HTML-escaped and never turned into a link.
import type { SecretFinding, Severity } from "./bundle-secrets";
import type { PublicCheckSummary } from "./public-check-core";

export type OutgoingEmail = { to: string; subject: string; html: string; text: string };

export function escapeHtml(s: string): string {
  return s.replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!,
  );
}

const SEV_COLOR: Record<Severity, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#64748b",
};

function headline(s: PublicCheckSummary): string {
  const serious = s.counts.critical + s.counts.high + s.counts.medium;
  if (serious > 0)
    return `${serious} exposed secret${serious === 1 ? "" : "s"} found on ${s.hostname}`;
  return s.complete
    ? `No exposed secret keys found on ${s.hostname}`
    : `No keys found in what we could scan on ${s.hostname}`;
}

export function buildReportEmail(input: {
  to: string;
  summary: PublicCheckSummary;
  findings: SecretFinding[];
  coverageNote: string;
  bookingUrl?: string | null;
}): OutgoingEmail {
  const { summary: s, findings } = input;
  const title = headline(s);
  const rows = findings
    .map(
      (f) => `<tr><td style="padding:12px 0;border-top:1px solid #e5e7eb">
  <div><span style="display:inline-block;padding:2px 8px;border-radius:999px;background:${SEV_COLOR[f.severity]};color:#fff;font-size:12px;font-weight:600;text-transform:capitalize">${f.severity}</span>
  <strong style="margin-left:6px">${escapeHtml(f.label)}</strong></div>
  <div style="font-family:Menlo,Consolas,monospace;font-size:12px;background:#f3f4f6;padding:4px 6px;border-radius:4px;margin:6px 0;word-break:break-all">${escapeHtml(f.masked)}</div>
  <div style="font-size:12px;color:#6b7280;word-break:break-all">Found in: ${f.urls.map(escapeHtml).join(", ")}</div>
  <div style="font-size:14px;margin-top:6px">${escapeHtml(f.advice)}</div>
</td></tr>`,
    )
    .join("");
  const cta = input.bookingUrl
    ? `<p style="margin:24px 0"><a href="${escapeHtml(input.bookingUrl)}" style="background:#0f172a;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none;font-weight:600">Book a SHIELD audit</a></p>`
    : "";
  const html = `<!doctype html><html><body style="margin:0;background:#f8fafc;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#0f172a">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:24px">
<tr><td>
<p style="font-size:12px;color:#64748b;margin:0 0 8px">SafeShip · API key check</p>
<h1 style="font-size:20px;margin:0 0 8px">${escapeHtml(title)}</h1>
<p style="font-size:14px;color:#475569;margin:0 0 12px">We scanned the page and ${s.filesScanned} of ${s.filesFound} JavaScript file${s.filesFound === 1 ? "" : "s"} it serves to every visitor.${s.complete ? "" : " Some files couldn't be scanned, so this isn't a clean bill of health."}</p>
</td></tr>
${rows ? `<tr><td><table role="presentation" width="100%" cellpadding="0" cellspacing="0">${rows}</table></td></tr>` : ""}
<tr><td style="padding-top:16px;font-size:14px;color:#334155">
<p>Keys in the browser are only one way AI-built apps leak data. Missing Row Level Security, open storage buckets and unprotected server functions don't show up in a public scan. A SafeShip SHIELD audit reviews your code, database policies and deployment and gives you a prioritised fix list.</p>
${cta}
<p style="font-size:12px;color:#94a3b8">Keys are masked in this report and were never stored in full. You received this because someone requested a check of ${escapeHtml(s.hostname)} and entered this address.</p>
</td></tr></table></td></tr></table></body></html>`;
  const text = [
    title,
    "",
    `Scanned the page and ${s.filesScanned} of ${s.filesFound} JavaScript files.${s.complete ? "" : " Some files couldn't be scanned."}`,
    "",
    ...findings.flatMap((f) => [
      `[${f.severity}] ${f.label}: ${f.masked}`,
      `  Found in: ${f.urls.join(", ")}`,
      `  ${f.advice}`,
      "",
    ]),
    "What was scanned:",
    input.coverageNote,
    "",
    input.bookingUrl ? `Book a SHIELD audit: ${input.bookingUrl}` : "",
    `You received this because someone requested a check of ${s.hostname} and entered this address.`,
  ].join("\n");
  return { to: input.to, subject: title, html, text };
}

export function buildOwnerAlert(input: {
  to: string;
  leadEmail: string;
  summary: PublicCheckSummary;
  findings: SecretFinding[];
  url: string;
  marketingConsent: boolean;
}): OutgoingEmail {
  const { summary: s } = input;
  const c = s.counts;
  const tag = c.critical ? "critical" : c.high ? "high" : c.medium ? "medium" : "clean";
  const subject = `[${tag}] New /check lead: ${s.hostname}`;
  const lines = [
    `Site: ${input.url}`,
    `Email: ${input.leadEmail}${input.marketingConsent ? " (OK to send tips)" : ""}`,
    `Found: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low`,
    `Coverage: ${s.filesScanned} of ${s.filesFound} JS files${s.complete ? "" : " (incomplete)"}`,
    "",
    ...input.findings.map((f) => `- [${f.severity}] ${f.label} ${f.masked}`),
  ];
  const text = lines.join("\n");
  const html = `<pre style="font-family:Menlo,Consolas,monospace;font-size:13px">${escapeHtml(text)}</pre>`;
  return { to: input.to, subject, html, text };
}
