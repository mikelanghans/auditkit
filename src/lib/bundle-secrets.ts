// Detect credentials in client-side code (HTML and JS bundles served to every
// visitor). Shared by the audit website scan and the public /check page.
// There are no imports, so tests can load this module directly.
//
// Principles:
// - Keys that are public by design (Supabase anon/publishable keys, Stripe
//   publishable keys) are not findings. Flagging them would put a false
//   critical in every Supabase app's report.
// - A matched secret value is never returned in full. Callers only ever see
//   `masked`, which keeps enough of the prefix to identify the key type.

export type Severity = "critical" | "high" | "medium" | "low";

export type SecretFinding = {
  ruleId: string;
  label: string;
  severity: Severity;
  /** Prefix + suffix only, e.g. "sk_live_51H…9x". Never the full value. */
  masked: string;
  /** Where it was seen (first few URLs). */
  urls: string[];
  occurrences: number;
  advice: string;
};

type Rule = {
  id: string;
  label: string;
  severity: Severity;
  re: RegExp;
  advice: string;
  /** Return false to drop a match (e.g. a public-by-design key). */
  accept?: (match: string) => boolean;
  /** Override severity/label from the matched value. */
  classify?: (match: string) => { severity: Severity; label: string } | null;
};

function b64urlDecode(s: string): string | null {
  try {
    const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
    const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
    if (typeof atob === "function") return atob(b64);
    return null;
  } catch {
    return null;
  }
}

/** Read a JWT payload without verifying it. Returns null if it isn't JSON. */
export function jwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const json = b64urlDecode(parts[1]);
  if (!json) return null;
  try {
    const v = JSON.parse(json);
    return v && typeof v === "object" ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

const ROTATE = "Rotate this key now, then move the call that needs it to server-side code.";

const RULES: Rule[] = [
  {
    id: "supabase_service_role_jwt",
    label: "Supabase service_role key",
    severity: "critical",
    // Classified from the JWT payload below; anon keys are dropped.
    re: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g,
    advice:
      "This key bypasses Row Level Security: anyone can read and change every table. Rotate it in Supabase (Settings → API) and only use it in server code.",
    classify: (m) => {
      const p = jwtPayload(m);
      if (!p) return null;
      const role = String(p.role ?? "");
      const iss = String(p.iss ?? "");
      if (role === "anon" || role === "authenticated") return null; // public by design / a user session
      if (role === "service_role")
        return { severity: "critical", label: "Supabase service_role key" };
      if (iss.includes("supabase"))
        return { severity: "medium", label: `Supabase JWT (role: ${role || "unknown"})` };
      // A signed token for some other system. Could be a harmless demo token.
      return { severity: "low", label: "Hard-coded JWT" };
    },
  },
  {
    id: "supabase_secret_key",
    label: "Supabase secret key",
    severity: "critical",
    re: /\bsb_secret_[A-Za-z0-9_-]{20,}/g,
    advice:
      "Supabase secret keys bypass Row Level Security. Revoke it in Supabase (Settings → API Keys) and use it only on the server.",
  },
  {
    id: "stripe_live_secret",
    label: "Stripe live secret key",
    severity: "critical",
    re: /\bsk_live_[A-Za-z0-9]{16,}/g,
    advice:
      "Anyone can charge, refund and read customers with this key. Roll it in the Stripe dashboard. " +
      ROTATE,
  },
  {
    id: "stripe_restricted_live",
    label: "Stripe restricted live key",
    severity: "high",
    re: /\brk_live_[A-Za-z0-9]{16,}/g,
    advice:
      "Restricted keys still carry real permissions. Roll it in the Stripe dashboard. " + ROTATE,
  },
  {
    id: "stripe_test_secret",
    label: "Stripe test secret key",
    severity: "medium",
    re: /\b[sr]k_test_[A-Za-z0-9]{16,}/g,
    advice:
      "Test keys can't move real money, but shipping any secret key to browsers means the live one may follow. " +
      ROTATE,
  },
  {
    id: "stripe_webhook_secret",
    label: "Stripe webhook signing secret",
    severity: "high",
    re: /\bwhsec_[A-Za-z0-9]{24,}/g,
    advice:
      "With this, anyone can forge Stripe webhook events to your app. Roll the endpoint secret in Stripe.",
  },
  {
    id: "openai_key",
    label: "OpenAI API key",
    severity: "critical",
    re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/g,
    advice:
      "Anyone can run up your OpenAI bill with this key. Revoke it at platform.openai.com. " +
      ROTATE,
    accept: (m) => !m.startsWith("sk-ant-"),
  },
  {
    id: "anthropic_key",
    label: "Anthropic API key",
    severity: "critical",
    re: /\bsk-ant-[A-Za-z0-9_-]{32,}/g,
    advice:
      "Anyone can run up your Anthropic bill with this key. Revoke it in the Claude Console. " +
      ROTATE,
  },
  {
    id: "github_token",
    label: "GitHub token",
    severity: "critical",
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})/g,
    advice: "This token can act on GitHub as its owner. Revoke it in GitHub settings.",
  },
  {
    id: "aws_access_key",
    label: "AWS access key ID",
    severity: "high",
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    advice:
      "An AWS key ID in client code usually means the secret key is nearby. Deactivate the key in IAM and check CloudTrail.",
  },
  {
    id: "private_key",
    label: "Private key (PEM)",
    severity: "critical",
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/g,
    advice:
      "A private key is served to every visitor. Replace the key pair and revoke anything it signed.",
  },
  {
    id: "db_connection_string",
    label: "Database connection string with password",
    severity: "critical",
    re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss):\/\/[^\s:"'`@/]+:[^\s"'`@/]{4,}@[^\s"'`/]+/g,
    advice:
      "Direct database credentials are public. Change the database password and restrict network access.",
  },
  {
    id: "slack_token",
    label: "Slack token",
    severity: "high",
    re: /\bxox[abprs]-[A-Za-z0-9-]{20,}/g,
    advice: "Revoke the token in your Slack app settings.",
  },
  {
    id: "slack_webhook",
    label: "Slack incoming webhook URL",
    severity: "medium",
    re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{20,}/g,
    advice: "Anyone can post into your Slack channel. Regenerate the webhook.",
  },
  {
    id: "sendgrid_key",
    label: "SendGrid API key",
    severity: "high",
    re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g,
    advice: "Anyone can send email as you. Delete the key in SendGrid.",
  },
  {
    id: "resend_key",
    label: "Resend API key",
    severity: "high",
    re: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/g,
    advice: "Anyone can send email as you. Delete the key in Resend.",
  },
  {
    id: "twilio_key",
    label: "Twilio API key",
    severity: "high",
    re: /\bSK[0-9a-f]{32}\b/g,
    advice: "Revoke the key in the Twilio console.",
  },
  {
    id: "mailgun_key",
    label: "Mailgun API key",
    severity: "high",
    re: /\bkey-[0-9a-f]{32}\b/g,
    advice: "Rotate the key in Mailgun.",
  },
  {
    id: "google_api_key",
    label: "Google API key",
    severity: "low",
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    advice:
      "Google keys for Maps and Firebase are often meant to be public. Check that this one is restricted to your domains and to the APIs you use.",
  },
];

/** Keep enough to identify the key type, never enough to use it. */
export function maskSecret(value: string): string {
  const v = value.trim();
  if (v.startsWith("-----BEGIN")) return v.replace(/-----$/, "") + "…";
  if (v.includes("://") && v.includes("@")) {
    return v.replace(/(:\/\/[^:]+:)[^@]+(@)/, "$1••••$2").slice(0, 60);
  }
  const prefixMatch =
    /^(sb_secret_|sk_live_|rk_live_|sk_test_|rk_test_|whsec_|sk-ant-|sk-proj-|sk-svcacct-|sk-admin-|sk-|gh[pousr]_|github_pat_|xox[abprs]-|SG\.|re_|key-|AIza|AKIA|ASIA|SK|eyJ)/.exec(
      v,
    );
  const keep = Math.min(prefixMatch ? prefixMatch[1].length + 4 : 4, Math.floor(v.length / 3));
  return `${v.slice(0, keep)}…${v.slice(-2)}`;
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function scanForSecrets(sources: { url: string; body: string }[]): SecretFinding[] {
  const byValue = new Map<string, SecretFinding>();
  for (const { url, body } of sources) {
    for (const rule of RULES) {
      rule.re.lastIndex = 0;
      const matches = body.match(rule.re);
      if (!matches) continue;
      for (const m of matches) {
        if (rule.accept && !rule.accept(m)) continue;
        let severity = rule.severity;
        let label = rule.label;
        if (rule.classify) {
          const c = rule.classify(m);
          if (!c) continue;
          severity = c.severity;
          label = c.label;
        }
        const key = `${rule.id}:${m}`;
        const existing = byValue.get(key);
        if (existing) {
          existing.occurrences++;
          if (!existing.urls.includes(url) && existing.urls.length < 5) existing.urls.push(url);
          continue;
        }
        byValue.set(key, {
          ruleId: rule.id,
          label,
          severity,
          masked: maskSecret(m),
          urls: [url],
          occurrences: 1,
          advice: rule.advice,
        });
      }
    }
  }
  return Array.from(byValue.values()).sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
}

export function countBySeverity(findings: SecretFinding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}
