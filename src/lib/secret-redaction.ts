/**
 * Redaction applied to client source code before it leaves our infrastructure.
 *
 * AuditKit reads private client repositories and sends selected files to the
 * Anthropic API for review. Those files can contain live credentials — a
 * committed `.env` is one of the things the repo scan explicitly flags as a
 * critical finding. Forwarding that file verbatim to a third party would mean
 * the security tool is itself exfiltrating the secret it just discovered.
 *
 * The goal is to preserve everything the model needs to reason about
 * (which variables exist, which SDKs are configured, where a key is referenced)
 * while removing the secret values themselves. Redaction is deliberately
 * lossy and deliberately eager: a false positive costs a little review quality,
 * a false negative leaks a client credential.
 */

/** Matches `.env`, `.env.local`, `.env.production`, `.env.example`, etc. */
export function isEnvFile(path: string): boolean {
  return /(^|\/)\.env(\.[\w.-]+)?$/i.test(path.toLowerCase());
}

/**
 * Value-bearing secret patterns. Each replaces only the *value* portion where
 * the pattern allows, so the surrounding variable name stays readable.
 */
const SECRET_VALUE_PATTERNS: { name: string; re: RegExp; replace: (m: string) => string }[] = [
  // Provider-prefixed tokens — the prefix is the useful signal, not the body.
  { name: "stripe-live", re: /\bsk_live_[A-Za-z0-9]{16,}\b/g, replace: () => "sk_live_[REDACTED]" },
  { name: "stripe-test", re: /\bsk_test_[A-Za-z0-9]{16,}\b/g, replace: () => "sk_test_[REDACTED]" },
  { name: "stripe-restricted", re: /\brk_(?:live|test)_[A-Za-z0-9]{16,}\b/g, replace: (m) => m.slice(0, 8) + "[REDACTED]" },
  { name: "webhook-secret", re: /\bwhsec_[A-Za-z0-9+/=_-]{16,}/g, replace: () => "whsec_[REDACTED]" },
  // Supabase's newer non-JWT secret API keys.
  { name: "supabase-secret", re: /\bsb_secret_[A-Za-z0-9_-]{16,}/g, replace: () => "sb_secret_[REDACTED]" },
  { name: "resend", re: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}\b/g, replace: () => "re_[REDACTED]" },
  { name: "twilio-api-key", re: /\bSK[0-9a-f]{32}\b/g, replace: () => "SK[REDACTED]" },
  { name: "anthropic", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, replace: () => "sk-ant-[REDACTED]" },
  { name: "openai", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g, replace: () => "sk-[REDACTED]" },
  { name: "github-pat", re: /\b(gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}\b/g, replace: (m) => m.slice(0, 4) + "[REDACTED]" },
  { name: "aws-access-key-id", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, replace: () => "AKIA[REDACTED]" },
  { name: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, replace: () => "AIza[REDACTED]" },
  { name: "slack-token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g, replace: () => "xox?-[REDACTED]" },
  { name: "sendgrid", re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g, replace: () => "SG.[REDACTED]" },
  // JWTs — covers Supabase anon/service_role keys, which are JWTs.
  {
    name: "jwt",
    re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    replace: () => "eyJ[REDACTED_JWT]",
  },
  // Passwords embedded in connection strings: postgres://user:PASSWORD@host
  {
    name: "url-credentials",
    re: /\b([a-z][a-z0-9+.-]*:\/\/[^\s:@/'"`]+):([^\s@/'"`]+)@/gi,
    replace: (m) => m.replace(/:([^:@]+)@$/, ":[REDACTED]@"),
  },
  // Literal Authorization header values.
  {
    name: "auth-header-value",
    re: /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]{16,}=*/g,
    replace: (m) => `${m.split(/\s+/)[0]} [REDACTED]`,
  },
  // Private key blocks (any label, including ENCRYPTED PRIVATE KEY) — replace
  // the whole body, keep the header for context.
  {
    name: "pem",
    re: /-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----[\s\S]*?-----END \1-----/g,
    replace: (m) => {
      const header = m.match(/-----BEGIN ([^-]+)-----/)?.[1] ?? "PRIVATE KEY";
      return `-----BEGIN ${header}-----\n[REDACTED]\n-----END ${header}-----`;
    },
  },
];

/**
 * Variable names whose assigned value should always be stripped, regardless of
 * whether the value itself looks like a known token format. Matched as a
 * substring against the name, so SUPABASE_SERVICE_ROLE_KEY hits on "service_role".
 */
const SENSITIVE_NAME_HINTS = [
  "secret",
  "password",
  "passwd",
  "token",
  "api_key",
  "apikey",
  "private_key",
  "privatekey",
  "service_role",
  "credential",
  "auth",
  "signing",
  "session_key",
  "encryption",
  "dsn",
  "database_url",
  "db_url",
  "connection_string",
  "access_key",
  "webhook",
];

function nameLooksSensitive(name: string): boolean {
  // Normalise camelCase, kebab-case and dotted names so serviceRoleKey,
  // x-api-key and stripe.secretKey match the same hints as SNAKE_CASE.
  const n = name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_");
  if (SENSITIVE_NAME_HINTS.some((h) => n.includes(h))) return true;
  // Bare "*_KEY" but not obviously-public things like PUBLISHABLE_KEY / ANON_KEY.
  if (/(^|_)key$/.test(n) && !/(publishable|public|anon)/.test(n)) return true;
  return false;
}

function placeholder(value: string): string {
  const len = value.trim().replace(/^['"`]|['"`]$/g, "").length;
  return `[REDACTED — ${len} chars]`;
}

/**
 * Redact a `.env`-style file down to its variable names.
 *
 * Keeps comments, blank lines, ordering and every key, because "this repo
 * commits a file defining SUPABASE_SERVICE_ROLE_KEY" is the finding. Drops
 * every value, because that is the part with blast radius. That includes:
 *  - commented-out assignments (`# STRIPE_SECRET_KEY=sk_live_…` — an old key
 *    kept "for rollback" is usually still live),
 *  - every line of a multi-line quoted value (e.g. a PEM private key),
 *  - any line we can't parse, which is replaced rather than passed through.
 * Known token shapes are then stripped from the whole result as a backstop.
 */
export function redactEnvFile(content: string): string {
  const lines = content.split(/\r?\n/);
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed) {
      out.push(line);
      continue;
    }
    const m = line.match(/^(\s*(?:#\s*)?(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.-]*)(\s*=\s*)(.*)$/);
    if (!m) {
      // Free-text comments are kept (token shapes are still stripped below).
      // Anything else unparseable is replaced, not passed through.
      out.push(trimmed.startsWith("#") ? line : "[REDACTED — unparsed line]");
      continue;
    }
    const [, indent, name, eq, value] = m;
    const v = value.trim();
    if (!v) {
      out.push(line);
      continue;
    }
    // A quoted value that doesn't close on this line continues onto the next ones.
    const q = v[0];
    if ((q === '"' || q === "'" || q === "`") && !v.slice(1).includes(q)) {
      let continuation = 0;
      while (i + 1 < lines.length) {
        i++;
        continuation++;
        if (lines[i].includes(q)) break;
      }
      out.push(`${indent}${name}${eq}[REDACTED — multi-line value, ${continuation + 1} lines]`);
      continue;
    }
    out.push(`${indent}${name}${eq}${placeholder(value)}`);
  }
  return applyValuePatterns(out.join("\n"));
}

function applyValuePatterns(text: string): string {
  let out = text;
  for (const p of SECRET_VALUE_PATTERNS) {
    p.re.lastIndex = 0;
    out = out.replace(p.re, (m) => p.replace(m));
  }
  return out;
}

/**
 * Redact secrets from an ordinary source file.
 *
 * Two passes: known token shapes anywhere in the text, then assignments whose
 * *variable name* implies a secret even if the value shape is unrecognised
 * (`const STRIPE_SECRET = "whatever"`).
 */
export function redactSourceFile(content: string): string {
  let out = applyValuePatterns(content);

  // Quoted assignments to sensitive-looking names, with the name itself
  // optionally quoted (object keys and header maps):
  //   KEY: "…"   KEY = '…'   "x-api-key": "…"   'Authorization': `…`
  out = out.replace(
    /(['"]?)([A-Za-z_][A-Za-z0-9_.-]*)\1(\s*[:=]\s*)(['"`])([^'"`\n]{8,})\4/g,
    (full, nq: string, name: string, sep: string, quote: string, value: string) => {
      if (!nameLooksSensitive(name)) return full;
      // Don't redact obvious non-secrets: env lookups, imports, placeholders,
      // or values another pattern already redacted.
      if (/^(process\.env|import\.meta|your[-_]|xxx|todo|changeme|<|\$\{)/i.test(value)) return full;
      if (value.includes("[REDACTED")) return full;
      return `${nq}${name}${nq}${sep}${quote}${placeholder(value)}${quote}`;
    },
  );

  return out;
}

/**
 * Single entry point used before any file content is put into an LLM prompt.
 * Returns the redacted text plus whether anything changed, so callers can tell
 * the operator that redaction occurred.
 */
export function redactForPrompt(path: string, content: string): { content: string; redacted: boolean } {
  const out = isEnvFile(path) ? redactEnvFile(content) : redactSourceFile(content);
  return { content: out, redacted: out !== content };
}
