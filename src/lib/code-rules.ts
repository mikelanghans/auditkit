// Code rules for common mistakes in AI-built apps (build plan 3.5, without
// the runner). Line-level patterns over the repo's current source, chosen to
// be high-signal; anything ambiguous is reported for review, not failed.
// No imports, so tests load it directly; repo-scan.functions.ts fetches files.

export type RuleId = "webhook_signatures" | "service_role_in_source" | "dynamic_code_eval" | "pii_in_logs";
export type RuleHit = { rule: RuleId; file: string; line: number; snippet: string };
export type RuleStatus = "pass" | "fail" | "inconclusive";

const SERVER_PATH = /(^|\/)(server|api|functions|supabase\/functions|netlify\/functions|workers?|backend|scripts)\/|\.server\.[a-z]+$|(^|\/)(route|server|middleware)\.[a-z]+$|^(?!src\/).*\.(mjs|cjs)$/i;
const CLIENT_PATH = /\.(tsx|jsx|vue|svelte|astro)$|(^|\/)(src\/(components|pages|hooks|app|lib|routes)|components|pages|app)\//i;

export function isClientFile(path: string): boolean {
  return CLIENT_PATH.test(path) && !SERVER_PATH.test(path);
}

function lineOf(text: string, index: number): number {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}
function snippetAt(text: string, index: number): string {
  const start = text.lastIndexOf("\n", index) + 1;
  const end = text.indexOf("\n", index);
  return text.slice(start, end < 0 ? undefined : end).trim().slice(0, 160);
}

// ---- webhooks
const STRIPE_EVENT = /\b(checkout\.session\.completed|customer\.subscription\.\w+|invoice\.(paid|payment_succeeded|payment_failed)|payment_intent\.\w+)\b|event\.type\s*===?\s*['"`][a-z_]+\.[a-z_.]+['"`]/;
const WEBHOOK_HINT = /webhook/i;
const READS_BODY = /\b(req|request|c\.req)\.(json|text|body|arrayBuffer|raw)\b|await\s+req\.text\(\)|request\.json\(\)/;
const VERIFIES = /constructEvent(Async)?\s*\(|webhooks\.verify|new\s+Webhook\s*\(|\.verify\(\s*(payload|body|raw|text)|verifySignature|validateSignature|timingSafeEqual|createHmac\s*\(|crypto\.subtle\.(verify|sign)\s*\(|svix|x-hub-signature|stripe-signature/i;

// ---- service role in client code
const SERVICE_ROLE = /SERVICE_ROLE(_KEY)?|service_role|sb_secret_/;

// ---- dynamic code
const EVAL = /\beval\s*\(\s*(?!['"`][^'"`$]*['"`]\s*\))|new\s+Function\s*\(\s*(?!['"`][^'"`$]*['"`]\s*\))/g;

// ---- PII in logs
const LOG_PII = /\bconsole\.(log|info|debug|warn|error)\s*\([^\n;]*\b(password|passwd|ssn|social_?security|card_?number|cvv|cvc|access_?token|refresh_?token|authorization|secret|api_?key|date_?of_?birth|dob)\b/gi;

export function findRuleHits(file: string, text: string): RuleHit[] {
  const hits: RuleHit[] = [];
  const isTest = /(\.test|\.spec)\.[a-z]+$|(^|\/)(__tests__|tests?)\//i.test(file);
  if (isTest) return hits;

  // A file that handles payment/provider events from a request body, with no
  // sign of signature verification anywhere in it.
  const handlesWebhook = (WEBHOOK_HINT.test(file) || WEBHOOK_HINT.test(text)) && READS_BODY.test(text) && (STRIPE_EVENT.test(text) || /webhook/i.test(file));
  if (handlesWebhook && !VERIFIES.test(text)) {
    const m = text.match(READS_BODY);
    const idx = m?.index ?? 0;
    hits.push({ rule: "webhook_signatures", file, line: lineOf(text, idx), snippet: snippetAt(text, idx) });
  }

  if (isClientFile(file)) {
    const m = SERVICE_ROLE.exec(text);
    if (m) hits.push({ rule: "service_role_in_source", file, line: lineOf(text, m.index), snippet: snippetAt(text, m.index) });
  }

  EVAL.lastIndex = 0;
  for (const m of text.matchAll(EVAL)) {
    hits.push({ rule: "dynamic_code_eval", file, line: lineOf(text, m.index ?? 0), snippet: snippetAt(text, m.index ?? 0) });
  }

  LOG_PII.lastIndex = 0;
  for (const m of text.matchAll(LOG_PII)) {
    hits.push({ rule: "pii_in_logs", file, line: lineOf(text, m.index ?? 0), snippet: snippetAt(text, m.index ?? 0) });
  }
  return hits;
}

const ADVICE: Record<RuleId, { found: string; fix: string; clean: string }> = {
  webhook_signatures: {
    found: "Webhook handlers that read the request body without verifying the sender's signature. Anyone who finds the URL can send fake events (\"payment succeeded\", \"subscription active\"):",
    fix: "Verify every webhook before acting on it: Stripe's stripe.webhooks.constructEvent(rawBody, signature, secret), Svix/Clerk/Resend's Webhook.verify, or an HMAC compared with timingSafeEqual. Use the raw body, not parsed JSON.",
    clean: "No webhook handler reads its body without a signature check.",
  },
  service_role_in_source: {
    found: "Client-side files that reference the Supabase service-role key. Anything in client code ships to every visitor's browser, and the service-role key bypasses all row-level security:",
    fix: "Remove the reference, rotate the key, and move the call that needs it into a server function or edge function.",
    clean: "No client-side file references the service-role key.",
  },
  dynamic_code_eval: {
    found: "eval() or new Function() on a non-constant value. If any part of it can come from a user, a URL, the database or an AI response, it runs as code:",
    fix: "Replace with JSON.parse for data, a lookup table for dispatch, or a sandboxed expression parser.",
    clean: "No eval() or new Function() on dynamic values.",
  },
  pii_in_logs: {
    found: "Log statements that mention passwords, tokens, keys or other sensitive fields. Logs are kept, shipped to third parties and read by more people than the database:",
    fix: "Log identifiers, not values: drop the field or redact it before logging.",
    clean: "No log statements mention passwords, tokens, keys or similar fields in the files read.",
  },
};

/** Judge one rule. A clean result is a pass only when every candidate file was read. */
export function judgeRule(
  rule: RuleId,
  hits: RuleHit[],
  coverage: { scanned: number; total: number; failed: number },
): { status: RuleStatus; notes: string } {
  const mine = hits.filter((h) => h.rule === rule);
  const a = ADVICE[rule];
  const cov = `Read ${coverage.scanned} of ${coverage.total} source file(s)${coverage.failed ? `; ${coverage.failed} couldn't be fetched` : ""}.`;
  if (mine.length)
    return {
      status: "fail",
      notes: `${a.found}\n${mine.slice(0, 25).map((h) => `- ${h.file}:${h.line}\n    ${h.snippet}`).join("\n")}${mine.length > 25 ? `\n- …and ${mine.length - 25} more` : ""}\n\n${a.fix}\n\n${cov}`,
    };
  const complete = coverage.scanned >= coverage.total && coverage.failed === 0;
  if (!complete || rule === "pii_in_logs")
    return {
      status: "inconclusive",
      notes: `${a.clean} ${rule === "pii_in_logs" ? "That's not proof: logging also happens in hosting, error trackers and the database. Check those before marking this item." : "Not every file was read, so this is not a pass."} ${cov}`,
    };
  return { status: "pass", notes: `${a.clean} ${cov}` };
}

/** Secret patterns found in the current code (not history). */
export function judgeHeadSecrets(
  hits: { file: string; pattern: string; sample: string }[],
  coverage: { scanned: number; total: number; failed: number },
): { status: RuleStatus; notes: string } {
  const cov = `Read ${coverage.scanned} of ${coverage.total} file(s)${coverage.failed ? `; ${coverage.failed} couldn't be fetched` : ""}.`;
  if (hits.length)
    return {
      status: "fail",
      notes: `Secrets in the repository's current code:\n${hits.slice(0, 30).map((h) => `- ${h.file}: ${h.pattern} (${h.sample})`).join("\n")}\n\nRotate each one, move it to an environment variable or secret store, and remove it from the code. Removing it from the latest commit doesn't remove it from history.\n\n${cov}`,
    };
  if (coverage.scanned < coverage.total || coverage.failed)
    return { status: "inconclusive", notes: `No secrets found in the files read, but not every file was read. ${cov}` };
  return { status: "pass", notes: `No known secret formats in the current code. ${cov}` };
}

/** Files worth a secrets read beyond source code: config and env templates. */
export function secretCandidatePaths(paths: string[], max: number): { pick: string[]; total: number } {
  const all = paths.filter(
    (p) =>
      /\.(json|ya?ml|toml|ini|cfg|conf|properties|xml|sh|py|rb|go|php|env\.[a-z]+|example|sample)$/i.test(p) &&
      !/(^|\/)(node_modules|dist|build|\.next|\.output|vendor|coverage)\//.test(p) &&
      !/(package-lock|npm-shrinkwrap|yarn\.lock|pnpm-lock|bun\.lock|composer\.lock)/i.test(p),
  );
  return { pick: all.slice(0, max), total: all.length };
}
