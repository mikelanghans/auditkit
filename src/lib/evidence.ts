// Evidence attached to scan results (build plan, phase 2a).
//
// Scanners describe what they observed (a response, a set of probes, a query
// result) as EvidenceInput, and point each result at the evidence it rests on.
// saveScanRun stores the evidence with the run, in one insert. Every piece is
// redacted before it is stored and hashed after, so the report can list a
// SHA-256 per item and a later reader can tell if it changed.
//
// Text evidence lives in the database. Files (screenshots, HAR, uploads) go to
// the private "evidence" storage bucket and only their path and hash are here.
import { redactSourceFile } from "./secret-redaction";

export type EvidenceKind =
  | "http_exchange"
  | "probe_set"
  | "query_result"
  | "config"
  | "code"
  | "ai_exchange"
  | "note"
  | "file"
  | "screenshot"
  | "har";

export type EvidenceInput = {
  /** Local name the scanner uses to point results at this item. */
  ref: string;
  kind: EvidenceKind;
  title: string;
  /** Anything JSON-serializable, or plain text. Redacted before storage. */
  content: unknown;
};

export type EvidenceRow = {
  id: string;
  audit_id: string;
  run_id: string | null;
  checklist_item_id: string | null;
  kind: EvidenceKind;
  title: string;
  content_text: string | null;
  storage_path: string | null;
  mime_type: string | null;
  size_bytes: number;
  sha256: string;
  source: "scanner" | "manual";
};

export const MAX_EVIDENCE_TEXT = 64_000;

/** Header names whose values are credentials or session state. */
const SECRET_HEADERS = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|apikey|x-supabase-api-key|x-auth-token)$/i;

/** Headers as a plain object, with credential values masked. */
export function headersForEvidence(h: Headers | Record<string, string> | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!h) return out;
  const entries: [string, string][] = h instanceof Headers ? [...h.entries()] : Object.entries(h);
  for (const [k, v] of entries) {
    const name = k.toLowerCase();
    if (name === "set-cookie") {
      // Keep the cookie name and its attributes (that's what is being judged),
      // drop the value.
      out[name] = String(v)
        .split(/,(?=\s*[A-Za-z0-9_\-.]+=)/)
        .map((c) => c.trim().replace(/^([^=;]+)=([^;]*)/, (_m, n) => `${n}=[REDACTED]`))
        .join(", ");
    } else if (SECRET_HEADERS.test(name)) {
      out[name] = "[REDACTED]";
    } else {
      out[name] = String(v);
    }
  }
  return out;
}

/** One HTTP request/response as evidence. Body excerpt is capped and redacted. */
export function httpExchange(
  req: { method?: string; url: string },
  res: { status?: number | null; headers?: Headers | Record<string, string> | null; body?: string | null; error?: string | null },
  bodyLimit = 2_000,
): Record<string, unknown> {
  return {
    request: { method: req.method ?? "GET", url: req.url },
    response: res.error
      ? { error: res.error }
      : {
          status: res.status ?? null,
          headers: headersForEvidence(res.headers ?? null),
          body_excerpt: res.body ? String(res.body).slice(0, bodyLimit) : null,
          body_truncated: !!res.body && String(res.body).length > bodyLimit,
        },
  };
}

/** Serialize, redact and cap evidence content. */
export function evidenceText(content: unknown): string {
  const raw = typeof content === "string" ? content : JSON.stringify(content, null, 2) ?? "";
  const redacted = redactSourceFile(raw);
  return redacted.length > MAX_EVIDENCE_TEXT
    ? `${redacted.slice(0, MAX_EVIDENCE_TEXT)}\n…[truncated ${redacted.length - MAX_EVIDENCE_TEXT} chars]`
    : redacted;
}

export async function sha256Hex(data: string | ArrayBuffer | Uint8Array): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);
  const digest = await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Build stored rows for a run. Ids are assigned here so results can point at them. */
export async function prepareEvidenceRows(
  auditId: string,
  runId: string,
  inputs: EvidenceInput[],
): Promise<{ rows: Omit<EvidenceRow, "checklist_item_id">[]; idByRef: Map<string, string> }> {
  const idByRef = new Map<string, string>();
  const rows: Omit<EvidenceRow, "checklist_item_id">[] = [];
  for (const e of inputs) {
    if (idByRef.has(e.ref)) continue;
    const text = evidenceText(e.content);
    const id = crypto.randomUUID();
    idByRef.set(e.ref, id);
    rows.push({
      id,
      audit_id: auditId,
      run_id: runId,
      kind: e.kind,
      title: e.title.slice(0, 300),
      content_text: text,
      storage_path: null,
      mime_type: typeof e.content === "string" ? "text/plain" : "application/json",
      size_bytes: new TextEncoder().encode(text).length,
      sha256: await sha256Hex(text),
      source: "scanner",
    });
  }
  return { rows, idByRef };
}

/**
 * A HAR file with credentials removed: request/response headers masked the
 * same way as scanner evidence, cookie values dropped, and request/response
 * bodies run through secret redaction. Throws if the text isn't a HAR.
 */
export function redactHar(text: string): string {
  const har = JSON.parse(text);
  const entries = har?.log?.entries;
  if (!Array.isArray(entries)) throw new Error("Not a HAR file (no log.entries).");
  const maskHeaders = (hs: unknown) =>
    Array.isArray(hs)
      ? hs.map((h: any) => {
          const name = String(h?.name ?? "");
          const masked = headersForEvidence({ [name]: String(h?.value ?? "") });
          return { ...h, value: masked[name.toLowerCase()] ?? "" };
        })
      : hs;
  const maskCookies = (cs: unknown) => (Array.isArray(cs) ? cs.map((c: any) => ({ ...c, value: "[REDACTED]" })) : cs);
  for (const e of entries) {
    if (e?.request) {
      e.request.headers = maskHeaders(e.request.headers);
      e.request.cookies = maskCookies(e.request.cookies);
      if (typeof e.request.url === "string") e.request.url = redactSourceFile(e.request.url);
      if (e.request.postData?.text) e.request.postData.text = redactSourceFile(String(e.request.postData.text));
    }
    if (e?.response) {
      e.response.headers = maskHeaders(e.response.headers);
      e.response.cookies = maskCookies(e.response.cookies);
      if (e.response.content?.text) e.response.content.text = redactSourceFile(String(e.response.content.text));
    }
  }
  return JSON.stringify(har, null, 2);
}
