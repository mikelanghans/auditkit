// What an audit covers (build plan, phase 1a). Pure helpers shared by the
// targets panel, the scanners and tests. Targets are locations, never secrets.

export type TargetKind = "website" | "repo" | "supabase" | "ai_endpoint" | "api";

export const TARGET_KINDS: { kind: TargetKind; label: string; placeholder: string }[] = [
  { kind: "website", label: "Website", placeholder: "https://app.example.com" },
  { kind: "repo", label: "GitHub repo", placeholder: "https://github.com/owner/repo" },
  { kind: "supabase", label: "Supabase project", placeholder: "https://<ref>.supabase.co" },
  { kind: "ai_endpoint", label: "AI endpoint", placeholder: "https://app.example.com/api/chat" },
  { kind: "api", label: "API base URL", placeholder: "https://api.example.com" },
];

export type AuditTarget = {
  id: string;
  audit_id: string;
  kind: TargetKind;
  value: string;
  label: string | null;
  meta: Record<string, unknown>;
  in_scope: boolean;
};

export type Environment = "production" | "staging" | "development" | "unknown";

export type AuditScope = {
  audit_id: string;
  environment: Environment;
  write_tests_allowed: boolean;
  authorized_by: string | null;
  authorized_at: string | null;
  authorization_ref: string | null;
  testing_window: string | null;
  out_of_scope: string | null;
  notes: string | null;
};

export type NormalizedTarget = { ok: true; value: string } | { ok: false; error: string };

function httpsOrigin(raw: string, { keepPath }: { keepPath: boolean }): URL | null {
  let s = raw.trim();
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s}`;
  try {
    const u = new URL(s);
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    if (u.username || u.password) return null;
    if (!u.hostname.includes(".")) return null;
    if (!keepPath) {
      u.pathname = "/";
    }
    u.hash = "";
    return u;
  } catch {
    return null;
  }
}

/** Normalize what was typed for a target; reject anything a scanner couldn't use. */
export function normalizeTarget(kind: TargetKind, raw: string): NormalizedTarget {
  const input = String(raw ?? "").trim();
  if (!input) return { ok: false, error: "Enter a value." };
  if (input.length > 2048) return { ok: false, error: "That's too long for a URL." };

  switch (kind) {
    case "website": {
      const u = httpsOrigin(input, { keepPath: false });
      if (!u) return { ok: false, error: "Enter a site URL like https://app.example.com" };
      return { ok: true, value: `${u.protocol}//${u.host}` };
    }
    case "repo": {
      const m = input
        .replace(/\.git$/i, "")
        .replace(/\/+$/, "")
        .match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100})$/i);
      if (!m) return { ok: false, error: "Enter a GitHub repo like https://github.com/owner/repo" };
      return { ok: true, value: `https://github.com/${m[1]}/${m[2]}` };
    }
    case "supabase": {
      const u = httpsOrigin(input, { keepPath: false });
      if (!u || u.protocol !== "https:" || u.port || !/^[a-z0-9]{16,}\.supabase\.(co|in|net)$/i.test(u.hostname)) {
        return { ok: false, error: "Enter the project URL like https://<ref>.supabase.co" };
      }
      return { ok: true, value: `https://${u.hostname.toLowerCase()}` };
    }
    case "ai_endpoint":
    case "api": {
      const u = httpsOrigin(input, { keepPath: true });
      if (!u) return { ok: false, error: "Enter a full URL like https://app.example.com/api/chat" };
      const path = u.pathname.replace(/\/+$/, "");
      return { ok: true, value: `${u.protocol}//${u.host}${path}${u.search}` };
    }
  }
}

/** First in-scope target of a kind, for pre-filling scanner forms. */
export function firstTarget(targets: AuditTarget[] | null | undefined, kind: TargetKind): AuditTarget | null {
  return (targets ?? []).find((t) => t.kind === kind && t.in_scope) ?? null;
}

/**
 * Gate for active tests: write probes, stress probes, cross-account writes.
 * Fails closed: no scope row, or a scope that doesn't allow it, means no.
 */
export async function checkWriteTestsAllowed(
  supabase: { from: (t: string) => any },
  auditId: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const { data, error } = await supabase
    .from("audit_scope")
    .select("write_tests_allowed")
    .eq("audit_id", auditId)
    .maybeSingle();
  if (error) return { ok: false, error: `Couldn't read this audit's scope (${error.message}), so active tests stay off.` };
  if (!data?.write_tests_allowed) {
    return {
      ok: false,
      error: "Active tests aren't authorized for this audit. Turn on \"Write and stress tests allowed\" in Targets & scope once the client has agreed in writing.",
    };
  }
  return { ok: true };
}
