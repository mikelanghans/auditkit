// Daily per-user quotas for the expensive actions. Enforced in the database by
// consume_quota() (see supabase/migrations/*_usage_quotas.sql) so that
// concurrent requests can't race past the limit.
import type { SupabaseClient } from "@supabase/supabase-js";

export type QuotaKind = "llm" | "scan" | "code_audit";

export type QuotaResult = { ok: true } | { ok: false; error: string };

/**
 * Reserve `amount` units of today's quota for the calling user. Fails closed:
 * if the quota can't be checked, the action does not run.
 */
export async function consumeQuota(supabase: SupabaseClient<any>, kind: QuotaKind, amount = 1): Promise<QuotaResult> {
  const { data, error } = await supabase.rpc("consume_quota", { p_kind: kind, p_amount: Math.max(1, Math.ceil(amount)) });
  if (error) {
    console.error("[quota] check failed", { kind, message: error.message });
    return { ok: false, error: "Usage limits could not be checked, so this action was not run. Please try again shortly." };
  }
  const r = (data ?? {}) as { allowed?: boolean; used?: number; limit?: number; reason?: string };
  if (r.allowed) return { ok: true };
  if (r.reason === "not_owner_mfa") {
    return { ok: false, error: "Sign in with two-factor verification to use AuditKit." };
  }
  const what = kind === "llm" ? "AI requests" : kind === "code_audit" ? "deep code audits" : "scans";
  return {
    ok: false,
    error: `Daily limit reached for ${what} (${r.used ?? "?"} of ${r.limit ?? "?"} used today). The limit resets at midnight UTC.`,
  };
}

/** Options for a scanner run outside its own request (the full-audit pipeline). */
export type ScannerCoreOptions = {
  /** False when the caller already spent the quota (the pipeline does it up front). */
  checkQuota: boolean;
};
