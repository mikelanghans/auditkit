// Settings for the E2E run. Everything points at a LOCAL Supabase started by
// `supabase start`; the run refuses anything else so it can never touch the
// production project or a client's systems.
export const SUPABASE_URL = process.env.E2E_SUPABASE_URL ?? "http://127.0.0.1:54321";
export const ANON_KEY = process.env.E2E_SUPABASE_ANON_KEY ?? "";
export const SERVICE_KEY = process.env.E2E_SUPABASE_SERVICE_ROLE_KEY ?? "";
export const APP_URL = "http://127.0.0.1:8080";
export const OWNER_EMAIL = "e2e-owner@auditkit.test";
export const OWNER_PASSWORD = "E2e-Only-Local-Password-1";
/** Reserved TLD: never resolves, so scans of it can't reach anyone. */
export const CANARY_SITE = "https://canary.invalid";
export const STATE_DIR = new URL("./.state/", import.meta.url).pathname;

export function assertLocal() {
  const host = new URL(SUPABASE_URL).hostname;
  if (host !== "127.0.0.1" && host !== "localhost") {
    throw new Error(`E2E refuses to run against ${SUPABASE_URL}: only a local Supabase is allowed.`);
  }
  if (!ANON_KEY || !SERVICE_KEY) throw new Error("Set E2E_SUPABASE_ANON_KEY and E2E_SUPABASE_SERVICE_ROLE_KEY (from `supabase status -o env`).");
}
