import { createClient } from "@supabase/supabase-js";

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL;
const supabasePublishableKey =
  import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_PUBLISHABLE_KEY;

/**
 * A client used only to send reset emails and to complete a reset.
 *
 * It keeps its session in memory under its own storage key and never persists
 * it. Before this, it shared the main app's localStorage key, so any
 * access/refresh token pair placed in a /reset-password link became the
 * app-wide login (login CSRF: a victim could be signed into an attacker's
 * account without noticing). After a reset the user signs in normally.
 */
export const passwordResetClient = createClient(supabaseUrl, supabasePublishableKey, {
  auth: {
    autoRefreshToken: false,
    detectSessionInUrl: true,
    flowType: "implicit",
    persistSession: false,
    storageKey: "auditkit-password-reset",
  },
});
