// Database policy review (build plan 3.1). Pure judgement over rows read
// through the Management API, so it can be tested without a database.
//
// Postgres semantics worth remembering:
// - Permissive policies OR together: one USING (true) opens the whole table
//   to the roles it names, whatever the other policies say.
// - An UPDATE policy without WITH CHECK reuses its USING expression.
// - user_metadata in the JWT is editable by the signed-in user, so a policy
//   that trusts it can be bypassed by that user.
// - A view runs with its owner's rights unless security_invoker is on, so an
//   exposed view skips the RLS of the tables under it.
// - A SECURITY DEFINER function without a fixed search_path can be made to
//   resolve names to objects an attacker created.

export type CheckStatus = "pass" | "fail" | "inconclusive";
export type PolicyCheck = { status: CheckStatus; notes: string };

export type PolicyRow = {
  schema: string;
  table: string;
  policy: string;
  permissive: string; // 'PERMISSIVE' | 'RESTRICTIVE'
  roles: string[] | string; // e.g. {anon,authenticated} or {public}
  cmd: string; // SELECT | INSERT | UPDATE | DELETE | ALL
  qual: string | null;
  with_check: string | null;
};

export const POLICIES_SQL = `
select schemaname as schema, tablename as table, policyname as policy, permissive,
       roles::text[] as roles, cmd, qual, with_check
from pg_policies
where schemaname in ('public', 'storage')
order by schemaname, tablename, policyname;`;

export const DEFINER_SEARCH_PATH_SQL = `
select p.proname as name, pg_get_function_identity_arguments(p.oid) as args,
       coalesce(array_to_string(p.proconfig, ','), '') as config
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public' and p.prosecdef and p.prokind = 'f'
order by 1;`;

export const EXPOSED_VIEWS_SQL = `
select c.relname as view,
       coalesce((select option_value from pg_options_to_table(c.reloptions) where option_name = 'security_invoker'), 'false') as security_invoker,
       has_table_privilege('anon', c.oid, 'SELECT') as anon_select,
       has_table_privilege('authenticated', c.oid, 'SELECT') as auth_select
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind in ('v', 'm')
order by 1;`;

function rolesOf(r: PolicyRow): string[] {
  if (Array.isArray(r.roles)) return r.roles.map((x) => String(x).toLowerCase());
  return String(r.roles ?? "").replace(/[{}"]/g, "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
}

const norm = (e: string | null | undefined) => (e ?? "").replace(/\s+/g, " ").replace(/^\(+|\)+$/g, "").trim().toLowerCase();

/** Expression that admits every row. */
export function isAlwaysTrue(expr: string | null | undefined): boolean {
  const e = norm(expr);
  return e === "true" || e === "1 = 1" || e === "1=1";
}

/** Expression that only checks the caller is signed in, not which rows are theirs. */
export function isAuthOnly(expr: string | null | undefined): boolean {
  const e = norm(expr).replace(/\(|\)/g, "").replace(/\s+/g, " ");
  return (
    /^auth\.uid is not null$/.test(e) ||
    /^auth\.role = 'authenticated'(::text)?$/.test(e) ||
    /^auth\.jwt ->> 'role' = 'authenticated'(::text)?$/.test(e) ||
    /^select auth\.uid as uid is not null$/.test(e) ||
    /^select auth\.role as role = 'authenticated'(::text)?$/.test(e)
  );
}

export function trustsUserMetadata(expr: string | null | undefined): boolean {
  return /user_metadata|raw_user_meta_data/i.test(expr ?? "");
}

const PUBLIC_ROLES = new Set(["public", "anon"]);

export function checkPolicies(rows: PolicyRow[] | null, error?: string | null): PolicyCheck {
  if (!rows) return { status: "inconclusive", notes: error ? `Could not read policies: ${error}.` : "Not checked. Reading policies requires a Management API PAT." };
  const open: string[] = [];
  const review: string[] = [];
  const metadata: string[] = [];
  for (const r of rows) {
    if (String(r.permissive).toUpperCase() === "RESTRICTIVE") continue;
    const roles = rolesOf(r);
    const anyone = roles.some((x) => PUBLIC_ROLES.has(x));
    const cmd = String(r.cmd).toUpperCase();
    const where = `${r.schema}.${r.table} · "${r.policy}" (${cmd} to ${roles.join(", ") || "public"})`;
    if (trustsUserMetadata(r.qual) || trustsUserMetadata(r.with_check)) {
      metadata.push(`${where}: trusts user_metadata, which the user can edit`);
    }
    const readsAll = cmd !== "INSERT" && isAlwaysTrue(r.qual);
    const writesAll = (cmd === "INSERT" || cmd === "UPDATE" || cmd === "ALL") && (isAlwaysTrue(r.with_check) || (cmd !== "INSERT" && r.with_check == null && isAlwaysTrue(r.qual)));
    const isStoragePolicy = r.schema === "storage";
    if (anyone && (readsAll || writesAll)) {
      open.push(`${where}: ${readsAll ? "USING (true)" : "WITH CHECK (true)"}, so anyone without logging in can ${cmd === "SELECT" ? "read every row" : cmd === "INSERT" ? "insert any row" : "act on every row"}${isStoragePolicy ? " in storage" : ""}`);
    } else if (!anyone && (readsAll || writesAll)) {
      const verb = cmd === "SELECT" ? "read every row" : cmd === "INSERT" ? "insert rows for anyone" : "change or delete every row";
      (cmd === "SELECT" ? review : open).push(`${where}: any signed-in user can ${verb}`);
    } else if (isAuthOnly(r.qual) || (cmd === "INSERT" && isAuthOnly(r.with_check))) {
      const verb = cmd === "SELECT" ? "read every row" : cmd === "INSERT" ? "insert rows for anyone" : "change or delete every row";
      (cmd === "SELECT" ? review : open).push(`${where}: only checks that the caller is signed in, so any user can ${verb}`);
    }
  }
  if (open.length || metadata.length) {
    return {
      status: "fail",
      notes: [
        open.length ? `Policies that give blanket access:\n${open.map((x) => `• ${x}`).join("\n")}` : "",
        metadata.length ? `Policies that trust user-editable metadata:\n${metadata.map((x) => `• ${x}`).join("\n")}` : "",
        review.length ? `Also review (any signed-in user can read every row; fine only for genuinely shared data):\n${review.map((x) => `• ${x}`).join("\n")}` : "",
        "Scope each policy to the caller's own rows, e.g. USING (user_id = (select auth.uid())), and add WITH CHECK to inserts and updates. Use app_metadata (set server-side), never user_metadata, for roles.",
      ].filter(Boolean).join("\n\n"),
    };
  }
  if (review.length) {
    return {
      status: "inconclusive",
      notes: `No policy opens data to logged-out users, but these let any signed-in user read every row. That's right only for data every user may see:\n${review.map((x) => `• ${x}`).join("\n")}\n\nConfirm each table holds shared data, then mark this item.`,
    };
  }
  return { status: "pass", notes: `${rows.length} policies reviewed. None admit every row, trust user metadata, or only check that the caller is signed in.` };
}

export type DefinerFnRow = { name: string; args: string; config: string };

export function checkDefinerSearchPath(rows: DefinerFnRow[] | null, error?: string | null): PolicyCheck {
  if (!rows) return { status: "inconclusive", notes: error ? `Could not list functions: ${error}.` : "Not checked. Listing functions requires a Management API PAT." };
  const loose = rows.filter((r) => !/(^|,)search_path=/i.test(r.config ?? ""));
  if (!loose.length) return { status: "pass", notes: rows.length ? `All ${rows.length} SECURITY DEFINER function(s) set a fixed search_path.` : "No SECURITY DEFINER functions in the public schema." };
  return {
    status: "fail",
    notes: `SECURITY DEFINER function(s) without a fixed search_path:\n${loose.map((r) => `• public.${r.name}(${r.args})`).join("\n")}\n\nThey run with their owner's rights, and without SET search_path a caller can make them resolve names to objects the caller created. Add SET search_path = '' (and schema-qualify names) or SET search_path = public, pg_temp.`,
  };
}

export type ViewRow = { view: string; security_invoker: string | boolean; anon_select: boolean; auth_select: boolean };

export function checkExposedViews(rows: ViewRow[] | null, error?: string | null): PolicyCheck {
  if (!rows) return { status: "inconclusive", notes: error ? `Could not list views: ${error}.` : "Not checked. Listing views requires a Management API PAT." };
  const exposed = rows.filter((r) => (r.anon_select || r.auth_select) && !/^(true|on|1)$/i.test(String(r.security_invoker)));
  if (!exposed.length) return { status: "pass", notes: rows.length ? `All ${rows.length} view(s) either use security_invoker or aren't readable through the API.` : "No views in the public schema." };
  return {
    status: "fail",
    notes: `Views readable through the API that bypass row-level security (no security_invoker):\n${exposed.map((r) => `• public.${r.view} (${[r.anon_select && "anon", r.auth_select && "authenticated"].filter(Boolean).join(", ")})`).join("\n")}\n\nA view runs with its owner's rights, so it returns every row of the tables under it. Use ALTER VIEW … SET (security_invoker = on), or revoke SELECT from anon/authenticated.`,
  };
}
