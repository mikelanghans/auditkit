// Full-audit preflight: check every credential and target the run was given
// before anything runs, so a typo'd key or a token without Contents access
// fails in seconds instead of after twenty minutes of scanning (or on a paid
// runner machine). Nothing here writes anywhere.
import { safeFetch, assertSafeOutboundUrl, SSRFBlockedError, describeBlockedUrl } from "./ssrf-guard";
import { checkRepoAccess } from "./code-audit.functions";
import { normalizeProjectUrl } from "./supabase-scan.functions";

export type PreflightCheck = {
  key: string;
  label: string;
  status: "pass" | "fail";
  detail: string;
};

export type PreflightInput = {
  websiteUrl: string | null;
  repos: string[];
  supabase: string | null;
  aiEndpoints: string[];
  creds: {
    githubToken?: string | null;
    anonKey?: string | null;
    serviceRoleKey?: string | null;
    managementPat?: string | null;
  };
  /** Deep audit selected: the clone check matters even for a public repo. */
  deepAudit?: boolean;
};

const TIMEOUT = 10_000;
const isJwt = (k: string) => /^eyJ[\w-]+\.[\w-]+\.[\w-]+$/.test(k);

async function urlSafe(url: string): Promise<string | null> {
  try {
    await assertSafeOutboundUrl(url);
    return null;
  } catch (e: any) {
    return e instanceof SSRFBlockedError ? describeBlockedUrl(e) : (e?.message ?? "Not a reachable public URL.");
  }
}

async function status(url: string, headers: Record<string, string>, allowHosts?: string[]): Promise<number | string> {
  try {
    const r = await safeFetch(url, { headers }, { timeoutMs: TIMEOUT, ...(allowHosts ? { allowHosts } : {}) });
    await r.body?.cancel().catch(() => {});
    return r.status;
  } catch (e: any) {
    return e?.message ?? "request failed";
  }
}

export async function runPreflight(input: PreflightInput): Promise<{ ok: boolean; checks: PreflightCheck[] }> {
  const checks: PreflightCheck[] = [];
  const pass = (key: string, label: string, detail: string) => checks.push({ key, label, status: "pass", detail });
  const fail = (key: string, label: string, detail: string) => checks.push({ key, label, status: "fail", detail });
  const jobs: Promise<void>[] = [];

  if (input.websiteUrl) {
    jobs.push(
      (async () => {
        const why = await urlSafe(input.websiteUrl!);
        if (why) fail("website", "Website", why);
        else pass("website", "Website", "Public address, OK to scan.");
      })(),
    );
  }

  for (const url of input.aiEndpoints) {
    jobs.push(
      (async () => {
        const why = await urlSafe(url);
        if (why) fail(`ai:${url}`, "AI endpoint", `${url}: ${why}`);
        else pass(`ai:${url}`, "AI endpoint", `${url} is a public address.`);
      })(),
    );
  }

  const token = input.creds.githubToken?.trim() || null;
  if (token) {
    for (const repo of input.repos) {
      jobs.push(
        (async () => {
          const r = await checkRepoAccess(repo, token);
          const name = repo.replace("https://github.com/", "");
          if (r.ok) pass(`repo:${repo}`, "GitHub token", `Can read and clone ${name}.`);
          else fail(`repo:${repo}`, "GitHub token", r.error);
        })(),
      );
    }
  } else if (input.deepAudit && input.repos[0]) {
    jobs.push(
      (async () => {
        const r = await checkRepoAccess(input.repos[0], null);
        if (!r.ok) fail(`repo:${input.repos[0]}`, "GitHub token", r.error);
      })(),
    );
  }

  const anon = input.creds.anonKey?.trim() || null;
  const service = input.creds.serviceRoleKey?.trim() || null;
  const pat = input.creds.managementPat?.trim() || null;
  if (input.supabase && (anon || service || pat)) {
    const project = normalizeProjectUrl(input.supabase);
    if (!project) {
      fail("supabase", "Supabase project", "The Supabase target must be https://<ref>.supabase.co.");
    } else {
      const host = new URL(project).hostname;
      if (anon) {
        jobs.push(
          (async () => {
            const s = await status(`${project}/auth/v1/settings`, { apikey: anon }, [host]);
            if (s === 200) pass("supabase:anon", "Supabase anon key", "Accepted by the project.");
            else fail("supabase:anon", "Supabase anon key", s === 401 ? "The project rejected the anon key." : `Couldn't check the anon key (${s}).`);
          })(),
        );
      }
      if (service) {
        jobs.push(
          (async () => {
            const headers: Record<string, string> = { apikey: service };
            if (isJwt(service)) headers.authorization = `Bearer ${service}`;
            const s = await status(`${project}/auth/v1/admin/users?per_page=1`, headers, [host]);
            if (s === 200) pass("supabase:service", "Supabase service-role key", "Has admin access to the project.");
            else
              fail(
                "supabase:service",
                "Supabase service-role key",
                s === 401 || s === 403 ? "That isn't this project's service-role (secret) key." : `Couldn't check the service-role key (${s}).`,
              );
          })(),
        );
      }
      if (pat) {
        const ref = host.split(".")[0];
        jobs.push(
          (async () => {
            const s = await status(`https://api.supabase.com/v1/projects/${ref}`, { authorization: `Bearer ${pat}` }, ["api.supabase.com"]);
            if (s === 200) pass("supabase:pat", "Supabase access token", "Can read this project through the Management API.");
            else
              fail(
                "supabase:pat",
                "Supabase access token",
                s === 401 ? "Supabase rejected the access token." : s === 403 || s === 404 ? "That access token can't see this project." : `Couldn't check the access token (${s}).`,
              );
          })(),
        );
      }
    }
  }

  await Promise.all(jobs);
  return { ok: checks.every((c) => c.status === "pass"), checks };
}
