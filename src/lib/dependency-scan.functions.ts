import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

const TIMEOUT_MS = 15_000;
const NPM_CONCURRENCY = 8;

export type DepFinding = {
  name: string;
  current: string;
  latest: string | null;
  severity: "critical" | "high" | "medium" | "low";
  cve: string | null;
  reason: string;
  advisoryUrl: string | null;
};

async function timedFetch(url: string, init: RequestInit = {}, timeoutMs = TIMEOUT_MS): Promise<Response> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctl.signal, redirect: "follow" });
  } finally {
    clearTimeout(t);
  }
}

function parseRepo(raw: string): { owner: string; repo: string } | null {
  const m = raw
    .trim()
    .replace(/\.git$/, "")
    .match(/(?:github\.com[/:])?([^/\s]+)\/([^/?#\s]+)/i);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

function ghHeaders(token: string): Record<string, string> {
  return {
    accept: "application/vnd.github+json",
    "user-agent": "AuditKit-DependencyScan/1.0",
    "x-github-api-version": "2022-11-28",
    authorization: `Bearer ${token}`,
  };
}

function cleanVersion(v: string): string {
  // strip ^ ~ >= etc, drop ranges
  const m = v.match(/(\d+\.\d+\.\d+(?:[-+][\w.]+)?)/);
  return m ? m[1] : v.replace(/^[\^~><=\s]+/, "").trim();
}

function majorOf(v: string): number | null {
  const m = v.match(/^v?(\d+)\./);
  return m ? parseInt(m[1], 10) : null;
}

async function pMap<T, R>(items: T[], n: number, fn: (it: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  async function worker() {
    while (true) {
      const idx = i++;
      if (idx >= items.length) return;
      out[idx] = await fn(items[idx]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
  return out;
}

async function fetchPackageJson(owner: string, repo: string, token: string): Promise<{ path: string; json: any } | null> {
  const headers = ghHeaders(token);
  const paths = ["package.json", "src/package.json", "client/package.json"];
  for (const p of paths) {
    const r = await timedFetch(
      `https://api.github.com/repos/${owner}/${repo}/contents/${p}`,
      { headers },
    );
    if (!r.ok) continue;
    const j = await r.json();
    if (!j?.content) continue;
    try {
      const text = atob(String(j.content).replace(/\n/g, ""));
      return { path: p, json: JSON.parse(text) };
    } catch {
      continue;
    }
  }
  return null;
}

type NpmMeta = { latest: string | null; latestTime: string | null; currentTime: string | null };

async function fetchNpmMeta(name: string, current: string): Promise<NpmMeta> {
  try {
    const r = await timedFetch(`https://registry.npmjs.org/${encodeURIComponent(name).replace("%40", "@")}`, {
      headers: { accept: "application/json", "user-agent": "AuditKit-DependencyScan/1.0" },
    });
    if (!r.ok) return { latest: null, latestTime: null, currentTime: null };
    const j: any = await r.json();
    const latest: string | null = j?.["dist-tags"]?.latest ?? null;
    const time = j?.time ?? {};
    return {
      latest,
      latestTime: latest ? time[latest] ?? null : null,
      currentTime: time[current] ?? null,
    };
  } catch {
    return { latest: null, latestTime: null, currentTime: null };
  }
}

async function fetchAdvisoriesBulk(pkgs: Record<string, string[]>): Promise<Record<string, any[]>> {
  try {
    const r = await timedFetch("https://registry.npmjs.org/-/npm/v1/security/advisories/bulk", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json", "user-agent": "AuditKit-DependencyScan/1.0" },
      body: JSON.stringify(pkgs),
    });
    if (!r.ok) return {};
    return (await r.json()) ?? {};
  } catch {
    return {};
  }
}

export const runDependencyScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { auditId: string; repoUrl: string; token: string }) => {
    if (!input?.auditId || typeof input.auditId !== "string") throw new Error("auditId required");
    if (!input?.repoUrl || typeof input.repoUrl !== "string") throw new Error("repoUrl required");
    if (!input?.token || typeof input.token !== "string") throw new Error("token required");
    if (input.token.length < 20) throw new Error("token looks too short to be a valid PAT");
    return input;
  })
  .handler(async ({ data, context }) => {
    const { supabase } = context;
    const parsed = parseRepo(data.repoUrl);
    if (!parsed) return { ok: false as const, error: `Could not parse GitHub URL: ${data.repoUrl}` };

    // Verify repo access
    const repoMeta = await timedFetch(
      `https://api.github.com/repos/${parsed.owner}/${parsed.repo}`,
      { headers: ghHeaders(data.token) },
    );
    if (repoMeta.status === 401) return { ok: false as const, error: "GitHub rejected the token (401). Check that it has read access." };
    if (repoMeta.status === 404) return { ok: false as const, error: "Repo not found (404)." };
    if (!repoMeta.ok) return { ok: false as const, error: `GitHub repo lookup failed (${repoMeta.status}).` };

    const pkg = await fetchPackageJson(parsed.owner, parsed.repo, data.token);
    if (!pkg) {
      return { ok: false as const, error: "package.json not found at root, src/, or client/." };
    }

    const deps: Record<string, string> = {
      ...(pkg.json.dependencies ?? {}),
      ...(pkg.json.devDependencies ?? {}),
    };
    const names = Object.keys(deps);
    if (names.length === 0) {
      return { ok: false as const, error: "package.json has no dependencies." };
    }

    // Fetch npm meta in parallel
    const cleaned: Record<string, string> = {};
    for (const n of names) cleaned[n] = cleanVersion(deps[n]);

    const metas = await pMap(names, NPM_CONCURRENCY, async (n) => ({ name: n, meta: await fetchNpmMeta(n, cleaned[n]) }));
    const metaByName = new Map(metas.map((m) => [m.name, m.meta]));

    // Bulk advisories: send full version list for each package (registry expects array of versions)
    const advisoryReq: Record<string, string[]> = {};
    for (const n of names) advisoryReq[n] = [cleaned[n]];
    const advisories = await fetchAdvisoriesBulk(advisoryReq);

    const now = Date.now();
    const SIX_MONTHS = 1000 * 60 * 60 * 24 * 30 * 6;
    const findings: DepFinding[] = [];

    for (const name of names) {
      const current = cleaned[name];
      const meta = metaByName.get(name) ?? { latest: null, latestTime: null, currentTime: null };
      const advList: any[] = advisories[name] ?? [];

      let recorded = false;
      for (const adv of advList) {
        const sev = String(adv?.severity ?? "low").toLowerCase();
        if (sev !== "critical" && sev !== "high" && sev !== "moderate" && sev !== "low") continue;
        const mapped: DepFinding["severity"] = sev === "moderate" ? "medium" : (sev as any);
        if (mapped === "critical" || mapped === "high") {
          findings.push({
            name,
            current,
            latest: meta.latest,
            severity: mapped,
            cve: Array.isArray(adv?.cves) && adv.cves.length ? adv.cves[0] : (adv?.cve ?? null),
            reason: adv?.title ?? "Known vulnerability",
            advisoryUrl: adv?.url ?? null,
          });
          recorded = true;
        }
      }
      if (recorded) continue;

      // Major version drift
      const curMaj = majorOf(current);
      const latMaj = meta.latest ? majorOf(meta.latest) : null;
      if (curMaj !== null && latMaj !== null && latMaj - curMaj >= 2) {
        findings.push({
          name,
          current,
          latest: meta.latest,
          severity: "medium",
          cve: null,
          reason: `${latMaj - curMaj} major versions behind latest`,
          advisoryUrl: null,
        });
        continue;
      }

      // Age
      if (meta.currentTime) {
        const age = now - new Date(meta.currentTime).getTime();
        if (age > SIX_MONTHS && meta.latest && meta.latest !== current) {
          findings.push({
            name,
            current,
            latest: meta.latest,
            severity: "low",
            cve: null,
            reason: `Installed version published ${Math.round(age / (1000 * 60 * 60 * 24 * 30))} months ago`,
            advisoryUrl: null,
          });
        }
      }
    }

    findings.sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return order[a.severity] - order[b.severity];
    });

    const counts = {
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
    };

    const hasBlocker = counts.critical > 0 || counts.high > 0;
    const status: "pass" | "fail" = hasBlocker ? "fail" : "pass";
    const summaryLines = [
      `Scanned ${names.length} dependencies in ${pkg.path} of ${parsed.owner}/${parsed.repo}.`,
      `Critical: ${counts.critical} · High: ${counts.high} · Medium: ${counts.medium} · Low: ${counts.low}.`,
    ];
    if (findings.length) {
      summaryLines.push("");
      summaryLines.push("Flagged packages:");
      for (const f of findings.slice(0, 40)) {
        summaryLines.push(
          `• [${f.severity.toUpperCase()}] ${f.name} ${f.current}${f.latest ? ` (latest ${f.latest})` : ""}${f.cve ? ` — ${f.cve}` : ""} — ${f.reason}`,
        );
      }
      if (findings.length > 40) summaryLines.push(`…and ${findings.length - 40} more.`);
    } else {
      summaryLines.push("No critical/high CVEs, no packages 2+ majors behind, no >6-month-old pins.");
    }

    // Persist
    const { data: items, error: ierr } = await supabase
      .from("checklist_items")
      .select("id, title")
      .eq("title", "Dependency vulnerabilities scanned")
      .limit(1);
    if (ierr) throw new Error(ierr.message);
    const itemId = items?.[0]?.id;
    let matched = false;
    if (itemId) {
      const stamp = new Date().toISOString();
      const note = `[Dependency scan ${stamp}]\n${summaryLines.join("\n")}`;
      const { error: upErr } = await supabase.from("audit_findings").upsert(
        {
          audit_id: data.auditId,
          checklist_item_id: itemId,
          status,
          notes: note,
          auto_scanned: true,
        },
        { onConflict: "audit_id,checklist_item_id" },
      );
      if (upErr) throw new Error(upErr.message);
      matched = true;
    }

    return {
      ok: true as const,
      repo: `${parsed.owner}/${parsed.repo}`,
      path: pkg.path,
      packagesScanned: names.length,
      counts,
      status,
      matched,
      findings,
    };
  });
