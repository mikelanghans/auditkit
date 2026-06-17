// Shared dependency scan helpers used by runRepoScan.
import type { SupabaseClient } from "@supabase/supabase-js";

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

export type DepScanResult = {
  ok: true;
  path: string;
  packagesScanned: number;
  counts: { critical: number; high: number; medium: number; low: number };
  status: "pass" | "fail";
  findings: DepFinding[];
  notes: string;
} | { ok: false; error: string };

async function timedFetch(url: string, init: RequestInit = {}, timeoutMs = TIMEOUT_MS): Promise<Response> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctl.signal, redirect: "follow" });
  } finally {
    clearTimeout(t);
  }
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

async function fetchPackageJson(owner: string, repo: string, token: string, defaultBranch: string): Promise<{ path: string; json: any } | null> {
  const headers = ghHeaders(token);
  const tryPaths = async (paths: string[]) => {
    for (const p of paths) {
      const r = await timedFetch(
        `https://api.github.com/repos/${owner}/${repo}/contents/${p}?ref=${encodeURIComponent(defaultBranch)}`,
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
  };

  // Prompt-spec: root first, then src/. Also include a couple of common monorepo paths as fallback.
  const common = await tryPaths(["package.json", "src/package.json", "client/package.json", "app/package.json", "web/package.json", "frontend/package.json", "apps/web/package.json", "packages/web/package.json"]);
  if (common) return common;

  const tree = await timedFetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`,
    { headers },
  );
  if (!tree.ok) return null;
  const treeJson = await tree.json();
  const candidates: string[] = (treeJson.tree ?? [])
    .filter((n: any) => n.type === "blob" && /(^|\/)package\.json$/.test(String(n.path)) && !/node_modules\//.test(String(n.path)))
    .map((n: any) => String(n.path))
    .sort((a: string, b: string) => a.split("/").length - b.split("/").length);
  if (candidates.length === 0) return null;
  return tryPaths(candidates);
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

export async function runDepScan(args: {
  owner: string;
  repo: string;
  token: string;
  defaultBranch: string;
  supabase: SupabaseClient<any, any, any>;
  auditId: string;
}): Promise<DepScanResult> {
  const { owner, repo, token, defaultBranch, supabase, auditId } = args;

  const pkg = await fetchPackageJson(owner, repo, token, defaultBranch);
  if (!pkg) {
    return { ok: false, error: `No package.json found in ${owner}/${repo} (checked root and src/, then walked the tree on branch ${defaultBranch}).` };
  }

  const deps: Record<string, string> = {
    ...(pkg.json.dependencies ?? {}),
    ...(pkg.json.devDependencies ?? {}),
  };
  const names = Object.keys(deps);
  if (names.length === 0) {
    return { ok: false, error: `${pkg.path} has no dependencies.` };
  }

  const cleaned: Record<string, string> = {};
  for (const n of names) cleaned[n] = cleanVersion(deps[n]);

  const metas = await pMap(names, NPM_CONCURRENCY, async (n) => ({ name: n, meta: await fetchNpmMeta(n, cleaned[n]) }));
  const metaByName = new Map(metas.map((m) => [m.name, m.meta]));

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
    `Scanned ${names.length} dependencies in ${pkg.path} of ${owner}/${repo}.`,
    `Critical: ${counts.critical} · High: ${counts.high} · Medium: ${counts.medium} · Low: ${counts.low}.`,
  ];
  if (findings.length) {
    summaryLines.push("", "Flagged packages:");
    for (const f of findings.slice(0, 40)) {
      summaryLines.push(
        `• [${f.severity.toUpperCase()}] ${f.name} ${f.current}${f.latest ? ` (latest ${f.latest})` : ""}${f.cve ? ` — ${f.cve}` : ""} — ${f.reason}`,
      );
    }
    if (findings.length > 40) summaryLines.push(`…and ${findings.length - 40} more.`);
  } else {
    summaryLines.push("No critical/high CVEs, no packages 2+ majors behind, no >6-month-old pins.");
  }
  const notes = summaryLines.join("\n");

  // Persist to "Dependency vulnerabilities scanned" checklist item if present.
  const { data: items } = await supabase
    .from("checklist_items")
    .select("id, title")
    .eq("title", "Dependency vulnerabilities scanned")
    .limit(1);
  const itemId = items?.[0]?.id;
  if (itemId) {
    const stamp = new Date().toISOString();
    await supabase.from("audit_findings").upsert(
      {
        audit_id: auditId,
        checklist_item_id: itemId,
        status,
        notes: `[Dependency scan ${stamp}]\n${notes}`,
        auto_scanned: true,
      },
      { onConflict: "audit_id,checklist_item_id" },
    );
  }

  return { ok: true, path: pkg.path, packagesScanned: names.length, counts, status, findings, notes };
}
