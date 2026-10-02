// Shared dependency scan helpers used by runRepoScan.
import type { SupabaseClient } from "@supabase/supabase-js";
import { decodeBase64Utf8 } from "./decode-blob";
import { GITHUB_HOSTS, NPM_HOSTS, safeFetch } from "./ssrf-guard";
import { collectDeps } from "./dep-manifest";
import { upsertScanFinding } from "./finding-writer";
import { saveScanRun, type HistorySummary } from "./scan-history";

const TIMEOUT_MS = 15_000;
const NPM_CONCURRENCY = 8;
const MAX_MANIFESTS = 25;

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
  status: "pass" | "fail" | "inconclusive";
  manifests: string[];
  gaps: string[];
  findings: DepFinding[];
  notes: string;
  history?: HistorySummary;
} | { ok: false; error: string };

/**
 * Talks to GitHub (with the client's PAT) and the public npm registry, so both
 * host sets are allowed. safeFetch drops the Authorization header before any
 * cross-origin hop, which matters here: the same helper carries a GitHub token
 * on some calls and hits npm on others.
 */
async function timedFetch(url: string, init: RequestInit = {}, timeoutMs = TIMEOUT_MS): Promise<Response> {
  return await safeFetch(url, init, {
    timeoutMs,
    allowHosts: [...GITHUB_HOSTS, ...NPM_HOSTS],
  });
}

function ghHeaders(token: string): Record<string, string> {
  return {
    accept: "application/vnd.github+json",
    "user-agent": "AuditKit-DependencyScan/1.0",
    "x-github-api-version": "2022-11-28",
    authorization: `Bearer ${token}`,
  };
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

type Manifest = { path: string; json: any };

/**
 * Find and read EVERY package.json in the repo (outside node_modules), not just
 * the first one. Monorepos keep their real app dependencies in sub-packages, so
 * scanning only the root manifest reported "no CVEs" for code it never looked at.
 * Anything that could not be read is returned in `gaps`.
 */
async function fetchManifests(owner: string, repo: string, token: string, defaultBranch: string): Promise<{ manifests: Manifest[]; gaps: string[] }> {
  const headers = ghHeaders(token);
  const gaps: string[] = [];

  let paths: string[] = [];
  const tree = await timedFetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(defaultBranch)}?recursive=1`,
    { headers },
  );
  if (tree.ok) {
    const treeJson = await tree.json();
    if (treeJson.truncated === true) {
      gaps.push("GitHub truncated the repository file listing, so some package.json files may not have been found.");
    }
    paths = (treeJson.tree ?? [])
      .filter((n: any) => n.type === "blob" && /(^|\/)package\.json$/.test(String(n.path)) && !/(^|\/)node_modules\//.test(String(n.path)))
      .map((n: any) => String(n.path))
      .sort((a: string, b: string) => a.split("/").length - b.split("/").length || a.localeCompare(b));
  } else {
    gaps.push(`Could not list the repository tree (HTTP ${tree.status}); only package.json at the repo root was checked.`);
    paths = ["package.json"];
  }
  if (paths.length > MAX_MANIFESTS) {
    gaps.push(`${paths.length - MAX_MANIFESTS} package.json file(s) beyond the ${MAX_MANIFESTS}-manifest limit were not scanned.`);
    paths = paths.slice(0, MAX_MANIFESTS);
  }

  const manifests: Manifest[] = [];
  for (const p of paths) {
    const r = await timedFetch(
      `https://api.github.com/repos/${owner}/${repo}/contents/${p.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(defaultBranch)}`,
      { headers },
    );
    if (!r.ok) {
      if (!(r.status === 404 && p === "package.json" && !tree.ok)) gaps.push(`${p}: could not be fetched (HTTP ${r.status}).`);
      continue;
    }
    const j = await r.json();
    try {
      const text = decodeBase64Utf8(String(j?.content ?? ""));
      manifests.push({ path: p, json: JSON.parse(text) });
    } catch {
      gaps.push(`${p}: could not be parsed.`);
    }
  }
  return { manifests, gaps };
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

/** Returns null when advisories could not be retrieved. Never treat that as "no advisories". */
async function fetchAdvisoriesBulk(pkgs: Record<string, string[]>): Promise<Record<string, any[]> | null> {
  try {
    const r = await timedFetch("https://registry.npmjs.org/-/npm/v1/security/advisories/bulk", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json", "user-agent": "AuditKit-DependencyScan/1.0" },
      body: JSON.stringify(pkgs),
    });
    if (!r.ok) return null;
    const j = await r.json();
    if (!j || typeof j !== "object" || Array.isArray(j)) return null;
    return j as Record<string, any[]>;
  } catch {
    return null;
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

  const { manifests, gaps } = await fetchManifests(owner, repo, token, defaultBranch);
  if (manifests.length === 0) {
    return { ok: false, error: `No readable package.json found in ${owner}/${repo} on branch ${defaultBranch}.${gaps.length ? ` ${gaps.join(" ")}` : ""}` };
  }
  const manifestPaths = manifests.map((m) => m.path);

  const { query, unresolved } = collectDeps(manifests);
  const names = Object.keys(query);
  if (names.length === 0 && unresolved.length === 0) {
    return { ok: false, error: `${manifestPaths.join(", ")} declare no dependencies.` };
  }
  if (unresolved.length) {
    gaps.push(`${unresolved.length} dependency spec(s) have no concrete version and could not be checked:\n${unresolved.slice(0, 20).map((u) => `  - ${u}`).join("\n")}${unresolved.length > 20 ? "\n  - …" : ""}`);
  }

  // Lowest declared version per package, for the staleness checks below.
  const cleaned: Record<string, string> = {};
  for (const n of names) cleaned[n] = query[n].slice().sort()[0];

  const metas = await pMap(names, NPM_CONCURRENCY, async (n) => ({ name: n, meta: await fetchNpmMeta(n, cleaned[n]) }));
  const metaByName = new Map(metas.map((m) => [m.name, m.meta]));

  const advisoryResult = names.length ? await fetchAdvisoriesBulk(query) : {};
  if (advisoryResult === null) {
    gaps.push("The npm advisory database could not be reached, so known vulnerabilities were NOT checked.");
  }
  const advisories: Record<string, any[]> = advisoryResult ?? {};

  const now = Date.now();
  const SIX_MONTHS = 1000 * 60 * 60 * 24 * 30 * 6;
  const findings: DepFinding[] = [];

  for (const name of names) {
    const current = query[name].join(", ");
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

    const curMaj = majorOf(cleaned[name]);
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
      if (age > SIX_MONTHS && meta.latest && meta.latest !== cleaned[name]) {
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
  // A clean result only counts if everything was actually checked.
  const status: "pass" | "fail" | "inconclusive" = hasBlocker ? "fail" : gaps.length > 0 ? "inconclusive" : "pass";
  const summaryLines = [
    `Scanned ${names.length} direct dependencies across ${manifests.length} manifest(s) in ${owner}/${repo}: ${manifestPaths.join(", ")}.`,
    `Versions checked are the lowest each declared range allows. Transitive dependencies are not included (no lockfile is read).`,
    `Critical: ${counts.critical} · High: ${counts.high} · Medium: ${counts.medium} · Low: ${counts.low}.`,
  ];
  if (gaps.length) {
    summaryLines.push("", "NOT fully checked, so this is not a pass:", ...gaps.map((g) => `• ${g}`));
  }
  if (findings.length) {
    summaryLines.push("", "Flagged packages:");
    for (const f of findings.slice(0, 40)) {
      summaryLines.push(
        `• [${f.severity.toUpperCase()}] ${f.name} ${f.current}${f.latest ? ` (latest ${f.latest})` : ""}${f.cve ? ` — ${f.cve}` : ""} — ${f.reason}`,
      );
    }
    if (findings.length > 40) summaryLines.push(`…and ${findings.length - 40} more.`);
  } else if (!gaps.length) {
    summaryLines.push("No critical/high CVEs, no packages 2+ majors behind, no >6-month-old pins.");
  }
  const notes = summaryLines.join("\n");

  // Persist to "Dependency vulnerabilities scanned" checklist item if present.
  // By key: the checklist once had two items with this title.
  const { data: items } = await supabase
    .from("checklist_items")
    .select("id, title")
    .eq("checklist_key", "dep_vulns")
    .limit(1);
  const itemId = items?.[0]?.id;
  const stamp = new Date().toISOString();
  const depNote = `[Dependency scan ${stamp}]\n${notes}`;
  let stored = false;
  if (itemId) {
    const w = await upsertScanFinding(supabase, {
      audit_id: auditId,
      checklist_item_id: itemId,
      status,
      notes: depNote,
    });
    stored = w.written;
  }
  const history = await saveScanRun(
    supabase,
    { auditId, scanner: "dependencies", target: `${owner}/${repo}` },
    [{ checklist_item_id: itemId ?? null, checklist_key: "dep_vulns", status, notes: depNote, stored }],
  );

  return { ok: true, path: manifestPaths.join(", "), packagesScanned: names.length, counts, status, findings, notes, manifests: manifestPaths, gaps, history };
}
