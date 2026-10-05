// Shared dependency scan helpers used by runRepoScan.
import type { SupabaseClient } from "@supabase/supabase-js";
import { decodeBase64Utf8 } from "./decode-blob";
import { GITHUB_HOSTS, NPM_HOSTS, safeFetch } from "./ssrf-guard";
import { collectDeps } from "./dep-manifest";
import { upsertScanFinding } from "./finding-writer";
import { saveScanRun, type HistorySummary } from "./scan-history";
import type { EvidenceInput } from "./evidence";
import { lockfileKind, parseLockfile, osvSeverity, type LockedPackage, type LockfileKind } from "./lockfile-parse";

const OSV_HOSTS = ["api.osv.dev"];
const MAX_LOCKFILES = 10;
const MAX_LOCKFILE_BYTES = 20_000_000;
const OSV_BATCH = 500;
/** Detail lookups per scan (Worker subrequest budget). Beyond this, severity is reported as unknown. */
const MAX_OSV_DETAILS = 60;

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
  /** Not declared in any package.json: pulled in by another package. */
  transitive?: boolean;
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
    allowHosts: [...GITHUB_HOSTS, ...NPM_HOSTS, ...OSV_HOSTS],
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
type LockfileRef = { path: string; sha: string; size: number | null; kind: LockfileKind };

/**
 * Find and read EVERY package.json in the repo (outside node_modules), not just
 * the first one. Monorepos keep their real app dependencies in sub-packages, so
 * scanning only the root manifest reported "no CVEs" for code it never looked at.
 * Anything that could not be read is returned in `gaps`.
 */
async function fetchManifests(owner: string, repo: string, token: string, defaultBranch: string): Promise<{ manifests: Manifest[]; lockfiles: LockfileRef[]; gaps: string[] }> {
  const headers = ghHeaders(token);
  const gaps: string[] = [];

  let paths: string[] = [];
  let lockfiles: LockfileRef[] = [];
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
    lockfiles = (treeJson.tree ?? [])
      .filter((n: any) => n.type === "blob" && lockfileKind(String(n.path)) && !/(^|\/)node_modules\//.test(String(n.path)))
      .map((n: any) => ({ path: String(n.path), sha: String(n.sha), size: typeof n.size === "number" ? n.size : null, kind: lockfileKind(String(n.path))! }));
    if (lockfiles.length > MAX_LOCKFILES) {
      gaps.push(`${lockfiles.length - MAX_LOCKFILES} lockfile(s) beyond the ${MAX_LOCKFILES}-lockfile limit were not scanned.`);
      lockfiles = lockfiles.slice(0, MAX_LOCKFILES);
    }
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
  return { manifests, lockfiles, gaps };
}

/** Read lockfiles through the git blob API (works past the 1 MB contents-API limit). */
async function fetchLockedPackages(
  owner: string,
  repo: string,
  token: string,
  lockfiles: LockfileRef[],
  gaps: string[],
): Promise<{ packages: LockedPackage[]; read: string[] }> {
  const all = new Map<string, LockedPackage>();
  const read: string[] = [];
  for (const lf of lockfiles) {
    if (lf.size !== null && lf.size > MAX_LOCKFILE_BYTES) {
      gaps.push(`${lf.path} is larger than ${MAX_LOCKFILE_BYTES / 1_000_000} MB and was not read.`);
      continue;
    }
    try {
      const r = await timedFetch(`https://api.github.com/repos/${owner}/${repo}/git/blobs/${lf.sha}`, { headers: ghHeaders(token) }, 30_000);
      if (!r.ok) {
        gaps.push(`${lf.path}: could not be fetched (HTTP ${r.status}).`);
        continue;
      }
      const j: any = await r.json();
      const text = decodeBase64Utf8(String(j?.content ?? "").replace(/\s/g, ""));
      const pkgs = parseLockfile(lf.kind, text);
      if (!pkgs.length) {
        gaps.push(`${lf.path}: no packages could be read from it.`);
        continue;
      }
      for (const p of pkgs) all.set(`${p.name}@${p.version}`, p);
      read.push(`${lf.path} (${pkgs.length})`);
    } catch (e: any) {
      gaps.push(`${lf.path}: could not be parsed (${e?.message ?? "error"}).`);
    }
  }
  return { packages: [...all.values()], read };
}

type OsvHit = { pkg: LockedPackage; id: string; summary: string | null; severity: ReturnType<typeof osvSeverity>; cve: string | null };

/**
 * Known vulnerabilities for exact versions from OSV.dev. Returns null when any
 * batch fails: a partial answer is never treated as "no vulnerabilities".
 */
async function queryOsv(packages: LockedPackage[], gaps: string[]): Promise<OsvHit[] | null> {
  const idsByPkg: { pkg: LockedPackage; ids: string[] }[] = [];
  for (let i = 0; i < packages.length; i += OSV_BATCH) {
    const batch = packages.slice(i, i + OSV_BATCH);
    try {
      const r = await timedFetch("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "content-type": "application/json", "user-agent": "AuditKit-DependencyScan/1.0" },
        body: JSON.stringify({ queries: batch.map((p) => ({ package: { name: p.name, ecosystem: "npm" }, version: p.version })) }),
      }, 30_000);
      if (!r.ok) {
        gaps.push(`OSV.dev returned HTTP ${r.status}, so known vulnerabilities were NOT fully checked.`);
        return null;
      }
      const j: any = await r.json();
      const results: any[] = Array.isArray(j?.results) ? j.results : [];
      if (results.length !== batch.length) {
        gaps.push("OSV.dev returned an incomplete answer, so known vulnerabilities were NOT fully checked.");
        return null;
      }
      results.forEach((res, k) => {
        const ids = (res?.vulns ?? []).map((v: any) => String(v?.id)).filter(Boolean);
        if (res?.next_page_token) gaps.push(`${batch[k].name}@${batch[k].version}: more advisories exist than OSV returned in one page.`);
        if (ids.length) idsByPkg.push({ pkg: batch[k], ids });
      });
    } catch (e: any) {
      gaps.push(`OSV.dev could not be reached (${e?.message ?? "error"}), so known vulnerabilities were NOT checked.`);
      return null;
    }
  }
  const unique = [...new Set(idsByPkg.flatMap((x) => x.ids))];
  const details = new Map<string, any>();
  await pMap(unique.slice(0, MAX_OSV_DETAILS), 6, async (id) => {
    try {
      const r = await timedFetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { headers: { "user-agent": "AuditKit-DependencyScan/1.0" } });
      if (r.ok) details.set(id, await r.json());
    } catch {
      /* severity stays unknown, which is reported, not dropped */
    }
  });
  const hits: OsvHit[] = [];
  for (const { pkg, ids } of idsByPkg) {
    for (const id of ids) {
      const d = details.get(id);
      hits.push({
        pkg,
        id,
        summary: d?.summary ?? null,
        severity: d ? osvSeverity(d) : "unknown",
        cve: (d?.aliases ?? []).find((a: string) => /^CVE-/.test(a)) ?? (id.startsWith("CVE-") ? id : null),
      });
    }
  }
  return hits;
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
  parentRunId?: string | null;
  /** Owner recorded on the run when running with the service-role client. */
  createdBy?: string | null;
}): Promise<DepScanResult> {
  const { owner, repo, token, defaultBranch, supabase, auditId } = args;

  const { manifests, lockfiles, gaps } = await fetchManifests(owner, repo, token, defaultBranch);
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

  // Exact versions from lockfiles (direct and transitive), checked against OSV.
  // Without a lockfile, fall back to the npm advisory API on declared ranges.
  const locked = lockfiles.length ? await fetchLockedPackages(owner, repo, token, lockfiles, gaps) : { packages: [], read: [] as string[] };
  if (locked.packages.length) await recordPackages(supabase, auditId, `${owner}/${repo}`, locked.packages);
  let osvHits: OsvHit[] | null = null;
  if (locked.packages.length) {
    osvHits = await queryOsv(locked.packages, gaps);
  } else if (!lockfiles.length) {
    gaps.push("No lockfile in the repo, so transitive dependencies were NOT checked and versions are the lowest each declared range allows.");
  }
  const useNpmAdvisories = osvHits === null;
  const advisoryResult = useNpmAdvisories && names.length ? await fetchAdvisoriesBulk(query) : {};
  if (advisoryResult === null) {
    gaps.push("The npm advisory database could not be reached, so known vulnerabilities were NOT checked.");
  }
  const advisories: Record<string, any[]> = advisoryResult ?? {};
  const direct = new Set(names);
  const vulnerableNames = new Set<string>();
  if (osvHits) {
    const unknown = osvHits.filter((h) => h.severity === "unknown").length;
    if (unknown) gaps.push(`${unknown} advisory record(s) couldn't be rated (no severity retrieved); they're listed as high until reviewed.`);
  }

  const now = Date.now();
  const SIX_MONTHS = 1000 * 60 * 60 * 24 * 30 * 6;
  const findings: DepFinding[] = [];

  for (const h of osvHits ?? []) {
    const sev = h.severity === "unknown" ? "high" : h.severity;
    findings.push({
      name: h.pkg.name,
      current: h.pkg.version,
      latest: metaByName.get(h.pkg.name)?.latest ?? null,
      severity: sev,
      cve: h.cve ?? h.id,
      reason: `${h.summary ?? "Known vulnerability"}${h.severity === "unknown" ? " (severity not retrieved)" : ""}`,
      advisoryUrl: `https://osv.dev/vulnerability/${encodeURIComponent(h.id)}`,
      transitive: !direct.has(h.pkg.name),
    });
    if (sev === "critical" || sev === "high") vulnerableNames.add(h.pkg.name);
  }

  for (const name of names) {
    const current = query[name].join(", ");
    const meta = metaByName.get(name) ?? { latest: null, latestTime: null, currentTime: null };
    const advList: any[] = advisories[name] ?? [];
    if (vulnerableNames.has(name)) continue;

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
    osvHits
      ? `Known vulnerabilities: ${locked.packages.length} exact package versions (direct and transitive) from ${locked.read.join(", ")}, checked against OSV.dev.`
      : `Known vulnerabilities: declared ranges checked against the npm advisory database (lowest version each range allows). Transitive dependencies were not checked.`,
    `Critical: ${counts.critical} · High: ${counts.high} · Medium: ${counts.medium} · Low: ${counts.low}.`,
  ];
  if (gaps.length) {
    summaryLines.push("", "NOT fully checked, so this is not a pass:", ...gaps.map((g) => `• ${g}`));
  }
  if (findings.length) {
    summaryLines.push("", "Flagged packages:");
    for (const f of findings.slice(0, 40)) {
      summaryLines.push(
        `• [${f.severity.toUpperCase()}] ${f.name} ${f.current}${f.transitive ? " (transitive)" : ""}${f.latest ? ` (latest ${f.latest})` : ""}${f.cve ? ` — ${f.cve}` : ""} — ${f.reason}`,
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
    {
      auditId,
      scanner: "dependencies",
      target: `${owner}/${repo}`,
      trigger: args.parentRunId ? "full" : "manual",
      parentRunId: args.parentRunId ?? null,
      createdBy: args.createdBy ?? null,
    },
    [{ checklist_item_id: itemId ?? null, checklist_key: "dep_vulns", status, notes: depNote, stored, evidence: ["deps"] }],
    {
      evidence: [
        {
          ref: "deps",
          kind: "probe_set",
          title: `Dependency check for ${owner}/${repo}`,
          content: { manifests: manifestPaths, lockfiles: locked.read, locked_packages: locked.packages.length, source: osvHits ? "osv.dev" : "npm advisories", packages_checked: names.length, counts, gaps, findings },
        } satisfies EvidenceInput,
      ],
    },
  );

  return { ok: true, path: manifestPaths.join(", "), packagesScanned: names.length, counts, status, findings, notes, manifests: manifestPaths, gaps, history };
}


// ---------------------------------------------------------------- stored packages (phase 4)

/**
 * Keep the exact package list from this repo's lockfiles on the audit, so a
 * scheduled run can re-check it against new advisories without the client's
 * GitHub token. Best effort: a failure here never fails the scan.
 */
async function recordPackages(supabase: SupabaseClient<any, any, any>, auditId: string, source: string, pkgs: LockedPackage[]) {
  try {
    const del = await supabase.from("audit_packages").delete().eq("audit_id", auditId).eq("source", source);
    if (del.error) throw new Error(del.error.message);
    for (let i = 0; i < pkgs.length; i += 1000) {
      const { error } = await supabase
        .from("audit_packages")
        .insert(pkgs.slice(i, i + 1000).map((p) => ({ audit_id: auditId, source, name: p.name, version: p.version })));
      if (error) throw new Error(error.message);
    }
  } catch (e: any) {
    console.warn("[dep-scan] package list not stored:", e?.message ?? e);
  }
}

/**
 * Re-check the stored package list against OSV.dev (scheduled runs). Writes the
 * dependency item and a "dependencies" run like the repo scan does.
 */
export async function recheckStoredPackages(
  supabase: any,
  auditId: string,
  opts: { parentRunId?: string | null; trigger?: "schedule" | "manual" | "full" | "retest"; createdBy?: string | null },
): Promise<{ ok: true; status: "pass" | "fail" | "inconclusive"; packages: number; vulnerable: number } | { ok: false; error: string }> {
  const { data: rows, error } = await supabase.from("audit_packages").select("source, name, version").eq("audit_id", auditId).limit(50000);
  if (error) return { ok: false, error: error.message };
  if (!rows?.length) return { ok: false, error: "No lockfile packages recorded for this audit yet. Run a repo scan once to record them." };
  const unique = new Map<string, LockedPackage>();
  for (const r of rows as any[]) unique.set(`${r.name}@${r.version}`, { name: r.name, version: r.version });
  const pkgs = [...unique.values()];
  const sources = [...new Set((rows as any[]).map((r) => r.source))];
  const gaps: string[] = [];
  const hits = await queryOsv(pkgs, gaps);
  const findings = (hits ?? []).map((h) => ({
    name: h.pkg.name,
    version: h.pkg.version,
    severity: h.severity === "unknown" ? "high" : h.severity,
    id: h.cve ?? h.id,
    summary: h.summary ?? "Known vulnerability",
    url: `https://osv.dev/vulnerability/${encodeURIComponent(h.id)}`,
  }));
  const blocking = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  const status: "pass" | "fail" | "inconclusive" = blocking.length ? "fail" : hits === null || gaps.length ? "inconclusive" : "pass";
  const stamp = new Date().toISOString();
  const notes = [
    `[Dependency re-check ${stamp}]`,
    `Re-checked ${pkgs.length} exact package versions recorded from ${sources.join(", ")} against OSV.dev (no new code was fetched; run a repo scan to refresh the list).`,
    blocking.length ? `\nCritical/high advisories:\n${blocking.slice(0, 40).map((f) => `• [${f.severity.toUpperCase()}] ${f.name} ${f.version} — ${f.id} — ${f.summary}`).join("\n")}` : "",
    gaps.length ? `\nNOT fully checked, so this is not a pass:\n${gaps.map((g) => `• ${g}`).join("\n")}` : "",
  ].filter(Boolean).join("\n");

  const { data: items } = await supabase.from("checklist_items").select("id").eq("checklist_key", "dep_vulns").limit(1);
  const itemId = items?.[0]?.id ?? null;
  let stored = false;
  if (itemId) stored = (await upsertScanFinding(supabase, { audit_id: auditId, checklist_item_id: itemId, status, notes })).written;
  await saveScanRun(
    supabase,
    { auditId, scanner: "dependencies", target: sources.join(", "), trigger: opts.trigger ?? "schedule", parentRunId: opts.parentRunId ?? null, createdBy: opts.createdBy ?? null },
    [{ checklist_item_id: itemId, checklist_key: "dep_vulns", status, notes, stored, evidence: ["osv"] }],
    { evidence: [{ ref: "osv", kind: "probe_set", title: `OSV.dev re-check of ${pkgs.length} recorded packages`, content: { sources, packages: pkgs.length, gaps, findings } }] },
  );
  return { ok: true, status, packages: pkgs.length, vulnerable: blocking.length };
}
