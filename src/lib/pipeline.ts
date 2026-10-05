// Full audit as a pipeline (build plan 1c). Pure: no imports from the app, so
// the engine, the UI and the tests share one definition of the order, the
// gates between stages and what each stage hands to the next.
//
// Order: recon (website, attack surface) → config (Supabase) → code (repo) →
// ai (endpoint, deeper tests) → deep (code audit on the runner) → report
// (merge every scanner's findings and draft the summary, once all are in).

export type StageGroup = "recon" | "config" | "code" | "ai" | "deep" | "report";
export type StageStatus = "pending" | "running" | "waiting" | "done" | "failed" | "skipped";
export type PipelineScanner = "website" | "surface" | "supabase" | "repo" | "ai_endpoint" | "ai_deep" | "code_audit" | "synthesis";

export const STAGE_GROUPS: { group: StageGroup; label: string }[] = [
  { group: "recon", label: "Recon" },
  { group: "config", label: "Config" },
  { group: "code", label: "Code" },
  { group: "ai", label: "AI" },
  { group: "deep", label: "Deep" },
  { group: "report", label: "Synthesis" },
];

export const SCANNER_LABEL: Record<PipelineScanner, string> = {
  website: "Website",
  surface: "Attack surface (DNS, certificates)",
  supabase: "Supabase",
  repo: "Repo + dependencies",
  ai_endpoint: "AI endpoint",
  ai_deep: "Deeper AI tests (auth, rate limit, tools, exfil)",
  code_audit: "Deep code audit (runner)",
  synthesis: "Merge findings and draft the summary",
};

export type PipelineTarget = {
  id: string;
  kind: string;
  value: string;
  meta?: Record<string, unknown> | null;
  in_scope: boolean;
};

export type PipelineOptions = {
  websiteUrl: string | null;
  deepAudit: boolean;
  aiDeep: boolean;
  writeTestsAllowed: boolean;
};

export type PlannedStage = {
  key: string;
  stage: StageGroup;
  position: number;
  scanner: PipelineScanner;
  target: string | null;
  meta: Record<string, unknown>;
  depends_on: string[];
};

export type StageRow = PlannedStage & {
  status: StageStatus;
  reason: string | null;
  output: Record<string, any>;
  started_at?: string | null;
  finished_at?: string | null;
  attempts?: number;
};

/** Which credentials a run was given (never the values). */
export type CredPresence = {
  github: boolean;
  supabaseKeys: boolean;
  supabasePat: boolean;
  aiToken: boolean;
};

/** Every stage this audit's targets call for, in pipeline order. */
export function planPipeline(targets: PipelineTarget[], opts: PipelineOptions): PlannedStage[] {
  const inScope = targets.filter((t) => t.in_scope);
  const of = (kind: string) => inScope.filter((t) => t.kind === kind);
  const out: Omit<PlannedStage, "position">[] = [];
  const add = (s: Omit<PlannedStage, "position" | "meta" | "depends_on"> & Partial<Pick<PlannedStage, "meta" | "depends_on">>) =>
    out.push({ meta: {}, depends_on: [], ...s });

  // Recon
  add({ key: "website", stage: "recon", scanner: "website", target: opts.websiteUrl });
  add({ key: "surface", stage: "recon", scanner: "surface", target: opts.websiteUrl });

  // Config: only the first Supabase project runs (one set of keys per run).
  const supa = of("supabase");
  if (!supa.length) add({ key: "supabase", stage: "config", scanner: "supabase", target: null });
  supa.forEach((t, i) =>
    add({ key: `supabase:${t.id}`, stage: "config", scanner: "supabase", target: t.value, meta: { ...(t.meta ?? {}), first: i === 0 } }),
  );

  // Code
  const repos = of("repo");
  if (!repos.length) add({ key: "repo", stage: "code", scanner: "repo", target: null });
  repos.forEach((t) => add({ key: `repo:${t.id}`, stage: "code", scanner: "repo", target: t.value, meta: { ...(t.meta ?? {}) } }));

  // AI
  const ais = of("ai_endpoint");
  if (!ais.length) add({ key: "ai", stage: "ai", scanner: "ai_endpoint", target: null });
  ais.forEach((t) => add({ key: `ai:${t.id}`, stage: "ai", scanner: "ai_endpoint", target: t.value, meta: { ...(t.meta ?? {}) } }));
  ais.forEach((t) =>
    add({
      key: `aideep:${t.id}`,
      stage: "ai",
      scanner: "ai_deep",
      target: t.value,
      meta: { ...(t.meta ?? {}), selected: opts.aiDeep, writeTestsAllowed: opts.writeTestsAllowed },
      // Deeper tests only make sense once the basic probe reached the endpoint.
      depends_on: [`ai:${t.id}`],
    }),
  );

  // Deep: the first repo, after its repo scan proved the code is readable.
  if (repos.length && opts.deepAudit) {
    add({ key: `deep:${repos[0].id}`, stage: "deep", scanner: "code_audit", target: repos[0].value, depends_on: [`repo:${repos[0].id}`] });
  }

  // Report: always last, after every other stage (deep audit included) settled.
  add({ key: "synthesis", stage: "report", scanner: "synthesis", target: null });

  return out.map((s, position) => ({ ...s, position }));
}

/** A stage that will never run, and why. Null means it may run now. */
export function gateStage(stage: StageRow, all: StageRow[], creds: CredPresence): string | null {
  // Missing inputs.
  switch (stage.scanner) {
    case "website":
    case "surface":
      if (!stage.target) return "This audit has no website set.";
      break;
    case "supabase":
      if (!stage.target) return "No Supabase target in Targets & scope.";
      if (stage.meta?.first === false)
        return "Only the first Supabase project runs in a full audit; scan the others from the Supabase dialog with their own keys.";
      if (!creds.supabaseKeys) return "Anon and service-role keys weren't given for this run.";
      break;
    case "repo":
      if (!stage.target) return "No repo target in Targets & scope.";
      if (!creds.github) return "No GitHub token given for this run.";
      break;
    case "ai_endpoint":
      if (!stage.target) return "No AI endpoint target in Targets & scope.";
      break;
    case "ai_deep":
      if (stage.meta?.selected === false) return "Deeper AI tests not selected for this run.";
      if (stage.meta?.writeTestsAllowed === false) return "Active tests aren't authorized in Targets & scope.";
      break;
    case "code_audit":
    case "synthesis":
      break;
  }

  // Upstream stages.
  for (const dep of stage.depends_on) {
    const up = all.find((s) => s.key === dep);
    if (!up) continue;
    if (up.status === "pending" || up.status === "running") return null; // not decided yet; the engine waits
    if (up.status !== "done") return `${SCANNER_LABEL[up.scanner]} didn't finish${up.reason ? ` (${up.reason})` : ""}, so this was skipped.`;
    if (stage.scanner === "code_audit" && up.scanner === "repo" && up.output?.codeReadable === false)
      return "The repo scan couldn't read the code with this token (it needs Contents: Read-only), so the deep audit wasn't started.";
    if (stage.scanner === "ai_deep" && up.scanner === "ai_endpoint" && up.output?.reachable === false)
      return "The AI endpoint didn't answer the basic probe, so the deeper tests were skipped.";
  }
  return null;
}

/** True once every upstream stage this one depends on has settled. */
export function depsSettled(stage: StageRow, all: StageRow[]): boolean {
  return stage.depends_on.every((k) => {
    const up = all.find((s) => s.key === k);
    return !up || (up.status !== "pending" && up.status !== "running");
  });
}

/** The next stage to run, in order. Null when nothing is left to start. */
export function nextStage(all: StageRow[]): StageRow | null {
  const sorted = [...all].sort((a, b) => a.position - b.position);
  const othersSettled = (s: StageRow) =>
    sorted.every((o) => o === s || o.status === "done" || o.status === "failed" || o.status === "skipped");
  return (
    sorted.find((s) => s.status === "pending" && depsSettled(s, sorted) && (s.scanner !== "synthesis" || othersSettled(s))) ?? null
  );
}

/** Nothing pending, running or waiting on the runner. */
export function pipelineSettled(all: StageRow[]): boolean {
  return all.every((s) => s.status === "done" || s.status === "failed" || s.status === "skipped");
}

/** Only the deep audit (on its own machine) is still out. */
export function onlyWaiting(all: StageRow[]): boolean {
  return (
    all.some((s) => s.status === "waiting") &&
    all.every((s) => s.scanner === "synthesis" || (s.status !== "pending" && s.status !== "running"))
  );
}

/** Stage rows as the step list the full-audit summary already understands. */
export function stagesToSteps(all: StageRow[]) {
  return [...all]
    .filter((s) => s.scanner !== "synthesis")
    .sort((a, b) => a.position - b.position)
    .map((s) => ({
      scanner: s.scanner as Exclude<PipelineScanner, "synthesis">,
      target: s.target,
      outcome: (s.status === "done" ? "done" : s.status === "waiting" ? "started" : s.status === "failed" ? "failed" : "not_run") as
        | "done"
        | "started"
        | "failed"
        | "not_run",
      reason: s.reason,
    }));
}

// ───────────────────────── feed-forward ─────────────────────────

const SAFE_PATH = /^[A-Za-z0-9._\-/@+ ]{1,300}$/;

/**
 * Leads for the deep audit from the repo scan: where the cheap checks already
 * found something. Paths come from the client's repo, so they're filtered to
 * plain path characters and capped before they go into the runner's prompt.
 */
export function deepAuditFocus(repoOutput: Record<string, any> | null | undefined, max = 40): string[] {
  const leads = repoOutput?.leads;
  if (!leads) return [];
  const out: string[] = [];
  const push = (file: unknown, line: unknown, what: string) => {
    const f = String(file ?? "");
    if (!SAFE_PATH.test(f) || f.includes("..")) return;
    const l = Number.isInteger(line) && (line as number) > 0 ? `:${line}` : "";
    const entry = `${f}${l} — ${what}`;
    if (!out.includes(entry)) out.push(entry);
  };
  const label = (s: unknown) => String(s ?? "").replace(/[^A-Za-z0-9_ .()-]/g, "").slice(0, 60);
  for (const s of leads.secrets ?? []) push(s.file, null, `possible committed secret (${label(s.pattern)})`);
  for (const r of leads.rules ?? []) push(r.file, r.line, `code rule ${label(r.rule)}`);
  for (const x of leads.xss ?? []) push(x.file, x.line, `unsanitized HTML sink ${label(x.sink)}`);
  return out.slice(0, max);
}

export type SuggestedTarget = { kind: "website" | "ai_endpoint"; value: string; label: string; meta: Record<string, unknown> };

/**
 * New targets earlier stages turned up, to add to Targets & scope as out of
 * scope suggestions. Nothing is scanned until the auditor puts it in scope.
 */
export function suggestTargets(
  all: StageRow[],
  existing: { kind: string; value: string }[],
  websiteUrl: string | null,
  maxHosts = 10,
): SuggestedTarget[] {
  const have = new Set(existing.map((t) => `${t.kind}|${t.value.toLowerCase()}`));
  const siteHost = (() => {
    try {
      return websiteUrl ? new URL(websiteUrl).hostname.toLowerCase() : null;
    } catch {
      return null;
    }
  })();
  const out: SuggestedTarget[] = [];
  const add = (t: SuggestedTarget) => {
    const k = `${t.kind}|${t.value.toLowerCase()}`;
    if (have.has(k)) return;
    have.add(k);
    out.push(t);
  };

  const surface = all.find((s) => s.scanner === "surface" && s.status === "done");
  let hosts = 0;
  for (const h of (surface?.output?.hosts ?? []) as unknown[]) {
    const host = String(h).toLowerCase();
    if (hosts >= maxHosts) break;
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host) || host.startsWith("*.") || host === siteHost) continue;
    add({ kind: "website", value: `https://${host}`, label: "Suggested: found in certificate logs", meta: { suggested_by: "surface" } });
    hosts++;
  }

  for (const repo of all.filter((s) => s.scanner === "repo" && s.status === "done")) {
    for (const e of (repo.output?.aiEndpoints ?? []) as any[]) {
      const url = String(e?.url ?? "");
      if (!/^https:\/\/[^\s]+$/.test(url) || url.length > 2048) continue;
      const field = String(e?.promptField ?? "prompt").replace(/[^A-Za-z0-9_]/g, "") || "prompt";
      add({ kind: "ai_endpoint", value: url, label: "Suggested: found in the repo", meta: { suggested_by: "repo", prompt_field: field } });
    }
  }
  return out;
}
