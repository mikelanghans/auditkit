// Lockfile parsing for the dependency scan (build plan 3.3): the exact
// version of every installed package, direct and transitive, from whichever
// lockfile the repo has. Pure functions; no network.

export type LockedPackage = { name: string; version: string };
export type LockfileKind = "package-lock" | "bun" | "pnpm" | "yarn";

export const LOCKFILE_NAMES: Record<string, LockfileKind> = {
  "package-lock.json": "package-lock",
  "npm-shrinkwrap.json": "package-lock",
  "bun.lock": "bun",
  "pnpm-lock.yaml": "pnpm",
  "yarn.lock": "yarn",
};

export function lockfileKind(path: string): LockfileKind | null {
  const base = path.split("/").pop() ?? "";
  return LOCKFILE_NAMES[base] ?? null;
}

const SEMVERISH = /^\d+\.\d+\.\d+([-+][0-9A-Za-z.+-]+)?$/;

function add(out: Map<string, LockedPackage>, name: string, version: string) {
  name = name.trim();
  version = version.trim().replace(/^v/, "");
  if (!name || !SEMVERISH.test(version)) return; // git/file/link deps have no registry version
  out.set(`${name}@${version}`, { name, version });
}

/** Split "name@version" where name may be scoped ("@scope/pkg@1.2.3"). */
export function splitSpec(spec: string): { name: string; rest: string } | null {
  const at = spec.lastIndexOf("@");
  if (at <= 0) return null;
  return { name: spec.slice(0, at), rest: spec.slice(at + 1) };
}

function parsePackageLock(text: string, out: Map<string, LockedPackage>) {
  const j = JSON.parse(text);
  if (j && typeof j.packages === "object") {
    for (const [key, v] of Object.entries<any>(j.packages)) {
      if (!key || !v?.version) continue; // "" is the root project
      const idx = key.lastIndexOf("node_modules/");
      if (idx < 0) continue; // workspace folders
      add(out, v.name ?? key.slice(idx + "node_modules/".length), String(v.version));
    }
    return;
  }
  // lockfileVersion 1
  const walk = (deps: any) => {
    for (const [name, v] of Object.entries<any>(deps ?? {})) {
      if (v?.version) add(out, name, String(v.version));
      if (v?.dependencies) walk(v.dependencies);
    }
  };
  walk(j?.dependencies);
}

/** bun.lock is JSON with trailing commas. */
function parseBunLock(text: string, out: Map<string, LockedPackage>) {
  const json = text.replace(/,(\s*[}\]])/g, "$1");
  const j = JSON.parse(json);
  for (const v of Object.values<any>(j?.packages ?? {})) {
    if (!Array.isArray(v) || typeof v[0] !== "string") continue;
    const s = splitSpec(v[0]);
    if (s) add(out, s.name, s.rest);
  }
}

function parsePnpmLock(text: string, out: Map<string, LockedPackage>) {
  let inPackages = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      inPackages = /^(packages|snapshots):\s*$/.test(line);
      continue;
    }
    if (!inPackages) continue;
    const m = line.match(/^ {2}['"]?\/?(.+?)['"]?:\s*$/);
    if (!m) continue;
    let key = m[1].replace(/\(.*$/, ""); // peer suffix "(react@18.2.0)"
    if (/^@?[^@/]+(\/[^@/]+)?\/\d/.test(key) && !key.includes("@", 1)) {
      // pnpm v5: "/name/1.2.3" or "/@scope/name/1.2.3"
      const i = key.lastIndexOf("/");
      add(out, key.slice(0, i), key.slice(i + 1));
      continue;
    }
    const s = splitSpec(key);
    if (s) add(out, s.name, s.rest.replace(/_.*$/, ""));
  }
}

function parseYarnLock(text: string, out: Map<string, LockedPackage>) {
  let names: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    if (/^\S/.test(line)) {
      // `"a@^1", a@~1:` or `"a@npm:^1":`
      names = line
        .replace(/:\s*$/, "")
        .split(/,\s*/)
        .map((x) => x.trim().replace(/^"|"$/g, ""))
        .map((spec) => splitSpec(spec.replace(/@npm:/, "@"))?.name ?? "")
        .filter(Boolean);
      continue;
    }
    const m = line.match(/^\s+version:?\s+"?([^"\s]+)"?\s*$/);
    if (m && names.length) {
      add(out, names[0], m[1]);
      names = [];
    }
  }
}

export function parseLockfile(kind: LockfileKind, text: string): LockedPackage[] {
  const out = new Map<string, LockedPackage>();
  if (kind === "package-lock") parsePackageLock(text, out);
  else if (kind === "bun") parseBunLock(text, out);
  else if (kind === "pnpm") parsePnpmLock(text, out);
  else parseYarnLock(text, out);
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
}

// ---------------------------------------------------------------- OSV

export type OsvSeverity = "critical" | "high" | "medium" | "low" | "unknown";

/** Severity from an OSV record: GitHub's label when present, else the CVSS base score. */
export function osvSeverity(v: any): OsvSeverity {
  const label = String(v?.database_specific?.severity ?? "").toLowerCase();
  if (label === "critical" || label === "high" || label === "low") return label;
  if (label === "moderate" || label === "medium") return "medium";
  for (const s of v?.severity ?? []) {
    const score = Number(String(s?.score ?? "").match(/^\d+(\.\d+)?$/)?.[0]);
    if (Number.isFinite(score)) return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";
  }
  return "unknown";
}
