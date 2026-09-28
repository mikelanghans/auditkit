// Pure helpers for turning package.json manifests into the exact
// name → versions set the advisory lookup needs. There are no imports, so
// tests can load this module directly.

/** Sections that end up installed in a normal `npm install`. */
export const INSTALLED_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies"] as const;

export type ManifestDeps = {
  /** real package name → set of concrete versions to check */
  query: Record<string, string[]>;
  /** "manifest:name@spec" entries we could not reduce to a concrete version */
  unresolved: string[];
  /** declared name (may be an alias) → real package name, for display */
  aliasOf: Record<string, string>;
};

const CONCRETE = /(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/;

/**
 * Reduce a declared spec to the version we query for. A range like ^1.2.3
 * becomes its floor (1.2.3), which is the lowest version it could install.
 * Local packages (workspace:, file:, link:) return "local": they are scanned
 * through their own package.json. Specs with no concrete version (latest, *,
 * git, URLs, dist-tags) return null, because they cannot be checked honestly.
 */
export function resolveSpec(name: string, spec: string): { name: string; version: string } | "local" | null {
  let realName = name;
  let s = String(spec ?? "").trim();
  const alias = /^npm:((?:@[^/@]+\/)?[^@]+)@(.+)$/.exec(s);
  if (alias) {
    realName = alias[1];
    s = alias[2].trim();
  }
  if (/^(workspace:|file:|link:|portal:)/i.test(s)) return "local";
  if (/^(patch:|git\+|git:|github:|https?:)/i.test(s)) return null;
  if (s.includes("/") && !alias) return null; // owner/repo shorthand
  const m = CONCRETE.exec(s);
  if (m) return { name: realName, version: m[1] };
  // Short ranges like ^18, ~4.17 or 5.x: query their floor.
  const short = /^[\^~>=v\s]*(\d+)(?:\.(\d+))?(?:\.[xX*])?$/.exec(s);
  if (short) return { name: realName, version: `${short[1]}.${short[2] ?? "0"}.0` };
  return null;
}

export function collectDeps(manifests: { path: string; json: any }[]): ManifestDeps {
  const query: Record<string, string[]> = {};
  const unresolved: string[] = [];
  const aliasOf: Record<string, string> = {};
  for (const { path, json } of manifests) {
    for (const section of INSTALLED_SECTIONS) {
      const deps = json?.[section];
      if (!deps || typeof deps !== "object") continue;
      for (const [name, spec] of Object.entries(deps)) {
        const r = resolveSpec(name, String(spec));
        if (r === "local") continue;
        if (!r) {
          unresolved.push(`${path}: ${name}@${String(spec)}`);
          continue;
        }
        if (r.name !== name) aliasOf[name] = r.name;
        const list = (query[r.name] ??= []);
        if (!list.includes(r.version)) list.push(r.version);
      }
    }
  }
  return { query, unresolved, aliasOf };
}
