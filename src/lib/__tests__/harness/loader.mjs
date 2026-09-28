import { existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const srcRoot = path.resolve(here, "../../..");
const stubs = {
  "@tanstack/react-start": pathToFileURL(path.join(here, "stub-start.mjs")).href,
  "@/integrations/supabase/auth-middleware": pathToFileURL(path.join(here, "stub-auth.mjs")).href,
};

function withTs(p) {
  for (const cand of [p, `${p}.ts`, `${p}.tsx`, path.join(p, "index.ts")]) {
    if (existsSync(cand) && !cand.endsWith("/")) return cand;
  }
  return null;
}

export async function resolve(specifier, context, next) {
  if (stubs[specifier]) return { url: stubs[specifier], shortCircuit: true };
  if (specifier.startsWith("@/")) {
    const f = withTs(path.join(srcRoot, specifier.slice(2)));
    if (f) return { url: pathToFileURL(f).href, shortCircuit: true };
  }
  if ((specifier.startsWith("./") || specifier.startsWith("../")) && context.parentURL?.startsWith("file:")) {
    const base = path.dirname(fileURLToPath(context.parentURL));
    const f = withTs(path.resolve(base, specifier));
    if (f && !/\.(m?js|json)$/.test(specifier)) return { url: pathToFileURL(f).href, shortCircuit: true };
  }
  return next(specifier, context);
}
