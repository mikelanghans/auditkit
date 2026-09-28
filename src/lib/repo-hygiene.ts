// Pure helpers for the repo scan. There are no imports, so tests can load this
// module directly.

/**
 * True when .gitignore actually ignores a file named `.env`. Lines are
 * processed in order like git does, so a later `!.env` un-ignores it.
 * `.envrc`, `.env.local` or `.environment-cache/` on their own do NOT ignore
 * `.env`, and neither does a directory-only pattern like `.env/`.
 */
export function gitignoreIgnoresEnv(gitignore: string): boolean {
  let ignored = false;
  for (const raw of gitignore.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const negated = line.startsWith("!");
    const pattern = negated ? line.slice(1) : line;
    if (/^(\/|\*\*\/)?(\.env|\.env\*|\*\.env)$/.test(pattern)) ignored = !negated;
  }
  return ignored;
}

/** A committed env file (not a documented example/sample/template). */
export function isEnvFilePath(path: string): boolean {
  return /(^|\/)\.env(\..+)?$/.test(path) && !/\.env\.(example|sample|template|dist)$/i.test(path);
}
