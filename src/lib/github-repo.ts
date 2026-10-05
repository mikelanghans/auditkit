// Shared GitHub repo URL parsing and "is this the right repo?" hints.
// No imports, so tests can load it directly.

const NAME = /^[A-Za-z0-9_.-]{1,100}$/;

/**
 * Accepts only GitHub references:
 *   https://github.com/owner/repo(.git)(/tree/…)   github.com/owner/repo
 *   git@github.com:owner/repo.git                  owner/repo
 * Anything else (another host, a website URL, a single word) is rejected
 * instead of being guessed at.
 */
export function parseGithubRepo(raw: string): { owner: string; repo: string } | null {
  const s = String(raw ?? "").trim();
  if (!s) return null;
  let path: string | null = null;
  const ssh = /^git@github\.com:(.+)$/i.exec(s);
  if (ssh) path = ssh[1];
  else if (/^(https?:\/\/)?(www\.)?github\.com\//i.test(s)) {
    try {
      const u = new URL(/^https?:\/\//i.test(s) ? s : `https://${s}`);
      if (!/^(www\.)?github\.com$/i.test(u.hostname)) return null;
      path = u.pathname.replace(/^\/+/, "");
    } catch {
      return null;
    }
  } else if (/^[^/\s:]+\/[^/\s:]+\/?$/.test(s) && !/\./.test(s.split("/")[0])) {
    // Bare owner/repo. An owner with a dot looks like a domain (example.com/x).
    path = s;
  }
  if (!path) return null;
  const [owner, repoRaw] = path.split("/");
  const repo = (repoRaw ?? "").replace(/\.git$/i, "");
  if (!owner || !repo || !NAME.test(owner) || !NAME.test(repo)) return null;
  return { owner, repo };
}

/** Canonical key for a repo, used to remember confirmations: "owner/repo", lowercase. */
export function repoKey(owner: string, repo: string): string {
  return `${owner}/${repo}`.toLowerCase();
}

export function siteHost(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const u = new URL(/^https?:\/\//i.test(url.trim()) ? url.trim() : `https://${url.trim()}`);
    return u.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

export type SiteMatch = { match: "yes" | "no" | "unknown"; note: string };

/**
 * Evidence that a repo belongs to the audited website: the repo's homepage
 * field, a CNAME file, or the domain appearing in files we already read.
 * "no" means we looked and found nothing; it's a warning, not proof.
 */
export function judgeSiteMatch(input: {
  siteUrl: string | null | undefined;
  homepage?: string | null;
  cname?: string | null;
  texts?: string[];
  searchHits?: number | null;
  /** The auditor already confirmed this repo belongs to the audit. */
  confirmed?: boolean;
}): SiteMatch {
  const host = siteHost(input.siteUrl);
  if (!host) return { match: "unknown", note: "The audit has no website, so the repo couldn't be matched to one." };
  if (siteHost(input.homepage) === host) return { match: "yes", note: `The repo's homepage is ${host}.` };
  if (input.cname && input.cname.trim().toLowerCase().replace(/^www\./, "") === host)
    return { match: "yes", note: `The repo's CNAME file points at ${host}.` };
  if ((input.texts ?? []).some((t) => t.toLowerCase().includes(host))) return { match: "yes", note: `The repo's code mentions ${host}.` };
  if (typeof input.searchHits === "number" && input.searchHits > 0) return { match: "yes", note: `GitHub code search finds ${host} in the repo.` };
  if (input.confirmed) return { match: "yes", note: `You confirmed this repo belongs to ${host}.` };
  if (input.searchHits === null || input.searchHits === undefined)
    return { match: "unknown", note: `Couldn't confirm this repo belongs to ${host} (code search unavailable).` };
  return {
    match: "no",
    note: `Nothing in this repo mentions ${host}: not its homepage, a CNAME file, or its code. Check it's the right repository for this audit.`,
  };
}
