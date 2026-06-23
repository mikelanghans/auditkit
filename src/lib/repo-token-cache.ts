// Session-only cache for GitHub PATs. Never persisted to the database or localStorage.
// Cleared when the browser tab closes.

const PREFIX = "repo-pat:";

function safeStorage(): Storage | null {
  try {
    if (typeof window === "undefined") return null;
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export function getCachedRepoToken(repoId: string | null | undefined): string | null {
  if (!repoId) return null;
  const s = safeStorage();
  if (!s) return null;
  return s.getItem(PREFIX + repoId);
}

export function setCachedRepoToken(repoId: string | null | undefined, token: string): void {
  if (!repoId || !token) return;
  const s = safeStorage();
  if (!s) return;
  try { s.setItem(PREFIX + repoId, token); } catch { /* quota / private mode */ }
}

export function clearCachedRepoToken(repoId: string | null | undefined): void {
  if (!repoId) return;
  const s = safeStorage();
  if (!s) return;
  s.removeItem(PREFIX + repoId);
}

export function clearAllCachedRepoTokens(): void {
  const s = safeStorage();
  if (!s) return;
  const toRemove: string[] = [];
  for (let i = 0; i < s.length; i++) {
    const k = s.key(i);
    if (k && k.startsWith(PREFIX)) toRemove.push(k);
  }
  toRemove.forEach((k) => s.removeItem(k));
}
