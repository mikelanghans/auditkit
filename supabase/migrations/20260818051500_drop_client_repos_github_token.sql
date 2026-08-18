-- Drop the plaintext GitHub PAT column from client_repos.
--
-- Rationale: nothing in the application ever read this column back. Every code
-- path that needs a PAT either re-prompts the auditor or reads the token from
-- sessionStorage (src/lib/repo-token-cache.ts). The column therefore stored
-- live third-party credentials at rest, in plaintext, in exchange for no
-- functionality — the worst possible trade.
--
-- Any values already in this column should be treated as compromised: the
-- tokens were stored unencrypted and are being dropped without being rotated
-- by this migration. Rotate any PAT that was saved through the repo launcher.
--
-- The write side was removed in src/components/repo-launcher.tsx in the same
-- change, so this is safe to apply without a code/DB ordering constraint.

ALTER TABLE public.client_repos DROP COLUMN IF EXISTS github_token;
