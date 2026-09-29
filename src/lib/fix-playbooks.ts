// Remediation playbooks for the fix-prompt generator. No imports, so tests can
// load this module directly.
//
// The model writes the prompt; these are the technical requirements it must
// follow for items where generic advice goes wrong in practice (a CSP that
// breaks a server-rendered app, HSTS with includeSubDomains on a domain that
// isn't all-HTTPS, a leaked key "fixed" in code but never rotated). Each is
// conditional on what the app actually is, so nothing here names a provider
// the evidence doesn't show.

type Playbook = { id: string; text: string };

const WHERE_HEADERS = `Where to set response headers depends on the app. Inspect the project to determine which case applies:
- Server-rendered app with a server entry (TanStack Start: src/server.ts or a global request middleware; Next.js: middleware or next.config headers; Express/Hono: middleware): set the header there on every HTML response.
- Static single-page app (Vite build served as files): set it at the hosting layer (vercel.json "headers", Netlify or Cloudflare Pages "_headers" file, or the host's header settings).
- If the host offers no way to set headers, report that instead of inventing a workaround. Do not fall back to a <meta> tag for headers a meta tag can't express (HSTS, X-Frame-Options, frame-ancestors).
Only change headers in production: the Lovable editor and similar tools show the app in an iframe, so framing restrictions must not apply to the preview.`;

const CSP: Playbook = {
  id: "csp",
  text: `${WHERE_HEADERS}

Content-Security-Policy requirements:
1. First find every origin the app really loads from (scripts, styles, fonts, images, API and websocket targets) by searching the code and config, and list them before writing the policy. Never guess origins.
2. script-src must not contain 'unsafe-inline', 'unsafe-eval' or wildcards. Server-rendered frameworks (TanStack Start, Next.js, Remix) emit inline scripts on every page, so use a per-request nonce: generate a random value per request, put 'nonce-<value>' in script-src and the same nonce attribute on every inline script the framework renders. A static Vite build normally has no inline scripts, so script-src 'self' plus any listed origins is enough there.
3. style-src 'self' 'unsafe-inline' is an acceptable trade-off for component libraries that inject styles; say that scripts are what matter.
4. Always include: object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none' (or 'self' if the app frames itself).
5. connect-src: 'self' plus only the API origins found in step 1. If the app uses Supabase (a supabase client or SUPABASE_URL is present), that means https://<project-ref>.supabase.co and, if it uses realtime, wss://<project-ref>.supabase.co.
6. Roll out as Content-Security-Policy-Report-Only first. Only after the browser console shows no violations while using the app, rename the header to Content-Security-Policy.
7. Verify with DevTools → Network → the document request → Response Headers, and the console.`,
};

const HSTS: Playbook = {
  id: "hsts",
  text: `${WHERE_HEADERS}

Strict-Transport-Security requirements:
- Send only on HTTPS responses: Strict-Transport-Security: max-age=31536000
- Add includeSubDomains only after confirming every subdomain serves HTTPS; otherwise browsers will refuse those subdomains for a year.
- Do not add preload unless the owner explicitly wants to submit to the preload list (it is hard to undo).
- Make sure http:// redirects to https:// (301) at the host.
- Verify with curl -sI https://<domain> | grep -i strict-transport-security.`,
};

const FRAME: Playbook = {
  id: "frame",
  text: `${WHERE_HEADERS}

Clickjacking protection requirements:
- Send X-Frame-Options: DENY (SAMEORIGIN only if the app deliberately frames its own pages), and also frame-ancestors 'none' in the CSP if one exists; modern browsers use frame-ancestors.
- Production only, so the builder's preview iframe keeps working.
- Verify the header on the document response, and that embedding the page in an iframe on another origin is blocked.`,
};

const SIMPLE_HEADER: Record<string, Playbook> = {
  xcontent_type: {
    id: "nosniff",
    text: `${WHERE_HEADERS}

Send X-Content-Type-Options: nosniff on all responses. Check that JS, CSS and JSON are served with correct Content-Type values, since nosniff makes browsers enforce them. Verify with curl -sI.`,
  },
  referrer_policy: {
    id: "referrer",
    text: `${WHERE_HEADERS}

Send Referrer-Policy: strict-origin-when-cross-origin. Use no-referrer instead if any URL in the app can carry tokens, reset codes or other sensitive values. Verify with curl -sI.`,
  },
  permissions_policy: {
    id: "permissions",
    text: `${WHERE_HEADERS}

Permissions-Policy requirements:
1. First search the code and dependencies for browser features the app uses: camera/microphone (getUserMedia), geolocation, payments (Payment Request, Apple Pay / Google Pay, Stripe), passkeys / WebAuthn, fullscreen, autoplay or embedded video, clipboard, USB/serial. List what was found before changing anything.
2. Disable only unused features, from this set: camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), midi=(), gyroscope=(), magnetometer=(), accelerometer=(), display-capture=(), xr-spatial-tracking=(), publickey-credentials-get=(). Do not add obsolete or unsupported names (battery, document-domain, ambient-light-sensor, navigation-override, speaker-selection).
3. A feature the app uses is allowed only for the app and the specific provider it needs, e.g. payment=(self "https://js.stripe.com"). Never use *.
4. Leave fullscreen, autoplay and encrypted-media alone if the app embeds video.
5. Verify: the header is on the page response, and login (including passkeys), payments and any camera/video features still work.`,
  },
};

const CORS: Playbook = {
  id: "cors",
  text: `CORS requirements:
- Never send Access-Control-Allow-Origin: * on endpoints that use cookies or Authorization headers, and never combine * with Access-Control-Allow-Credentials: true.
- Keep an explicit allowlist of the app's own origins (production, staging, local dev). Echo the request Origin back only when it is on the list, and add Vary: Origin.
- Handle OPTIONS preflight with the same allowlist; list only the methods and headers the endpoint needs.
- Apply this to every place responses are built: API routes, server functions, and edge functions (Supabase edge functions usually define a shared corsHeaders object; fix it there).
- Verify: a fetch from an unlisted origin is blocked in the browser; the app itself still works.`,
};

const HEADERS_ALL: Playbook = {
  id: "headers",
  text: `${WHERE_HEADERS}

Set these together, production only: Strict-Transport-Security: max-age=31536000 (add includeSubDomains only if every subdomain is HTTPS); X-Content-Type-Options: nosniff; Referrer-Policy: strict-origin-when-cross-origin; X-Frame-Options: DENY; a Permissions-Policy that disables only unused features. Treat Content-Security-Policy separately: it needs an origin inventory, a nonce for server-rendered apps, and a Report-Only rollout. Verify with curl -sI.`,
};

const LEAKED_SECRET: Playbook = {
  id: "secret",
  text: `Leaked-secret requirements (order matters):
1. Rotate first. The key is already public: revoke or roll it in the provider's dashboard before touching code. A code change alone does not un-leak it.
2. Move every use of the secret to server-side code (a server function, API route or edge function) and call that from the browser instead.
3. Rename the environment variable so it has no client-exposed prefix (VITE_, NEXT_PUBLIC_, PUBLIC_, EXPO_PUBLIC_) and store the new value only in server-side secrets.
4. Redeploy, then confirm the built JavaScript no longer contains the key (search the served bundles or the build output for its prefix).
5. Check the provider's logs for use of the old key since it was exposed.
Public-by-design keys (Supabase anon/publishable, Stripe publishable) are not secrets and must stay in the client; do not "fix" those.`,
};

const GIT_HISTORY: Playbook = {
  id: "git-history",
  text: `Secrets-in-git-history requirements:
1. Rotate every secret that was ever committed, even if it has since been deleted; anyone with a clone still has it.
2. Remove any committed .env files from the repo and add .env and .env.* (keeping .env.example) to .gitignore.
3. Rewriting history (git filter-repo) is optional after rotation and requires everyone to re-clone; say so rather than doing it automatically.
4. Add secret scanning going forward (GitHub push protection or a pre-commit gitleaks hook).`,
};

const RLS: Playbook = {
  id: "rls",
  text: `Supabase Row Level Security requirements:
1. Enable RLS on every table in the public schema: ALTER TABLE ... ENABLE ROW LEVEL SECURITY. Put changes in a new migration file.
2. Write explicit policies per operation (SELECT, INSERT, UPDATE, DELETE) scoped to the user, e.g. USING (auth.uid() = user_id) and WITH CHECK (auth.uid() = user_id). Never use USING (true) for user-owned data.
3. Revoke write grants the anon role doesn't need: REVOKE INSERT, UPDATE, DELETE ON <table> FROM anon;
4. For reference data that is truly public, allow SELECT only.
5. Verify with the anon key and no session: selects on user tables return no rows, and inserts/updates/deletes are rejected. Then check a signed-in user sees only their own rows.`,
};

const DEFINER: Playbook = {
  id: "definer",
  text: `SECURITY DEFINER function requirements:
1. For each function listed in the evidence: REVOKE EXECUTE ON FUNCTION <name>(<args>) FROM anon, PUBLIC; then GRANT EXECUTE ... TO authenticated only if signed-in users need it.
2. Inside the function, check the caller (auth.uid()) before touching data, and SET search_path = public (or an explicit schema) on the function.
3. If a function doesn't need to bypass RLS, change it to SECURITY INVOKER.
4. Put the changes in a new migration. Verify: calling /rest/v1/rpc/<name> with only the anon key returns a permission error.`,
};

const STORAGE_LIST: Playbook = {
  id: "storage",
  text: `Storage listing requirements:
1. Replace permissive SELECT policies on storage.objects with ones scoped to the owner, e.g. bucket_id = '<bucket>' AND (storage.foldername(name))[1] = auth.uid()::text, for files stored under a per-user folder.
2. Keep buckets private and serve files through signed URLs with short expiry.
3. Verify: listing the bucket with only the anon key returns nothing, and a signed-in user sees only their own files.`,
};

const BY_KEY: Record<string, Playbook> = {
  csp_header: CSP,
  hsts_header: HSTS,
  xframe_header: FRAME,
  cors_policy: CORS,
  bundle_secrets: LEAKED_SECRET,
  vite_exposure: LEAKED_SECRET,
  anon_write_access: RLS,
  anon_callable_definer_functions: DEFINER,
  storage_anon_listing: STORAGE_LIST,
  ...SIMPLE_HEADER,
};

const BY_TITLE: Record<string, Playbook> = {
  "Security headers configured": HEADERS_ALL,
  "Content Security Policy set": CSP,
  "CORS policy configured correctly": CORS,
  "No service role key in client-side code": LEAKED_SECRET,
  "No secrets in client-side bundle": LEAKED_SECRET,
  "No secrets in git history": GIT_HISTORY,
  "RLS enabled on all tables": RLS,
  "Anon key permissions scoped correctly": RLS,
  "No direct table access without auth check": RLS,
  "Anon role cannot write to tables": RLS,
};

export function playbookFor(item: {
  checklist_key?: string | null;
  title?: string | null;
}): Playbook | null {
  return (
    (item.checklist_key && BY_KEY[item.checklist_key]) ||
    (item.title && BY_TITLE[item.title]) ||
    null
  );
}
