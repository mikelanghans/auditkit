# Canary: a deliberately vulnerable target

AuditKit's planted-flaw suite (`src/lib/__tests__/canary.test.mts`) runs the
scanners against fakes on every test run. This folder is the live version: a
throwaway Supabase project and site you own, with the same flaws planted, to
run a real "Run full audit" against after deploys and scanner changes.

**Never put real data or real keys in it. Delete it when you're done with a round of testing.**

## Set up

1. Create a new, empty Supabase project (free tier is fine). Call it `auditkit-canary`.
2. In its SQL editor, run `supabase-canary.sql`.
3. Deploy any small site (a Lovable starter works) and add to it:
   - no security headers at all;
   - a client-side constant `const STRIPE = "sk_live_51CanaryCanaryCanaryCanaryCanaryCanary00"` (a fake key in the live-key format);
   - a `public/.env` file containing `SUPABASE_SERVICE_ROLE_KEY=canary`;
   - production source maps on (`build.sourcemap: true` in Vite).
4. In AuditKit, create a client "Canary" and an audit for the site, add the
   site and the Supabase project as targets, then **Run full audit** with the
   project's anon key, service-role key and a Management API PAT.

## What must come out as FAIL

| Check | Planted |
|---|---|
| RLS enabled on all tables | `payments` has RLS off |
| Anon key permissions scoped / no direct table access / no unauthenticated user data | `profiles` readable by anyone (`USING (true)`) |
| Anon role cannot write to tables | anon has INSERT/UPDATE/DELETE on `payments` |
| No public storage buckets / storage files can't be listed | `uploads` bucket is public and listable |
| No SECURITY DEFINER functions callable without auth | `admin_reset()` executable by anon |
| Sensitive columns encrypted at rest | `users_private.password` is plain text |
| Minimum password length / leaked password protection / email confirmation | set in Authentication settings: min length 6, HIBP off, confirm email off |
| Website: headers, CSP, bundle secrets, source maps, exposed files | from the site setup above |

Anything that comes out **pass** is a scanner bug. Anything **inconclusive**
should say exactly what it couldn't see.
