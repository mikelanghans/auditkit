// End-to-end tests for AuditKit itself. They run against a LOCAL Supabase
// (`supabase start`) and the dev server on 127.0.0.1, with every browser
// request outside this machine blocked and scan targets on the reserved
// .invalid domain, so no client system is ever contacted.
//
//   npx supabase start
//   eval "$(npx supabase status -o env | sed 's/^/export E2E_SUPABASE_/; s/E2E_SUPABASE_API_URL/E2E_SUPABASE_URL/')"
//   npx playwright test -c e2e
import { defineConfig, devices } from "@playwright/test";
import { ANON_KEY, APP_URL, SERVICE_KEY, SUPABASE_URL } from "./env";

export default defineConfig({
  testDir: "./tests",
  globalSetup: "./global-setup.ts",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 120_000,
  expect: { timeout: 20_000 },
  reporter: process.env.CI ? [["list"], ["html", { open: "never", outputFolder: "../playwright-report" }]] : "list",
  use: {
    baseURL: APP_URL,
    storageState: new URL("./.state/owner.json", import.meta.url).pathname,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    acceptDownloads: true,
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "npx vite dev --host 127.0.0.1 --port 8080 --strictPort",
    cwd: "..",
    url: `${APP_URL}/auth`,
    timeout: 180_000,
    reuseExistingServer: !process.env.CI,
    env: {
      VITE_SUPABASE_URL: SUPABASE_URL,
      VITE_SUPABASE_PUBLISHABLE_KEY: ANON_KEY,
      SUPABASE_URL,
      SUPABASE_PUBLISHABLE_KEY: ANON_KEY,
      SUPABASE_SERVICE_ROLE_KEY: SERVICE_KEY,
      PUBLIC_APP_URL: APP_URL,
    },
  },
});
