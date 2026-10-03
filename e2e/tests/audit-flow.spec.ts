// The main audit flow, in order: scope → capture → full audit → trail → report.
import { test, expect } from "../fixtures";

test.describe.configure({ mode: "serial" });

test("targets and scope are saved and logged", async ({ page, run }) => {
  await page.goto(`/audits/${run.auditId}`);
  await page.getByText("Targets & scope").click();
  // The audit's website was carried over as its first target.
  await expect(page.getByText("https://canary.invalid").first()).toBeVisible();

  await page.getByRole("combobox").filter({ hasText: "Website" }).first().click();
  await page.getByRole("option", { name: "GitHub repo" }).click();
  await page.getByPlaceholder("https://github.com/owner/repo").fill("github.com/acme-e2e/canary.git");
  await page.getByRole("button", { name: "Add" }).click();
  await expect(page.getByText("https://github.com/acme-e2e/canary")).toBeVisible();

  await page.getByPlaceholder("Name, role").fill("E2E Tester, CTO");
  await page.locator('input[type="date"]').first().fill("2026-10-01");
  await page.getByRole("button", { name: "Save scope" }).click();
  await expect(page.getByText("Scope saved.")).toBeVisible();
  await expect(page.getByText("Authorized", { exact: true })).toBeVisible();
});

test("captured evidence is redacted, then triaged to a finding", async ({ page, run }) => {
  await page.goto(`/audits/${run.auditId}`);
  await page.getByText("Capture inbox").click();
  await page.getByPlaceholder("Title (optional)").first().fill("E2E captured request");
  await page
    .getByPlaceholder("Paste a note, a cURL command, a raw request/response…")
    .first()
    .fill('curl https://canary.invalid/api -H "Authorization: Bearer sk_live_51E2eE2eE2eE2eE2eE2eE2eE2eE2eE2eE2e00"');
  await page.getByRole("button", { name: "Capture" }).click();
  await expect(page.getByText("Captured to the inbox.")).toBeVisible();

  const item = page.getByText("E2E captured request");
  await item.click();
  await expect(page.getByText(/REDACTED/).first()).toBeVisible();
  await expect(page.getByText("sk_live_51E2eE2eE2e")).toHaveCount(0);

  await page.getByRole("combobox").filter({ hasText: "Attach to checklist item…" }).click();
  await page.getByRole("option").first().click();
  await page.getByRole("button", { name: "Attach" }).click();
  await expect(page.getByText("Attached.")).toBeVisible();
  await expect(page.getByText("Nothing waiting to be triaged.")).toBeVisible();
});

test("a full audit runs every step and records what couldn't run", async ({ page, run }) => {
  await page.goto(`/audits/${run.auditId}`);
  await page.getByRole("button", { name: "Run full audit" }).click();
  await page.getByRole("button", { name: "Start" }).click();
  // canary.invalid doesn't exist and no keys are given, so steps fail or
  // don't run; the run must still close and say so.
  await expect(page.getByText(/Full audit (complete|finished with gaps)/)).toBeVisible({ timeout: 90_000 });

  await page.goto(`/audits/${run.auditId}/activity`);
  await expect(page.getByText("Full audit").first()).toBeVisible();
  await expect(page.getByText(/not run/).first()).toBeVisible();
});

test("the audit trail verifies", async ({ page, run }) => {
  await page.goto(`/audits/${run.auditId}/activity`);
  await expect(page.getByText(/Chain verified · \d+ events/)).toBeVisible();
  await expect(page.getByText(/Scope set|Target added|Evidence added|Scan finished/).first()).toBeVisible();
});

test("the report is built from the data and exports Markdown", async ({ page, run }) => {
  await page.goto(`/audits/${run.auditId}/report`);
  await expect(page.getByRole("heading", { name: "Scope and method" })).toBeVisible();
  await expect(page.getByText("E2E Tester, CTO", { exact: false })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Appendix: evidence index" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Appendix: audit trail" })).toBeVisible();
  await expect(page.getByText(/Verified: \d+ recorded events/)).toBeVisible();

  const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Markdown" }).click()]);
  const path = await download.path();
  const { readFileSync } = await import("node:fs");
  const md = readFileSync(path!, "utf8");
  expect(md).toContain("# Security Audit Report");
  expect(md).toContain("## Scope and method");
  expect(md).toContain("E2E Tester, CTO");
  expect(md).not.toContain("sk_live_51E2eE2eE2e");
});
