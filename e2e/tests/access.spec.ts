// Signed-out visitors can't reach audit pages or data.
import { test, expect } from "@playwright/test";
import { blockNonLocal } from "../guard";

test.use({ storageState: { cookies: [], origins: [] } });

test("signed-out visitors are sent to sign in", async ({ page, context }) => {
  await blockNonLocal(context);
  await page.goto("/dashboard");
  await expect(page).toHaveURL(/\/auth/);
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
});
