import { test as base, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { STATE_DIR } from "./env";
import { blockNonLocal } from "./guard";

type Run = { auditId: string; clientId: string; totpSecret: string };

export const test = base.extend<{ run: Run }>({
  run: async ({}, use) => {
    await use(JSON.parse(readFileSync(`${STATE_DIR}/run.json`, "utf8")) as Run);
  },
  context: async ({ context }, use) => {
    await blockNonLocal(context);
    await use(context);
  },
});
export { expect };
