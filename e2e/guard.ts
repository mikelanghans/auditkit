// Every browser request outside this machine is refused, so a test (or a bug
// it exercises) can't reach a real service. Google Fonts are allowed only as
// styling; nothing else leaves localhost.
import type { BrowserContext } from "@playwright/test";

const ALLOWED = new Set(["127.0.0.1", "localhost", "fonts.googleapis.com", "fonts.gstatic.com"]);

export async function blockNonLocal(ctx: BrowserContext) {
  await ctx.route("**/*", (route) => {
    const url = route.request().url();
    if (url.startsWith("data:") || url.startsWith("blob:")) return route.continue();
    let host = "";
    try {
      host = new URL(url).hostname;
    } catch {
      return route.abort();
    }
    return ALLOWED.has(host) ? route.continue() : route.abort("blockedbyclient");
  });
}
