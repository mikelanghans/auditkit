// Service-role client stand-in: tests set globalThis.__TEST_ADMIN__ to a fake client.
export const supabaseAdmin = new Proxy({}, {
  get(_, prop) {
    const c = globalThis.__TEST_ADMIN__;
    if (!c) throw new Error("__TEST_ADMIN__ not set");
    const v = c[prop];
    return typeof v === "function" ? v.bind(c) : v;
  },
});
