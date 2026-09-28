// Minimal createServerFn: runs the validator and handler directly. When a
// server function calls another one without a context (as the real runtime
// allows), the current test context is reused.
export function createServerFn() {
  let validator = (d) => d;
  const b = {
    middleware() { return b; },
    inputValidator(fn) { validator = fn; return b; },
    handler(h) {
      return async (opts = {}) => h({ data: validator(opts.data), context: opts.context ?? globalThis.__TEST_CONTEXT__ });
    },
  };
  return b;
}
export function useServerFn(fn) { return fn; }
