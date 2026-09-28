// Test-only module loader: lets node run the real server-function handlers
// without the TanStack runtime or Supabase. Used by `npm run test:scanners`.
import { register } from "node:module";
register("./loader.mjs", import.meta.url);
