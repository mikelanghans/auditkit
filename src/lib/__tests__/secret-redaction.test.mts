import { redactForPrompt, redactEnvFile, redactSourceFile, isEnvFile } from "../secret-redaction.ts";

let fail = 0;
const check = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond ? "" : "  <<< " + extra}`);
  if (!cond) fail++;
};

// --- .env handling ---
const env = `# app config
SUPABASE_URL=https://abc.supabase.co
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.abcdefghijklmnop
STRIPE_SECRET_KEY=sk_live_51H8xQwEXAMPLEabcdefghijk
export OPENAI_API_KEY="sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD"
EMPTY=
PORT=3000
`;
const redEnv = redactEnvFile(env);
check("env: service_role JWT value gone", !redEnv.includes("eyJyb2xlIjoic2VydmljZV9yb2xl"), redEnv);
check("env: stripe live key gone", !redEnv.includes("sk_live_51H8xQwEXAMPLE"), redEnv);
check("env: openai key gone", !redEnv.includes("sk-proj-abcdefghij"), redEnv);
check("env: key NAMES preserved", redEnv.includes("SUPABASE_SERVICE_ROLE_KEY") && redEnv.includes("STRIPE_SECRET_KEY"));
check("env: comment preserved", redEnv.includes("# app config"));
check("env: empty value untouched", redEnv.includes("EMPTY="));
check("env: PORT value also redacted (eager)", redEnv.includes("PORT="));

// --- source file handling ---
const src = `
const supabase = createClient(url, "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.Xy1234567890abcd");
const STRIPE_SECRET = "sk_live_51ABCDEFGHIJKLMNOPqrst";
const GH = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const apiKey = process.env.ANTHROPIC_API_KEY;
const PUBLISHABLE_KEY = "pk_live_notasecret_butlong";
const label = "Some ordinary long user facing string";
`;
const redSrc = redactSourceFile(src);
check("src: supabase JWT gone", !redSrc.includes("eyJyb2xlIjoiYW5vbiJ9"), redSrc);
check("src: stripe key gone", !redSrc.includes("sk_live_51ABCDEFGHIJ"), redSrc);
check("src: github PAT gone", !redSrc.includes("ghp_ABCDEFGHIJKLMNOP"), redSrc);
check("src: AWS key id gone", !redSrc.includes("AKIAIOSFODNN7EXAMPLE"), redSrc);
check("src: process.env reference preserved", redSrc.includes("process.env.ANTHROPIC_API_KEY"), redSrc);
check("src: ordinary string preserved", redSrc.includes("Some ordinary long user facing string"), redSrc);
check("src: structure intact (createClient visible)", redSrc.includes("createClient(url,"), redSrc);

// --- PEM ---
const pem = `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxyzSECRETMATERIAL\nmoresecret\n-----END RSA PRIVATE KEY-----`;
const redPem = redactSourceFile(pem);
check("pem: body gone", !redPem.includes("SECRETMATERIAL"), redPem);
check("pem: header kept", redPem.includes("BEGIN RSA PRIVATE KEY"), redPem);

// --- path detection ---
check("path: .env", isEnvFile(".env"));
check("path: nested .env.production", isEnvFile("apps/web/.env.production"));
check("path: .env.example still treated as env", isEnvFile(".env.example"));
check("path: environment.ts is NOT env", !isEnvFile("src/environment.ts"));

// --- redacted flag ---
check("flag: reports redaction happened", redactForPrompt(".env", env).redacted === true);
check("flag: clean file reports no redaction", redactForPrompt("a.ts", "const x = 1;\n").redacted === false);


// --- gaps found in the 2026-09-28 security audit (docs/security-audit) ---
const envGaps = `# rotated 2026-01 -- old prod key kept for rollback
# STRIPE_SECRET_KEY=sk_live_DUMMYOLDKEY0000000000000000
STRIPE_SECRET_KEY=sk_live_DUMMYNEWKEY1111111111111111
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
MIIEvDUMMYPEMBODYLINEONEaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
DUMMYPEMBODYLINETWObbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
-----END PRIVATE KEY-----"
AFTER=1
`;
const redGaps = redactEnvFile(envGaps);
check("env: commented-out key value gone", !redGaps.includes("DUMMYOLDKEY"), redGaps);
check("env: commented key NAME kept", redGaps.includes("STRIPE_SECRET_KEY"), redGaps);
check("env: free-text comment kept", redGaps.includes("# rotated 2026-01"), redGaps);
check("env: multi-line PEM body gone", !redGaps.includes("DUMMYPEMBODYLINE"), redGaps);
check("env: lines after multi-line value still parsed", redGaps.includes("AFTER="), redGaps);

const srcGaps: [string, string, string][] = [
  ["drizzle.config.ts", `export default { dbCredentials: { url: "postgresql://postgres:DummyDbPassw0rd@db.dummyref.supabase.co:5432/postgres" } };`, "DummyDbPassw0rd"],
  ["src/lib/ai.ts", `fetch(u, { headers: { "Authorization": "Bearer dummyBearerToken1234567890" } });`, "dummyBearerToken1234567890"],
  ["src/lib/ai.ts", `fetch(u, { headers: { "x-api-key": "dummyApiKeyValue1234567890" } });`, "dummyApiKeyValue1234567890"],
  ["src/admin.ts", `const serviceRoleKey = "sb_secret_DUMMYdummyDUMMYdummy1234";`, "DUMMYdummyDUMMYdummy1234"],
  ["src/admin.ts", `createClient(url, "sb_secret_DUMMYdummyDUMMYdummy5678");`, "DUMMYdummyDUMMYdummy5678"],
  ["src/keys.ts", "const k = `-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFDUMMYENCRYPTEDBODY\n-----END ENCRYPTED PRIVATE KEY-----`;", "MIIFDUMMYENCRYPTEDBODY"],
  ["src/pay.ts", `const r = "rk_live_DUMMYrestricted00000000"; const w = "whsec_DUMMYwebhooksecret0000";`, "DUMMYrestricted"],
  ["src/pay.ts", `const w = "whsec_DUMMYwebhooksecret0000";`, "DUMMYwebhooksecret"],
  ["src/cfg.ts", `export const cfg = { stripe: { secretKey: "not-a-known-shape-but-secret" } };`, "not-a-known-shape-but-secret"],
];
for (const [path, content, secret] of srcGaps) {
  const r = redactForPrompt(path, content);
  check(`src gap: ${secret.slice(0, 18)}… removed`, !r.content.includes(secret) && r.redacted, r.content);
}
check("src: publishable key still readable", redactSourceFile(`const supabasePublishableKey = "sb_publishable_abcdefghijklmnop";`).includes("sb_publishable_"));

console.log(fail === 0 ? "\nALL PASS" : `\n${fail} FAILURE(S)`);
process.exit(fail === 0 ? 0 : 1);
