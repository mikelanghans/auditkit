// Lockfile parsing and OSV severity (3.3). Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";

const ids = (pk: { name: string; version: string }[]) => pk.map((p) => `${p.name}@${p.version}`);

test("package-lock v3 and v1: every installed package, nested ones included", async () => {
  const { parseLockfile } = await import("../lockfile-parse.ts");
  const v3 = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { name: "app", version: "1.0.0" },
      "node_modules/lodash": { version: "4.17.20" },
      "node_modules/@scope/pkg": { version: "2.0.0" },
      "node_modules/a/node_modules/minimist": { version: "0.0.8" },
      "packages/web": { version: "0.0.1" },
      "node_modules/local": { version: "file:../local" },
    },
  });
  assert.deepEqual(ids(parseLockfile("package-lock", v3)), ["@scope/pkg@2.0.0", "lodash@4.17.20", "minimist@0.0.8"]);
  const v1 = JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: "1.0.0", dependencies: { b: { version: "2.0.0" } } } } });
  assert.deepEqual(ids(parseLockfile("package-lock", v1)), ["a@1.0.0", "b@2.0.0"]);
});

test("bun.lock (JSONC with trailing commas)", async () => {
  const { parseLockfile } = await import("../lockfile-parse.ts");
  const text = `{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "app", }, },
  "packages": {
    "react": ["react@18.3.1", "", {}, "sha512-x"],
    "@tanstack/react-query": ["@tanstack/react-query@5.59.0", "", { "dependencies": {} }, "sha512-y"],
    "linked": ["linked@workspace:packages/linked", {}],
  },
}`;
  assert.deepEqual(ids(parseLockfile("bun", text)), ["@tanstack/react-query@5.59.0", "react@18.3.1"]);
});

test("pnpm-lock v9, v6 and v5 keys", async () => {
  const { parseLockfile } = await import("../lockfile-parse.ts");
  const v9 = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18
        version: 18.3.1
packages:
  react@18.3.1:
    resolution: {integrity: sha512-x}
  '@babel/core@7.24.0':
    resolution: {integrity: sha512-y}
snapshots:
  react-dom@18.3.1(react@18.3.1):
    dependencies: {}
`;
  assert.deepEqual(ids(parseLockfile("pnpm", v9)), ["@babel/core@7.24.0", "react@18.3.1", "react-dom@18.3.1"]);
  const v6 = `lockfileVersion: '6.0'
packages:
  /lodash@4.17.20:
    resolution: {integrity: x}
  /@scope/a@1.0.0(react@18.0.0):
    resolution: {integrity: y}
`;
  assert.deepEqual(ids(parseLockfile("pnpm", v6)), ["@scope/a@1.0.0", "lodash@4.17.20"]);
  const v5 = `lockfileVersion: 5.4
packages:
  /lodash/4.17.20:
    resolution: {integrity: x}
  /@scope/a/1.0.0:
    resolution: {integrity: y}
`;
  assert.deepEqual(ids(parseLockfile("pnpm", v5)), ["@scope/a@1.0.0", "lodash@4.17.20"]);
});

test("yarn.lock v1 and berry", async () => {
  const { parseLockfile } = await import("../lockfile-parse.ts");
  const v1 = `# yarn lockfile v1

"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/x"

lodash@^4.17.15:
  version "4.17.20"
`;
  assert.deepEqual(ids(parseLockfile("yarn", v1)), ["@babel/code-frame@7.12.13", "lodash@4.17.20"]);
  const berry = `__metadata:
  version: 6

"lodash@npm:^4.17.15":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
`;
  assert.deepEqual(ids(parseLockfile("yarn", berry)), ["lodash@4.17.21"]);
});

test("OSV severity from the GitHub label or the CVSS score", async () => {
  const { osvSeverity } = await import("../lockfile-parse.ts");
  assert.equal(osvSeverity({ database_specific: { severity: "MODERATE" } }), "medium");
  assert.equal(osvSeverity({ database_specific: { severity: "CRITICAL" } }), "critical");
  assert.equal(osvSeverity({ severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] }), "unknown", "vector strings aren't scored here");
  assert.equal(osvSeverity({ severity: [{ type: "CVSS_V3", score: "7.5" }] }), "high");
  assert.equal(osvSeverity({}), "unknown");
});

// ---------------------------------------------------------------- end to end

import { FakeDb, stubFetch, json, text, b64 } from "./harness/fakes.mts";

function repoRoutes(o: { osv: (body: any) => Response; lockfile?: boolean }) {
  const lock = JSON.stringify({
    lockfileVersion: 3,
    packages: { "": {}, "node_modules/express": { version: "4.17.1" }, "node_modules/express/node_modules/qs": { version: "6.7.0" } },
  });
  return (url: string, init: RequestInit) => {
    const u = new URL(url);
    if (u.host === "api.github.com") {
      if (u.pathname.includes("/git/trees/"))
        return json({ tree: [{ type: "blob", path: "package.json", sha: "m1" }, ...(o.lockfile === false ? [] : [{ type: "blob", path: "package-lock.json", sha: "l1", size: lock.length }])] });
      if (u.pathname.endsWith("/contents/package.json")) return json({ content: b64(JSON.stringify({ dependencies: { express: "^4.17.1" } })) });
      if (u.pathname.endsWith("/git/blobs/l1")) return json({ content: b64(lock), encoding: "base64" });
    }
    if (u.host === "registry.npmjs.org") {
      if (u.pathname.includes("advisories")) return json({});
      return json({ "dist-tags": { latest: "4.21.0" }, time: { "4.17.1": new Date().toISOString(), "4.21.0": new Date().toISOString() } });
    }
    if (u.host === "api.osv.dev") {
      if (u.pathname === "/v1/querybatch") return o.osv(JSON.parse(String(init.body)));
      if (u.pathname === "/v1/vulns/GHSA-hrpp-h998-j3pp")
        return json({ id: "GHSA-hrpp-h998-j3pp", summary: "qs vulnerable to Prototype Pollution", aliases: ["CVE-2022-24999"], database_specific: { severity: "HIGH" } });
    }
    return text("nf", 404);
  };
}

async function depScan(routes: ReturnType<typeof repoRoutes>) {
  const db = new FakeDb({ audits: [{ id: "a1", created_by: "u1" }], checklist_items: [{ id: "dep", checklist_key: "dep_vulns", title: "Dependency vulnerabilities scanned" }] });
  stubFetch(routes);
  const { runDepScan } = await import("../dep-scan-core.ts");
  const res: any = await runDepScan({ owner: "acme", repo: "app", token: "t".repeat(40), defaultBranch: "main", supabase: db.client() as any, auditId: "a1" });
  return { res, status: db.finding("a1", "dep")?.status };
}

test("dependency scan: a vulnerable transitive package from the lockfile fails", async () => {
  const { res, status } = await depScan(
    repoRoutes({
      osv: (body) =>
        json({ results: body.queries.map((q: any) => (q.package.name === "qs" ? { vulns: [{ id: "GHSA-hrpp-h998-j3pp" }] } : {})) }),
    }),
  );
  assert.equal(res.ok, true, res.error);
  assert.equal(status, "fail");
  const qs = res.findings.find((f: any) => f.name === "qs");
  assert.equal(qs.transitive, true);
  assert.equal(qs.cve, "CVE-2022-24999");
  assert.equal(qs.severity, "high");
});

test("dependency scan: OSV down is inconclusive, never a pass; no lockfile is inconclusive", async () => {
  const down = await depScan(repoRoutes({ osv: () => text("oops", 503) }));
  assert.notEqual(down.status, "pass");
  const clean = await depScan(repoRoutes({ osv: (body) => json({ results: body.queries.map(() => ({})) }) }));
  assert.equal(clean.status, "pass", "lockfile read and OSV answered for every package");
  const nolock = await depScan(repoRoutes({ lockfile: false, osv: (body) => json({ results: body.queries.map(() => ({})) }) }));
  assert.equal(nolock.status, "inconclusive");
});

test("dependency scan records the locked packages; a later re-check uses them without GitHub", async () => {
  const db = new FakeDb({ audits: [{ id: "a1", created_by: "u1" }], checklist_items: [{ id: "dep", checklist_key: "dep_vulns", title: "Dependency vulnerabilities scanned" }] });
  stubFetch(repoRoutes({ osv: (body) => json({ results: body.queries.map(() => ({})) }) }));
  const { runDepScan, recheckStoredPackages } = await import("../dep-scan-core.ts");
  await runDepScan({ owner: "acme", repo: "app", token: "t".repeat(40), defaultBranch: "main", supabase: db.client() as any, auditId: "a1" });
  assert.deepEqual(db.rows("audit_packages").map((r) => `${r.source} ${r.name}@${r.version}`).sort(), ["acme/app express@4.17.1", "acme/app qs@6.7.0"]);

  // A new advisory appears for qs; GitHub is unreachable now.
  const calls = stubFetch((url) => {
    const u = new URL(url);
    if (u.host === "api.github.com") throw new Error("must not call GitHub");
    if (u.pathname === "/v1/querybatch") return json({ results: [{ vulns: [{ id: "GHSA-hrpp-h998-j3pp" }] }, {}].sort(() => 0) });
    if (u.pathname.startsWith("/v1/vulns/")) return json({ id: "GHSA-hrpp-h998-j3pp", summary: "qs prototype pollution", database_specific: { severity: "HIGH" } });
    return text("nf", 404);
  });
  const r: any = await recheckStoredPackages(db.client() as any, "a1", { trigger: "schedule", createdBy: "u1" });
  assert.equal(r.ok, true, r.error);
  assert.equal(r.status, "fail");
  assert.equal(db.finding("a1", "dep")?.status, "fail");
  assert.ok(calls.every((c) => !c.includes("api.github.com")));
  const run = db.rows("scan_runs").at(-1);
  assert.equal(run.trigger, "schedule");
  assert.equal(run.created_by, "u1");
});
