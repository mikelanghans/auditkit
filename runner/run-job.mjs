// Deep-audit runner entrypoint. One Fly machine = one job; the machine is
// destroyed when this process exits.
//
// Supervisor (root)                         Agent (uid auditor)
// ─────────────────                         ───────────────────
// decrypt job, start egress proxy,
// check network namespaces work,
// clone repo read-only (token used once),
// drop GitHub from the proxy allowlist ───▶ in a loopback-only network
//                                           namespace (netns-agent.sh), run the
//                                           security-audit skill via
//                                           the Claude Agent SDK, output to
//                                           /work/out/run-1, target code only
//                                           inside `sbx`. Only way out: the
//                                           model-API gateway (api-gateway.mjs),
//                                           which holds the real key.
// kill anything the agent left running,
// run the skill's validators (pristine
// root-owned copy, unprivileged, no network),
// post signed results to AuditKit, exit.
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, chmodSync, openSync, fstatSync, readFileSync, closeSync, constants as fsc } from "node:fs";
import { hostname } from "node:os";

const AGENT_MODE = process.argv.includes("--agent");
const WORK = "/work";
const REPO = `${WORK}/repo`;
const OUT = `${WORK}/out/run-1`;
const SKILL_DIR = "/home/auditor/.claude/skills/security-audit";
// Validators run from the root-owned copy baked into the image, never from the
// agent's (writable) skill directory.
const VALIDATOR_DIR = "/opt/security-audit-skill/skills/security-audit";
const AUDITOR_UID = 10001;
const EGRESS_UID = 10002;
const PROXY = "http://127.0.0.1:3128";
const PROXY_SOCKET_DIR = "/run/egress";
const GATEWAY_SOCKET = `${PROXY_SOCKET_DIR}/api.sock`;
const GATEWAY_PORT = 8080; // inside the agent's namespace, see netns-agent.sh
const MAX_JOB_MS = Number(process.env.CODE_AUDIT_MAX_HOURS ?? 3) * 3600_000;
const MAX_OUTPUT_FILE_BYTES = 8 * 1024 * 1024;
// AuditKit's webhook rejects bodies over 6 MiB; stay under it.
const MAX_CALLBACK_BYTES = 5.5 * 1024 * 1024;

// Set once the callback is usable, so an unexpected crash is still reported to
// AuditKit instead of leaving the run stuck on "queued".
let reportCrash = null;

if (AGENT_MODE) await runAgent();
else
  await supervise().catch(async (e) => {
    console.error(e);
    if (reportCrash) await reportCrash(`Runner crashed: ${e?.message ?? e}`);
    process.exit(1);
  });

// ───────────────────────────── supervisor ─────────────────────────────

async function supervise() {
  const jobKey = process.env.CODE_AUDIT_JOB_KEY;
  const blob = process.env.AUDITKIT_JOB;
  delete process.env.AUDITKIT_JOB;
  delete process.env.CODE_AUDIT_JOB_KEY;
  if (process.env.CODE_AUDIT_WEBHOOK_SECRET) {
    // AuditKit's master secret must never be on a runner: with it, one
    // machine could sign results for every run. Remove it from the Fly app.
    console.error("CODE_AUDIT_WEBHOOK_SECRET is set on the runner; refusing to run. Remove it (fly secrets unset).");
    process.exit(2);
  }
  if (!jobKey || !blob) {
    console.error("missing CODE_AUDIT_JOB_KEY or AUDITKIT_JOB");
    process.exit(2);
  }
  const { decryptJob, signCallback } = await import("./contract.ts");
  let job;
  try {
    job = await decryptJob(blob, jobKey);
  } catch {
    console.error("job could not be decrypted; refusing to run");
    process.exit(2);
  }
  if (!/^[0-9a-f]{64}$/.test(String(job.callbackKey ?? ""))) {
    console.error("job has no callback key; refusing to run");
    process.exit(2);
  }
  const secret = job.callbackKey; // signs callbacks for this run only
  // A job blob is only good for a short while after AuditKit issued it.
  if (Date.now() - Date.parse(job.issuedAt) > 30 * 60_000) {
    console.error("job is stale; refusing to run");
    process.exit(2);
  }

  // Hard stop for the whole job, whatever hangs (clone, agent, validators).
  setTimeout(async () => {
    console.error("[runner] job deadline reached");
    if (reportCrash) await reportCrash("The runner hit its overall time limit and was stopped.");
    process.exit(1);
  }, MAX_JOB_MS + 20 * 60_000).unref();

  const callbackHost = new URL(job.callbackUrl).hostname;
  mkdirSync(PROXY_SOCKET_DIR, { recursive: true, mode: 0o700 });
  run("chown", [`${EGRESS_UID}:${EGRESS_UID}`, PROXY_SOCKET_DIR]);
  run("chmod", ["700", PROXY_SOCKET_DIR]);
  // Supervisor-only proxy (the agent can't reach it): GitHub for the clone,
  // plus our callback host. The model API is never on this list.
  let proxy = startProxy(["github.com", "codeload.github.com", callbackHost]);

  const { ProxyAgent } = await import("undici");
  const dispatcher = new ProxyAgent(PROXY);
  const post = async (payload) => {
    const body = JSON.stringify(payload);
    const { timestamp, signature } = await signCallback(body, secret);
    for (let attempt = 1; attempt <= 5; attempt++) {
      try {
        const res = await fetch(job.callbackUrl, {
          method: "POST",
          headers: { "content-type": "application/json", "x-auditkit-run": job.runId, "x-auditkit-timestamp": timestamp, "x-auditkit-signature": signature },
          body,
          dispatcher,
        });
        if (res.ok || (res.status >= 400 && res.status < 500 && res.status !== 408 && res.status !== 429)) {
          console.log(`[callback] ${payload.event} → ${res.status}`);
          return res.ok;
        }
      } catch (e) {
        console.error(`[callback] attempt ${attempt} failed: ${e?.message ?? e}`);
      }
      await new Promise((r) => setTimeout(r, attempt * 5000));
    }
    return false;
  };
  const fail = async (error) => {
    console.error(`[runner] failed: ${error}`);
    await post({ runId: job.runId, event: "failed", error: String(error).slice(0, 1500) });
    process.exit(1);
  };
  reportCrash = fail;

  // Progress is best-effort: one attempt, never blocks the job, at most one
  // update every 20 seconds unless the phase changes.
  let lastProgressAt = 0;
  let lastPhase = "";
  let pendingProgress = null;
  const sendProgress = (p) => {
    const body = JSON.stringify({ runId: job.runId, event: "progress", ...p });
    signCallback(body, secret)
      .then(({ timestamp, signature }) =>
        fetch(job.callbackUrl, {
          method: "POST",
          headers: { "content-type": "application/json", "x-auditkit-run": job.runId, "x-auditkit-timestamp": timestamp, "x-auditkit-signature": signature },
          body,
          dispatcher,
        }),
      )
      .catch((e) => console.error(`[progress] ${e?.message ?? e}`));
  };
  const progress = (p) => {
    const now = Date.now();
    if (p.phase !== lastPhase || now - lastProgressAt >= 20_000) {
      lastPhase = p.phase;
      lastProgressAt = now;
      pendingProgress = null;
      sendProgress(p);
    } else pendingProgress = p;
  };
  const flushTimer = setInterval(() => {
    if (pendingProgress && Date.now() - lastProgressAt >= 20_000) progress(pendingProgress);
  }, 5_000);
  flushTimer.unref();

  await post({ runId: job.runId, event: "started", machineId: process.env.FLY_MACHINE_ID ?? hostname() });
  progress({ phase: "starting", detail: "Locking down the network" });

  // 0. Network isolation for the agent is a fresh network namespace (see
  // netns-agent.sh); make sure the kernel supports it before doing anything.
  try {
    run("unshare", ["--net", "true"]);
  } catch (e) {
    return fail(`This machine can't create an isolated network namespace, so the audit was not started: ${e.message}`);
  }

  // 1. Clone, read-only, token used once and never written to disk.
  progress({ phase: "cloning", detail: job.repoUrl.replace("https://github.com/", "") });
  try {
    mkdirSync(REPO, { recursive: true });
    mkdirSync(OUT, { recursive: true });
    // /work/out stays root-owned so the agent can't swap run-1 for a symlink;
    // only run-1 itself is the agent's.
    run("chmod", ["755", `${WORK}/out`]);
    run("chown", [`${AUDITOR_UID}:${AUDITOR_UID}`, OUT]);
    const gitEnv = { ...cleanEnv(), https_proxy: PROXY, HTTPS_PROXY: PROXY, GIT_TERMINAL_PROMPT: "0" };
    // The token goes in through the environment (not argv, which any local
    // user can read in /proc) and is scoped to github.com.
    const fetchEnv = job.githubToken
      ? {
          ...gitEnv,
          GIT_CONFIG_COUNT: "1",
          GIT_CONFIG_KEY_0: "http.https://github.com/.extraHeader",
          GIT_CONFIG_VALUE_0: `Authorization: Basic ${Buffer.from(`x-access-token:${job.githubToken}`).toString("base64")}`,
        }
      : gitEnv;
    run("git", ["init", "-q", REPO], gitEnv);
    run("git", ["-C", REPO, "fetch", "-q", "--depth", "1", "--end-of-options", job.repoUrl, job.gitRef || "HEAD"], fetchEnv, 10 * 60_000);
    run("git", ["-C", REPO, "checkout", "-q", "FETCH_HEAD"], gitEnv, 5 * 60_000);
    job.githubToken = null;
  } catch (e) {
    return fail(`Could not clone ${job.repoUrl}: ${e.message}`);
  }
  const sourceCommit = run("git", ["-C", REPO, "rev-parse", "HEAD"]).trim();
  run("chmod", ["-R", "a-w", REPO]);

  // 2. From here on the supervisor only talks to our callback, and the agent
  // only to the model-API gateway.
  proxy.kill();
  proxy = startProxy([callbackHost]);
  const gateway = startGateway();

  // 3. Run the agent as an unprivileged user. Its stdout is passed through to
  // the machine log; lines starting with @@progress are forwarded to AuditKit.
  progress({ phase: "auditing", detail: "Starting the audit agent", agents: 0, steps: 0 });
  const exit = await new Promise((resolve) => {
    // unshare --net: new network namespace with loopback only. netns-agent.sh
    // starts the proxy bridge, verifies isolation, then drops to `auditor`.
    const child = spawn("unshare", ["--net", "sh", "/app/netns-agent.sh"], {
      cwd: OUT,
      stdio: ["ignore", "pipe", "inherit"],
      env: {
        JOB_OUT: OUT,
        API_GATEWAY_SOCKET: GATEWAY_SOCKET,
        PATH: "/usr/local/bin:/usr/bin:/bin",
        HOME: "/home/auditor",
        // The real key stays in the gateway; the agent only has a placeholder.
        ANTHROPIC_API_KEY: "sk-ant-placeholder-held-by-gateway",
        ANTHROPIC_BASE_URL: `http://127.0.0.1:${GATEWAY_PORT}`,
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
        DISABLE_TELEMETRY: "1",
        CODE_AUDIT_MODEL: process.env.CODE_AUDIT_MODEL ?? "",
        JOB_PROFILE: job.profile,
        JOB_BUDGET: String(job.budget),
        JOB_REPO: job.repoUrl,
        JOB_FOCUS: JSON.stringify(Array.isArray(job.focus) ? job.focus.filter((f) => typeof f === "string").slice(0, 40) : []),
      },
    });
    let buf = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      buf += chunk;
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.startsWith("@@progress ")) {
          try {
            const p = JSON.parse(line.slice(11));
            progress({ phase: "auditing", detail: p.detail, agents: p.agents, steps: p.steps, todosDone: p.todosDone, todosTotal: p.todosTotal });
          } catch {
            /* ignore malformed progress */
          }
        } else process.stdout.write(`${line}\n`);
      }
      if (buf.length > 100_000) buf = "";
    });
    const timer = setTimeout(() => child.kill("SIGKILL"), MAX_JOB_MS);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });

  // 4. Nothing the agent started may keep running (or keep editing its
  // output) while we validate and read it.
  spawnSync("pkill", ["-KILL", "-u", String(AUDITOR_UID)]);
  gateway.kill();

  // 5. Validate with the skill's own validators, then report.
  progress({ phase: "validating", detail: "Checking the audit output" });
  const read = (name) => readAgentFile(`${OUT}/${name}`);
  const findingsText = read("findings.json");
  const ledgerText = read("coverage-ledger.json");
  if (!findingsText || !ledgerText) {
    return fail(`The audit agent exited (code ${exit}) without writing findings.json and coverage-ledger.json.`);
  }
  // Validators read agent-written files, so they run unprivileged, with no
  // network and an empty environment, from the pristine root-owned copy.
  const validate = (script, file) => {
    const r = spawnSync(
      "unshare",
      ["--net", "setpriv", `--reuid=${AUDITOR_UID}`, `--regid=${AUDITOR_UID}`, "--clear-groups", "--no-new-privs", "--",
        "env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", process.execPath, `${VALIDATOR_DIR}/${script}`, `${OUT}/${file}`],
      { encoding: "utf8", env: cleanEnv(), timeout: 120_000 },
    );
    const out = ((r.stdout || "") + (r.stderr || "")).trim().split("\n").slice(0, 20).join("\n");
    return r.status === 0 ? out : `FAIL (exit ${r.status ?? r.signal}): ${out}`.slice(0, 2000);
  };
  let meta = {};
  try {
    meta = JSON.parse(read("run-metadata.json") ?? "{}");
  } catch {
    /* reported as incomplete below */
  }
  let findings, ledger;
  try {
    findings = JSON.parse(findingsText);
    ledger = JSON.parse(ledgerText);
  } catch (e) {
    return fail(`Audit output is not valid JSON: ${e.message}`);
  }
  progress({ phase: "reporting", detail: "Sending results to AuditKit" });
  const completed = {
    runId: job.runId,
    event: "completed",
    runStatus: meta.run_status === "complete" ? "complete" : "incomplete",
    incompleteReason: meta.run_status === "complete" ? null : meta.incomplete_reason ?? `agent exit code ${exit}`,
    sourceCommit,
    agentsUsed: Number.isInteger(meta.agents_spent) ? meta.agents_spent : null,
    validators: { findings: validate("validate-findings.cjs", "findings.json"), ledger: validate("validate-coverage-ledger.cjs", "coverage-ledger.json") },
    findings,
    coverageLedger: ledger,
    reportMd: read("REPORT.md") ?? undefined,
    findingsDetailMd: read("FINDINGS-DETAIL.md") ?? undefined,
    needsValidationMd: read("NEEDS-VALIDATION.md") ?? undefined,
  };
  // Drop the long-form markdown before giving up if the body is too big.
  if (Buffer.byteLength(JSON.stringify(completed)) > MAX_CALLBACK_BYTES) {
    completed.findingsDetailMd = completed.needsValidationMd = undefined;
  }
  if (Buffer.byteLength(JSON.stringify(completed)) > MAX_CALLBACK_BYTES) {
    return fail("The audit output is too large to send back to AuditKit.");
  }
  if (!(await post(completed))) {
    return fail("AuditKit did not accept the audit results (see the runner log).");
  }
  proxy.kill();
  process.exit(0);
}

function cleanEnv() {
  // sbin for unshare/ip and friends; this env is only used by the root supervisor.
  return { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", HOME: "/root", LANG: "C.UTF-8" };
}

function run(cmd, args, env = cleanEnv(), timeout = 60_000) {
  const r = spawnSync(cmd, args, { encoding: "utf8", env, timeout });
  if (r.error?.code === "ETIMEDOUT") throw new Error(`${cmd} ${args[0]} timed out`);
  if (r.status !== 0) throw new Error(`${cmd} ${args[0]} failed: ${(r.stderr || r.stdout || "").trim().slice(0, 500)}`);
  return r.stdout;
}

/**
 * Read a file the agent wrote, as root, without following a symlink it may
 * have planted (e.g. REPORT.md → /proc/1/environ). Regular files only, capped.
 */
function readAgentFile(path) {
  let fd;
  try {
    fd = openSync(path, fsc.O_RDONLY | fsc.O_NOFOLLOW | fsc.O_NONBLOCK);
  } catch {
    return null;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > MAX_OUTPUT_FILE_BYTES) return null;
    return readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
}

function startProxy(hosts) {
  const child = spawn(process.execPath, ["/app/egress-proxy.mjs"], {
    uid: EGRESS_UID,
    gid: EGRESS_UID,
    stdio: "inherit",
    env: { PATH: "/usr/bin:/bin", EGRESS_ALLOW: hosts.join(",") },
  });
  spawnSync("sleep", ["0.5"]);
  return child;
}

function startGateway() {
  const child = spawn(process.execPath, ["/app/api-gateway.mjs"], {
    uid: EGRESS_UID,
    gid: EGRESS_UID,
    stdio: "inherit",
    env: { PATH: "/usr/bin:/bin", ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY ?? "", API_GATEWAY_SOCKET: GATEWAY_SOCKET },
  });
  spawnSync("sleep", ["0.5"]);
  return child;
}

// ───────────────────────────── agent ─────────────────────────────

/**
 * Leads from AuditKit's quick repo scan. Paths come from the client's repo, so
 * they are re-filtered here and framed as unverified hints, never instructions.
 */
function focusSection() {
  let focus = [];
  try {
    focus = JSON.parse(process.env.JOB_FOCUS || "[]");
  } catch {}
  const safe = (Array.isArray(focus) ? focus : [])
    .map((f) => String(f))
    .filter((f) => /^[A-Za-z0-9._\-/@+ :()—]{1,400}$/.test(f) && !f.includes(".."))
    .slice(0, 40);
  if (!safe.length) return "";
  return `Leads from an earlier automated scan of this repo (pattern matches, unverified; give these locations extra attention, confirm or reject each one on the evidence, and still cover the whole codebase):
${safe.map((f) => `- ${f}`).join("\n")}

`;
}

async function runAgent() {
  const { query } = await import("@anthropic-ai/claude-agent-sdk");
  const profile = process.env.JOB_PROFILE;
  const budget = process.env.JOB_BUDGET;
  chmodSync(OUT, 0o700);

  const prompt = `Run a full security audit of the repository at ${REPO} using the security-audit skill, in full audit mode.

This is a non-interactive job: nobody can answer questions. Where the skill says to ask the user, take the documented default and record the choice in run-metadata.json.

Setup values:
- Skill directory: ${SKILL_DIR}
- Target: ${REPO} (read-only checkout of ${process.env.JOB_REPO})
- Output directory: ${OUT}
- Profile: ${profile}
- Strict budget: ${budget} agent invocations across all phases. Never exceed it; if it cannot fund the minimum, follow the skill's incomplete-run rules.

Execution environment facts:
- There is no network at all apart from the model API, which is reached through a local gateway. Do not attempt to install dependencies or fetch anything.
- The OS-enforced sandbox the skill requires is the command \`sbx <scratch-dir> <command> [args...]\`: fresh network namespace (loopback only), cleared environment, read-only filesystem except the scratch dir, output and home directories hidden, CPU/memory/process/file-size limits and a 120s wall clock. Run target-controlled code only through sbx with the agent's own scratch dir. If a check can't run under sbx, record it as needs_validation as the skill describes.
- Do not probe any deployed endpoint or external service.

${focusSection()}Finish by writing every artifact the skill defines and making sure findings.json and coverage-ledger.json pass the skill's validators.`;

  // Progress for the supervisor: sub-agents launched, tool calls, and the
  // agent's current to-do item. Printed as @@progress lines on stdout.
  let agents = 0;
  let steps = 0;
  let detail = "Reading the skill";
  let todosDone = null;
  let todosTotal = null;
  let lastEmit = 0;
  const emit = (force = false) => {
    const now = Date.now();
    if (!force && now - lastEmit < 5_000) return;
    lastEmit = now;
    process.stdout.write(`@@progress ${JSON.stringify({ detail, agents, steps, todosDone, todosTotal })}\n`);
  };

  let result = "";
  for await (const msg of query({
    prompt,
    options: {
      cwd: OUT,
      settingSources: ["user"],
      allowedTools: ["Skill", "Task", "Read", "Grep", "Glob", "Write", "Edit", "Bash", "TodoWrite"],
      permissionMode: "bypassPermissions",
      maxTurns: 4000,
      ...(process.env.CODE_AUDIT_MODEL ? { model: process.env.CODE_AUDIT_MODEL } : {}),
    },
  })) {
    if (msg.type === "result") result = msg.subtype ?? "";
    if (msg.type === "assistant" && !msg.parent_tool_use_id) {
      for (const block of msg.message?.content ?? []) {
        if (block?.type !== "tool_use") continue;
        steps++;
        let force = false;
        if (block.name === "Task") {
          agents++;
          detail = String(block.input?.description ?? "Running a sub-agent");
          force = true;
        } else if (block.name === "TodoWrite" && Array.isArray(block.input?.todos)) {
          const todos = block.input.todos;
          todosTotal = todos.length;
          todosDone = todos.filter((t) => t?.status === "completed").length;
          const current = todos.find((t) => t?.status === "in_progress");
          if (current) detail = String(current.activeForm ?? current.content ?? detail);
          force = true;
        }
        emit(force);
      }
    } else if (msg.type === "assistant") {
      for (const block of msg.message?.content ?? []) if (block?.type === "tool_use") steps++;
      emit();
    }
  }
  emit(true);
  console.log(`[agent] finished: ${result}`);
  process.exit(result === "success" ? 0 : 1);
}
