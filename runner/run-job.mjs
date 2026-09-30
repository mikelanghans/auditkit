// Deep-audit runner entrypoint. One Fly machine = one job; the machine is
// destroyed when this process exits.
//
// Supervisor (root)                         Agent (uid auditor)
// ─────────────────                         ───────────────────
// decrypt job, start egress proxy,
// lock egress (lockdown.sh),
// clone repo read-only (token used once),
// drop GitHub from the proxy allowlist ───▶ run the security-audit skill via
//                                           the Claude Agent SDK, output to
//                                           /work/out/run-1, target code only
//                                           inside `sbx`
// run the skill's validators, post signed
// results to AuditKit, exit.
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, chmodSync } from "node:fs";
import { hostname } from "node:os";

const AGENT_MODE = process.argv.includes("--agent");
const WORK = "/work";
const REPO = `${WORK}/repo`;
const OUT = `${WORK}/out/run-1`;
const SKILL_DIR = "/home/auditor/.claude/skills/security-audit";
const AUDITOR_UID = 10001;
const EGRESS_UID = 10002;
const PROXY = "http://127.0.0.1:3128";
const MAX_JOB_MS = Number(process.env.CODE_AUDIT_MAX_HOURS ?? 3) * 3600_000;

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
  const secret = process.env.CODE_AUDIT_WEBHOOK_SECRET;
  const blob = process.env.AUDITKIT_JOB;
  delete process.env.AUDITKIT_JOB;
  if (!secret || !blob) {
    console.error("missing CODE_AUDIT_WEBHOOK_SECRET or AUDITKIT_JOB");
    process.exit(2);
  }
  const { decryptJob, signCallback } = await import("./contract.ts");
  let job;
  try {
    job = await decryptJob(blob, secret);
  } catch {
    console.error("job could not be decrypted; refusing to run");
    process.exit(2);
  }
  // A job blob is only good for a short while after AuditKit issued it.
  if (Date.now() - Date.parse(job.issuedAt) > 30 * 60_000) {
    console.error("job is stale; refusing to run");
    process.exit(2);
  }

  const callbackHost = new URL(job.callbackUrl).hostname;
  let proxy = startProxy(["api.anthropic.com", "github.com", "codeload.github.com", callbackHost]);

  const { ProxyAgent } = await import("undici");
  const dispatcher = new ProxyAgent(PROXY);
  const post = async (payload) => {
    const body = JSON.stringify(payload);
    const { timestamp, signature } = await signCallback(body, secret);
    for (let attempt = 1; attempt <= 5; attempt++) {
      try {
        const res = await fetch(job.callbackUrl, {
          method: "POST",
          headers: { "content-type": "application/json", "x-auditkit-timestamp": timestamp, "x-auditkit-signature": signature },
          body,
          dispatcher,
        });
        if (res.ok || (res.status >= 400 && res.status < 500 && res.status !== 408 && res.status !== 429)) {
          console.log(`[callback] ${payload.event} → ${res.status}`);
          return;
        }
      } catch (e) {
        console.error(`[callback] attempt ${attempt} failed: ${e?.message ?? e}`);
      }
      await new Promise((r) => setTimeout(r, attempt * 5000));
    }
  };
  const fail = async (error) => {
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
          headers: { "content-type": "application/json", "x-auditkit-timestamp": timestamp, "x-auditkit-signature": signature },
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

  // 0. Egress lockdown, then prove it: the audit user must not reach the internet directly.
  try {
    run("sh", ["/app/lockdown.sh"]);
  } catch (e) {
    return fail(`Network lockdown failed, so the audit was not started: ${e.message}`);
  }
  const probe = spawnSync(
    process.execPath,
    ["-e", "const s=require('net').connect(443,'1.1.1.1');s.setTimeout(3000,()=>process.exit(0));s.on('connect',()=>process.exit(3));s.on('error',()=>process.exit(0));"],
    { uid: AUDITOR_UID, gid: AUDITOR_UID, env: { PATH: "/usr/bin:/bin" }, timeout: 10_000 },
  );
  if (probe.status !== 0)
    return fail(
      probe.status === 3
        ? "Network lockdown is not effective (the audit user could reach the internet directly), so the audit was not started."
        : `Could not verify the network lockdown (probe exit ${probe.status ?? probe.error?.message}), so the audit was not started.`,
    );

  // 1. Clone, read-only, token used once and never written to disk.
  progress({ phase: "cloning", detail: job.repoUrl.replace("https://github.com/", "") });
  try {
    mkdirSync(REPO, { recursive: true });
    mkdirSync(OUT, { recursive: true });
    run("chown", ["-R", `${AUDITOR_UID}:${AUDITOR_UID}`, `${WORK}/out`]);
    const auth = job.githubToken
      ? ["-c", `http.extraHeader=Authorization: Basic ${Buffer.from(`x-access-token:${job.githubToken}`).toString("base64")}`]
      : [];
    const gitEnv = { ...cleanEnv(), https_proxy: PROXY, HTTPS_PROXY: PROXY, GIT_TERMINAL_PROMPT: "0" };
    run("git", ["init", "-q", REPO], gitEnv);
    run("git", ["-C", REPO, ...auth, "fetch", "-q", "--depth", "1", job.repoUrl, job.gitRef || "HEAD"], gitEnv);
    run("git", ["-C", REPO, "checkout", "-q", "FETCH_HEAD"], gitEnv);
    job.githubToken = null;
  } catch (e) {
    return fail(`Could not clone ${job.repoUrl}: ${e.message}`);
  }
  const sourceCommit = run("git", ["-C", REPO, "rev-parse", "HEAD"]).trim();
  run("chmod", ["-R", "a-w", REPO]);

  // 2. From here on the only external host is the model API (and our callback).
  proxy.kill();
  proxy = startProxy(["api.anthropic.com", callbackHost]);

  // 3. Run the agent as an unprivileged user. Its stdout is passed through to
  // the machine log; lines starting with @@progress are forwarded to AuditKit.
  progress({ phase: "auditing", detail: "Starting the audit agent", agents: 0, steps: 0 });
  const exit = await new Promise((resolve) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", "/app/run-job.mjs", "--agent"], {
      uid: AUDITOR_UID,
      gid: AUDITOR_UID,
      cwd: OUT,
      stdio: ["ignore", "pipe", "inherit"],
      env: {
        PATH: "/usr/local/bin:/usr/bin:/bin",
        HOME: "/home/auditor",
        ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY ?? "",
        HTTPS_PROXY: PROXY,
        https_proxy: PROXY,
        NO_PROXY: "127.0.0.1,localhost",
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
        DISABLE_TELEMETRY: "1",
        CODE_AUDIT_MODEL: process.env.CODE_AUDIT_MODEL ?? "",
        JOB_PROFILE: job.profile,
        JOB_BUDGET: String(job.budget),
        JOB_REPO: job.repoUrl,
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

  // 4. Validate with the skill's own validators, then report.
  progress({ phase: "validating", detail: "Checking the audit output" });
  const read = (name) => (existsSync(`${OUT}/${name}`) ? readFileSync(`${OUT}/${name}`, "utf8") : null);
  const findingsText = read("findings.json");
  const ledgerText = read("coverage-ledger.json");
  if (!findingsText || !ledgerText) {
    return fail(`The audit agent exited (code ${exit}) without writing findings.json and coverage-ledger.json.`);
  }
  const validate = (script, file) => {
    const r = spawnSync(process.execPath, [`${SKILL_DIR}/${script}`, `${OUT}/${file}`], { encoding: "utf8" });
    return ((r.stdout || "") + (r.stderr || "")).trim().split("\n").slice(0, 20).join("\n");
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
  await post({
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
  });
  proxy.kill();
  process.exit(0);
}

function cleanEnv() {
  // sbin for iptables and friends; this env is only used by the root supervisor.
  return { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", HOME: "/root", LANG: "C.UTF-8" };
}

function run(cmd, args, env = cleanEnv()) {
  const r = spawnSync(cmd, args, { encoding: "utf8", env });
  if (r.status !== 0) throw new Error(`${cmd} ${args[0]} failed: ${(r.stderr || r.stdout || "").trim().slice(0, 500)}`);
  return r.stdout;
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

// ───────────────────────────── agent ─────────────────────────────

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
- There is no network except the model API. Do not attempt to install dependencies or fetch anything.
- The OS-enforced sandbox the skill requires is the command \`sbx <scratch-dir> <command> [args...]\`: fresh network namespace (loopback only), cleared environment, read-only filesystem except the scratch dir, output and home directories hidden, CPU/memory/process/file-size limits and a 120s wall clock. Run target-controlled code only through sbx with the agent's own scratch dir. If a check can't run under sbx, record it as needs_validation as the skill describes.
- Do not probe any deployed endpoint or external service.

Finish by writing every artifact the skill defines and making sure findings.json and coverage-ledger.json pass the skill's validators.`;

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
