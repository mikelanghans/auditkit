// Tests for the deep-audit runner's network lockdown: the model-API gateway
// (the agent's only way out) and the supervisor's CONNECT allowlist.
// Run with: npm run test:scanners
import { test } from "node:test";
import assert from "node:assert/strict";
// @ts-ignore plain .mjs runner modules
import { isAllowedRequest, upstreamHeaders } from "../../../runner/api-gateway.mjs";
// @ts-ignore plain .mjs runner modules
import { parseConnectTarget } from "../../../runner/egress-proxy.mjs";

test("gateway: only POSTs to the Messages API get through", () => {
  assert.equal(isAllowedRequest("POST", "/v1/messages"), true);
  assert.equal(isAllowedRequest("POST", "/v1/messages?beta=true"), true);
  assert.equal(isAllowedRequest("POST", "/v1/messages/count_tokens"), true);
  for (const [m, u] of [
    ["GET", "/v1/messages"],
    ["POST", "/v1/files"],
    ["POST", "/v1/messages/batches"],
    ["POST", "/v1/organizations/api_keys"],
    ["POST", "/v1/messages/../files"],
    ["POST", "http://evil.example/v1/messages/../../v1/files"],
    ["POST", "/v1/messages%2F..%2Ffiles"],
    ["DELETE", "/v1/messages"],
  ])
    assert.equal(isAllowedRequest(m, u), false, `${m} ${u}`);
});

test("gateway: the agent's own credentials are replaced, never forwarded", () => {
  const h = upstreamHeaders(
    {
      "x-api-key": "sk-ant-attacker",
      Authorization: "Bearer attacker",
      cookie: "a=b",
      host: "evil.example",
      "anthropic-version": "2023-06-01",
      "content-type": "application/json",
    },
    "sk-ant-real",
  );
  assert.equal(h["x-api-key"], "sk-ant-real");
  assert.equal(h.host, "api.anthropic.com");
  assert.equal(h.authorization, undefined);
  assert.equal(h.Authorization, undefined);
  assert.equal(h.cookie, undefined);
  assert.equal(h["anthropic-version"], "2023-06-01");
});

test("egress proxy: exact allowlisted host on port 443 only", () => {
  const allow = new Set(["github.com", "app.example.com"]);
  assert.equal(parseConnectTarget("github.com:443", allow), "github.com");
  assert.equal(parseConnectTarget("GitHub.com:443", allow), "github.com");
  for (const bad of ["github.com:22", "evil.github.com:443", "github.com.evil.net:443", "api.anthropic.com:443", "github.com", "[::1]:443", "github.com:443:1"])
    assert.equal(parseConnectTarget(bad, allow), null, bad);
});
