// Model-API gateway. Runs as the `egress` user outside the agent's network
// namespace and is the agent's ONLY way out (via uds-bridge.mjs).
//
// Why: the agent reads hostile code and has a Bash tool. If it held the real
// ANTHROPIC_API_KEY and a general HTTPS proxy to api.anthropic.com, a
// prompt-injected agent could send the key (or anything else) to an
// attacker's own Anthropic account. Here the agent gets a placeholder key and
// plain HTTP to this gateway; the gateway adds the real key and forwards only
// the Messages API. Nothing else on api.anthropic.com (Files, Batches, admin…)
// and no other host is reachable from the agent at all.
import http from "node:http";
import https from "node:https";
import { unlinkSync } from "node:fs";
import { pathToFileURL } from "node:url";

const UPSTREAM = "api.anthropic.com";

/** Only the calls the Agent SDK needs to run the model. */
export function isAllowedRequest(method, rawUrl) {
  if (method !== "POST") return false;
  let path;
  try {
    path = new URL(String(rawUrl ?? ""), "http://gateway").pathname;
  } catch {
    return false;
  }
  return path === "/v1/messages" || path === "/v1/messages/count_tokens";
}

// Credentials and hop-by-hop headers are never taken from the agent: whatever
// key it sends is replaced with the real one.
const DROP_HEADERS = new Set(["authorization", "x-api-key", "cookie", "host", "connection", "keep-alive", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"]);

export function upstreamHeaders(incoming, apiKey) {
  const out = {};
  for (const [k, v] of Object.entries(incoming ?? {})) {
    const key = k.toLowerCase();
    if (!DROP_HEADERS.has(key) && v != null) out[key] = v;
  }
  out["x-api-key"] = apiKey;
  out.host = UPSTREAM;
  return out;
}

function main() {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  const socketPath = process.env.API_GATEWAY_SOCKET;
  if (!apiKey || !socketPath) {
    console.error("api-gateway: ANTHROPIC_API_KEY and API_GATEWAY_SOCKET are required");
    process.exit(2);
  }
  delete process.env.ANTHROPIC_API_KEY;

  const server = http.createServer((req, res) => {
    if (!isAllowedRequest(req.method, req.url)) {
      console.error(`[gateway] blocked ${req.method} ${String(req.url).slice(0, 200)}`);
      res.writeHead(403, { "content-type": "text/plain" }).end("blocked by audit gateway\n");
      req.resume();
      return;
    }
    const url = new URL(req.url, "http://gateway");
    const up = https.request(
      { host: UPSTREAM, port: 443, method: "POST", path: url.pathname + url.search, headers: upstreamHeaders(req.headers, apiKey) },
      (upRes) => {
        res.writeHead(upRes.statusCode ?? 502, upRes.headers);
        upRes.pipe(res);
      },
    );
    up.on("error", (e) => {
      console.error(`[gateway] upstream error: ${e.message}`);
      if (!res.headersSent) res.writeHead(502).end();
      else res.destroy();
    });
    req.on("error", () => up.destroy());
    req.pipe(up);
  });
  // Long agent turns stream for minutes.
  server.requestTimeout = 0;
  server.headersTimeout = 60_000;

  try {
    unlinkSync(socketPath);
  } catch {
    /* not there yet */
  }
  server.listen(socketPath, () => console.log(`[gateway] Messages API only, on ${socketPath}`));
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) main();
