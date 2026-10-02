// Allowlisting HTTPS CONNECT proxy for the SUPERVISOR only (clone + signed
// callbacks). Runs as the `egress` user on 127.0.0.1 in the machine's network
// namespace. The audit agent lives in its own namespace and cannot reach this
// listener; its only way out is api-gateway.mjs.
import http from "node:http";
import net from "node:net";
import { pathToFileURL } from "node:url";

const port = Number(process.env.EGRESS_PROXY_PORT ?? 3128);
const allow = new Set(
  String(process.env.EGRESS_ALLOW ?? "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean),
);

/** host:443 only, exact hostname match. */
export function parseConnectTarget(rawUrl, allowSet) {
  const m = /^([a-z0-9.-]+):(\d{1,5})$/i.exec(String(rawUrl ?? ""));
  if (!m) return null;
  const host = m[1].toLowerCase();
  if (!allowSet.has(host) || Number(m[2]) !== 443) return null;
  return host;
}

const server = http.createServer((req, res) => res.writeHead(403).end("only CONNECT is allowed\n"));
server.on("connect", (req, clientSocket, head) => {
  const target = parseConnectTarget(req.url, allow);
  if (!target) {
    console.error(`[egress] blocked ${String(req.url).slice(0, 200)}`);
    clientSocket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
    return;
  }
  const upstream = net.connect(443, target, () => {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head?.length) upstream.write(head);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
  });
  upstream.on("error", () => clientSocket.destroy());
  clientSocket.on("error", () => upstream.destroy());
});

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href)
  server.listen(port, "127.0.0.1", () => console.log(`[egress] proxy on 127.0.0.1:${port}, allow: ${[...allow].join(", ")}`));
