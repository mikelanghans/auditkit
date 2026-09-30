// Allowlisting HTTPS CONNECT proxy. Runs as the `egress` user. The audit agent
// runs in its own network namespace with loopback only (netns-agent.sh), so it
// reaches the internet solely through this proxy's Unix socket, and only to the
// hosts below. The supervisor uses the TCP listener for the clone and callbacks.
import http from "node:http";
import net from "node:net";
import { unlinkSync } from "node:fs";

const port = Number(process.env.EGRESS_PROXY_PORT ?? 3128);
const allow = new Set(
  String(process.env.EGRESS_ALLOW ?? "api.anthropic.com")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean),
);

function handleConnect(req, clientSocket, head) {
  const [host, portStr] = String(req.url ?? "").split(":");
  const target = (host ?? "").toLowerCase();
  const p = Number(portStr);
  if (!allow.has(target) || p !== 443) {
    console.error(`[egress] blocked ${req.url}`);
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
}

function makeServer() {
  // Plain-HTTP proxying is never needed; everything we allow is HTTPS.
  const server = http.createServer((req, res) => res.writeHead(403).end("only CONNECT is allowed\n"));
  server.on("connect", handleConnect);
  return server;
}

makeServer().listen(port, "127.0.0.1", () => console.log(`[egress] proxy on 127.0.0.1:${port}, allow: ${[...allow].join(", ")}`));

const socketPath = process.env.EGRESS_PROXY_SOCKET;
if (socketPath) {
  try {
    unlinkSync(socketPath);
  } catch {
    /* not there yet */
  }
  makeServer().listen(socketPath, () => console.log(`[egress] proxy on ${socketPath}`));
}
