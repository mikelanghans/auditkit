// Inside the agent's network namespace: accept on 127.0.0.1:<port> and forward
// each connection to a Unix socket outside the namespace (the model-API
// gateway). Runs as the `egress` user; the gateway decides what is allowed.
// Usage: node uds-bridge.mjs <port> <socket-path>
import net from "node:net";

const port = Number(process.argv[2]);
const socketPath = process.argv[3];
if (!Number.isInteger(port) || !socketPath) {
  console.error("usage: uds-bridge.mjs <port> <socket-path>");
  process.exit(2);
}

net
  .createServer((client) => {
    const upstream = net.connect(socketPath);
    client.pipe(upstream);
    upstream.pipe(client);
    const close = () => {
      client.destroy();
      upstream.destroy();
    };
    client.on("error", close);
    upstream.on("error", close);
  })
  .listen(port, "127.0.0.1");
