// Inside the agent's network namespace: accept on 127.0.0.1:3128 and forward
// each connection to the egress proxy's Unix socket outside the namespace.
// Runs as the `egress` user; the proxy still decides which hosts are allowed.
import net from "node:net";

const socketPath = process.env.EGRESS_PROXY_SOCKET;
if (!socketPath) {
  console.error("uds-bridge: EGRESS_PROXY_SOCKET not set");
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
  .listen(3128, "127.0.0.1");
