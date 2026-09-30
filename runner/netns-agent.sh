#!/bin/sh
# Runs inside a fresh network namespace (started with `unshare --net` by the
# supervisor), so the only interface is loopback: nothing here can reach the
# internet directly, whatever firewall support the VM kernel has.
#
# The one way out is the allowlisting proxy, which lives outside this
# namespace. A small bridge, running as the `egress` user, forwards
# 127.0.0.1:3128 in here to the proxy's Unix socket.
set -eu
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
export PATH

ip link set lo up

setpriv --reuid=10002 --regid=10002 --clear-groups --no-new-privs -- \
  env -i PATH=/usr/local/bin:/usr/bin:/bin EGRESS_PROXY_SOCKET="$EGRESS_PROXY_SOCKET" \
  node /app/uds-bridge.mjs &

# Wait for the bridge to listen.
i=0
until node -e "require('net').connect(3128,'127.0.0.1').on('connect',()=>process.exit(0)).on('error',()=>process.exit(1))" 2>/dev/null; do
  i=$((i + 1))
  [ "$i" -gt 50 ] && { echo "netns: proxy bridge did not start" >&2; exit 20; }
  sleep 0.1
done

# Prove isolation: as the audit user, a direct connection must fail.
if setpriv --reuid=10001 --regid=10001 --clear-groups --no-new-privs -- \
  node -e "const s=require('net').connect(443,'1.1.1.1');s.setTimeout(3000,()=>process.exit(0));s.on('connect',()=>process.exit(3));s.on('error',()=>process.exit(0));"
then echo "netns: isolated (direct internet blocked, proxy bridge up)" >&2
else echo "netns: isolation check failed; refusing to run the agent" >&2; exit 21
fi

cd "$JOB_OUT"
exec setpriv --reuid=10001 --regid=10001 --clear-groups --no-new-privs -- \
  node --experimental-strip-types --no-warnings /app/run-job.mjs --agent
