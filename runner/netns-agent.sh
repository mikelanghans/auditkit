#!/bin/sh
# Runs inside a fresh network namespace (started with `unshare --net` by the
# supervisor), so the only interface is loopback: nothing here can reach the
# internet directly, whatever firewall support the VM kernel has.
#
# The one way out is the model-API gateway (api-gateway.mjs), which lives
# outside this namespace and holds the real API key. A small bridge, running
# as the `egress` user, forwards 127.0.0.1:8080 in here to its Unix socket.
# There is no general proxy in here: no CONNECT, no other hosts.
set -eu
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
export PATH

ip link set lo up

setpriv --reuid=10002 --regid=10002 --clear-groups --no-new-privs -- \
  env -i PATH=/usr/local/bin:/usr/bin:/bin \
  node /app/uds-bridge.mjs 8080 "$API_GATEWAY_SOCKET" &

# Wait for the bridge to listen.
i=0
until node -e "require('net').connect(8080,'127.0.0.1').on('connect',()=>process.exit(0)).on('error',()=>process.exit(1))" 2>/dev/null; do
  i=$((i + 1))
  [ "$i" -gt 50 ] && { echo "netns: gateway bridge did not start" >&2; exit 20; }
  sleep 0.1
done

# Prove isolation as the audit user: a direct connection must fail, and the
# gateway must refuse anything but the Messages API.
if setpriv --reuid=10001 --regid=10001 --clear-groups --no-new-privs -- \
  node -e "const s=require('net').connect(443,'1.1.1.1');s.setTimeout(3000,()=>process.exit(0));s.on('connect',()=>process.exit(3));s.on('error',()=>process.exit(0));"
then :
else echo "netns: isolation check failed (direct connection worked); refusing to run the agent" >&2; exit 21
fi
if setpriv --reuid=10001 --regid=10001 --clear-groups --no-new-privs -- \
  node -e "fetch('http://127.0.0.1:8080/v1/files').then(r=>process.exit(r.status===403?0:4),()=>process.exit(5))"
then echo "netns: isolated (no direct internet; gateway allows the Messages API only)" >&2
else echo "netns: gateway check failed; refusing to run the agent" >&2; exit 22
fi

cd "$JOB_OUT"
exec setpriv --reuid=10001 --regid=10001 --clear-groups --no-new-privs -- \
  node --experimental-strip-types --no-warnings /app/run-job.mjs --agent
