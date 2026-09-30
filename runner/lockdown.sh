#!/bin/sh
# Egress lockdown: after this, only the `egress` user (the allowlisting proxy)
# can open outbound connections. Everything else, including the audit agent
# and any target code, can reach loopback only. Fails closed: any error stops
# the job before the agent starts.
set -eu
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
export PATH

# Debian's iptables uses the nf_tables backend; fall back to the legacy
# backend if the VM kernel doesn't support nf_tables.
pick() {
  if "$1" -L OUTPUT -n >/dev/null 2>&1; then echo "$1"
  elif command -v "$1-legacy" >/dev/null 2>&1 && "$1-legacy" -L OUTPUT -n >/dev/null 2>&1; then echo "$1-legacy"
  else echo "lockdown: neither $1 nor $1-legacy works on this kernel" >&2; exit 1
  fi
}

for base in iptables ip6tables; do
  ipt=$(pick "$base")
  $ipt -P OUTPUT ACCEPT
  $ipt -F OUTPUT
  $ipt -A OUTPUT -o lo -j ACCEPT
  $ipt -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  $ipt -A OUTPUT -m owner --uid-owner egress -j ACCEPT
  $ipt -P OUTPUT DROP
  echo "lockdown: $ipt OUTPUT locked"
done
echo "egress locked"
