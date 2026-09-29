#!/bin/sh
# Egress lockdown: after this, only the `egress` user (the allowlisting proxy)
# can open outbound connections. Everything else, including the audit agent
# and any target code, can reach loopback only.
set -eu
for ipt in iptables ip6tables; do
  $ipt -P OUTPUT ACCEPT
  $ipt -F OUTPUT
  $ipt -A OUTPUT -o lo -j ACCEPT
  $ipt -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  $ipt -A OUTPUT -m owner --uid-owner egress -j ACCEPT
  $ipt -P OUTPUT DROP
done
echo "egress locked"
