#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Forwarding microbenchmark through the DUT, run from the host.
# usage: msize-bench.sh LABEL OUTFILE [nopf|pf]
#   nopf (default): pf disabled.  pf: pf enabled with a stateful pass
#   ruleset, so forwarded packets carry pf's mbuf tag (state-key link).
# Requires the two-guest topology (helper OpenBSD as SRC/ECO, DUT 5BSD).
set -u
label=$1 out=$2 mode=${3:-nopf}
S="ssh -F /usr/obj/5BSD-pf-parity/keys/ssh_config"
{
echo "== $label $(date -u +%FT%TZ)"
$S dut 'uname -v; sysctl -n kern.ipc.nmbufs kern.ipc.nmbclusters; pfctl -d >/dev/null 2>&1; echo pf-disabled'
if [ "$mode" = pf ]; then
	$S dut 'printf "set skip on { lo vtnet0 }\npass\n" | pfctl -f - && pfctl -e >/dev/null 2>&1; echo pf-enabled-stateful'
fi
$S helper 'grep -q "^discard" /etc/inetd.eco.conf || { echo "discard	stream	tcp	nowait	root	internal" >> /etc/inetd.eco.conf; pkill -HUP -f "inetd /etc/inetd.eco.conf"; }; sleep 1'
$S dut 'netstat -m | head -4; vmstat -z | egrep "^(mbuf|mbuf_packet|mbuf_cluster):"; vmstat -m | grep mbuf_tag'
for i in 1 2 3 4 5; do
	$S helper "dd if=/dev/zero bs=64k count=1600 2>/dev/null | /usr/bin/time -p nc -N 10.188.213.52 9" 2>&1 | grep real | sed "s/^/tcp100MB run$i /"
done
for i in 1 2 3 4 5; do
	$S helper "/usr/bin/time -p ping -q -f -c 20000 -s 56 10.188.213.52" 2>&1 | egrep "real|packet loss" | tr '\n' ' ' | sed "s/^/pingflood run$i /"; echo
done
$S dut 'netstat -m | head -4; vmstat -z | egrep "^(mbuf|mbuf_packet|mbuf_cluster):"; vmstat -m | grep mbuf_tag; pfctl -f /etc/pf.conf; pfctl -e >/dev/null 2>&1'
} >> "$out" 2>&1
