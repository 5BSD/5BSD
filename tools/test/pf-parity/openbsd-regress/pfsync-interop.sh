#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# pfsync(4) interoperability between the 5BSD DUT and the OpenBSD helper
# over their shared link (DUT vtnet1, helper vio1).  Each side skips the
# interface the other side's test connection uses, so a state can only
# appear there through pfsync.  Prints PASS/FAIL lines; restores both.
set -u
S="ssh -F /usr/obj/5BSD-pf-parity/keys/ssh_config"
rc=0

$S helper 'printf "set skip on { lo vio0 vio2 vio3 pair2 pair3 lo2 lo3 }\npass\n" | pfctl -f - && pfctl -e >/dev/null 2>&1; ifconfig pfsync0 create 2>/dev/null; ifconfig pfsync0 syncdev vio1 up'
$S dut 'printf "set skip on { vtnet0 }\npass\nanchor \"regress\"\n" | pfctl -f - && pfctl -e >/dev/null 2>&1; ifconfig pfsync0 create 2>/dev/null; ifconfig pfsync0 syncdev vtnet1 up; pfctl -Fs >/dev/null 2>&1'
$S helper 'pfctl -Fs >/dev/null 2>&1'
sleep 2

# A: a state created on 5BSD appears on OpenBSD.
$S dut 'nc -z -w 1 10.188.211.51 7777 >/dev/null 2>&1; true'
sleep 3
if $S helper 'pfctl -ss' | grep -q '10.188.211.51:7777'; then
	echo "PASS 5bsd-to-openbsd: state synchronised"
else
	echo "FAIL 5bsd-to-openbsd: $($S helper 'pfctl -ss' | head -5)"; rc=1
fi

# B: a state created on OpenBSD appears on 5BSD (DUT skips vtnet1 now).
$S dut 'printf "set skip on { vtnet0 vtnet1 }\npass\nanchor \"regress\"\n" | pfctl -f -; pfctl -Fs >/dev/null 2>&1'
# An established connection to the DUT's discard service, held open.
$S helper '(sleep 30 | nc 10.188.210.50 9 >/dev/null 2>&1 &) ; true'
sleep 5
if $S dut 'pfctl -ss' | grep -q '10.188.210.50:9 .*ESTABLISHED'; then
	echo "PASS openbsd-to-5bsd: state synchronised"
else
	echo "FAIL openbsd-to-5bsd: $($S dut 'pfctl -ss' | head -5)"; rc=1
fi

# C: bulk update: a new 5BSD pfsync peer requests the OpenBSD state table.
$S dut 'ifconfig pfsync0 destroy; pfctl -Fs >/dev/null 2>&1; ifconfig pfsync0 create; ifconfig pfsync0 syncdev vtnet1 up'
sleep 10
if $S dut 'pfctl -ss' | grep -q '10.188.210.50:9 '; then
	echo "PASS openbsd-bulk-to-5bsd: bulk update received"
else
	echo "FAIL openbsd-bulk-to-5bsd: $($S dut 'pfctl -ss' | head -5)"; rc=1
fi

$S helper 'ifconfig pfsync0 destroy; pfctl -Fs >/dev/null 2>&1; pfctl -d >/dev/null 2>&1; true'
$S dut 'ifconfig pfsync0 destroy; pfctl -Fs >/dev/null 2>&1; pfctl -f /etc/pf.conf; pfctl -e >/dev/null 2>&1; true'
exit $rc
