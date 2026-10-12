#!/bin/sh
# Copy 5BSD ATF test scripts for OpenBSD PF to the disposable DUT and run
# their cases with atf-sh (body, then cleanup).
# usage: run-atf.sh <test_script.sh> [case ...]
set -u
S="ssh -F /usr/obj/5BSD-pf-parity/keys/ssh_config dut"
T=/usr/obj/5BSD-pf-src/tests/sys/netpfil/pf/openbsd
D=/usr/tests/sys/netpfil/pf/openbsd
script=$1; shift
$S "mkdir -p $D"
for f in $script tproxy.py; do
	[ -f $T/$f ] && cat $T/$f | $S "cat > $D/$f"
done
$S "chmod 555 $D/tproxy.py 2>/dev/null; true"
cases="$*"
[ -n "$cases" ] || cases=$(grep -o 'atf_add_test_case "[a-z_0-9]*"' $T/$script | sed 's/.*"\(.*\)"/\1/')
for c in $cases; do
	echo "=== $script:$c"
	$S "cd /tmp && rm -rf atf.$c && mkdir atf.$c && cd atf.$c && /usr/libexec/atf-sh $D/$script -s $D -r result $c >out 2>err; cat result; tail -5 err; /usr/libexec/atf-sh $D/$script -s $D $c:cleanup >/dev/null 2>&1; true"
done
