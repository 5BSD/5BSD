#!/bin/sh
set -eu
kit=${1:?kit path}
t=$(mktemp -d /tmp/nested-stall.XXXXXX)
trap 'rm -rf "$t"' EXIT
fail=0
# Recursive cleanup must consume the list before invoking any action.
HT_KIT=$kit HT_LOG=$t/log HT_WORK=$t
export HT_KIT HT_LOG HT_WORK
(
	. "$kit/lib/common.sh"
	depth=0
	at_cleanup 'echo action >> "$t/actions"; depth=$((depth + 1)); [ "$depth" -ge 3 ] || run_cleanup'
	run_cleanup
)
n=$(wc -l < "$t/actions" | tr -d ' ')
if [ "$n" -eq 1 ]; then echo 'PASS cleanup consumed before recursion'; else echo "FAIL cleanup repeated $n times"; fail=1; fi
# Model scheduling delay: each completed sleep resumes 30 elapsed seconds
# later. The 20-second budget must expire after the first delayed wakeup.
awk '/^case "\$\{1:-\}"/ { exit } { print }' "$kit/guest/l2-boot.sh" > "$t/l2-functions"
(
	L2_RUNDIR=$t
	. "$t/l2-functions"
	echo 0 > "$t/clock"; echo 0 > "$t/sleeps"
	date() { cat "$t/clock"; }
	sleep() {
		n=$(cat "$t/clock"); echo $((n + 30)) > "$t/clock"
		n=$(cat "$t/sleeps"); echo $((n + 1)) > "$t/sleeps"
	}
	l2_kill() { kill -KILL "$1" 2>/dev/null || :; wait "$1" 2>/dev/null || :; }
	if L2_BDIAG=no bounded 20 "$t/child" /bin/sleep 30; then exit 1; else [ "$?" -eq 124 ]; fi
)
n=$(cat "$t/sleeps")
if [ "$n" -eq 1 ]; then echo 'PASS delayed wakeup respects elapsed deadline'; else echo "FAIL delayed wakeup counted $n sleeps"; fail=1; fi
# Detach invalidates the old lifetime even if a new console starts.
(
	. "$kit/lib/common.sh"
	: > "$t/old-token"; echo "$t/old-token" > "$t/ht-test.lifetime"
	vm_detach_console ht-test
	[ ! -e "$t/old-token" ] && [ ! -e "$t/ht-test.lifetime" ]
) && echo 'PASS detach cancels console lifetime' || { echo 'FAIL detach retained lifetime'; fail=1; }
# A background hold budget, not just lifetime, limits early diagnostics.
(
	L2_RUNDIR=$t
	. "$t/l2-functions"
	echo $(( $(date +%s) - 35 )) > "$S/t0"
	lim=600; fgwait=60; L2_DIAG_LIM=90; sampled=no
	l2_diag() { echo "$diag_sfx" >> "$t/samples"; }
	l2_sample_if_due
	[ ! -e "$t/samples" ] || exit 1
	fgwait=600
	l2_sample_if_due
	l2_sample_if_due
	[ "$(cat "$t/samples")" = .sample ]
) && echo 'PASS diagnostic fits foreground budget and runs once' || { echo 'FAIL diagnostic foreground budget'; fail=1; }
# Reporting must return bounded partial evidence even if a report tool hangs.
(
	L2_RUNDIR=$t
	. "$t/l2-functions"
	L2_GRACE=0; L2_REPORT_LIM=5
	l2_report_body() { echo partial-report; exec /bin/sleep 30; }
	if l2_report > "$t/report-output"; then exit 1; else [ "$?" -eq 5 ]; fi
	grep -qx partial-report "$t/report-output"
	grep -q 'L2-FAIL report exceeded' "$t/report-output"
) && echo 'PASS bounded report retains evidence' || { echo 'FAIL report deadline'; fail=1; }
exit "$fail"
