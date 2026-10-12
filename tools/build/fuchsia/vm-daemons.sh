#!/bin/sh
# vm-daemons.sh -- guest-side checks for capability daemons migrated to FIDL
# (tools/build/fuchsia/DAEMONS.md).  Pass it to vm-provider.sh as
# EXTRA_SCRIPT; it runs as root on the console after the plane converges,
# before Kyua.  Two parts:
#
# 1. Live-provider lifecycle through each migrated daemon's operator tool:
#    reads succeed, the shipped default-deny policy refuses privileged
#    operations in the provider (EPERM, not a lookup failure), a core unit
#    refuses runtime restart, and 200 short sessions succeed.  Prints
#    <NAME>_LIFECYCLE_PASS or _FAIL per daemon.
# 2. Request latency (daemon_bench.h): every installed latency_bench (one per
#    provider tests directory, FIDL) and every /root/vm-extra.d/latency_bench.*
#    (the pre-FIDL build of the same bench, from build-daemon-bench.sh) runs
#    ROUNDS interleaved rounds of CALLS round trips between the provider's
#    real client library and its real per-session server.  LATENCY lines are
#    the bench's own clock; LATENCY_DTRACE lines time libchannel
#    request-start -> request-done in the client, probes that fire for both
#    the pre-FIDL and the FIDL clients.
CALLS=${CALLS:-2000}
ROUNDS=${ROUNDS:-3}
R=/tmp/kyua-results
mkdir -p "$R"

refused() {	# command... : must fail with "not permitted" from the provider
	if "$@" > "$R/daemon.out" 2>&1; then
		echo "unexpectedly succeeded: $*"; return 1
	fi
	grep -q 'not permitted' "$R/daemon.out" && return 0
	echo "failed for another reason: $* -> $(head -n 1 "$R/daemon.out")"
	return 1
}
core_restart_denied() {	# label process
	pid=$(pgrep -x "$2" | head -n 1)
	if switchboardctl restart "$1" > "$R/daemon.out" 2>&1; then
		echo "core restart of $1 permitted"; return 1
	fi
	grep -q 'management class core' "$R/daemon.out" ||
	    { echo "restart of $1 failed unexpectedly: $(head -n 1 "$R/daemon.out")"; return 1; }
	[ "$(pgrep -x "$2" | head -n 1)" = "$pid" ] ||
	    { echo "$2 process changed after denied restart"; return 1; }
	return 0
}
sessions() {	# count command...
	n=$1; shift; i=0
	while [ $i -lt "$n" ]; do "$@" > /dev/null 2>&1 || break; i=$((i + 1)); done
	echo $i
}

# ------------------------------------------------------------ system.Power
if [ -x /usr/tests/usr.sbin/BSDPower/latency_bench ]; then
	ok=PASS
	s=$(BSDPowerctl states 2>&1) || { echo "POWER: states failed: $s"; ok=FAIL; }
	echo "POWER_STATES=$s"
	c=$(BSDPowerctl inhibitors 2>&1) || { echo "POWER: inhibitors failed: $c"; ok=FAIL; }
	echo "POWER_INHIBITORS=$c"
	refused BSDPowerctl suspend 3 || ok=FAIL
	refused BSDPowerctl inhibit 1 || ok=FAIL
	core_restart_denied system.Power/bsdpower BSDPower || ok=FAIL
	n=$(sessions 200 BSDPowerctl states)
	echo "POWER_SESSIONS=$n"
	[ "$n" = 200 ] || ok=FAIL
	echo "POWER_LIFECYCLE_$ok"
fi

# ----------------------------------------------------------- system.Sysctl
if [ -x /usr/tests/usr.sbin/BSDSysctl/latency_bench ]; then
	ok=PASS
	v=$(sysctlcmpctl get kern.ostype 2>&1) || { echo "SYSCTL: get failed: $v"; ok=FAIL; }
	echo "SYSCTL_GET=$v"
	[ "$v" = "$(sysctl -n kern.ostype)" ] || { echo "SYSCTL: value differs from sysctl(8)"; ok=FAIL; }
	n=$(sysctlcmpctl list 2>/dev/null | wc -l | tr -d ' ')
	echo "SYSCTL_LIST_COUNT=$n"
	[ "$n" -gt 0 ] || ok=FAIL
	refused sysctlcmpctl set kern.maxfiles 1000 || ok=FAIL
	core_restart_denied system.Sysctl/bsdsysctl BSDSysctl || ok=FAIL
	n=$(sessions 200 sysctlcmpctl get kern.ostype)
	echo "SYSCTL_SESSIONS=$n"
	[ "$n" = 200 ] || ok=FAIL
	echo "SYSCTL_LIFECYCLE_$ok"
fi

# ------------------------------------- live clients of converted providers
# Each line runs a shipped tool against the live provider over the plane.
live() {	# name command...
	n=$1; shift
	if out=$("$@" 2>&1); then
		echo "LIVE_$n=PASS"
	else
		echo "LIVE_$n=FAIL: $(echo "$out" | head -n 3 | tr '\n' ' ')"
	fi
}
command -v logctl > /dev/null && live LOG_STATS logctl stats
command -v logctl > /dev/null && live LOG_EMIT logctl emit vm.daemons check info "fidl live check"
command -v notifyctl > /dev/null && live NOTIFY_STATS notifyctl stats
command -v notifyctl > /dev/null && live NOTIFY_PUBLISH notifyctl publish user.vm.check hello
command -v networkcmpctl > /dev/null && live NETWORK_INFO networkcmpctl info
command -v networkcmpctl > /dev/null && live NETWORK_RESOLVE networkcmpctl resolve -4 127.0.0.1
# Name lookup reads /etc/hosts through BSDFilesystem, opened once when
# BSDNetwork starts (resolver.c netresolve_init, best effort); reported, not
# gated: it depends on start order, not on the protocol.
command -v networkcmpctl > /dev/null && live NETWORK_RESOLVE_HOSTS networkcmpctl resolve -4 localhost
command -v networkcmpctl > /dev/null && live NETWORK_STATE networkcmpctl state-watch 1 0

# ----------------------------------------------------------------- latency
kld=$(kldload -n dtraceall 2>&1) || echo "LATENCY_KLDLOAD dtraceall: $kld"
dtrace_ok=
dtrace -l -n 'BEGIN' > /dev/null 2>&1 && dtrace_ok=1
[ -n "$dtrace_ok" ] || echo "LATENCY_NOTE dtrace unavailable; bench clock only"
benches=
for bench in /usr/tests/*/*/latency_bench /usr/tests/*/*/*/latency_bench \
    /root/vm-extra.d/latency_bench.*; do
	[ -x "$bench" ] && benches="$benches $bench"
done
r=1
while [ "$r" -le "$ROUNDS" ]; do
	for bench in $benches; do
		if [ -z "$dtrace_ok" ]; then
			"$bench" "$CALLS" 2>&1 | grep '^LATENCY ' | \
			    sed "s|\$| bench=$bench round=$r|"
			continue
		fi
		out=$(dtrace -Z -q -x bufsize=4m -n '
libchannel$target:::request-start { s[arg0, arg1] = timestamp; }
libchannel$target:::request-done /s[arg0, arg1]/ {
	this->d = timestamp - s[arg0, arg1];
	@n = count(); @a = avg(this->d); @q = quantize(this->d);
	s[arg0, arg1] = 0;
}
END { printa("DTRACE_COUNT %@d\n", @n); printa("DTRACE_AVG %@d\n", @a); printa(@q); }' \
		    -c "$bench $CALLS" 2>&1)
		echo "$out" | grep '^LATENCY ' | sed "s|\$| bench=$bench round=$r|"
		count=$(echo "$out" | awk '/^DTRACE_COUNT/ { print $2 }')
		avg=$(echo "$out" | awk '/^DTRACE_AVG/ { print $2 }')
		# Median bucket of the quantize() histogram.
		p50=$(echo "$out" | awk -v n="${count:-0}" '
		    $1 ~ /^-?[0-9]+$/ && substr($2, 1, 1) == "|" {
			c += $NF; if (!done && c * 2 >= n) { print $1; done = 1 } }')
		echo "LATENCY_DTRACE bench=$bench round=$r count=${count:-none} avg_ns=${avg:-none} p50_bucket_ns=${p50:-none}"
		[ -n "$count" ] || echo "$out" | head -n 5 | sed 's/^/LATENCY_DTRACE_OUTPUT: /'
	done
	r=$((r + 1))
done
# Per-call system calls of one bench pair (FIDL and pre-migration), from
# ktrace: where a latency difference comes from.
SYSCALL_CALLS=${SYSCALL_CALLS:-200}
for bench in /usr/tests/usr.sbin/BSDPower/latency_bench \
    /root/vm-extra.d/latency_bench.power.legacy; do
	[ -x "$bench" ] || continue
	trace=/tmp/vm-daemons.ktrace
	rm -f "$trace"
	ktrace -f "$trace" -t c "$bench" "$SYSCALL_CALLS" > /dev/null 2>&1 || true
	kdump -f "$trace" 2>/dev/null | awk -v n="$SYSCALL_CALLS" -v b="$bench" '
	    $3 == "CALL" { sub(/\(.*/, "", $4); c[$4]++; t++ }
	    END { line = sprintf("LATENCY_SYSCALLS bench=%s calls=%d total_per_call=%.1f", b, n, t / n);
		  for (k in c) if (c[k] >= n) line = line sprintf(" %s=%.1f", k, c[k] / n);
		  print line }'
done
echo LATENCY_DONE
