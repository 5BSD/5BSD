#!/bin/sh
# Run inside the L1 guest: boot the L2 guest from the second disk (vtbd1)
# with bhyve and wait for its marker on an nmdm console.
#   l2-boot.sh MARKER [MEM]      run L2 (prints L2-OK or L2-FAIL at the end)
#   l2-boot.sh --status          background run: last tick, bhyve alive?
#   l2-boot.sh --wait [SECONDS]  background run: wait for the end, report
#   l2-boot.sh --limits          print the stage limits this environment uses
# Environment (all optional):
#   L2_CPUS=1        L2 vCPUs
#   L2_WORK=0        MiB per vCPU for the CPU-bound checksum workload
#                    (srtool work MB 1000+cpu, pinned to each vCPU); L1
#                    computes the same digests natively and compares
#   L2_HOLD=0        seconds L2 stays up printing ticks before poweroff
#   L2_NET=no        yes: tap in L1 (10.231.78.1/24), L2 at .2; L1 pings
#                    L2 during the hold (needs L2_HOLD >= 10)
#   L2_BG=no         yes: return once L2 holds (use --status / --wait)
#   L2_SAMPLE_AFTER=15 seconds before one bounded L1/L2 diagnostic capture
#                    (0 disables); copied live to L1 console
#   L2_TIMEOUT=120   bhyve lifetime limit
#   L2_BUDGET=       seconds the caller waits for this script (its console
#                    limit minus a margin). The foreground never waits
#                    longer: L2_TIMEOUT is lowered so that every stage
#                    limit plus the stuck-run diagnostics fit (--limits).
#   L2_LIVE=/dev/console  where the L2 console and bhyve stderr are copied
#                    live, prefixed [L2] / [L2-bhyve], so the host capture
#                    of L1's console has them even if this script never
#                    returns; "none" disables (default for L2_BG=yes).
# Guest stage deadlines use elapsed guest time; the host enforces its own
# command deadline if L1 stops scheduling. We do not rely on timeout(1)
# to terminate bhyve: bhyve turns
# SIGTERM into an ACPI power-button press (a guest that never booted never
# powers off) and a process blocked in the kernel ignores signals, so
# timeout(1) could wait forever (gen4: no output after 900 s). A stage that
# overruns gets the L1 diagnostics (procstat -kk of bhyve/bhyveload/dtraced,
# ps, top, dmesg) before it is killed; a process that cannot be killed is
# reported and left behind.
set -u
S=${L2_RUNDIR:-/tmp/l2run}
T=${SRTOOL:-/root/hosttest/srtool}
# Stage limits (seconds); the overrides exist for the kit selftest.
L2_DESTROY_LIM=${L2_DESTROY_LIM:-5} L2_LOAD_LIM=${L2_LOAD_LIM:-30}
L2_GRACE=${L2_GRACE:-3} L2_DIAG_LIM=${L2_DIAG_LIM:-15} L2_REPORT_LIM=${L2_REPORT_LIM:-15}
L2_BASE_LIM=${L2_BASE_LIM:-2}
CONDEV=${L2_CONDEV:-/dev/nmdm7B} VMMCTL=${L2_VMMCTL:-/dev/vmmctl}
cr=$(printf '\r')
live=${L2_LIVE:-none} diag_live=no diag_sfx=
con() { tr -d '\r' < $S/console; }

# l2_limits LIM BUDGET BG: sets lim (bhyve), fgwait (foreground wait for the
# bhyve stage) and total (worst-case foreground seconds).
l2_limits()
{
	lim=$1 budget=$2
	pre=$((5 + L2_BASE_LIM + L2_DESTROY_LIM + L2_LOAD_LIM))
	post=$((L2_GRACE + 3 + L2_DIAG_LIM + 5 + L2_REPORT_LIM))
	if [ -n "$budget" ] && [ "$budget" -gt 0 ]; then
		room=$((budget - pre - post))
		[ "$room" -lt 60 ] && room=60
		if [ "$3" = yes ]; then
			# bhyve keeps its lifetime limit; only the wait for the hold
			# is bounded by the budget.
			fgwait=$lim; [ "$fgwait" -gt "$room" ] && fgwait=$room
		else
			[ "$lim" -gt "$room" ] && lim=$room
			fgwait=$lim
		fi
	else
		fgwait=$lim
	fi
	total=$((pre + fgwait + post))
}

l2_live() # FILE TAG: copy FILE to $live as it grows
{
	[ "$live" = none ] && return 0
	tail -n +1 -F "$1" 2>/dev/null | sed -l -e "s/$cr//g" -e "s/^/[$2] /" >> "$live" 2>/dev/null &
	echo $! >> $S/livepids
}

l2_live_stop()
{
	for p in $(cat $S/livepids 2>/dev/null); do kill "$p" 2>/dev/null; done
	pkill -f "tail -n \+1 -F $S/" 2>/dev/null
	rm -f $S/livepids
}

# Run "$@" with a hard bound; on timeout print diagnostics, then kill.
# bounded SECS OUTFILE cmd...   returns the command's status or 124.
bounded()
{
	b_lim=$1 b_out=$2 b_diag=${L2_BDIAG:-yes}; shift 2
	"$@" > "$b_out" 2>&1 & b_pid=$!
	b_start=$(date +%s)
	while kill -0 $b_pid 2>/dev/null && [ $(( $(date +%s) - b_start )) -lt "$b_lim" ]; do sleep 1; done
	if kill -0 $b_pid 2>/dev/null; then
		[ "$b_diag" = yes ] && l2_diag "$1 still running after ${b_lim}s"
		l2_kill $b_pid "$1"
		return 124
	fi
	wait $b_pid
}

# l2_kill PID NAME: TERM, grace, KILL; never waits on an unkillable process.
l2_kill()
{
	kill -TERM "$1" 2>/dev/null
	k_start=$(date +%s)
	while kill -0 "$1" 2>/dev/null && [ $(( $(date +%s) - k_start )) -lt "$L2_GRACE" ]; do sleep 1; done
	kill -0 "$1" 2>/dev/null || return 0
	kill -KILL "$1" 2>/dev/null; sleep 3
	if kill -0 "$1" 2>/dev/null; then
		echo "L2-STUCK $2 pid $1 still present after SIGKILL (see preceding diagnostics)"
	fi
}

l2_diag_body()
{
	echo "-- console reader: $(cat $S/conpid 2>/dev/null)"
	cat "$S/console-reader.err" 2>/dev/null
	stty -f "$CONDEV" -a 2>&1
	echo "== L2-DIAG: $1 ($(date -u +%H:%M:%SZ), L1 up $(uptime | sed 's/.*up *//; s/,.*load/ load/'))"
	for diag_cpu in $(jot "$(cat $S/cpus 2>/dev/null || echo 1)" 0); do
		timeout -k 1 3 bhyvectl --vm=l2 --cpu="$diag_cpu" \
		    --get-rip --get-rflags --get-intinfo --get-stats 2>&1
	done
	for n in bhyve bhyveload bhyvectl dtraced dtrace; do
		for p in $(pgrep -x $n); do
			echo "-- $n pid $p: $(ps -o state= -o wchan= -o %cpu= -o time= -p $p 2>/dev/null)"
			timeout -k 2 10 procstat -kk $p 2>&1 | head -24
		done
	done
	echo "-- top threads by CPU"
	timeout -k 2 10 top -b -S -H -o cpu -s 1 -d 2 20 2>&1 | sed -n '/^last pid/,$p' | tail -24
	echo "-- busiest processes' kernel stacks"
	for p in $(ps -axH -o pid=,%cpu= 2>/dev/null | sort -k2 -nr | awk '$2 > 20 {print $1}' | sort -u | head -5); do
		echo "- pid $p $(ps -o comm= -p $p 2>/dev/null)"
		timeout -k 2 10 procstat -kk $p 2>&1 | head -12
	done
	echo "-- ps -auxww"
	ps -auxww 2>&1 | head -70
	echo "-- vmm / HyperTrace / dtrace state"
	ls /dev/vmm 2>&1
	kldstat 2>&1 | grep -E 'vmm|dtrace|hypertrace|virtio|dtt'
	ls -la /var/ddtrace 2>&1 | head -12
	timeout -k 2 10 service dtraced status 2>&1 | head -3
	timeout -k 2 10 sysctl kern.dtrace 2>/dev/null | head -20
	echo "-- dmesg tail"
	dmesg 2>&1 | tail -40
	echo "== L2-DIAG end"
}

# Diagnostics are bounded too (a diagnostic tool can block on the same lock).
l2_diag()
{
	if [ "$live" != none ]; then
		printf 'L2-DIAG starting: %s\n' "$1" >> $S/bhyve
	fi
	l2_diag_body "$1" > $S/diag$diag_sfx.tmp 2>&1 & d_pid=$!
	d_start=$(date +%s)
	while kill -0 $d_pid 2>/dev/null && [ $(( $(date +%s) - d_start )) -lt "$L2_DIAG_LIM" ]; do sleep 1; done
	kill -0 $d_pid 2>/dev/null && { kill -KILL $d_pid 2>/dev/null; echo "(diagnostics cut at ${L2_DIAG_LIM}s)" >> $S/diag$diag_sfx.tmp; }
	cat $S/diag$diag_sfx.tmp; cat $S/diag$diag_sfx.tmp >> $S/diag$diag_sfx
	[ "$diag_live" = yes ] && [ "$live" != none ] && sed 's/^/[L2-DIAG] /' $S/diag$diag_sfx.tmp >> "$live" 2>/dev/null
	rm -f $S/diag$diag_sfx.tmp
}

l2_report_body()
{
	# Retire the watchdog before the next run can reuse this directory.
	# This wait is covered by the report deadline, including --wait calls
	# made by a different shell after a background run.
	: > $S/watchdog-stop
	while [ ! -f $S/watchdog-done ]; do sleep 0.1; done
	rc=$(cat $S/rc 2>/dev/null || echo running)
	t1=$(date +%s); t0=$(cat $S/t0 2>/dev/null || echo "$t1")
	[ -s $S/tap ] && ifconfig "$(cat $S/tap)" destroy 2>/dev/null
	kill "$(cat $S/conpid 2>/dev/null)" 2>/dev/null
	L2_BDIAG=no bounded "$L2_DESTROY_LIM" $S/destroy bhyvectl --vm=l2 --destroy
	l2_live_stop
	m=$(cat $S/marker)
	ok=no
	con | grep "HOSTTEST-L2-MARKER $m" && ok=yes
	work=$(cat $S/work)
	if [ "$work" -gt 0 ]; then
		n=$(cat $S/cpus); i=0; wok=yes; detail=""
		while [ $i -lt "$n" ]; do
			want=$("$T" expect "$work" $((1000 + i)))
			got=$(con | sed -n "s/.*HOSTTEST-L2-WORK cpu=$i sum=\([0-9a-f]*\).*/\1/p" | tail -1)
			on=$(con | sed -n "s/.*HOSTTEST-L2-WORK cpu=$i sum=[0-9a-f]* ran_on=\([0-9]*\).*/\1/p" | tail -1)
			[ "$got" = "$want" ] && [ "$on" = "$i" ] || wok=no
			[ "$got" = "$want" ] && g=match || g="${got:-none}!=$want"
			detail="$detail cpu$i=$g@${on:-?}"
			i=$((i + 1))
		done
		echo "L2-WORK-$([ $wok = yes ] && echo OK || echo FAIL) mb=$work$detail $(con | grep -o 'HOSTTEST-L2-WORK-DONE.*' | tail -1)"
	fi
	if [ "$(cat $S/net)" = yes ]; then
		if grep -q ' 0.0% packet loss' $S/ping 2>/dev/null; then echo "L2-NET-OK $(tail -1 $S/ping)"
		else echo "L2-NET-FAIL $(tail -2 $S/ping 2>/dev/null | tr '\n' ' ')"; fi
	fi
	if [ "$(cat "$S/devices" 2>/dev/null)" = storage ]; then
		con | grep '^L2-DEVICE '
		for kind in virtio-blk nvme ahci; do
			for stage in before after; do
				con | grep -q "^L2-DEVICE $kind $stage PASS " || ok=no
			done
			case "$kind" in virtio-blk) seed=811 ;; nvme) seed=812 ;; ahci) seed=813 ;; esac
			if dd if="$S/$kind.img" of="$S/backing-read" bs=1m count=4 2>/dev/null &&
			    backing_got=$(sha256 -q "$S/backing-read") &&
			    backing_want=$("$T" expect 4 "$seed") &&
			    [ -n "$backing_want" ] && [ "$backing_got" = "$backing_want" ]; then
				echo "L2-BACKING $kind PASS"
			else
				echo "L2-BACKING $kind FAIL"; ok=no
			fi
		done
	fi
	if [ $ok = yes ]; then
		echo "L2-OK bhyve_exit=$rc seconds=$((t1 - t0)) ticks=$(con | grep -c HOSTTEST-L2-TICK)"
	else
		echo "-- L2 console (last 40 lines)"; con | tail -40
		echo "-- bhyve output"; cat $S/bhyve 2>/dev/null
		echo "L2-FAIL bhyve_exit=$rc$([ -s $S/diag ] || [ -s $S/diag.wd ] && echo ' (L2-DIAG above)')"
		return 5
	fi
}

# Include cleanup/checksum reporting in the advertised foreground budget.
# The host command deadline remains authoritative if L1 stops scheduling.
l2_report()
{
	r_lim=$((L2_REPORT_LIM - L2_GRACE - 3))
	[ "$r_lim" -gt 0 ] || r_lim=1
	L2_BDIAG=no bounded "$r_lim" $S/report l2_report_body
	r_status=$?
	cat $S/report
	if [ "$r_status" -eq 124 ]; then
		echo "L2-FAIL report exceeded its ${L2_REPORT_LIM}s budget"
		return 5
	fi
	return "$r_status"
}

# Capture in the foreground, before reporting can remove/reuse the run
# directory. Leave enough lifetime for this capture to finish before the
# watchdog starts its own diagnostic pass.
l2_sample_if_due()
{
	[ "$sampled" = no ] && [ "${L2_SAMPLE_AFTER:-15}" -gt 0 ] || return 0
	sample_elapsed=$(( $(date +%s) - $(cat $S/t0) ))
	[ "$sample_elapsed" -ge "${L2_SAMPLE_AFTER:-15}" ] || return 0
	[ $((sample_elapsed + L2_DIAG_LIM + 5)) -lt "$fgwait" ] || return 0
	sampled=yes
	diag_live=yes diag_sfx=.sample
	l2_diag "L2 still running; early state capture"
	diag_live=no diag_sfx=
}

# l2_end_bhyve REASON: diagnostics while it is stuck, then stop it.
l2_end_bhyve()
{
	l2_diag "$1"
	p=$(cat $S/bhyvepid 2>/dev/null)
	[ -n "$p" ] && l2_kill "$p" bhyve
	w=0; while [ ! -f $S/rc ] && [ $w -lt 5 ]; do sleep 1; w=$((w + 1)); done
	[ -f $S/rc ] || echo stuck > $S/rc
}

case "${1:-}" in
--limits)
	l2_limits "${L2_TIMEOUT:-120}" "${L2_BUDGET:-}" "${L2_BG:-no}"
	echo "L2-LIMITS console=5 destroy=$L2_DESTROY_LIM bhyveload=$L2_LOAD_LIM bhyve=$lim wait=$fgwait grace=$L2_GRACE diag=$L2_DIAG_LIM report=$L2_REPORT_LIM total=$total budget=${L2_BUDGET:-none}"
	exit 0 ;;
--status)
	t=$(con | sed -n 's/.*HOSTTEST-L2-TICK n=\([0-9]*\).*/\1/p' | tail -1)
	echo "L2-STATUS tick=${t:-none} rc=$(cat $S/rc 2>/dev/null || echo running)"
	exit 0 ;;
--wait)
	lim=${2:-600}; wait_start=$(date +%s)
	while [ ! -f $S/rc ] && [ $(( $(date +%s) - wait_start )) -lt "$lim" ]; do sleep 1; done
	if [ ! -f $S/rc ]; then
		echo "L2-WAIT-TIMEOUT after ${lim}s"
		kill "$(cat $S/watchdog 2>/dev/null)" 2>/dev/null
		l2_end_bhyve "--wait ${lim}s expired"
	fi
	l2_report; exit $? ;;
esac

m=${1:?marker} mem=${2:-${L2_MEM:-512M}} disk=/dev/vtbd1
cpus=${L2_CPUS:-1} work=${L2_WORK:-0} hold=${L2_HOLD:-0} net=${L2_NET:-no}
bg=${L2_BG:-no}
[ "$bg" = yes ] || live=${L2_LIVE:-/dev/console}
l2_limits "${L2_TIMEOUT:-120}" "${L2_BUDGET:-}" "$bg"
echo "L1 cpu: $(sysctl -n hw.model) ncpu=$(sysctl -n hw.ncpu)"
echo "L2-LIMITS console=5 bhyveload=$L2_LOAD_LIM bhyve=$lim wait=$fgwait total=$total budget=${L2_BUDGET:-none} live=$live"
grep -o 'Features2=[^ ]*' /var/run/dmesg.boot | head -1
grep -E 'AMD Features2|SVM:|VT-x:' /var/run/dmesg.boot | head -3
if ! kldstat -q -m vmm || [ ! -e "$VMMCTL" ]; then
	echo "L1-VMM-NOT-LOADED"; dmesg | grep -i -E 'vmm|svm|vmx|hypertrace' | tail -8; exit 3
fi
sysctl hw.vmm.svm.features hw.vmm.svm.num_asids hw.vmm.vmx.initialized 2>/dev/null
# Baseline: what L1 is busy with before L2 starts (gen4: L1 used 2.65 vCPUs).
echo "-- L1 baseline: top threads by CPU"
timeout -k 2 "$L2_BASE_LIM" top -b -S -H -o cpu -s 1 -d 2 8 2>&1 | sed -n '/^last pid/,$p' | tail -10
[ -s $S/conpid ] && kill "$(cat $S/conpid)" 2>/dev/null
[ -d $S ] && l2_live_stop
mkdir -p $S
bounded "$L2_DESTROY_LIM" $S/destroy0 bhyvectl --vm=l2 --destroy
[ $? -eq 124 ] && { echo "L2-FAIL bhyvectl --destroy of a stale l2 did not finish"; exit 4; }
rm -rf $S; mkdir -p $S
echo "$m" > $S/marker; echo "$cpus" > $S/cpus; echo "$work" > $S/work; echo "$net" > $S/net
slots="" kenv=""
case "${L2_DEVICES:-none}" in
none) ;;
storage)
 for kind in virtio-blk nvme ahci; do
  truncate -s 16m "$S/$kind.img" || exit 6
 done
 slots="-s 5,virtio-blk,$S/virtio-blk.img -s 6,nvme,$S/nvme.img -s 7,ahci-hd,$S/ahci.img"
 kenv="-e hosttest.l2devices=storage"
 ;;
*) echo 'L2-FAIL invalid L2_DEVICES'; exit 6 ;;
esac
echo "${L2_DEVICES:-none}" > "$S/devices"
: > $S/console; : > $S/bhyve
# Configure and hold the receiving tty before any loader output.  A plain
# cat leaves ECHO/ICANON enabled and can feed the boot menu back as input.
reader=${L2_CONSOLE_READER:-/root/hosttest/l2-console}
"$reader" "$CONDEV" "$S/console.ready" > "$S/console" 2> "$S/console-reader.err" &
echo $! > "$S/conpid"
console_start=$(date +%s)
while [ ! -e "$S/console.ready" ]; do
	if ! kill -0 "$(cat "$S/conpid")" 2>/dev/null ||
	    [ $(( $(date +%s) - console_start )) -ge 5 ]; then
		kill "$(cat "$S/conpid")" 2>/dev/null || :
		cat "$S/console-reader.err"
		echo "L2-FAIL console reader did not initialize"
		exit 4
	fi
	sleep 0.1
done
l2_live $S/console L2
l2_live $S/bhyve L2-bhyve
if [ "$net" = yes ]; then
	tap=$(ifconfig tap create) || { echo "L2-FAIL cannot create a tap in L1"; exit 6; }
	echo "$tap" > $S/tap
	ifconfig "$tap" inet 10.231.78.1/24 up
	slots="$slots -s 4,virtio-net,$tap"; kenv="$kenv -e hosttest.inet=10.231.78.2/24"
fi
echo "L2 stage: bhyveload (limit ${L2_LOAD_LIM}s)"
# shellcheck disable=SC2086
bounded "$L2_LOAD_LIM" $S/load bhyveload -c /dev/nmdm7A -m "$mem" -d "$disk" -e hosttest.role=l2 \
    -e "hosttest.marker=$m" -e hosttest.hostname=ht-l2 -e "hosttest.l2work=$work" \
    -e "hosttest.l2hold=$hold" $kenv l2
lrc=$?
if [ $lrc -ne 0 ]; then
	cat $S/load; echo "L2-FAIL bhyveload rc=$lrc$([ $lrc -eq 124 ] && echo " (overran ${L2_LOAD_LIM}s; L2-DIAG above)")"
	kill "$(cat $S/conpid)" 2>/dev/null; l2_live_stop; exit 4
fi
date +%s > $S/t0
echo "L2 stage: bhyve (limit ${lim}s)"
# shellcheck disable=SC2086
( bhyve -c "$cpus" -m "$mem" -H -w -D -s 0,hostbridge -s 3,virtio-blk,"$disk" \
    $slots -s 31,lpc -l com1,/dev/nmdm7A l2 >> $S/bhyve 2>&1 & echo $! > $S/bhyvepid
  wait $!; echo $? > $S/rc.tmp; mv $S/rc.tmp $S/rc ) > /dev/null 2>&1 &
# Lifetime limit, also for a background run after this script returned.
( diag_live=yes diag_sfx=.wd; wd_start=$(cat $S/t0)
  while [ ! -f $S/rc ] && [ ! -f $S/watchdog-stop ] && [ $(( $(date +%s) - wd_start )) -lt "$lim" ]; do sleep 1; done
  if [ ! -f $S/rc ] && [ ! -f $S/watchdog-stop ]; then
	echo "L2-TIMEOUT bhyve still running after ${lim}s" >> $S/bhyve
	l2_end_bhyve "bhyve lifetime limit ${lim}s"
  fi
  : > $S/watchdog-done ) > /dev/null 2>&1 &
echo $! > $S/watchdog
sampled=no
if [ "$hold" -gt 0 ]; then
	# Wait until L2 holds (it is up) or the run ends.
	hold_start=$(cat $S/t0)
	while [ ! -f $S/rc ] && [ $(( $(date +%s) - hold_start )) -lt "$fgwait" ] && ! con | grep -q 'HOSTTEST-L2-HOLD start'; do
		l2_sample_if_due
		sleep 1
	done
	if [ "$bg" = yes ] && [ ! -f $S/rc ] && ! con | grep -q 'HOSTTEST-L2-HOLD start'; then
		: > $S/watchdog-stop
		l2_end_bhyve "L2 did not reach its hold within ${fgwait}s"
		l2_report; exit $?
	fi
	if [ "$net" = yes ] && [ ! -f $S/rc ]; then
		sleep 2; ping -c 3 -t 10 10.231.78.2 > $S/ping 2>&1
	fi
	if [ "$bg" = yes ]; then
		[ -f $S/rc ] && { l2_report; exit $?; }
		echo "L2-BG-RUNNING after $(( $(date +%s) - $(cat $S/t0) ))s"
		exit 0
	fi
fi
# The watchdog ends bhyve at $lim (after diagnostics); wait for it, bounded
# from bhyve's start (a hold wait above is part of the same budget).
t0=$(cat $S/t0)
while [ ! -f $S/rc ] && [ $(( $(date +%s) - t0 )) -lt $((lim + L2_GRACE + 3 + L2_DIAG_LIM + 5)) ]; do
	l2_sample_if_due
	sleep 1
done
if [ ! -f $S/rc ]; then
	# Its diagnostics are in diag.wd; no second round (budget).
	: > $S/watchdog-stop
	kill -KILL "$(cat $S/bhyvepid 2>/dev/null)" 2>/dev/null
	echo "L2-STUCK bhyve did not end $((lim + L2_GRACE + 3 + L2_DIAG_LIM + 5))s after its start"
	echo stuck > $S/rc
fi
[ -s $S/diag.wd ] && { echo "-- L2-DIAG from the lifetime watchdog"; cat $S/diag.wd; }
sleep 1
l2_report
