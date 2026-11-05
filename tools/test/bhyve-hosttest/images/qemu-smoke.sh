#!/bin/sh
# Unprivileged smoke test of the guest image under QEMU/TCG (authoring aid:
# bhyve needs root and vmm). Checks boot, the serial autologin with /bin/sh,
# the rc.local marker, the console command driver, the guest helpers and
# which HyperTrace/vmm modules the guest loaded.
#   usage: images/qemu-smoke.sh [IMAGE] [WORKDIR]
set -u
KIT=$(cd "$(dirname "$0")/.." && pwd)
IMG=${1:-/usr/obj/5BSD-otel-validation/hosttest-images/current/guest.img}
W=${2:-/usr/obj/5BSD-otel-validation/hosttest-results/qemu-smoke}
Q=${QEMU:-/usr/local/bin/qemu-system-x86_64}
[ -x "$Q" ] || { echo "no QEMU at $Q" >&2; exit 2; }
rm -rf "$W"; mkdir -p "$W"
cp "$IMG" "$W/disk.img"
port=4790; while sockstat -4 -l | grep -q "127.0.0.1:$port[[:space:]]"; do port=$((port + 1)); done
"$Q" -accel tcg,thread=multi -machine q35 -cpu max -m 2048 -smp 2 \
    -drive file="$W/disk.img",format=raw,if=virtio -nic none -display none \
    -serial "tcp:127.0.0.1:$port,server=on,wait=on" > "$W/qemu.log" 2>&1 &
qpid=$!
conpid=
trap 'kill $qpid 2>/dev/null; [ -z "$conpid" ] || { pkill -P $conpid; kill $conpid; } 2>/dev/null; rm -f "$W/disk.img"' EXIT
# Connect only once QEMU listens (sr2: a fixed 2 s sleep lost the race on
# a loaded host; nc then exited and the console stayed empty).
i=0; while ! sockstat -4 -l | grep -q "127.0.0.1:$port[[:space:]]" && [ $i -lt 120 ]; do sleep 0.5; i=$((i + 1)); done
: > "$W/console"; : > "$W/input"
(tail -f "$W/input" | nc 127.0.0.1 "$port" >> "$W/console" 2>&1) &
conpid=$!
t0=$(date +%s)
until tr -d '\r' < "$W/console" | grep -q HOSTTEST-GUEST-READY; do
	kill -0 $qpid 2>/dev/null || { echo "qemu exited"; cat "$W/qemu.log"; exit 1; }
	[ $(( $(date +%s) - t0 )) -lt ${TIMEOUT:-900} ] || { echo "no ready marker"; tail -30 "$W/console"; exit 1; }
	sleep 2
done
echo "ready after $(( $(date +%s) - t0 )) s"
sleep 5   # let getty autologin settle
g() { CONSOLE_LOG=$W/console CONSOLE_INPUT=$W/input sh "$KIT/lib/acmd-console.sh" "$1" "${2:-60}"; }
rc=0
g 'echo SHELL=$0 USER=$(id -un); hostname; cat /etc/hosttest-generation' 60 | tee "$W/whoami.txt" || rc=1
g 'kldstat | grep -E "dtrace|dttransport|virtio_dtrace|vmm|nmdm"; ls -l /dev/dttransport /dev/vmm 2>&1; dmesg | grep -i -E "vmm|undefined|hypertrace" | tail -5' 60 | tee "$W/modules.txt" || true
g '/root/hosttest/counter.sh start; sleep 1; /root/hosttest/counter.sh read' 30 | tee "$W/counter.txt" || rc=1
g '/root/hosttest/workload.sh htsmoke 3' 60 | tee "$W/workload.txt" || rc=1
g 'ls -l /root/hosttest /var/ddtrace; /root/hosttest/vsock-pipe 2>&1 | head -2; true' 30 | tee "$W/files.txt" || rc=1
g 'i=0; while [ $i -lt 40 ]; do printf "%s" "long-command-chunking-check-"; i=$((i+1)); done; echo; echo LONG-OK' 60 | grep -q LONG-OK || { echo "long command path failed"; rc=1; }
grep -q 'SHELL=.*sh USER=root' "$W/whoami.txt" || { echo "console is not a root sh"; rc=1; }
grep -q 'COUNTER value=[1-9]' "$W/counter.txt" || { echo "counter failed"; rc=1; }
grep -q 'WORKLOAD tag=htsmoke runs=[1-9]' "$W/workload.txt" || { echo "workload failed"; rc=1; }
# sr2 guest helpers (guest/sr-guest.sh, guest/l2-role.sh, guest-bin/srtool),
# judged with the same library functions the phases use; the reference
# digests come from the host copy of srtool.
if [ "${SMOKE_SR2:-yes}" = yes ]; then
	(
	HT_KIT=$KIT; . "$KIT/lib/common.sh" > /dev/null 2>&1; trap - EXIT
	SR=$KIT/guest-bin/srtool G=/root/hosttest/sr-guest.sh
	sr2rc=0
	nok() { echo "sr2 FAIL $*"; sr2rc=1; }
	E=$("$SR" expect 32 5)
	g "$G prep 32 5; $G spin 2" 180 > "$W/sr-prep.txt" 2>&1
	g "$G read" 120 > "$W/sr-read1.txt" 2>&1
	sleep 2
	g "$G read" 120 > "$W/sr-read2.txt" 2>&1
	set -- $(sr_hold_verdict "$W/sr-read1.txt" "$E"); [ "$1" = ok ] && echo "sr2 ok holder: $*" || nok "holder: $*"
	[ "$(sr_val "$W/sr-read1.txt" 'SRFILE ' sha256)" = "$E" ] && echo "sr2 ok pattern file = host digest" || nok "file $(grep SRFILE "$W/sr-read1.txt")"
	set -- $(sr_spin_verdict "$W/sr-read1.txt" "$W/sr-read2.txt" 2); [ "$1" = ok ] && echo "sr2 ok vcpus: $*" || nok "spin: $*"
	set -- $(sr_clock_verdict "$W/sr-read1.txt" "$W/sr-read2.txt" 2); [ "$1" = ok ] && echo "sr2 ok clock: $*" || nok "clock: $*"
	grep -q 'SRTMPFS unavailable' "$W/sr-prep.txt" && nok "tmpfs for status files unavailable" || echo "sr2 ok status files on tmpfs"
	g "$G write sm 4 6" 60 > "$W/sr-write.txt" 2>&1
	[ "$(sr_val "$W/sr-write.txt" 'SRPOST ' sha256)" = "$("$SR" expect 4 6)" ] && echo "sr2 ok write+readback" || nok "write $(cat "$W/sr-write.txt")"
	g "$G exists sm; $G exists nope" 30 > "$W/sr-exists.txt" 2>&1
	grep -q 'SREXISTS tag=sm yes' "$W/sr-exists.txt" && grep -q 'SREXISTS tag=nope no' "$W/sr-exists.txt" && echo "sr2 ok exists" || nok "exists $(cat "$W/sr-exists.txt")"
	g "$G tcp-listen 5601; $G tcp-send 127.0.0.1 5601 smoketok; $G tcp-got 5601" 60 > "$W/sr-tcp.txt" 2>&1
	grep -q 'SRTCP-GOT port=5601 data=smoketok' "$W/sr-tcp.txt" && echo "sr2 ok tcp (loopback)" || nok "tcp $(cat "$W/sr-tcp.txt")"
	g "$G dirty 16; sleep 3; $G dirty-read" 60 > "$W/sr-dirty.txt" 2>&1
	p=$(sr_val "$W/sr-dirty.txt" 'SRDIRTY ' pass) e=$(sr_val "$W/sr-dirty.txt" 'SRDIRTY ' errors)
	[ -n "$p" ] && [ "$p" -gt 1 ] && [ "$e" = 0 ] && grep -q 'alive=yes' "$W/sr-dirty.txt" && echo "sr2 ok dirty pass=$p errors=0" || nok "dirty $(tail -1 "$W/sr-dirty.txt")"
	g "$G cpuleaves" 60 > "$W/sr-leaves.txt" 2>&1
	for l in 0x80000026 0x1a; do echo "sr2 info leaf $l: $(sr_leaf_verdict "$W/sr-leaves.txt" $l)"; done
	grep -q '^SRLEAF cpu=1 ' "$W/sr-leaves.txt" && echo "sr2 ok cpuleaves read on every vCPU (cpuctl preloaded)" || nok "cpuleaves $(head -2 "$W/sr-leaves.txt")"
	g "L2_CONSOLE=/dev/stdout /root/hosttest/l2-role.sh SMK 4 2" 120 > "$W/l2-role.txt" 2>&1
	w0=$("$SR" expect 4 1000) w1=$("$SR" expect 4 1001)
	grep -q 'HOSTTEST-L2-MARKER SMK .*ncpu=2' "$W/l2-role.txt" && grep -q "HOSTTEST-L2-WORK cpu=0 sum=$w0 ran_on=0" "$W/l2-role.txt" &&
	    grep -q "HOSTTEST-L2-WORK cpu=1 sum=$w1 ran_on=1" "$W/l2-role.txt" && [ "$(grep -c 'HOSTTEST-L2-TICK n=' "$W/l2-role.txt")" -eq 2 ] &&
	    grep -q HOSTTEST-L2-HOLD-END "$W/l2-role.txt" && echo "sr2 ok l2-role marker, per-vCPU checksums, hold ticks" || nok "l2-role $(cat "$W/l2-role.txt")"
	g "$G stop; sleep 1; pgrep -f srtool || echo NONE-LEFT" 30 > "$W/sr-stop.txt" 2>&1
	grep -q NONE-LEFT "$W/sr-stop.txt" && echo "sr2 ok stop" || nok "stop $(cat "$W/sr-stop.txt")"
	exit $sr2rc
	) | tee "$W/sr2.txt"
	grep -q 'sr2 FAIL' "$W/sr2.txt" && rc=1
fi
g 'shutdown -p now' 10 >/dev/null 2>&1
i=0; while kill -0 $qpid 2>/dev/null && [ $i -lt 120 ]; do sleep 1; i=$((i + 1)); done
echo "SMOKE $([ $rc -eq 0 ] && echo PASS || echo FAIL) (logs in $W)"
exit $rc
