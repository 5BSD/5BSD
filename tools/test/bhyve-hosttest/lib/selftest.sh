#!/bin/sh
# Unprivileged self-test of lib/common.sh logic (results, cleanup ordering,
# dry-run refusals, ht_session fan-out, workload parsing). Uses stubs for
# dtrace and the guest console; no VMs, no root.
set -u
HT_KIT=$(cd "$(dirname "$0")/.." && pwd -P); export HT_KIT
T=$(mktemp -d /usr/obj/5BSD-otel-validation/hosttest-results/selftest.XXXXXX)
HT_RUN=$T/run; mkdir -p "$HT_RUN"; : > "$HT_RUN/SUMMARY"; export HT_RUN
fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }

# 1. results + cleanup LIFO
(
	HT_DRYRUN=no; . "$HT_KIT/lib/common.sh"
	phase_begin t1
	at_cleanup "echo first >> $T/order"
	at_cleanup "echo second >> $T/order"
	check a PASS x; check b SKIP y; check c INFO z
	phase_end
) > "$T/t1.out" 2>&1
[ "$(cat "$T/order" | tr '\n' ' ')" = "second first " ] && ok "cleanup LIFO" || bad "cleanup order: $(cat "$T/order")"
grep -q '^t1 PASS pass=1 fail=0 skip=1' "$HT_RUN/SUMMARY" && ok "phase_end PASS" || bad "summary: $(cat "$HT_RUN/SUMMARY")"
(
	HT_DRYRUN=no; . "$HT_KIT/lib/common.sh"
	phase_begin t2; check a PASS; check b FAIL boom; phase_end
) > /dev/null 2>&1 && bad "FAIL phase returned 0" || ok "FAIL phase returns nonzero"
grep -q '^t2 FAIL pass=1 fail=1' "$HT_RUN/SUMMARY" && ok "phase_end FAIL" || bad "t2 summary"

# 2. refuse: real mode exits 3, dry mode records and continues
( HT_DRYRUN=no; . "$HT_KIT/lib/common.sh"; phase_begin t3; refuse "nope"; echo NOTREACHED ) > "$T/t3.out" 2>&1
rc=$?
[ $rc -eq 3 ] && ! grep -q NOTREACHED "$T/t3.out" && ok "refuse exits 3" || bad "refuse rc=$rc"
( HT_DRYRUN=yes; . "$HT_KIT/lib/common.sh"; phase_begin t4; need_module nosuchmodule_ht; need_tool nosuchtool_ht; dry_end ) > "$T/t4.out" 2>&1
grep -q '^t4 WOULD-REFUSE' "$HT_RUN/SUMMARY" && [ "$(grep -c WOULD-REFUSE "$HT_RUN/t4/checks.tsv")" -eq 2 ] &&
    ok "dry-run collects refusals" || bad "dry-run: $(cat "$HT_RUN/t4/checks.tsv")"

# 3. ht_session fans out guest commands and waits for them, not for other
#    background jobs; ht_runs parses the workload line.
mkdir -p "$T/stub"
cat > "$T/stub/dtrace" <<'EOF2'
#!/bin/sh
echo "ARGS $*"; sleep 2; echo "  ht-trace1   htmark1   42"
EOF2
chmod +x "$T/stub/dtrace"
(
	HT_DRYRUN=no; . "$HT_KIT/lib/common.sh"; PATH=$T/stub:$PATH
	phase_begin t5; HT_WORK=$T/w; mkdir -p "$HT_WORK"
	vm_cmd() { sleep 1; echo "WORKLOAD tag=$(echo "$2" | awk '{print $2}') runs=17 on $1"; }
	sleep 30 & bg=$!
	s0=$(date +%s)
	ht_session s 5 1 "ht-trace1:/root/hosttest/workload.sh htmark1 3;ht-trace2:/root/hosttest/workload.sh htmark9 3" -- \
	    -n 'ht-trace1:syscall:::entry { @[vmname] = count(); }'
	s1=$(date +%s)
	kill $bg
	echo "elapsed $((s1 - s0))"
	echo "runs1 $(ht_runs "$HT_OUT/s.ht-trace1.guest") runs2 $(ht_runs "$HT_OUT/s.ht-trace2.guest")"
	cat "$HT_OUT/s.out"
) > "$T/t5.out" 2>&1
grep -q 'runs1 17 runs2 17' "$T/t5.out" && ok "ht_session guest fan-out" || bad "fan-out: $(cat "$T/t5.out")"
e=$(sed -n 's/^elapsed //p' "$T/t5.out")
[ -n "$e" ] && [ "$e" -lt 10 ] && ok "ht_session does not wait on unrelated jobs ($e s)" || bad "elapsed $e"
grep -q "ARGS -E -q -n ht-trace1:syscall" "$T/t5.out" && ok "dtrace -E argv" || bad "argv: $(grep ARGS "$T/t5.out")"

# 4. (htcap) forwarder registration is the channel count, not the VM name.
mkdir -p "$T/stub4"
cat > "$T/stub4/dtracedctl" <<'EOF2'
#!/bin/sh
# Real format: dtracedctl --show-stats=NAME never prints NAME.
case "$1" in
--show-stats=ht-two) n=2 ;; --show-stats=ht-one) n=1 ;; *) n=0 ;;
esac
printf 'forwarder channels: %s\noutbound deliveries: 0\ninstalled deliveries: 0\nrevoked deliveries: 0\n' "$n"
EOF2
chmod +x "$T/stub4/dtracedctl"
(
	HT_DRYRUN=no; . "$HT_KIT/lib/common.sh"; PATH=$T/stub4:$PATH
	phase_begin t6; HT_WORK=$T/w6; mkdir -p "$HT_WORK"
	ht_wait_forwarder ht-two 2 && echo "two ok" || echo "two FAIL"
	ht_wait_forwarder ht-one 2 && echo "one WRONG" || echo "one refused"
	ht_wait_forwarder ht-none 2 && echo "none WRONG" || echo "none refused"
) > "$T/t6.out" 2>&1
grep -q 'two ok' "$T/t6.out" && grep -q 'one refused' "$T/t6.out" && grep -q 'none refused' "$T/t6.out" &&
    ok "ht_wait_forwarder needs rx+wx channels" || bad "forwarder: $(cat "$T/t6.out")"

# 4b. Delivery evidence survives ledger deletion at session teardown.
mkdir -p "$T/stub4b"
cat > "$T/stub4b/dtracedctl" <<'EOF2'
#!/bin/sh
case "$1" in --show-stats=ht-trace1) o=1 i=1 ;; *) o=0 i=0 ;; esac
[ ! -f "$DELIVERY_DONE" ] || { o=0; i=0; }
printf 'forwarder channels: 2\noutbound deliveries: %s\ninstalled deliveries: %s\nrevoked deliveries: 0\n' "$o" "$i"
EOF2
cat > "$T/stub4b/dtrace" <<'EOF2'
#!/bin/sh
sleep 3
: > "$DELIVERY_DONE"
EOF2
chmod +x "$T/stub4b/dtracedctl" "$T/stub4b/dtrace"
(
	HT_DRYRUN=no; . "$HT_KIT/lib/common.sh"; PATH=$T/stub4b:$PATH
	phase_begin t6b; HT_WORK=$T/w6b; mkdir -p "$HT_WORK"
	DELIVERY_DONE=$HT_WORK/done; export DELIVERY_DONE
	HT_VMS=" ht-trace1 ht-trace2"
	printf 'ERROR: x.cc:1 failed to handle job kind 1 for ht-trace2: Operation timed out\n' > "$HT_OUT/dtraced.log"
	vm_cmd() { :; }
	ht_session d 8 0 "" -- -n 'ht-trace1:syscall:::entry { @ = count(); }'
	ht_err d
	grep -q "installed deliveries: 0" "$HT_OUT/d.stats-after.ht-trace1" && echo "teardown zero"
	# Reuse the same name after DELIVERY_DONE: every new counter is zero.
	ht_session d 8 0 "" -- -n 'ht-trace1:syscall:::entry { @ = count(); }'
	ht_delivered d ht-trace1 || echo "stale sample rejected"
) > "$T/t6b.out" 2>&1
grep -q 'deliveries out/inst: ht-trace1=1/1 ht-trace2=0/0; dtraced job failures: 1' "$T/t6b.out" &&
    ok "ht_err retains live deliveries after teardown clears ledger" || bad "delivery: $(cat "$T/t6b.out")"

grep -q 'stale sample rejected' "$T/t6b.out" && ok "reused session clears old delivery evidence" || bad "stale delivery success"

# A wedged statistics client may ignore TERM; the sampler must still stop.
mkdir -p "$T/stub4d" "$T/t6d"
cat > "$T/stub4d/dtracedctl" <<'EOF2'
#!/bin/sh
trap '' TERM
exec sleep 30
EOF2
chmod +x "$T/stub4d/dtracedctl"
env HT_KIT="$HT_KIT" HT_OUT="$T/t6d" STUBDIR="$T/stub4d" \
    timeout -k 1 10 sh -c '. "$HT_KIT/lib/common.sh"; PATH=$STUBDIR:$PATH; ht_sample_delivery s ht-test' \
    > "$T/t6d.out" 2>&1 && ok "stats sampler kills a TERM-resistant client" || bad "unbounded stats sampler"

grep -q 'teardown zero' "$T/t6b.out" && ok "teardown sample retained separately" || bad "teardown stats missing"

# A later sample with installed=1/outbound=0 cannot replace success.
(
	HT_DRYRUN=no; . "$HT_KIT/lib/common.sh"; phase_begin t6c
	mkdir -p "$T/stub4c"
	cat > "$T/stub4c/dtracedctl" <<'EOF2'
#!/bin/sh
printf 'outbound deliveries: 0\ninstalled deliveries: 1\n'
EOF2
	chmod +x "$T/stub4c/dtracedctl"
	PATH=$T/stub4c:$PATH
	printf 'outbound deliveries: 1\ninstalled deliveries: 1\n' > "$HT_OUT/s.stats.ht-a"
	ht_sample_delivery s ht-a
	ht_delivered s ht-a
) > "$T/t6c.out" 2>&1 && ok "live success survives later inconsistent sample" || bad "live sample retention"

# 5. (htcap) restore/migration targets are created empty first; suspend verdicts.
mkdir -p "$T/stub5"
cat > "$T/stub5/bhyvectl" <<'EOF2'
#!/bin/sh
echo "bhyvectl $*" >> "$STUBLOG"
case "$*" in
*--suspend=*)
	f=${*##*--suspend=}; f=${f%% *}
	[ "$SUSPEND_MODE" = none ] || echo BHYVE-CHECKPOINT-MANIFEST-3 > "$f"
	kill "$(cat "$VMPIDFILE")"
	[ "$SUSPEND_MODE" = noreply ] && { echo "nvlist_xfer() failed: Socket is not connected"; echo "errno = 57"; exit 57; }
	[ "$SUSPEND_MODE" = none ] && exit 1
	exit 0 ;;
esac
exit 0
EOF2
chmod +x "$T/stub5/bhyvectl"
(
	HT_DRYRUN=no; . "$HT_KIT/lib/common.sh"; PATH=$T/stub5:$PATH
	export STUBLOG=$T/stub5.log; : > "$STUBLOG"
	phase_begin t7; HT_WORK=$T/w7; mkdir -p "$HT_WORK"
	vm_create_empty ht-rst && echo "create rc=0"
	grep -q -- '--vm=ht-rst --destroy' "$STUBLOG" && grep -q -- '--create --vm=ht-rst' "$STUBLOG" && echo "create order ok"
	vm_create_empty not-ht 2>/dev/null || echo "name guard ok"
	for m in ok noreply none; do
		# bhyve stand-in that exits 5 (BHYVE_EXIT_SUSPEND) on SIGTERM.
		SUSPEND_READY=$HT_WORK/suspend-ready; export SUSPEND_READY
		rm -f "$SUSPEND_READY"
		sh -c 'trap "exit 5" TERM; : > "$SUSPEND_READY"; while :; do sleep 0.1; done' &
		echo $! > "$HT_WORK/ht-s.pid"; export VMPIDFILE=$HT_WORK/ht-s.pid SUSPEND_MODE=$m
		i=0
		while [ ! -e "$SUSPEND_READY" ] && [ "$i" -lt 50 ]; do
			sleep 0.1; i=$((i + 1))
		done
		[ -e "$SUSPEND_READY" ] || {
			kill -KILL "$(cat "$VMPIDFILE")" 2>/dev/null
			wait "$(cat "$VMPIDFILE")" 2>/dev/null
			exit 1
		}
		rm -f "$HT_WORK/ckp-$m"
		vm_suspend ht-s "$HT_WORK/ckp-$m" "susp-$m" "$HT_WORK/susp-$m.txt" 10 && echo "restorable $m" || echo "not-restorable $m"
	done
) > "$T/t7.out" 2>&1
grep -q 'create rc=0' "$T/t7.out" && grep -q 'create order ok' "$T/t7.out" && grep -q 'name guard ok' "$T/t7.out" &&
    ok "vm_create_empty destroys stale then creates" || bad "create: $(cat "$T/t7.out")"
c=$HT_RUN/t7/checks.tsv
grep -q '^susp-ok	PASS	bhyve exited suspended (status 5)' "$c" &&
    grep -q '^susp-noreply	FAIL	suspend worked (checkpoint published, bhyve exit 5) but bhyvectl rc=57' "$c" &&
    grep -q '^susp-none	FAIL	bhyvectl rc=1 bhyve=5 published=no' "$c" &&
    grep -q 'restorable ok' "$T/t7.out" && grep -q 'restorable noreply' "$T/t7.out" && grep -q 'not-restorable none' "$T/t7.out" &&
    ok "vm_suspend verdicts (acknowledged / unanswered / unpublished)" || bad "suspend: $(cat "$c") $(cat "$T/t7.out")"

# ============================ sr2 cases ======================================
SR=$HT_KIT/guest-bin/srtool
# sr2-1. vendor detection, nested gate, capability report (Intel readiness).
mkdir -p "$T/stub8"
printf '  Origin="AuthenticAMD"  Id=0xa70f52  Family=0x19  Model=0x75  Stepping=2\n  SVM: NP,NRIP,VClean,AFlush,DAssist,NAsids=32768\n' > "$T/dmesg.amd"
printf '  Origin="GenuineIntel"  Id=0xb06a2  Family=0x6  Model=0xba  Stepping=2\n  VT-x: PAT,HLT,MTF,PAUSE,EPT,UG,VPID\n' > "$T/dmesg.intel"
printf 'nothing here\n' > "$T/dmesg.none"
cat > "$T/stub8/sysctl" <<'EOF2'
#!/bin/sh
[ "$1" = -n ] && shift
case "$1" in
hw.vmm.svm.nested) echo "${STUB_SVM_NESTED:-1}" ;;
hw.vmm.vmx.nested) echo "${STUB_VMX_NESTED:-0}" ;;
hw.vmm.svm.features) [ -n "${STUB_SVM_FEATURES:-}" ] && echo "$STUB_SVM_FEATURES" || exit 1 ;;
hw.vmm.vmx.initialized) echo "${STUB_VMX_INIT:-0}" ;;
*) /sbin/sysctl -n "$1" ;;
esac
EOF2
chmod +x "$T/stub8/sysctl"
(
	. "$HT_KIT/lib/common.sh"; PATH=$T/stub8:$PATH
	STUB_SVM_NESTED=1 STUB_VMX_NESTED=0 STUB_VMX_INIT=0 STUB_SVM_FEATURES=""
	HT_DMESG_BOOT=$T/dmesg.amd; echo "v1=$(host_vendor)"
	echo "g1=$(nested_gate amd)"
	export STUB_SVM_NESTED STUB_VMX_NESTED STUB_VMX_INIT STUB_SVM_FEATURES
	STUB_SVM_NESTED=0; echo "g2=$(nested_gate amd) rc=$(nested_gate amd >/dev/null; echo $?)"; STUB_SVM_NESTED=1
	HT_DMESG_BOOT=$T/dmesg.intel; echo "v2=$(host_vendor)"
	echo "g3=$(nested_gate intel) rc=$(nested_gate intel >/dev/null; echo $?)"
	STUB_VMX_NESTED=1; echo "g4=$(nested_gate intel)"; STUB_VMX_NESTED=0
	HT_DMESG_BOOT=$T/dmesg.none; echo "v3=$(host_vendor)"
	STUB_VMX_INIT=1; echo "v4=$(host_vendor)"
	HT_DMESG_BOOT=$T/dmesg.intel; host_cap_report
) > "$T/t8.out" 2>&1
grep -q '^v1=amd$' "$T/t8.out" && grep -q '^g1=ok$' "$T/t8.out" && grep -q '^g2=hw.vmm.svm.nested is 0 rc=1' "$T/t8.out" &&
    grep -q '^v2=intel$' "$T/t8.out" && grep -q '^g3=Intel nested VMX off: hw.vmm.vmx.nested=0.* rc=1' "$T/t8.out" &&
    grep -q '^g4=ok$' "$T/t8.out" && grep -q '^v3=unknown$' "$T/t8.out" && grep -q '^v4=intel$' "$T/t8.out" &&
    grep -q '^host: vendor=intel .*Family=0x6 Model=0xba' "$T/t8.out" && grep -q '^host: virtualization: VT-x:' "$T/t8.out" &&
    grep -q '^host: nested gate: Intel nested VMX off' "$T/t8.out" && grep -q '^host: kernel ident=' "$T/t8.out" &&
    ok "host_vendor / nested_gate / host_cap_report (AMD, Intel off+on, unknown)" || bad "vendor: $(cat "$T/t8.out")"

# sr2-2. Intel with nested VMX off: nested phase is SKIP (not REFUSED/FAIL).
(
	HT_DRYRUN=no; . "$HT_KIT/lib/common.sh"; PATH=$T/stub8:$PATH
	HT_DMESG_BOOT=$T/dmesg.intel STUB_VMX_NESTED=0
	need_root() { :; }; need_generation() { :; }; need_vmm() { :; }; need_image() { :; }
	. "$HT_KIT/phases/nested.sh"
) > "$T/t9.out" 2>&1; rc=$?
[ $rc -eq 0 ] && grep -q '^nested SKIP pass=0 fail=0 skip=8' "$HT_RUN/SUMMARY" &&
    grep -q '^l2-boots-to-marker	SKIP	Intel nested VMX off: hw.vmm.vmx.nested=0' "$HT_RUN/nested/checks.tsv" &&
    ok "nested phase on Intel with hw.vmm.vmx.nested=0: SKIP with the reason (rc 0)" || bad "intel skip rc=$rc: $(cat "$T/t9.out")"

# sr2-3. Restore refusals reach the FAIL detail (fail-before: the gen3 kit
#        reported only "restored bhyve did not start (ht-snap.bhyve.log)").
grep -q 'restore-counter-continues FAIL "restored bhyve did not start (ht-snap.bhyve.log)"' "$HT_KIT/phases/snapshot.sh.bak-sr2" &&
    ! grep -q 'restored bhyve did not start' "$HT_KIT/phases/snapshot.sh" &&
    ok "before: snapshot restore FAIL had no cause; after: uses vm_restore/HT_REFUSAL" || bad "snapshot restore detail"
mkdir -p "$T/stub10"
cat > "$T/stub10/bhyve" <<'EOF2'
#!/bin/sh
# Stub bhyve: STUB_MODE early|late|run.
port=$(echo "$*" | sed -n 's/.*com1,tcp=127.0.0.1:\([0-9]*\).*/\1/p')
echo "Unhandled ps2 mouse command 0xe1"
case $STUB_MODE in
early)
	echo "Checkpoint CPU contract differs at CPUID 0x80000026.0 edx: source 0x00000004, destination 0x0000000a"
	echo "Checkpoint CPU contract is incompatible with this destination."
	exit 4 ;;
late)
	nc -l 127.0.0.1 "$port" > /dev/null 2>&1 & np=$!
	sleep 2
	echo "Checkpoint 'devices' topology is incompatible: Operation not supported by device"
	echo "Checkpoint topology or device contract is invalid."
	kill $np; exit 4 ;;
run)
	exec nc -l 127.0.0.1 "$port" > /dev/null 2>&1 ;;
esac
EOF2
cat > "$T/stub10/bhyvectl" <<'EOF2'
#!/bin/sh
exit 0
EOF2
chmod +x "$T/stub10/bhyve" "$T/stub10/bhyvectl"
(
	HT_DRYRUN=no; . "$HT_KIT/lib/common.sh"; PATH=$T/stub10:$PATH
	phase_begin t10; HT_WORK=$T/w10; mkdir -p "$HT_WORK"
	vm_mem_guard() { :; }
	printf '2\n1G\n-s 0,hostbridge -s 3,virtio-blk,/dev/null -s 31,lpc\n' > "$HT_WORK/ht-r.args"
	echo "old attempt: Checkpoint is not a current manifest." > "$HT_WORK/ht-r.bhyve.log"
	STUB_MODE=early; export STUB_MODE
	vm_restore ht-r /x/ckp && echo "early WRONG" || echo "early refusal=[$HT_REFUSAL]"
	STUB_MODE=late HT_RESTORE_SETTLE=6
	vm_restore ht-r /x/ckp && echo "late WRONG" || echo "late refusal=[$HT_REFUSAL]"
	STUB_MODE=run HT_RESTORE_SETTLE=2
	vm_restore ht-r /x/ckp && echo "run ok" || echo "run WRONG [$HT_REFUSAL]"
	vm_destroy ht-r
	printf 'Awaiting inbound live migration...\nInbound migration topology refused (reason 12): device 2 (virtio-blk) compat_crc32: source 0x11223345, destination 0x11223344\nInbound migration failed at phase 8 (reason 12).\n' > "$T/dst.log"
	echo "mig=[$(bhyve_refusal "$T/dst.log")]"
	printf 'Unhandled ps2 mouse command 0xe1\nsomething odd happened\n' > "$T/odd.log"
	echo "odd=[$(bhyve_refusal "$T/odd.log")]"
) > "$T/t10.out" 2>&1
grep -q 'early refusal=\[Checkpoint CPU contract differs at CPUID 0x80000026.0 edx: source 0x00000004, destination 0x0000000a; Checkpoint CPU contract is incompatible' "$T/t10.out" &&
    ! grep -q 'early refusal=.*old attempt' "$T/t10.out" &&
    ok "vm_restore: early refusal names the CPU contract field (this attempt only)" || bad "early: $(cat "$T/t10.out")"
grep -q "late refusal=\[bhyve exit 4 Checkpoint 'devices' topology is incompatible" "$T/t10.out" &&
    ok "vm_restore: refusal after the console listens is caught (settle wait)" || bad "late: $(grep late "$T/t10.out")"
grep -q 'run ok' "$T/t10.out" && ok "vm_restore: a running restore returns 0" || bad "run: $(grep run "$T/t10.out")"
sleep 1
if pgrep -f "tail -f $T/w10/ht-r.input" > /dev/null; then
	bad "console readers leaked: $(pgrep -lf "tail -f $T/w10/ht-r.input" | tr '\n' ' ')"; pkill -f "tail -f $T/w10/ht-r.input"
else
	ok "no console reader left behind after refused and accepted restores"
fi
grep -q 'mig=\[Inbound migration topology refused (reason 12): device 2 (virtio-blk) compat_crc32: source 0x11223345, destination 0x11223344; Inbound migration failed' "$T/t10.out" &&
    grep -q 'odd=\[something odd happened\]' "$T/t10.out" &&
    ok "bhyve_refusal: migration topology line; fallback without ps2 noise" || bad "refusal: $(cat "$T/t10.out")"

# sr2-4. Guest probe parsing (srtool / sr-guest.sh lines).
E=$("$SR" expect 4 9)
cat > "$T/r-before.txt" <<EOF2
SRCLOCK real=1000.000000000 mono=50.000000000 uptime=50.0
SRHOLD pid=77 mb=4 seed=9 digest=$E verifies=3 last=$E ok=yes
SRSPIN-0 SRSPIN pid=1 n=100 cpu=0 x=1
SRSPIN-1 SRSPIN pid=2 n=200 cpu=1 x=1
EOF2
cat > "$T/r-after.txt" <<EOF2
SRCLOCK real=1100.500000000 mono=50.700000000 uptime=50.7
SRHOLD pid=77 mb=4 seed=9 digest=$E verifies=4 last=$E ok=yes
SRFILE sha256=$E bytes=4194304
SRSPIN-0 SRSPIN pid=1 n=130 cpu=0 x=1
SRSPIN-1 SRSPIN pid=2 n=260 cpu=1 x=1
EOF2
sed 's/n=260 cpu=1/n=200 cpu=1/' "$T/r-after.txt" > "$T/r-stuck.txt"
sed 's/n=260 cpu=1/n=999 cpu=0/' "$T/r-after.txt" > "$T/r-wrongcpu.txt"
sed "s/last=$E ok=yes/last=00ff ok=no/" "$T/r-after.txt" > "$T/r-corrupt.txt"
printf 'SRHOLD-DEAD pid=77 (No such process)\n' > "$T/r-dead.txt"
sed 's/mono=50.700000000/mono=49.000000000/' "$T/r-after.txt" > "$T/r-back.txt"
(
	. "$HT_KIT/lib/common.sh"
	echo "h1=$(sr_hold_verdict "$T/r-after.txt" "$E")"
	echo "h2=$(sr_hold_verdict "$T/r-corrupt.txt" "$E")"
	echo "h3=$(sr_hold_verdict "$T/r-dead.txt" "$E")"
	echo "h4=$(sr_hold_verdict "$T/r-after.txt" 1234)"
	echo "s1=$(sr_spin_verdict "$T/r-before.txt" "$T/r-after.txt" 2)"
	echo "s2=$(sr_spin_verdict "$T/r-before.txt" "$T/r-stuck.txt" 2)"
	echo "s3=$(sr_spin_verdict "$T/r-before.txt" "$T/r-wrongcpu.txt" 2)"
	echo "s4=$(sr_spin_verdict "$T/r-before.txt" "$T/r-after.txt" 4)"
	echo "c1=$(sr_clock_verdict "$T/r-before.txt" "$T/r-after.txt" 100)"
	echo "c2=$(sr_clock_verdict "$T/r-before.txt" "$T/r-back.txt" 100)"
	echo "c3=$(sr_clock_verdict "$T/r-before.txt" "$T/r-dead.txt" 100)"
	echo "f1=$(sr_val "$T/r-after.txt" 'SRFILE ' sha256)"
	echo "v1=$(sr_val "$T/r-after.txt" 'SRHOLD ' verifies)"
) > "$T/t11.out" 2>&1
grep -q '^h1=ok holder pid 77 verification 4' "$T/t11.out" && grep -q '^h2=bad holder digest=.* now=00ff' "$T/t11.out" &&
    grep -q '^h3=bad SRHOLD-DEAD pid=77' "$T/t11.out" && grep -q '^h4=bad ' "$T/t11.out" &&
    ok "sr_hold_verdict (same digest / corrupted / holder dead / wrong reference)" || bad "hold: $(grep '^h' "$T/t11.out")"
grep -q '^s1=ok vcpu0:100->130@cpu0 vcpu1:200->260@cpu1$' "$T/t11.out" && grep -q '^s2=bad' "$T/t11.out" &&
    grep -q '^s3=bad.*vcpu1:200->999@cpu0' "$T/t11.out" && grep -q '^s4=bad.*vcpu3:?->?' "$T/t11.out" &&
    ok "sr_spin_verdict (advanced+pinned / stuck / wrong CPU / missing vCPU)" || bad "spin: $(grep '^s' "$T/t11.out")"
grep -q '^c1=ok guest realtime +100.500 s, monotonic +0.700 s, host elapsed 100 s, realtime jump vs host +0.500 s' "$T/t11.out" &&
    grep -q '^c2=backwards ' "$T/t11.out" && grep -q '^c3=missing clock reading' "$T/t11.out" &&
    grep -q "^f1=$E$" "$T/t11.out" && grep -q '^v1=4$' "$T/t11.out" &&
    ok "sr_clock_verdict (jump reported / backwards / missing) and sr_val" || bad "clock: $(grep -E '^(c|f|v)' "$T/t11.out")"

# sr2-5. CPUID host-CPU-local leaf verdicts (vendor-neutral).
z="0x00000000 0x00000000 0x00000000 0x00000000"
{
	echo "SRLEAF cpu=0 leaf=0x80000026 maxbasic=0x00000010 maxext=0x80000028 value=$z"
	echo "SRLEAF cpu=1 leaf=0x80000026 maxbasic=0x00000010 maxext=0x80000028 value=$z"
	echo "SRLEAF cpu=0 leaf=0x1a maxbasic=0x00000010 maxext=0x80000028 value=0x00000001 0x00000000 0x00000000 0x00000000"
	echo "SRLEAF cpu=1 leaf=0x1a maxbasic=0x00000010 maxext=0x80000028 value=0x00000001 0x00000000 0x00000000 0x00000000"
} > "$T/leaf-ok.txt"
{
	echo "SRLEAF cpu=0 leaf=0x80000026 maxbasic=0x00000010 maxext=0x80000028 value=0x00000000 0x00000000 0x00000000 0x00000004"
	echo "SRLEAF cpu=1 leaf=0x80000026 maxbasic=0x00000010 maxext=0x80000028 value=0x00000000 0x00000000 0x00000000 0x0000000a"
	echo "SRLEAF cpu=0 leaf=0x1a maxbasic=0x00000020 maxext=0x80000008 value=0x40000001 0x00000000 0x00000000 0x00000000"
	echo "SRLEAF cpu=1 leaf=0x1a maxbasic=0x00000020 maxext=0x80000008 value=0x40000001 0x00000000 0x00000000 0x00000000"
} > "$T/leaf-bad.txt"
echo SRLEAF-NOCPUCTL > "$T/leaf-none.txt"
(
	. "$HT_KIT/lib/common.sh"
	echo "l1=$(sr_leaf_verdict "$T/leaf-ok.txt" 0x80000026)"
	echo "l2=$(sr_leaf_verdict "$T/leaf-ok.txt" 0x1a)"
	echo "l3=$(sr_leaf_verdict "$T/leaf-bad.txt" 0x80000026)"
	echo "l4=$(sr_leaf_verdict "$T/leaf-bad.txt" 0x1a)"
	echo "l5=$(sr_leaf_verdict "$T/leaf-none.txt" 0x1a)"
	echo "l6=$(sr_leaf_verdict "$T/leaf-ok.txt" 0x7)"
) > "$T/t12.out" 2>&1
grep -q '^l1=ok leaf 0x80000026 reads zero on all 2 vCPUs' "$T/t12.out" &&
    grep -q '^l2=ok leaf 0x1a not enumerated by the guest (max 0x00000010)' "$T/t12.out" &&
    grep -q '^l3=bad leaf 0x80000026 differs across vCPUs' "$T/t12.out" &&
    grep -q '^l4=bad leaf 0x1a nonzero on all 2 vCPUs' "$T/t12.out" &&
    grep -q '^l5=skip ' "$T/t12.out" && grep -q '^l6=bad no SRLEAF lines' "$T/t12.out" &&
    ok "sr_leaf_verdict (zero / not enumerated / differs / nonzero / no cpuctl / missing)" || bad "leaf: $(cat "$T/t12.out")"

# sr2-6. Checkpoint copies, tampering and cleanup (fail-before: the gen3
#        cleanup patterns left every checkpoint member behind).
mkdir -p "$T/ck/A"
g=845a259e5b627b2ba532253421bd4c64
"$SR" pattern 1 3 > "$T/ck/A/srA.data.$g"; "$SR" pattern 1 4 > "$T/ck/A/srA.kern.$g"; "$SR" pattern 1 5 > "$T/ck/A/srA.meta.$g"
: > "$T/ck/A/srA.lock"
{
	echo BHYVE-CHECKPOINT-MANIFEST-3; echo architecture=amd64; echo machine=x86
	echo "data=srA.data.$g"; echo "kern=srA.kern.$g"; echo "meta=srA.meta.$g"
	echo "data_sha256=$(sha256 -q "$T/ck/A/srA.data.$g")"; echo "kern_sha256=$(sha256 -q "$T/ck/A/srA.kern.$g")"
	echo "meta_sha256=$(sha256 -q "$T/ck/A/srA.meta.$g")"
} > "$T/ck/A/srA"
(
	. "$HT_KIT/lib/common.sh"
	d0=$(ckp_digest "$T/ck/A/srA")
	ckp_copy "$T/ck/A/srA" "$T/ck/neg" && echo "copied $(ls "$T/ck/neg" | tr '\n' ' ')"
	f=$(ckp_member "$T/ck/neg/srA" meta); echo "member $(basename "$f")"
	flip_byte "$f" 40973
	[ "$(sha256 -q "$f")" != "$(sed -n 's/^meta_sha256=//p' "$T/ck/neg/srA")" ] && echo "tampered copy no longer matches its manifest"
	[ "$(ckp_digest "$T/ck/A/srA")" = "$d0" ] && echo "original unchanged"
	[ "$(ckp_digest "$T/ck/neg/srA")" != "$d0" ] && echo "copy digest differs"
) > "$T/t13.out" 2>&1
grep -q "copied srA srA.data.$g srA.kern.$g srA.meta.$g $" "$T/t13.out" && grep -q "member srA.meta.$g" "$T/t13.out" &&
    grep -q 'tampered copy no longer matches' "$T/t13.out" && grep -q 'original unchanged' "$T/t13.out" &&
    grep -q 'copy digest differs' "$T/t13.out" &&
    ok "ckp_copy (members, no lock) / flip_byte / ckp_digest" || bad "ckp: $(cat "$T/t13.out")"
# Cleanup end to end: phase_workdir's registered actions from the old and
# the new library, run against the files bhyve really creates.
for v in old new; do
	lib=$HT_KIT/lib/common.sh; [ $v = old ] && lib=$HT_KIT/lib/common.sh.bak-sr2
	(
		HT_DRYRUN=no; . "$lib"; HT_WORK_ROOT=$T/cw-$v
		phase_begin t14$v; phase_workdir
		d=${HT_CKP:-$HT_WORK}
		for f in ckp1 ckp1.lock ckp1.data.$g ckp1.kern.$g ckp1.meta.$g; do : > "$d/$f"; done
		: > "$HT_WORK/a.img"; mkdir -p "$HT_WORK/tls"; : > "$HT_WORK/tls/src.key"; : > "$HT_WORK/x.console"
		run_cleanup
		find "$HT_WORK" -type f | sed "s|$HT_WORK/||" | sort | tr '\n' ' ' > "$T/cw-$v.left"
	) > /dev/null 2>&1
done
case "$(cat "$T/cw-old.left")" in *ckp1.data.$g*) oldleft=yes ;; *) oldleft=no ;; esac
[ $oldleft = yes ] && [ "$(cat "$T/cw-new.left")" = "x.console " ] &&
    ok "cleanup: before, checkpoint members and TLS keys stayed ($(cat "$T/cw-old.left" | wc -w | tr -d ' ') files); after, only logs remain" ||
    bad "cleanup old left: $(cat "$T/cw-old.left") | new left: $(cat "$T/cw-new.left")"

# sr2-7. HyperTrace delivery assertion.
mkdir -p "$T/d15"
printf 'forwarder channels: 2\noutbound deliveries: 0\ninstalled deliveries: 0\n' > "$T/d15/s.stats.ht-a"
printf 'forwarder channels: 2\noutbound deliveries: 3\ninstalled deliveries: 3\n' > "$T/d15/s.stats.ht-b"
printf 'forwarder channels: 2\noutbound deliveries: 3\ninstalled deliveries: 0\n' > "$T/d15/s.stats.ht-c"
(
	. "$HT_KIT/lib/common.sh"; HT_OUT=$T/d15
	for x in a b c d; do ht_delivered s ht-$x && echo "$x yes" || echo "$x no"; done
) > "$T/t15.out" 2>&1
[ "$(tr '\n' ' ' < "$T/t15.out")" = "a no b yes c no d no " ] &&
    ok "ht_delivered needs outbound and installed > 0" || bad "delivered: $(cat "$T/t15.out")"

# sr2-8. need_image refuses an image built from other kit guest files;
#        vm_mem_guard refuses a guest that does not fit.
mkdir -p "$T/img/current"; : > "$T/img/current/guest.img"
(
	HT_DRYRUN=yes; . "$HT_KIT/lib/common.sh"; HT_IMAGES=$T/img HT_GENERATION=16.snapX
	printf 'generation=16.snapX\nimage=%s\nkit_overlay_sha256=%s\n' "$T/img/current/guest.img" "$(kit_overlay_sha256)" > "$T/img/current/guest.manifest"
	phase_begin t16a; need_image; dry_end
) > /dev/null 2>&1
(
	HT_DRYRUN=yes; . "$HT_KIT/lib/common.sh"; HT_IMAGES=$T/img HT_GENERATION=16.snapX
	printf 'generation=16.snapX\nimage=%s\nkit_overlay_sha256=stale\n' "$T/img/current/guest.img" > "$T/img/current/guest.manifest"
	phase_begin t16b; need_image; dry_end
) > /dev/null 2>&1
grep -q '^t16a READY' "$HT_RUN/SUMMARY" && grep -q '^t16b WOULD-REFUSE' "$HT_RUN/SUMMARY" &&
    grep -q 'built from other kit guest files' "$HT_RUN/t16b/checks.tsv" &&
    ok "need_image: current overlay accepted, stale overlay refused" || bad "overlay: $(grep t16 "$HT_RUN/SUMMARY")"
mkdir -p "$T/stub17"
cat > "$T/stub17/sysctl" <<'EOF2'
#!/bin/sh
[ "$1" = -n ] && shift
case "$1" in
hw.pagesize) echo 4096 ;; vm.stats.vm.v_free_count) echo "$STUB_FREE" ;;
vm.stats.vm.v_inactive_count) echo 0 ;; kstat.zfs.misc.arcstats.size) echo 0 ;;
*) /sbin/sysctl -n "$1" ;;
esac
EOF2
chmod +x "$T/stub17/sysctl"
(
	HT_DRYRUN=no; . "$HT_KIT/lib/common.sh"; PATH=$T/stub17:$PATH
	phase_begin t17
	STUB_FREE=262144; export STUB_FREE   # 1024 MB
	vm_mem_guard ht-big 4G && echo "big WRONG" || echo "big refused: $HT_GUARD_MSG"
	STUB_FREE=2621440                      # 10240 MB
	vm_mem_guard ht-ok 4G && echo "ok fits" || echo "ok WRONG"
	echo "mb $(mem_mb_of 512M) $(mem_mb_of 1G) $(mem_mb_of 4096)"
) > "$T/t17.out" 2>&1
grep -q 'big refused: not enough memory for ht-big: needs 4096 MB + 1024 MB margin, about 1024 MB available' "$T/t17.out" &&
    grep -q 'ok fits' "$T/t17.out" && grep -q 'mb 512 1024 4096' "$T/t17.out" &&
    ok "vm_mem_guard / mem_mb_of" || bad "mem: $(cat "$T/t17.out")"

# sr2-9. l2-boot.sh report parsing (L1 side of the L2 checksum, net, ticks).
L=$T/l2run; mkdir -p "$L"
w0=$("$SR" expect 2 1000) w1=$("$SR" expect 2 1001)
mkl2() { # console-lines rc
	rm -rf "$L"; mkdir -p "$L"
	: > "$L/watchdog-done"
	echo MK > "$L/marker"; echo 2 > "$L/cpus"; echo 2 > "$L/work"; echo yes > "$L/net"
	echo "$(date +%s)" > "$L/t0"; echo "$2" > "$L/rc"; printf '%b' "$1" > "$L/console"
	printf '3 packets transmitted, 3 packets received, 0.0%% packet loss\nround-trip min/avg/max/stddev = 0.1/0.2/0.3/0.1 ms\n' > "$L/ping"
}
mkl2 "HOSTTEST-L2-MARKER MK model=x ncpu=2\r\nHOSTTEST-L2-WORK cpu=1 sum=$w1 ran_on=1\r\nHOSTTEST-L2-WORK cpu=0 sum=$w0 ran_on=0\r\nHOSTTEST-L2-WORK-DONE seconds=1\r\nHOSTTEST-L2-TICK n=0 SRCLOCK\r\nHOSTTEST-L2-TICK n=1 SRCLOCK\r\n" 0
L2_RUNDIR=$L SRTOOL=$SR sh "$HT_KIT/guest/l2-boot.sh" --status > "$T/t18a.out" 2>&1
L2_RUNDIR=$L SRTOOL=$SR sh "$HT_KIT/guest/l2-boot.sh" --wait 2 >> "$T/t18a.out" 2>&1; echo "rc=$?" >> "$T/t18a.out"
mkl2 "HOSTTEST-L2-MARKER MK model=x ncpu=2\nHOSTTEST-L2-WORK cpu=0 sum=$w0 ran_on=1\nHOSTTEST-L2-WORK cpu=1 sum=deadbeef ran_on=1\n" 0
L2_RUNDIR=$L SRTOOL=$SR sh "$HT_KIT/guest/l2-boot.sh" --wait 2 > "$T/t18b.out" 2>&1; echo "rc=$?" >> "$T/t18b.out"
mkl2 "boot noise only\n" 124
L2_RUNDIR=$L SRTOOL=$SR sh "$HT_KIT/guest/l2-boot.sh" --wait 2 > "$T/t18c.out" 2>&1; echo "rc=$?" >> "$T/t18c.out"
grep -q 'L2-STATUS tick=1 rc=0' "$T/t18a.out" && grep -q '^L2-WORK-OK mb=2 cpu0=match@0 cpu1=match@1' "$T/t18a.out" &&
    grep -q '^L2-NET-OK' "$T/t18a.out" && grep -q '^L2-OK bhyve_exit=0 .* ticks=2' "$T/t18a.out" && grep -q '^rc=0' "$T/t18a.out" &&
    grep -q '^L2-WORK-FAIL mb=2 cpu0=match@1 cpu1=deadbeef!=' "$T/t18b.out" &&
    grep -q '^L2-FAIL bhyve_exit=124' "$T/t18c.out" && grep -q '^rc=5' "$T/t18c.out" &&
    ok "l2-boot.sh report: checksum per vCPU (digest+pinning), net, ticks, missing marker" ||
    bad "l2 report: $(cat "$T/t18a.out" "$T/t18b.out" "$T/t18c.out")"

# sr2-10. Console limits stay above the inner L2 limits (fail-before: the
#         gen3 HyperTrace path gave the L2 run a 600 s console limit while
#         l2-boot.sh allowed bhyveload 120 s + bhyve 720 s).
oldlim=$(sed -n 's/.*ht_session l1trace \([0-9]*\) .*/\1/p' "$HT_KIT/phases/nested.sh.bak-sr2" | head -1)
oldin=$(sed -n 's/.*L2_TIMEOUT:-\([0-9]*\).*/\1/p' "$HT_KIT/guest/l2-boot.sh.bak-sr2" | head -1)
l2t=$(sed -n 's/^L2T=\${HT_L2_TIMEOUT:-\([0-9]*\)}.*/\1/p' "$HT_KIT/phases/nested.sh")
l2c=$(sed -n 's/^L2C=\$((L2T + \([0-9]*\))).*/\1/p' "$HT_KIT/phases/nested.sh")
n_unbounded=$(grep 'l2-boot.sh' "$HT_KIT/phases/nested.sh" | grep 'vm_cmd' | grep -v -c -E '\$L2C|HOLD \+ 240|HOLD \+ 120 \+ 200|--status')
[ -n "$oldlim" ] && [ "$oldlim" -lt $((oldin + 120)) ] && [ -n "$l2t" ] && [ -n "$l2c" ] &&
    [ $((l2t + l2c)) -gt $((l2t + 30)) ] && [ "$n_unbounded" -eq 0 ] &&
    ok "console limits: before $oldlim s < $((oldin + 120)) s inner; after L2T=$l2t, console L2T+$l2c" ||
    bad "limits old=$oldlim/$oldin new=$l2t/+$l2c unbounded=$n_unbounded"

# l2-1. Inner L2 limits are used, not just printed, and fit the console
#       limit (gen4: l2-boot.sh showed 600 s but never returned before the
#       900 s console limit, so no L2 output reached the host).
l2t=$(sed -n 's/^L2T=\${HT_L2_TIMEOUT:-\([0-9]*\)}.*/\1/p' "$HT_KIT/phases/nested.sh")
l2c=$((l2t + $(sed -n 's/^L2C=\$((L2T + \([0-9]*\))).*/\1/p' "$HT_KIT/phases/nested.sh")))
l2b=$((l2c - $(sed -n 's/^L2B=\$((L2C - \([0-9]*\))).*/\1/p' "$HT_KIT/phases/nested.sh")))
hold=$(sed -n 's/^HOLD=\${HT_L2_HOLD:-\([0-9]*\)}.*/\1/p' "$HT_KIT/phases/nested.sh")
lim_of() { sed -n "s/.* $1=\([0-9]*\).*/\1/p"; }
fg=$(L2_TIMEOUT=$l2t L2_BUDGET=$l2b sh "$HT_KIT/guest/l2-boot.sh" --limits)
bgl=$(L2_BG=yes L2_TIMEOUT=$((hold + l2t)) L2_BUDGET=$l2b sh "$HT_KIT/guest/l2-boot.sh" --limits)
small=$(L2_TIMEOUT=$l2t L2_BUDGET=150 sh "$HT_KIT/guest/l2-boot.sh" --limits)
post=$(L2_TIMEOUT=1 sh "$HT_KIT/guest/l2-boot.sh" --limits | awk '{for(i=1;i<=NF;i++){split($i,a,"=");v[a[1]]=a[2]}} END{print v["grace"]+3+v["diag"]+5+v["report"]}')
n_l2=$(grep -E '(vm_cmd|nested_run).*l2-boot.sh.*marker' "$HT_KIT/phases/nested.sh" | grep -c .)
n_budget=$(grep -E '(vm_cmd|nested_run).*l2-boot.sh.*marker' "$HT_KIT/phases/nested.sh" | grep -c 'L2_BUDGET=\$L2B')
n_oldbudget=$(grep -c 'L2_BUDGET' "$HT_KIT/phases/nested.sh.bak-l2")
waitc=$(sed -n 's/.*l2-boot.sh --wait \$((HOLD + \([0-9]*\)))" \$((HOLD + \([0-9]*\) + \([0-9]*\))).*/\1 \2 \3/p' "$HT_KIT/phases/nested.sh")
set -- $waitc
[ -n "$l2t" ] && [ "$(echo "$fg" | lim_of bhyve)" -eq "$l2t" ] && [ "$(echo "$fg" | lim_of total)" -le "$l2b" ] && [ "$l2b" -lt "$l2c" ] &&
    [ "$(echo "$bgl" | lim_of bhyve)" -eq $((hold + l2t)) ] && [ "$(echo "$bgl" | lim_of total)" -le "$l2b" ] &&
    [ "$(echo "$small" | lim_of total)" -le 150 ] && [ "$(echo "$small" | lim_of bhyve)" -lt "$l2t" ] &&
    [ "$n_l2" -ge 4 ] && [ "$n_budget" -eq "$n_l2" ] && [ "$n_oldbudget" -eq 0 ] &&
    [ $# -eq 3 ] && [ "$1" -eq "$2" ] && [ $(($1 + post)) -lt $(($2 + $3)) ] &&
    ok "L2 limits: bhyve ${l2t}s, L1 worst case $(echo "$fg" | lim_of total)s <= budget ${l2b}s < console ${l2c}s; all $n_l2 runs pass the budget (before: 0)" ||
    bad "L2 limits: fg=[$fg] bg=[$bgl] small=[$small] runs=$n_l2 budget=$n_budget old=$n_oldbudget wait=[$waitc] post=$post"

# l2-2/3. A bhyve that ignores SIGTERM (bhyve maps it to the ACPI power
#         button) or a bhyveload blocked in the kernel: before, l2-boot.sh
#         never returned and printed nothing after the sysctl lines (the gen4
#         L1 console); after, it returns within its limits with L1
#         diagnostics, and the L2 bhyve output is copied live.
SB=$T/l2stub; mkdir -p "$SB/bin"
printf '#!/bin/sh\ntrap "" TERM\necho "stub bhyve: no guest entry" >&2\nwhile :; do sleep 1; done\n' > "$SB/bin/bhyve"
printf '#!/bin/sh\n[ "${STUB_LOAD_HANG:-no}" = yes ] || exit 0\ntrap "" TERM\nwhile :; do sleep 1; done\n' > "$SB/bin/bhyveload"
for c in bhyvectl kldstat; do printf '#!/bin/sh\nexit 0\n' > "$SB/bin/$c"; done
for c in sysctl procstat top dmesg service; do printf '#!/bin/sh\necho "stub %s $*"\n' $c > "$SB/bin/$c"; done
# A console reader remains alive after readiness; an empty regular file
# followed by cat exited immediately and raced the readiness check.
printf '#!/bin/sh\n: > "$2"\nexec tail -f "$1"\n' > "$SB/bin/l2-console"
chmod +x "$SB/bin/"*; : > "$SB/con"; : > "$SB/vmmctl"
l2stub() { # OUT SCRIPT [VAR=VALUE...]
	o=$1 s=$2; shift 2
	env "$@" PATH="$SB/bin:$PATH" L2_RUNDIR="$SB/run" L2_CONDEV="$SB/con" L2_VMMCTL="$SB/vmmctl" \
	    L2_CONSOLE_READER="$SB/bin/l2-console" L2_LIVE="$SB/live" L2_TIMEOUT=2 L2_GRACE=1 L2_DIAG_LIM=5 L2_BASE_LIM=2 L2_LOAD_LIM=2 \
	    L2_DESTROY_LIM=2 timeout -k 2 20 sh "$s" MK > "$o" 2>&1
	echo "rc=$?" >> "$o"
	pkill -f "$SB/bin/" 2>/dev/null; sleep 1
}
l2stub "$T/l2old.out" "$HT_KIT/guest/l2-boot.sh.bak-l2"
: > "$SB/live"
l2stub "$T/l2new.out" "$HT_KIT/guest/l2-boot.sh"
l2stub "$T/l2load.out" "$HT_KIT/guest/l2-boot.sh" STUB_LOAD_HANG=yes
{ [ ! -e /dev/vmmctl ] || { grep -q "^rc=124" "$T/l2old.out" && ! grep -q L2-FAIL "$T/l2old.out"; }; } &&
    grep -q '^rc=5' "$T/l2new.out" && grep -q '^L2-TIMEOUT bhyve still running after 2s' "$T/l2new.out" &&
    grep -q '^== L2-DIAG: bhyve lifetime limit 2s' "$T/l2new.out" && grep -q '^stub procstat -kk\|^-- ps -auxww' "$T/l2new.out" &&
    grep -q '^L2-FAIL bhyve_exit=137 (L2-DIAG above)' "$T/l2new.out" &&
    grep -q '^\[L2-bhyve\] stub bhyve: no guest entry' "$SB/live" && grep -q '^\[L2-DIAG\] == L2-DIAG' "$SB/live" &&
    grep -q '^rc=4' "$T/l2load.out" && grep -q '^== L2-DIAG: bhyveload still running after 2s' "$T/l2load.out" &&
    grep -q '^L2-FAIL bhyveload rc=124' "$T/l2load.out" &&
    ok "stuck L2 stages: before no return in 20 s; after bounded, L1 diagnostics, live copy" ||
    bad "stuck L2: old=[$(tail -2 "$T/l2old.out" | tr '\n' ' ')] new=[$(grep -E '^L2-|^rc=' "$T/l2new.out" | tr '\n' ' ')] load=[$(grep -E '^L2-|^rc=' "$T/l2load.out" | tr '\n' ' ')] live=$(grep -c . "$SB/live")"

# l2-4. A console command that times out keeps the output it printed.
CL=$T/acon.log CI=$T/acon.in; : > "$CL"; : > "$CI"
( CONSOLE_LOG=$CL CONSOLE_INPUT=$CI sh "$HT_KIT/lib/acmd-console.sh" 'echo x' 3 > "$T/acon.out" 2>&1; echo "rc=$?" >> "$T/acon.out" ) &
ap=$!; i=0; while [ ! -s "$CI" ] && [ $i -lt 20 ]; do sleep 0.2; i=$((i + 1)); done
b=$(grep -o '__VSOCK_BEGIN_[0-9_]*__' "$CI" | head -1)
printf '%s\r\nL2-LIMITS bhyve=600\r\nL2 stage: bhyve (limit 600s)\r\n' "$b" >> "$CL"
wait $ap
grep -q '^L2 stage: bhyve (limit 600s)' "$T/acon.out" && grep -q 'timed out after 3s' "$T/acon.out" && grep -q '^rc=124' "$T/acon.out" &&
    ok "acmd-console: partial output kept on timeout" || bad "acmd-console partial: $(cat "$T/acon.out")"

# sr2-11. ATF WORKDIR ancestry, with the runner's own test (stat %Lp; see
#         run-svm-nested-atf.sh trusted_workdir). Before: $HT_WORK/atf under
#         /usr/obj (build user) fails; /var/tmp fails as well because %Lp has
#         no sticky bit (product bug, sr2-record.md); after: /var/run passes.
anc_ok() { c=$1; while :; do set -- $(stat -f '%u %Lp' "$c"); [ "$1" -eq 0 ] || return 1
	if [ $((0$2 & 0022)) -ne 0 ]; then [ -d "$c" ] && [ $((0$2 & 01000)) -ne 0 ] || return 1; fi
	[ "$c" = / ] && return 0; c=${c%/*}; [ -n "$c" ] || c=/; done; }
anc_ok /usr/obj/5BSD-otel-validation/hosttest-work && oldanc=pass || oldanc=fail
anc_ok /var/tmp && tmpanc=pass || tmpanc=fail
anc_ok /var/run && newanc=pass || newanc=fail
grep -q 'mktemp -d /var/run/ht-atf' "$HT_KIT/phases/nested.sh" && [ $oldanc = fail ] && [ $tmpanc = fail ] && [ $newanc = pass ] &&
    grep -q 'pkg install -r 5BSD-base 5BSD-waspnest-tests' "$HT_KIT/phases/nested.sh" &&
    ok "ATF WORKDIR: old /usr/obj ancestors $oldanc, /var/tmp $tmpanc, new /var/run $newanc; SKIP names the install command" ||
    bad "atf workdir old=$oldanc tmp=$tmpanc new=$newanc"

# sr2-12. Phase plumbing.
for p in hwstat devices hypertrace snapshot saverestore nested; do
	( . "$HT_KIT/lib/common.sh"; phase_expect $p ) | grep -q unknown && bad "no duration for $p"
done
grep -q 'saverestore) phases=' "$HT_KIT/hosttest.sh" || grep -q 'hwstat|hypertrace|nested|snapshot|saverestore|devices-sr|devices)' "$HT_KIT/hosttest.sh" &&
    ok "every phase has an expected duration; hosttest.sh knows saverestore" || bad "plumbing"

# dm-1. devices-sr inventory compare (console noise, \r, order, a lost and a
#       new device).
D=$T/dm; mkdir -p "$D"
printf 'DSRPCI vtnet0@pci0:0:4:0: class=0x020000\r\nnoise\r\nDSRDEV em0\r\nDSRUSB ugen0.2: <HID Tablet BHYVE> at usbus0\r\n' > "$D/a"
printf 'DSRUSB ugen0.2: <HID Tablet BHYVE> at usbus0\nkernel: msg\nDSRDEV em0\nDSRPCI vtnet0@pci0:0:4:0: class=0x020000\n' > "$D/b"
printf 'DSRPCI vtnet0@pci0:0:4:0: class=0x020000\nDSRDEV em1\n' > "$D/c"
(
	. "$HT_KIT/lib/common.sh"; trap - EXIT
	echo "1:$(dsr_inv_diff "$D/a" "$D/b")"
	echo "2:$(dsr_inv_diff "$D/a" "$D/c")"
	echo "3:$(dsr_inv_diff "$D/a" "$D/nonexistent")"
) > "$T/dm1.out" 2>&1
grep -q '^1:same 3$' "$T/dm1.out" && grep -q '^2:differs: -em0|ugen0.2: <HID Tablet BHYVE> at usbus0| +em1|$' "$T/dm1.out" && grep -q '^3:empty$' "$T/dm1.out" &&
    ok "dsr_inv_diff: same (CR/noise/order ignored), differs names lost+new, empty" || bad "inv diff: $(cat "$T/dm1.out")"

# dm-2. RFB banner, watchdog expiry count after an offset, counter growth.
printf 'RFB 003.008\n' > "$D/rfb1"; printf 'HTTP/1.0 400\n' > "$D/rfb2"; : > "$D/rfb3"
printf 'i6300esb: watchdog expired, applying action "notify"\n== restore\n' > "$D/bl"
off=$(( $(wc -c < "$D/bl") + 1 ))
printf 'x\ni6300esb: watchdog expired, applying action "notify"\n' >> "$D/bl"
printf 'DSRWDOG pats=5\n' > "$D/w1"; printf 'DSRWDOG pats=9\r\n' > "$D/w2"; printf 'DSRWDOG pats=\n' > "$D/w3"
(
	. "$HT_KIT/lib/common.sh"; trap - EXIT
	echo "r1:$(dsr_rfb "$D/rfb1")"; echo "r2:$(dsr_rfb "$D/rfb2")"; echo "r3:$(dsr_rfb "$D/rfb3")"
	echo "w0:$(dsr_wdog_fires "$D/bl" 1) w1:$(dsr_wdog_fires "$D/bl" "$off")"
	echo "g1:$(dsr_grew "$D/w1" "$D/w2" 'DSRWDOG ' pats)"; echo "g2:$(dsr_grew "$D/w2" "$D/w1" 'DSRWDOG ' pats)"
	echo "g3:$(dsr_grew "$D/w1" "$D/w3" 'DSRWDOG ' pats)"
) > "$T/dm2.out" 2>&1
grep -q '^r1:ok RFB 003.008$' "$T/dm2.out" && grep -q "^r2:bad 'HTTP/1.0 400'" "$T/dm2.out" && grep -q "^r3:bad 'nothing'" "$T/dm2.out" &&
    grep -q '^w0:2 w1:1$' "$T/dm2.out" && grep -q '^g1:ok 5->9$' "$T/dm2.out" && grep -q '^g2:bad 9->5$' "$T/dm2.out" && grep -q "^g3:bad '5'->''$" "$T/dm2.out" &&
    ok "dsr_rfb, dsr_wdog_fires (only after the restore offset), dsr_grew (CR, shrink, empty)" || bad "dm2: $(cat "$T/dm2.out")"

# dm-3. Source scan for emulations without save/restore: a stub tree and the
#       real bhyve tree (only passthru).
mkdir -p "$D/bhyve/amd64"
printf 'static const struct pci_devemu a = {\n\t.pe_emu = "withsnap",\n\t.pe_snapshot = f,\n};\n' > "$D/bhyve/a.c"
printf 'static const struct pci_devemu b = {\n\t.pe_emu =\t"nosnap",\n\t.pe_barwrite = w,\n};\n' > "$D/bhyve/amd64/b.c"
printf 'int helper(void);\n' > "$D/bhyve/c.c"
(
	. "$HT_KIT/lib/common.sh"; trap - EXIT
	echo "stub:$(dsr_nosnap_devices "$D/bhyve")"
	[ -d /usr/obj/5BSD-hypertrace/usr.sbin/bhyve ] && echo "real:$(dsr_nosnap_devices /usr/obj/5BSD-hypertrace/usr.sbin/bhyve)"
) > "$T/dm3.out" 2>&1
grep -q '^stub:nosnap$' "$T/dm3.out" && { ! grep -q '^real:' "$T/dm3.out" || grep -q '^real:passthru$' "$T/dm3.out"; } &&
    ok "dsr_nosnap_devices: stub -> nosnap; bhyve tree -> $(sed -n 's/^real://p' "$T/dm3.out")" || bad "nosnap: $(cat "$T/dm3.out")"

# dm-4. ESP detection on images (fail-before: the pre-dm image has none;
#       pass-after: images/mkimage.sh now adds one) plus a synthetic GPT.
dd if=/dev/zero of="$D/gpt.img" bs=512 count=8 2>/dev/null
printf '\050\163\052\301\037\370\322\021\272\113\000\240\311\076\311\073' | dd of="$D/gpt.img" bs=1 seek=$((1024 + 2 * 128)) conv=notrunc 2>/dev/null
(
	. "$HT_KIT/lib/common.sh"; trap - EXIT
	echo "syn:$(img_has_esp "$D/gpt.img")"
	echo "zero:$(dd if=/dev/zero of="$D/z.img" bs=512 count=8 2>/dev/null; img_has_esp "$D/z.img")"
	old=/usr/obj/5BSD-otel-validation/hosttest-images/16.snap20261101224940/guest.img
	new=/usr/obj/5BSD-otel-validation/dm-images/16.snap20261101224940/guest.img
	[ -f "$old" ] && echo "old:$(img_has_esp "$old")"
	[ -f "$new" ] && echo "new:$(img_has_esp "$new")"
) > "$T/dm4.out" 2>&1
grep -q '^syn:yes p3$' "$T/dm4.out" && grep -q '^zero:no$' "$T/dm4.out" &&
    ! grep -q -E '^old:yes' "$T/dm4.out" && ! grep -q -E '^new:no' "$T/dm4.out" &&
    grep -q 'efi:=' "$HT_KIT/images/mkimage.sh" && ! grep -q 'efi:=' "$HT_KIT/images/mkimage.sh.bak-dm" &&
    ok "img_has_esp: synthetic p3, zero no; $(grep -E '^(old|new):' "$T/dm4.out" | tr '\n' ' ')(mkimage.sh before: no ESP, after: ESP)" || bad "esp: $(cat "$T/dm4.out")"

# dm-5. Every guest driver the phase needs is in GENERIC or preloaded
#       (5BSD refuses late kldload). Fail-before: the pre-dm loader.conf.
need="virtio_console virtio_p9fs p9fs fusefs virtio_fs virtio_snd virtio_gpu virtio_input virtio_rtc virtio_crypto virtio_pmem virtio_mem virtio_iommu geom_eli ichwd pvpanic"
miss() { for m in $need; do grep -q "^${m}_load=\"YES\"" "$1" || printf '%s ' "$m"; done; }
mnew=$(miss "$HT_KIT/images/overlay/loader.conf") mold=$(miss "$HT_KIT/images/overlay/loader.conf.bak-dm")
[ -z "$mnew" ] && [ -n "$mold" ] && ok "guest drivers preloaded (before dm missing: $mold)" || bad "preload missing now: '$mnew' before: '$mold'"

# dm-6. Plumbing: hosttest.sh knows devices-sr (all, status, single), the
#       phase has a duration, the guest helper and dsrtool are in the image
#       overlay digest and dry-run plan lines name every optional backend.
( . "$HT_KIT/lib/common.sh"; trap - EXIT; phase_expect devices-sr ) | grep -q unknown && bad "no duration for devices-sr"
grep -q 'saverestore devices-sr devices nested' "$HT_KIT/hosttest.sh" && grep -q 'saverestore|devices-sr|devices)' "$HT_KIT/hosttest.sh" &&
    grep -q 'guest/dsr-guest.sh\|guest/\*.sh' "$HT_KIT/lib/common.sh" && [ -f "$HT_KIT/guest-bin/dsrtool" ] &&
    [ "$(grep -c 'plan "optional\|for o in scsi input vfs tpm ppt uefi' "$HT_KIT/phases/devices-sr.sh")" -ge 1 ] &&
    ok "devices-sr plumbing (hosttest.sh, phase_expect, overlay digest covers guest/*.sh + guest-bin/dsrtool)" || bad "devices-sr plumbing"
# dm-7. The phase's hook names match its groups (a typo silently skips a step).
for gname in stor net gfx gpu fs misc iommu; do
	grep -q "^dsr_pre_$gname()" "$HT_KIT/phases/devices-sr.sh" && grep -q "^dsr_post_$gname()" "$HT_KIT/phases/devices-sr.sh" &&
	    grep -q "^grp_$gname()" "$HT_KIT/phases/devices-sr.sh" || bad "devices-sr group $gname lacks grp_/dsr_pre_/dsr_post_"
done
hk=$(sed -n 's/^\(dsr_[a-z]*_[a-z]*\)().*/\1/p' "$HT_KIT/phases/devices-sr.sh" | grep -v -E '^dsr_(pre|mid|between|up|post|host)_(stor|net|gfx|gpu|fs|misc|iommu)$' | grep -v -E '^dsr_(group|net)$')
[ -z "$hk" ] && ok "devices-sr hook names all match a group" || bad "unknown hooks: $hk"


# dsr2-1. Shell sync after boot: a fake serial guest whose login shell
#         (resizewin) swallows the first line typed after the prompt. The
#         first command after vm_wait READY must still be answered.
#         Fail-before: common.sh.bak-dsr2 (vm_wait only slept 1 s).
dsr2_fake_guest() # WORKDIR NAME: CR-terminated input lines -> sh -> console
{
	( n=0; tail -f "$1/$2.input" | stdbuf -o0 tr '\r' '\n' | while IFS= read -r l; do
		n=$((n + 1)); [ $n -eq 1 ] && continue
		sh -c "$l" >> "$1/$2.console" 2>&1
	done ) > /dev/null 2>&1 &
	echo $!
}
for which in before after; do
	W2=$T/dsr2-$which; mkdir -p "$W2"
	printf 'HOSTTEST-GUEST-READY role=l1\r\nroot@ht-x:~ # \r\n' > "$W2/ht-x.console"; : > "$W2/ht-x.input"
	: > "$W2/alive"; echo "$W2/alive" > "$W2/ht-x.lifetime"
	gp=$(dsr2_fake_guest "$W2" ht-x)
	lib=$HT_KIT/lib/common.sh; [ $which = after ] || lib=$HT_KIT/lib/common.sh.bak-dsr2
	(
		. "$lib"; trap - EXIT; HT_WORK=$W2; log() { :; }
		vm_wait ht-x HOSTTEST-GUEST-READY 10; echo "wait=$?"
		echo "cmd=$(vm_cmd ht-x 'echo first-answer' 5 2>&1 | tr -d '\r' | tr '\n' ' ')"
	) > "$T/dsr2-1-$which.out" 2>&1
	pkill -P "$gp" 2>/dev/null; kill "$gp" 2>/dev/null
	pkill -f "tail -f $W2/ht-x.input" 2>/dev/null
done
grep -q 'cmd=first-answer' "$T/dsr2-1-after.out" && ! grep -q 'cmd=first-answer' "$T/dsr2-1-before.out" &&
    ok "first command after boot is answered although the login shell swallows one line (before: lost)" ||
    bad "dsr2-1 before: $(cat "$T/dsr2-1-before.out") after: $(cat "$T/dsr2-1-after.out")"

# ============================ nl2 cases ======================================
# nl2-1. L0 capture: starts on the L2 bhyve stage line, records thread stacks,
# DTrace and per-vCPU queries, reports a vCPU query that never returns as
# BLOCKED (bounded), and summarises; a run that ends first captures nothing.
S9=$T/stubnl2; W9=$T/worknl2; mkdir -p "$S9" "$W9"
cat > "$S9/procstat" <<'EOF2'
#!/bin/sh
echo "  PID    TID COMM                TDNAME              KSTACK"
echo "89907 169410 bhyve               vcpu 0              <running>"
echo "89907 169412 bhyve               vcpu 2              mi_switch+0xbc _sleep+0x1a9 _vm_map_unlock_and_wait+0xe6 vm_map_delete+0x1ea vm_map_remove+0x95 svm_nested_npt_root_clear+0x1e"
EOF2
cat > "$S9/dtrace" <<'EOF2'
#!/bin/sh
printf '== fbt-top60\nfn svm_launch 57857\nfn vm_run 645\nfn svm_run 645\n== l2-exits vcpu code\nl2x 2 0x400 7\n== nested-npf vcpu\nnpf 2 5\n'
EOF2
cat > "$S9/bhyvectl" <<'EOF2'
#!/bin/sh
# Like bhyvectl(8): --cpu selects the vCPU; --vcpu is not an option.
case "$*" in *--vcpu=*) echo "bhyvectl: unrecognized option" >&2; exit 1 ;; esac
case "$*" in *--cpu=1\ *) exec sleep 30 ;; esac
echo "rip[0] 0xffffffff80000000"
EOF2
printf '#!/bin/sh\necho "LWP STAT"\n' > "$S9/ps"
chmod +x "$S9"/*
sleep 120 & fakepid=$!
echo $fakepid > "$W9/ht-x.pid"
printf 'old line\nL2 stage: bhyve (limit 600s)\n' > "$W9/ht-x.console"
(
	. "$HT_KIT/lib/common.sh"; trap - EXIT; PATH=$S9:$PATH; HT_WORK=$W9
	HT_L0DIAG_AT=0 HT_L0DIAG_SECS=1 HT_L0DIAG_QSECS=3
	# the stage line before FROMLINE is old: nothing until a new one appears
	( sleep 3; echo 'L2 stage: bhyve (limit 600s)' >> "$W9/ht-x.console" ) &
	t0=$(date +%s)
	l0diag_watch ht-x "$W9/ht-x.console" 3 "$W9/d1" 2 30
	echo "waited=$(( $(date +%s) - t0 ))"
	mkdir -p "$W9/d2"; : > "$W9/d2/stop"
	l0diag_watch ht-x "$W9/ht-x.empty" 1 "$W9/d2" 2 30
) > "$T/nl2-1.out" 2>&1
kill $fakepid 2>/dev/null
s1=$(cat "$W9/d1/summary.txt" 2>/dev/null)
echo "$s1" | grep -q '^t+0s: sleeping vCPU threads: vcpu2:_vm_map_unlock_and_wait<vm_map_delete<vm_map_remove' &&
    echo "$s1" | grep -q 'top: svm_launch=57857 ' && echo "$s1" | grep -q 'L2 exits 7, nested NPF 5' &&
    echo "$s1" | grep -q 'vCPU queries blocked: 1; failed: none$' && grep -q 'BLOCKED after 3s' "$W9/d1/t+0s.vcpu1.txt" &&
    grep -q '^rc=0' "$W9/d1/t+0s.vcpu0.txt" && grep -q 'tick-\$2s' "$W9/d1/l0diag.d" &&
    [ "$(sed -n 's/^waited=//p' "$T/nl2-1.out")" -ge 3 ] &&
    grep -q '^no capture: the L2 run ended before its bhyve stage' "$W9/d2/summary.txt" &&
    ok "L0 capture: stage trigger after FROMLINE, stacks/DTrace summary, blocked vCPU query bounded, stop before stage" ||
    bad "nl2-1: $(cat "$T/nl2-1.out") summary: $s1 d2: $(cat "$W9/d2/summary.txt" 2>/dev/null)"
# nl2-2. nested.sh wires the capture into the first L2 run and its verdict.
grep -q 'l0diag_watch \$vm "\$HT_WORK/\$vm.console" \$l0from' "$HT_KIT/phases/nested.sh" &&
    grep -q 'l2_check l2-boots-to-marker "\$O/l2.txt" "\$l0d/summary.txt"' "$HT_KIT/phases/nested.sh" &&
    grep -q ': > "\$l0d/stop";.*wait \$l0p' "$HT_KIT/phases/nested.sh" &&
    ok "nested.sh starts the L0 capture with the first L2 run and reports it in l2-boots-to-marker" ||
    bad "nl2-2: nested.sh capture wiring missing"

# ============================ npf cases ======================================
# npf-1. The capture sizes a nested-NPF storm: NPFs per distinct L2 page, the
# top faulting page with its info1, NPT02 clears, and errno / false-validity
# returns cast to their C types (gen6 printed bool "true" as a pointer-sized
# number); a bhyvectl query error is "failed", not "blocked".
S10=$T/stubnpf; W10=$T/worknpf; mkdir -p "$S10" "$W10"
cat > "$S10/procstat" <<'EOF2'
#!/bin/sh
echo "  PID    TID COMM                TDNAME              KSTACK"
echo "89907 169410 bhyve               vcpu 0              <running>"
EOF2
cat > "$S10/dtrace" <<'EOF2'
#!/bin/sh
printf '== fbt-top60\nfn svm_nested_npt_root_populate 9\n== nested-errors fn errno\nerr svm_nested_npt_root_populate 12 2\n'
printf '== nested-validity-false fn\nvf svm_nested_eventinj_valid 1\n== l2-exits vcpu code\nl2x 0 0x400 9\nl2x 0 0x7b 3\n'
printf '== nested-npf vcpu\nnpf 0 9\n== nested-npf distinct L2 pages\nnpfdist 3\n'
printf '== nested-npf top L2 page info1\nnpfpage 0x7000 0x4 3\nnpfpage 0x5000 0x6 5\nnpfpage 0x9000 0x4 1\n'
printf '== npt02-clears\nclears 4\n'
EOF2
cp "$S9/bhyvectl" "$S10/bhyvectl"
printf '#!/bin/sh\necho "LWP STAT"\n' > "$S10/ps"
chmod +x "$S10"/*
sleep 120 & fakepid=$!
(
	. "$HT_KIT/lib/common.sh"; trap - EXIT; PATH=$S10:$PATH; HT_WORK=$W10
	HT_L0DIAG_QSECS=3
	mkdir -p "$W10/d"; : > "$W10/d/summary.txt"
	l0diag_snap ht-x $fakepid "$W10/d" t+0s 1 1
) > "$T/npf-1.out" 2>&1
kill $fakepid 2>/dev/null
s10=$(cat "$W10/d/summary.txt" 2>/dev/null)
echo "$s10" | grep -q 'L2 exits 12, nested NPF 9 over 3 L2 pages (x3.0 per page, top 0x5000 info1 0x6 x5), NPT02 clears 4,' &&
    echo "$s10" | grep -q 'nested errors: svm_nested_npt_root_populate=12x2 ; false validity checks: svm_nested_eventinj_validx1 ;' &&
    echo "$s10" | grep -q 'vCPU queries blocked: none; failed: none$' && grep -q '^rc=0' "$W10/d/t+0s.vcpu0.txt" &&
    grep -q '(arg1 & 0xff) == 0' "$W10/d/l0diag.d" && grep -q '(int)arg1 != 0' "$W10/d/l0diag.d" &&
    ! grep -q 'arg1 != 0/ { @nz' "$W10/d/l0diag.d" && grep -q 'npfseen\[' "$W10/d/l0diag.d" &&
    ok "L0 capture: NPF refault ratio, top page/info1, NPT02 clears, typed returns, bhyvectl --cpu" ||
    bad "npf-1: $(cat "$T/npf-1.out") summary: $s10"

# dsr3-1. The net group's pre-suspend ping snapshots are named after the tag
#         dsr_post_net reads (ping-em/ping-vn); the run of 2026-11-02 read a
#         missing ping-em-suspend.txt and reported replies ''->'33'.
#         Fail-before: devices-sr.sh.bak-dsr3 wrote ping-a/ping-b.
P=$HT_KIT/phases/devices-sr.sh
d3ping() { for t in em vn; do grep -q "gq ping-$t-suspend.txt \"\$G ping-read $t\"" "$1" || printf '%s ' "$t"; done; }
grep -q 'dsr_grew "$O/ping-$1-suspend.txt"' "$P" && [ -z "$(d3ping "$P")" ] && [ -n "$(d3ping "$P.bak-dsr3")" ] &&
    ok "devices-sr net: ping snapshots named per tag (before missing: $(d3ping "$P.bak-dsr3"))" || bad "dsr3-1 ping names: now '$(d3ping "$P")'"
# dsr3-2. With the 9p share unmounted, file-write lands in the guest's own
#         /mnt/9p with rc 0 (dsr-virtio-9p-create "rc 0, host missing").
#         Every share write/read must sit behind the mount check.
#         Fail-before: .bak-dsr3 wrote /mnt/9p without checking the mount.
d3gate() { awk '/^dsr_pre_fs\(\)|^dsr_post_fs\(\)/{f=1} f&&/^}/{f=0} f&&/P9M" != yes/{g=1} f&&/\/mnt\/9p\// && !g{print NR}' "$1" | head -1; }
[ -z "$(d3gate "$P")" ] && [ -n "$(d3gate "$P.bak-dsr3")" ] && grep -q 'P9M=$(v 9p-mount.txt' "$P" &&
    ok "devices-sr 9p: share I/O only after a successful mount (before: ungated at line $(d3gate "$P.bak-dsr3"))" || bad "dsr3-2 9p gate: line '$(d3gate "$P")'"
# dsr3-3. The guest attaches virtio-iommu only with hw.virtio_iommu.enable=1
#         (vtiommu 'none' on the host run); the endpoint failure is reported
#         as its own check.  Fail-before: loader.conf.bak-dsr3.
L=$HT_KIT/images/overlay/loader.conf
grep -q '^hw.virtio_iommu.enable="1"$' "$L" && ! grep -q '^hw.virtio_iommu.enable' "$L.bak-dsr3" &&
    grep -q 'dfail dsr-virtio-iommu-endpoint' "$P" && ! grep -q 'dsr-virtio-iommu-endpoint' "$P.bak-dsr3" &&
    ok "devices-sr iommu: guest driver enabled; endpoint reported separately" || bad "dsr3-3 iommu tunable/endpoint"
# ap-1. The guest negotiates VIRTIO_F_ACCESS_PLATFORM through a vtiommu
#       identity domain, so the iommu group's endpoint disk must attach and
#       pass; a missing endpoint is a product failure, not an expected one.
#       Fail-before: devices-sr.sh.bak-ap never reported the endpoint PASS.
grep -q 'check dsr-virtio-iommu-endpoint PASS' "$P" && ! grep -q 'check dsr-virtio-iommu-endpoint PASS' "$P.bak-ap" &&
    ! grep -q 'FreeBSD guests do not negotiate' "$P" &&
    ok "devices-sr iommu: endpoint disk expected to attach (ACCESS_PLATFORM)" || bad "ap-1 iommu endpoint expectation"
# Nested isolation must disable L0 tracing too, while preserving stacks and
# bounded vCPU queries. An absent DTrace sample must not be reported as zero.
sleep 120 & fakepid=$!
(
	. "$HT_KIT/lib/common.sh"; trap - EXIT; PATH=$S10:$PATH; HT_WORK=$W10
	HT_L0DIAG_DTRACE=no HT_L0DIAG_QSECS=3
	mkdir -p "$W10/no-trace"; : > "$W10/no-trace/summary.txt"
	l0diag_snap ht-x $fakepid "$W10/no-trace" t+0s 1 1
) > "$T/no-trace.out" 2>&1
kill $fakepid 2>/dev/null
[ ! -s "$W10/no-trace/t+0s.dtrace.txt" ] &&
    [ ! -e "$W10/no-trace/l0diag.d" ] &&
    grep -q '^rc=0' "$W10/no-trace/t+0s.vcpu0.txt" &&
    grep -q 'DTrace disabled for isolation' "$W10/no-trace/summary.txt" &&
    ! grep -q 'nested NPF 0' "$W10/no-trace/summary.txt" &&
    ok "nested isolation: no L0 DTrace, bounded vCPU queries retained" || bad "nested isolation capture"

# Snapshot OTLP verdicts must use positive metric points, not stdout or tags
# mentioned only by log/resource metadata. Exercise rejection as well as success.
(
	. "$HT_KIT/lib/common.sh"; trap - EXIT
	printf '%s\n' 'event hypertrace.vm.registered' 'log htpost' > "$T/otel-points"
	! ht_otlp_has_count "$T/otel-points" htpost || exit 1
	printf '%s\n' 'point dtrace.dtrace.count [key.0=htpost] 0' >> "$T/otel-points"
	! ht_otlp_has_count "$T/otel-points" htpost || exit 1
	printf '%s\n' 'point dtrace.dtrace.count [key.0=htpost] 5405' >> "$T/otel-points"
	ht_otlp_has_count "$T/otel-points" htpost || exit 1
	! ht_otlp_has_count "$T/otel-points" htpre || exit 1
	printf '%s\n' 'point dtrace.dtrace.count [key.0=htpre] 1' >> "$T/otel-points"
	ht_otlp_has_count "$T/otel-points" htpre || exit 1
) && ok "OTLP count verdicts: positive metrics and stale-tag detection" || bad "OTLP count verdicts"

# A partially valid capture must never publish passing metric evidence.
(
	. "$HT_KIT/lib/common.sh"; trap - EXIT
	mkdir -p "$T/otel-stub/bin" "$T/otel-json"
	cat > "$T/otel-stub/bin/otlp_json_validate" <<'EOF2'
#!/bin/sh
cat "$1"
! grep -q BAD "$1"
EOF2
	chmod +x "$T/otel-stub/bin/otlp_json_validate"
	HT_KIT=$T/otel-stub
	! ht_otlp_parse "$T/otel-json" "$T/otel-parsed" || exit 1
	[ ! -e "$T/otel-parsed" ] || exit 1
	printf '%s\n' 'point dtrace.dtrace.count [key.0=htpost] 5405' > "$T/otel-json/1.json"
	ht_otlp_parse "$T/otel-json" "$T/otel-parsed" || exit 1
	ht_otlp_has_count "$T/otel-parsed" htpost || exit 1
	printf '%s\n' 'point dtrace.dtrace.count [key.0=htpost] 1' BAD > "$T/otel-json/2.json"
	! ht_otlp_parse "$T/otel-json" "$T/otel-parsed" || exit 1
	[ ! -e "$T/otel-parsed" ] || exit 1
) && ok "OTLP validation: empty/malformed/partial captures fail closed" || bad "OTLP validation gate"

# The interrupted 06:22 snapshot left bridge0 on the next run's /24.
# Detect that before a second bridge can steal/duplicate its local route.
(
	. "$HT_KIT/lib/common.sh"; trap - EXIT
	ifconfig() { cat "$T/net-interfaces"; }
	netstat() { echo 'Destination Gateway Flags Netif'; }
	printf '%s\n' 'bridge0: flags=8843<UP>' '    inet 10.231.77.1 netmask 0xffffff00' > "$T/net-interfaces"
	! ht_private_net_preflight 10.231.77 "$T/net-before" || exit 1
	case "$HT_NET_CONFLICT" in *bridge0=10.231.77.1*) ;; *) exit 1 ;; esac
	ht_private_net_preflight 10.231.79 "$T/net-before" || exit 1
	printf '%s\n' 'bridge7: flags=8843<UP>' '    inet 10.231.77.99 netmask 0xffffff00' > "$T/net-interfaces"
	! ht_private_net_preflight 10.231.77 "$T/net-before" || exit 1
	printf '%s\n' 'rge0: flags=8843<UP>' '    inet 192.168.50.179 netmask 0xffffff00' > "$T/net-interfaces"
	ht_private_net_preflight 10.231.77 "$T/net-before" || exit 1
	ifconfig() { return 1; }
	! ht_private_net_preflight 10.231.77 "$T/net-before" || exit 1
) && ok "private network preflight: reject existing subnet, preserve others, fail closed" || bad "private subnet conflict detection"

sh "$HT_KIT/lib/network-selftest.sh" "$T/network-diag" &&
    ok "network diagnostics and verdict regressions" || bad "network diagnostics and verdict regressions"

sh "$HT_KIT/lib/console-lifetime-selftest.sh" || fail=1
sh "$HT_KIT/lib/stall-selftest.sh" "$HT_KIT" || fail=1
sh "$HT_KIT/lib/boot-deadline-selftest.sh" "$HT_KIT" || fail=1
# Exercise the added probe/device verdicts with controlled failures.
coverage_python=$(command -v python3.12 || command -v python3 || true)
if [ -n "$coverage_python" ] && "$coverage_python" "$HT_KIT/lib/coverage-test.py" > "$T/coverage.log" 2>&1; then
 ok "DTrace and nested device positive/negative verdicts"
else
 bad "expanded coverage tests (Python 3 required): see $T/coverage.log"
fi

echo "selftest $([ $fail -eq 0 ] && echo PASS || echo FAIL) ($T)"
exit $fail
