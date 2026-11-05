# Phase saverestore (sr2): bhyve save/restore in depth, vendor-neutral.
#  A) ht-sr1 (2 vCPU, 1 GiB): guest holds HT_SR_MB (256) MiB of a seeded
#     pattern in one process and on disk; suspend -> checkpoint A; two
#     independent restores of A (each from a copy of the disk taken at the
#     suspend); then N=HT_SR_CYCLES (3) suspend->restore cycles; then a
#     checkpoint of the running guest restored. After every restore: the same
#     process still holds the same digest (computed independently on the
#     host), the file verifies, every vCPU's pinned worker advances, the
#     guest clock never goes backwards (jump reported), ping and TCP in both
#     directions over the bridge, and a write after restore reads back.
#  B) ht-sr4 (4 vCPU): checkpoint while all 4 vCPUs are busy, suspend/restore,
#     all 4 pinned workers advance, memory digest.
#  C) refused restores, on copies of checkpoint A only: one flipped byte in
#     the .data/.kern/.meta member, a truncated manifest, a missing and a
#     moved device, and a CPU-contract change (nested exposure) that must be
#     refused with "Checkpoint CPU contract differs at <field>". The original
#     checkpoint's digest is compared before and after.
#  Also: host-CPU-local CPUID leaves (AMD 0x80000026, Intel 0x1A) read the
#  same (zero) on every vCPU -- the gen3 same-host restore failure.

phase_begin saverestore
need_root
need_generation
need_vmm
need_image
need_mem_mb 3072
need_disk_mb 24576
sysctl -n kern.conftxt | grep -q '^options[[:space:]]*BHYVE_SNAPSHOT' || refuse "kernel lacks options BHYVE_SNAPSHOT"
bhyve -h 2>&1 | grep -q -- '-r: path to checkpoint file' || refuse "bhyve built without snapshot support"
[ -x "$HT_KIT/guest-bin/srtool" ] || refuse "guest-bin/srtool missing; run images/refresh-tools.sh, then images/build-guest.sh"
dry && dry_end
phase_workdir
O=$HT_OUT
G=/root/hosttest/sr-guest.sh
V=$(host_vendor)
MB=${HT_SR_MB:-256}
SEED=$(( $(date +%s) % 100000 + 1 ))     # fresh per run: no stale file can match
EXP=$("$HT_KIT/guest-bin/srtool" expect "$MB" "$SEED")
check sr-reference-digest INFO "host-computed SHA-256 of the $MB MiB pattern (seed $SEED): $EXP; vendor $V"

# --- host-CPU-local CPUID leaves on the host itself (why gen3 failed) ------
if [ -e /dev/cpuctl0 ]; then
	for l in 0x80000026 0x1a; do
		n=$(for c in /dev/cpuctl[0-9]*; do cpucontrol -i $l,0 "$c" 2>/dev/null | sed 's/.*: //'; done | sort -u | wc -l | tr -d ' ')
		echo "leaf $l: $n distinct value(s) across host CPUs" >> "$O/host-cpu-leaves.txt"
	done
	check host-cpu-local-leaves INFO "$(tr '\n' ';' < "$O/host-cpu-leaves.txt") (more than one = the host value depends on the executing CPU)"
fi

# --- private network: bridge + 2 taps, host 10.231.79.1/24 ------------------
HIP=10.231.79.1
br=$(ifconfig bridge create) || refuse "cannot create bridge"
at_cleanup "ifconfig $br destroy"
tap1=$(ifconfig tap create) || refuse "cannot create tap"
at_cleanup "ifconfig $tap1 destroy"
tap2=$(ifconfig tap create) || refuse "cannot create tap"
at_cleanup "ifconfig $tap2 destroy"
ifconfig "$br" inet $HIP/24 addm "$tap1" addm "$tap2" up
ifconfig "$tap1" up; ifconfig "$tap2" up
pfctl -s info 2>/dev/null | grep -q 'Status: Enabled' && pf_on=yes || pf_on=no
log "network $br/$tap1,$tap2 (pf enabled: $pf_on; no pf rules are changed)"

# sr_net TAG VM GUEST_IP: ping, guest->host TCP, host->guest TCP.
sr_net()
{
	vm_cmd "$2" "ping -c 3 -t 10 $HIP | tail -2" 30 > "$O/$1-ping.txt" 2>&1
	grep -q ' 0.0% packet loss' "$O/$1-ping.txt" && check "$1-ping" PASS "$(tail -1 "$O/$1-ping.txt")" ||
	    check "$1-ping" FAIL "guest cannot ping $HIP (pf enabled: $pf_on): $(tail -1 "$O/$1-ping.txt") $(vm_diag "$2")"
	hp=5500
	while sockstat -4 -l 2>/dev/null | grep -q ":$hp[[:space:]]"; do hp=$((hp + 1)); done
	tok1="g2h-$1-$SEED" tok2="h2g-$1-$SEED"
	timeout 40 nc -l $HIP $hp > "$O/$1-g2h.txt" 2>&1 & np=$!
	sleep 0.5
	vm_cmd "$2" "$G tcp-send $HIP $hp $tok1" 40 > "$O/$1-g2h-guest.txt" 2>&1
	wait $np 2>/dev/null
	vm_cmd "$2" "$G tcp-listen 5601" 20 > "$O/$1-h2g-guest.txt" 2>&1
	echo "$tok2" | timeout 20 nc -N "$3" 5601 > /dev/null 2>&1; hrc=$?
	vm_cmd "$2" "$G tcp-got 5601" 30 >> "$O/$1-h2g-guest.txt" 2>&1
	g2h=no h2g=no
	grep -q -x "$tok1" "$O/$1-g2h.txt" && g2h=yes
	grep -q "SRTCP-GOT port=5601 data=$tok2" "$O/$1-h2g-guest.txt" && h2g=yes
	[ $g2h = yes ] && [ $h2g = yes ] && check "$1-tcp" PASS "guest->host :$hp and host->guest :5601 both delivered" ||
	    check "$1-tcp" FAIL "guest->host=$g2h ($(grep SRTCP-SENT "$O/$1-g2h-guest.txt")) host->guest=$h2g (nc rc=$hrc; $(grep SRTCP-GOT "$O/$1-h2g-guest.txt"))"
}

# Packed runs must prove negotiation, rather than just preserve offered options.
# Split runs can opt in with HT_SR_VIRTQUEUE=yes on an updated guest image.
sr_virtqueue()
{
 case "${HT_SR_VIRTQUEUE:-no}" in yes|no) ;;
 *) check "$1-virtqueue" FAIL "HT_SR_VIRTQUEUE must be yes or no"; return 1 ;; esac
 case "${HT_ROOT_PACKED:-no}:${HT_SR_VIRTQUEUE:-no}" in
 yes:*|no:yes) ;;
 no:no) return 0 ;;
 *) check "$1-virtqueue" FAIL "HT_SR_VIRTQUEUE must be yes or no"; return 1 ;;
 esac
 case "${HT_ROOT_PACKED:-no}" in yes) ring=1 ;; *) ring=0 ;; esac
 if vm_cmd "$2" "sh /root/hosttest/virtqueue-local.sh ${HT_ROOT_PACKED:-no}" 30 > "$O/$1-virtqueue.txt" 2>&1 &&
     grep -qx "VIRTQUEUE-LOCAL-OK packed=$ring" "$O/$1-virtqueue.txt"; then
  check "$1-virtqueue" PASS "root queue submissions and completions; packed=$ring"
 else
  check "$1-virtqueue" FAIL "root queue activity/mode unverified; see $1-virtqueue.txt"
  return 1
 fi
}

# sr_verify TAG VM BEFORE_FILE HOST_T0 NCPU EXPECTED [full]
#   After a restore: guest responds, memory holder digest, file digest,
#   pinned per-vCPU workers, clock; "full" adds network and a write.
sr_verify()
{
	tag=$1 v=$2 before=$3 t0=$4 n=$5 exp=$6 full=${7:-}
	vm_cmd "$v" "$G read" 120 > "$O/$tag-read1.txt" 2>&1; r1=$?
	t1=$(date +%s)
	if [ $r1 -ne 0 ] || ! grep -q SRCLOCK "$O/$tag-read1.txt"; then
		check "$tag-guest-responds" FAIL "no answer from the restored guest within 120 s (hang?) $(vm_diag "$v")"
		return 1
	fi
	check "$tag-guest-responds" PASS "answered $((t1 - t0)) s after the restore started"
	sr_virtqueue "$tag" "$v"
	sleep 3
	vm_cmd "$v" "$G read" 120 > "$O/$tag-read2.txt" 2>&1
	set -- $(sr_hold_verdict "$O/$tag-read1.txt" "$exp")
	[ "$1" = ok ] && { shift; check "$tag-memory" PASS "$*"; } || { shift; check "$tag-memory" FAIL "$*"; }
	fs=$(sr_val "$O/$tag-read1.txt" 'SRFILE ' sha256)
	[ "$fs" = "$exp" ] && check "$tag-file" PASS "pattern file sha256 = expected" ||
	    check "$tag-file" FAIL "pattern file sha256 '${fs:-missing}' != expected"
	set -- $(sr_spin_verdict "$O/$tag-read1.txt" "$O/$tag-read2.txt" "$n")
	[ "$1" = ok ] && { shift; check "$tag-vcpus" PASS "all $n pinned workers advanced:$*"; } ||
	    { shift; check "$tag-vcpus" FAIL "not every vCPU ran after restore:$*"; }
	cv=$(sr_clock_verdict "$before" "$O/$tag-read1.txt" $((t1 - t0)))
	cv2=$(sr_clock_verdict "$O/$tag-read1.txt" "$O/$tag-read2.txt" 3)
	if [ "${cv%% *}" = ok ] && [ "${cv2%% *}" = ok ]; then
		check "$tag-clock" PASS "${cv#ok }; then ticking: ${cv2#ok }"
	else
		check "$tag-clock" FAIL "across restore: $cv | 3 s later: $cv2"
	fi
	if [ "$full" = full ]; then
		sr_net "$tag" "$v" "$GIP"
		wexp=$("$HT_KIT/guest-bin/srtool" expect 16 $((SEED + 1)))
		vm_cmd "$v" "$G write $tag 16 $((SEED + 1))" 60 > "$O/$tag-write.txt" 2>&1
		ws=$(sr_val "$O/$tag-write.txt" 'SRPOST ' sha256)
		[ "$ws" = "$wexp" ] && check "$tag-write-after-restore" PASS "16 MiB written, synced and read back" ||
		    check "$tag-write-after-restore" FAIL "read back '${ws:-none}' != expected $(tail -1 "$O/$tag-write.txt")"
	fi
	return 0
}

# sr_restore_check TAG VM CKP: restore with the boot configuration; on
# refusal a FAIL whose detail is bhyve's own refusal line.
sr_restore_check()
{
	if vm_restore "$2" "$3"; then
		check "$1-restore" PASS "bhyve -r $(basename "$3") running"
		return 0
	fi
	check "$1-restore" FAIL "restore refused: $HT_REFUSAL"
	return 1
}

# === A) ht-sr1: data integrity, two restores of one checkpoint, cycles ======
vm=ht-sr1 GIP=10.231.79.2
disk=$(vm_disk $vm)
if ! { vm_boot $vm "$disk" 1G 2 "hosttest.role=l1 hosttest.hostname=$vm hosttest.inet=$GIP/24" "-s 4,virtio-net,$tap1" &&
    vm_wait $vm HOSTTEST-GUEST-READY ${HT_BOOT_TIMEOUT:-60}; }; then
	check boot-ht-sr1 FAIL "$(vm_diag $vm)"; phase_end; exit 1
fi
check boot-ht-sr1 PASS
sr_virtqueue sr-baseline "$vm"
vm_cmd $vm "$G cpuleaves" 60 > "$O/guest-cpuleaves.txt" 2>&1
for l in 0x80000026 0x1a; do
	set -- $(sr_leaf_verdict "$O/guest-cpuleaves.txt" $l)
	case $1 in ok) v=PASS ;; skip) v=SKIP ;; *) v=FAIL ;; esac; shift
	case "$V:$l" in amd:0x80000026|intel:0x1a) rel="(the $V per-core leaf)" ;; *) rel="(other vendor's leaf)" ;; esac
	check "guest-cpu-local-leaf-$l" $v "$* $rel"
done
vm_cmd $vm "$G prep $MB $SEED; $G spin 2" 180 > "$O/A-prep.txt" 2>&1
hs=$(sr_val "$O/A-prep.txt" 'SRHOLD ' digest) fs=$(sr_val "$O/A-prep.txt" 'SRFILE ' sha256)
if [ "$hs" = "$EXP" ] && [ "$fs" = "$EXP" ]; then
	check sr-prep PASS "holder and file hold the $MB MiB pattern; 2 pinned workers started"
else
	check sr-prep FAIL "holder '${hs:-none}' file '${fs:-none}' expected $EXP: $(grep -E 'SRHOLD-|SRTMPFS' "$O/A-prep.txt" | head -1)"
fi
sr_net sr-baseline $vm $GIP

# Suspend checkpoint A, then keep the disk exactly as it was at the suspend.
vm_cmd $vm "$G read" 120 > "$O/A-before.txt" 2>&1
t0=$(date +%s)
mkdir -p "$HT_CKP/A"
vm_suspend $vm "$HT_CKP/A/srA" sr-suspend-A "$O/A-suspend.txt" 180
vm_destroy $vm
cp "$disk" "$HT_WORK/diskA.img"
dA=$(ckp_digest "$HT_CKP/A/srA")
log "checkpoint A digest $dA ($(du -Ash "$HT_CKP/A" | awk '{print $1}') apparent)"

# Restore #1 of A.
if sr_restore_check sr-r1 $vm "$HT_CKP/A/srA"; then
	ifconfig "$tap1" up
	sr_verify sr-r1 $vm "$O/A-before.txt" "$t0" 2 "$EXP" full
fi
vm_destroy $vm

# Restore #2 of the same checkpoint, from a fresh copy of the suspend-time
# disk: independent of restore #1 (its file is absent, the holder's
# verification count is the checkpoint's again).
cp "$HT_WORK/diskA.img" "$disk"
t0=$(date +%s)
if sr_restore_check sr-r2 $vm "$HT_CKP/A/srA"; then
	ifconfig "$tap1" up
	sr_verify sr-r2 $vm "$O/A-before.txt" "$t0" 2 "$EXP" full
	vm_cmd $vm "$G exists sr-r1" 30 > "$O/sr-r2-exists.txt" 2>&1
	c1=$(sr_val "$O/sr-r1-read1.txt" 'SRHOLD ' verifies) c2=$(sr_val "$O/sr-r2-read1.txt" 'SRHOLD ' verifies)
	if grep -q 'SREXISTS tag=sr-r1 no' "$O/sr-r2-exists.txt" && [ -n "$c2" ] && [ "$c1" = "$c2" ]; then
		check sr-r2-independent PASS "restore #1's file absent; holder verification #$c2 in both restores (both start from checkpoint A)"
	else
		check sr-r2-independent FAIL "restore #1 file: $(grep -o 'SREXISTS.*' "$O/sr-r2-exists.txt"); verification count r1='$c1' r2='$c2'"
	fi

	# Suspend -> restore cycles of the running guest (its own disk).
	c=1
	while [ $c -le "${HT_SR_CYCLES:-3}" ]; do
		vm_cmd $vm "$G read" 120 > "$O/C$c-before.txt" 2>&1
		t0=$(date +%s)
		mkdir -p "$HT_CKP/C$c"
		if ! vm_suspend $vm "$HT_CKP/C$c/srC" "sr-cycle$c-suspend" "$O/C$c-suspend.txt" 180; then
			vm_destroy $vm; break
		fi
		vm_destroy $vm
		rm -rf "$HT_CKP/C$((c - 1))"
		sr_restore_check "sr-cycle$c" $vm "$HT_CKP/C$c/srC" || break
		ifconfig "$tap1" up
		if [ $c -eq "${HT_SR_CYCLES:-3}" ]; then
			sr_verify "sr-cycle$c" $vm "$O/C$c-before.txt" "$t0" 2 "$EXP" full || break
		else
			sr_verify "sr-cycle$c" $vm "$O/C$c-before.txt" "$t0" 2 "$EXP" || break
		fi
		c=$((c + 1))
	done

	# Checkpoint of the running guest (no suspend), then restore it. The
	# workers write only to tmpfs; sync first and stop the source right
	# after the checkpoint so the disk matches the memory image.
	vm_cmd $vm "sync; $G read" 120 > "$O/R-before.txt" 2>&1
	t0=$(date +%s)
	mkdir -p "$HT_CKP/R"
	bhyvectl --vm=$vm --checkpoint="$HT_CKP/R/srR" > "$O/R-checkpoint.txt" 2>&1; rc=$?
	vm_destroy $vm
	if [ $rc -eq 0 ] && ckp_manifest "$HT_CKP/R/srR"; then
		check sr-running-checkpoint PASS "checkpoint of the running guest published"
		if sr_restore_check sr-running $vm "$HT_CKP/R/srR"; then
			ifconfig "$tap1" up
			sr_verify sr-running $vm "$O/R-before.txt" "$t0" 2 "$EXP"
		fi
	else
		check sr-running-checkpoint FAIL "bhyvectl rc=$rc $(tail -1 "$O/R-checkpoint.txt") $(vm_diag $vm)"
	fi
fi
vm_shutdown $vm
rm -rf "$HT_CKP/R" "$HT_CKP"/C[0-9]*

# === B) ht-sr4: 4 vCPUs ======================================================
vm=ht-sr4 GIP=10.231.79.3
MB4=128 SEED4=$((SEED + 7))
EXP4=$("$HT_KIT/guest-bin/srtool" expect $MB4 $SEED4)
disk4=$(vm_disk $vm)
if vm_boot $vm "$disk4" 1G 4 "hosttest.role=l1 hosttest.hostname=$vm hosttest.inet=$GIP/24" "-s 4,virtio-net,$tap2" &&
    vm_wait $vm HOSTTEST-GUEST-READY ${HT_BOOT_TIMEOUT:-60}; then
	check boot-ht-sr4 PASS
	sr_virtqueue sr4-baseline "$vm"
	vm_cmd $vm "$G prep $MB4 $SEED4; $G spin 4" 180 > "$O/sr4-prep.txt" 2>&1
	vm_cmd $vm "$G read" 120 > "$O/sr4-busy1.txt" 2>&1
	mkdir -p "$HT_CKP/B"
	bhyvectl --vm=$vm --checkpoint="$HT_CKP/B/srB1" > "$O/sr4-checkpoint.txt" 2>&1; rc=$?
	sleep 2
	vm_cmd $vm "$G read" 120 > "$O/sr4-busy2.txt" 2>&1
	set -- $(sr_spin_verdict "$O/sr4-busy1.txt" "$O/sr4-busy2.txt" 4)
	if [ $rc -eq 0 ] && ckp_manifest "$HT_CKP/B/srB1" && [ "$1" = ok ]; then
		shift; check sr4-checkpoint-busy PASS "checkpoint with 4 busy vCPUs; all kept running:$*"
	else
		shift; check sr4-checkpoint-busy FAIL "bhyvectl rc=$rc $(tail -1 "$O/sr4-checkpoint.txt"); workers:$*"
	fi
	rm -rf "$HT_CKP/B"
	mkdir -p "$HT_CKP/B"
	vm_cmd $vm "$G read" 120 > "$O/sr4-before.txt" 2>&1
	t0=$(date +%s)
	if vm_suspend $vm "$HT_CKP/B/srB" sr4-suspend "$O/sr4-suspend.txt" 180; then
		vm_destroy $vm
		if sr_restore_check sr4 $vm "$HT_CKP/B/srB"; then
			ifconfig "$tap2" up
			sr_verify sr4 $vm "$O/sr4-before.txt" "$t0" 4 "$EXP4"
			vm_cmd $vm "ping -c 3 -t 10 $HIP | tail -2" 30 > "$O/sr4-ping.txt" 2>&1
			grep -q ' 0.0% packet loss' "$O/sr4-ping.txt" && check sr4-ping PASS ||
			    check sr4-ping FAIL "$(tail -1 "$O/sr4-ping.txt")"
		fi
	fi
	vm_shutdown $vm
	rm -rf "$HT_CKP/B"
else
	check boot-ht-sr4 FAIL "$(vm_diag $vm)"
fi
rm -f "$disk4"

# === C) refused restores (copies of checkpoint A only) ========================
if [ -f "$HT_CKP/A/srA" ]; then
	cp "$HT_WORK/diskA.img" "$HT_WORK/neg.img"
	cp "$HT_WORK/ht-sr1.args" "$HT_WORK/ht-srneg.args"
	NEGSLOTS="-s 0,hostbridge -s 3,virtio-blk,$HT_WORK/neg.img -s 6,virtio-rnd -s 4,virtio-net,$tap1 -s 31,lpc"
	# neg NAME CKP SLOTS OPTS EXPECT-REGEX WHAT
	neg()
	{
		if vm_restore ht-srneg "$2" "$3" "$4"; then
			check "$1" FAIL "bhyve accepted $6 and is running the guest"
		elif echo "$HT_REFUSAL" | grep -E -q "$5"; then
			check "$1" PASS "refused: $HT_REFUSAL"
		else
			check "$1" FAIL "refused, but not with /$5/: $HT_REFUSAL"
		fi
		vm_destroy ht-srneg
	}
	for kind in data kern meta; do
		d=$HT_CKP/neg-$kind; rm -rf "$d"
		if ckp_copy "$HT_CKP/A/srA" "$d"; then
			f=$(ckp_member "$d/srA" $kind)
			sz=$(stat -f %z "$f")
			off=$(( sz > 65536 ? 40973 : sz / 2 ))
			flip_byte "$f" $off
			neg "sr-neg-tamper-$kind" "$d/srA" "$NEGSLOTS" "" 'integrity verification failed' "a $kind member with byte $off flipped"
		else
			check "sr-neg-tamper-$kind" FAIL "could not copy checkpoint A to $d"
		fi
		rm -rf "$d"
	done
	d=$HT_CKP/neg-manifest; rm -rf "$d"
	ckp_copy "$HT_CKP/A/srA" "$d"
	truncate -s $(( $(stat -f %z "$d/srA") / 2 )) "$d/srA"
	neg sr-neg-truncated-manifest "$d/srA" "$NEGSLOTS" "" 'manifest' "a truncated manifest"
	rm -rf "$d"
	d=$HT_CKP/neg-dev; rm -rf "$d"
	ckp_copy "$HT_CKP/A/srA" "$d"
	neg sr-neg-device-missing "$d/srA" \
	    "-s 0,hostbridge -s 3,virtio-blk,$HT_WORK/neg.img -s 4,virtio-net,$tap1 -s 31,lpc" "" \
	    'topology|device contract' "a configuration without the virtio-rnd device"
	neg sr-neg-device-moved "$d/srA" \
	    "-s 0,hostbridge -s 3,virtio-blk,$HT_WORK/neg.img -s 7,virtio-rnd -s 4,virtio-net,$tap1 -s 31,lpc" "" \
	    'topology|device contract' "virtio-rnd moved from slot 6 to 7"
	# bhyve names no device for a restore-time device mismatch (see sr2
	# record); report what it said.
	check sr-neg-device-named INFO "$(grep -E '^sr-neg-device-(missing|moved)	' "$O/checks.tsv" | cut -f1,3 | grep -q 'virtio-rnd' && echo 'refusal names virtio-rnd' || echo 'refusal does not name the device (restore path logs only the topology class)')"
	# CPU contract: same host, but the nested-virtualization exposure differs.
	if nested_gate "$V" > /dev/null; then
		case $V in amd) nopt="-o x86.nested_svm=true" ;; intel) nopt="-o x86.nested_vmx=true" ;; esac
		neg sr-neg-cpu-contract "$d/srA" "$NEGSLOTS" "$nopt" 'CPU contract differs at' \
		    "a destination that exposes nested $V virtualization the checkpoint did not have"
	else
		check sr-neg-cpu-contract SKIP "needs nested virtualization to change the CPU contract: $(nested_gate "$V")"
	fi
	rm -rf "$d"
	[ "$(ckp_digest "$HT_CKP/A/srA")" = "$dA" ] &&
	    check sr-neg-original-untouched PASS "checkpoint A digest unchanged ($dA)" ||
	    check sr-neg-original-untouched FAIL "checkpoint A changed during the refused-restore tests"
	rm -f "$HT_WORK/neg.img"
else
	check sr-neg SKIP "no checkpoint A (sr-suspend-A failed)"
fi
rm -f "$HT_WORK/diskA.img"
phase_end
