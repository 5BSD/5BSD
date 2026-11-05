# Phase 4: VM save/restore and migration on the real host.
#  a) checkpoint (VM keeps running) and suspend + restore of a running guest:
#     a counter process must survive and keep counting, the private network
#     (bridge+tap created and removed here) must still answer;
#  b) HyperTrace fresh-session contract after a suspend/restore of a guest
#     with virtio-dtrace, suspended while a dtrace -E session is active:
#     delivery counters, new identity/epoch, old session gone, a newly
#     submitted program works and sees only new events;
#  c) localhost live migration with the confirmed handoff:
#     plaintext_unix same-host opt-in, mutual TLS with local certs, and
#     plaintext under a memory-dirtying workload (sr2);
#  d) active vsock connection relayed across a plaintext migration.
# The deeper save/restore matrix (data integrity, repeated restores, vCPUs,
# clock, TCP, refused restores) is the saverestore phase.

phase_begin snapshot
need_root
need_generation
need_vmm
need_image
need_mem_mb 4096
need_disk_mb 20480
need_tool openssl
need_tool timeout
sysctl -n kern.conftxt | grep -q '^options[[:space:]]*BHYVE_SNAPSHOT' || refuse "kernel lacks options BHYVE_SNAPSHOT"
bhyve -h 2>&1 | grep -q -- '-r: path to checkpoint file' || refuse "bhyve built without snapshot support"
bhyvectl --help 2>&1 | grep -q -- '--migrate-plaintext-unix' || refuse "bhyvectl lacks migration options"
dry && dry_end
phase_workdir
O=$HT_OUT
C=/root/hosttest/counter.sh
G=/root/hosttest/sr-guest.sh
ls /var/db/bhyve/migration > "$O/journals-before.txt" 2>/dev/null

# --- private network: bridge + tap, host 10.231.77.1/24 --------------------
ht_private_net_preflight 10.231.77 "$O/network-before" || refuse "$HT_NET_CONFLICT"
br=$(ifconfig bridge create) || refuse "cannot create bridge"
at_cleanup "ifconfig $br destroy"
tap=$(ifconfig tap create) || refuse "cannot create tap"
at_cleanup "ifconfig $tap destroy"
ifconfig "$br" inet 10.231.77.1/24 addm "$tap" up || refuse "bridge address/member setup failed"
ifconfig "$tap" up || refuse "tap setup failed"
ifconfig "$br" > "$O/bridge.txt"
pfctl -s info 2>/dev/null | grep -q 'Status: Enabled' && pf_on=yes || pf_on=no
log "network $br/$tap (pf enabled: $pf_on; no pf rules are changed)"

# Guest diagnostics share the bounded serial command with the ping; numeric
# queries avoid DNS. Full ping output is retained in a-start/a-after-restore.
NET_DIAG='echo NETWORK-DIAG; ifconfig -a; netstat -rn -f inet; route -n get -inet 10.231.77.1; arp -an; netstat -inb'

counter_value() { sed -n 's/.*COUNTER value=\([0-9]*\) alive=\([a-z]*\).*/\1 \2/p' "$1" | tail -1; }

# === a) checkpoint / suspend / restore ======================================
NET="-s 4,virtio-net,$tap"
vm=ht-snap; disk=$(vm_disk $vm)
vm_boot $vm "$disk" 1G 2 "hosttest.role=l1 hosttest.hostname=$vm hosttest.inet=10.231.77.2/24" "$NET" &&
    vm_wait $vm HOSTTEST-GUEST-READY ${HT_BOOT_TIMEOUT:-60} || { check boot-ht-snap FAIL "$(vm_diag $vm)"; phase_end; exit 1; }
check boot-ht-snap PASS
ht_net_diagnostics "$O/net-before-pre" "$br" "$tap" 10.231.77.2
vm_cmd $vm "$C start; $NET_DIAG; ping -c 2 -t 5 10.231.77.1; arp -an" 30 > "$O/a-start.txt" 2>&1
ht_net_diagnostics "$O/net-before-post" "$br" "$tap" 10.231.77.2
grep -q COUNTER-STARTED "$O/a-start.txt" && check counter-started PASS || check counter-started FAIL "$(tail -1 "$O/a-start.txt")"
ht_net_ping_ok "$O/a-start.txt" && check net-before PASS ||
    check net-before FAIL "guest cannot ping host bridge; see a-start.txt and net-before-*"

# Nonterminal checkpoint: VM must keep running and counting.
t0=$(date +%s)
bhyvectl --vm=$vm --checkpoint="$HT_CKP/ckp1" > "$O/checkpoint.txt" 2>&1; rc=$?
t1=$(date +%s)
if [ $rc -eq 0 ] && ckp_manifest "$HT_CKP/ckp1"; then
	check checkpoint-manifest PASS "$((t1 - t0)) s, $(du -Ash "$HT_CKP"/ckp1* | awk '{s=s" "$1} END {print s}') (apparent)"
else
	check checkpoint-manifest FAIL "bhyvectl rc=$rc $(tail -1 "$O/checkpoint.txt") $(vm_diag $vm)"
fi
sleep 2
vm_cmd $vm "$C read" 20 > "$O/a-after-ckp.txt" 2>&1
set -- $(counter_value "$O/a-after-ckp.txt"); v1=${1:-0}; a1=${2:-no}
[ "$a1" = yes ] && [ "$v1" -gt 0 ] && check running-after-checkpoint PASS "counter $v1" ||
    check running-after-checkpoint FAIL "counter '$v1' alive '$a1' $(vm_diag $vm)"

# Suspend (VM exits) then restore with the identical device configuration.
vm_cmd $vm "$C read" 20 > "$O/a-before-suspend.txt" 2>&1
set -- $(counter_value "$O/a-before-suspend.txt"); vb=${1:-0}
vm_suspend $vm "$HT_CKP/ckp2" suspend-exits "$O/suspend.txt" 120
vm_destroy $vm
sleep 3   # the counter would advance if the guest were still running
if vm_restore $vm "$HT_CKP/ckp2"; then
	ifconfig "$tap" up
	sleep 3
	ht_net_diagnostics "$O/net-restored-pre" "$br" "$tap" 10.231.77.2
	vm_cmd $vm "$C read; sleep 2; $C read; $NET_DIAG; ping -c 2 -t 5 10.231.77.1; arp -an" 40 > "$O/a-after-restore.txt" 2>&1
	ht_net_diagnostics "$O/net-restored-post" "$br" "$tap" 10.231.77.2
	va=$(sed -n 's/.*COUNTER value=\([0-9]*\) alive=yes.*/\1/p' "$O/a-after-restore.txt" | head -1)
	vz=$(sed -n 's/.*COUNTER value=\([0-9]*\) alive=yes.*/\1/p' "$O/a-after-restore.txt" | tail -1)
	if [ -n "$va" ] && [ -n "$vz" ] && [ "$va" -ge "$vb" ] && [ "$vz" -gt "$va" ]; then
		check restore-counter-continues PASS "before suspend $vb, after restore $va -> $vz"
	else
		check restore-counter-continues FAIL "before $vb, after '$va' -> '$vz' $(vm_diag $vm)"
	fi
	ht_net_ping_ok "$O/a-after-restore.txt" && check net-after-restore PASS ||
	    check net-after-restore FAIL "ping after restore failed; see a-after-restore.txt and net-restored-*"
else
	# The refusal line names the CPU contract field or topology (gen4).
	check restore-counter-continues FAIL "restore refused: $HT_REFUSAL"
	check net-after-restore SKIP "no restored guest"
fi
vm_shutdown $vm

# === b) HyperTrace fresh session across suspend/restore ======================
if kldstat -q -m hypertrace && [ -e /dev/dtrace/hypertrace ]; then
	ht_dtraced_up
	vm=ht-snapht; disk=$(vm_disk $vm)
	if vm_boot $vm "$disk" 1G 2 "hosttest.role=l1 hosttest.hostname=$vm $HT_GUEST_DTRACE_KENV" "$HT_VTDTR_ARGS" &&
	    vm_wait $vm HOSTTEST-GUEST-READY ${HT_BOOT_TIMEOUT:-60} && ht_wait_forwarder $vm 60; then
		check ht-boot PASS "$(head -1 "$HT_WORK/stats.$vm" 2>/dev/null)"
		ht_up=yes
	else
		check ht-boot FAIL "HyperTrace guest did not come up: $(head -1 "$HT_WORK/stats.$vm" 2>/dev/null) $(vm_diag $vm) $(ht_jobfail_lines)"
		ht_up=no
	fi
	W=/root/hosttest/workload.sh
	otel_session() { # NAME TAG
		mkdir -p "$O/$1-otlp"
		"$HT_KIT/bin/otlp_collector" -o "$O/$1-otlp" -p 0 -t 90 > /dev/null 2>&1 & cp=$!
		i=0; while [ ! -s "$O/$1-otlp/port" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
		ht_session "$1" 45 10 "$vm:$W $2 10" -- -x otel=otlp -x otelprotocol=http/json \
		    -x "otelendpoint=http://127.0.0.1:$(cat "$O/$1-otlp/port")" \
		    -n "$vm:proc:::exec-success /execname == \"htpre\" || execname == \"htpost\"/ { @[execname] = count(); }"
		sleep 2; kill $cp 2>/dev/null; wait $cp 2>/dev/null
		ht_otlp_parse "$O/$1-otlp" "$O/$1-parsed.txt" ||
		    log "invalid/missing OTLP capture: $O/$1-parsed.txt.errors"
	}
	lpid=""
	if [ $ht_up = yes ]; then
		otel_session htpre htpre
		e1=$(sed -n "s/^resource hypertrace.vm.epoch=//p" "$O/htpre-parsed.txt" | sort -u | tr '\n' ' ')
		ht_otlp_has_count "$O/htpre-parsed.txt" htpre && check ht-before-checkpoint PASS "epoch $e1" ||
		    check ht-before-checkpoint FAIL "no positive htpre OTLP count (htpre-parsed.txt) $(ht_err htpre)"
		ht_delivered htpre $vm && check ht-pre-delivery PASS "$(ht_delivery htpre)" ||
		    check ht-pre-delivery FAIL "deliveries not above 0 before the checkpoint $(ht_err htpre)"
		# sr2: suspend while a dtrace -E session is active (the coordinated
		# checkpoint must stop it cleanly), then restore and reconnect.
		# The guest workload ends ~10 s after the restore, so the console shell is
		# free again for htpost; the dtrace -E session itself runs 150 s.
		ht_session htlive 150 5 "$vm:$W htlive 30" -- \
		    -n "$vm:proc:::exec-success /execname == \"htlive\"/ { @[execname] = count(); }" &
		lpid=$!
		sleep 25
		pgrep -f 'dtrace -E -q' > /dev/null && live=yes || live=no
		check ht-session-active-at-suspend "$([ $live = yes ] && echo PASS || echo FAIL)" \
		    "dtrace -E consumer running when --suspend was sent: $live $([ $live = no ] && ht_err htlive)"
	fi
	if [ $ht_up = no ]; then
		check ht-coordinated-suspend SKIP "HyperTrace guest did not come up (ht-boot)"
		vm_destroy $vm
	else
		vm_suspend $vm "$HT_CKP/ckp-ht" ht-coordinated-suspend "$O/ht-suspend.txt" 600 ||
		    log "ht suspend detail: $(vm_diag $vm)"
		vm_destroy $vm
		dtracedctl --show-stats > "$O/ht-stats-after-suspend.txt" 2>&1
		if [ "${lpid:-}" ]; then
			wait "$lpid"
			check ht-live-session-outcome INFO "session active across the suspend ended rc=$(cat "$O/htlive.rc" 2>/dev/null): $(tr -s ' \n' ' ' < "$O/htlive.out" | cut -c1-120) | $(head -1 "$O/htlive.err" 2>/dev/null)"
		fi
		if vm_restore $vm "$HT_CKP/ckp-ht" && ht_wait_forwarder $vm 90; then
			check ht-restore-reconnect PASS "$(head -1 "$HT_WORK/stats.$vm")"
			otel_session htpost htpost
			e2=$(sed -n "s/^resource hypertrace.vm.epoch=//p" "$O/htpost-parsed.txt" | sort -u | tr '\n' ' ')
			ht_otlp_has_count "$O/htpost-parsed.txt" htpost &&
			    ! ht_otlp_has_count "$O/htpost-parsed.txt" htpre &&
			    ! ht_otlp_has_count "$O/htpost-parsed.txt" htlive &&
			    check ht-fresh-session-new-program PASS "only new events after restore" ||
			    check ht-fresh-session-new-program FAIL "$(tr -s ' \n' ' ' < "$O/htpost.out") $(ht_err htpost)"
			ht_delivered htpost $vm && check ht-post-delivery PASS "$(ht_delivery htpost)" ||
			    check ht-post-delivery FAIL "deliveries not above 0 after the restore $(ht_err htpost)"
			[ -n "$e2" ] && [ "$e1" != "$e2" ] && check ht-new-epoch PASS "epoch $e1 -> $e2" ||
			    check ht-new-epoch FAIL "epoch before '$e1' after '$e2'"
			# This is a new consumer, so its first observation is registered.
			# A restarted event requires one consumer to observe both epochs.
			grep -q '^event hypertrace\.vm\.registered$' "$O/htpost-parsed.txt" &&
			    check ht-restored-registration PASS || check ht-restored-registration FAIL "no registration event in the fresh consumer"
		else
			check ht-restore-reconnect FAIL "restored HyperTrace guest did not reconnect: ${HT_REFUSAL:-forwarder channels: $(head -1 "$HT_WORK/stats.$vm" 2>/dev/null)} $(vm_diag $vm) $(ht_jobfail_lines)"
		fi
	fi
	vm_shutdown $vm
else
	check ht-fresh-session SKIP "hypertrace.ko not loaded on the host"
fi

# === c/d) localhost live migration ==========================================
# mig_run MODE NAME EXTRA_SRC_OPTS EXTRA_DST_OPTS EXTRA_SLOTS_SRC EXTRA_SLOTS_DST
#   MIG_GUEST_PRE: guest command on the source before the handoff
#   MIG_GUEST_POST: guest command on the destination after it (output in
#   mig-MODE-post.txt)
mig_run()
{
	mode=$1 src=ht-$2-src dst=ht-$2-dst; shift 2
	sopt=$1 dopt=$2 sslots=$3 dslots=$4
	disk=$(vm_disk "$src")
	vm_boot "$src" "$disk" 1G 2 "hosttest.role=l1 hosttest.hostname=$src" "$sopt $sslots" &&
	    vm_wait "$src" HOSTTEST-GUEST-READY ${HT_BOOT_TIMEOUT:-60} || { check "mig-$mode-boot" FAIL "$(vm_diag "$src")"; return 1; }
	vm_cmd "$src" "$C start" 20 > "$O/mig-$mode-start.txt" 2>&1
	[ -n "${MIG_GUEST_PRE:-}" ] && vm_cmd "$src" "$MIG_GUEST_PRE" 30 >> "$O/mig-$mode-start.txt" 2>&1
	vm_cmd "$src" "$C read" 20 > "$O/mig-$mode-before.txt" 2>&1
	set -- $(counter_value "$O/mig-$mode-before.txt"); vb=${1:-0}
	dport=$(free_port $(( $(cat "$HT_WORK/$src.port") + 1 ))); echo "$dport" > "$HT_WORK/$dst.port"
	: > "$HT_WORK/$dst.console"; : > "$HT_WORK/$dst.input"
	HT_VMS="$HT_VMS $dst"; at_cleanup "vm_destroy $dst"
	case $mode in
	tls)
		dcmd="exec bhyve -c 2 -m 1G -H -w -D -R 3 $dopt -s 0,hostbridge -s 3,virtio-blk,$disk -s 6,virtio-rnd $dslots -s 31,lpc -l com1,tcp=127.0.0.1:$dport $dst 4<$T/dst.crt 5<$T/dst.key 6<$T/ca.crt"
		scmd="exec bhyvectl --vm=$src --migrate-fd=3 $sopt_ctl 4<$T/src.crt 5<$T/src.key 6<$T/ca.crt" ;;
	*)
		dcmd="exec bhyve -c 2 -m 1G -H -w -D -R 3 $dopt -s 0,hostbridge -s 3,virtio-blk,$disk -s 6,virtio-rnd $dslots -s 31,lpc -l com1,tcp=127.0.0.1:$dport $dst"
		scmd="exec bhyvectl --vm=$src --migrate-fd=3 --migrate-plaintext-unix" ;;
	esac
	echo "dst: $dcmd" > "$O/mig-$mode-cmds.txt"; echo "src: $scmd" >> "$O/mig-$mode-cmds.txt"
	# bhyveload guests: the destination VM must exist before bhyve -R.
	vm_create_empty "$dst" || { check "mig-$mode-handoff" FAIL "bhyvectl --create --vm=$dst failed"; vm_destroy "$src"; return 1; }
	vm_mem_guard "$dst" 1G || { check "mig-$mode-handoff" FAIL "$HT_GUARD_MSG"; vm_destroy "$src"; return 1; }
	t0=$(date +%s)
	"$HT_KIT/bin/ht-sockpair" -p "$HT_WORK/$dst.pid" -t 3 sh -c "$dcmd >> $HT_WORK/$dst.bhyve.log 2>&1" \
	    -- sh -c "$scmd" > "$O/mig-$mode-bhyvectl.txt" 2>&1; rc=$?
	t1=$(date +%s)
	[ -z "${MIG_WATCH:-}" ] || wc -l < "$MIG_WATCH" | tr -d ' ' > "$O/mig-$mode-lines-at-handoff"
	if [ $rc -eq 0 ]; then check "mig-$mode-handoff" PASS "bhyvectl completed in $((t1 - t0)) s"; else
		# gen4: the destination names the refused device/field.
		check "mig-$mode-handoff" FAIL "bhyvectl rc=$rc $(tail -2 "$O/mig-$mode-bhyvectl.txt" | tr '\n' ' ') [destination: $(bhyve_refusal "$HT_WORK/$dst.bhyve.log")]"; fi
	i=0; while kill -0 "$(cat "$HT_WORK/$src.pid")" 2>/dev/null && [ $i -lt 60 ]; do sleep 1; i=$((i + 1)); done
	kill -0 "$(cat "$HT_WORK/$src.pid")" 2>/dev/null && check "mig-$mode-source-retired" FAIL "source bhyve still running" ||
	    check "mig-$mode-source-retired" PASS
	if vm_attach_console "$dst"; then
		sleep 2
		vm_cmd "$dst" "$C read; sleep 2; $C read" 30 > "$O/mig-$mode-after.txt" 2>&1
		va=$(sed -n 's/.*COUNTER value=\([0-9]*\) alive=yes.*/\1/p' "$O/mig-$mode-after.txt" | head -1)
		vz=$(sed -n 's/.*COUNTER value=\([0-9]*\) alive=yes.*/\1/p' "$O/mig-$mode-after.txt" | tail -1)
		[ -n "$va" ] && [ -n "$vz" ] && [ "$va" -ge "$vb" ] && [ "$vz" -gt "$va" ] &&
		    check "mig-$mode-guest-continues" PASS "counter $vb -> $va -> $vz on $dst" ||
		    check "mig-$mode-guest-continues" FAIL "before $vb after '$va' -> '$vz' $(vm_diag "$dst")"
		[ -z "${MIG_GUEST_POST:-}" ] || vm_cmd "$dst" "$MIG_GUEST_POST" 60 > "$O/mig-$mode-post.txt" 2>&1
	else
		check "mig-$mode-guest-continues" FAIL "destination not running: $(bhyve_refusal "$HT_WORK/$dst.bhyve.log")"
	fi
	[ -z "${MIG_WATCH:-}" ] || { sleep 3; wc -l < "$MIG_WATCH" | tr -d ' ' > "$O/mig-$mode-lines-at-end"; }
	vm_shutdown "$dst"; vm_destroy "$src"
}

sopt_ctl=""
mig_run plain plain "" "-o migrate.plaintext_unix=true" "" ""

# sr2: plaintext migration while the guest rewrites HT_DIRTY_MB (256) MiB
# continuously (srtool dirty checks each word still holds the previous
# pass's value, so a dirty page the migration lost shows up as errors).
DMB=${HT_DIRTY_MB:-256}
MIG_GUEST_PRE="$G dirty $DMB; sleep 3; $G dirty-read"
MIG_GUEST_POST="$G dirty-read; sleep 4; $G dirty-read"
mig_run dirty dirty "" "-o migrate.plaintext_unix=true" "" ""
MIG_GUEST_PRE="" MIG_GUEST_POST=""
p0=$(sr_val "$O/mig-dirty-start.txt" 'SRDIRTY ' pass)
p1=$(head -1 "$O/mig-dirty-post.txt" 2>/dev/null | sed -n 's/.* pass=\([0-9]*\).*/\1/p')
p2=$(sr_val "$O/mig-dirty-post.txt" 'SRDIRTY ' pass)
er=$(sr_val "$O/mig-dirty-post.txt" 'SRDIRTY ' errors)
al=$(sr_val "$O/mig-dirty-post.txt" 'SRDIRTY ' alive)
if ! grep -q '^mig-dirty-handoff	PASS' "$O/checks.tsv"; then
	check mig-dirty-memory-intact FAIL "no completed migration under a ${DMB} MiB dirtying load (see mig-dirty-handoff); pass before ${p0:-?}"
elif [ -n "$p0" ] && [ -n "$p2" ] && [ "$p2" -gt "${p1:-0}" ] && [ "${p1:-0}" -ge "$p0" ] && [ "$er" = 0 ] && [ "$al" = yes ]; then
	check mig-dirty-memory-intact PASS "${DMB} MiB rewritten continuously: pass $p0 before, $p1 -> $p2 on the destination, 0 word errors"
else
	check mig-dirty-memory-intact FAIL "pass before '$p0' after '$p1' -> '$p2' errors '$er' alive '$al' ($(tail -1 "$O/mig-dirty-post.txt" 2>/dev/null))"
fi

# Mutual TLS with throwaway local certificates (kept under the work dir).
T=$HT_WORK/tls; mkdir -p "$T"; chmod 700 "$T"
(
	cd "$T" || exit 1
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
	    -subj /CN=hosttest-ca -keyout ca.key -out ca.crt
	for n in src dst; do
		openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		    -subj "/CN=hosttest-$n" -keyout $n.key -out $n.csr
		printf 'subjectAltName=DNS:hosttest-%s\nextendedKeyUsage=serverAuth,clientAuth\n' $n > $n.ext
		openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
		    -extfile $n.ext -out $n.crt
		openssl x509 -in $n.crt -outform DER | sha256 -q > $n.sha256
	done
	chmod 600 ./*.key
) > "$O/tls-gen.log" 2>&1
if [ -s "$T/dst.sha256" ]; then
	sopt_ctl="--migrate-certificate-fd=4 --migrate-key-fd=5 --migrate-trust-fd=6 --migrate-peer-sha256=$(cat "$T/dst.sha256")"
	mig_run tls tls "" "-o migrate.tls.certificate_fd=4 -o migrate.tls.private_key_fd=5 -o migrate.tls.trust_fd=6 -o migrate.tls.peer_sha256=$(cat "$T/src.sha256")" "" ""
else
	check mig-tls-handoff FAIL "certificate generation failed: $(tail -1 "$O/tls-gen.log")"
fi

# Active vsock connection relayed across a plaintext migration.
EID=$(openssl rand -hex 16)
mkdir -p "$HT_WORK/vs-src" "$HT_WORK/vs-dst"
nc -lkU "$HT_WORK/vs-src/5000" > "$O/vsock-received.txt" 2>&1 & ncp=$!
at_cleanup "kill $ncp 2>/dev/null"
# The destination path names the same logical host service.
ln -sf "$HT_WORK/vs-src/5000" "$HT_WORK/vs-dst/5000"
MIG_WATCH=$O/vsock-received.txt
MIG_GUEST_PRE="( while :; do date +%s; sleep 0.5; done | /root/hosttest/vsock-pipe 2 5000 > /dev/null 2>&1 & ) ; sleep 2"
mig_run vsock vsock "-o checkpoint.migrate_active_vsock=true" \
    "-o migrate.plaintext_unix=true -o checkpoint.migrate_active_vsock=true" \
    "-s 5,virtio-vsock,cid=3,path=$HT_WORK/vs-src,migration_endpoint_id=$EID" \
    "-s 5,virtio-vsock,cid=3,path=$HT_WORK/vs-dst,migration_endpoint_id=$EID"
MIG_GUEST_PRE="" MIG_WATCH=""
# Lines received after the handoff prove the relay forwards the old stream
# (the guest writes two lines per second on one connection opened before
# the migration).
nh=$(cat "$O/mig-vsock-lines-at-handoff" 2>/dev/null || echo 0)
ne=$(cat "$O/mig-vsock-lines-at-end" 2>/dev/null || echo 0)
# Only meaningful when the migration really handed off: while the source
# keeps running, its own vsock stream also keeps the line count growing.
if ! grep -q '^mig-vsock-handoff	PASS' "$O/checks.tsv" ||
    ! grep -q '^mig-vsock-source-retired	PASS' "$O/checks.tsv"; then
	check vsock-relay-after-migration FAIL "no completed vsock migration (mig-vsock-handoff/source-retired); $nh lines at handoff, $ne at end"
elif [ "$nh" -gt 0 ] && [ "$ne" -gt $((nh + 2)) ]; then
	check vsock-relay-after-migration PASS "$nh lines before handoff, $ne after (same connection)"
else
	check vsock-relay-after-migration FAIL "$nh lines at handoff, $ne at end"
fi
kill $ncp 2>/dev/null

ls /var/db/bhyve/migration > "$O/journals-after.txt" 2>/dev/null
for j in $(comm -13 "$O/journals-before.txt" "$O/journals-after.txt" 2>/dev/null); do
	bhyvectl --migrate-journal="/var/db/bhyve/migration/$j" >> "$O/journals.txt" 2>&1
done
check migration-journals INFO "new journals: $(comm -13 "$O/journals-before.txt" "$O/journals-after.txt" | tr '\n' ' ') (left in /var/db/bhyve/migration)"
phase_end
