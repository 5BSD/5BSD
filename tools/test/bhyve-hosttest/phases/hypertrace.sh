# Phase 2: HyperTrace on real bhyve.
# Two 5BSD guests with virtio-dtrace + a guest dtraced minion; the host runs
# dtraced as overlord. Checks: device/driver attach, forwarder registration,
# `dtrace -E` with guest probes, multiple programs in one -E session,
# per-VM isolation and globbing, exact drain (no loss) of a bounded workload,
# fresh state per session, and `-x otel` host mode with one resource per
# guest validated by the independent OTLP validators.

phase_begin hypertrace
need_root
need_generation
need_vmm
need_hypertrace_host
need_image
need_mem_mb 3072
need_disk_mb 10240
dry && dry_end
phase_workdir
O=$HT_OUT

ht_dtraced_up || { phase_end; exit 1; }
dtracedctl --show-stats > "$O/stats-before.txt" 2>&1

for vm in ht-trace1 ht-trace2; do
	vm_boot "$vm" "$(vm_disk "$vm")" 1G 2 \
	    "hosttest.role=l1 hosttest.hostname=$vm $HT_GUEST_DTRACE_KENV" "$HT_VTDTR_ARGS" ||
	    { check "boot-$vm" FAIL "bhyve did not start $(vm_diag "$vm")"; phase_end; exit 1; }
done
for vm in ht-trace1 ht-trace2; do
	if vm_wait "$vm" 'HOSTTEST-GUEST-READY' ${HT_BOOT_TIMEOUT:-60}; then check "boot-$vm" PASS; else
		check "boot-$vm" FAIL "no ready marker $(vm_diag "$vm")"; phase_end; exit 1; fi
done

# Guest side attach.
vm_cmd ht-trace1 'kldstat -v | grep -E "virtio_dtrace|dttransport" | head -4; ls -l /dev/dttransport; pciconf -l | grep -i -E "vtdtr|dtrace"; pgrep -lf dtraced; dmesg | grep -i -E "vtdtr|hypertrace|dttransport" | tail -5' 30 > "$O/guest-attach.txt" 2>&1
grep -q '/dev/dttransport' "$O/guest-attach.txt" && check guest-dttransport PASS || check guest-dttransport FAIL "no /dev/dttransport"
grep -q 'dtraced' "$O/guest-attach.txt" && check guest-dtraced-minion PASS || check guest-dtraced-minion FAIL "dtraced not running in guest"
forwarders_ok=yes
for vm in ht-trace1 ht-trace2; do
	if ht_wait_forwarder "$vm" 60; then check "forwarder-$vm" PASS "$(head -3 "$HT_WORK/stats.$vm" | tr '\n' ' ')"
	else forwarders_ok=no; check "forwarder-$vm" FAIL "dtracedctl --show-stats=$vm shows fewer than 2 channels: $(head -1 "$HT_WORK/stats.$vm" 2>/dev/null) $(vm_diag "$vm") $(ht_jobfail_lines)"; fi
done
cp "$HT_WORK"/stats.* "$O/" 2>/dev/null
[ "$forwarders_ok" = yes ] || { ht_guest_diagnostics forwarder; phase_end; exit 1; }

# Distinguish local provider/execution failures from forwarding failures.
for target in host ht-trace1 ht-trace2; do
 if [ "$target" = host ]; then
  sh "$HT_KIT/guest/dtrace-cases.sh" > "$O/local-$target.txt" 2>&1
  local_rc=$?
 else
  vm_cmd "$target" 'sh /root/hosttest/dtrace-cases.sh' 100 > "$O/local-$target.txt" 2>&1
  local_rc=$?
 fi
 for probe in begin-end syscall-entry syscall-return syscall-exit proc-exec invalid-program; do
  if [ "$local_rc" -eq 0 ] && grep -qx "DTRACE-CASE $probe PASS" "$O/local-$target.txt"; then
   check "dtrace-local-$target-$probe" PASS
  else
   check "dtrace-local-$target-$probe" FAIL "see local-$target.txt (command rc=$local_rc)"
  fi
 done
done

W=/root/hosttest/workload.sh
# 1. Single program with guest syscall probes.
ht_session single 45 10 "ht-trace1:$W htmark1 15" -- \
    -n 'ht-trace1:syscall:::entry /execname == "htmark1"/ { @[vmname, execname] = count(); }'
if grep -E 'ht-trace1[[:space:]]+htmark1[[:space:]]+[1-9]' "$O/single.out" >/dev/null; then
	check dtrace-E-guest-syscall PASS "$(grep htmark1 "$O/single.out" | head -1 | tr -s ' ')"
else
	check dtrace-E-guest-syscall FAIL "no htmark1 aggregation: $(ht_err single)"
fi
# sr2: the program must have been delivered to and installed in the guest
# (gen3: outbound/installed stayed 0 because the forwarder got SHA framing).
if ht_delivered single ht-trace1; then
	check delivery-counters-ht-trace1 PASS "$(ht_delivery single)"
else
	check delivery-counters-ht-trace1 FAIL "no live sample with outbound/installed deliveries above 0 during session single $(ht_err single)"
fi

# Later tests cannot qualify a broken basic round trip. Preserve the first
# failure and its spool/daemon evidence instead of accumulating timeouts.
if ! grep -E 'ht-trace1[[:space:]]+htmark1[[:space:]]+[1-9]' "$O/single.out" >/dev/null ||
    ! ht_delivered single ht-trace1; then
	log "Stopping HyperTrace after the failed basic delivery/aggregation test"
	phase_end; exit 1
fi

# Validate the exact guest probe names before testing their combination.
# FreeBSD's syscall provider exposes _exit, not exit.
if vm_cmd ht-trace1 'dtrace -l -n syscall::_exit:entry' 20 > "$O/multi-probe-exit.txt" 2>&1 &&
    grep -Eq '[[:space:]]_exit[[:space:]]+entry[[:space:]]*$' "$O/multi-probe-exit.txt"; then
	check multi-exit-probe-exists PASS
else
	check multi-exit-probe-exists FAIL "guest _exit entry probe absent or query failed; see multi-probe-exit.txt"
	phase_end; exit 1
fi

trace_session_finished()
{
 case "$(cat "$O/$1.rc" 2>/dev/null)" in 0) return 0 ;; *) return 1 ;; esac
}
# Request-level VirtIO SDT probes cover both split and packed queues.
# The guest transport suppresses its own SDT probes at queue allocation;
# these host-side predicates select root disk activity after forwarding.
# Any transport event is forbidden and rejected by the aggregate checker.
virtqueue_probes=yes
for spec in virtqueue::enqueue:result virtqueue::dequeue:complete; do
 if ! vm_cmd ht-trace1 "dtrace -l -n $spec" 20 > "$O/virtqueue-${spec##*:}.probes" 2>&1; then
  virtqueue_probes=no
 fi
done
if [ "$virtqueue_probes" = yes ]; then
 ht_session virtqueue 30 5 "ht-trace1:sh /root/hosttest/virtqueue-workload.sh" -- \
  -n 'ht-trace1:virtqueue::enqueue:result /stringof(arg0) == "vtblk0 request.0" && arg5 == 0/ { @submit["SUBMIT", vmname, arg1, arg2] = count(); }' \
  -n 'ht-trace1:virtqueue::dequeue:complete /stringof(arg0) == "vtblk0 request.0"/ { @complete["COMPLETE", vmname, arg1, arg2] = count(); }' \
  -n 'ht-trace1:virtqueue::enqueue:result,ht-trace1:virtqueue::dequeue:complete /substr(stringof(arg0), 0, 5) == "vtdtr"/ { @transport["TRANSPORT", vmname, arg1, arg2] = count(); }'
 if trace_session_finished virtqueue && ht_delivered virtqueue ht-trace1 &&
     grep -qx VIRTQUEUE-WORK-DONE "$O/virtqueue.ht-trace1.guest" &&
     sh "$HT_KIT/lib/virtqueue-check.sh" "$O/virtqueue.out" "${HT_ROOT_PACKED:-no}" > "$O/virtqueue-counts.txt"; then
  check dtrace-E-virtqueue PASS "$(cat "$O/virtqueue-counts.txt")"
 else
  check dtrace-E-virtqueue FAIL "no clean guest VirtIO request/completion evidence: $(ht_err virtqueue)"
 fi
else
 check dtrace-E-virtqueue FAIL "guest request-level virtqueue probes missing; rebuild guest kernel with the new probes and KDTRACE_HOOKS"
fi

for kind in exec exit; do
 case "$kind" in exec) probe='proc:::exec-success' ;; exit) probe='syscall::_exit:entry' ;; esac
 ht_session "individual-$kind" 30 5 "ht-trace1:$W htindiv 8" -- \
     -n "ht-trace1:$probe /execname == \"htindiv\"/ { @[\"HIT\"] = count(); }"
 want=$(ht_runs "$O/individual-$kind.ht-trace1.guest")
 got=$(awk '$1 == "HIT" {print $2}' "$O/individual-$kind.out" | tail -1)
 if trace_session_finished "individual-$kind" && [ -n "$want" ] && [ "$want" -gt 0 ] && [ "$want" = "$got" ]; then
  check "dtrace-E-individual-$kind" PASS "guest ran $want, host counted $got"
 else
  check "dtrace-E-individual-$kind" FAIL "runs='$want' count='$got' $(ht_err individual-$kind)"
 fi
done

# 2. Multiple programs in one -E session (-E sends all).
ht_session multi 45 10 "ht-trace1:$W htmark2 15" -- \
    -n 'ht-trace1:proc:::exec-success /execname == "htmark2"/ { @a["P1", execname] = count(); }' \
    -n 'ht-trace1:syscall::_exit:entry /execname == "htmark2"/ { @b["P2", execname] = count(); }'
multi_runs=$(ht_runs "$O/multi.ht-trace1.guest")
p1=$(awk '$1 == "P1" && $2 == "htmark2" {print $3}' "$O/multi.out" | tail -1)
p2=$(awk '$1 == "P2" && $2 == "htmark2" {print $3}' "$O/multi.out" | tail -1)
if trace_session_finished multi && [ -n "$multi_runs" ] && [ "$multi_runs" -gt 0 ] && [ "$p1" = "$multi_runs" ] && [ "$p2" = "$multi_runs" ]; then
	check dtrace-E-multiple-programs PASS "P1=$p1 P2=$p2 workload=$multi_runs"
else
	check dtrace-E-multiple-programs FAIL "P1=$(grep -c P1 "$O/multi.out") P2=$(grep -c P2 "$O/multi.out") $(ht_err multi)"
fi

# 3. Isolation and glob: both guests run the same tag; a program aimed at
#    ht-trace1 must only see ht-trace1, the glob must see both.
ht_session iso1 45 10 "ht-trace1:$W htmark3 12;ht-trace2:$W htmark3 12" -- \
    -n 'ht-trace1:proc:::exec-success /execname == "htmark3"/ { @[vmname] = count(); }'
if grep -q 'ht-trace1' "$O/iso1.out" && ! grep -q 'ht-trace2' "$O/iso1.out"; then
	check isolation-single-target PASS
else
	check isolation-single-target FAIL "$(tr -s ' \n' ' ' < "$O/iso1.out") $(ht_err iso1)"
fi
ht_session iso2 45 10 "ht-trace1:$W htmark4 12;ht-trace2:$W htmark4 12" -- \
    -n 'ht-trace*:proc:::exec-success /execname == "htmark4"/ { @[vmname] = count(); }'
if grep -q 'ht-trace1' "$O/iso2.out" && grep -q 'ht-trace2' "$O/iso2.out"; then
	check glob-target-both-guests PASS
else
	check glob-target-both-guests FAIL "$(tr -s ' \n' ' ' < "$O/iso2.out") $(ht_err iso2)"
fi

# 4. Exact drain: a bounded workload that ends before the session stops
#    must be counted exactly (exec-success fires once per run).
ht_session drain 50 10 "ht-trace1:$W htdrain 10" -- \
    -n 'ht-trace1:proc:::exec-success /execname == "htdrain"/ { @n["DRAIN"] = count(); }'
runs=$(ht_runs "$O/drain.ht-trace1.guest")
got=$(awk '$1 == "DRAIN" {print $2}' "$O/drain.out" | tail -1)
if [ -n "$runs" ] && [ "$runs" = "$got" ]; then
	check drain-exact-count PASS "guest ran $runs, host counted $got"
else
	check drain-exact-count FAIL "guest ran '$runs', host counted '$got' (drops: $(grep -i drop "$O/drain.err" | head -1))"
fi
# Only meaningful when the drain session produced its aggregation; a session
# that never started has no drops to report (htcap: was a false PASS).
if [ -z "$got" ]; then
	check no-drops FAIL "drain session produced no data: $(ht_err drain)"
elif grep -i -q 'drop' "$O"/*.err; then
	check no-drops FAIL "$(grep -i -h drop "$O"/*.err | head -2 | tr '\n' ' ')"
else
	check no-drops PASS
fi

# 5. Fresh session state: a new -E session must not resurrect the previous
#    session's aggregation (old tag absent even though the predicate allows it).
ht_session fresh 45 10 "ht-trace1:$W htsessB 10" -- \
    -n 'ht-trace1:proc:::exec-success /execname == "htdrain" || execname == "htsessB"/ { @[execname] = count(); }'
if grep -q htsessB "$O/fresh.out" && ! grep -q htdrain "$O/fresh.out"; then
	check fresh-session-no-old-aggregates PASS
else
	check fresh-session-no-old-aggregates FAIL "$(tr -s ' \n' ' ' < "$O/fresh.out") $(ht_err fresh)"
fi
dtracedctl --show-stats > "$O/stats-after-sessions.txt" 2>&1
check dtraced-stats-recorded INFO "see stats-before.txt / stats-after-sessions.txt (installed/revoked counts)"

# 6. -x otel host mode: one resource per guest, validated independently.
mkdir -p "$O/otlp"
"$HT_KIT/bin/otlp_collector" -o "$O/otlp" -p 0 -t 120 > "$O/otlp-collector.log" 2>&1 &
cpid=$!; at_cleanup "kill $cpid 2>/dev/null"
i=0; while [ ! -s "$O/otlp/port" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
ep="http://127.0.0.1:$(cat "$O/otlp/port")"
ht_session otel 50 10 "ht-trace1:$W htotel 12;ht-trace2:$W htotel 12" -- \
    -x otel=otlp -x otelprotocol=http/json -x "otelendpoint=$ep" \
    -n 'ht-trace*:syscall:::entry /execname == "htotel"/ { @[execname] = count(); }'
sleep 3; kill $cpid 2>/dev/null; wait $cpid 2>/dev/null
if ls "$O"/otlp/*.json >/dev/null 2>&1 && "$HT_KIT/bin/otlp_validate" "$O"/otlp/*.json > "$O/otlp-validate.txt" 2>&1; then
	check otel-otlp-validate PASS "$(cat "$O/otlp-validate.txt")"
else
	check otel-otlp-validate FAIL "$(tail -1 "$O/otlp-validate.txt" 2>/dev/null) $(ht_err otel)"
fi
for f in "$O"/otlp/*.json; do "$HT_KIT/bin/otlp_json_validate" "$f"; done > "$O/otlp-parsed.txt" 2>&1
for vm in ht-trace1 ht-trace2; do
	if grep -q "^resource hypertrace.vm.name=$vm" "$O/otlp-parsed.txt"; then
		check "otel-resource-$vm" PASS "$(grep -E '^resource hypertrace\.vm\.(id|epoch)=' "$O/otlp-parsed.txt" | sort -u | tr '\n' ' ' | cut -c1-200)"
	else
		check "otel-resource-$vm" FAIL "no resource with hypertrace.vm.name=$vm"
	fi
done
grep -q '^resource hypertrace.host.name=' "$O/otlp-parsed.txt" && check otel-hypervisor-attribute PASS ||
    check otel-hypervisor-attribute FAIL "hypertrace.host.name missing"
grep -h -o 'hypertrace\.vm\.registered' "$O"/otlp/*.json >/dev/null 2>&1 &&
    check otel-vm-registered-event PASS || check otel-vm-registered-event FAIL "no hypertrace.vm.registered log event"

for vm in ht-trace1 ht-trace2; do vm_shutdown "$vm"; done
# bhyve's own diagnostics (forwarder/device errors) next to the results.
for vm in ht-trace1 ht-trace2; do
	cp "$HT_WORK/$vm.bhyve.log" "$HT_WORK/$vm.console" "$O/" 2>/dev/null
done
phase_end
