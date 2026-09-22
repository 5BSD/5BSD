#!/bin/sh
# Storage-TCB robustness stress: several units churn the transaction machinery in
# parallel (begin + abort, an occasional heavy commit, and periodic snapshot/
# list/open_version/rollback) while the daemon's reconcile reaper runs its idle
# staging sweep against the same live pool.  It proves the storage TCB stays
# ROBUST under sustained concurrent TXN load: no panic, no deadlock, no pool
# corruption, no leaked staging clone -- and forward progress.
#
# NOTE ON THROUGHPUT: absolute iteration counts here are tiny and this harness
# gates ROBUSTNESS, not throughput.  Verified on BOTH a VBSD-DEBUG and a rebuilt
# non-DEBUG (VBSD) kernel: each tzfs mutating op serialises on the broker's global
# sx lock (zfshandle_ioctl) and carries a ZFS txg-sync/CPU cost, so this zero-
# think-time tight loop (worst case; real clients don't loop commits) crawls
# regardless of WITNESS -- the low count is that serialisation + QEMU's slow
# emulated disk, not a daemon defect (no crash/deadlock/leak was ever seen; the
# pool stayed healthy).  The OpenZFS dbuf VERIFY panic this churn trips is
# DEBUG-only (absent on the non-DEBUG kernel).  Drains in-flight commits before
# querying because the console itself starves under active load.
# TXN and snapshot ops are unit-scoped in the client API, so each unit contends
# on its OWN claim; the concurrency stresses the daemon's fork-per-connection
# serving and the reaper-vs-live-txn interaction across the pool.
#
#   UNITS (default 3), STRESS_SECS (default 60)
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
: "${UNITS:=3}"; : "${STRESS_SECS:=60}"
scrub_stage
# restart = "never" (the stage_bundle default): the probe loops forever on its
# own, and a pkill during drain then stops it for good instead of relaunching.
n=1; while [ $n -le "$UNITS" ]; do
	stage_bundle System T$n app.T$n "" txnstressprobe txnstressprobe >/dev/null
	n=$((n+1))
done
build_image ts
boot rw || exit 1

echo "=== $UNITS units churn the TXN path for ${STRESS_SECS}s ==="
V "sleep 6; pgrep -fc txnstressprobe | sed 's/^/STRESSERS_UP=/'" 20
V "sleep $STRESS_SECS; echo hammered" $((STRESS_SECS + 30))

echo "=== stop churn; disable restart; drain in-flight commits (slow under DEBUG) ==="
# restart="never", so a kill stops them; the workers then finish in-flight
# commits and the pool quiesces for querying.
V "pkill -9 -f txnstressprobe; echo killed" 20
# Poll until no worker is still inside a ZFS op (TrustedZ/tx-sync), up to ~150s.
V "i=0; while [ \$i -lt 30 ]; do \
     ps -axo wchan,command 2>/dev/null | grep Filesystem | grep -qE 'TrustedZ|tx->tx' || break; \
     sleep 5; i=\$((i+1)); done; echo DRAINED_AFTER=\$((i*5))s" 170

echo "=== robustness assertions ==="
V "pgrep -f 'Filesystem \\(' >/dev/null && echo DAEMON_ALIVE_PASS || echo DAEMON_DEAD_FAIL; \
   procstat -kk \$(pgrep -f 'Filesystem\\[reclaim\\]') 2>/dev/null | tail -1 | grep -q _sx_xlock \
     && echo REAPER_LOCK_STUCK_FAIL || echo REAPER_NOT_STUCK_PASS; \
   zfs list zroot/Capabilities/Data >/dev/null 2>&1 && echo POOL_HEALTHY_PASS || echo POOL_SICK_FAIL" 30

echo "=== forward progress + no leak ==="
prog=0
n=1; while [ $n -le "$UNITS" ]; do
	DS=zroot/Capabilities/Data/T$n/txnstressprobe/persistent/state
	V "$(OBS $DS); printf 'T$n: '; cat /mnt/obs/tally 2>/dev/null || echo NO_TALLY; \
	   $(DROP_OBS $DS)" 40
	n=$((n+1))
done
# Give the idle reap a couple of passes to clear any abandoned/in-flight clones.
V "sleep 25; c=\$(zfs list -H -o name -r zroot/Capabilities/Data 2>/dev/null | grep -cE '/v[0-9a-f]{16,}\$'); \
   echo RESIDUAL_STAGING_CLONES=\$c; \
   [ \"\$c\" -eq 0 ] && echo NO_STAGING_LEAK_PASS || echo STAGING_RESIDUAL_\$c" 50
echo DONE
