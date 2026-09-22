#!/bin/sh
# Container-model ABANDONED-TXN SWEEP proof.
#
# A TXN_BEGIN stages a read-write clone of a claim, reaped explicitly by
# TXN_COMMIT/TXN_ABORT.  A client that begins a transaction and then vanishes
# (crash, kill) without committing or aborting leaves that clone behind:
# connection teardown only UNMOUNTS it (a txn may legitimately resume on a later
# connection, so it is not tagged ephemeral), it lives in the persistent tree
# where the ephemeral lease/boot GC never looks, and the container reconcile
# only reaps whole uninstalled bundles -- so nothing reclaims it while the
# bundle stays installed.  A transaction cannot span a reboot, so bsdfilesystem
# runs a boot-scoped staging sweep at startup that destroys every such orphan.
#
# reclaimprobe drives it: on each boot it TXN_BEGINs on "abandonme", writes into
# the staging clone, and exits without committing/aborting, recording the
# abandoned txn id into the observable "state" container.
#
#   boot #1  -> an abandoned v<hex> clone is left in the namespace (teardown did
#               NOT reap it): ABANDONED_CLONE_PRESENT
#   reboot   -> the daemon's startup sweep runs BEFORE serving; that specific
#               boot-#1 clone id is gone: SWEEP_REAPED (a fresh boot-#2 abandon
#               may appear, which is expected and irrelevant)
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
scrub_stage
stage_bundle System Test app.Test "" reclaimprobe reclaimprobe >/dev/null
ST=zroot/Capabilities/Data/Test/reclaimprobe/persistent/state
NS=zroot/Capabilities/Data/Test/reclaimprobe/persistent
build_image ax
boot rw || exit 1

echo "=== boot #1: reclaimprobe abandons a txn on 'abandonme' ==="
V "sleep 8; zfs list -H -o name -r $NS 2>/dev/null | grep -E '/v[0-9a-f]{16,}\$' | sort" 30
ABID=$(sh "$RIG/vcmd.sh" "$(OBS $ST); cat /mnt/obs/abandoned-id 2>/dev/null; echo; $(DROP_OBS $ST)" 30 \
    | tr -d '\r' | grep -oE 'v[0-9a-f]{16,}' | head -1)
echo "boot#1 abandoned txn id = ${ABID:-<none>}"
V "n=\$(zfs list -H -o name -r $NS 2>/dev/null | grep -cE '/v[0-9a-f]{16,}\$'); \
   echo BOOT1_ABANDONED_CLONES=\$n; \
   [ \"\$n\" -ge 1 ] && echo ABANDONED_CLONE_PRESENT_PASS || echo NO_ABANDONED_CLONE_FAIL; \
   s=\$(zfs list -t snapshot -H -o name -r $NS 2>/dev/null | grep -cE '@v[0-9a-f]{16,}\$'); \
   echo BOOT1_BASE_SNAPSHOTS=\$s; \
   [ \"\$s\" -ge 1 ] && echo ABANDONED_SNAPSHOT_PRESENT_PASS || echo NO_ABANDONED_SNAPSHOT" 30

echo "=== reboot: the daemon's boot-scoped sweep must reap the abandoned clone ==="
V "sync; sync; sleep 3" 15
boot rw || exit 1
V "sleep 10; echo CLONES:; zfs list -H -o name -r $NS 2>/dev/null | grep -E '/v[0-9a-f]{16,}\$' | sort; \
   echo SNAPSHOTS:; zfs list -t snapshot -H -o name -r $NS 2>/dev/null | grep -E '@v[0-9a-f]{16,}\$' | sort" 30

echo "=== verdict: boot-#1 clone AND its base snapshot must be gone ==="
if [ -z "$ABID" ]; then
	echo "COULD_NOT_CAPTURE_ABANDONED_ID_FAIL"
else
	V "zfs list -H -o name -r $NS 2>/dev/null | grep -qE '/${ABID}\$' \
	   && echo SWEEP_MISSED_CLONE_FAIL:${ABID} || echo SWEEP_REAPED_CLONE_PASS:${ABID}; \
	   zfs list -t snapshot -H -o name -r $NS 2>/dev/null | grep -qE '@${ABID}\$' \
	   && echo SWEEP_MISSED_SNAPSHOT_FAIL:${ABID} || echo SWEEP_REAPED_SNAPSHOT_PASS:${ABID}" 30
fi
echo DONE
