#!/bin/sh
# Container-model TXN ORIGIN-BINDING (cross-claim commit) proof.
#
# A staging transaction opened on claim A must not be committable over a
# DIFFERENT claim B in the same container: doing so would rename A's promoted
# clone over B and destroy B's data.  bsdfilesystem binds every txn to the
# claim it was begun on (the "bsdfilesystem:txnbase" user property stamped at
# TXN_BEGIN) and rejects a mismatched TXN_COMMIT with EINVAL *before* any side
# effect, so the target claim stays mounted and intact.
#
# reclaimprobe drives it: it TXN_BEGINs on "lifecycle", then attempts a
# TXN_COMMIT of that txn over "state" (a different claim).  It records the
# outcome INTO the observable "state" container:
#   xclaim-rejected  -> the commit was refused and "state" survived (PASS)
#   xclaim-ACCEPTED  -> the origin binding failed; "state" was violated (FAIL)
# A rejected commit is side-effect-free, so the probe can still write into
# "state" afterward -- the successful write is itself part of the proof.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
scrub_stage
stage_bundle System Test app.Test "" reclaimprobe reclaimprobe >/dev/null
DS=zroot/Capabilities/Data/Test/reclaimprobe/persistent/state
build_image xc
boot rw || exit 1

echo "=== boot: reclaimprobe runs the cross-claim commit attempt ==="
V "sleep 8; zfs list -H -o name $DS 2>&1" 30
V "$(OBS $DS); echo XCLAIM=\$(cat /mnt/obs/xclaim 2>/dev/null); $(DROP_OBS $DS)" 30

echo "=== verdict ==="
V "$(OBS $DS); r=\$(cat /mnt/obs/xclaim 2>/dev/null); \
   [ \"\$r\" = xclaim-rejected ] && echo CROSSCLAIM_REJECTED_PASS || echo CROSSCLAIM_FAIL:\$r; \
   zfs list $DS >/dev/null 2>&1 && echo STATE_SURVIVED_PASS || echo STATE_DESTROYED_FAIL; \
   $(DROP_OBS $DS)" 30
echo DONE
