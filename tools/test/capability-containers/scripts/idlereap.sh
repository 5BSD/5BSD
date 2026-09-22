#!/bin/sh
# Container-model IDLE STAGING-REAP proof (no reboot).
#
# The boot sweep only reclaims abandoned TXN staging clones at startup, so on a
# long-uptime system one would pin space until the next reboot.  The reconcile
# loop's idle reap closes that: each settled timer pass it destroys stamped
# staging clones older than staging_idle_grace, while a clone held by a LIVE txn
# survives because it is still mounted (destroy fails EBUSY).
#
# reclaimprobe abandons a txn on "abandonme" at boot (TXN_BEGIN, write, exit with
# no COMMIT/ABORT).  With a short grace + reconcile interval, the idle pass must
# reap that clone AND its base snapshot WITHOUT any reboot.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
scrub_stage
stage_bundle System Test app.Test "" reclaimprobe reclaimprobe >/dev/null
ST=zroot/Capabilities/Data/Test/reclaimprobe/persistent/state
NS=zroot/Capabilities/Data/Test/reclaimprobe/persistent

# Short cadence so the idle reap fires within the test: grace 5s, timer 10s.
CFG=$R/Capabilities/Config/bsdfilesystem.ucl
if ! grep -q '^staging_idle_grace' "$CFG"; then
	printf '\nreclaim_interval = 10;\nstaging_idle_grace = 5;\n' >> "$CFG"
fi
# The recorded METALOG size no longer matches the edited config; drop it so
# makefs uses the actual file (mirrors the sysctl.conf handling in the builder).
chmod u+w "$R/METALOG"
sed -i '' 's#^\(\./Capabilities/Config/bsdfilesystem.ucl type=file [^ ]* [^ ]* mode=[0-7]*\) size=[0-9]*#\1#' \
    "$R/METALOG"

build_image il
boot rw || exit 1

echo "=== boot: reclaimprobe abandons a txn; clone present before the idle pass ==="
V "sleep 6; echo CLONES:; zfs list -H -o name -r $NS 2>/dev/null | grep -E '/v[0-9a-f]{16,}\$'; \
   n=\$(zfs list -H -o name -r $NS 2>/dev/null | grep -cE '/v[0-9a-f]{16,}\$'); \
   [ \"\$n\" -ge 1 ] && echo ABANDONED_CLONE_PRESENT_PASS || echo NO_CLONE_FAIL" 30
ABID=$(sh "$RIG/vcmd.sh" "$(OBS $ST); cat /mnt/obs/abandoned-id 2>/dev/null; echo; $(DROP_OBS $ST)" 30 \
    | tr -d '\r' | grep -oE 'v[0-9a-f]{16,}' | head -1)
echo "abandoned txn id = ${ABID:-<none>}"

echo "=== while the client is LIVE, its clone is mounted: aged past the grace, the ==="
echo "=== idle reap must NOT reclaim it (destroy fails EBUSY on the live mount) ==="
V "sleep 25; zfs list -H -o name -r $NS 2>/dev/null | grep -qE '/v[0-9a-f]{16,}\$' \
   && echo LIVE_TXN_PROTECTED_PASS || echo LIVE_TXN_WRONGLY_REAPED_FAIL" 40

echo "=== the client VANISHES (kill, no reboot): its connection closes and the ==="
echo "=== txn clone unmounts, so the idle reap can now reclaim it ==="
V "pkill -f reclaimprobe; sleep 3; pgrep -f reclaimprobe >/dev/null && echo PROBE_STILL_UP || echo PROBE_GONE" 20

echo "=== wait out grace + one timer pass (NO reboot); idle reap must reclaim it ==="
V "sleep 40; echo CLONES:; zfs list -H -o name -r $NS 2>/dev/null | grep -E '/v[0-9a-f]{16,}\$'; \
   echo SNAPSHOTS:; zfs list -t snapshot -H -o name -r $NS 2>/dev/null | grep -E '@v[0-9a-f]{16,}\$'" 60

echo "=== verdict: the abandoned clone AND its snapshot are gone, no reboot ==="
if [ -z "$ABID" ]; then
	echo "COULD_NOT_CAPTURE_ABANDONED_ID_FAIL"
else
	V "zfs list -H -o name -r $NS 2>/dev/null | grep -qE '/${ABID}\$' \
	   && echo IDLE_REAP_MISSED_CLONE_FAIL:${ABID} || echo IDLE_REAP_CLONE_PASS:${ABID}; \
	   zfs list -t snapshot -H -o name -r $NS 2>/dev/null | grep -qE '@${ABID}\$' \
	   && echo IDLE_REAP_MISSED_SNAPSHOT_FAIL:${ABID} || echo IDLE_REAP_SNAPSHOT_PASS:${ABID}; \
	   zfs list $ST >/dev/null 2>&1 && echo STATE_CLAIM_SURVIVED_PASS || echo STATE_CLAIM_LOST_FAIL" 30
fi
echo DONE
