#!/bin/sh
# The TIMER path of the reconcile, live (no reboot): with short cadences
# (tzfsd reclaim_interval=20, LOGD_RECLAIM_INTERVAL=15, CRYPTO_RECLAIM_INTERVAL=20)
#  1. a removal undone within one interval is NEVER reaped (seen gone once):
#     Test.cap removed and re-added 5s later keeps its container;
#  2. a confirmed removal of Test (container), A (logprobe -> log owner) and
#     B (cryptoprobe -> kernel key) is reaped by the timer passes: still there
#     after one interval (grace), gone after two.
# The staged config/manifests are restored afterwards.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
CFG=$R/Capabilities/Config/tzfsd.ucl; LU=$R/Capabilities/System/Log.cap/Units/logd.unit/Unit.ucl; CU=$R/Capabilities/System/Crypto.cap/Units/localcrypto.unit/Unit.ucl
for f in "$CFG" "$LU" "$CU"; do cp "$f" "$WORK/$(basename "$f").$(echo "$f" | md5 | cut -c1-6).orig"; done
restore() { for f in "$CFG" "$LU" "$CU"; do cp "$WORK/$(basename "$f").$(echo "$f" | md5 | cut -c1-6).orig" "$f"; done; }
trap restore EXIT
chmod u+w "$CFG" "$LU" "$CU" "$R/METALOG"
grep -q '^reclaim_interval' "$CFG" || printf '\nreclaim_interval = 20;\n' >> "$CFG"
grep -q 'RECLAIM_INTERVAL' "$LU" || printf 'environment { LOGD_RECLAIM_INTERVAL = "15"; }\n' >> "$LU"
grep -q 'RECLAIM_INTERVAL' "$CU" || printf 'environment { CRYPTO_RECLAIM_INTERVAL = "20"; }\n' >> "$CU"
for f in ./Capabilities/Config/tzfsd.ucl ./Capabilities/System/Log.cap/Units/logd.unit/Unit.ucl ./Capabilities/System/Crypto.cap/Units/localcrypto.unit/Unit.ucl; do n=$(wc -c < "$R/${f#./}" | tr -d ' '); sed -i '' "s#\($f type=file [^ ]* [^ ]* mode=[0-7]* size=\)[0-9]*#\1$n#" "$R/METALOG"; done
echo "==> stage Test (reclaimprobe), A (logprobe), B (cryptoprobe), /root/keyowners, /root/Test.cap.bak"
scrub_stage
stage_bundle System Test app.Test "" reclaimprobe reclaimprobe >/dev/null
stage_bundle System A app.A "" logprobe logprobe >/dev/null
stage_bundle System B app.B "" cryptoprobe cryptoprobe >/dev/null
cp -R "$R/Capabilities/System/Test.cap" "$R/root/Test.cap.bak"; meta_bundle ./root/Test.cap.bak reclaimprobe >> "$R/METALOG"
grep -v '^\./root/keyowners ' "$R/METALOG" > "$R/METALOG.new" && mv "$R/METALOG.new" "$R/METALOG"
rm -f "$R/root/keyowners"; cp "$PROBES/keyowners" "$R/root/keyowners"; chmod 0555 "$R/root/keyowners"; echo "./root/keyowners type=file uname=root gname=wheel mode=0555" >> "$R/METALOG"
build_image tr
boot rw || exit 1
LOGDS=zroot/Capabilities/Data/Log/logd/persistent/state
V "sleep 15; zfs list -H -o name zroot/Capabilities/Data/Test zroot/Capabilities/Data/A zroot/Capabilities/Data/B 2>&1 | tr '\n' ' '; echo; /root/keyowners | tr '\n' ' '; echo; $(OBS $LOGDS); strings /mnt/obs/owners.meta 2>/dev/null | grep -E '^(A|B|Test)\$' | tr '\n' ' ' | sed 's/^/LOG_OWNERS=/'; echo; $(DROP_OBS $LOGDS)" 40
V "/root/keyowners | grep -q '^OWNER=B\$' && echo KEY_B_HELD || echo KEY_B_MISSING_FAIL; grep -a 'reclaim:' /var/log/messages | tail -2 | cut -c1-140" 20
echo "==> 1. transient removal (undone within one 20s interval) must NOT be reaped"
V "chmod -R u+w /Capabilities/System/Test.cap; rm -rf /Capabilities/System/Test.cap; sleep 5; cp -Rp /root/Test.cap.bak /Capabilities/System/Test.cap; sleep 50; zfs list zroot/Capabilities/Data/Test/reclaimprobe/persistent/state >/dev/null 2>&1 && echo TRANSIENT_NOT_REAPED_PASS || echo TRANSIENT_REAPED_FAIL; pgrep -f '[/ ]reclaimprobe( |\$)' >/dev/null && echo PROBE_BACK || echo PROBE_NOT_BACK_FAIL; grep -a 'reclaim:' /var/log/messages | tail -2 | cut -c1-140" 90
echo "==> 2. confirmed removal of Test, A, B: grace after one interval, reaped by the timer after two"
V "for b in Test A B; do chmod -R u+w /Capabilities/System/\$b.cap; rm -rf /Capabilities/System/\$b.cap; done; sleep 8; zfs list zroot/Capabilities/Data/Test >/dev/null 2>&1 && echo GRACE_CONTAINER_KEPT_PASS || echo GRACE_CONTAINER_REAPED_EARLY_FAIL; /root/keyowners | grep -q '^OWNER=B\$' && echo GRACE_KEY_KEPT_PASS || echo GRACE_KEY_DROPPED_EARLY_FAIL" 40
V "sleep 50; grep -a 'reclaim:' /var/log/messages | grep -a 'timer' | tail -3 | cut -c1-150; zfs list zroot/Capabilities/Data/Test >/dev/null 2>&1 && echo TIMER_CONTAINER_NOT_REAPED_FAIL || echo TIMER_CONTAINER_REAPED_PASS; /root/keyowners | grep -q '^OWNER=B\$' && echo TIMER_KEY_NOT_DROPPED_FAIL || echo TIMER_KEY_DROPPED_PASS; grep -aq 'reclaim: timer pass reaped' /var/log/messages && echo TIMER_PASS_LOGGED_PASS || echo TIMER_PASS_NOT_LOGGED_FAIL" 90
V "$(OBS $LOGDS); strings /mnt/obs/owners.meta 2>/dev/null | grep -qE '^A\$' && echo TIMER_LOG_OWNER_STILL_MAPPED_FAIL || echo TIMER_LOG_OWNER_SEALED_PASS; strings /mnt/obs/owners.meta 2>/dev/null | grep -E '^(A|B|Test|Log)\$' | tr '\n' ' '; echo; $(DROP_OBS $LOGDS); zfs list -H -o name -r zroot/Capabilities/Data | grep -vE 'Data/Log|Data\$' | tr '\n' ' '; echo" 40
echo DONE
