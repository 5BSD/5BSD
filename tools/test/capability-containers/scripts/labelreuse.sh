#!/bin/sh
# Label reuse (doc "Edge cases"): reinstalling the same bundle within the grace
# (remove + re-add before any reap) INHERITS its container; reinstalling after
# a removal was confirmed and reaped starts FRESH.  reclaimprobe appends one
# "launch" line per start to persistent/state/marker, and claims a cache
# sub-container (cache/scratch) that must be reaped with the unit.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
DS=zroot/Capabilities/Data/Test/reclaimprobe/persistent/state
LINES="zfs destroy -r zroot/obsclone 2>/dev/null; zfs destroy $DS@obs 2>/dev/null; zfs snapshot $DS@obs && zfs clone -o mountpoint=/mnt/obs $DS@obs zroot/obsclone && echo MARKER_LINES=\$(wc -l < /mnt/obs/marker | tr -d ' ')"
echo "==> stage Test.cap (reclaimprobe) in System/ and a pristine copy at /root/Test.cap.bak"
TC=$R/Capabilities/System/Test.cap; chmod -R u+w "$TC" 2>/dev/null; rm -rf "$TC"; mkdir -p "$TC/Units/reclaimprobe.unit/bin"
cp "$PROBES/reclaimprobe" "$TC/Units/reclaimprobe.unit/bin/reclaimprobe"; chmod 0555 "$TC/Units/reclaimprobe.unit/bin/reclaimprobe"
printf 'activation { boot = true; }\nprogram = "reclaimprobe";\nrestart = "never";\nuser = "root";\n' > "$TC/Units/reclaimprobe.unit/Unit.ucl"
printf 'schema = "org.5bsd.capability-bundle";\nschema_version = 1;\nbundle_id = "app.Test";\nversion = "1.0.0";\nsequence = 1;\nauthor = "5BSD";\npublisher = "org.5bsd.base";\nunits = ["reclaimprobe"];\n' > "$TC/Bundle.ucl"
rm -rf $R/root/Test.cap.bak; cp -R "$TC" $R/root/Test.cap.bak
chmod u+w "$R/METALOG"; grep -vE 'Capabilities/System/(Test|A|B|C)\.cap|^\./root/Test\.cap\.bak' "$R/METALOG" > "$R/METALOG.new" && mv "$R/METALOG.new" "$R/METALOG"
for n in A B C; do chmod -R u+w $R/Capabilities/System/$n.cap 2>/dev/null; rm -rf $R/Capabilities/System/$n.cap; done
for base in ./Capabilities/System/Test.cap ./root/Test.cap.bak; do cat >> "$R/METALOG" <<EOF
$base type=dir uname=root gname=wheel mode=0755
$base/Bundle.ucl type=file uname=root gname=wheel mode=0644
$base/Units type=dir uname=root gname=wheel mode=0755
$base/Units/reclaimprobe.unit type=dir uname=root gname=wheel mode=0755
$base/Units/reclaimprobe.unit/Unit.ucl type=file uname=root gname=wheel mode=0644
$base/Units/reclaimprobe.unit/bin type=dir uname=root gname=wheel mode=0755
$base/Units/reclaimprobe.unit/bin/reclaimprobe type=file uname=root gname=wheel mode=0555
EOF
done
echo "==> build image"; build_image lu
echo "==> boot #1: first launch -> 1 line; cache sub-container claimed"
boot rw || exit 1
V "sleep 4; $LINES; zfs list zroot/Capabilities/Data/Test/reclaimprobe/cache/scratch >/dev/null 2>&1 && echo CACHE_CLAIMED_PASS || echo CACHE_CLAIM_MISSING_FAIL" 30
echo "==> reinstall within the grace: rm + re-add (no reap in between) -> inherited (2 lines)"
V "chmod -R u+w /Capabilities/System/Test.cap; rm -rf /Capabilities/System/Test.cap; sleep 5; cp -Rp /root/Test.cap.bak /Capabilities/System/Test.cap; sleep 8; ps ax -o command | grep -c '[r]eclaimprobe' | sed 's/^/PROBE_UP_AFTER_REINSTALL=/'" 40
V "sleep 3; $LINES" 30
V "n=\$(wc -l < /mnt/obs/marker | tr -d ' '); [ \"\$n\" = 2 ] && echo LABEL_REUSE_INHERITED_PASS || echo LABEL_REUSE_NOT_INHERITED_FAIL" 15
echo "==> remove; leave an operator CLONE of the container's snapshot outside it + a plain snapshot"
V "chmod -R u+w /Capabilities/System/Test.cap; rm -rf /Capabilities/System/Test.cap; sleep 6; zfs snapshot $DS@keep; zfs list -t snapshot -H -o name -r zroot/Capabilities/Data/Test; sync; sync; sleep 8" 30
echo "==> boot #2: the clone pins the snapshot -> reap fails SOFT (EBUSY, hinted, retried), container intact"
boot rw || exit 1
V "sleep 3; grep -a 'reclaim:' /var/log/messages | tail -3" 15
V "if zfs list zroot/Capabilities/Data/Test >/dev/null 2>&1 && grep -aq 'pinned by a clone outside the container' /var/log/messages; then echo CLONE_BLOCKS_REAP_SOFT_PASS; else echo CLONE_BLOCK_FAIL; fi" 15
echo "==> drop the clone (snapshot @obs and @keep stay): the next boot pass must sweep the snapshots and reap"
V "zfs destroy -r zroot/obsclone; zfs list -t snapshot -H -o name -r zroot/Capabilities/Data/Test; sync; sync; sleep 8" 30
boot rw || exit 1
V "sleep 3; grep -a 'reclaim:' /var/log/messages | tail -3" 15
V "zfs list zroot/Capabilities/Data/Test >/dev/null 2>&1 && echo REAP_BEFORE_REINSTALL_MISSING_FAIL || echo REAPED_BEFORE_REINSTALL_PASS; zfs list zroot/Capabilities/Data/Test/reclaimprobe/cache/scratch >/dev/null 2>&1 && echo CACHE_SURVIVED_REAP_FAIL || echo CACHE_RECLAIMED_PASS; grep -aq 'reclaim: destroyed orphan persistent namespace Test' /var/log/messages && echo SNAPSHOTS_SWEPT_PASS || echo SNAPSHOT_SWEEP_FAIL" 15
echo "==> reinstall SLOWLY (dir + Bundle.ucl + empty Units first, units 6s later, below the watched level) -> fresh (1 line)"
V "mkdir /Capabilities/System/Test.cap; cp -p /root/Test.cap.bak/Bundle.ucl /Capabilities/System/Test.cap/; mkdir /Capabilities/System/Test.cap/Units; sleep 6; grep -a 'bundle_registry\|registry:' /var/log/messages | tail -4" 30
V "grep -aq \"quarantined SYSTEM bundle '/Capabilities/System/Test.cap'\" /var/log/messages && echo PARTIAL_QUARANTINED_PASS || echo PARTIAL_NOT_QUARANTINED_FAIL; grep -aq 'rescan failed' /var/log/messages && echo PARTIAL_FAILED_WHOLE_SCAN_FAIL || echo PARTIAL_SCAN_ISOLATED_PASS" 15
V "date; time cp -Rp /root/Test.cap.bak/Units/reclaimprobe.unit /Capabilities/System/Test.cap/Units/; date; ls -la /Capabilities/System/Test.cap/Units/reclaimprobe.unit /Capabilities/System/Test.cap/Units/reclaimprobe.unit/bin | cut -c1-100" 30
# NB: "bundle_registry: loaded ..." is LOG_INFO and never reaches /var/log/messages
# (*.notice); admission is asserted on the unit actually running (the marker
# read below proves it wrote its launch line) and on the retries stopping.
V "i=0; while ! pgrep -f '[/ ]reclaimprobe( |\$)' >/dev/null && [ \$i -lt 60 ]; do i=\$((i+1)); sleep 0.5; done; date; echo ADMIT_WAIT=\$i; pgrep -f '[/ ]reclaimprobe( |\$)' >/dev/null && echo PARTIAL_ADMITTED_BY_RETRY_PASS || echo PARTIAL_NEVER_LOADED_FAIL" 60
V "sleep 6; grep -a 'registry' /var/log/messages | tail -3 | cut -c1-160; grep -aq 'retry 8/8' /var/log/messages && echo RETRIES_RAN_TO_BUDGET_FAIL || echo RETRIES_STOPPED_ON_ADMISSION_PASS" 20
V "$LINES" 30
V "n=\$(wc -l < /mnt/obs/marker | tr -d ' '); [ \"\$n\" = 1 ] && echo LABEL_REUSE_FRESH_PASS || echo LABEL_REUSE_STALE_FAIL; zfs list zroot/Capabilities/Data/Test/reclaimprobe/cache/scratch >/dev/null 2>&1 && echo CACHE_CLAIMED_AGAIN_PASS || echo CACHE_AFTER_FRESH_MISSING_FAIL" 20
V "zfs destroy -r zroot/obsclone 2>/dev/null; zfs destroy $DS@obs 2>/dev/null; sync; sync; sleep 3" 15
echo DONE
