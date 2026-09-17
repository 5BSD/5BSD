#!/bin/sh
# logd container-model reclaim proof: a real bundle (Test.cap/logprobe) emits to
# system.Log, so logd maps its owner->bundle "Test" in owners.meta; removing the
# bundle + rebooting must make logd's reconcile seal that owner and drop it from
# the map, while live bundles' entries survive.  owners.meta lives in the logd
# store dataset (anon-mounted, fd-only), so observe it via a snapshot+clone.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
DS=zroot/Capabilities/Data/Log/logd/persistent/state
# Observe owners.meta through a snapshot+clone of the (anon-mounted) logd store.
OBS="zfs destroy -r zroot/obsclone 2>/dev/null; zfs destroy $DS@obs 2>/dev/null; zfs snapshot $DS@obs && zfs clone -o mountpoint=/mnt/obs $DS@obs zroot/obsclone && echo OWNERS_STRINGS=\$(strings /mnt/obs/owners.meta 2>/dev/null | tr '\\n' ' ') && echo TEST_IN_MAP=\$(grep -a -o Test /mnt/obs/owners.meta 2>/dev/null | wc -l | tr -d ' ')"

echo "==> stage Test.cap (logprobe) into guestroot/Capabilities/System"
TC=$R/Capabilities/System/Test.cap
chmod -R u+w "$TC" 2>/dev/null; rm -rf "$TC"
mkdir -p "$TC/Units/logprobe.unit/bin"
cp "$PROBES/logprobe" "$TC/Units/logprobe.unit/bin/logprobe"; chmod 0555 "$TC/Units/logprobe.unit/bin/logprobe"
cat > "$TC/Bundle.ucl" <<-'EOF'
	schema = "org.5bsd.capability-bundle";
	schema_version = 1;
	bundle_id = "app.Test";
	version = "1.0.0";
	sequence = 1;
	author = "5BSD";
	publisher = "org.5bsd.base";
	units = ["logprobe"];
	EOF
cat > "$TC/Units/logprobe.unit/Unit.ucl" <<-'EOF'
	activation { boot = true; }
	program = "logprobe";
	restart = "never";
	user = "root";
	EOF
# Scrub any earlier Test.cap METALOG lines (stale reclaimprobe paths), re-add.
chmod u+w "$R/METALOG"
grep -v 'Capabilities/System/Test.cap' "$R/METALOG" > "$R/METALOG.new" && mv "$R/METALOG.new" "$R/METALOG"
cat >> "$R/METALOG" <<EOF
./Capabilities/System/Test.cap type=dir uname=root gname=wheel mode=0755
./Capabilities/System/Test.cap/Bundle.ucl type=file uname=root gname=wheel mode=0644
./Capabilities/System/Test.cap/Units type=dir uname=root gname=wheel mode=0755
./Capabilities/System/Test.cap/Units/logprobe.unit type=dir uname=root gname=wheel mode=0755
./Capabilities/System/Test.cap/Units/logprobe.unit/Unit.ucl type=file uname=root gname=wheel mode=0644
./Capabilities/System/Test.cap/Units/logprobe.unit/bin type=dir uname=root gname=wheel mode=0755
./Capabilities/System/Test.cap/Units/logprobe.unit/bin/logprobe type=file uname=root gname=wheel mode=0555
EOF

echo "==> build image from scratch"
build_image lr

echo "==> boot #1 (rw): install -> logprobe emits -> owner mapped to Test"
boot rw || exit 1
V "ps ax | grep logprobe | grep -v grep | head -1; echo ---" 12
V "sleep 5; $OBS" 30
echo "==> uninstall: remove Test.cap + reload"
V "chmod -R u+w /Capabilities/System/Test.cap; rm -rf /Capabilities/System/Test.cap; switchboardctl reload 2>&1 | tail -1" 25
V "ps ax | grep logprobe | grep -v grep || echo 'logprobe UNLOADED'" 12
V "sync; sync; sleep 8; ls /Capabilities/System | grep -q Test.cap && echo TESTCAP_STILL_ON_DISK || echo TESTCAP_REMOVED_ON_DISK" 20

echo "==> boot #2 (external restart, rw): logd BOOT reconcile seals Test's owner"
boot rw || exit 1
V "sleep 3; $OBS" 30
echo "=== verdicts ==="
V "zfs destroy -r zroot/obsclone 2>/dev/null; zfs snapshot $DS@v 2>/dev/null; zfs clone -o mountpoint=/mnt/v $DS@v zroot/vclone 2>/dev/null; if [ -f /mnt/v/owners.meta ]; then if grep -a -q Test /mnt/v/owners.meta; then echo LOGOWNER_STILL_MAPPED_FAIL; else echo LOGOWNER_REAPED_PASS; fi; else echo OWNERS_META_MISSING; fi; if [ -s /mnt/v/owners.meta ]; then echo LIVE_OWNERS_PRESERVED_PASS; else echo LIVE_OWNERS_EMPTY_NOTE; fi" 30
echo DONE
