#!/bin/sh
# Container-model install-folder watch, end to end on a from-scratch image:
# Test.cap (reclaimprobe + logprobe) ships in System/.  At runtime we CREATE
# Apps/ (pkg would), MOVE the bundle there with NO reload -> switchboard's watch
# must unload it from System/ and load it from Apps/; then rm -rf it -> unload;
# reboot -> tzfsd reaps Data/Test and logd seals its owner.  Also checks the
# Run/live marker follows the unit's life.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
scrub_stage
DS=zroot/Capabilities/Data/Log/logd/persistent/state
OBS="zfs destroy -r zroot/obsclone 2>/dev/null; zfs destroy $DS@obs 2>/dev/null; zfs snapshot $DS@obs && zfs clone -o mountpoint=/mnt/obs $DS@obs zroot/obsclone && echo TEST_IN_MAP=\$(grep -a -o Test /mnt/obs/owners.meta 2>/dev/null | wc -l | tr -d ' ')"

echo "==> stage Test.cap (reclaimprobe + logprobe) into guestroot/Capabilities/System"
TC=$R/Capabilities/System/Test.cap
chmod -R u+w "$TC" 2>/dev/null; rm -rf "$TC"
for u in reclaimprobe logprobe; do mkdir -p "$TC/Units/$u.unit/bin"; cp "$PROBES/$u" "$TC/Units/$u.unit/bin/$u"; chmod 0555 "$TC/Units/$u.unit/bin/$u"
  printf 'activation { boot = true; }\nprogram = "%s";\nrestart = "never";\nuser = "root";\n' "$u" > "$TC/Units/$u.unit/Unit.ucl"; done
cat > "$TC/Bundle.ucl" <<-'EOF'
	schema = "org.5bsd.capability-bundle";
	schema_version = 1;
	bundle_id = "app.Test";
	version = "1.0.0";
	sequence = 1;
	author = "5BSD";
	publisher = "org.5bsd.base";
	units = ["reclaimprobe", "logprobe"];
	EOF
chmod u+w "$R/METALOG"; grep -v 'Capabilities/System/Test.cap' "$R/METALOG" > "$R/METALOG.new" && mv "$R/METALOG.new" "$R/METALOG"
{ echo "./Capabilities/System/Test.cap type=dir uname=root gname=wheel mode=0755"
  echo "./Capabilities/System/Test.cap/Bundle.ucl type=file uname=root gname=wheel mode=0644"
  echo "./Capabilities/System/Test.cap/Units type=dir uname=root gname=wheel mode=0755"
  for u in reclaimprobe logprobe; do
    echo "./Capabilities/System/Test.cap/Units/$u.unit type=dir uname=root gname=wheel mode=0755"
    echo "./Capabilities/System/Test.cap/Units/$u.unit/Unit.ucl type=file uname=root gname=wheel mode=0644"
    echo "./Capabilities/System/Test.cap/Units/$u.unit/bin type=dir uname=root gname=wheel mode=0755"
    echo "./Capabilities/System/Test.cap/Units/$u.unit/bin/$u type=file uname=root gname=wheel mode=0555"; done; } >> "$R/METALOG"

echo "==> build image from scratch"
build_image fw

echo "==> boot #1 (rw): both units up from System/, watch armed"
boot rw || exit 1
V "grep -a 'registry: watching' /var/log/messages | tail -2" 12
V "ps ax -o command | grep -E 'reclaimprobe|logprobe' | grep -v grep | wc -l | tr -d ' ' | sed 's/^/UNITS_UP=/'" 12
V "ls /Capabilities/Run/live | tr '\n' ' ' | sed 's/^/RUNLIVE=/'; echo" 12
V "zfs list -H -o name zroot/Capabilities/Data/Test 2>&1 | sed 's/^/DATA=/'" 12

echo "==> MOVE System/Test.cap -> Apps/Test.cap (no reload): watch must unload+reload it"
V "mkdir -m 0755 /Capabilities/Apps 2>/dev/null; sleep 4; mv /Capabilities/System/Test.cap /Capabilities/Apps/Test.cap; echo moved" 15
V "sleep 6; grep -a 'registry:' /var/log/messages | tail -4" 12
V "switchboardctl status 2>&1 | grep -E 'reclaimprobe|logprobe' | sed 's/^/STATUS: /'" 15
V "ps ax -o command | grep -E 'reclaimprobe|logprobe' | grep -v grep | wc -l | tr -d ' ' | sed 's/^/UNITS_UP_AFTER_MOVE=/'" 12
V "ls /Capabilities/Run/live | grep -c '^Test\$' | sed 's/^/RUNLIVE_TEST_AFTER_MOVE=/'" 12

echo "==> REMOVE Apps/Test.cap (no reload): watch must unload"
V "rm -rf /Capabilities/Apps/Test.cap; sleep 6; grep -a 'reload: stopping removed' /var/log/messages | tail -2" 15
V "ps ax -o command | grep -E 'reclaimprobe|logprobe' | grep -v grep | wc -l | tr -d ' ' | sed 's/^/UNITS_UP_AFTER_RM=/'" 12
V "ls /Capabilities/Run/live | grep -c '^Test\$' | sed 's/^/RUNLIVE_TEST_AFTER_RM=/'" 12
V "sync; sync; sleep 8; ls /Capabilities/Apps /Capabilities/System | grep -c Test.cap | sed 's/^/TESTCAP_LEFT_ON_DISK=/'" 20

echo "==> boot #2: tzfsd reaps Data/Test, logd seals the owner"
boot rw || exit 1
V "grep -a 'reclaim:' /var/log/messages | tail -4" 12
V "sleep 3; $OBS" 30
echo "=== verdicts ==="
V "if zfs list zroot/Capabilities/Data/Test >/dev/null 2>&1; then echo TEST_CONTAINER_PRESENT_FAIL; else echo TEST_CONTAINER_REAPED_PASS; fi" 15
V "zfs destroy -r zroot/obsclone 2>/dev/null; zfs snapshot $DS@v 2>/dev/null; zfs clone -o mountpoint=/mnt/v $DS@v zroot/vclone 2>/dev/null; if grep -a -q Test /mnt/v/owners.meta 2>/dev/null; then echo LOGOWNER_STILL_MAPPED_FAIL; else echo LOGOWNER_REAPED_PASS; fi" 30
echo DONE
