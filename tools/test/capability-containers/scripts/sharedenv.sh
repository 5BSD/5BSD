#!/bin/sh
# Shared environment e2e (docs "Storage and delivery": shared env descriptor).
#  Env.cap: units envwriter (claims shared "env" rw, writes settings) and
#  envreader (service_storage_open_env: read-only view) run TOGETHER:
#   - both hold the same store at once -> ONE anonymous mount (kernel shares it);
#   - the reader sees the writer's content; every mutation is ENOTCAPABLE;
#   - killing the writer leaves the mount (reader still ticks);
#   - killing the reader (last anchor) unmounts it.
#  Test.cap: reclaimprobe claims persistent + cache on ONE connection and must
#   still write to persistent afterwards (one anchor per claim, not per conn).
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
meta() { # base prog...
  base=$1; shift
  echo "$base type=dir uname=root gname=wheel mode=0755"; echo "$base/Bundle.ucl type=file uname=root gname=wheel mode=0644"; echo "$base/Units type=dir uname=root gname=wheel mode=0755"
  for u in "$@"; do echo "$base/Units/$u.unit type=dir uname=root gname=wheel mode=0755"; echo "$base/Units/$u.unit/Unit.ucl type=file uname=root gname=wheel mode=0644"; echo "$base/Units/$u.unit/bin type=dir uname=root gname=wheel mode=0755"; echo "$base/Units/$u.unit/bin/$u type=file uname=root gname=wheel mode=0555"; done
}
echo "==> stage Env.cap (envwriter + envreader) and Test.cap (reclaimprobe)"
chmod u+w "$R/METALOG"; grep -vE 'Capabilities/System/(Test|A|B|C|Env)\.cap|^\./root/Test\.cap\.bak' "$R/METALOG" > "$R/METALOG.new" && mv "$R/METALOG.new" "$R/METALOG"
for n in Test A B C Env; do chmod -R u+w $R/Capabilities/System/$n.cap 2>/dev/null; rm -rf $R/Capabilities/System/$n.cap; done; rm -rf $R/root/Test.cap.bak
E=$R/Capabilities/System/Env.cap; mkdir -p $E/Units/envwriter.unit/bin $E/Units/envreader.unit/bin
cp $PROBES/envprobe $E/Units/envwriter.unit/bin/envwriter; cp $PROBES/envprobe $E/Units/envreader.unit/bin/envreader; chmod 0555 $E/Units/*/bin/*
printf 'schema = "org.5bsd.capability-bundle";\nschema_version = 1;\nbundle_id = "app.Env";\nversion = "1.0.0";\nsequence = 1;\nauthor = "5BSD";\npublisher = "org.5bsd.base";\nunits = ["envwriter", "envreader"];\n' > $E/Bundle.ucl
printf 'activation { boot = true; }\nprogram = "envwriter";\narguments = ["writer"];\nrestart = "never";\nprotect = [];\nuser = "root";\n' > $E/Units/envwriter.unit/Unit.ucl
printf 'activation { boot = true; }\nprogram = "envreader";\narguments = ["reader"];\nrestart = "always";\nprotect = [];\nuser = "root";\n' > $E/Units/envreader.unit/Unit.ucl
T=$R/Capabilities/System/Test.cap; mkdir -p $T/Units/reclaimprobe.unit/bin; cp $PROBES/reclaimprobe $T/Units/reclaimprobe.unit/bin/reclaimprobe; chmod 0555 $T/Units/reclaimprobe.unit/bin/reclaimprobe
printf 'schema = "org.5bsd.capability-bundle";\nschema_version = 1;\nbundle_id = "app.Test";\nversion = "1.0.0";\nsequence = 1;\nauthor = "5BSD";\npublisher = "org.5bsd.base";\nunits = ["reclaimprobe"];\n' > $T/Bundle.ucl
printf 'activation { boot = true; }\nprogram = "reclaimprobe";\nrestart = "never";\nuser = "root";\n' > $T/Units/reclaimprobe.unit/Unit.ucl
{ meta ./Capabilities/System/Env.cap envwriter envreader; meta ./Capabilities/System/Test.cap reclaimprobe; } >> $R/METALOG
echo "==> build image"; build_image se
echo "==> boot"
boot rw || exit 1
V "sleep 12; uname -v | cut -c1-80" 30
# Results live in the units' own stores (units in capmode cannot syslog);
# read them through a snapshot clone.  RES <dataset> prints the clone dir.
RES='zfs destroy -r zroot/obsclone 2>/dev/null; zfs destroy $D@obs 2>/dev/null; zfs snapshot $D@obs && zfs clone -o mountpoint=/mnt/obs $D@obs zroot/obsclone'
RD=zroot/Capabilities/Data/Env/envreader/persistent/state
TD=zroot/Capabilities/Data/Test/reclaimprobe/persistent/state
echo "=== verdicts: sharing + read-only ==="
V "D=$RD; $RES; echo '--- reader result:'; cat /mnt/obs/result" 30
V "grep -q 'ENV_READ=COLOR=blue' /mnt/obs/result && echo SHARED_ENV_READ_PASS || echo SHARED_ENV_READ_FAIL; grep -q '^RO_ENFORCED' /mnt/obs/result && echo SHARED_ENV_RO_PASS || echo SHARED_ENV_RO_FAIL; grep -q 'RO_VIOLATED\|ENV_CLAIM_FAILED\|NEVER_APPEARED\|TICK_FAIL' /mnt/obs/result && echo READER_ERROR_FAIL || true" 20
V "D=$TD; $RES; [ -e /mnt/obs/after-cache ] && [ -e /mnt/obs/marker ] && echo MULTI_CLAIM_ANCHOR_PASS || echo MULTI_CLAIM_ANCHOR_FAIL; ls /mnt/obs" 30
V "pgrep -f '[/ ]envwriter( |\$)' >/dev/null && pgrep -f '[/ ]envreader( |\$)' >/dev/null && echo BOTH_UNITS_UP_PASS || echo UNITS_DOWN_FAIL; mount | grep -c 'Data/Env/shared/persistent/env' | sed 's/^/ENV_MOUNTS=/'; mount | grep -c 'Data/Test/reclaimprobe' | sed 's/^/TEST_MOUNTS=/'" 20
V "[ \"\$(mount | grep -c 'Data/Env/shared/persistent/env')\" = 1 ] && echo SHARED_MOUNT_ONCE_PASS || echo SHARED_MOUNT_COUNT_FAIL; [ \"\$(mount | grep -c 'Data/Test/reclaimprobe')\" = 2 ] && echo TWO_CLAIMS_TWO_MOUNTS_PASS || echo TEST_MOUNT_COUNT_FAIL" 20
echo "=== writer exits: the reader's mount must survive (not the last anchor) ==="
V "pkill -f '[/ ]envwriter( |\$)'; sleep 5; pgrep -f '[/ ]envwriter( |\$)' >/dev/null && echo WRITER_STILL_UP_FAIL || echo WRITER_GONE; D=$RD; $RES; n0=\$(grep -c 'ENV_TICK=COLOR=blue' /mnt/obs/result); sleep 8; $RES; n1=\$(grep -c 'ENV_TICK=COLOR=blue' /mnt/obs/result); echo TICKS_BEFORE=\$n0 TICKS_AFTER=\$n1; [ \$n1 -gt \$n0 ] && echo MOUNT_SURVIVES_WRITER_EXIT_PASS || echo MOUNT_LOST_ON_WRITER_EXIT_FAIL; grep -q ENV_TICK_FAIL /mnt/obs/result && echo TICK_FAIL_SEEN_FAIL; [ \"\$(mount | grep -c 'Data/Env/shared/persistent/env')\" = 1 ] && echo STILL_MOUNTED_PASS || echo UNMOUNTED_EARLY_FAIL" 50
echo "=== crash-restart churn: the reader (restart=always) is killed 3x; each relaunch re-claims while the previous teardown may still be running ==="
V "c0=\$(grep -c ENV_CLAIMED /mnt/obs/result); k=0; for i in 1 2 3; do j=0; while ! pgrep -f '[/ ]envreader( |\$)' >/dev/null && [ \$j -lt 40 ]; do j=\$((j+1)); sleep 0.5; done; pgrep -f '[/ ]envreader( |\$)' >/dev/null && { pkill -f '[/ ]envreader( |\$)'; k=\$((k+1)); }; sleep 0.3; done; echo KILLS=\$k; sleep 10; D=$RD; $RES; c1=\$(grep -c ENV_CLAIMED /mnt/obs/result); echo CLAIMS_BEFORE=\$c0 CLAIMS_AFTER=\$c1; [ \$c1 -ge \$((c0+3)) ] && echo CHURN_RECLAIMS_PASS || echo CHURN_RECLAIM_FAIL; grep -q 'ENV_CLAIM_FAILED' /mnt/obs/result && echo CHURN_CLAIM_ERROR_FAIL; pgrep -f '[/ ]envreader( |\$)' >/dev/null && echo READER_BACK_PASS || echo READER_DOWN_FAIL; [ \"\$(mount | grep -c 'Data/Env/shared/persistent/env')\" = 1 ] && echo CHURN_ONE_MOUNT_PASS || echo CHURN_MOUNT_COUNT_FAIL; grep -a 'busy retr' /var/log/messages | tail -2 | cut -c1-120; tail -5 /mnt/obs/result" 90
echo "=== last holder goes (bundle removed -> reader unloaded) -> unmounted ==="
V "zfs destroy -r zroot/obsclone 2>/dev/null; zfs destroy $RD@obs 2>/dev/null; zfs destroy $TD@obs 2>/dev/null; chmod -R u+w /Capabilities/System/Env.cap; rm -rf /Capabilities/System/Env.cap; sleep 8; pgrep -f '[/ ]envreader( |\$)' >/dev/null && echo READER_STILL_UP_FAIL || echo READER_UNLOADED; [ \"\$(mount | grep -c 'Data/Env/shared/persistent/env')\" = 0 ] && echo LAST_ANCHOR_UNMOUNTS_PASS || echo STILL_MOUNTED_AFTER_LAST_FAIL; zfs list -H -o name zroot/Capabilities/Data/Env/shared/persistent/env; zfs list -t snapshot -H -o name -r zroot/Capabilities/Data | wc -l" 40
echo "=== reclaim across reboot: Env removed -> container (incl. shared env) reaped ==="
V "sync; sync; sleep 8" 20
boot rw || exit 1
V "sleep 3; grep -a 'reclaim:' /var/log/messages | tail -3 | cut -c1-160; zfs list zroot/Capabilities/Data/Env >/dev/null 2>&1 && echo ENV_CONTAINER_PRESENT_FAIL || echo ENV_CONTAINER_REAPED_PASS; zfs list zroot/Capabilities/Data/Test >/dev/null 2>&1 && echo TEST_LIVE_PRESERVED_PASS || echo TEST_LIVE_MISSING_FAIL" 20
echo DONE
