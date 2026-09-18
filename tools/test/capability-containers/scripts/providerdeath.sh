#!/bin/sh
# Provider death: system.Filesystem (tzfsd) is killed under running units.
#  - the stores stay mounted (tzfsd's per-connection workers are plain
#    children and outlive it; the kernel keeps the mount while anchors exist):
#    the reader keeps reading its shared env;
#  - switchboard relaunches tzfsd (restart=on-failure) and a bundle installed
#    afterwards claims its container from the new instance;
#  - no tzfsd processes leak (the old reconcile child must not linger).
# The shipped tzfsd manifest shields SIGKILL; the test drops that shield in
# the staged copy (restored afterwards) -- the subject is what happens to the
# units, not the shield.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
TU=$R/Capabilities/System/Filesystem.cap/Units/tzfsd.unit/Unit.ucl
rm -f "$WORK/tzfsd.Unit.ucl.orig"; cp "$TU" "$WORK/tzfsd.Unit.ucl.orig"; trap 'cp "$WORK/tzfsd.Unit.ucl.orig" "$TU"' EXIT
# The shipped list spans lines: drop from "protect = [" through its "];".
chmod u+w "$TU"; awk 'BEGIN{skip=0} /^protect = \[/{skip=1; print "protect = [];"; if ($0 ~ /\];/) skip=0; next} skip{ if ($0 ~ /\];/) skip=0; next } {print}' "$TU" > "$TU.new" && mv "$TU.new" "$TU"
grep -q '^protect = \[\];' "$TU" && ! grep -q '"sigkill"' "$TU" || { echo "could not unshield tzfsd"; exit 2; }
n=$(wc -c < "$TU" | tr -d ' '); chmod u+w "$R/METALOG"; sed -i '' "s#\(\./Capabilities/System/Filesystem.cap/Units/tzfsd.unit/Unit.ucl type=file [^ ]* [^ ]* mode=[0-7]* size=\)[0-9]*#\1$n#" "$R/METALOG"
echo "==> stage Env.cap (writer + reader), Test.cap, and /root/Late.cap (installed later)"
scrub_stage
E=$(stage_bundle System Env app.Env "" envwriter envprobe 'protect = [];' 'arguments = ["writer"];')
mkdir -p "$E/Units/envreader.unit/bin"; cp "$PROBES/envprobe" "$E/Units/envreader.unit/bin/envreader"; chmod 0555 "$E/Units/envreader.unit/bin/envreader"
sed -i '' 's/units = \["envwriter"\];/units = ["envwriter", "envreader"];/' "$E/Bundle.ucl"
printf 'activation { boot = true; }\nprogram = "envreader";\narguments = ["reader"];\nrestart = "always";\nprotect = [];\nuser = "root";\n' > "$E/Units/envreader.unit/Unit.ucl"
meta_bundle ./Capabilities/System/Env.cap envreader | grep envreader >> "$R/METALOG"
stage_bundle System Test app.Test "" reclaimprobe reclaimprobe >/dev/null
L=$(stage_bundle Apps Late app.Late "" reclaimprobe reclaimprobe); mkdir -p "$R/root"; rm -rf "$R/root/Late.cap"; mv "$L" "$R/root/Late.cap"
grep -v "Capabilities/Apps/Late.cap" "$R/METALOG" > "$R/METALOG.new" && mv "$R/METALOG.new" "$R/METALOG"; meta_bundle ./root/Late.cap reclaimprobe >> "$R/METALOG"
build_image pd
boot rw || exit 1
RD=zroot/Capabilities/Data/Env/envreader/persistent/state
V "sleep 12; pgrep -f '[/ ]envreader( |\$)' >/dev/null && echo READER_UP; pgrep -xc tzfsd | sed 's/^/TZFSD_PROCS_BEFORE=/'; pgrep -x tzfsd | sort -n | tr '\n' ' '; echo; mount | grep -c 'Data/Env/shared' | sed 's/^/ENV_MOUNTS=/'" 30
V "zfs list -H -o name -r zroot/Capabilities/Data/Env 2>&1 | tr '\n' ' '; echo; grep -a 'envreader\|envwriter\|Env.cap' /var/log/messages | tail -6 | cut -c1-150; ls /Capabilities/Run/live | tr '\n' ' '; echo" 30
V "zfs list $RD >/dev/null 2>&1 && echo READER_STATE_PASS || echo READER_STATE_MISSING_FAIL; grep -a 'REQUEST.*env\|open_cache\|envprobe' /var/log/messages | tail -6 | cut -c1-150" 20
V "$(OBS $RD); echo '--- reader result head:'; head -5 /mnt/obs/result" 30
V "$(OBS $RD); c0=\$(grep -c ENV_TICK /mnt/obs/result); echo TICKS0=\$c0" 30
echo "==> kill -9 tzfsd (the provider), then watch the units and the relaunch"
V "p=\$(pgrep -x tzfsd | sort -n | head -1); ps -o ppid= -p \$p | sed 's/^/TZFSD_PPID=/'; kill -9 \$p && echo KILLED_\$p || echo KILL_DENIED_FAIL; sleep 8; q=\$(pgrep -x tzfsd | sort -n | head -1); echo NEW_TZFSD=\$q; [ -n \"\$q\" ] && [ \"\$q\" != \"\$p\" ] && echo TZFSD_RELAUNCHED_PASS || echo TZFSD_NOT_RELAUNCHED_FAIL; grep -a 'tzfsd\|Filesystem' /var/log/messages | tail -4 | cut -c1-150" 40
V "sleep 8; $(OBS $RD); c1=\$(grep -c ENV_TICK /mnt/obs/result); echo TICKS1=\$c1; grep -q 'ENV_TICK_FAIL' /mnt/obs/result && echo TICK_FAIL_SEEN_FAIL; [ \$c1 -gt 0 ] && echo READER_TICKING; mount | grep -c 'Data/Env/shared' | sed 's/^/ENV_MOUNTS_AFTER=/'; [ \"\$(mount | grep -c 'Data/Env/shared')\" = 1 ] && echo MOUNT_SURVIVES_PROVIDER_DEATH_PASS || echo MOUNT_LOST_ON_PROVIDER_DEATH_FAIL" 40
V "$(OBS $RD); c2=\$(grep -c ENV_TICK /mnt/obs/result); echo TICKS2=\$c2; c1=\$(grep -c ENV_TICK /mnt/obs/result); sleep 7; $(OBS $RD); c3=\$(grep -c ENV_TICK /mnt/obs/result); echo TICKS3=\$c3; [ \$c3 -gt \$c2 ] && echo READER_STILL_READING_PASS || echo READER_STALLED_FAIL" 40
echo "==> a unit that was ALIVE across the death keeps claiming (its library times out the dead session within 10s and reopens)"
V "n0=\$(zfs list -H -o name -r zroot/Capabilities/Data/Env/envwriter/cache 2>/dev/null | grep -c '/cache/t[0-9]'); sleep 26; n1=\$(zfs list -H -o name -r zroot/Capabilities/Data/Env/envwriter/cache 2>/dev/null | grep -c '/cache/t[0-9]'); echo NEW_CLAIMS_BEFORE=\$n0 NEW_CLAIMS_AFTER=\$n1; WD=zroot/Capabilities/Data/Env/envwriter/persistent/state; zfs destroy -r zroot/obsclone 2>/dev/null; zfs destroy \$WD@obs 2>/dev/null; zfs snapshot \$WD@obs && zfs clone -o mountpoint=/mnt/obs \$WD@obs zroot/obsclone && echo '--- writer claims:' && tail -8 /mnt/obs/result; [ \$n1 -gt \$n0 ] && echo LIVE_UNIT_RECLAIMS_AFTER_RESPAWN_PASS || echo LIVE_UNIT_CLAIMS_STUCK_FAIL" 90
echo "==> a bundle installed AFTER the relaunch claims from the new tzfsd"
V "mkdir -p /Capabilities/Apps; cp -Rp /root/Late.cap /Capabilities/Apps/Late.cap; sleep 12; pgrep -f '[/ ]reclaimprobe( |\$)' | wc -l | tr -d ' ' | sed 's/^/PROBES_UP=/'; zfs list zroot/Capabilities/Data/Late/reclaimprobe/persistent/state >/dev/null 2>&1 && echo LATE_CLAIM_AFTER_RESPAWN_PASS || echo LATE_CLAIM_FAIL" 40
V "sleep 3; pgrep -xc tzfsd | sed 's/^/TZFSD_PROCS_AFTER=/'; ps ax -o pid,ppid,command | grep '[t]zfsd' | cut -c1-100" 20
V "$(DROP_OBS $RD); sync; sync; sleep 3" 15
echo DONE
