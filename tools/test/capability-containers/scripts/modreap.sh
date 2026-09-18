#!/bin/sh
# Container-model proof: sysextd as a reconcile client.  Kernel modules loaded
# on a bundle's behalf are attributed to the bundle (from the stamped
# container) and unloaded once the bundle is gone -- but only the modules
# sysextd itself loaded, only when no other bundle still claims them, and a
# busy module is left loaded and retried.  A reboot resets the map (modules do
# not survive one).
#
#   M2 (boot):           geom_nop if_edsc nullfs
#   M3 (boot):           if_disc
#   M1 (installed late): geom_nop (found loaded: M2's load, so sysextd's)
#                        zfs      (found loaded: the loader's, never sysextd's)
#
# All three are System bundles: only SYSTEM-domain units may reach
# system.SystemExtension (an Apps unit gets ENOENT), and on a plane nobody
# may kldload by hand, so the "found already loaded, not ours" case is the
# loader-loaded zfs module.  The map keys bundles by container name (the
# .cap basename).  The shipped allow-list is replaced for the run (restored
# afterwards) and sysextd's timer/grace is shortened to 15s through its unit
# environment.  METALOG size fields of the edited files are dropped: makefs
# truncates a file to the size the spec names.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
scrub_stage
SU=$R/Capabilities/System/SystemExtension.cap/Units/sysextd.unit/Unit.ucl
SC=$R/Capabilities/Config/sysextd.ucl
rm -f "$WORK/sysextd.Unit.ucl.orig" "$WORK/sysextd.conf.orig"
cp "$SU" "$WORK/sysextd.Unit.ucl.orig"; cp "$SC" "$WORK/sysextd.conf.orig"
trap 'chmod u+w "$SU" "$SC"; cp "$WORK/sysextd.Unit.ucl.orig" "$SU"; cp "$WORK/sysextd.conf.orig" "$SC"' EXIT
chmod u+w "$SU" "$SC" "$R/METALOG"
grep -q '^environment' "$SU" || printf 'environment { SYSEXTD_RECLAIM_INTERVAL = "15"; }\n' >> "$SU"
sed -i '' 's#^\(\./Capabilities/System/SystemExtension.cap/Units/sysextd.unit/Unit.ucl type=file.*\) size=[0-9]*#\1#' "$R/METALOG"
cat > "$SC" <<'EOF'
# modreap proof: the shipped set plus harmless test modules.
allowed_extensions = ["cryptodev", "vhid", "zfs", "linux64",
    "geom_nop", "if_edsc", "if_disc", "nullfs"];
EOF
sed -i '' 's#^\(\./Capabilities/Config/sysextd.ucl type=file.*\) size=[0-9]*#\1#' "$R/METALOG"

echo "==> stage M2, M3 (System) and /root/M1.cap (installed later)"
stage_bundle System M2 app.M2 "" modprobe modprobe 'protect = [];' 'arguments = ["geom_nop", "if_edsc", "nullfs"];' >/dev/null
stage_bundle System M3 app.M3 "" modprobe modprobe 'protect = [];' 'arguments = ["if_disc"];' >/dev/null
L=$(stage_bundle System M1 app.M1 "" modprobe modprobe 'protect = [];' 'arguments = ["geom_nop", "zfs"];'); mkdir -p "$R/root"; rm -rf "$R/root/M1.cap"; mv "$L" "$R/root/M1.cap"
grep -v "Capabilities/System/M1.cap" "$R/METALOG" > "$R/METALOG.new" && mv "$R/METALOG.new" "$R/METALOG"; meta_bundle ./root/M1.cap modprobe >> "$R/METALOG"
build_image mr
boot rw || exit 1
MAP=/var/run/sysextd/modules.meta
D2=zroot/Capabilities/Data/M2/modprobe/persistent/state
D3=zroot/Capabilities/Data/M3/modprobe/persistent/state
D1=zroot/Capabilities/Data/M1/modprobe/persistent/state

echo "=== boot units loaded their modules; the map attributes them ==="
V "sleep 20; for m in geom_nop if_edsc nullfs if_disc; do kldstat -q -n \$m && echo LOADED=\$m || echo NOT_LOADED=\$m; done; echo '--- map:'; cat $MAP" 40
V "$(OBS $D2); cat /mnt/obs/result; $(DROP_OBS $D2); $(OBS $D3); cat /mnt/obs/result; $(DROP_OBS $D3)" 60
V "kldstat -q -n geom_nop && kldstat -q -n if_edsc && kldstat -q -n nullfs && kldstat -q -n if_disc && echo ENSURED_ALL_PASS || echo ENSURE_MISSING_FAIL; grep -q '^geom_nop M2 1' $MAP && grep -q '^if_edsc M2 1' $MAP && grep -q '^nullfs M2 1' $MAP && grep -q '^if_disc M3 1' $MAP && grep -q '^epoch ' $MAP && echo MAP_ATTRIBUTED_PASS || echo MAP_ATTRIBUTION_FAIL" 20

echo "=== M1 installed late: geom_nop found loaded (sysextd's, through M2), zfs found loaded (the loader's, not sysextd's) ==="
V "cp -Rp /root/M1.cap /Capabilities/System/; sleep 20; $(OBS $D1); cat /mnt/obs/result; $(DROP_OBS $D1); echo '--- map:'; cat $MAP" 60
V "grep -q '^geom_nop M1 1' $MAP && grep -q '^zfs M1 0' $MAP && echo LATE_ATTRIBUTED_PASS || echo LATE_ATTRIBUTION_FAIL" 20

echo "=== M1 uninstalled: geom_nop stays (M2 still claims it), zfs stays (not sysextd's), M1's attributions go ==="
V "chmod -R u+w /Capabilities/System/M1.cap; rm -rf /Capabilities/System/M1.cap; sleep 50; grep -a 'sysextd.*reclaim' /var/log/messages | tail -5 | cut -c1-170; echo '--- map:'; cat $MAP" 70
V "kldstat -q -n geom_nop && echo M1_SHARED_KEPT_PASS || echo M1_SHARED_UNLOADED_FAIL; grep -aq 'geom_nop (bundle M1): still claimed by another bundle' /var/log/messages && echo M1_SHARED_LOGGED_PASS || echo M1_SHARED_NOT_LOGGED_FAIL; kldstat -q -n zfs && grep -aq 'zfs (bundle M1): found already loaded, not sysextd' /var/log/messages && echo M1_FOREIGN_KEPT_PASS || echo M1_FOREIGN_FAIL; grep -q ' M1 ' $MAP && echo M1_ATTRIBUTION_STUCK_FAIL || echo M1_ATTRIBUTION_DROPPED_PASS" 20

echo "=== M2 uninstalled while nullfs is busy (a mount): geom_nop and if_edsc unload, nullfs is kept and retried ==="
V "mkdir -p /mnt/nb && mount -t nullfs /tmp /mnt/nb && mount | grep -c '/mnt/nb' | sed 's/^/NULLFS_MOUNTS=/'; chmod -R u+w /Capabilities/System/M2.cap; rm -rf /Capabilities/System/M2.cap; sleep 50; grep -a 'sysextd.*reclaim' /var/log/messages | tail -5 | cut -c1-170; echo '--- map:'; cat $MAP" 80
V "kldstat -q -n if_edsc || kldstat -q -n geom_nop && echo M2_UNSHARED_STILL_LOADED_FAIL || echo M2_UNSHARED_UNLOADED_PASS; kldstat -q -n nullfs && grep -q '^nullfs M2 1' $MAP && echo M2_BUSY_KEPT_PASS || echo M2_BUSY_LOST_FAIL; grep -aq 'nullfs (bundle M2): Device busy; left loaded' /var/log/messages && echo M2_BUSY_LOGGED_PASS || echo M2_BUSY_NOT_LOGGED_FAIL" 20
echo "=== the mount goes away: the next pass unloads nullfs ==="
V "umount /mnt/nb; sleep 40; grep -a 'sysextd.*reclaim' /var/log/messages | tail -3 | cut -c1-170; echo '--- map:'; cat $MAP" 60
V "kldstat -q -n nullfs && echo M2_BUSY_STILL_LOADED_FAIL || echo M2_BUSY_RETRIED_PASS; grep -q ' M2 ' $MAP && echo M2_ATTRIBUTION_STUCK_FAIL || echo M2_ATTRIBUTION_DROPPED_PASS" 20

echo "=== reboot: modules are gone with the boot; the map is reset (/var/run is emptied at boot; a surviving map is reset by its epoch); M3 re-requests if_disc ==="
V "sync; sync; sleep 5" 15
boot rw || exit 1
V "sleep 20; grep -a 'previous boot' /var/log/messages | tail -1 | cut -c1-150; echo '--- map:'; cat $MAP; kldstat -q -n if_disc && echo M3_RELOADED_PASS || echo M3_NOT_RELOADED_FAIL; grep -q '^epoch ' $MAP && ! grep -q ' M[12] ' $MAP && echo MAP_RESET_ON_REBOOT_PASS || echo MAP_NOT_RESET_FAIL; grep -q '^if_disc M3 1' $MAP && echo M3_REATTRIBUTED_PASS || echo M3_REATTRIBUTION_FAIL" 40
echo DONE
