#!/bin/sh
# Jail reclaim (bsdnamespace as a reconcile client): two bundles, J1 and J2, each
# run a unit that enters a PERSISTENT jail (wj_<hash>) -- the kind that by
# design outlives its unit.  With a short cadence (BSDNAMESPACE_RECLAIM_INTERVAL=15)
# uninstalling J1 must have bsdnamespace's TIMER pass remove J1's jail (attributed
# through bsdnamespace's owner map) while J2's survives; a reboot then shows the
# map pruning an entry whose jail is gone (jails never survive a reboot).
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
WU=$R/Capabilities/System/Namespace.cap/Units/bsdnamespace.unit/Unit.ucl
rm -f "$WORK/bsdnamespace.Unit.ucl.orig"; cp "$WU" "$WORK/bsdnamespace.Unit.ucl.orig"; trap 'cp "$WORK/bsdnamespace.Unit.ucl.orig" "$WU"' EXIT
chmod u+w "$WU" "$R/METALOG"
grep -q '^environment' "$WU" || printf 'environment { BSDNAMESPACE_RECLAIM_INTERVAL = "15"; }\n' >> "$WU"
sed -i '' 's#^\(\./Capabilities/System/Namespace.cap/Units/bsdnamespace.unit/Unit.ucl type=file.*\) size=[0-9]*#\1#' "$R/METALOG"	# makefs truncates to the spec size: drop it
echo "==> stage J1, J2 (jailprobe each, persistent jails rooted at /)"
scrub_stage
grep -vE 'Capabilities/System/J[12]\.cap' "$R/METALOG" > "$R/METALOG.new" && mv "$R/METALOG.new" "$R/METALOG"
for n in J1 J2; do chmod -R u+w "$R/Capabilities/System/$n.cap" 2>/dev/null; rm -rf "$R/Capabilities/System/$n.cap"; done
stage_bundle System J1 app.J1 "" jailprobe jailprobe >/dev/null
stage_bundle System J2 app.J2 "" jailprobe jailprobe >/dev/null
build_image jr
boot rw || exit 1
V "sleep 15; jls -N | awk 'NR>1{print \$1}' | grep -c '^wj_' | sed 's/^/WJ_JAILS=/'; grep -a 'reclaim' /var/log/messages | grep -ai 'jail' | tail -2 | cut -c1-150" 40
V "[ \$(jls -N | awk 'NR>1{print \$1}' | grep -c '^wj_') = 2 ] && echo TWO_PERSISTENT_JAILS_PASS || echo JAILS_MISSING_FAIL" 20
WD=zroot/Capabilities/Data/Namespace/bsdnamespace/persistent/owners
V "$(OBS $WD); echo '--- owner map:'; cat /mnt/obs/jails.meta; [ \$(grep -c ' J[12]\$' /mnt/obs/jails.meta) = 2 ] && echo OWNER_MAP_PASS || echo OWNER_MAP_FAIL; $(DROP_OBS $WD)" 30
echo "==> uninstall J1: the unit unloads, its persistent jail stays (grace), the timer pass removes it"
V "chmod -R u+w /Capabilities/System/J1.cap; rm -rf /Capabilities/System/J1.cap; sleep 8; jls -N | awk 'NR>1{print \$1}' | grep -c '^wj_' | sed 's/^/WJ_JAILS_IN_GRACE=/'; [ \$(jls -N | awk 'NR>1{print \$1}' | grep -c '^wj_') = 2 ] && echo GRACE_JAIL_KEPT_PASS || echo GRACE_JAIL_GONE_EARLY_FAIL" 40
V "sleep 40; grep -a 'reclaim' /var/log/messages | grep -ai 'jail' | tail -3 | cut -c1-150; jls -N | awk 'NR>1{print \$1}' | grep -c '^wj_' | sed 's/^/WJ_JAILS_AFTER_TIMER=/'" 60
V "[ \$(jls -N | awk 'NR>1{print \$1}' | grep -c '^wj_') = 1 ] && echo ORPHAN_JAIL_REAPED_PASS || echo ORPHAN_JAIL_COUNT_FAIL; grep -aq 'reclaim: removed 1 orphan jail(s) of bundle J1' /var/log/messages && echo J1_JAIL_REMOVED_PASS || echo J1_REMOVAL_NOT_LOGGED_FAIL; grep -aq 'of bundle J2' /var/log/messages && echo LIVE_JAIL_REMOVED_FAIL || echo LIVE_JAIL_KEPT_PASS" 30
V "$(OBS $WD); [ \$(grep -c ' J1\$' /mnt/obs/jails.meta) = 0 ] && [ \$(grep -c ' J2\$' /mnt/obs/jails.meta) = 1 ] && echo OWNER_MAP_PRUNED_PASS || echo OWNER_MAP_STALE_FAIL; cat /mnt/obs/jails.meta; $(DROP_OBS $WD); sync; sync; sleep 8" 40
echo "==> reboot: J2's jail is re-created by its unit; a stale entry (J2's old jail name, same label -> same name) stays valid"
boot rw || exit 1
V "sleep 15; jls -N | awk 'NR>1{print \$1}' | grep -c '^wj_' | sed 's/^/WJ_JAILS_AFTER_BOOT=/'; [ \$(jls -N | awk 'NR>1{print \$1}' | grep -c '^wj_') = 1 ] && echo REBOOT_LIVE_JAIL_PASS || echo REBOOT_JAIL_COUNT_FAIL; grep -a 'reclaim' /var/log/messages | grep -ai 'jail' | tail -2 | cut -c1-150" 40
echo DONE
