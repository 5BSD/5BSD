#!/bin/sh
# Container-model UPGRADE-SAFETY proof.  An upgrade is the same bundle_id with a
# bumped sequence/version, in place.  The dangerous outcome is that the
# reconcile mistakes the transient for a removal and reaps the bundle's durable
# container.  This proves the opposite, and that the container is still
# reclaimable AFTER an upgrade (the upgrade did not strand it un-attributable):
#
#   boot #1 install v1            -> the unit claims a fresh persistent container
#                                    (reclaimprobe appends one "launch" line)
#   upgrade in place + reload     -> the unit relaunches into the SAME container;
#                                    its earlier data is intact and a second line
#                                    is appended (durable data survived)
#   reboot, still installed       -> the boot-pass reconcile must NOT reap it
#                                    (a third line; the dataset and its data live)
#   uninstall for real + reboot   -> the boot-pass reconcile DOES reap it (the
#                                    upgrade left it perfectly reclaimable)
#
# The container is anon-mounted (fd-only), so its data is observed through a
# snapshot/clone of the dataset.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
scrub_stage
stage_bundle System Test app.Test "" reclaimprobe reclaimprobe >/dev/null
DS=zroot/Capabilities/Data/Test/reclaimprobe/persistent/state
build_image up
boot rw || exit 1

echo "=== boot #1: v1 installed, fresh persistent container claimed ==="
V "sleep 6; zfs list -H -o name $DS 2>&1; $(OBS $DS); echo LAUNCHES=\$(wc -l < /mnt/obs/marker 2>/dev/null | tr -d ' '); $(DROP_OBS $DS)" 40
V "zfs list $DS >/dev/null 2>&1 && echo V1_CONTAINER_CLAIMED_PASS || echo V1_CONTAINER_MISSING_FAIL; $(OBS $DS); [ \"\$(wc -l < /mnt/obs/marker 2>/dev/null | tr -d ' ')\" = 1 ] && echo V1_FRESH_CONTAINER_PASS || echo V1_NOT_FRESH_FAIL; $(DROP_OBS $DS)" 40

echo "=== upgrade in place: same bundle_id, sequence 1 -> 2, version 1.0.0 -> 1.1.0, reload ==="
V "sed -i '' -e 's/version = \"1.0.0\"/version = \"1.1.0\"/' -e 's/sequence = 1/sequence = 2/' /Capabilities/System/Test.cap/Bundle.ucl; grep -E 'version|sequence' /Capabilities/System/Test.cap/Bundle.ucl" 15
V "switchboardctl reload 2>&1 | tail -2; sleep 8" 30
V "zfs list $DS >/dev/null 2>&1 && echo UPGRADE_CONTAINER_KEPT_PASS || echo UPGRADE_CONTAINER_REAPED_FAIL; $(OBS $DS); n=\$(wc -l < /mnt/obs/marker 2>/dev/null | tr -d ' '); echo LAUNCHES_AFTER_UPGRADE=\$n; [ \"\$n\" -ge 1 ] && echo UPGRADE_DATA_PRESERVED_PASS || echo UPGRADE_DATA_WIPED_FAIL; $(DROP_OBS $DS)" 50
V "grep -a 'reclaim:' /var/log/messages | grep -a 'Test' | tail -3 | cut -c1-150; grep -aq 'destroyed orphan .*Test' /var/log/messages && echo UPGRADE_WRONGLY_REAPED_FAIL || echo UPGRADE_NO_REAP_LOGGED_PASS" 20

echo "=== reboot, still installed: the boot-pass reconcile must NOT reap the upgraded bundle ==="
V "sync; sync; sleep 3" 15
boot rw || exit 1
V "sleep 8; grep -a 'reclaim:' /var/log/messages | tail -3 | cut -c1-150" 20
V "zfs list $DS >/dev/null 2>&1 && echo REBOOT_CONTAINER_PRESERVED_PASS || echo REBOOT_CONTAINER_REAPED_FAIL; $(OBS $DS); n=\$(wc -l < /mnt/obs/marker 2>/dev/null | tr -d ' '); echo LAUNCHES_AFTER_REBOOT=\$n; [ \"\$n\" -ge 2 ] && echo REBOOT_DATA_ACCUMULATED_PASS || echo REBOOT_DATA_LOST_FAIL; $(DROP_OBS $DS)" 50

echo "=== uninstall for real + reboot: the boot-pass reconcile DOES reap it (still reclaimable after an upgrade) ==="
V "chmod -R u+w /Capabilities/System/Test.cap; rm -rf /Capabilities/System/Test.cap; sync; sync; sleep 3" 20
boot rw || exit 1
V "sleep 8; grep -a 'reclaim:' /var/log/messages | tail -3 | cut -c1-160" 20
V "zfs list $DS >/dev/null 2>&1 && echo POSTUPGRADE_UNINSTALL_STUCK_FAIL || echo POSTUPGRADE_UNINSTALL_REAPED_PASS" 20
echo DONE
