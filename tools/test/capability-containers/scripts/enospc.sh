#!/bin/sh
# TXN_BEGIN clone-failure cleanup proof (fault injection).
#
# Fix under test: when TXN_BEGIN's base snapshot succeeds but the clone fails
# (e.g. ENOSPC), the handler must destroy the orphan snapshot -- with no clone,
# no later staging sweep would ever find it, and the caller got no id to ABORT.
#
# A fault-injection build of bsdfilesystem (BSDFILESYSTEM_FAULT_TXN_CLONE in the
# unit environment) forces exactly that sequence for every TXN_BEGIN.
# enospcprobe TXN_BEGINs once on "faultclaim", expects the failure, and records
# it.  The proof: faultclaim exists, the txn failed, and NO snapshot is left
# behind (the cleanup dropped it).
#
# Requires the fault daemon binary staged by the caller into FAULTBIN.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
FAULTBIN=${FAULTBIN:?set FAULTBIN to the fault-injection BSDFilesystem binary}
scrub_stage
stage_bundle System Fault app.Fault "" enospcprobe enospcprobe >/dev/null
FC=zroot/Capabilities/Data/Fault/enospcprobe/persistent/faultclaim

# Swap in the fault daemon and turn the fault on via the unit environment.
FD=$R/Capabilities/System/Filesystem.cap/Units/bsdfilesystem.unit
chmod u+w "$FD/bin/BSDFilesystem"; cp "$FAULTBIN" "$FD/bin/BSDFilesystem"
chmod 0555 "$FD/bin/BSDFilesystem"
chmod u+w "$FD/Unit.ucl"
grep -q 'BSDFILESYSTEM_FAULT_TXN_CLONE' "$FD/Unit.ucl" || \
    printf '\nenvironment { BSDFILESYSTEM_FAULT_TXN_CLONE = "1"; }\n' >> "$FD/Unit.ucl"
# The edited Unit.ucl no longer matches its recorded METALOG size; drop it.
chmod u+w "$R/METALOG"
sed -i '' 's#^\(\./Capabilities/System/Filesystem.cap/Units/bsdfilesystem.unit/Unit.ucl type=file [^ ]* [^ ]* mode=[0-7]*\) size=[0-9]*#\1#' \
    "$R/METALOG"

build_image es
boot rw || exit 1

echo "=== boot: enospcprobe TXN_BEGINs on faultclaim; the fault fails the clone ==="
V "sleep 8; zfs list -H -o name $FC 2>&1" 30
V "$(OBS $FC); ls /mnt/obs 2>/dev/null | tr '\n' ' '; echo; \
   [ -e /mnt/obs/txn-failed ] && echo TXN_FAILED_AS_EXPECTED_PASS || echo TXN_NOT_FAILED_FAIL; \
   $(DROP_OBS $FC)" 30

echo "=== verdict: the base snapshot must NOT have leaked ==="
V "n=\$(zfs list -t snapshot -H -o name -r $FC 2>/dev/null | grep -cE '@v[0-9a-f]{16,}\$'); \
   echo FAULTCLAIM_SNAPSHOTS=\$n; \
   [ \"\$n\" -eq 0 ] && echo NO_LEAKED_SNAPSHOT_PASS || echo LEAKED_SNAPSHOT_FAIL; \
   zfs list $FC >/dev/null 2>&1 && echo CLAIM_INTACT_PASS || echo CLAIM_LOST_FAIL" 30
echo DONE
