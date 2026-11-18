#!/bin/sh
# The scratch disk: vm-provider.sh attaches a blank disk with the serial
# kyua-scratch (and preloads zfs) exactly when a suite selects
# usr.sbin/capsule/storage_test:disk_import_and_binding, or when
# SCRATCH_DISK=1 asks for it; the guest names it in the case's input.  Runs
# the actual blocks of vm-provider.sh.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

sed -n '/^scratch_disk=\${SCRATCH_DISK:-auto}$/,/^fi$/p' "$root/vm-provider.sh" > "$work/sd.sh"
grep -q 'zfs_load' "$work/sd.sh"
pick() {
	env -i PATH="$PATH" suites="$1" dq_loader= ${2:+SCRATCH_DISK=$2} \
	    sh -c ". '$work/sd.sh'; printf '%s %s\n' \"\$scratch_disk\" \"\$dq_loader\""
}
for s in "usr.sbin" "usr.sbin/" "usr.sbin/capsule" "sys/kern usr.sbin/capsule" \
    "usr.sbin/capsule/storage_test" \
    "usr.sbin/capsule/storage_test:disk_import_and_binding"; do
	[ "$(pick "$s")" = '1 zfs_load="YES"' ] ||
	    { echo "FAIL: no scratch disk for \"$s\": $(pick "$s")"; exit 1; }
done
for s in "sys/kern" "usr.sbin/capsule/capsule_init_test" \
    "usr.sbin/capsule/storage_test:no_ambient_anchor" "usr.sbin/capsulectl" \
    "usr.sbin/cap"; do
	[ "$(pick "$s")" = '0 ' ] ||
	    { echo "FAIL: scratch disk for \"$s\": $(pick "$s")"; exit 1; }
done
[ "$(pick sys/kern 1)" = '1 zfs_load="YES"' ] || { echo "FAIL: SCRATCH_DISK=1"; exit 1; }
[ "$(pick usr.sbin/capsule 0)" = '0 ' ] || { echo "FAIL: SCRATCH_DISK=0"; exit 1; }
if pick sys/kern yes >/dev/null 2>&1; then echo "FAIL: SCRATCH_DISK=yes accepted"; exit 1; fi
# Attached with that serial, written to the image, and named in the input.
grep -q 'serial=kyua-scratch$' "$root/vm-provider.sh"
grep -q '^SCRATCH_DISK=\$scratch_disk$' "$root/vm-provider.sh"
grep -q 'diskinfo -s "/dev/\$d" 2>/dev/null)" = kyua-scratch' "$root/vm-provider.sh"
grep -q '/usr/tests/usr.sbin/capsule/scratch-device$' "$root/vm-provider.sh"
grep -q '^#define	SCRATCH_DISK_IDENT	"kyua-scratch"$' \
    "$root/../../../usr.sbin/capsule/tests/storage_test.c"
echo 'PASS the scratch disk goes to the runs that select disk_import_and_binding, with zfs'
