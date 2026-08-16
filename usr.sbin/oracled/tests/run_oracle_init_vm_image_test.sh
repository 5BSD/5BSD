#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Build a clean source-tree VM image and verify that it boots with Oracle as
# PID 1.  This is intentionally a root-only integration test.

set -eu

usage()
{
	cat >&2 <<-EOF
	usage: $0

	Optional environment:
	  SRCTOP             source tree (default: /usr/src)
	  VM_SIZE            raw image size (default: 4g)
	  BOOT_TIMEOUT       boot-test timeout in seconds (default: 180)
	  VM_MEMORY          guest memory (default: 1024M)
	  KEEP_VM_IMAGE      set to yes to retain a successful image
	  EXPECTED_BANNER    literal banner fragment (default: 5BSD/amd64 (5BSD))
	  INTERACTIVE        set to yes to attach the guest serial console to this terminal
	  VM_TAP             existing host tap interface to attach as guest vtnet0
	EOF
	exit 2
}

fail()
{
	echo "oracle-init VM image test: FAIL: $*" >&2
	exit 1
}

[ "${1:-}" = "" ] || usage
[ "$(id -u)" -eq 0 ] || fail "must run as root"

src=${SRCTOP:-/usr/src}
[ -d "$src" ] || fail "SRCTOP is not a directory: $src"
builder="$src/release/scripts/mk-vmimage.sh"
boot_test="$src/usr.sbin/oracled/tests/run_oracle_init_vm_boot_test.sh"
[ -x "$builder" ] || fail "VM image builder is not executable: $builder"
[ -x "$boot_test" ] || fail "VM boot test is not executable: $boot_test"

vm_size=${VM_SIZE:-4g}
boot_timeout=${BOOT_TIMEOUT:-180}
vm_memory=${VM_MEMORY:-1024M}
keep_image=${KEEP_VM_IMAGE:-no}
interactive=${INTERACTIVE:-no}
vm_tap=${VM_TAP:-}
expected_banner="${EXPECTED_BANNER:-5BSD/amd64 (5BSD)}"
case "$boot_timeout" in
''|*[!0-9]*) fail "BOOT_TIMEOUT must be a positive integer" ;;
esac
[ "$boot_timeout" -gt 0 ] || fail "BOOT_TIMEOUT must be a positive integer"
case "$keep_image" in
yes|no) ;;
*) fail "KEEP_VM_IMAGE must be yes or no" ;;
esac
case "$interactive" in
yes|no) ;;
*) fail "INTERACTIVE must be yes or no" ;;
esac
case "$vm_tap" in
'') ;;
*[!A-Za-z0-9_.-]*) fail "invalid VM_TAP: $vm_tap" ;;
esac

workdir=$(mktemp -d /tmp/oracle-pid1-vm.XXXXXX) || fail "mktemp failed"
case "$workdir" in
/tmp/oracle-pid1-vm.*) ;;
*) fail "unsafe temporary directory: $workdir" ;;
esac

passed=false
cleanup()
{
	rc=$?
	trap - EXIT HUP INT TERM
	if [ "$passed" = true ] && [ "$keep_image" = no ]; then
		rm -rf "$workdir"
	elif [ "$passed" != true ]; then
		echo "oracle-init VM image test: artifacts retained in $workdir" >&2
	fi
	exit "$rc"
}
on_interrupt()
{
	fail "interrupted; Ctrl-C is not test completion"
}
trap cleanup EXIT
trap on_interrupt HUP INT TERM

image="$workdir/oracle.raw"
echo "Building clean Oracle PID 1 VM image in $workdir"
env TARGET=amd64 TARGET_ARCH=amd64 NOPKGBASE=YES WITHOUT_QEMU=YES NOSWAP=YES \
	"$builder" -C "$src/release/tools/vmimage.subr" -c /dev/null \
	-d "$workdir/root" -F ufs -f raw -i "$workdir/rootfs.img" \
	-o "$image" -s "$vm_size" -S "$src"

if [ "$interactive" = yes ]; then
	echo "Starting interactive VM session for $image"
else
	echo "Boot-testing $image"
fi
env IMAGE="$image" VM_MEMORY="$vm_memory" BOOT_TIMEOUT="$boot_timeout" \
	EXPECTED_BANNER="$expected_banner" \
	INTERACTIVE="$interactive" \
	VM_TAP="$vm_tap" \
	BOOT_LOG="$workdir/serial.log" "$boot_test"

passed=true
if [ "$interactive" = yes ]; then
	echo "oracle-init VM image test: interactive session completed"
else
	echo "oracle-init VM image test: PASS"
fi
