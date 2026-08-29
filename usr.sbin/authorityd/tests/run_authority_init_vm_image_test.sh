#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Build a clean source-tree VM image and verify that it boots with Authority as
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
	  PKG_CMD            pkg executable (default: pkg)
	  PKGBASE_REPO_DIR   existing pkg repository configuration directory;
	                     when unset, build a fresh repository from SRCTOP
	EOF
	exit 2
}

fail()
{
	echo "authority-init VM image test: FAIL: $*" >&2
	exit 1
}

validate_image_root()
{
	root=$1
	verify_log=$2

	[ -x "$root/usr/sbin/servicectl" ] ||
		fail "image root is missing servicectl"
	"$pkg_cmd" --rootdir "$root" -o IGNORE_OSVERSION=yes \
	    info -e 5BSD-set-base >/dev/null ||
		fail "image root was not installed from pkgbase"
	chroot "$root" /usr/bin/getent passwd capability | awk -F: '
	    $1 == "capability" && $3 == 976 && $4 == 976 &&
	    $6 == "/nonexistent" && $7 == "/usr/sbin/nologin" { ok = 1 }
	    END { exit !ok }
	' || fail "image root has an invalid capability user or passwd database"
	chroot "$root" /usr/bin/getent group capability | awk -F: '
	    $1 == "capability" && $3 == 976 { ok = 1 }
	    END { exit !ok }
	' || fail "image root has an invalid capability group or group database"
	chroot "$root" /usr/bin/getent services ssh | awk '
	    $1 == "ssh" && $2 == "22/tcp" { ok = 1 }
	    END { exit !ok }
	' || fail "image root has an invalid services database"
	chroot "$root" /bin/sh -c '
	    set -- /Capabilities/System/*.cap
	    [ -e "$1" ]
	    exec /usr/sbin/servicectl verify "$@"
	' >"$verify_log" || fail "image root contains invalid system bundles"
	grep -q 'kmod_requires: \[vhid\]' "$verify_log" ||
		fail "Bluetooth.cap does not declare its vhid kernel prerequisite"
	awk '
	    /^  \[[0-9]+\] org\.5bsd\.blued\/blued$/ {
		blued = 1
		next
	    }
	    blued && /activation: first connection/ { lazy = 1 }
	    blued && /^  \[[0-9]+\]/ { blued = 0 }
	    END { exit !lazy }
	' "$verify_log" ||
		fail "Bluetooth.cap is not activated on first connection"
	file -b "$root/boot/images/5bsd-logo.png" | grep -q \
	    '^PNG image data, 960 x 384, 8-bit/color RGBA, non-interlaced$' ||
		fail "image root contains an unsupported boot splash"
}

[ "${1:-}" = "" ] || usage
[ "$(id -u)" -eq 0 ] || fail "must run as root"

src=${SRCTOP:-/usr/src}
[ -d "$src" ] || fail "SRCTOP is not a directory: $src"
builder="$src/release/scripts/mk-vmimage.sh"
boot_test="$src/usr.sbin/authorityd/tests/run_authority_init_vm_boot_test.sh"
[ -x "$builder" ] || fail "VM image builder is not executable: $builder"
[ -x "$boot_test" ] || fail "VM boot test is not executable: $boot_test"

vm_size=${VM_SIZE:-4g}
boot_timeout=${BOOT_TIMEOUT:-180}
vm_memory=${VM_MEMORY:-1024M}
keep_image=${KEEP_VM_IMAGE:-no}
interactive=${INTERACTIVE:-no}
vm_tap=${VM_TAP:-}
expected_banner="${EXPECTED_BANNER:-5BSD/amd64 (5BSD)}"
pkg_cmd=${PKG_CMD:-pkg}
pkgbase_repo_dir=${PKGBASE_REPO_DIR:-}
command -v "$pkg_cmd" >/dev/null 2>&1 ||
	fail "PKG_CMD is not executable: $pkg_cmd"
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

workdir=$(mktemp -d /tmp/authority-pid1-vm.XXXXXX) || fail "mktemp failed"
case "$workdir" in
/tmp/authority-pid1-vm.*) ;;
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
		echo "authority-init VM image test: artifacts retained in $workdir" >&2
	fi
	exit "$rc"
}
on_interrupt()
{
	fail "interrupted; Ctrl-C is not test completion"
}
trap cleanup EXIT
trap on_interrupt HUP INT TERM

image="$workdir/authority.raw"

worldstage=$(make -f "$src/Makefile.inc1" -C "$src" \
	TARGET=amd64 TARGET_ARCH=amd64 -V WSTAGEDIR)
[ -x "$worldstage/usr/bin/uname" ] ||
	fail "missing world stage; run buildworld before this test: $worldstage"
pkg_abi=$("$pkg_cmd" -o ABI_FILE="$worldstage/usr/bin/uname" config ABI)
[ -n "$pkg_abi" ] || fail "could not determine the staged world package ABI"

if [ -z "$pkgbase_repo_dir" ]; then
	pkgbase_repo="$workdir/pkgbase-repo"
	pkgbase_repo_dir="$workdir/pkgbase-repo-dir"
	echo "Building fresh pkgbase repository in $pkgbase_repo"
	make -C "$src" TARGET=amd64 TARGET_ARCH=amd64 \
		PKG_CMD="$pkg_cmd" \
		REPODIR="$pkgbase_repo" packages
	[ -d "$pkgbase_repo/$pkg_abi/latest" ] ||
		fail "pkgbase build did not create $pkgbase_repo/$pkg_abi/latest"
	mkdir -p "$pkgbase_repo_dir"
	printf '5BSD-base: { url: "file://%s", enabled: yes }\n' \
		"$pkgbase_repo/$pkg_abi/latest" \
		> "$pkgbase_repo_dir/5BSD-base.conf"
else
	[ -d "$pkgbase_repo_dir" ] ||
		fail "PKGBASE_REPO_DIR is not a directory: $pkgbase_repo_dir"
fi

echo "Building clean pkgbase Authority PID 1 VM image in $workdir"
env TARGET=amd64 TARGET_ARCH=amd64 WITHOUT_QEMU=YES NOSWAP=YES \
	WITHOUT_DEBUG_FILES=YES WITHOUT_KERNEL_SYMBOLS=YES \
	PKG_CMD="$pkg_cmd" PKG_ABI="$pkg_abi" \
	PKGBASE_REPO_DIR="$pkgbase_repo_dir" \
	"$builder" -C "$src/release/tools/vmimage.subr" -c /dev/null \
	-d "$workdir/root" -F ufs -f raw -i "$workdir/rootfs.img" \
	-o "$image" -s "$vm_size" -S "$src"

echo "Validating clean image root"
validate_image_root "$workdir/root" "$workdir/bundle-verify.log"

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
	echo "authority-init VM image test: interactive session completed"
else
	echo "authority-init VM image test: PASS"
fi
