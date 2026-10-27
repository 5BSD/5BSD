#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Run only inside the source tree's buildenv, using its matching world sysroot.
set -eu
[ "${BUILDENV:-}" = 1 ] || { echo 'requires make buildenv' >&2; exit 1; }
source_root=$1
build_jobs=$2
/usr/local/bin/python3.12 "$source_root/tools/test/secureboot/runner_test.py"
/usr/local/bin/python3.12 -B "$source_root/tools/test/secureboot/assembler_test.py"
# Header-only Capsicum helpers must reach the matching world sysroot before
# compiling consumers; never install headers into the host's /usr/include.
case "${SYSROOT:?matching world sysroot required}" in
    /usr/obj/*) ;;
    *) echo 'world sysroot must be under /usr/obj' >&2; exit 1 ;;
esac
make -C "$source_root/include" includes DESTDIR="$SYSROOT" INSTALL="${INSTALL:-install} -U" NO_ROOT=yes
make -C "$source_root/lib/libcapsicum" includes DESTDIR="$SYSROOT" INSTALL="${INSTALL:-install} -U" NO_ROOT=yes
make -C "$source_root/lib/libc" -j"$build_jobs" WITHOUT_TESTS=yes all
make -C "$source_root/lib/libc" install MK_MAN=no MK_TESTS=no \
    DESTDIR="$SYSROOT" INSTALL="${INSTALL:-install} -U" NO_ROOT=yes
make -C "$source_root/libexec/rtld-elf" -j"$build_jobs" WITHOUT_TESTS=yes all
for program in sbin/md5 sbin/sysctl usr.bin/cmp usr.bin/cap_mkdb; do
    make -C "$source_root/$program" -j"$build_jobs" WITHOUT_TESTS=yes clean
    make -C "$source_root/$program" -j"$build_jobs" WITHOUT_TESTS=yes all
done
make -C "$source_root/lib/libcapsulert" -j"$build_jobs" WITHOUT_TESTS=yes all
make -C "$source_root/lib/libcapsulert" install MK_MAN=no MK_TESTS=no \
    DESTDIR="$SYSROOT" INSTALL="${INSTALL:-install} -U" NO_ROOT=yes
make -C "$source_root/lib/libservice" -j"$build_jobs" WITHOUT_TESTS=yes all
# Capability-image links use the matching sysroot, not the library object path.
make -C "$source_root/lib/libservice" install MK_MAN=no MK_TESTS=no \
    DESTDIR="$SYSROOT" INSTALL="${INSTALL:-install} -U" NO_ROOT=yes
make -C "$source_root/lib/libpam/libpam" -j"$build_jobs" WITHOUT_TESTS=yes all
make -C "$source_root/lib/libpam/modules/pam_unix" -j"$build_jobs" WITHOUT_TESTS=yes all
make -C "$source_root/usr.sbin/pwd_mkdb" -j"$build_jobs" WITHOUT_TESTS=yes all
make -C "$source_root/tools/test/secureboot/accounts" -j"$build_jobs" all
for program in capsule switchboard BSDAudit BSDNotify BSDCrypto BSDFilesystem; do
    make -C "$source_root/usr.sbin/$program" -j"$build_jobs" WITHOUT_TESTS=yes clean
    make -C "$source_root/usr.sbin/$program" -j"$build_jobs" WITHOUT_TESTS=yes all
done

make -C "$source_root/tools/test/secureboot/native" -j"$build_jobs" clean
make -C "$source_root/tools/test/secureboot/native" -j"$build_jobs" all





make -C "$source_root/tools/test/secureboot/storage-client" -j"$build_jobs" all
make -C "$source_root/tools/test/secureboot/provider-crash" -j"$build_jobs" all
make -C "$source_root/usr.sbin/bsd-build/ucl-policy-json" -j"$build_jobs" all

make -C "$source_root/tools/test/secureboot/storage-observer" -j"$build_jobs" all


# Independent firmware-variable fixture; the old combined BIP PID 1 fixture
# has been retired. Legacy runner/assembler cleanup remains outstanding.
make -C "$source_root/tools/test/secureboot" -j"$build_jobs" PROGS=firmware_init all
