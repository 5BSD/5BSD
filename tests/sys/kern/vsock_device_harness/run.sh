#!/bin/sh
# Build and run the bhyve virtio-vsock device-level TX harness locally.
#
# In the tree this is a normal ATF test (see tests/sys/kern/Makefile).  This
# script runs it WITHOUT the ATF runtime: it supplies a tiny <atf-c.h> shim (in
# a throwaway dir, never in the source tree, so it cannot shadow the real ATF
# build) that runs each ATF_TC_BODY inline and reports failures.  It also
# #includes the real pci_virtio_vsock.c and shadows its bhyve headers with the
# mocks here, and compiles against the SOURCE <sys/vsock.h> (pkgbase-installed
# headers may lag the tree).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
srctop=${SRCTOP:-/usr/src}
cc=${CC:-cc}
sanitizers=${SANITIZERS:-address,undefined}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cp "$here"/*.h "$here/vsock_device_test.c" \
    "$here/virtio_modern_test.c" "$here/virtio_input_test.c" \
    "$here/virtio_rnd_test.c" "$here/virtio_rnd_interrupt_test.c" \
    "$here/virtio_core_test.c" "$work/"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_vsock.c"        "$work/pci_virtio_vsock.c"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_vsock_iov.h"    "$work/pci_virtio_vsock_iov.h"
# DTrace USDT probe wrappers: harness builds WITHOUT -DWITH_DTRACE, so the header
# resolves every VSOCK_PROBE_* to a no-op (no <sys/sdt.h>, no DOF needed).
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_vsock_probes.h" "$work/pci_virtio_vsock_probes.h"
ln -s "$srctop/usr.sbin/bhyve/virtio_pci_modern.c" "$work/virtio_pci_modern.c"
ln -s "$srctop/usr.sbin/bhyve/virtio_pci_modern_probes.h" "$work/virtio_pci_modern_probes.h"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_input.c" "$work/pci_virtio_input.c"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_rnd.c" "$work/pci_virtio_rnd.c"
ln -s "$srctop/usr.sbin/bhyve/virtio.c" "$work/virtio.c"

mkdir -p "$work/inc/sys"
cp "$srctop/sys/sys/vsock.h" "$work/inc/sys/vsock.h"

# Minimal <atf-c.h> shim: run each ATF_TC_BODY inline, report failures.
mkdir -p "$work/atfshim"
cat > "$work/atfshim/atf-c.h" <<'EOF'
#ifndef ATF_SHIM_H
#define ATF_SHIM_H
#include <stdio.h>
#include <stdlib.h>
static int atf_checks, atf_failed;
#define ATF_TC_WITHOUT_HEAD(n) static void atf_tcbody_##n(void)
#define ATF_TC_BODY(n, tc)     static void atf_tcbody_##n(void)
#define ATF_CHECK(x) do { atf_checks++; if (!(x)) { \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); \
    atf_failed++; } } while (0)
#define ATF_REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "  ABORT %s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } \
    } while (0)
#define ATF_TP_ADD_TC(tp, n) do { atf_tcbody_##n(); } while (0)
#define atf_no_error() (fprintf(stderr, \
    "device harness: %d checks, %d failed\n", atf_checks, atf_failed), \
    atf_failed ? 1 : 0)
#define ATF_TP_ADD_TCS(tp) int main(void)
#endif
EOF

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work/inc" \
    -I"$srctop/sys" \
    -o "$work/devtest" "$work/vsock_device_test.c" \
    -Wl,--wrap=socket,--wrap=connectat,--wrap=send,--wrap=recv,--wrap=sendmsg,--wrap=shutdown,--wrap=poll,--wrap=close,--wrap=accept,--wrap=socketpair,--wrap=fcntl,--wrap=setsockopt,--wrap=getsockopt,--wrap=recvmsg,--wrap=ioctl,--wrap=realloc \
    -lpthread

"$work/devtest"

"$cc" -g -O1 -fsanitize="$sanitizers" \
	-I"$work/atfshim" -I"$work/inc" \
	-I"$work" -I"$srctop/usr.sbin" -I"$srctop/sys" \
	-o "$work/modern-test" \
    "$work/virtio_modern_test.c" -lpthread

"$work/modern-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -DWITHOUT_CAPSICUM \
	-I"$work/atfshim" -I"$work/inc" \
    -I"$work" -I"$srctop/sys" -o "$work/input-test" \
    "$work/virtio_input_test.c" -lpthread

"$work/input-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -DWITHOUT_CAPSICUM \
	-I"$work/atfshim" -I"$work/inc" \
    -I"$work" -I"$srctop/sys" -o "$work/rnd-test" \
    "$work/virtio_rnd_test.c" -lpthread

"$work/rnd-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -ffunction-sections \
	-DWITHOUT_CAPSICUM -I"$work/atfshim" -I"$work/inc" \
	-I"$work" -I"$srctop/usr.sbin" -I"$srctop/sys" \
	-Wl,--gc-sections -o "$work/rnd-interrupt-test" \
	"$work/virtio_rnd_interrupt_test.c" -lpthread

"$work/rnd-interrupt-test"

"$cc" -g -O1 -fsanitize="$sanitizers" -ffunction-sections \
	-DWITHOUT_CAPSICUM -I"$work/atfshim" -I"$work/inc" \
	-I"$work" -I"$srctop/usr.sbin" -I"$srctop/sys" \
	-Wl,--gc-sections -o "$work/core-test" \
	"$work/virtio_core_test.c" -lpthread

"$work/core-test"
