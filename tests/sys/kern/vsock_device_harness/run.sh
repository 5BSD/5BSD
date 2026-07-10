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
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cp "$here"/*.h "$here/vsock_device_test.c" "$work/"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_vsock.c"        "$work/pci_virtio_vsock.c"
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_vsock_iov.h"    "$work/pci_virtio_vsock_iov.h"
# DTrace USDT probe wrappers: harness builds WITHOUT -DWITH_DTRACE, so the header
# resolves every VSOCK_PROBE_* to a no-op (no <sys/sdt.h>, no DOF needed).
ln -s "$srctop/usr.sbin/bhyve/pci_virtio_vsock_probes.h" "$work/pci_virtio_vsock_probes.h"

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

"$cc" -g -O1 -fsanitize=address -I"$work/atfshim" -I"$work/inc" \
    -o "$work/devtest" "$work/vsock_device_test.c" \
    -Wl,--wrap=socket,--wrap=connectat,--wrap=send,--wrap=recv,--wrap=sendmsg,--wrap=shutdown,--wrap=poll,--wrap=close,--wrap=accept,--wrap=socketpair,--wrap=fcntl,--wrap=setsockopt,--wrap=getsockopt \
    -lpthread

"$work/devtest"
