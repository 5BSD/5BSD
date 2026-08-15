#!/bin/sh
# Build and run both guest-side vsock unit harnesses WITHOUT the ATF runtime,
# using a tiny atf-c.h shim (mirrors vsock_device_harness/run.sh).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
srctop=${SRCTOP:-$(cd "$here/../../../.." && pwd)}
cc=${CC:-cc}
sanitizers=${SANITIZERS:-address,undefined}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$here"/kmock.h "$here"/transport_kmock.h "$here"/glue.c \
    "$here"/vsock_rx_test.c "$here"/virtio_vsock_transport_test.c \
    "$here"/virtio_if.h "$work"/
cp -R "$here"/sys "$here"/net "$here"/kern "$here"/machine \
    "$here"/dev "$work"/
ln -s "$srctop/sys/kern/uipc_vsock.c" "$work"/uipc_vsock.c
ln -s "$srctop/sys/dev/virtio/vsock/virtio_vsock.c" \
    "$work"/virtio_vsock.c
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
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); atf_failed++; } } while (0)
#define ATF_CHECK_MSG(x, ...) do { atf_checks++; if (!(x)) { \
    fprintf(stderr, "  FAIL %s:%d: ", __FILE__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); atf_failed++; } } while (0)
#define ATF_REQUIRE(x) do { atf_checks++; if (!(x)) { \
    fprintf(stderr, "  ABORT %s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
#define ATF_REQUIRE_MSG(x, ...) do { atf_checks++; if (!(x)) { \
    fprintf(stderr, "  ABORT %s:%d: ", __FILE__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); abort(); } } while (0)
#define ATF_TP_ADD_TC(tp, n) do { atf_tcbody_##n(); } while (0)
#define atf_no_error() (fprintf(stderr, \
    "harness: %d checks, %d failed\n", atf_checks, atf_failed), atf_failed ? 1 : 0)
#define ATF_TP_ADD_TCS(tp) int main(void)
#endif
EOF
cd "$work"
$cc -O1 -g -fsanitize="$sanitizers" -I. -Iatfshim -include kmock.h \
    -Wno-macro-redefined -o rxtest vsock_rx_test.c glue.c
./rxtest
$cc -O1 -g -fsanitize="$sanitizers" -I. -Iatfshim \
	-I"$srctop/sys" \
    -Wno-macro-redefined -Wno-unused-function -Wno-unused-variable \
    -pthread -o transporttest virtio_vsock_transport_test.c
./transporttest
