/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Fault-injection / seam coverage for the ATT client and server FAILURE
 * arms that are unreachable in a healthy process:
 *
 *   - att_open / att_open_fd / att_open_eatt / att_eatt_accept socket
 *     setup: the socket()/bind()/connect()/setsockopt()/getsockopt()/
 *     accept4()/malloc() success AND failure arms.  Driven through a
 *     linker --wrap(3) seam so the real L2CAP/Bluetooth transport is not
 *     required (the genuine on-controller path stays rig-only).
 *   - the "response buffer malloc() failed -> INSUFF_RESOURCES / -1" arms
 *     in att_server_dispatch.c and att_server_notify.c, reached by using a
 *     large (>ATT_PDU_BUF_SIZE) MTU so ATT_RSP_BUF_DECL takes the malloc()
 *     path, then faulting that specific allocation by size.
 *   - the OpenSSL EVP_MAC_* failure arms in att_server_hash.c.
 *   - the "hci_log_enabled()" TRUE logging arms in att.c / dispatch.
 *
 * Oracle: each function's documented error contract in att.h / att_server.h
 * and the ATT spec (Core Spec v6.0 Vol 3 Part F/G).  Error codes are the
 * spec-mandated BT_CORE63_WIRE_ATT_ERR_* values, never captured output.
 *
 * Links with: att.c att_server.c att_server_dispatch.c att_server_notify.c
 *             att_server_hash.c   (-lbluetooth -lcrypto)
 * Requires the parent Makefile to wrap the seam symbols
 * (LDFLAGS.att_fault_test):
 *   -Wl,--wrap=socket -Wl,--wrap=bind -Wl,--wrap=connect
 *   -Wl,--wrap=accept4 -Wl,--wrap=setsockopt -Wl,--wrap=getsockopt
 *   -Wl,--wrap=malloc -Wl,--wrap=EVP_MAC_fetch -Wl,--wrap=EVP_MAC_CTX_new
 *   -Wl,--wrap=EVP_MAC_init -Wl,--wrap=EVP_MAC_update -Wl,--wrap=EVP_MAC_final
 * and: CFLAGS.att_fault_test.c += -Wno-missing-prototypes
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>

/*
 * L2CAP socket-option level/name for the EATT bearer OMTU query.  Defined
 * locally to avoid pulling ng_btsocket.h's kernel type dependencies into a
 * userspace test; values match sys/netgraph/bluetooth/include/ng_btsocket.h.
 */
#ifndef SOL_L2CAP
#define SOL_L2CAP	0x1609
#endif
#ifndef SO_L2CAP_OMTU
#define SO_L2CAP_OMTU	2
#endif
#ifndef SO_L2CAP_IMTU
#define SO_L2CAP_IMTU	1
#endif

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "hci_log.h"
#include "spec_att_client_oracles.h"

/* ================================================================
 * Minimal stubs for external symbols referenced by att*.c.
 * (This file deliberately does NOT include test_common.h, because it
 * needs a *controllable* hci_log_enabled and ble_coc_connect.)
 * ================================================================ */
atomic_int blued_verbose;
int blued_daemonized;
atomic_bool blued_shutting_down;

static bool g_log_on;			/* controllable hci_log_enabled() */
bool
hci_log_enabled(void)
{
	return (g_log_on);
}

void
hci_log_l2cap(uint16_t con_handle __unused, uint16_t cid __unused,
    const uint8_t *data __unused, size_t len __unused, bool incoming __unused)
{
}

void
hci_log_packet(uint8_t type __unused, const uint8_t *data __unused,
    uint16_t len __unused, bool incoming __unused)
{
}

/* Controllable EATT CoC connector: hand back real socketpair-backed fds. */
int	ble_coc_connect(const uint8_t *, const uint8_t *, uint8_t, uint16_t,
	    uint16_t);
static int g_coc_fail_after = 1000;	/* fail the Nth (0-based) connect */
static int g_coc_calls;
static int g_coc_peer[ATT_MAX_EATT_BEARERS];
static int g_coc_npeer;

int
ble_coc_connect(const uint8_t *local_addr __unused,
    const uint8_t *addr __unused, uint8_t addr_type __unused,
    uint16_t psm __unused, uint16_t mtu __unused)
{
	int fds[2];

	if (g_coc_calls++ >= g_coc_fail_after) {
		errno = ECONNREFUSED;
		return (-1);
	}
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) < 0)
		return (-1);
	g_coc_peer[g_coc_npeer++] = fds[1];
	return (fds[0]);
}

int
ble_ecbfc_connect(const uint8_t *local_addr __unused,
    const uint8_t *addr __unused, uint8_t addr_type __unused,
    uint16_t psm, uint16_t mtu __unused, int count, int *out)
{
	int i;

	ATF_CHECK_EQ(psm, ATT_EATT_PSM);
	for (i = 0; i < count; i++) {
		out[i] = ble_coc_connect(NULL, NULL, 0, psm, 0);
		if (out[i] < 0)
			break;
	}
	return (i);
}

static void
coc_reset(void)
{
	g_coc_fail_after = 1000;
	g_coc_calls = 0;
	for (int i = 0; i < g_coc_npeer; i++)
		if (g_coc_peer[i] >= 0)
			close(g_coc_peer[i]);
	g_coc_npeer = 0;
}

#include "ctl.h"
#include "smp.h"
bool
smp_verify_signature(const uint8_t csrk[16] __unused,
    const uint8_t *msg __unused, size_t msg_len __unused,
    const uint8_t mac[8] __unused, uint32_t counter __unused)
{
	return (false);
}
void
blued_ctl_notify_value(struct blued_conn *conn __unused, uint16_t handle __unused,
    const uint8_t *value __unused, uint16_t len __unused,
    uint16_t bearer_mtu __unused)
{
}
void
blued_ctl_notify_write(int owner_fd __unused, uint16_t handle __unused,
    const uint8_t *value __unused, uint16_t len __unused)
{
}
void
blued_ctl_notify_read(int owner_fd __unused, uint16_t handle __unused,
    uint16_t offset __unused)
{
}
void
blued_ctl_notify_authorize(int owner_fd __unused, uint16_t handle __unused,
    bool is_write __unused, const struct att_conn *ac __unused)
{
}

/* ================================================================
 * Linker --wrap(3) seam.  Every wrapper passes through to __real_ unless
 * the matching global is "armed".  Because --wrap only intercepts the
 * references emitted from the object files linked into THIS program, the
 * wrappers see att*.c's own direct calls (plus this test's), which is
 * exactly the surface to fault.
 * ================================================================ */

/* socket(): 0 passthrough; 1 hand back a real AF_UNIX dgram fd; -1 fail. */
static int g_wrap_socket;
/* bind()/connect()/setsockopt(): 0 passthrough; 1 succeed w/o syscall; -1 fail. */
static int g_wrap_bind;
static int g_wrap_connect;
static int g_wrap_setsockopt;
/* accept4(): 0 passthrough; 1 hand back a real AF_UNIX dgram fd; -1 fail. */
static int g_wrap_accept4;
/* getsockopt SO_L2CAP_OMTU: 0 passthrough; 1 succeed returning g_omtu. */
static int g_wrap_getsockopt_omtu;
static uint16_t g_omtu = 200;
static uint16_t g_imtu = 200;
/* malloc(): fail exactly the allocation of this size (0 disables). */
static size_t g_malloc_fail_size;

/*
 * Heap-accounting seam (F8/K5 leak regression).  When g_track_size is armed,
 * every malloc/free of exactly that size is counted (and the returned pointers
 * matched) so a test can assert an early-return path frees the response buffer
 * it allocated instead of leaking it.  Off (g_track_size == 0) by default so
 * all other tests are unaffected.
 */
static size_t g_track_size;
static int g_track_alloc;
static int g_track_free;
static void *g_track_ptrs[32];
static int g_track_n;

static void
seam_reset(void)
{
	g_wrap_socket = g_wrap_bind = g_wrap_connect = 0;
	g_wrap_setsockopt = g_wrap_accept4 = g_wrap_getsockopt_omtu = 0;
	g_malloc_fail_size = 0;
	g_omtu = 200;
	g_imtu = 200;
	g_log_on = false;
	g_track_size = 0;
	g_track_alloc = g_track_free = g_track_n = 0;
	memset(g_track_ptrs, 0, sizeof(g_track_ptrs));
}

extern int __real_socket(int, int, int);
int
__wrap_socket(int domain, int type, int protocol)
{
	if (g_wrap_socket == 1)
		return (__real_socket(AF_UNIX, SOCK_DGRAM, 0));
	if (g_wrap_socket == -1) {
		errno = EACCES;
		return (-1);
	}
	return (__real_socket(domain, type, protocol));
}

extern int __real_bind(int, const struct sockaddr *, socklen_t);
int
__wrap_bind(int s, const struct sockaddr *a, socklen_t l)
{
	if (g_wrap_bind == -1) {
		errno = EADDRNOTAVAIL;
		return (-1);
	}
	if (g_wrap_bind == 1 || a->sa_family == AF_BLUETOOTH)
		return (0);
	return (__real_bind(s, a, l));
}

extern int __real_connect(int, const struct sockaddr *, socklen_t);
int
__wrap_connect(int s, const struct sockaddr *a, socklen_t l)
{
	if (g_wrap_connect == 1)
		return (0);
	if (g_wrap_connect == -1) {
		errno = ECONNREFUSED;
		return (-1);
	}
	return (__real_connect(s, a, l));
}

extern int __real_setsockopt(int, int, int, const void *, socklen_t);
int
__wrap_setsockopt(int s, int level, int name, const void *val, socklen_t l)
{
	if (level == SOL_L2CAP && name == SO_L2CAP_OWN_ADDR_TYPE)
		return (0);
	if (g_wrap_setsockopt == 1)
		return (0);
	if (g_wrap_setsockopt == -1) {
		errno = ENOPROTOOPT;
		return (-1);
	}
	return (__real_setsockopt(s, level, name, val, l));
}

extern int __real_accept4(int, struct sockaddr *, socklen_t *, int);
int
__wrap_accept4(int s, struct sockaddr *a, socklen_t *l, int flags)
{
	if (g_wrap_accept4 == 1)
		return (__real_socket(AF_UNIX, SOCK_DGRAM, 0));
	if (g_wrap_accept4 == -1) {
		errno = ECONNABORTED;
		return (-1);
	}
	return (__real_accept4(s, a, l, flags));
}

extern int __real_getsockopt(int, int, int, void *, socklen_t *);
int
__wrap_getsockopt(int s, int level, int name, void *val, socklen_t *l)
{
	if (g_wrap_getsockopt_omtu == 1 && level == SOL_L2CAP &&
	    (name == SO_L2CAP_OMTU || name == SO_L2CAP_IMTU)) {
		uint16_t mtu = name == SO_L2CAP_IMTU ? g_imtu : g_omtu;

		if (l != NULL && *l >= sizeof(uint16_t)) {
			memcpy(val, &mtu, sizeof(uint16_t));
			*l = sizeof(uint16_t);
		}
		return (0);
	}
	return (__real_getsockopt(s, level, name, val, l));
}

extern void *__real_malloc(size_t);
void *
__wrap_malloc(size_t sz)
{
	void *p;

	if (g_malloc_fail_size != 0 && sz == g_malloc_fail_size)
		return (NULL);
	p = __real_malloc(sz);
	if (p != NULL && g_track_size != 0 && sz == g_track_size) {
		g_track_alloc++;
		if (g_track_n < (int)(sizeof(g_track_ptrs) /
		    sizeof(g_track_ptrs[0])))
			g_track_ptrs[g_track_n++] = p;
	}
	return (p);
}

extern void __real_free(void *);
void
__wrap_free(void *p)
{
	if (p != NULL && g_track_size != 0) {
		for (int i = 0; i < g_track_n; i++) {
			if (g_track_ptrs[i] == p) {
				g_track_free++;
				g_track_ptrs[i] = NULL;
				break;
			}
		}
	}
	__real_free(p);
}

/* ---- OpenSSL EVP_MAC_* seam (att_server_hash.c) ---- */
static int g_evp_fetch_fail, g_evp_ctx_fail, g_evp_init_fail;
static int g_evp_update_fail_at, g_evp_update_n, g_evp_final_fail;

extern EVP_MAC *__real_EVP_MAC_fetch(void *, const char *, const char *);
EVP_MAC *
__wrap_EVP_MAC_fetch(void *libctx, const char *algo, const char *props)
{
	if (g_evp_fetch_fail)
		return (NULL);
	return (__real_EVP_MAC_fetch(libctx, algo, props));
}

extern EVP_MAC_CTX *__real_EVP_MAC_CTX_new(EVP_MAC *);
EVP_MAC_CTX *
__wrap_EVP_MAC_CTX_new(EVP_MAC *mac)
{
	if (g_evp_ctx_fail)
		return (NULL);
	return (__real_EVP_MAC_CTX_new(mac));
}

extern int __real_EVP_MAC_init(EVP_MAC_CTX *, const unsigned char *, size_t,
    const OSSL_PARAM *);
int
__wrap_EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen,
    const OSSL_PARAM *params)
{
	if (g_evp_init_fail)
		return (0);
	return (__real_EVP_MAC_init(ctx, key, keylen, params));
}

extern int __real_EVP_MAC_update(EVP_MAC_CTX *, const unsigned char *, size_t);
int
__wrap_EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t len)
{
	if (g_evp_update_fail_at != 0 && ++g_evp_update_n == g_evp_update_fail_at)
		return (0);
	return (__real_EVP_MAC_update(ctx, data, len));
}

extern int __real_EVP_MAC_final(EVP_MAC_CTX *, unsigned char *, size_t *,
    size_t);
int
__wrap_EVP_MAC_final(EVP_MAC_CTX *ctx, unsigned char *out, size_t *outl,
    size_t outsize)
{
	if (g_evp_final_fail)
		return (0);
	return (__real_EVP_MAC_final(ctx, out, outl, outsize));
}

/* ================================================================
 * att_open — socket/bind/connect/setsockopt/malloc arms.
 * Contract (att.h): returns 0 and sets ac->fd on success; -1 otherwise.
 * ================================================================ */
static const uint8_t g_addr[6] = { 1, 2, 3, 4, 5, 6 };

ATF_TC_WITHOUT_HEAD(open_socket_fail);
ATF_TC_BODY(open_socket_fail, tc)
{
	struct att_conn ac;

	seam_reset();
	g_wrap_socket = -1;
	ATF_CHECK_EQ(att_open(&ac, NULL, 0, g_addr, 0), -1);
	ATF_CHECK_EQ(ac.fd, -1);
}

ATF_TC_WITHOUT_HEAD(open_bind_fail);
ATF_TC_BODY(open_bind_fail, tc)
{
	struct att_conn ac;

	seam_reset();
	g_wrap_socket = 1;		/* real AF_UNIX fd */
	g_wrap_bind = -1;
	ATF_CHECK_EQ(att_open(&ac, NULL, 0, g_addr, 0), -1);
}

ATF_TC_WITHOUT_HEAD(open_connect_fail);
ATF_TC_BODY(open_connect_fail, tc)
{
	struct att_conn ac;

	seam_reset();
	g_wrap_socket = 1;
	g_wrap_bind = 1;
	g_wrap_connect = -1;
	ATF_CHECK_EQ(att_open(&ac, NULL, 0, g_addr, 0), -1);
}

ATF_TC_WITHOUT_HEAD(open_setsockopt_warn);
ATF_TC_BODY(open_setsockopt_warn, tc)
{
	struct att_conn ac;

	/* setsockopt failure is only a warning; att_open still succeeds. */
	seam_reset();
	g_wrap_socket = 1;
	g_wrap_bind = 1;
	g_wrap_connect = 1;
	g_wrap_setsockopt = -1;
	ATF_CHECK_EQ(att_open(&ac, NULL, 0, g_addr, 0), 0);
	ATF_CHECK(ac.fd >= 0);
	ATF_CHECK_EQ(ac.mtu, ATT_DEFAULT_MTU);
	att_close(&ac);
}

ATF_TC_WITHOUT_HEAD(open_malloc_fail);
ATF_TC_BODY(open_malloc_fail, tc)
{
	struct att_conn ac;

	seam_reset();
	g_wrap_socket = 1;
	g_wrap_bind = 1;
	g_wrap_connect = 1;
	g_malloc_fail_size = ATT_MAX_MTU;	/* ac->buf = malloc(ATT_MAX_MTU) */
	ATF_CHECK_EQ(att_open(&ac, NULL, 0, g_addr, 0), -1);
	ATF_CHECK_EQ(ac.fd, -1);
	g_malloc_fail_size = 0;
}

ATF_TC_WITHOUT_HEAD(open_success);
ATF_TC_BODY(open_success, tc)
{
	struct att_conn ac;

	seam_reset();
	g_wrap_socket = 1;
	g_wrap_bind = 1;
	g_wrap_connect = 1;
	ATF_CHECK_EQ(att_open(&ac, NULL, 0, g_addr, 1), 0);
	ATF_CHECK(ac.fd >= 0);
	ATF_CHECK_EQ(ac.mtu, ATT_DEFAULT_MTU);
	ATF_CHECK(ac.buf != NULL);
	att_close(&ac);
	ATF_CHECK_EQ(ac.fd, -1);
}

/* ================================================================
 * att_open_fd — pre-created fd; connect/setsockopt/malloc arms.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(open_fd_success);
ATF_TC_BODY(open_fd_success, tc)
{
	struct att_conn ac;
	int fd;

	seam_reset();
	g_wrap_connect = 1;
	fd = __real_socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(att_open_fd(&ac, fd, NULL, 0, g_addr, 0), 0);
	ATF_CHECK_EQ(ac.fd, fd);
	att_close(&ac);
}

ATF_TC_WITHOUT_HEAD(open_fd_setsockopt_warn);
ATF_TC_BODY(open_fd_setsockopt_warn, tc)
{
	struct att_conn ac;
	int fd;

	seam_reset();
	g_wrap_connect = 1;
	g_wrap_setsockopt = -1;		/* SO_RCVTIMEO warn arm */
	fd = __real_socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(att_open_fd(&ac, fd, NULL, 0, g_addr, 0), 0);
	att_close(&ac);
}

ATF_TC_WITHOUT_HEAD(open_fd_connect_fail);
ATF_TC_BODY(open_fd_connect_fail, tc)
{
	struct att_conn ac;
	int fd;

	seam_reset();
	g_wrap_connect = -1;
	fd = __real_socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(att_open_fd(&ac, fd, NULL, 0, g_addr, 0), -1);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(open_fd_malloc_fail);
ATF_TC_BODY(open_fd_malloc_fail, tc)
{
	struct att_conn ac;
	int fd;

	seam_reset();
	g_wrap_connect = 1;
	g_malloc_fail_size = ATT_MAX_MTU;
	fd = __real_socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(att_open_fd(&ac, fd, NULL, 0, g_addr, 0), -1);
	ATF_CHECK_EQ(ac.fd, -1);
	g_malloc_fail_size = 0;
	close(fd);
}

/* ================================================================
 * att_open_eatt — CoC bearers; getsockopt OMTU success/failure arms.
 * Contract (att_server.h/att.c): returns number of bearers opened.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(open_eatt_omtu_success);
ATF_TC_BODY(open_eatt_omtu_success, tc)
{
	struct att_conn ac;

	seam_reset();
	memset(&ac, 0, sizeof(ac));
	ac.fd = -1;
	ac.encrypted = true;
	g_wrap_getsockopt_omtu = 1;		/* OMTU = 200 (>= default) */
	g_imtu = 180;
	g_omtu = 200;
	ATF_CHECK_EQ(att_open_eatt(&ac, NULL, g_addr, 0, 2), 2);
	ATF_CHECK_EQ(ac.eatt_count, 2);
	ATF_CHECK_EQ_MSG(ac.eatt[0].mtu, 180,
	    "EATT bearer MTU is min(IMTU, OMTU) (Vol 3 Part G 5.3.1)");
	att_close_eatt(&ac);
	coc_reset();
}

ATF_TC_WITHOUT_HEAD(open_eatt_omtu_too_small);
ATF_TC_BODY(open_eatt_omtu_too_small, tc)
{
	struct att_conn ac;

	seam_reset();
	memset(&ac, 0, sizeof(ac));
	ac.fd = -1;
	ac.encrypted = true;
	g_wrap_getsockopt_omtu = 1;
	g_omtu = 10;				/* < EATT minimum -> clamp */
	ATF_CHECK_EQ(att_open_eatt(&ac, NULL, g_addr, 1, 1), 0);
	ATF_CHECK_EQ_MSG(ac.eatt_count, 0,
	    "an EATT bearer below the 64-octet minimum is rejected");
	att_close_eatt(&ac);
	coc_reset();
}

ATF_TC_WITHOUT_HEAD(open_eatt_getsockopt_fail);
ATF_TC_BODY(open_eatt_getsockopt_fail, tc)
{
	struct att_conn ac;

	/* Both negotiated MTUs are mandatory; a query failure rejects bearer. */
	seam_reset();
	memset(&ac, 0, sizeof(ac));
	ac.fd = -1;
	ac.encrypted = true;
	ATF_CHECK_EQ(att_open_eatt(&ac, NULL, g_addr, 0, 1), 0);
	ATF_CHECK_EQ(ac.eatt_count, 0);
	att_close_eatt(&ac);
	coc_reset();
}

ATF_TC_WITHOUT_HEAD(open_eatt_connect_break);
ATF_TC_BODY(open_eatt_connect_break, tc)
{
	struct att_conn ac;

	/* First CoC connect fails immediately -> 0 bearers opened. */
	seam_reset();
	memset(&ac, 0, sizeof(ac));
	ac.fd = -1;
	ac.encrypted = true;
	g_coc_fail_after = 0;
	ATF_CHECK_EQ(att_open_eatt(&ac, NULL, g_addr, 0, 3), 0);
	ATF_CHECK_EQ(ac.eatt_count, 0);
	coc_reset();
}

ATF_TC_WITHOUT_HEAD(open_eatt_count_clamp);
ATF_TC_BODY(open_eatt_count_clamp, tc)
{
	struct att_conn ac;

	/* count > ATT_MAX_EATT_BEARERS clamps to the max. */
	seam_reset();
	memset(&ac, 0, sizeof(ac));
	ac.fd = -1;
	ac.encrypted = true;
	g_wrap_getsockopt_omtu = 1;
	ATF_CHECK_EQ(att_open_eatt(&ac, NULL, g_addr, 0, ATT_MAX_EATT_BEARERS + 3),
	    ATT_MAX_EATT_BEARERS);
	att_close_eatt(&ac);
	coc_reset();
}

/* ================================================================
 * att_eatt_accept — accept4 success + getsockopt OMTU + ENOSPC + fail.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(accept_success_omtu);
ATF_TC_BODY(accept_success_omtu, tc)
{
	struct att_conn ac;
	int lst;

	seam_reset();
	memset(&ac, 0, sizeof(ac));
	ac.fd = -1;
	g_wrap_accept4 = 1;			/* real AF_UNIX fd */
	g_wrap_getsockopt_omtu = 1;
	g_omtu = 150;
	lst = __real_socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(lst >= 0);
	ATF_CHECK_EQ(att_eatt_accept(&ac, lst), 0);
	ATF_CHECK_EQ(ac.eatt_count, 1);
	ATF_CHECK_EQ_MSG(ac.eatt[0].mtu, 150, "accepted bearer takes OMTU");
	att_close_eatt(&ac);
	close(lst);
}

ATF_TC_WITHOUT_HEAD(accept_success_default_mtu);
ATF_TC_BODY(accept_success_default_mtu, tc)
{
	struct att_conn ac;
	int lst;

	/* Missing negotiated MTUs must reject the bearer, never guess a default. */
	seam_reset();
	memset(&ac, 0, sizeof(ac));
	ac.fd = -1;
	g_wrap_accept4 = 1;
	lst = __real_socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(lst >= 0);
	ATF_CHECK_EQ(att_eatt_accept(&ac, lst), -1);
	ATF_CHECK_EQ(ac.eatt_count, 0);
	att_close_eatt(&ac);
	close(lst);
}

ATF_TC_WITHOUT_HEAD(accept_fail);
ATF_TC_BODY(accept_fail, tc)
{
	struct att_conn ac;

	seam_reset();
	memset(&ac, 0, sizeof(ac));
	ac.fd = -1;
	g_wrap_accept4 = -1;
	ATF_CHECK_EQ(att_eatt_accept(&ac, 7), -1);
	ATF_CHECK_EQ(ac.eatt_count, 0);
}

ATF_TC_WITHOUT_HEAD(accept_enospc);
ATF_TC_BODY(accept_enospc, tc)
{
	struct att_conn ac;

	/* Already at max bearers -> ENOSPC, no accept attempted. */
	seam_reset();
	memset(&ac, 0, sizeof(ac));
	ac.fd = -1;
	ac.eatt_count = ATT_MAX_EATT_BEARERS;
	errno = 0;
	ATF_CHECK_EQ(att_eatt_accept(&ac, 7), -1);
	ATF_CHECK_EQ(errno, ENOSPC);
}

ATF_TC_WITHOUT_HEAD(accept_setsockopt_warn);
ATF_TC_BODY(accept_setsockopt_warn, tc)
{
	struct att_conn ac;
	int lst;

	/* setsockopt(SO_RCVTIMEO) failure is only a warning. */
	seam_reset();
	memset(&ac, 0, sizeof(ac));
	ac.fd = -1;
	g_wrap_accept4 = 1;
	g_wrap_setsockopt = -1;
	g_wrap_getsockopt_omtu = 1;
	lst = __real_socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(lst >= 0);
	ATF_CHECK_EQ(att_eatt_accept(&ac, lst), 0);
	att_close_eatt(&ac);
	close(lst);
}

ATF_TC_WITHOUT_HEAD(accept_omtu_too_small);
ATF_TC_BODY(accept_omtu_too_small, tc)
{
	struct att_conn ac;
	int lst;

	/* A negotiated MTU below the EATT minimum invalidates the bearer. */
	seam_reset();
	memset(&ac, 0, sizeof(ac));
	ac.fd = -1;
	g_wrap_accept4 = 1;
	g_wrap_getsockopt_omtu = 1;
	g_omtu = 5;
	lst = __real_socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(lst >= 0);
	ATF_CHECK_EQ(att_eatt_accept(&ac, lst), -1);
	ATF_CHECK_EQ(ac.eatt_count, 0);
	att_close_eatt(&ac);
	close(lst);
}

/* Client att_conn on a real SOCK_SEQPACKET socketpair with a given MTU. */
static void
log_client_pair_mtu(struct att_conn *ac, int *peer, uint16_t mtu)
{
	int fds[2];

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(ac, 0, sizeof(*ac));
	ac->fd = fds[0];
	ac->bearer_fd = -1;
	ac->mtu = mtu;
	ac->buf = __real_malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
	for (int i = 0; i < ATT_MAX_EATT_BEARERS; i++)
		ac->eatt[i].fd = -1;
	*peer = fds[1];
}

/* ================================================================
 * att_write_cmd — heap-PDU malloc() failure and hci_log() arm.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(write_cmd_malloc_fail);
ATF_TC_BODY(write_cmd_malloc_fail, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t data[600];

	/* pdulen = 3 + 600 = 603 > sizeof(pdubuf) (517) -> malloc(603). */
	seam_reset();
	log_client_pair_mtu(&ac, &peer, 700);
	memset(data, 0xAB, sizeof(data));
	g_malloc_fail_size = 603;
	ATF_CHECK_EQ(att_write_cmd(&ac, 0x0003, data, sizeof(data)), -1);
	g_malloc_fail_size = 0;
	free(ac.buf);
	close(ac.fd);
	close(peer);
}

ATF_TC_WITHOUT_HEAD(write_cmd_log);
ATF_TC_BODY(write_cmd_log, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t data[4] = { 1, 2, 3, 4 };

	/* Logging ON exercises the Write Command send-log arm. */
	seam_reset();
	g_log_on = true;
	log_client_pair_mtu(&ac, &peer, 100);
	ATF_CHECK_EQ(att_write_cmd(&ac, 0x0003, data, sizeof(data)), 0);
	free(ac.buf);
	close(ac.fd);
	close(peer);
	g_log_on = false;
}

/* ================================================================
 * Server dispatch: response-buffer malloc() failure -> INSUFF_RESOURCES.
 * A large MTU forces ATT_RSP_BUF_DECL down the malloc() path; the seam
 * faults exactly the malloc(ac->mtu).  Spec: an ATT server that cannot
 * allocate resources replies Insufficient Resources (Vol 3 Part F 3.4.1.1
 * error 0x11) -- or drops silently for requests with no response buffer.
 * ================================================================ */
#define BIGMTU	600
static struct att_attr g_store[64];
static uint8_t g_valbuf[8192];

static void
fault_pair(struct att_conn *ac, struct att_db *db, int *peer)
{
	int fds[2];

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(ac, 0, sizeof(*ac));
	ac->fd = fds[0];
	ac->bearer_fd = -1;
	ac->mtu = BIGMTU;			/* > ATT_PDU_BUF_SIZE */
	ac->buf = __real_malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
	*peer = fds[1];
	attdb_init(db, g_store, 64, g_valbuf, sizeof(g_valbuf));
	attdb_add_service(db, 0x1800);
	attdb_add_characteristic(db, 0x2A00, GATT_PROP_READ, ATT_PERM_READ,
	    "dev", 3);
}

static void
fault_pair_free(struct att_conn *ac, int peer)
{
	free(ac->buf);
	ac->buf = NULL;
	if (ac->fd >= 0)
		close(ac->fd);
	if (peer >= 0)
		close(peer);
}

/* Drive one request opcode with the RSP_BUF malloc faulted. */
static void
rspbuf_oom(const uint8_t *pdu, size_t len)
{
	struct att_conn ac;
	struct att_db db;
	int peer;

	seam_reset();
	fault_pair(&ac, &db, &peer);
	g_malloc_fail_size = BIGMTU;		/* fault malloc(ac->mtu) */
	(void)att_server_handle(&ac, &db, pdu, len, -1, 0);
	g_malloc_fail_size = 0;
	fault_pair_free(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(disp_oom_find_info);
ATF_TC_BODY(disp_oom_find_info, tc)
{
	uint8_t pdu[] = { BT_CORE63_WIRE_ATT_OP_FIND_INFO_REQ, 0x01, 0x00, 0xFF, 0xFF };
	rspbuf_oom(pdu, sizeof(pdu));
}
ATF_TC_WITHOUT_HEAD(disp_oom_read_by_group);
ATF_TC_BODY(disp_oom_read_by_group, tc)
{
	uint8_t pdu[] = { BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ, 0x01, 0x00, 0xFF, 0xFF,
	    0x00, 0x28 };
	rspbuf_oom(pdu, sizeof(pdu));
}
ATF_TC_WITHOUT_HEAD(disp_oom_read_by_type);
ATF_TC_BODY(disp_oom_read_by_type, tc)
{
	uint8_t pdu[] = { BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ, 0x01, 0x00, 0xFF, 0xFF,
	    0x03, 0x28 };
	rspbuf_oom(pdu, sizeof(pdu));
}
ATF_TC_WITHOUT_HEAD(disp_oom_read);
ATF_TC_BODY(disp_oom_read, tc)
{
	uint8_t pdu[] = { BT_CORE63_WIRE_ATT_OP_READ_REQ, 0x03, 0x00 };
	rspbuf_oom(pdu, sizeof(pdu));
}
ATF_TC_WITHOUT_HEAD(disp_oom_read_blob);
ATF_TC_BODY(disp_oom_read_blob, tc)
{
	uint8_t pdu[] = { BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ, 0x03, 0x00, 0x00, 0x00 };
	rspbuf_oom(pdu, sizeof(pdu));
}
ATF_TC_WITHOUT_HEAD(disp_oom_find_by_type);
ATF_TC_BODY(disp_oom_find_by_type, tc)
{
	uint8_t pdu[] = { BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ, 0x01, 0x00, 0xFF, 0xFF,
	    0x00, 0x28, 0x00, 0x18 };
	rspbuf_oom(pdu, sizeof(pdu));
}
ATF_TC_WITHOUT_HEAD(disp_oom_read_multiple);
ATF_TC_BODY(disp_oom_read_multiple, tc)
{
	uint8_t pdu[] = { BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_REQ, 0x03, 0x00, 0x03, 0x00 };
	rspbuf_oom(pdu, sizeof(pdu));
}
ATF_TC_WITHOUT_HEAD(disp_oom_read_multiple_var);
ATF_TC_BODY(disp_oom_read_multiple_var, tc)
{
	uint8_t pdu[] = { BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ, 0x03, 0x00,
	    0x03, 0x00 };
	rspbuf_oom(pdu, sizeof(pdu));
}
ATF_TC_WITHOUT_HEAD(disp_oom_prepare_write);
ATF_TC_BODY(disp_oom_prepare_write, tc)
{
	uint8_t pdu[] = { BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ, 0x03, 0x00, 0x00, 0x00,
	    0xAA };
	rspbuf_oom(pdu, sizeof(pdu));
}

/*
 * F8/K5: a malformed Find Information Request (len < 5) on a large-MTU bearer
 * must NOT leak its response buffer.  On an EATT bearer with MTU > 517 the
 * dispatcher heap-allocates the response buffer (ATT_RSP_BUF_DECL); the
 * len < 5 "Invalid PDU" early return must free it before returning, otherwise
 * ~mtu bytes leak per malformed PDU and a peer can drive the server to OOM.
 * Heap-account every malloc/free of exactly the bearer MTU: after the request
 * the tracked allocation count must equal the free count (net zero).
 */
ATF_TC_WITHOUT_HEAD(disp_find_info_short_no_leak);
ATF_TC_BODY(disp_find_info_short_no_leak, tc)
{
	struct att_conn ac;
	struct att_db db;
	int peer;
	/* Find Information Request truncated to 4 octets (< 5): malformed. */
	uint8_t pdu[] = { BT_CORE63_WIRE_ATT_OP_FIND_INFO_REQ, 0x01, 0x00, 0xFF };

	seam_reset();
	fault_pair(&ac, &db, &peer);		/* ac.mtu == BIGMTU (> 517) */

	g_track_size = BIGMTU;			/* account malloc(ac->mtu) */
	(void)att_server_handle(&ac, &db, pdu, sizeof(pdu), -1, 0);
	g_track_size = 0;

	ATF_CHECK_MSG(g_track_alloc >= 1,
	    "the large-MTU response buffer must have been allocated");
	ATF_CHECK_EQ_MSG(g_track_alloc, g_track_free,
	    "malformed Find Information must free its response buffer "
	    "(alloc=%d free=%d)", g_track_alloc, g_track_free);

	fault_pair_free(&ac, peer);
}

/* ================================================================
 * Notify/indicate: response-buffer malloc() failure -> -1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(notify_oom);
ATF_TC_BODY(notify_oom, tc)
{
	struct att_conn ac;
	struct att_db db;
	int peer;
	uint8_t v[4] = { 1, 2, 3, 4 };

	seam_reset();
	fault_pair(&ac, &db, &peer);
	g_malloc_fail_size = BIGMTU;
	ATF_CHECK_EQ(att_send_notification(&ac, 0x0003, v, sizeof(v)), -1);
	g_malloc_fail_size = 0;
	fault_pair_free(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(indicate_oom);
ATF_TC_BODY(indicate_oom, tc)
{
	struct att_conn ac;
	struct att_db db;
	int peer;
	uint8_t v[4] = { 1, 2, 3, 4 };

	seam_reset();
	fault_pair(&ac, &db, &peer);
	g_malloc_fail_size = BIGMTU;
	ATF_CHECK_EQ(att_send_indication(&ac, 0x0003, v, sizeof(v)), -1);
	g_malloc_fail_size = 0;
	fault_pair_free(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(multi_ntf_oom);
ATF_TC_BODY(multi_ntf_oom, tc)
{
	struct att_conn ac;
	struct att_db db;
	int peer;
	uint16_t handles[1] = { 0x0003 };
	uint16_t lens[1] = { 4 };
	const uint8_t v0[4] = { 1, 2, 3, 4 };
	const uint8_t *vals[1] = { v0 };

	seam_reset();
	fault_pair(&ac, &db, &peer);
	g_malloc_fail_size = BIGMTU;
	ATF_CHECK_EQ(att_send_multiple_handle_value_ntf(&ac, handles, vals,
	    lens, 1), -1);
	g_malloc_fail_size = 0;
	fault_pair_free(&ac, peer);
}

/* ================================================================
 * att_server_hash.c — EVP_MAC_* failure arms.
 * Contract: on any EVP failure the hash is zeroed (memset 0).
 * ================================================================ */
static void
hash_db_build(struct att_db *db)
{
	attdb_init(db, g_store, 64, g_valbuf, sizeof(g_valbuf));
	attdb_add_service(db, 0x1800);
	attdb_add_characteristic(db, 0x2A00, GATT_PROP_READ, ATT_PERM_READ,
	    "d", 1);
	attdb_add_cccd(db);
	/*
	 * A 16-bit-typed descriptor that is NOT one of the 10 hashable types
	 * (Vol 3 Part G 7.3.1) exercises the switch 'default: continue' skip.
	 */
	attdb_add_descriptor(db, 0x2999, ATT_PERM_READ, "x", 1);
}

static void
hash_expect_zero(struct att_db *db)
{
	uint8_t h[16], zero[16];

	memset(zero, 0, sizeof(zero));
	memset(h, 0xEE, sizeof(h));
	attdb_compute_db_hash(db, h);
	ATF_CHECK_EQ_MSG(memcmp(h, zero, 16), 0,
	    "EVP failure must zero the DB hash");
}

ATF_TC_WITHOUT_HEAD(hash_fetch_fail);
ATF_TC_BODY(hash_fetch_fail, tc)
{
	struct att_db db;

	seam_reset();
	hash_db_build(&db);
	g_evp_fetch_fail = 1;
	hash_expect_zero(&db);
	g_evp_fetch_fail = 0;
}
ATF_TC_WITHOUT_HEAD(hash_ctx_fail);
ATF_TC_BODY(hash_ctx_fail, tc)
{
	struct att_db db;

	seam_reset();
	hash_db_build(&db);
	g_evp_ctx_fail = 1;
	hash_expect_zero(&db);
	g_evp_ctx_fail = 0;
}
ATF_TC_WITHOUT_HEAD(hash_init_fail);
ATF_TC_BODY(hash_init_fail, tc)
{
	struct att_db db;

	seam_reset();
	hash_db_build(&db);
	g_evp_init_fail = 1;
	hash_expect_zero(&db);
	g_evp_init_fail = 0;
}
ATF_TC_WITHOUT_HEAD(hash_update_fail);
ATF_TC_BODY(hash_update_fail, tc)
{
	struct att_db db;

	seam_reset();
	hash_db_build(&db);
	g_evp_update_fail_at = 1;		/* fail first EVP_MAC_update */
	g_evp_update_n = 0;
	hash_expect_zero(&db);
	g_evp_update_fail_at = 0;
}
ATF_TC_WITHOUT_HEAD(hash_update_fail2);
ATF_TC_BODY(hash_update_fail2, tc)
{
	struct att_db db;

	/* Fail the 2nd EVP_MAC_update (the UUID-bytes update). */
	seam_reset();
	hash_db_build(&db);
	g_evp_update_fail_at = 2;
	g_evp_update_n = 0;
	hash_expect_zero(&db);
	g_evp_update_fail_at = 0;
}
ATF_TC_WITHOUT_HEAD(hash_update_fail3);
ATF_TC_BODY(hash_update_fail3, tc)
{
	struct att_db db;

	/* Fail the 3rd EVP_MAC_update (the value update, include_value=1). */
	seam_reset();
	hash_db_build(&db);
	g_evp_update_fail_at = 3;
	g_evp_update_n = 0;
	hash_expect_zero(&db);
	g_evp_update_fail_at = 0;
}
ATF_TC_WITHOUT_HEAD(hash_final_fail);
ATF_TC_BODY(hash_final_fail, tc)
{
	struct att_db db;

	seam_reset();
	hash_db_build(&db);
	g_evp_final_fail = 1;
	hash_expect_zero(&db);
	g_evp_final_fail = 0;
}

/* ================================================================
 * hci_log_enabled() TRUE logging arms in att.c / dispatch.
 * ================================================================ */
#define log_client_pair(ac, peer)	log_client_pair_mtu((ac), (peer), 100)

ATF_TC_WITHOUT_HEAD(log_request_paths);
ATF_TC_BODY(log_request_paths, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t rsp[3];

	/* Logging ON exercises the send-log and recv-log arms of att_request. */
	seam_reset();
	g_log_on = true;
	log_client_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_MTU_RSP;
	put_le16(rsp + 1, 100);
	ATF_REQUIRE(send(peer, rsp, sizeof(rsp), MSG_EOR) == (ssize_t)sizeof(rsp));
	ATF_CHECK_EQ(att_exchange_mtu(&ac, 100), 0);
	free(ac.buf);
	close(ac.fd);
	close(peer);
	g_log_on = false;
}

ATF_TC_WITHOUT_HEAD(log_recv_confirm);
ATF_TC_BODY(log_recv_confirm, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t ind[3] = { BT_CORE63_WIRE_ATT_OP_HANDLE_IND, 0x03, 0x00 };
	uint8_t out[8];
	size_t olen;

	/* att_recv() + att_confirm() logging arms. */
	seam_reset();
	g_log_on = true;
	log_client_pair(&ac, &peer);
	ATF_REQUIRE(send(peer, ind, sizeof(ind), MSG_EOR) == (ssize_t)sizeof(ind));
	ATF_CHECK_EQ(att_recv(&ac, out, sizeof(out), &olen), 0);
	ATF_CHECK_EQ(att_confirm(&ac), 0);
	free(ac.buf);
	close(ac.fd);
	close(peer);
	g_log_on = false;
}

ATF_TC_WITHOUT_HEAD(log_server_dispatch);
ATF_TC_BODY(log_server_dispatch, tc)
{
	struct att_conn ac;
	struct att_db db;
	int peer, fds[2];

	/* Server response-log arm (dispatch hci_log_l2cap on send). */
	seam_reset();
	g_log_on = true;
	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(&ac, 0, sizeof(ac));
	ac.fd = fds[0];
	ac.bearer_fd = -1;
	ac.mtu = ATT_PDU_BUF_SIZE;
	ac.buf = __real_malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac.buf != NULL);
	peer = fds[1];
	attdb_init(&db, g_store, 64, g_valbuf, sizeof(g_valbuf));
	attdb_add_service(&db, 0x1800);
	{
		uint8_t pdu[] = { BT_CORE63_WIRE_ATT_OP_MTU_REQ, 0x00, 0x02 };
		(void)att_server_handle(&ac, &db, pdu, sizeof(pdu), -1, 0);
	}
	free(ac.buf);
	close(ac.fd);
	close(peer);
	g_log_on = false;
}

/* ================================================================ */
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, open_socket_fail);
	ATF_TP_ADD_TC(tp, open_bind_fail);
	ATF_TP_ADD_TC(tp, open_connect_fail);
	ATF_TP_ADD_TC(tp, open_setsockopt_warn);
	ATF_TP_ADD_TC(tp, open_malloc_fail);
	ATF_TP_ADD_TC(tp, open_success);
	ATF_TP_ADD_TC(tp, open_fd_success);
	ATF_TP_ADD_TC(tp, open_fd_setsockopt_warn);
	ATF_TP_ADD_TC(tp, open_fd_connect_fail);
	ATF_TP_ADD_TC(tp, open_fd_malloc_fail);
	ATF_TP_ADD_TC(tp, open_eatt_omtu_success);
	ATF_TP_ADD_TC(tp, open_eatt_omtu_too_small);
	ATF_TP_ADD_TC(tp, open_eatt_getsockopt_fail);
	ATF_TP_ADD_TC(tp, open_eatt_connect_break);
	ATF_TP_ADD_TC(tp, open_eatt_count_clamp);
	ATF_TP_ADD_TC(tp, accept_success_omtu);
	ATF_TP_ADD_TC(tp, accept_success_default_mtu);
	ATF_TP_ADD_TC(tp, accept_fail);
	ATF_TP_ADD_TC(tp, accept_enospc);
	ATF_TP_ADD_TC(tp, accept_setsockopt_warn);
	ATF_TP_ADD_TC(tp, accept_omtu_too_small);
	ATF_TP_ADD_TC(tp, write_cmd_malloc_fail);
	ATF_TP_ADD_TC(tp, write_cmd_log);
	ATF_TP_ADD_TC(tp, disp_oom_find_info);
	ATF_TP_ADD_TC(tp, disp_oom_read_by_group);
	ATF_TP_ADD_TC(tp, disp_oom_read_by_type);
	ATF_TP_ADD_TC(tp, disp_oom_read);
	ATF_TP_ADD_TC(tp, disp_oom_read_blob);
	ATF_TP_ADD_TC(tp, disp_oom_find_by_type);
	ATF_TP_ADD_TC(tp, disp_oom_read_multiple);
	ATF_TP_ADD_TC(tp, disp_oom_read_multiple_var);
	ATF_TP_ADD_TC(tp, disp_oom_prepare_write);
	ATF_TP_ADD_TC(tp, disp_find_info_short_no_leak);
	ATF_TP_ADD_TC(tp, notify_oom);
	ATF_TP_ADD_TC(tp, indicate_oom);
	ATF_TP_ADD_TC(tp, multi_ntf_oom);
	ATF_TP_ADD_TC(tp, hash_fetch_fail);
	ATF_TP_ADD_TC(tp, hash_ctx_fail);
	ATF_TP_ADD_TC(tp, hash_init_fail);
	ATF_TP_ADD_TC(tp, hash_update_fail);
	ATF_TP_ADD_TC(tp, hash_update_fail2);
	ATF_TP_ADD_TC(tp, hash_update_fail3);
	ATF_TP_ADD_TC(tp, hash_final_fail);
	ATF_TP_ADD_TC(tp, log_request_paths);
	ATF_TP_ADD_TC(tp, log_recv_confirm);
	ATF_TP_ADD_TC(tp, log_server_dispatch);

	return (atf_no_error());
}
