/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Fault-injection coverage for the syscall / allocator FAILURE arms of the
 * libble client entry points ble_open() and ble_open_fd().
 *
 * ble.c (lib/libble):
 *   ble_open():     socket() < 0        -> return NULL   (ble.c:614)
 *                   calloc() == NULL     -> return NULL   (ble.c:627)
 *   ble_open_fd():  calloc() == NULL     -> return NULL   (ble.c:641)
 *
 * These branches handle real runtime failures (fd exhaustion, OOM) and are
 * unreachable in a healthy process.  We reach them with a linker --wrap(3)
 * seam on socket() and calloc(): each wrapper fails the Nth (1-based) call
 * when armed and otherwise tail-calls __real_<sym>.
 *
 * Oracle: ble.h documents ble_open()/ble_open_fd() as returning a ble_ctx_t *
 * or NULL on failure (the "// connect to default socket" usage note and the
 * BLE_ERR_* table).  Because the failure occurs before/at context allocation
 * there is no ctx on which to record a BLE_ERR_* code, so the observable
 * contract is a NULL return.
 *
 * Links with: ble.c
 * CFLAGS: -I${SRCTOP}/lib/libble
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <atf-c.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ble.h"
#include "ipc_proto.h"

/* ================================================================
 * Fault-injection seam (fail the Nth 1-based call when armed).
 * --wrap only intercepts references emitted from ble.c and this test;
 * libc-internal socket()/calloc() calls are unaffected.
 * ================================================================ */
static long	fi_socket_at, fi_socket_n;
static long	fi_calloc_at, fi_calloc_n;
static long	fi_malloc_at, fi_malloc_n;

static int
fi_hit(long *at, long *n)
{

	(*n)++;
	return (*at != 0 && *n == *at);
}

static void
fault_reset(void)
{

	fi_socket_at = fi_socket_n = 0;
	fi_calloc_at = fi_calloc_n = 0;
	fi_malloc_at = fi_malloc_n = 0;
}

extern int	__real_socket(int, int, int);
int
__wrap_socket(int domain, int type, int protocol)
{

	if (fi_hit(&fi_socket_at, &fi_socket_n)) {
		errno = EMFILE;		/* plausible: descriptor exhaustion */
		return (-1);
	}
	return (__real_socket(domain, type, protocol));
}

extern void	*__real_calloc(size_t, size_t);
void *
__wrap_calloc(size_t nmemb, size_t size)
{

	if (fi_hit(&fi_calloc_at, &fi_calloc_n)) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_calloc(nmemb, size));
}

extern void	*__real_malloc(size_t);
void *
__wrap_malloc(size_t size)
{

	if (fi_hit(&fi_malloc_at, &fi_malloc_n)) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_malloc(size));
}

/* ================================================================
 * Helper: a bound+listening AF_UNIX socket so ble_open() can connect()
 * successfully and thus reach its calloc() arm.
 * ================================================================ */
static int	g_listener = -1;
static char	g_sockpath[104];
static pthread_t g_responder;
static bool	g_responder_active;

/*
 * Server side of the framed HELLO handshake so that a successful ble_open()
 * (which now completes the handshake) does not block: accept one connection
 * and answer the client's HELLO with our version and event capability.  If the
 * client closes early (e.g. ble_open failed at its calloc arm before sending
 * HELLO), recv() returns EOF and the thread exits cleanly.
 */
static void *
fault_hello_responder(void *arg)
{
	int lfd = *(int *)arg;
	struct pollfd pfd;
	uint8_t hdr[IPC_HDR_SIZE];
	uint8_t rh[IPC_HDR_SIZE];
	uint8_t features[IPC_HELLO_FEATURES_SIZE];
	uint32_t plen;
	uint16_t type, harg;
	size_t got;
	int c;

	pfd.fd = lfd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 3000) <= 0)
		return (NULL);
	c = accept(lfd, NULL, NULL);
	if (c < 0)
		return (NULL);

	got = 0;
	while (got < IPC_HDR_SIZE) {
		ssize_t r = recv(c, hdr + got, IPC_HDR_SIZE - got, 0);

		if (r <= 0) {
			close(c);
			return (NULL);
		}
		got += (size_t)r;
	}
	ipc_hdr_decode(hdr, &plen, &type, &harg);
	while (plen > 0) {
		uint8_t tmp[64];
		size_t want = (plen < sizeof(tmp)) ? plen : sizeof(tmp);
		ssize_t r = recv(c, tmp, want, 0);

		if (r <= 0)
			break;
		plen -= (uint32_t)r;
	}

	ipc_put_le32(features, IPC_FEATURE_EVENTS);
	ipc_hdr_encode(rh, sizeof(features), IPC_T_HELLO,
	    IPC_PROTO_VERSION);
	(void)write(c, rh, sizeof(rh));
	(void)write(c, features, sizeof(features));
	close(c);
	return (NULL);
}

static void
start_listener(void)
{
	struct sockaddr_un sun;
	int fd;

	snprintf(g_sockpath, sizeof(g_sockpath),
	    "/tmp/blued_fault_ble.%d.sock", (int)getpid());
	unlink(g_sockpath);

	fd = __real_socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(fd >= 0);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, g_sockpath, sizeof(sun.sun_path));
	ATF_REQUIRE_EQ(0, bind(fd, (struct sockaddr *)&sun, sizeof(sun)));
	ATF_REQUIRE_EQ(0, listen(fd, 4));
	g_listener = fd;

	/*
	 * Spawn the handshake responder now, before any fault is armed, so its
	 * pthread setup allocations are never intercepted by the calloc seam.
	 */
	g_responder_active =
	    (pthread_create(&g_responder, NULL, fault_hello_responder,
	    &g_listener) == 0);
}

static void
stop_listener(void)
{

	if (g_responder_active) {
		(void)pthread_join(g_responder, NULL);
		g_responder_active = false;
	}
	if (g_listener >= 0)
		close(g_listener);
	unlink(g_sockpath);
	g_listener = -1;
}

/* ================================================================
 * ble_open(): socket() < 0 -> NULL (ble.c:614)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ble_open_socket_fail);
ATF_TC_BODY(ble_open_socket_fail, tc)
{
	ble_ctx_t *ctx;

	start_listener();

	/* Arm the next socket() call (the one inside ble_open) to fail. */
	fault_reset();
	fi_socket_at = 1;
	ctx = ble_open(g_sockpath);
	ATF_CHECK_MSG(ctx == NULL,
	    "ble_open must return NULL when socket() fails");

	/* Sanity: with no fault, the same call succeeds (connect + calloc). */
	fault_reset();
	ctx = ble_open(g_sockpath);
	ATF_CHECK_MSG(ctx != NULL, "baseline ble_open should succeed");
	ble_close(ctx);

	stop_listener();
}

/* ================================================================
 * ble_open(): calloc() == NULL -> NULL (ble.c:627), after a successful
 * socket()+connect().
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ble_open_calloc_fail);
ATF_TC_BODY(ble_open_calloc_fail, tc)
{
	ble_ctx_t *ctx;

	start_listener();

	fault_reset();
	fi_calloc_at = 1;		/* first calloc = ctx allocation */
	ctx = ble_open(g_sockpath);
	ATF_CHECK_MSG(ctx == NULL,
	    "ble_open must return NULL when ctx calloc() fails");

	stop_listener();
}

/* ================================================================
 * ble_open_fd(): calloc() == NULL -> NULL (ble.c:641).
 * No socket/connect needed.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ble_open_fd_calloc_fail);
ATF_TC_BODY(ble_open_fd_calloc_fail, tc)
{
	ble_ctx_t *ctx;
	int fds[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

	fault_reset();
	fi_calloc_at = 1;
	ctx = ble_open_fd(fds[0]);
	ATF_CHECK_MSG(ctx == NULL,
	    "ble_open_fd must return NULL when ctx calloc() fails");

	/* Baseline: succeeds and takes ownership of the fd. */
	fault_reset();
	ctx = ble_open_fd(fds[1]);
	ATF_CHECK_MSG(ctx != NULL, "baseline ble_open_fd should succeed");
	ble_close(ctx);		/* closes fds[1] */

	close(fds[0]);
}

ATF_TC_WITHOUT_HEAD(operation_state_calloc_failures);
ATF_TC_BODY(operation_state_calloc_failures, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	ble_scan_params_t scan;

	start_listener();
	fault_reset();
	ctx = ble_open(g_sockpath);
	ATF_REQUIRE_MSG(ctx != NULL, "baseline handshake must succeed");
	stop_listener();
	memset(&addr, 0, sizeof(addr));
	memset(&scan, 0, sizeof(scan));

#define CHECK_CALLOC_FAILURE(call) do { \
	fault_reset(); \
	fi_calloc_at = 1; \
	ATF_CHECK_EQ_MSG(-1, (call), "%s must reject state-allocation OOM", \
	    #call); \
	ATF_CHECK_EQ_MSG(BLE_ERR_NOMEM, ble_errno(ctx), \
	    "%s must preserve BLE_ERR_NOMEM", #call); \
} while (0)

	CHECK_CALLOC_FAILURE(ble_scan_filtered(ctx, &scan, NULL, NULL));
	CHECK_CALLOC_FAILURE(ble_connect(ctx, &addr, NULL, NULL));
	CHECK_CALLOC_FAILURE(ble_connect_name(ctx, 0, "sensor", NULL, NULL));
	CHECK_CALLOC_FAILURE(ble_discover(ctx, &addr, NULL, NULL));
	CHECK_CALLOC_FAILURE(ble_read(ctx, &addr, 1, NULL, NULL));
	CHECK_CALLOC_FAILURE(ble_read_battery(ctx, &addr, NULL, NULL));

#undef CHECK_CALLOC_FAILURE
	fault_reset();
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(bond_record_allocation_failures);
ATF_TC_BODY(bond_record_allocation_failures, tc)
{
	ble_bond_record_t *rec;
	ble_ctx_t *ctx;
	uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	fault_reset();
	fi_calloc_at = 1;
	ATF_CHECK_EQ(NULL, ble_bond_record_from_data(data, sizeof(data)));

	fault_reset();
	fi_malloc_at = 1;
	ATF_CHECK_EQ(NULL, ble_bond_record_from_data(data, sizeof(data)));

	fault_reset();
	rec = ble_bond_record_from_data(data, sizeof(data));
	ATF_REQUIRE(rec != NULL);
	start_listener();
	ctx = ble_open(g_sockpath);
	ATF_REQUIRE(ctx != NULL);
	stop_listener();
	fault_reset();
	fi_calloc_at = 1;
	ATF_CHECK_EQ(-1, ble_bond_import(ctx, rec));
	ATF_CHECK_EQ(BLE_ERR_NOMEM, ble_errno(ctx));
	fault_reset();
	ble_bond_record_free(rec);
	ble_close(ctx);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, ble_open_socket_fail);
	ATF_TP_ADD_TC(tp, ble_open_calloc_fail);
	ATF_TP_ADD_TC(tp, ble_open_fd_calloc_fail);
	ATF_TP_ADD_TC(tp, operation_state_calloc_failures);
	ATF_TP_ADD_TC(tp, bond_record_allocation_failures);

	return (atf_no_error());
}
