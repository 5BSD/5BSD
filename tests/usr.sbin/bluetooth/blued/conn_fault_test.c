/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Fault-injection coverage for the allocator FAILURE arm of the blued
 * connection allocator.
 *
 * conn.c (usr.sbin/bluetooth/blued):
 *   blued_conn_alloc(): calloc() == NULL -> return NULL   (conn.c:68)
 *
 * This branch handles a real OOM at connection-object allocation and is
 * unreachable in a healthy process.  We reach it with a linker --wrap(3)
 * seam on calloc(): the wrapper fails the Nth (1-based) call when armed and
 * otherwise tail-calls __real_calloc().  --wrap only redirects the calloc
 * references emitted from conn.o and this test object; libc/libpthread
 * internal allocations are unaffected.
 *
 * Oracle: conn.h documents blued_conn_alloc() as returning a struct
 * blued_conn * or NULL on failure.  When the object allocation itself fails
 * the observable contract is a NULL return with the connection list left
 * unchanged (no partial insertion).
 *
 * Links with: conn.c
 * LDFLAGS: -Wl,--wrap=calloc
 */

#include <sys/event.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <atf-c.h>
#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "blued.h"
#include "conn.h"

#include "ble_util.h"
#include "test_common.h"

struct blued_ctx blued_g;
const int _blued_kq_ctl_tag;
const int _blued_kq_acquire_tag;

/* ================================================================
 * Fault-injection seam: fail the Nth (1-based) calloc when armed.
 * ================================================================ */
static long	fi_calloc_at, fi_calloc_n;

static void
fault_reset(void)
{

	fi_calloc_at = fi_calloc_n = 0;
}

extern void	*__real_calloc(size_t, size_t);
void *
__wrap_calloc(size_t nmemb, size_t size)
{

	fi_calloc_n++;
	if (fi_calloc_at != 0 && fi_calloc_n == fi_calloc_at) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_calloc(nmemb, size));
}

static void
test_init(void)
{

	fault_reset();
	memset(&blued_g, 0, sizeof(blued_g));
	blued_g.kq = -1;
	blued_g.ctl_fd = -1;
	blued_g.bond_fd = -1;
	blued_g.vhid_ctl_fd = -1;
	LIST_INIT(&blued_g.adapters);
	LIST_INIT(&blued_g.conns);
	LIST_INIT(&blued_g.ctl_clients);
	pthread_rwlock_init(&blued_g.conns_lock, NULL);
}

static int
conn_count(void)
{
	struct blued_conn *conn;
	int n = 0;

	LIST_FOREACH(conn, &blued_g.conns, entries)
		n++;
	return (n);
}

/* ================================================================
 * calloc() fails inside blued_conn_alloc(): the allocator returns NULL
 * (conn.c:68) and the connection list is left empty.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_conn_alloc_calloc_fail);
ATF_TC_BODY(fault_conn_alloc_calloc_fail, tc)
{
	struct blued_conn *conn;

	test_init();

	/* Arm: the very next calloc (the one in blued_conn_alloc) fails. */
	fi_calloc_n = 0;
	fi_calloc_at = 1;
	conn = blued_conn_alloc();
	fi_calloc_at = 0;

	ATF_CHECK(conn == NULL);		/* NULL-return contract */
	ATF_CHECK_EQ(conn_count(), 0);		/* nothing inserted */
}

/* ================================================================
 * Control: with the seam disarmed, blued_conn_alloc() succeeds and the
 * conn lands on the list — confirms the wrapper is transparent when not
 * armed and that the failure above was solely allocator-driven.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_conn_alloc_succeeds_when_disarmed);
ATF_TC_BODY(fault_conn_alloc_succeeds_when_disarmed, tc)
{
	struct blued_conn *conn;

	test_init();

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	ATF_CHECK_EQ(conn->att_fd, -1);
	ATF_CHECK_EQ(conn_count(), 1);

	blued_conn_free(conn);
	ATF_CHECK_EQ(conn_count(), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fault_conn_alloc_calloc_fail);
	ATF_TP_ADD_TC(tp, fault_conn_alloc_succeeds_when_disarmed);

	return (atf_no_error());
}
