/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Deep-coverage unit tests for blued connection lifecycle (conn.c).
 *
 * conn_test.c covers the common alloc/free/by_addr/register/set_state paths.
 * This file drives the residual branch arms those tests leave uncovered:
 *   - blued_conn_free(NULL) early return;
 *   - blued_conn_free() of a peripheral conn whose att_owned owns a live fd
 *     (the close() arm) and, separately, a NULL value buffer;
 *   - blued_conn_free() of a conn that was never inserted on the list
 *     (le_prev == NULL: the LIST_REMOVE guard skip);
 *   - blued_conn_set_state() with verbosity raised so the state-name switch
 *     (reached only inside the LOG_HOGP argument) is actually evaluated for
 *     every named state plus the UNKNOWN default.
 *
 * Oracle: conn.h contract and the documented lifecycle semantics; no live
 * Bluetooth hardware is required.
 */

#include <sys/event.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdatomic.h>
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

static void
test_init(void)
{

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
 * blued_conn_free(NULL) must be a no-op (early return).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_conn_free_null);
ATF_TC_BODY(deep_conn_free_null, tc)
{

	test_init();
	blued_conn_free(NULL);		/* must not crash */
	ATF_CHECK_EQ(conn_count(), 0);
}

/* ================================================================
 * Peripheral-style conn: att_owned owns a real fd + value buffer.
 * blued_conn_free must close the fd (fd >= 0 arm) and free the buffer.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_conn_free_att_owned_closes_fd);
ATF_TC_BODY(deep_conn_free_att_owned_closes_fd, tc)
{
	struct blued_conn *conn;
	struct att_conn *ac;
	int devnull;

	test_init();

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);

	devnull = open("/dev/null", O_RDWR);
	ATF_REQUIRE(devnull >= 0);

	ac = calloc(1, sizeof(*ac));
	ATF_REQUIRE(ac != NULL);
	ac->fd = devnull;		/* fd >= 0: exercises the close() arm */
	ac->buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
	conn->att_owned = ac;

	blued_conn_free(conn);
	ATF_CHECK_EQ(conn_count(), 0);

	/* The fd must have been closed by free(); re-close should fail. */
	ATF_CHECK(close(devnull) == -1);
}

/* ================================================================
 * att_owned with a NULL value buffer: the buf != NULL arm is not taken,
 * and fd < 0 means the close() arm is skipped.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_conn_free_att_owned_null_buf);
ATF_TC_BODY(deep_conn_free_att_owned_null_buf, tc)
{
	struct blued_conn *conn;
	struct att_conn *ac;

	test_init();

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);

	ac = calloc(1, sizeof(*ac));
	ATF_REQUIRE(ac != NULL);
	ac->fd = -1;			/* no fd to close */
	ac->buf = NULL;			/* buf == NULL arm */
	conn->att_owned = ac;

	blued_conn_free(conn);
	ATF_CHECK_EQ(conn_count(), 0);
}

/* ================================================================
 * A conn that was never inserted on blued_g.conns (le_prev == NULL):
 * the double-free guard must skip LIST_REMOVE and still free the node.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_conn_free_not_on_list);
ATF_TC_BODY(deep_conn_free_not_on_list, tc)
{
	struct blued_conn *conn;

	test_init();

	/* calloc (not blued_conn_alloc): entries.le_prev stays NULL. */
	conn = calloc(1, sizeof(*conn));
	ATF_REQUIRE(conn != NULL);
	conn->att_fd = -1;
	ATF_CHECK(conn->entries.le_prev == NULL);

	blued_conn_free(conn);		/* must not touch the (empty) list */
	ATF_CHECK_EQ(conn_count(), 0);
}

/* ================================================================
 * set_state with verbosity >= 1 forces the LOG_HOGP argument to be
 * evaluated, exercising blued_conn_state_name() for every named state
 * plus the UNKNOWN default case.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_conn_set_state_names_logged);
ATF_TC_BODY(deep_conn_set_state_names_logged, tc)
{
	struct blued_conn *conn;

	test_init();
	blued_verbose = 1;		/* make LOG_HOGP(1, ...) evaluate args */

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);

	/* old==IDLE -> CONNECTING: names IDLE + CONNECTING */
	blued_conn_set_state(conn, BLUED_CONN_CONNECTING);
	/* -> ACTIVE */
	blued_conn_set_state(conn, BLUED_CONN_ACTIVE);
	/* -> RECONNECTING */
	blued_conn_set_state(conn, BLUED_CONN_RECONNECTING);
	/* -> IDLE (back through named states) */
	blued_conn_set_state(conn, BLUED_CONN_IDLE);
	/* -> 99: exercises the UNKNOWN default arm for new_state */
	blued_conn_set_state(conn, 99);
	ATF_CHECK_EQ(atomic_load(&conn->state), 99);
	/* 99 -> IDLE: old_state now hits the UNKNOWN default arm too */
	blued_conn_set_state(conn, BLUED_CONN_IDLE);
	ATF_CHECK_EQ(atomic_load(&conn->state), BLUED_CONN_IDLE);

	blued_verbose = 0;
	blued_conn_free(conn);
}

/* ================================================================
 * blued_conn_register() on a conn whose att_fd is still < 0 must fail
 * fast (the att_fd < 0 guard) without touching the kqueue.  A freshly
 * alloc'd conn has att_fd == -1 (conn.c default), so no fd is required.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_conn_register_att_fd_negative);
ATF_TC_BODY(deep_conn_register_att_fd_negative, tc)
{
	struct blued_conn *conn;

	test_init();
	blued_g.kq = kqueue();
	ATF_REQUIRE(blued_g.kq >= 0);

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	ATF_REQUIRE_EQ(conn->att_fd, -1);	/* default: no ATT fd yet */

	/* att_fd < 0 -> register must return -1 and register nothing. */
	ATF_CHECK_EQ(blued_conn_register(conn), -1);

	blued_conn_free(conn);
	close(blued_g.kq);
}

/* ================================================================
 * blued_conn_register() with a valid att_fd but a broken kqueue fd:
 * the kevent(2) call fails, so register must surface -1.  Drives the
 * "kevent < 0" error arm (and the EV_SET fill) that the success-path
 * register test in conn_test.c leaves uncovered.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_conn_register_kevent_fails);
ATF_TC_BODY(deep_conn_register_kevent_fails, tc)
{
	struct blued_conn *conn;
	int fd;

	test_init();			/* leaves blued_g.kq == -1 */

	fd = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fd >= 0);

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->att_fd = fd;		/* >= 0: passes the att_fd guard */

	/* kq == -1 -> kevent(2) returns -1 (EBADF) -> register fails. */
	ATF_CHECK_EQ(blued_conn_register(conn), -1);

	blued_conn_free(conn);
	close(fd);
}

/* ================================================================
 * set_state with the daemon flag raised: the LOG_HOGP expansion takes
 * its syslog() arm (blued_daemonized != 0) instead of the stderr arm,
 * covering that macro branch.  Behaviour (the state transition) is
 * unchanged; only the log sink differs.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_conn_set_state_daemonized);
ATF_TC_BODY(deep_conn_set_state_daemonized, tc)
{
	struct blued_conn *conn;

	test_init();
	blued_verbose = 1;
	blued_daemonized = 1;		/* LOG_HOGP -> syslog() arm */

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);

	blued_conn_set_state(conn, BLUED_CONN_CONNECTING);
	ATF_CHECK_EQ(atomic_load(&conn->state), BLUED_CONN_CONNECTING);

	blued_daemonized = 0;
	blued_verbose = 0;
	blued_conn_free(conn);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, deep_conn_free_null);
	ATF_TP_ADD_TC(tp, deep_conn_free_att_owned_closes_fd);
	ATF_TP_ADD_TC(tp, deep_conn_free_att_owned_null_buf);
	ATF_TP_ADD_TC(tp, deep_conn_free_not_on_list);
	ATF_TP_ADD_TC(tp, deep_conn_set_state_names_logged);
	ATF_TP_ADD_TC(tp, deep_conn_register_att_fd_negative);
	ATF_TP_ADD_TC(tp, deep_conn_register_kevent_fails);
	ATF_TP_ADD_TC(tp, deep_conn_set_state_daemonized);

	return (atf_no_error());
}
