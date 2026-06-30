/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF unit tests for blued connection lifecycle (conn.c).
 *
 * Tests allocation, deallocation, list membership, address lookup,
 * and kqueue registration of blued_conn objects.
 */

#include <sys/event.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <atf-c.h>
#include <string.h>
#include <unistd.h>

#include "blued.h"
#include "conn.h"

/* ================================================================
 * Stubs for external symbols referenced by conn.c / blued.h
 * ================================================================ */

#include "ble_util.h"
#include "test_common.h"

struct blued_ctx blued_g;
const int _blued_kq_ctl_tag;

/*
 * Reinitialize blued_g to a clean state before each test.
 */
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
}

/*
 * Count connections in blued_g.conns.
 */
static int
conn_count(void)
{
	struct blued_conn *conn;
	int n;

	n = 0;
	LIST_FOREACH(conn, &blued_g.conns, entries)
		n++;
	return (n);
}

/*
 * Check whether a given conn is in blued_g.conns.
 */
static int
conn_in_list(struct blued_conn *target)
{
	struct blued_conn *conn;

	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (conn == target)
			return (1);
	}
	return (0);
}

/* ================================================================
 * Test: blued_conn_alloc returns valid conn with correct defaults
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_alloc);
ATF_TC_BODY(test_conn_alloc, tc)
{
	struct blued_conn *conn;

	test_init();

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	ATF_CHECK_EQ(conn->att_fd, -1);
	ATF_CHECK_EQ(conn->state, BLUED_CONN_IDLE);
	ATF_CHECK_EQ(conn->reconnect_timer, (uintptr_t)0);
	ATF_CHECK(conn_in_list(conn));
	ATF_CHECK_EQ(conn_count(), 1);

	blued_conn_free(conn);
}

/* ================================================================
 * Test: blued_conn_free removes conn from list
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_free);
ATF_TC_BODY(test_conn_free, tc)
{
	struct blued_conn *conn;

	test_init();

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	ATF_CHECK_EQ(conn_count(), 1);

	blued_conn_free(conn);
	ATF_CHECK_EQ(conn_count(), 0);
}

/* ================================================================
 * Test: allocate 3 conns, free middle, verify other 2 remain
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_alloc_multiple);
ATF_TC_BODY(test_conn_alloc_multiple, tc)
{
	struct blued_conn *c1, *c2, *c3;

	test_init();

	c1 = blued_conn_alloc();
	c2 = blued_conn_alloc();
	c3 = blued_conn_alloc();
	ATF_REQUIRE(c1 != NULL);
	ATF_REQUIRE(c2 != NULL);
	ATF_REQUIRE(c3 != NULL);
	ATF_CHECK_EQ(conn_count(), 3);

	blued_conn_free(c2);
	ATF_CHECK_EQ(conn_count(), 2);
	ATF_CHECK(conn_in_list(c1));
	ATF_CHECK(!conn_in_list(c2));
	ATF_CHECK(conn_in_list(c3));

	blued_conn_free(c1);
	blued_conn_free(c3);
}

/* ================================================================
 * Test: blued_conn_by_addr finds a conn by address
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_by_addr_found);
ATF_TC_BODY(test_conn_by_addr_found, tc)
{
	struct blued_conn *conn, *found;
	bdaddr_t addr;

	test_init();

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);

	/* Set a known address: 11:22:33:44:55:66 */
	memset(&addr, 0, sizeof(addr));
	addr.b[0] = 0x11;
	addr.b[1] = 0x22;
	addr.b[2] = 0x33;
	addr.b[3] = 0x44;
	addr.b[4] = 0x55;
	addr.b[5] = 0x66;
	memcpy(&conn->dst, &addr, sizeof(addr));

	found = blued_conn_by_addr(&addr);
	ATF_CHECK(found == conn);

	blued_conn_free(conn);
}

/* ================================================================
 * Test: blued_conn_by_addr returns NULL for unknown address
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_by_addr_not_found);
ATF_TC_BODY(test_conn_by_addr_not_found, tc)
{
	struct blued_conn *conn, *found;
	bdaddr_t known, unknown;

	test_init();

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);

	memset(&known, 0, sizeof(known));
	known.b[0] = 0xAA;
	memcpy(&conn->dst, &known, sizeof(known));

	memset(&unknown, 0, sizeof(unknown));
	unknown.b[0] = 0xBB;

	found = blued_conn_by_addr(&unknown);
	ATF_CHECK(found == NULL);

	blued_conn_free(conn);
}

/* ================================================================
 * Test: blued_conn_register adds conn's fd to kqueue
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_register);
ATF_TC_BODY(test_conn_register, tc)
{
	struct blued_conn *conn;
	struct kevent kev;
	struct timespec ts;
	int sp[2], ret;

	test_init();

	blued_g.kq = kqueue();
	ATF_REQUIRE(blued_g.kq >= 0);

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
	ATF_REQUIRE(ret == 0);

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->att_fd = sp[0];

	ret = blued_conn_register(conn);
	ATF_CHECK_EQ(ret, 0);

	/* Write data on sp[1] so the kevent fires on sp[0] */
	ret = (int)send(sp[1], "X", 1, 0);
	ATF_REQUIRE(ret == 1);

	ts.tv_sec = 1;
	ts.tv_nsec = 0;
	ret = kevent(blued_g.kq, NULL, 0, &kev, 1, &ts);
	ATF_REQUIRE(ret == 1);
	ATF_CHECK_EQ((int)kev.ident, sp[0]);
	ATF_CHECK_EQ(kev.filter, EVFILT_READ);
	ATF_CHECK(kev.udata == conn);

	close(sp[0]);
	close(sp[1]);
	blued_conn_free(conn);
	close(blued_g.kq);
}

/* ================================================================
 * Test: allocate BLUED_MAX_CONNS connections — verify that the limit
 * is enforced by blued_conn_alloc(), and the (MAX+1)th alloc fails.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_pool_exhaustion);
ATF_TC_BODY(test_conn_pool_exhaustion, tc)
{
	struct blued_conn *conns[BLUED_MAX_CONNS];
	struct blued_conn *extra;
	int i;

	test_init();

	for (i = 0; i < BLUED_MAX_CONNS; i++) {
		conns[i] = blued_conn_alloc();
		ATF_REQUIRE_MSG(conns[i] != NULL,
		    "alloc failed at index %d", i);
	}
	ATF_CHECK_EQ(conn_count(), BLUED_MAX_CONNS);

	/* The (MAX+1)th alloc should fail with ENOSPC */
	extra = blued_conn_alloc();
	ATF_CHECK(extra == NULL);

	for (i = 0; i < BLUED_MAX_CONNS; i++)
		blued_conn_free(conns[i]);
	ATF_CHECK_EQ(conn_count(), 0);
}

/* ================================================================
 * Test: blued_conn_set_state transitions and verifies new state
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_set_state);
ATF_TC_BODY(test_conn_set_state, tc)
{
	struct blued_conn *conn;

	test_init();

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	ATF_CHECK_EQ(conn->state, BLUED_CONN_IDLE);

	blued_conn_set_state(conn, BLUED_CONN_CONNECTING);
	ATF_CHECK_EQ(conn->state, BLUED_CONN_CONNECTING);

	blued_conn_set_state(conn, BLUED_CONN_ACTIVE);
	ATF_CHECK_EQ(conn->state, BLUED_CONN_ACTIVE);

	/* Setting same state should be a no-op */
	blued_conn_set_state(conn, BLUED_CONN_ACTIVE);
	ATF_CHECK_EQ(conn->state, BLUED_CONN_ACTIVE);

	blued_conn_set_state(conn, BLUED_CONN_RECONNECTING);
	ATF_CHECK_EQ(conn->state, BLUED_CONN_RECONNECTING);

	blued_conn_free(conn);
}

/* ================================================================
 * Test: blued_conn_by_handle — no such function exists in conn.c.
 * Lookup by handle is done inline in blued.c.  Skipped.
 * ================================================================ */

/* ================================================================
 * Test: blued_conn_free removes conn from the global list
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_free_removes_from_list);
ATF_TC_BODY(test_conn_free_removes_from_list, tc)
{
	struct blued_conn *c1, *c2, *c3;

	test_init();

	c1 = blued_conn_alloc();
	c2 = blued_conn_alloc();
	c3 = blued_conn_alloc();
	ATF_REQUIRE(c1 != NULL);
	ATF_REQUIRE(c2 != NULL);
	ATF_REQUIRE(c3 != NULL);
	ATF_CHECK_EQ(conn_count(), 3);

	/* Free the middle one */
	blued_conn_free(c2);
	ATF_CHECK_EQ(conn_count(), 2);
	ATF_CHECK(!conn_in_list(c2));
	ATF_CHECK(conn_in_list(c1));
	ATF_CHECK(conn_in_list(c3));

	/* Free the first */
	blued_conn_free(c1);
	ATF_CHECK_EQ(conn_count(), 1);
	ATF_CHECK(conn_in_list(c3));

	/* Free the last */
	blued_conn_free(c3);
	ATF_CHECK_EQ(conn_count(), 0);
}

/* ================================================================
 * Test: double free — LIST_REMOVE on an already-removed node is
 * undefined behavior.  blued_conn_free does NOT guard against it.
 * Skipped to avoid UB in test suite.
 * ================================================================ */

/* ================================================================
 * Test: allocate, free, reallocate — verify slot reuse works
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_alloc_after_free);
ATF_TC_BODY(test_conn_alloc_after_free, tc)
{
	struct blued_conn *c1, *c2;

	test_init();

	c1 = blued_conn_alloc();
	ATF_REQUIRE(c1 != NULL);
	ATF_CHECK_EQ(conn_count(), 1);

	blued_conn_free(c1);
	ATF_CHECK_EQ(conn_count(), 0);

	/* Allocate again — should succeed and produce a valid conn */
	c2 = blued_conn_alloc();
	ATF_REQUIRE(c2 != NULL);
	ATF_CHECK_EQ(conn_count(), 1);
	ATF_CHECK(conn_in_list(c2));
	ATF_CHECK_EQ(c2->att_fd, -1);
	ATF_CHECK_EQ(c2->state, BLUED_CONN_IDLE);

	blued_conn_free(c2);
}

/* ================================================================
 * Test: verify initial field values after alloc
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_initial_values);
ATF_TC_BODY(test_conn_initial_values, tc)
{
	struct blued_conn *conn;
	bdaddr_t zero_addr;

	test_init();

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);

	ATF_CHECK_EQ(conn->att_fd, -1);
	ATF_CHECK(conn->att == NULL);
	ATF_CHECK(conn->hogp == NULL);
	ATF_CHECK_EQ(conn->state, BLUED_CONN_IDLE);
	ATF_CHECK_EQ(conn->role, 0);	/* BLUED_ROLE_CENTRAL == 0 */
	ATF_CHECK(conn->att_owned == NULL);
	ATF_CHECK(conn->gatt_db == NULL);
	ATF_CHECK(!conn->reconnect);
	ATF_CHECK_EQ(conn->reconnect_delay, 0);
	ATF_CHECK_EQ(conn->reconnect_timer, 0);
	ATF_CHECK_EQ(conn->idle_timer, 0);
	ATF_CHECK_EQ(conn->con_handle, 0);
	ATF_CHECK_EQ(conn->addr_type, 0);
	ATF_CHECK(conn->adapter == NULL);

	/* dst should be zero (calloc) */
	memset(&zero_addr, 0, sizeof(zero_addr));
	ATF_CHECK(memcmp(&conn->dst, &zero_addr, sizeof(zero_addr)) == 0);

	blued_conn_free(conn);
}

/* ================================================================
 * Test: set state through full lifecycle
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_state_lifecycle);
ATF_TC_BODY(test_conn_state_lifecycle, tc)
{
	struct blued_conn *conn;

	test_init();

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);

	/* Walk through the full state machine */
	ATF_CHECK_EQ(conn->state, BLUED_CONN_IDLE);

	blued_conn_set_state(conn, BLUED_CONN_CONNECTING);
	ATF_CHECK_EQ(conn->state, BLUED_CONN_CONNECTING);

	blued_conn_set_state(conn, BLUED_CONN_ACTIVE);
	ATF_CHECK_EQ(conn->state, BLUED_CONN_ACTIVE);

	blued_conn_set_state(conn, BLUED_CONN_IDLE);
	ATF_CHECK_EQ(conn->state, BLUED_CONN_IDLE);

	blued_conn_set_state(conn, BLUED_CONN_RECONNECTING);
	ATF_CHECK_EQ(conn->state, BLUED_CONN_RECONNECTING);

	blued_conn_free(conn);
}

/* ================================================================
 * Test: blued_conn_state_name returns correct strings for each state.
 *
 * blued_conn_state_name is static in conn.c, so we test it indirectly
 * by verifying that blued_conn_set_state correctly transitions between
 * all named states without crash.  The name strings are used in logging
 * which we don't capture, but the transitions exercise every switch case.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_state_name);
ATF_TC_BODY(test_conn_state_name, tc)
{
	struct blued_conn *conn;
	int states[] = {
		BLUED_CONN_IDLE,
		BLUED_CONN_CONNECTING,
		BLUED_CONN_ACTIVE,
		BLUED_CONN_RECONNECTING,
		99, /* unknown — exercises default case */
	};
	int i;

	test_init();

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);

	/*
	 * Walk through all states including an invalid one (99).
	 * The function should handle the unknown state via the
	 * "UNKNOWN" default case without crashing.
	 */
	for (i = 0; i < (int)(sizeof(states) / sizeof(states[0])); i++) {
		blued_conn_set_state(conn, states[i]);
		ATF_CHECK_EQ(conn->state, states[i]);
	}

	/* Transition back to a known state */
	blued_conn_set_state(conn, BLUED_CONN_IDLE);
	ATF_CHECK_EQ(conn->state, BLUED_CONN_IDLE);

	blued_conn_free(conn);
}

/* ================================================================
 * Test: allocate BLUED_MAX_CONNS, verify next alloc returns NULL,
 * free one, verify alloc succeeds again, then free all.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_alloc_max);
ATF_TC_BODY(test_conn_alloc_max, tc)
{
	struct blued_conn *conns[BLUED_MAX_CONNS];
	struct blued_conn *extra, *recycled;
	int i;

	test_init();

	/* Fill to capacity */
	for (i = 0; i < BLUED_MAX_CONNS; i++) {
		conns[i] = blued_conn_alloc();
		ATF_REQUIRE_MSG(conns[i] != NULL,
		    "alloc failed at index %d", i);
	}
	ATF_CHECK_EQ(conn_count(), BLUED_MAX_CONNS);

	/* Next alloc should fail */
	extra = blued_conn_alloc();
	ATF_CHECK(extra == NULL);

	/* Free one slot and verify alloc succeeds again */
	blued_conn_free(conns[0]);
	ATF_CHECK_EQ(conn_count(), BLUED_MAX_CONNS - 1);

	recycled = blued_conn_alloc();
	ATF_CHECK(recycled != NULL);
	ATF_CHECK_EQ(conn_count(), BLUED_MAX_CONNS);

	/* Clean up: free recycled + remaining */
	blued_conn_free(recycled);
	for (i = 1; i < BLUED_MAX_CONNS; i++)
		blued_conn_free(conns[i]);
	ATF_CHECK_EQ(conn_count(), 0);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_conn_alloc);
	ATF_TP_ADD_TC(tp, test_conn_free);
	ATF_TP_ADD_TC(tp, test_conn_alloc_multiple);
	ATF_TP_ADD_TC(tp, test_conn_by_addr_found);
	ATF_TP_ADD_TC(tp, test_conn_by_addr_not_found);
	ATF_TP_ADD_TC(tp, test_conn_register);
	ATF_TP_ADD_TC(tp, test_conn_pool_exhaustion);
	ATF_TP_ADD_TC(tp, test_conn_set_state);
	ATF_TP_ADD_TC(tp, test_conn_free_removes_from_list);
	ATF_TP_ADD_TC(tp, test_conn_alloc_after_free);
	ATF_TP_ADD_TC(tp, test_conn_initial_values);
	ATF_TP_ADD_TC(tp, test_conn_state_lifecycle);
	ATF_TP_ADD_TC(tp, test_conn_state_name);
	ATF_TP_ADD_TC(tp, test_conn_alloc_max);

	return (atf_no_error());
}
