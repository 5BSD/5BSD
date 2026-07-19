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
#include <sys/param.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <atf-c.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "blued.h"
#include "conn.h"

/* ================================================================
 * Stubs for external symbols referenced by conn.c / blued.h
 * ================================================================ */

#include "ble_util.h"
#define TEST_CUSTOM_BLE_ECBFC_CONNECT
#include "test_common.h"

struct blued_ctx blued_g;
const int _blued_kq_ctl_tag;
const int _blued_kq_acquire_tag;

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
 * Test: blued_conn_by_peer finds an exact adapter-local peer
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_by_addr_found);
ATF_TC_BODY(test_conn_by_addr_found, tc)
{
	struct blued_conn *conn, *found;
	struct blued_adapter adapter = { .index = 0 };
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
	conn->adapter = &adapter;
	conn->addr_type = BDADDR_LE_PUBLIC;

	found = blued_conn_by_peer(&adapter, &addr, BDADDR_LE_PUBLIC);
	ATF_CHECK(found == conn);

	blued_conn_free(conn);
}

/* ================================================================
 * Test: blued_conn_by_peer returns NULL for an unknown peer
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_by_addr_not_found);
ATF_TC_BODY(test_conn_by_addr_not_found, tc)
{
	struct blued_conn *conn, *found;
	struct blued_adapter adapter = { .index = 0 };
	bdaddr_t known, unknown;

	test_init();

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);

	memset(&known, 0, sizeof(known));
	known.b[0] = 0xAA;
	memcpy(&conn->dst, &known, sizeof(known));
	conn->adapter = &adapter;
	conn->addr_type = BDADDR_LE_PUBLIC;

	memset(&unknown, 0, sizeof(unknown));
	unknown.b[0] = 0xBB;

	found = blued_conn_by_peer(&adapter, &unknown, BDADDR_LE_PUBLIC);
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

/* Central registration includes every already-open enhanced ATT bearer. */
ATF_TC_WITHOUT_HEAD(test_conn_register_eatt);
ATF_TC_BODY(test_conn_register_eatt, tc)
{
	struct att_conn ac;
	struct blued_conn *conn;
	struct kevent ev[2];
	struct timespec ts = { 1, 0 };
	int fixed[2], enhanced[2], n;

	test_init();
	blued_g.kq = kqueue();
	ATF_REQUIRE(blued_g.kq >= 0);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fixed));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, enhanced));

	memset(&ac, 0, sizeof(ac));
	ac.fd = fixed[0];
	ac.mtu = ATT_DEFAULT_MTU;
	ac.eatt_count = 1;
	ac.eatt[0].fd = enhanced[0];
	ac.eatt[0].mtu = 128;
	ac.eatt[0].active = true;

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->att_fd = fixed[0];
	conn->att = &ac;
	ATF_REQUIRE_EQ(0, blued_conn_register(conn));
	ATF_REQUIRE_EQ(1, send(fixed[1], "F", 1, 0));
	ATF_REQUIRE_EQ(1, send(enhanced[1], "E", 1, 0));

	n = kevent(blued_g.kq, NULL, 0, ev, nitems(ev), &ts);
	ATF_REQUIRE_EQ(2, n);
	ATF_CHECK(ev[0].udata == conn);
	ATF_CHECK(ev[1].udata == conn);
	ATF_CHECK((int)ev[0].ident == fixed[0] ||
	    (int)ev[1].ident == fixed[0]);
	ATF_CHECK((int)ev[0].ident == enhanced[0] ||
	    (int)ev[1].ident == enhanced[0]);

	blued_conn_unregister_att(conn);
	close(fixed[0]);
	close(fixed[1]);
	close(enhanced[0]);
	close(enhanced[1]);
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

	/*
	 * The (MAX+1)th alloc must fail and set errno=ENOSPC.
	 * Contract: conn.c blued_conn_alloc() enforces BLUED_MAX_CONNS and
	 * sets errno = ENOSPC before returning NULL (conn.c:82-86).
	 */
	errno = 0;
	extra = blued_conn_alloc();
	ATF_CHECK(extra == NULL);
	ATF_CHECK_EQ(errno, ENOSPC);

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
	ATF_CHECK(!conn->con_handle_valid);
	ATF_CHECK_EQ(conn->addr_type, 0);
	ATF_CHECK(conn->adapter == NULL);

	/* dst should be zero (calloc) */
	memset(&zero_addr, 0, sizeof(zero_addr));
	ATF_CHECK(memcmp(&conn->dst, &zero_addr, sizeof(zero_addr)) == 0);

	blued_conn_free(conn);
}

/* Handle 0x0000 is valid and must be associated by peer, not zero defaults. */
ATF_TC_WITHOUT_HEAD(test_handle_zero_is_valid_and_peer_scoped);
ATF_TC_BODY(test_handle_zero_is_valid_and_peer_scoped, tc)
{
	static const uint8_t peer[6] = { 0x70, 2, 3, 4, 5, 6 };
	static const uint8_t other_peer[6] = { 0x71, 2, 3, 4, 5, 6 };
	static const uint8_t local_rpa[6] = { 0x42, 8, 9, 10, 11, 12 };
	static const uint8_t zero[6];
	struct blued_adapter adapter;
	struct blued_conn *actual, *pending;

	test_init();
	memset(&adapter, 0, sizeof(adapter));
	actual = blued_conn_alloc();
	pending = blued_conn_alloc(); /* list head: would steal a zero match */
	ATF_REQUIRE(actual != NULL && pending != NULL);
	actual->adapter = pending->adapter = &adapter;
	actual->addr_type = pending->addr_type = BDADDR_LE_PUBLIC;
	memcpy(&actual->dst, peer, 6);
	memcpy(&pending->dst, other_peer, 6);

	blued_conn_note_enhanced(&adapter, 0x0000, peer, 0,
	    local_rpa, zero);
	ATF_CHECK(actual->con_handle_valid);
	ATF_CHECK_EQ(0x0000, actual->con_handle);
	ATF_CHECK_EQ(actual, blued_conn_by_handle(&adapter, 0x0000));
	ATF_CHECK(!pending->con_handle_valid);
	ATF_CHECK(!pending->local_addr_from_hci);

	blued_conn_free(pending);
	blued_conn_free(actual);
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

	/*
	 * Next alloc must fail with errno=ENOSPC.
	 * Contract: conn.c blued_conn_alloc() sets errno = ENOSPC when the
	 * connection pool is at BLUED_MAX_CONNS (conn.c:82-86).
	 */
	errno = 0;
	extra = blued_conn_alloc();
	ATF_CHECK(extra == NULL);
	ATF_CHECK_EQ(errno, ENOSPC);

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
 * F1: a reference taken by a setup thread keeps the connection alive
 * across a racing teardown.  blued_conn_free drops the list reference
 * but must not free memory while another owner still holds a reference;
 * the object is released only when the final reference is dropped.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_refcount_survives_free_with_ref);
ATF_TC_BODY(test_conn_refcount_survives_free_with_ref, tc)
{
	struct blued_conn *conn;

	test_init();

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);

	/* A detached setup thread takes a reference before it runs. */
	blued_conn_ref(conn);

	/* Teardown races the thread: the list reference is dropped. */
	blued_conn_free(conn);
	ATF_CHECK_EQ(0, conn_count());
	ATF_CHECK(!conn_in_list(conn));

	/*
	 * The object must still be valid to the reference holder — reading
	 * a field here would be a use-after-free if free() had released it.
	 */
	ATF_CHECK_EQ(-1, conn->att_fd);

	/* Dropping the final reference frees it cleanly (no double free). */
	blued_conn_unref(conn);
}

/* ================================================================
 * F19: blued_conn_free must EV_DELETE the conn-owned reconnect and idle
 * timers (they carry conn as kevent udata) before the connection can be
 * freed, so a later timer fire cannot dereference freed memory.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_conn_free_deletes_timers);
ATF_TC_BODY(test_conn_free_deletes_timers, tc)
{
	struct blued_conn *conn;
	struct kevent kev;
	int kq;

	test_init();

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	blued_g.kq = kq;

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);

	/* Arm both conn-owned timers with conn as udata. */
	conn->reconnect_timer = 0x1000;
	EV_SET(&kev, conn->reconnect_timer, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS, 3600, conn);
	ATF_REQUIRE_EQ(0, kevent(kq, &kev, 1, NULL, 0, NULL));

	conn->idle_timer = 0x1001;
	EV_SET(&kev, conn->idle_timer, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS, 3600, conn);
	ATF_REQUIRE_EQ(0, kevent(kq, &kev, 1, NULL, 0, NULL));

	blued_conn_free(conn);

	/* Both timers must already be gone: a second EV_DELETE -> ENOENT. */
	EV_SET(&kev, 0x1000, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	errno = 0;
	ATF_CHECK_EQ(-1, kevent(kq, &kev, 1, NULL, 0, NULL));
	ATF_CHECK_EQ(ENOENT, errno);

	EV_SET(&kev, 0x1001, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	errno = 0;
	ATF_CHECK_EQ(-1, kevent(kq, &kev, 1, NULL, 0, NULL));
	ATF_CHECK_EQ(ENOENT, errno);

	close(kq);
}

/* ================================================================
 * F2/F3: controller loss (HCI fd EOF) must not busy-spin the event
 * loop.  A readable-registered fd whose peer has closed reports EV_EOF
 * on every kqueue pass until it is EV_DELETEd — exactly the spin the
 * event loop's EV_EOF handler (blued_adapter_lost) breaks by removing
 * the dead fd and tearing down the adapter.  This exercises that
 * kqueue contract directly (blued_event.c is not unit-linkable).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hci_fd_eof_stops_spin);
ATF_TC_BODY(test_hci_fd_eof_stops_spin, tc)
{
	struct kevent kev, ev;
	struct timespec zero = { 0, 0 };
	void *marker;
	int kq, sp[2], n;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));

	/* Register sp[0] like an adapter HCI fd: EVFILT_READ, udata tag. */
	marker = &kq;
	EV_SET(&kev, sp[0], EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, marker);
	ATF_REQUIRE_EQ(0, kevent(kq, &kev, 1, NULL, 0, NULL));

	/* Controller "unplugged": the peer closes -> EOF. */
	close(sp[1]);

	/* kqueue reports EV_EOF, and re-reports it on the next pass (spin). */
	n = kevent(kq, NULL, 0, &ev, 1, &zero);
	ATF_REQUIRE_EQ(1, n);
	ATF_CHECK((ev.flags & EV_EOF) != 0);
	ATF_CHECK_EQ(marker, ev.udata);
	n = kevent(kq, NULL, 0, &ev, 1, &zero);
	ATF_CHECK_MSG(n == 1,
	    "EV_EOF re-reports until the dead fd is deleted (the spin)");

	/* Remedy: EV_DELETE the dead fd (as blued_adapter_lost does). */
	EV_SET(&kev, sp[0], EVFILT_READ, EV_DELETE, 0, 0, NULL);
	(void)kevent(kq, &kev, 1, NULL, 0, NULL);

	/* The spin is stopped: no further events for the removed fd. */
	n = kevent(kq, NULL, 0, &ev, 1, &zero);
	ATF_CHECK_EQ_MSG(0, n,
	    "after EV_DELETE the dead controller fd no longer fires");

	close(sp[0]);
	close(kq);
}

/* An already-returned kevent must yield recv ownership to a GATT worker. */
ATF_TC_WITHOUT_HEAD(test_stale_att_event_yields_to_worker);
ATF_TC_BODY(test_stale_att_event_yields_to_worker, tc)
{
	struct blued_conn conn;

	memset(&conn, 0, sizeof(conn));
	atomic_init(&conn.att_ops_active, 0);
	ATF_CHECK(blued_conn_att_event_ready(&conn));

	/* Models ctl_gatt_job_start after kevent has returned its read event. */
	atomic_store_explicit(&conn.att_ops_active, 1, memory_order_release);
	ATF_CHECK(!blued_conn_att_event_ready(&conn));

	/* Once the correlated transaction completes, event-loop receive resumes. */
	atomic_store_explicit(&conn.att_ops_active, 0, memory_order_release);
	ATF_CHECK(blued_conn_att_event_ready(&conn));
}

/* Enhanced Connection Complete supplies the on-air local RPA for SMP. */
ATF_TC_WITHOUT_HEAD(test_enhanced_complete_local_rpa);
ATF_TC_BODY(test_enhanced_complete_local_rpa, tc)
{
	static const uint8_t peer[6] = { 1, 2, 3, 4, 5, 6 };
	static const uint8_t local_rpa[6] = { 0x41, 8, 9, 10, 11, 12 };
	static const uint8_t peer_rpa[6] = { 0x42, 13, 14, 15, 16, 17 };
	struct blued_adapter adapter;
	struct blued_conn *conn;

	test_init();
	memset(&adapter, 0, sizeof(adapter));
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->adapter = &adapter;
	memcpy(&conn->dst, peer, sizeof(peer));
	conn->addr_type = BDADDR_LE_RANDOM;

	/* 0x03 is HCI's random identity type; the daemon stores random. */
	blued_conn_note_enhanced(&adapter, 0x123, peer, 0x03,
	    local_rpa, peer_rpa);
	ATF_CHECK_EQ(conn->con_handle, 0x123);
	ATF_CHECK_EQ(conn->local_addr_type, BDADDR_LE_RANDOM);
	ATF_CHECK(conn->local_addr_from_hci);
	ATF_CHECK(memcmp(&conn->local_addr, local_rpa, 6) == 0);

	blued_conn_free(conn);
}

/* Metadata arriving before accept is cached per adapter, never cross-routed. */
ATF_TC_WITHOUT_HEAD(test_enhanced_complete_cached_multiadapter);
ATF_TC_BODY(test_enhanced_complete_cached_multiadapter, tc)
{
	static const uint8_t peer[6] = { 21, 22, 23, 24, 25, 26 };
	static const uint8_t local_rpa[6] = { 0x43, 28, 29, 30, 31, 32 };
	static const uint8_t peer_rpa[6] = { 0x44, 34, 35, 36, 37, 38 };
	struct blued_adapter a, b;
	struct blued_conn *wrong, *right;

	test_init();
	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));
	a.addr.b[0] = 0xa0;
	b.addr.b[0] = 0xb0;
	blued_conn_note_enhanced(&a, 0x234, peer, 0x02,
	    local_rpa, peer_rpa);

	wrong = blued_conn_alloc();
	right = blued_conn_alloc();
	ATF_REQUIRE(wrong != NULL && right != NULL);
	wrong->adapter = &b;
	right->adapter = &a;
	memcpy(&wrong->dst, peer, 6);
	memcpy(&right->dst, peer, 6);
	wrong->addr_type = right->addr_type = BDADDR_LE_PUBLIC;

	blued_conn_apply_cached_local(wrong);
	ATF_CHECK(!wrong->local_addr_from_hci);
	ATF_CHECK(memcmp(&wrong->local_addr, local_rpa, 6) != 0);
	blued_conn_apply_cached_local(right);
	ATF_CHECK(right->local_addr_from_hci);
	ATF_CHECK_EQ(right->con_handle, 0x234);
	ATF_CHECK_EQ(right->local_addr_type, BDADDR_LE_RANDOM);
	ATF_CHECK(memcmp(&right->local_addr, local_rpa, 6) == 0);

	blued_conn_free(wrong);
	blued_conn_free(right);
}

/* A zero Local_RPA means the controller used its public identity address. */
ATF_TC_WITHOUT_HEAD(test_enhanced_complete_public_fallback);
ATF_TC_BODY(test_enhanced_complete_public_fallback, tc)
{
	static const uint8_t peer[6] = { 51, 52, 53, 54, 55, 56 };
	static const uint8_t zero[6];
	struct blued_adapter adapter;
	struct blued_conn *conn;

	test_init();
	memset(&adapter, 0, sizeof(adapter));
	adapter.addr.b[0] = 0xce;
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->adapter = &adapter;
	memcpy(&conn->dst, peer, 6);
	conn->addr_type = BDADDR_LE_PUBLIC;
	blued_conn_note_enhanced(&adapter, 0x345, peer, 0, zero, zero);
	ATF_CHECK(conn->local_addr_from_hci);
	ATF_CHECK_EQ(conn->local_addr_type, BDADDR_LE_PUBLIC);
	ATF_CHECK(memcmp(&conn->local_addr, &adapter.addr, 6) == 0);
	blued_conn_free(conn);
}

/* A current-link event that beats setup/cache application must win. */
ATF_TC_WITHOUT_HEAD(test_central_reset_precedes_enhanced_complete);
ATF_TC_BODY(test_central_reset_precedes_enhanced_complete, tc)
{
	static const uint8_t peer[6] = { 61, 62, 63, 64, 65, 66 };
	static const uint8_t current_rpa[6] = { 0x45, 68, 69, 70, 71, 72 };
	static const uint8_t zero[6];
	struct blued_adapter adapter;
	struct blued_conn *conn;

	test_init();
	memset(&adapter, 0, sizeof(adapter));
	adapter.addr.b[0] = 0xd0;
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->adapter = &adapter;
	memcpy(&conn->dst, peer, 6);
	conn->addr_type = BDADDR_LE_PUBLIC;

	/* Reconnect boundary, then HCI event before the setup thread resumes. */
	blued_conn_reset_local(conn);
	blued_conn_note_enhanced(&adapter, 0x456, peer, 0,
	    current_rpa, zero);
	blued_conn_apply_cached_local(conn);
	blued_conn_local_from_socket(conn, -1);
	ATF_CHECK(conn->local_addr_from_hci);
	ATF_CHECK_EQ(conn->con_handle, 0x456);
	ATF_CHECK_EQ(conn->local_addr_type, BDADDR_LE_RANDOM);
	ATF_CHECK(memcmp(&conn->local_addr, current_rpa, 6) == 0);
	blued_conn_free(conn);
}

/* Own type 0x03 uses the provisioned random fallback when Local_RPA is zero. */
ATF_TC_WITHOUT_HEAD(test_private_central_zero_local_rpa);
ATF_TC_BODY(test_private_central_zero_local_rpa, tc)
{
	static const uint8_t peer[6] = { 73, 74, 75, 76, 77, 78 };
	static const uint8_t fallback_rpa[6] = { 0x46, 80, 81, 82, 83, 84 };
	static const uint8_t zero[6];
	struct blued_adapter adapter;
	struct blued_conn *conn;
	uint8_t local[6], type;

	test_init();
	memset(&adapter, 0, sizeof(adapter));
	adapter.privacy = true;
	adapter.random_addr_valid = true;
	memcpy(&adapter.random_addr, fallback_rpa, 6);
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->adapter = &adapter;
	memcpy(&conn->dst, peer, 6);
	conn->addr_type = BDADDR_LE_PUBLIC; /* initial unbonded peer */
	conn->local_own_addr_type = 0x03;
	blued_conn_reset_local(conn);

	blued_conn_note_enhanced(&adapter, 0x567, peer, 0, zero, zero);
	blued_conn_local_from_socket(conn, -1);
	ATF_CHECK(blued_conn_get_local(conn, local, &type));
	ATF_CHECK_EQ(type, BDADDR_LE_RANDOM);
	ATF_CHECK(memcmp(local, fallback_rpa, 6) == 0);
	ATF_CHECK(!conn->local_addr_from_hci);
	ATF_CHECK_EQ(conn->con_handle, 0x567);
	blued_conn_free(conn);
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
	ATF_TP_ADD_TC(tp, test_conn_register_eatt);
	ATF_TP_ADD_TC(tp, test_conn_pool_exhaustion);
	ATF_TP_ADD_TC(tp, test_conn_set_state);
	ATF_TP_ADD_TC(tp, test_conn_free_removes_from_list);
	ATF_TP_ADD_TC(tp, test_conn_alloc_after_free);
	ATF_TP_ADD_TC(tp, test_conn_initial_values);
	ATF_TP_ADD_TC(tp, test_conn_state_lifecycle);
	ATF_TP_ADD_TC(tp, test_conn_state_name);
	ATF_TP_ADD_TC(tp, test_conn_alloc_max);
	ATF_TP_ADD_TC(tp, test_conn_refcount_survives_free_with_ref);
	ATF_TP_ADD_TC(tp, test_conn_free_deletes_timers);
	ATF_TP_ADD_TC(tp, test_hci_fd_eof_stops_spin);
	ATF_TP_ADD_TC(tp, test_stale_att_event_yields_to_worker);
	ATF_TP_ADD_TC(tp, test_enhanced_complete_local_rpa);
	ATF_TP_ADD_TC(tp, test_handle_zero_is_valid_and_peer_scoped);
	ATF_TP_ADD_TC(tp, test_enhanced_complete_cached_multiadapter);
	ATF_TP_ADD_TC(tp, test_enhanced_complete_public_fallback);
	ATF_TP_ADD_TC(tp, test_central_reset_precedes_enhanced_complete);
	ATF_TP_ADD_TC(tp, test_private_central_zero_local_rpa);

	return (atf_no_error());
}
