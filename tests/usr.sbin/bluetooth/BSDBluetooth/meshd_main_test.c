/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Daemon-wiring tests: meshd.c.
 *
 * meshd.c holds the ctl client loop, the app-client slot allocator and the
 * (slot, generation) kevent token that keeps a stale event for a closed client
 * from acting on a brand-new client that reused BOTH the slot and, after
 * close(), the same descriptor number.  It was excluded from MESHD_ENGINE for
 * one reason only: it defines main().  Its externals are libc and the mesh
 * engine, so -- as cli_test.c and cli_meshctl_test.c already do for the CLI
 * translation units -- the shipping unit is #include'd with main() renamed and
 * its statics are driven directly.
 */

#include <sys/socket.h>

#include <fcntl.h>

#define main meshd_main_unused
#include "meshd.c"
#undef main

#include <atf-c.h>

/* ================================================================
 * udata token encoding
 * ================================================================ */

/*
 * Pins the tag layout the dispatch loop actually relies on.  The loop tests
 * MESHD_BLUED_UDATA_TAG (bit 0) FIRST and continues out of that arm, so the
 * discriminating invariants are:
 *   - every bearer token sets bit 0;
 *   - no app-client token sets bit 0 (its low two bits are exactly the tag);
 *   - the aligned &meshd_listen_token pointer sets neither.
 * Note bit 1 alone is NOT discriminating -- a bearer token for an odd
 * generation also sets it -- so this asserts bit 0, not bit 1, on the bearer
 * side.
 */
ATF_TC_WITHOUT_HEAD(udata_tags_are_disjoint);
ATF_TC_BODY(udata_tags_are_disjoint, tc)
{
	uintptr_t bearer, app, listener;
	uint64_t g;
	size_t slot;

	app = (uintptr_t)meshd_app_udata(3, 9);
	listener = (uintptr_t)&meshd_listen_token;

	ATF_CHECK((app & MESHD_APP_UDATA_TAG) != 0);
	ATF_CHECK_MSG((app & MESHD_BLUED_UDATA_TAG) == 0,
	    "an app-client token would be claimed by the bearer arm");
	ATF_CHECK_MSG((listener & (MESHD_BLUED_UDATA_TAG |
	    MESHD_APP_UDATA_TAG)) == 0,
	    "the listener pointer aliases a udata tag bit");

	/* Both parities of generation, and every slot, keep bit 0 correct. */
	for (g = 0; g < 8; g++) {
		bearer = (uintptr_t)meshd_blued_udata(g);
		ATF_CHECK_MSG((bearer & MESHD_BLUED_UDATA_TAG) != 0,
		    "bearer token for generation %ju lost its tag",
		    (uintmax_t)g);
		for (slot = 0; slot < MESHD_MAX_APP_CLIENTS; slot++) {
			app = (uintptr_t)meshd_app_udata(slot, g);
			ATF_CHECK_MSG((app & MESHD_BLUED_UDATA_TAG) == 0,
			    "app token (slot %zu, gen %ju) set the bearer tag",
			    slot, (uintmax_t)g);
			ATF_CHECK_MSG(app != listener,
			    "app token (slot %zu, gen %ju) aliases the listener",
			    slot, (uintmax_t)g);
		}
	}
}

/* Pins the bearer token round trip across the full generation range used. */
ATF_TC_WITHOUT_HEAD(bearer_udata_round_trip);
ATF_TC_BODY(bearer_udata_round_trip, tc)
{
	static const uint64_t gens[] = { 0, 1, 2, 1000, 0x7fffffffULL };
	size_t i;

	for (i = 0; i < nitems(gens); i++)
		ATF_CHECK_EQ(gens[i],
		    meshd_blued_udata_generation(meshd_blued_udata(gens[i])));
}

/*
 * Pins meshd_blued_event_current(): a bearer event is current only when it
 * carries the tag, the CURRENT generation and the CURRENT descriptor.  A stale
 * event for a reconnected bearer -- same fd number, older generation -- must be
 * refused, or it would tear down the live connection.
 */
ATF_TC_WITHOUT_HEAD(bearer_event_rejects_stale_generation_and_fd);
ATF_TC_BODY(bearer_event_rejects_stale_generation_and_fd, tc)
{
	struct meshd_blued bc;
	struct kevent ev;
	uint64_t gen;
	int fd;

	memset(&bc, 0, sizeof(bc));
	meshd_blued_init(&bc, NULL);
	bc.fd = 11;
	bc.generation = 5;
	fd = meshd_blued_fd(&bc);
	gen = meshd_blued_generation(&bc);
	ATF_REQUIRE_EQ(11, fd);
	ATF_REQUIRE_EQ(5, gen);

	EV_SET(&ev, (uintptr_t)fd, EVFILT_READ, 0, 0, 0,
	    meshd_blued_udata(gen));
	ATF_CHECK(meshd_blued_event_current(&bc, &ev));

	/* Same descriptor, previous connection's generation. */
	EV_SET(&ev, (uintptr_t)fd, EVFILT_READ, 0, 0, 0,
	    meshd_blued_udata(gen - 1));
	ATF_CHECK_MSG(!meshd_blued_event_current(&bc, &ev),
	    "a stale generation matched the live bearer");

	/* Right generation, a descriptor this bearer no longer owns. */
	EV_SET(&ev, (uintptr_t)fd + 1, EVFILT_READ, 0, 0, 0,
	    meshd_blued_udata(gen));
	ATF_CHECK(!meshd_blued_event_current(&bc, &ev));

	/* An untagged udata (an app-client or listener event) never matches. */
	EV_SET(&ev, (uintptr_t)fd, EVFILT_READ, 0, 0, 0,
	    &meshd_listen_token);
	ATF_CHECK(!meshd_blued_event_current(&bc, &ev));

	ATF_CHECK(!meshd_blued_event_current(NULL, &ev));
	ATF_CHECK(!meshd_blued_event_current(&bc, NULL));
}

/*
 * Pins meshd_blued_registration_changed(): the loop re-registers whenever the
 * descriptor OR the generation moved, so a reconnect that happens to reuse the
 * same fd number still refreshes the kqueue registration.
 */
ATF_TC_WITHOUT_HEAD(bearer_registration_change_detects_reconnect);
ATF_TC_BODY(bearer_registration_change_detects_reconnect, tc)
{
	struct meshd_blued bc;

	memset(&bc, 0, sizeof(bc));
	meshd_blued_init(&bc, NULL);
	bc.fd = 9;
	bc.generation = 3;

	ATF_CHECK(!meshd_blued_registration_changed(&bc, 9, 3));
	ATF_CHECK(meshd_blued_registration_changed(&bc, 8, 3));
	ATF_CHECK_MSG(meshd_blued_registration_changed(&bc, 9, 2),
	    "a same-fd reconnect was not detected as a registration change");
}

/* ================================================================
 * App-client slot reuse
 * ================================================================ */

/*
 * THE case this encoding exists for.  A client is allocated in a slot, its
 * event token is captured, it is closed, and a NEW client takes the SAME slot
 * and the SAME descriptor number.  The captured token must no longer resolve:
 * acting on it would close the new client.
 */
ATF_TC_WITHOUT_HEAD(app_client_slot_reuse_invalidates_stale_token);
ATF_TC_BODY(app_client_slot_reuse_invalidates_stale_token, tc)
{
	struct meshd_node nd;
	struct meshd_app_client *first, *second;
	struct kevent ev;
	void *stale;

	memset(&nd, 0, sizeof(nd));

	first = meshd_client_alloc(&nd, 42);
	ATF_REQUIRE(first != NULL);
	stale = meshd_client_udata(&nd, first);
	EV_SET(&ev, 42, EVFILT_READ, 0, 0, 0, stale);
	ATF_REQUIRE_EQ(first, meshd_app_client_current(&nd, &ev));

	/* The client goes away; the slot is released. */
	meshd_app_client_fini(first);
	ATF_CHECK_MSG(meshd_app_client_current(&nd, &ev) == NULL,
	    "a stale token resolved to a closed client");

	/* A new client reuses the slot AND the descriptor number. */
	second = meshd_client_alloc(&nd, 42);
	ATF_REQUIRE_EQ(first, second);	/* same slot */
	ATF_CHECK_MSG(meshd_app_client_current(&nd, &ev) == NULL,
	    "a stale token resolved to the client that reused its slot");

	/* The new client's own token does resolve. */
	EV_SET(&ev, 42, EVFILT_READ, 0, 0, 0,
	    meshd_client_udata(&nd, second));
	ATF_CHECK_EQ(second, meshd_app_client_current(&nd, &ev));

	meshd_app_client_fini(second);
}

/*
 * Pins the remaining rejection arms of meshd_app_client_current(): an untagged
 * udata, an out-of-range slot, an inactive slot and a descriptor mismatch.
 */
ATF_TC_WITHOUT_HEAD(app_client_current_rejection_arms);
ATF_TC_BODY(app_client_current_rejection_arms, tc)
{
	struct meshd_node nd;
	struct meshd_app_client *cl;
	struct kevent ev;

	memset(&nd, 0, sizeof(nd));
	cl = meshd_client_alloc(&nd, 7);
	ATF_REQUIRE(cl != NULL);

	/* Untagged (a bearer token). */
	EV_SET(&ev, 7, EVFILT_READ, 0, 0, 0, meshd_blued_udata(1));
	ATF_CHECK(meshd_app_client_current(&nd, &ev) == NULL);

	/* Slot beyond the table. */
	EV_SET(&ev, 7, EVFILT_READ, 0, 0, 0,
	    meshd_app_udata(MESHD_MAX_APP_CLIENTS + 1, cl->generation));
	ATF_CHECK(meshd_app_client_current(&nd, &ev) == NULL);

	/* Right slot and generation, wrong descriptor. */
	EV_SET(&ev, 8, EVFILT_READ, 0, 0, 0, meshd_client_udata(&nd, cl));
	ATF_CHECK_MSG(meshd_app_client_current(&nd, &ev) == NULL,
	    "a token matched a descriptor the client does not own");

	ATF_CHECK(meshd_app_client_current(NULL, &ev) == NULL);
	ATF_CHECK(meshd_app_client_current(&nd, NULL) == NULL);

	meshd_app_client_fini(cl);
}

/*
 * Pins the slot encoding's capacity: every slot the allocator can hand out
 * must survive the (slot, generation) round trip.  The slot field is six bits,
 * so a table larger than 64 would silently alias slots onto each other.
 */
ATF_TC_WITHOUT_HEAD(app_client_every_slot_round_trips);
ATF_TC_BODY(app_client_every_slot_round_trips, tc)
{
	struct meshd_node nd;
	struct kevent ev;
	size_t i;

	ATF_REQUIRE_MSG(MESHD_MAX_APP_CLIENTS <= 64,
	    "the six-bit slot field cannot address %d clients",
	    MESHD_MAX_APP_CLIENTS);

	memset(&nd, 0, sizeof(nd));
	for (i = 0; i < MESHD_MAX_APP_CLIENTS; i++) {
		struct meshd_app_client *cl;

		cl = meshd_client_alloc(&nd, (int)(100 + i));
		ATF_REQUIRE_MSG(cl != NULL, "slot %zu not allocated", i);
		ATF_CHECK_EQ(&nd.app_clients[i], cl);
		EV_SET(&ev, 100 + i, EVFILT_READ, 0, 0, 0,
		    meshd_client_udata(&nd, cl));
		ATF_CHECK_MSG(meshd_app_client_current(&nd, &ev) == cl,
		    "slot %zu did not round trip", i);
	}
	/* The table is full: the allocator refuses rather than overrunning. */
	ATF_CHECK(meshd_client_alloc(&nd, 999) == NULL);

	for (i = 0; i < MESHD_MAX_APP_CLIENTS; i++)
		meshd_app_client_fini(&nd.app_clients[i]);
}

/* ================================================================
 * ctl client line handling
 * ================================================================ */

/*
 * Pins the EOF arm of meshd_client_read(): a client that writes a batch of
 * commands and then shuts down its side still gets its answers -- EOF is
 * flagged, not treated as an error, and the complete lines that arrived with
 * it are processed.
 */
ATF_TC_WITHOUT_HEAD(client_read_eof_still_answers_queued_lines);
ATF_TC_BODY(client_read_eof_still_answers_queued_lines, tc)
{
	struct meshd_node nd;
	struct meshd_app_client *cl;
	int sp[2];

	memset(&nd, 0, sizeof(nd));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	/* The daemon sets every accepted control descriptor non-blocking. */
	ATF_REQUIRE(fcntl(sp[0], F_SETFL, O_NONBLOCK) == 0);
	ATF_REQUIRE(fcntl(sp[1], F_SETFL, O_NONBLOCK) == 0);
	cl = meshd_client_alloc(&nd, sp[0]);
	ATF_REQUIRE(cl != NULL);

	ATF_REQUIRE(write(sp[1], "status\n", 7) == 7);
	ATF_REQUIRE_EQ(0, shutdown(sp[1], SHUT_WR));

	ATF_CHECK_MSG(meshd_client_read(&nd, NULL, cl) >= 0,
	    "EOF after a complete line was reported as an error");
	ATF_CHECK_MSG(cl->eof != 0, "EOF not flagged");
	ATF_CHECK_MSG(cl->txlen > 0, "the queued reply was lost at EOF");

	meshd_app_client_fini(cl);
	close(sp[0]);
	close(sp[1]);
}

/*
 * Pins the receive-buffer bound in meshd_client_read(): a line longer than the
 * buffer is refused instead of overflowing it, and a partial line is retained
 * across reads.
 */
ATF_TC_WITHOUT_HEAD(client_read_bounds_the_receive_buffer);
ATF_TC_BODY(client_read_bounds_the_receive_buffer, tc)
{
	struct meshd_node nd;
	struct meshd_app_client *cl;
	char chunk[256];
	size_t sent;
	int sp[2], rc;

	memset(&nd, 0, sizeof(nd));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	/* The daemon sets every accepted control descriptor non-blocking. */
	ATF_REQUIRE(fcntl(sp[0], F_SETFL, O_NONBLOCK) == 0);
	ATF_REQUIRE(fcntl(sp[1], F_SETFL, O_NONBLOCK) == 0);
	cl = meshd_client_alloc(&nd, sp[0]);
	ATF_REQUIRE(cl != NULL);

	/* A partial (newline-free) line is buffered, not executed. */
	ATF_REQUIRE(write(sp[1], "sta", 3) == 3);
	ATF_REQUIRE_EQ(0, meshd_client_read(&nd, NULL, cl));
	ATF_CHECK_EQ(3, cl->rxlen);
	ATF_CHECK_EQ(0, cl->txlen);

	/* Its completion executes exactly one line. */
	ATF_REQUIRE(write(sp[1], "tus\n", 4) == 4);
	rc = meshd_client_read(&nd, NULL, cl);
	ATF_CHECK(rc >= 0);
	ATF_CHECK_EQ(0, cl->rxlen);
	ATF_CHECK(cl->txlen > 0);

	/*
	 * An unterminated flood past the buffer is refused.  The socket buffer
	 * is smaller than rxbuf, so feed and drain in turn until the read path
	 * rejects (or the buffer provably could not be filled).
	 */
	memset(chunk, 'x', sizeof(chunk));
	for (sent = 0; sent < 8 * sizeof(cl->rxbuf); sent += sizeof(chunk)) {
		if (write(sp[1], chunk, sizeof(chunk)) !=
		    (ssize_t)sizeof(chunk))
			continue;
		rc = meshd_client_read(&nd, NULL, cl);
		if (rc < 0)
			break;
	}
	ATF_CHECK_MSG(rc < 0, "an over-long control line was accepted");

	meshd_app_client_fini(cl);
	close(sp[0]);
	close(sp[1]);
}

/*
 * Pins meshd_client_queue_bytes()/meshd_client_write(): the transmit queue is
 * bounded (a client that never drains cannot make the daemon grow without
 * limit) and a full flush resets the offsets so the slot is reusable.
 */
ATF_TC_WITHOUT_HEAD(client_transmit_queue_is_bounded_and_resets);
ATF_TC_BODY(client_transmit_queue_is_bounded_and_resets, tc)
{
	struct meshd_node nd;
	struct meshd_app_client *cl;
	char line[128];
	int sp[2], i, rc = 0;

	memset(&nd, 0, sizeof(nd));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	/* The daemon sets every accepted control descriptor non-blocking. */
	ATF_REQUIRE(fcntl(sp[0], F_SETFL, O_NONBLOCK) == 0);
	ATF_REQUIRE(fcntl(sp[1], F_SETFL, O_NONBLOCK) == 0);
	cl = meshd_client_alloc(&nd, sp[0]);
	ATF_REQUIRE(cl != NULL);

	memset(line, 'y', sizeof(line) - 1);
	line[sizeof(line) - 1] = '\0';
	for (i = 0; i < 1000 && rc == 0; i++)
		rc = meshd_client_queue_line(cl, line);
	ATF_CHECK_MSG(rc != 0,
	    "the reply queue accepted %d lines without bound", i);
	ATF_CHECK(cl->txlen <= sizeof(cl->txbuf));

	/* Flush, draining the peer so the write side can make progress. */
	for (i = 0; i < 100 && cl->txlen != 0; i++) {
		char sink[512];

		ATF_REQUIRE_EQ(0, meshd_client_write(cl));
		while (read(sp[1], sink, sizeof(sink)) > 0)
			;
	}
	ATF_CHECK_MSG(cl->txlen == 0, "the reply queue never drained");
	ATF_CHECK_EQ(0, cl->txoff);

	meshd_app_client_fini(cl);
	close(sp[0]);
	close(sp[1]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, udata_tags_are_disjoint);
	ATF_TP_ADD_TC(tp, bearer_udata_round_trip);
	ATF_TP_ADD_TC(tp, bearer_event_rejects_stale_generation_and_fd);
	ATF_TP_ADD_TC(tp, bearer_registration_change_detects_reconnect);
	ATF_TP_ADD_TC(tp, app_client_slot_reuse_invalidates_stale_token);
	ATF_TP_ADD_TC(tp, app_client_current_rejection_arms);
	ATF_TP_ADD_TC(tp, app_client_every_slot_round_trips);
	ATF_TP_ADD_TC(tp, client_read_eof_still_answers_queued_lines);
	ATF_TP_ADD_TC(tp, client_read_bounds_the_receive_buffer);
	ATF_TP_ADD_TC(tp, client_transmit_queue_is_bounded_and_resets);

	return (atf_no_error());
}
