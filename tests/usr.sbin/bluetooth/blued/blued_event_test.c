/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Daemon-wiring tests: blued_event.c.
 *
 * This is the first test program to link the event loop at all.  It drives the
 * REAL blued_event.c object (see blued_daemon_stub.c for the 62-symbol blued.c
 * seam that makes that possible) through three entry points:
 *
 *   blued_event_batch_begin()/blued_event_dispatch_batch()
 *	One iteration of the loop against a synthetic struct kevent array, so a
 *	batch whose descriptor numbers and heap addresses were both recycled
 *	inside it is an ordinary unit test rather than a race with a controller.
 *   blued_hci_event_defer()/blued_handle_hci_event()
 *	The bounded, classified deferred-HCI ring: admission, priority
 *	eviction, bulk reserve, FIFO order and the stale-fd drop.
 *   blued_conn_disconnect()/blued_idle_arm()/blued_ind_arm_timeout()
 *	The connection-lifecycle latches, stubbed out in all 13 programs that
 *	link ctl.c and therefore never covered anywhere until now.
 *
 * HCI command emission is observed through the established --wrap=bt_devreq
 * seam; free(3) is wrapped so the "reaped ctl client is not released until the
 * next batch" invariant is directly observable.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/un.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "blued.h"
#include "blued_daemon_stub.h"
#include "blued_internal.h"
#include "ble_util.h"
#include "config.h"
#include "conn.h"
#include "ctl.h"
#include "ctl_internal.h"
#include "gatt.h"
#include "hci_util.h"
#include "smp.h"

/* ================================================================
 * bt_devreq wrap: record the HCI commands the event loop emits.
 * ================================================================ */

#define	EVT_MAX_CMDS	64

struct evt_cmd {
	int		fd;
	uint16_t	opcode;
	uint8_t		cparam[64];
	size_t		clen;
};

static struct evt_cmd evt_cmds[EVT_MAX_CMDS];
static unsigned int evt_ncmds;

int	__wrap_bt_devreq(int s, struct bt_devreq *r, time_t to);
int	__real_bt_devreq(int s, struct bt_devreq *r, time_t to);

int
__wrap_bt_devreq(int s, struct bt_devreq *r, time_t to __unused)
{

	if (evt_ncmds < EVT_MAX_CMDS) {
		evt_cmds[evt_ncmds].fd = s;
		evt_cmds[evt_ncmds].opcode = r->opcode;
		evt_cmds[evt_ncmds].clen = r->clen > sizeof(evt_cmds[0].cparam) ?
		    sizeof(evt_cmds[0].cparam) : r->clen;
		if (r->cparam != NULL && evt_cmds[evt_ncmds].clen > 0)
			memcpy(evt_cmds[evt_ncmds].cparam, r->cparam,
			    evt_cmds[evt_ncmds].clen);
	}
	evt_ncmds++;
	/* Status octet first in every reply parameter block used here. */
	if (r->rparam != NULL && r->rlen > 0)
		memset(r->rparam, 0, r->rlen);
	return (0);
}

/* Count the recorded commands carrying OPCODE. */
static unsigned int
evt_count_opcode(uint16_t opcode)
{
	unsigned int i, n = 0;

	for (i = 0; i < evt_ncmds && i < EVT_MAX_CMDS; i++)
		if (evt_cmds[i].opcode == opcode)
			n++;
	return (n);
}

#define	OPCODE_LTK_NEG_REPLY						\
	NG_HCI_OPCODE(NG_HCI_OGF_LE,					\
	    NG_HCI_OCF_LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY)
#define	OPCODE_LTK_REPLY						\
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_LONG_TERM_KEY_REQUEST_REPLY)

/* ================================================================
 * free(3) wrap: observe the deferred release of reaped ctl clients.
 * ================================================================ */

static void *evt_free_watch;
static unsigned int evt_free_watch_hits;

void	__wrap_free(void *p);
void	__real_free(void *p);

void
__wrap_free(void *p)
{

	if (p != NULL && p == evt_free_watch)
		evt_free_watch_hits++;
	__real_free(p);
}

/* ================================================================
 * Fixture
 * ================================================================ */

static struct blued_adapter evt_adp;
static int evt_hci_sp[2] = { -1, -1 };

static void
evt_reset(void)
{

	evt_ncmds = 0;
	memset(evt_cmds, 0, sizeof(evt_cmds));
	evt_free_watch = NULL;
	evt_free_watch_hits = 0;
	blued_stub_reset();
	running = 1;

	memset(&blued_g, 0, sizeof(blued_g));
	blued_g.kq = -1;
	blued_g.ctl_fd = -1;
	blued_g.bond_fd = -1;
	blued_g.vhid_ctl_fd = -1;
	blued_g.setup_pipe[0] = blued_g.setup_pipe[1] = -1;
	LIST_INIT(&blued_g.adapters);
	LIST_INIT(&blued_g.conns);
	LIST_INIT(&blued_g.ctl_clients);
	LIST_INIT(&blued_g.ctl_acquires);
	pthread_rwlock_init(&blued_g.conns_lock, NULL);
	pthread_mutex_init(&blued_g.bond_db_lock, NULL);
	pthread_mutex_init(&blued_g.gatt_db_lock, NULL);
	pthread_mutex_init(&blued_g.att_sec_lock, NULL);
	pthread_mutex_init(&blued_g.reslist_lock, NULL);
	blued_ctl_clients_lock_init(&blued_g.ctl_clients_lock);
	blued_g.main_thread = pthread_self();

	blued_g.kq = kqueue();
	ATF_REQUIRE(blued_g.kq >= 0);
	ATF_REQUIRE_EQ(0, pipe(blued_g.setup_pipe));

	memset(&evt_adp, 0, sizeof(evt_adp));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, evt_hci_sp));
	evt_adp.hci_fd = evt_hci_sp[0];
	evt_adp.index = 0;
	evt_adp.active = true;
	evt_adp.powered = true;
	evt_adp.periph_listen_fd = -1;
	evt_adp.eatt_listen_fd = -1;
	strlcpy(evt_adp.name, "ubt0", sizeof(evt_adp.name));
	LIST_INSERT_HEAD(&blued_g.adapters, &evt_adp, entries);
}

static void
evt_teardown(void)
{

	if (blued_g.kq >= 0)
		close(blued_g.kq);
	if (blued_g.setup_pipe[0] >= 0)
		close(blued_g.setup_pipe[0]);
	if (blued_g.setup_pipe[1] >= 0)
		close(blued_g.setup_pipe[1]);
	if (evt_hci_sp[0] >= 0)
		close(evt_hci_sp[0]);
	if (evt_hci_sp[1] >= 0)
		close(evt_hci_sp[1]);
	hci_fd_closed(evt_adp.hci_fd);
	blued_g.kq = -1;
	blued_g.setup_pipe[0] = blued_g.setup_pipe[1] = -1;
	evt_hci_sp[0] = evt_hci_sp[1] = -1;
}

/*
 * Drain the ring through the real replay path.  blued_handle_hci_event()
 * replays the parked entries first and then recv()s; the fixture socket is
 * empty and the read is MSG_DONTWAIT, so the trailing read is a discarded
 * EAGAIN.
 */
static void
evt_drain(void)
{

	blued_handle_hci_event(&evt_adp);
}

/*
 * Poke the self-pipe exactly as a setup thread does.  The sweep's first act is
 * a blocking read of the pipe, so a synthetic setup-pipe event must be
 * accompanied by the byte the real producer would have written.
 */
static void
evt_poke_setup_pipe(void)
{

	ATF_REQUIRE_EQ(1, write(blued_g.setup_pipe[1], "x", 1));
}

/* ---- packet builders ---- */

/* LE Long Term Key Request (subevent 0x05), a PRIORITY control event. */
static size_t
evt_pkt_ltk_request(uint8_t *out, uint16_t handle, uint64_t rand_val,
    uint16_t ediv)
{

	out[0] = NG_HCI_EVENT_PKT;
	out[1] = 0x3e;
	out[2] = 13;
	out[3] = 0x05;
	out[4] = (uint8_t)(handle & 0xff);
	out[5] = (uint8_t)(handle >> 8);
	memcpy(out + 6, &rand_val, 8);
	out[14] = (uint8_t)(ediv & 0xff);
	out[15] = (uint8_t)(ediv >> 8);
	return (16);
}

/* LE Periodic Advertising Sync Established (subevent 0x0e): BULK, and the
 * only bulk subevent with adapter-visible state, so a bulk admission or drop
 * is observable. */
static size_t
evt_pkt_sync_est(uint8_t *out, uint16_t sync_handle)
{

	memset(out, 0, 19);
	out[0] = NG_HCI_EVENT_PKT;
	out[1] = 0x3e;
	out[2] = 16;
	out[3] = 0x0e;
	out[4] = 0x00;				/* status */
	out[5] = (uint8_t)(sync_handle & 0xff);
	out[6] = (uint8_t)(sync_handle >> 8);
	out[7] = 0x00;				/* advertising SID */
	out[8] = 0x00;				/* advertiser addr type */
	out[15] = 0x01;				/* advertiser PHY = 1M */
	out[16] = 0x06;				/* periodic interval lo */
	out[17] = 0x00;
	out[18] = 0x00;				/* clock accuracy */
	return (19);
}

static bool
evt_sync_bit(uint16_t handle)
{

	return ((evt_adp.periodic_syncs[handle / 8] &
	    (uint8_t)(1U << (handle % 8))) != 0);
}

/* ---- conn / client builders ---- */

static struct blued_conn *
evt_make_conn(int role, int state)
{
	struct blued_conn *c;

	c = blued_conn_alloc();
	ATF_REQUIRE(c != NULL);
	c->adapter = &evt_adp;
	c->role = role;
	c->att_fd = -1;
	c->addr_type = BDADDR_LE_PUBLIC;
	atomic_store(&c->state, state);
	return (c);
}

static struct blued_ctl_client *
evt_make_client(int sp[2])
{
	struct blued_ctl_client *client;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	client = calloc(1, sizeof(*client));
	ATF_REQUIRE(client != NULL);
	client->fd = sp[0];
	client->generation = 1;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	return (client);
}

/* ================================================================
 * Deferred HCI event ring
 * ================================================================ */

/*
 * Pins blued_event.c blued_hci_defer_is_priority() + the `limit' selection in
 * blued_hci_event_defer(): with the ring already holding DEPTH-RESERVE bulk
 * reports, one more BULK report is refused while a CONTROL event is admitted.
 * Revert the reserve (limit = DEPTH for both classes) and the 25th sync-est
 * lands, setting its adapter bit.
 */
ATF_TC_WITHOUT_HEAD(defer_bulk_reserve_holds_back_reports);
ATF_TC_BODY(defer_bulk_reserve_holds_back_reports, tc)
{
	uint8_t pkt[32];
	size_t len;
	uint16_t h;

	evt_reset();

	/* 24 == BLUED_HCI_DEFER_DEPTH - BLUED_HCI_DEFER_RESERVE. */
	for (h = 0; h < 24; h++) {
		len = evt_pkt_sync_est(pkt, h);
		blued_hci_event_defer(evt_adp.hci_fd, pkt, len);
	}
	/* One past the bulk limit: must be refused. */
	len = evt_pkt_sync_est(pkt, 24);
	blued_hci_event_defer(evt_adp.hci_fd, pkt, len);

	evt_drain();

	for (h = 0; h < 24; h++)
		ATF_CHECK_MSG(evt_sync_bit(h), "bulk report %u lost", h);
	ATF_CHECK_MSG(!evt_sync_bit(24),
	    "bulk report admitted past the control-event reserve");

	evt_teardown();
}

/*
 * Pins blued_hci_defer_evict_bulk() and the "control events are ALWAYS
 * admitted" rule: a ring completely full of bulk reports still takes every
 * control event, each evicting the oldest bulk entry.
 */
ATF_TC_WITHOUT_HEAD(defer_priority_evicts_bulk_when_full);
ATF_TC_BODY(defer_priority_evicts_bulk_when_full, tc)
{
	uint8_t pkt[32];
	size_t len;
	unsigned int i;

	evt_reset();

	/* Fill every slot: 24 admitted bulk, the rest refused. */
	for (i = 0; i < 64; i++) {
		len = evt_pkt_sync_est(pkt, (uint16_t)(i % 24));
		blued_hci_event_defer(evt_adp.hci_fd, pkt, len);
	}
	/* Nine control events: more than the reserve, so eviction is forced. */
	for (i = 0; i < 9; i++) {
		len = evt_pkt_ltk_request(pkt, (uint16_t)(0x40 + i), 0, 0);
		blued_hci_event_defer(evt_adp.hci_fd, pkt, len);
	}

	evt_drain();

	/* No bond database: every replayed LTK Request answers negatively. */
	ATF_CHECK_EQ(9, evt_count_opcode(OPCODE_LTK_NEG_REPLY));

	evt_teardown();
}

/*
 * Pins the FIFO discipline of blued_hci_defer_drop_at()/the drain: control
 * events replay in the order they were parked.
 */
ATF_TC_WITHOUT_HEAD(defer_preserves_control_event_order);
ATF_TC_BODY(defer_preserves_control_event_order, tc)
{
	uint8_t pkt[32];
	size_t len;
	unsigned int i;

	evt_reset();

	for (i = 0; i < 5; i++) {
		len = evt_pkt_ltk_request(pkt, (uint16_t)(0x10 + i), 0, 0);
		blued_hci_event_defer(evt_adp.hci_fd, pkt, len);
	}
	evt_drain();

	ATF_REQUIRE_EQ(5, evt_ncmds);
	for (i = 0; i < 5; i++) {
		uint16_t h;

		ATF_CHECK_EQ(OPCODE_LTK_NEG_REPLY, evt_cmds[i].opcode);
		memcpy(&h, evt_cmds[i].cparam, 2);
		ATF_CHECK_EQ(0x10 + i, le16toh(h));
	}

	evt_teardown();
}

/*
 * Pins C3-M16 in blued_hci_defer_drain(): a packet parked against a descriptor
 * that no ACTIVE adapter owns is dropped outright rather than replayed against
 * a stale adapter (and without consuming a per-fd devreq lock slot).
 */
ATF_TC_WITHOUT_HEAD(defer_drops_packet_for_departed_adapter);
ATF_TC_BODY(defer_drops_packet_for_departed_adapter, tc)
{
	uint8_t pkt[32];
	size_t len;

	evt_reset();

	/* Parked against a descriptor belonging to no adapter at all. */
	len = evt_pkt_ltk_request(pkt, 0x0020, 0, 0);
	blued_hci_event_defer(evt_hci_sp[1], pkt, len);
	/* And one for the live adapter, so the drain has work to finish. */
	len = evt_pkt_ltk_request(pkt, 0x0021, 0, 0);
	blued_hci_event_defer(evt_adp.hci_fd, pkt, len);

	evt_drain();

	ATF_CHECK_EQ(1, evt_count_opcode(OPCODE_LTK_NEG_REPLY));
	ATF_REQUIRE(evt_ncmds >= 1);
	ATF_CHECK_EQ(evt_adp.hci_fd, evt_cmds[0].fd);

	evt_teardown();
}

/*
 * Pins the "replay parked events BEFORE reading new ones" ordering at the head
 * of blued_handle_hci_event(): a deferred event is always older than whatever
 * is pending on the socket, so its effect must land first.
 */
ATF_TC_WITHOUT_HEAD(defer_replays_before_socket_read);
ATF_TC_BODY(defer_replays_before_socket_read, tc)
{
	uint8_t pkt[32];
	size_t len;

	evt_reset();

	/* Parked (older) event: handle 0x0030. */
	len = evt_pkt_ltk_request(pkt, 0x0030, 0, 0);
	blued_hci_event_defer(evt_adp.hci_fd, pkt, len);

	/* Newer event, pending on the socket: handle 0x0031. */
	len = evt_pkt_ltk_request(pkt, 0x0031, 0, 0);
	ATF_REQUIRE(send(evt_hci_sp[1], pkt, len, 0) == (ssize_t)len);

	blued_handle_hci_event(&evt_adp);

	ATF_REQUIRE_EQ(2, evt_ncmds);
	{
		uint16_t h0, h1;

		memcpy(&h0, evt_cmds[0].cparam, 2);
		memcpy(&h1, evt_cmds[1].cparam, 2);
		ATF_CHECK_EQ(0x0030, le16toh(h0));
		ATF_CHECK_EQ(0x0031, le16toh(h1));
	}

	evt_teardown();
}

/*
 * Pins the packet-size guard at the head of blued_hci_event_defer(): an
 * over-long or empty packet is refused rather than overflowing the ring slot.
 */
ATF_TC_WITHOUT_HEAD(defer_rejects_malformed_lengths);
ATF_TC_BODY(defer_rejects_malformed_lengths, tc)
{
	uint8_t big[4 + NG_HCI_EVENT_PKT_SIZE];

	evt_reset();

	memset(big, 0, sizeof(big));
	blued_hci_event_defer(evt_adp.hci_fd, big, sizeof(big));
	blued_hci_event_defer(evt_adp.hci_fd, big, 0);
	blued_hci_event_defer(evt_adp.hci_fd, NULL, 4);

	evt_drain();
	ATF_CHECK_EQ(0, evt_ncmds);

	evt_teardown();
}

/* ================================================================
 * LE Long Term Key Request handling
 * ================================================================ */

/*
 * Pins C3-D31 in the LTK Request arm: while a pairing worker owns the LTK
 * response (conn->smp_owns_ltk), the event loop answers NOTHING -- neither the
 * stored key nor a negative reply, either of which would earn a Command
 * Disallowed and drop the link.
 */
ATF_TC_WITHOUT_HEAD(ltk_request_silent_while_smp_owns);
ATF_TC_BODY(ltk_request_silent_while_smp_owns, tc)
{
	struct smp_bond_db db;
	struct blued_conn *c;
	uint8_t pkt[32];
	size_t len;

	evt_reset();
	memset(&db, 0, sizeof(db));
	blued_g.bond_db = &db;

	c = evt_make_conn(BLUED_ROLE_PERIPHERAL, BLUED_CONN_ACTIVE);
	c->con_handle = 0x0042;
	c->con_handle_valid = true;
	atomic_store(&c->smp_owns_ltk, true);

	len = evt_pkt_ltk_request(pkt, 0x0042, 0, 0);
	ATF_REQUIRE(send(evt_hci_sp[1], pkt, len, 0) == (ssize_t)len);
	blued_handle_hci_event(&evt_adp);
	ATF_CHECK_EQ(0, evt_ncmds);

	/* Once the worker releases it, the same request is answered. */
	atomic_store(&c->smp_owns_ltk, false);
	ATF_REQUIRE(send(evt_hci_sp[1], pkt, len, 0) == (ssize_t)len);
	blued_handle_hci_event(&evt_adp);
	ATF_CHECK_EQ(1, evt_count_opcode(OPCODE_LTK_NEG_REPLY));

	blued_conn_free(c);
	blued_g.bond_db = NULL;
	evt_teardown();
}

/*
 * Pins finding S-m4: a Secure Connections bond is only ever addressed by
 * EDIV=0/Rand=0 (Core Spec Vol 3 Part H 2.4.4).  A reconnect LTK Request
 * carrying a non-zero EDIV must be refused, not answered with the SC LTK.
 */
ATF_TC_WITHOUT_HEAD(ltk_request_sc_bond_rejects_nonzero_ediv);
ATF_TC_BODY(ltk_request_sc_bond_rejects_nonzero_ediv, tc)
{
	struct smp_bond_db db;
	struct blued_conn *c;
	uint8_t pkt[32];
	size_t len;

	evt_reset();
	memset(&db, 0, sizeof(db));
	db.count = 1;
	db.bonds[0].addr_type = BDADDR_LE_PUBLIC;
	db.bonds[0].has_ltk = true;
	db.bonds[0].is_sc = true;
	memset(db.bonds[0].ltk, 0xa5, sizeof(db.bonds[0].ltk));
	blued_g.bond_db = &db;

	c = evt_make_conn(BLUED_ROLE_PERIPHERAL, BLUED_CONN_ACTIVE);
	c->con_handle = 0x0043;
	c->con_handle_valid = true;
	memcpy(&db.bonds[0].addr, &c->dst, sizeof(db.bonds[0].addr));

	/* Non-zero EDIV against an SC bond: refuse. */
	len = evt_pkt_ltk_request(pkt, 0x0043, 0, 0x1234);
	ATF_REQUIRE(send(evt_hci_sp[1], pkt, len, 0) == (ssize_t)len);
	blued_handle_hci_event(&evt_adp);
	ATF_CHECK_EQ(1, evt_count_opcode(OPCODE_LTK_NEG_REPLY));
	ATF_CHECK_EQ(0, evt_count_opcode(OPCODE_LTK_REPLY));

	/* EDIV=0/Rand=0 addresses the SC bond and is answered with the key. */
	evt_ncmds = 0;
	len = evt_pkt_ltk_request(pkt, 0x0043, 0, 0);
	ATF_REQUIRE(send(evt_hci_sp[1], pkt, len, 0) == (ssize_t)len);
	blued_handle_hci_event(&evt_adp);
	ATF_CHECK_EQ(1, evt_count_opcode(OPCODE_LTK_REPLY));

	blued_conn_free(c);
	blued_g.bond_db = NULL;
	evt_teardown();
}

/* ================================================================
 * Timer identity
 * ================================================================ */

/*
 * Pins C3-M6 (blued_event.c blued_idle_arm): every arm allocates a FRESH
 * ident, so an idle-timeout kevent the kernel already placed in this batch
 * cannot match the re-armed connection and disconnect a live link.
 */
ATF_TC_WITHOUT_HEAD(idle_rearm_allocates_fresh_ident);
ATF_TC_BODY(idle_rearm_allocates_fresh_ident, tc)
{
	struct blued_conn *c;
	struct kevent batch[1];
	uintptr_t first;

	evt_reset();

	c = evt_make_conn(BLUED_ROLE_PERIPHERAL, BLUED_CONN_ACTIVE);
	blued_idle_arm(c);
	first = c->idle_timer;
	ATF_REQUIRE(first != 0);
	blued_idle_arm(c);
	ATF_CHECK_MSG(c->idle_timer != first,
	    "re-arm reused ident %ju", (uintmax_t)first);

	/* The stale expiry for the FIRST ident matches no connection. */
	EV_SET(&batch[0], first, EVFILT_TIMER, 0, 0, 0, BLUED_KQ_IDLE_TIMEOUT);
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));
	ATF_CHECK_MSG(atomic_load(&c->state) != BLUED_CONN_IDLE,
	    "stale idle timeout disconnected a live connection");
	ATF_CHECK(c->idle_timer != 0);

	/*
	 * The current ident does fire, and the peripheral link is dropped --
	 * which frees the conn, so the assertion is on the registry.
	 */
	EV_SET(&batch[0], c->idle_timer, EVFILT_TIMER, 0, 0, 0,
	    BLUED_KQ_IDLE_TIMEOUT);
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));
	ATF_CHECK_MSG(LIST_EMPTY(&blued_g.conns),
	    "the live idle timeout did not disconnect");

	evt_teardown();
}

/*
 * Pins blued_idle_arm's peripheral-only guard: a central connection never
 * arms an idle timer (its liveness is the HOGP report stream).
 */
ATF_TC_WITHOUT_HEAD(idle_arm_is_peripheral_only);
ATF_TC_BODY(idle_arm_is_peripheral_only, tc)
{
	struct blued_conn *c;

	evt_reset();
	c = evt_make_conn(BLUED_ROLE_CENTRAL, BLUED_CONN_ACTIVE);
	blued_idle_arm(c);
	ATF_CHECK_EQ(0, c->idle_timer);
	blued_conn_free(c);
	evt_teardown();
}

/*
 * Pins the second recycled-allocation key in the reconnect-timer arm: the
 * event's ident must be the timer THIS conn armed.  A stale ONESHOT from a
 * freed conn that happens to alias the address is ignored, and the genuine
 * fire consumes the id so a late duplicate cannot match again.
 */
ATF_TC_WITHOUT_HEAD(reconnect_timer_rejects_stale_ident);
ATF_TC_BODY(reconnect_timer_rejects_stale_ident, tc)
{
	struct blued_conn *c;
	struct kevent batch[1];

	evt_reset();

	c = evt_make_conn(BLUED_ROLE_CENTRAL, BLUED_CONN_RECONNECTING);
	c->reconnect = true;
	c->reconnect_timer = 4242;
	c->reconnect_delay = 3;

	/* Wrong ident for this conn: ignored, id not consumed. */
	EV_SET(&batch[0], 4241, EVFILT_TIMER, 0, 0, 0, c);
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));
	ATF_CHECK_EQ(4242, c->reconnect_timer);
	ATF_CHECK_EQ(BLUED_CONN_RECONNECTING, atomic_load(&c->state));

	evt_teardown();
}

/*
 * Pins the first recycled-allocation key: a timer whose udata pointer matches
 * a live conn that is NOT a central conn awaiting reconnect is ignored.
 */
ATF_TC_WITHOUT_HEAD(reconnect_timer_rejects_wrong_role_or_state);
ATF_TC_BODY(reconnect_timer_rejects_wrong_role_or_state, tc)
{
	struct blued_conn *c;
	struct kevent batch[1];

	evt_reset();

	c = evt_make_conn(BLUED_ROLE_PERIPHERAL, BLUED_CONN_RECONNECTING);
	c->reconnect = true;
	c->reconnect_timer = 77;
	EV_SET(&batch[0], 77, EVFILT_TIMER, 0, 0, 0, c);
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));
	ATF_CHECK_EQ(77, c->reconnect_timer);

	/* Same conn, central role but ACTIVE: still refused. */
	c->role = BLUED_ROLE_CENTRAL;
	atomic_store(&c->state, BLUED_CONN_ACTIVE);
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));
	ATF_CHECK_EQ(77, c->reconnect_timer);

	evt_teardown();
}

/*
 * Pins the udata demux of the timer arms: an unknown conn pointer is dropped
 * without dereference, and the daemon-wide timers route to their own handlers.
 */
ATF_TC_WITHOUT_HEAD(timer_udata_demux);
ATF_TC_BODY(timer_udata_demux, tc)
{
	struct kevent batch[4];
	char scratch;

	evt_reset();

	EV_SET(&batch[0], 1, EVFILT_TIMER, 0, 0, 0, &scratch);
	EV_SET(&batch[1], 2, EVFILT_TIMER, 0, 0, 0, BLUED_KQ_SIGNCTR_FLUSH);
	EV_SET(&batch[2], 3, EVFILT_TIMER, 0, 0, 0, BLUED_KQ_CTL_ACCEPT_RETRY);
	EV_SET(&batch[3], 4, EVFILT_TIMER, 0, 0, 0, BLUED_KQ_READVERTISE);
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 4));

	/*
	 * Only the unknown-conn timer reaches the discoverable predicate; the
	 * three tagged timers are claimed by their own arms first.
	 */
	ATF_CHECK_EQ(1, blued_stub.discoverable_timer_calls);
	ATF_CHECK_EQ(1, blued_stub.discoverable_timer_last);

	evt_teardown();
}

/* ================================================================
 * Signal arm
 * ================================================================ */

/* Pins the signal arm: SIGHUP reloads and continues; anything else stops. */
ATF_TC_WITHOUT_HEAD(signal_arm_hup_reloads_other_stops);
ATF_TC_BODY(signal_arm_hup_reloads_other_stops, tc)
{
	struct kevent batch[2];

	evt_reset();

	EV_SET(&batch[0], SIGHUP, EVFILT_SIGNAL, 0, 0, 0, NULL);
	EV_SET(&batch[1], SIGHUP, EVFILT_SIGNAL, 0, 0, 0, NULL);
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 2));
	ATF_CHECK_EQ(2, blued_stub.reload_config_calls);
	ATF_CHECK_EQ(1, running);

	EV_SET(&batch[0], SIGTERM, EVFILT_SIGNAL, 0, 0, 0, NULL);
	EV_SET(&batch[1], SIGHUP, EVFILT_SIGNAL, 0, 0, 0, NULL);
	blued_event_batch_begin();
	ATF_CHECK(!blued_event_dispatch_batch(batch, 2));
	ATF_CHECK_EQ(0, running);
	/* The batch stopped AT the terminating signal; nothing after it ran. */
	ATF_CHECK_EQ(2, blued_stub.reload_config_calls);

	running = 1;
	evt_teardown();
}

/* ================================================================
 * Control-client identity within one batch
 * ================================================================ */

/*
 * Pins C3-M9 (blued_ctl_client_retire + blued_event_batch_begin): a control
 * client reaped during a batch is NOT freed until the NEXT batch opens, so its
 * heap address cannot be handed to a client accepted later in the same batch
 * and make a stale (udata, ident) pair forgeable.
 */
ATF_TC_WITHOUT_HEAD(reaped_ctl_client_survives_its_batch);
ATF_TC_BODY(reaped_ctl_client_survives_its_batch, tc)
{
	struct blued_ctl_client *client;
	struct kevent batch[1];
	int sp[2];

	evt_reset();

	client = evt_make_client(sp);
	evt_free_watch = client;

	/* Peer closes: EV_EOF on the client's descriptor reaps it. */
	close(sp[1]);
	EV_SET(&batch[0], client->fd, EVFILT_READ, EV_EOF, 0, 0, client);
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));

	ATF_CHECK(LIST_EMPTY(&blued_g.ctl_clients));
	ATF_CHECK_MSG(evt_free_watch_hits == 0,
	    "reaped client freed inside its own batch");

	/* Opening the next batch is what releases it. */
	blued_event_batch_begin();
	ATF_CHECK_EQ(1, evt_free_watch_hits);

	evt_teardown();
}

/*
 * Pins the stale-event guard `ev->udata == client && ev->ident == client->fd'
 * on BOTH dispatch paths: a matching udata with the wrong descriptor never
 * reaps, on the readable and on the writable side.
 */
ATF_TC_WITHOUT_HEAD(ctl_client_ident_must_match_fd);
ATF_TC_BODY(ctl_client_ident_must_match_fd, tc)
{
	struct blued_ctl_client *client;
	struct kevent batch[2];
	int sp[2];

	evt_reset();

	client = evt_make_client(sp);
	evt_free_watch = client;

	/* Same udata, a descriptor this client does not own. */
	EV_SET(&batch[0], (uintptr_t)client->fd + 1, EVFILT_READ, EV_EOF, 0, 0,
	    client);
	EV_SET(&batch[1], (uintptr_t)client->fd + 1, EVFILT_WRITE, EV_EOF, 0, 0,
	    client);
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 2));

	ATF_CHECK(!LIST_EMPTY(&blued_g.ctl_clients));
	blued_event_batch_begin();
	ATF_CHECK_EQ(0, evt_free_watch_hits);

	LIST_REMOVE(client, entries);
	free(client);
	close(sp[0]);
	close(sp[1]);
	evt_teardown();
}

/*
 * Pins the writable arm: a real EV_EOF on the client's own descriptor does
 * reap and retire it, on the same deferred-free discipline as the read path.
 */
ATF_TC_WITHOUT_HEAD(ctl_client_writable_eof_retires);
ATF_TC_BODY(ctl_client_writable_eof_retires, tc)
{
	struct blued_ctl_client *client;
	struct kevent batch[1];
	int sp[2];

	evt_reset();

	client = evt_make_client(sp);
	evt_free_watch = client;
	close(sp[1]);

	EV_SET(&batch[0], client->fd, EVFILT_WRITE, EV_EOF, 0, 0, client);
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));
	ATF_CHECK(LIST_EMPTY(&blued_g.ctl_clients));
	ATF_CHECK_EQ(0, evt_free_watch_hits);
	blued_event_batch_begin();
	ATF_CHECK_EQ(1, evt_free_watch_hits);

	evt_teardown();
}

/* ================================================================
 * blued_conn_disconnect: the disconnect_pending latch
 *
 * Stubbed out in all 13 programs that link ctl.c, so none of the three
 * use-after-free fixes that depend on this latch had any coverage.
 * ================================================================ */

/*
 * Pins finding 86: a CONNECTING conn is owned by its detached setup thread, so
 * a disconnect trigger only LATCHES; nothing is torn down under the thread.
 */
ATF_TC_WITHOUT_HEAD(disconnect_defers_while_connecting);
ATF_TC_BODY(disconnect_defers_while_connecting, tc)
{
	struct blued_conn *c;

	evt_reset();

	c = evt_make_conn(BLUED_ROLE_CENTRAL, BLUED_CONN_CONNECTING);
	blued_conn_disconnect(c);
	ATF_CHECK(atomic_load(&c->disconnect_pending));
	ATF_CHECK_EQ(BLUED_CONN_CONNECTING, atomic_load(&c->state));
	ATF_CHECK(!LIST_EMPTY(&blued_g.conns));

	blued_conn_free(c);
	evt_teardown();
}

/*
 * Pins C3-M1: the latch is stored BEFORE att_ops_active is read, and an
 * in-flight ATT op defers the whole teardown (the store-then-load half of the
 * Dekker handshake with blued_conn_att_ops_end).
 */
ATF_TC_WITHOUT_HEAD(disconnect_defers_while_att_ops_in_flight);
ATF_TC_BODY(disconnect_defers_while_att_ops_in_flight, tc)
{
	struct blued_conn *c;

	evt_reset();

	c = evt_make_conn(BLUED_ROLE_PERIPHERAL, BLUED_CONN_ACTIVE);
	blued_conn_att_ops_begin(c);
	blued_conn_disconnect(c);
	ATF_CHECK_MSG(atomic_load(&c->disconnect_pending),
	    "latch not left set for the retiring worker to observe");
	ATF_CHECK(!LIST_EMPTY(&blued_g.conns));

	/* With no op in flight the same call clears the latch and proceeds. */
	blued_conn_att_ops_end(c);
	blued_conn_disconnect(c);
	ATF_CHECK(LIST_EMPTY(&blued_g.conns));

	evt_teardown();
}

/*
 * Pins finding 45: a central conn already awaiting its reconnect timer is a
 * no-op for a second disconnect trigger in the same batch -- the armed ONESHOT
 * must not be overwritten (leaked) nor a second setup thread spawned.  A
 * reconnect=false teardown is still allowed through.
 */
ATF_TC_WITHOUT_HEAD(disconnect_is_noop_while_awaiting_reconnect);
ATF_TC_BODY(disconnect_is_noop_while_awaiting_reconnect, tc)
{
	struct blued_conn *c;

	evt_reset();

	c = evt_make_conn(BLUED_ROLE_CENTRAL, BLUED_CONN_RECONNECTING);
	c->reconnect = true;
	c->reconnect_timer = 999;
	c->reconnect_delay = 12;
	blued_conn_disconnect(c);
	ATF_CHECK_EQ(999, c->reconnect_timer);
	ATF_CHECK_EQ(12, c->reconnect_delay);
	ATF_CHECK(!LIST_EMPTY(&blued_g.conns));

	/* An adapter-loss teardown (reconnect cleared) finalizes it. */
	c->reconnect = false;
	blued_conn_disconnect(c);
	ATF_CHECK(LIST_EMPTY(&blued_g.conns));

	evt_teardown();
}

/* Pins the double-disconnect guard: an IDLE conn is never torn down twice. */
ATF_TC_WITHOUT_HEAD(disconnect_is_noop_when_idle);
ATF_TC_BODY(disconnect_is_noop_when_idle, tc)
{
	struct blued_conn *c;

	evt_reset();
	c = evt_make_conn(BLUED_ROLE_PERIPHERAL, BLUED_CONN_IDLE);
	blued_conn_disconnect(c);
	ATF_CHECK(!LIST_EMPTY(&blued_g.conns));
	blued_conn_free(c);
	evt_teardown();
}

/*
 * Pins finding H-M1: entering reconnect backoff clears con_handle_valid and
 * NULLs conn->att immediately, so the Encryption-Change / Key-Refresh / APTO
 * arms -- which match purely on the handle -- cannot act on this conn using a
 * handle the controller may reassign during the backoff window.
 */
ATF_TC_WITHOUT_HEAD(disconnect_invalidates_handle_on_reconnect_backoff);
ATF_TC_BODY(disconnect_invalidates_handle_on_reconnect_backoff, tc)
{
	struct blued_conn *c;
	struct att_conn att;

	evt_reset();

	memset(&att, 0, sizeof(att));
	att.fd = -1;
	c = evt_make_conn(BLUED_ROLE_CENTRAL, BLUED_CONN_ACTIVE);
	c->reconnect = true;
	c->reconnect_delay = 3;
	c->con_handle = 0x0050;
	c->con_handle_valid = true;
	c->att = &att;

	blued_conn_disconnect(c);

	ATF_CHECK_EQ(BLUED_CONN_RECONNECTING, atomic_load(&c->state));
	ATF_CHECK_MSG(!c->con_handle_valid, "stale handle left valid");
	ATF_CHECK_MSG(c->att == NULL, "stale ATT state left attached");
	ATF_CHECK(c->reconnect_timer != 0);
	ATF_CHECK_EQ(6, c->reconnect_delay);	/* exponential backoff */

	blued_conn_free(c);
	evt_teardown();
}

/*
 * Pins the reconnect backoff ceiling: the delay saturates at
 * blued_reconnect_max_delay rather than doubling without bound.
 */
ATF_TC_WITHOUT_HEAD(disconnect_reconnect_backoff_saturates);
ATF_TC_BODY(disconnect_reconnect_backoff_saturates, tc)
{
	struct blued_conn *c;

	evt_reset();
	blued_reconnect_max_delay = 20;

	c = evt_make_conn(BLUED_ROLE_CENTRAL, BLUED_CONN_ACTIVE);
	c->reconnect = true;
	c->reconnect_delay = 16;
	blued_conn_disconnect(c);
	ATF_CHECK_EQ(20, c->reconnect_delay);

	blued_reconnect_max_delay = 60;
	blued_conn_free(c);
	evt_teardown();
}

/* ================================================================
 * Setup-pipe sweep
 * ================================================================ */

/*
 * Pins the needs_cleanup arm of the setup-pipe sweep: a CONNECTING conn flagged
 * for terminal teardown is DEFERRED (latch + keep the flag) rather than freed
 * under its still-running setup thread.
 */
ATF_TC_WITHOUT_HEAD(sweep_defers_terminal_cleanup_while_connecting);
ATF_TC_BODY(sweep_defers_terminal_cleanup_while_connecting, tc)
{
	struct blued_conn *c;
	struct kevent batch[1];

	evt_reset();

	c = evt_make_conn(BLUED_ROLE_CENTRAL, BLUED_CONN_CONNECTING);
	atomic_store(&c->needs_cleanup, true);

	EV_SET(&batch[0], blued_g.setup_pipe[0], EVFILT_READ, 0, 0, 0,
	    BLUED_KQ_SETUP_PIPE);
	evt_poke_setup_pipe();
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));

	ATF_REQUIRE_MSG(!LIST_EMPTY(&blued_g.conns),
	    "conn freed under its setup thread");
	ATF_CHECK(atomic_load(&c->needs_cleanup));
	ATF_CHECK(atomic_load(&c->disconnect_pending));

	blued_conn_free(c);
	evt_teardown();
}

/*
 * Pins finding H-H2: terminal cleanup of a non-CONNECTING conn still defers
 * while an ATT op is in flight, and completes once the worker retires.
 */
ATF_TC_WITHOUT_HEAD(sweep_terminal_cleanup_waits_for_att_ops);
ATF_TC_BODY(sweep_terminal_cleanup_waits_for_att_ops, tc)
{
	struct blued_conn *c;
	struct kevent batch[1];

	evt_reset();

	c = evt_make_conn(BLUED_ROLE_PERIPHERAL, BLUED_CONN_ACTIVE);
	atomic_store(&c->needs_cleanup, true);
	blued_conn_att_ops_begin(c);

	EV_SET(&batch[0], blued_g.setup_pipe[0], EVFILT_READ, 0, 0, 0,
	    BLUED_KQ_SETUP_PIPE);
	evt_poke_setup_pipe();
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));
	ATF_CHECK_MSG(!LIST_EMPTY(&blued_g.conns),
	    "conn freed under an in-flight ATT op");
	ATF_CHECK(atomic_load(&c->disconnect_pending));

	blued_conn_att_ops_end(c);
	evt_poke_setup_pipe();
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));
	ATF_CHECK(LIST_EMPTY(&blued_g.conns));

	evt_teardown();
}

/*
 * Pins the RECONNECTING carve-out in the disconnect_pending arm of the sweep:
 * consuming the latch for a conn awaiting reconnect must NOT swallow its
 * pending needs_reconnect_arm, or the conn sits in RECONNECTING forever
 * holding a connection slot with no timer armed.
 */
ATF_TC_WITHOUT_HEAD(sweep_reconnect_arm_survives_pending_disconnect);
ATF_TC_BODY(sweep_reconnect_arm_survives_pending_disconnect, tc)
{
	struct blued_conn *c;
	struct kevent batch[1];

	evt_reset();

	c = evt_make_conn(BLUED_ROLE_CENTRAL, BLUED_CONN_RECONNECTING);
	c->reconnect = true;
	c->reconnect_delay = 0;
	atomic_store(&c->disconnect_pending, true);
	atomic_store(&c->needs_reconnect_arm, true);

	EV_SET(&batch[0], blued_g.setup_pipe[0], EVFILT_READ, 0, 0, 0,
	    BLUED_KQ_SETUP_PIPE);
	evt_poke_setup_pipe();
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));

	ATF_CHECK(!LIST_EMPTY(&blued_g.conns));
	ATF_CHECK_MSG(c->reconnect_timer != 0,
	    "reconnect arm swallowed by the disconnect latch");
	/* Unset delay defaults to 3 seconds, then doubles for the next try. */
	ATF_CHECK_EQ(6, c->reconnect_delay);
	ATF_CHECK(!atomic_load(&c->needs_reconnect_arm));

	blued_conn_free(c);
	evt_teardown();
}

/*
 * Pins the ACTIVE-before-register ordering the sweep depends on (findings
 * C1/C2/C5): the CONNECTED push event is emitted once, only after the setup
 * thread has moved the conn to ACTIVE *and* a controller handle exists.
 */
ATF_TC_WITHOUT_HEAD(sweep_announces_active_conn_once);
ATF_TC_BODY(sweep_announces_active_conn_once, tc)
{
	struct blued_conn *c;
	struct kevent batch[1];

	evt_reset();

	c = evt_make_conn(BLUED_ROLE_PERIPHERAL, BLUED_CONN_ACTIVE);
	EV_SET(&batch[0], blued_g.setup_pipe[0], EVFILT_READ, 0, 0, 0,
	    BLUED_KQ_SETUP_PIPE);

	/* ACTIVE but no controller handle yet: not announced. */
	evt_poke_setup_pipe();
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));
	ATF_CHECK_MSG(!c->announced, "announced before the handle existed");

	c->con_handle = 0x0060;
	c->con_handle_valid = true;
	evt_poke_setup_pipe();
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));
	ATF_CHECK(c->announced);

	/* Idempotent: a second sweep does not re-announce. */
	c->announced = false;
	atomic_store(&c->state, BLUED_CONN_CONNECTING);
	evt_poke_setup_pipe();
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));
	ATF_CHECK_MSG(!c->announced, "announced a conn that is not ACTIVE");

	atomic_store(&c->state, BLUED_CONN_ACTIVE);
	blued_conn_free(c);
	evt_teardown();
}

/* ================================================================
 * Adapter loss
 * ================================================================ */

/*
 * Pins blued_adapter_lost(): an EV_EOF on the HCI descriptor stops watching
 * the dead fd, tears down this adapter's connections WITHOUT reconnect, clears
 * the periodic-sync shadow and marks the adapter inactive -- and is idempotent,
 * so the level-triggered event cannot spin the loop.
 */
ATF_TC_WITHOUT_HEAD(adapter_loss_tears_down_and_is_idempotent);
ATF_TC_BODY(adapter_loss_tears_down_and_is_idempotent, tc)
{
	struct blued_conn *c;
	struct kevent batch[2];

	evt_reset();

	c = evt_make_conn(BLUED_ROLE_CENTRAL, BLUED_CONN_ACTIVE);
	c->reconnect = true;
	evt_adp.periodic_adv_enabled = true;
	evt_adp.periodic_sync_pending = true;
	evt_adp.periodic_syncs[0] = 0xff;

	EV_SET(&batch[0], evt_adp.hci_fd, EVFILT_READ, EV_EOF, 0, 0, &evt_adp);
	EV_SET(&batch[1], evt_adp.hci_fd, EVFILT_READ, EV_EOF, 0, 0, &evt_adp);
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 2));

	ATF_CHECK_MSG(!evt_adp.active, "adapter left active after EOF");
	ATF_CHECK(LIST_EMPTY(&blued_g.conns));
	ATF_CHECK(!evt_adp.periodic_adv_enabled);
	ATF_CHECK(!evt_adp.periodic_sync_pending);
	ATF_CHECK_EQ(0, evt_adp.periodic_syncs[0]);

	evt_teardown();
}

/* ================================================================
 * Unroutable events
 * ================================================================ */

/*
 * Pins the fall-through of blued_handle_readable(): an event whose udata
 * matches nothing is logged and dropped, never dereferenced.
 */
ATF_TC_WITHOUT_HEAD(unroutable_readable_event_is_dropped);
ATF_TC_BODY(unroutable_readable_event_is_dropped, tc)
{
	struct kevent batch[1];
	char scratch;

	evt_reset();
	EV_SET(&batch[0], 4096, EVFILT_READ, 0, 0, 0, &scratch);
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));
	evt_teardown();
}

/*
 * Pins the supervisor arm: the lost-switchboard event deregisters itself so the
 * level-triggered EV_EOF cannot busy-spin the loop.
 */
ATF_TC_WITHOUT_HEAD(supervisor_loss_deregisters);
ATF_TC_BODY(supervisor_loss_deregisters, tc)
{
	struct kevent batch[1], probe;
	int sp[2];

	evt_reset();
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	EV_SET(&probe, sp[0], EVFILT_READ, EV_ADD, 0, 0, BLUED_KQ_SUPERVISOR);
	ATF_REQUIRE_EQ(0, kevent(blued_g.kq, &probe, 1, NULL, 0, NULL));

	EV_SET(&batch[0], sp[0], EVFILT_READ, EV_EOF, 0, 0, BLUED_KQ_SUPERVISOR);
	blued_event_batch_begin();
	ATF_CHECK(blued_event_dispatch_batch(batch, 1));

	/* The registration is gone: deleting it again fails with ENOENT. */
	EV_SET(&probe, sp[0], EVFILT_READ, EV_DELETE, 0, 0, NULL);
	ATF_CHECK_EQ(-1, kevent(blued_g.kq, &probe, 1, NULL, 0, NULL));
	ATF_CHECK_EQ(ENOENT, errno);

	close(sp[0]);
	close(sp[1]);
	evt_teardown();
}


/* ================================================================
 * LE Remote Connection Parameter Request (subevent 0x06) is ANSWERED
 * ================================================================ */

#define	OPCODE_CONN_PARAM_REPLY						\
	NG_HCI_OPCODE(NG_HCI_OGF_LE,					\
	    NG_HCI_OCF_LE_REMOTE_CONN_PARAM_REQ_REPLY)
#define	OPCODE_CONN_PARAM_NEG_REPLY					\
	NG_HCI_OPCODE(NG_HCI_OGF_LE,					\
	    NG_HCI_OCF_LE_REMOTE_CONN_PARAM_REQ_NEG_REPLY)

/* LE Remote Connection Parameter Request (§7.7.65.6). */
static size_t
evt_pkt_conn_param_req(uint8_t *out, uint16_t handle, uint16_t imin,
    uint16_t imax, uint16_t latency, uint16_t timeout)
{

	out[0] = NG_HCI_EVENT_PKT;
	out[1] = 0x3e;
	out[2] = 11;
	out[3] = NG_HCI_LEEV_REMOTE_CONN_PARAM_REQUEST;
	out[4] = (uint8_t)(handle & 0xff);
	out[5] = (uint8_t)(handle >> 8);
	out[6] = (uint8_t)(imin & 0xff);
	out[7] = (uint8_t)(imin >> 8);
	out[8] = (uint8_t)(imax & 0xff);
	out[9] = (uint8_t)(imax >> 8);
	out[10] = (uint8_t)(latency & 0xff);
	out[11] = (uint8_t)(latency >> 8);
	out[12] = (uint8_t)(timeout & 0xff);
	out[13] = (uint8_t)(timeout >> 8);
	return (14);
}

/*
 * Core Vol 6 Part B §5.1.7.2: a request the Link Layer must indicate to the
 * Host is rejected ON AIR with Unsupported Remote Feature (0x1A) when the
 * Host does not answer.  The daemon must therefore answer every request --
 * with the Reply for a proposal it would have made itself, and otherwise with
 * the Negative Reply carrying Unacceptable Connection Parameters (0x3B).
 */
ATF_TC_WITHOUT_HEAD(conn_param_request_is_answered);
ATF_TC_BODY(conn_param_request_is_answered, tc)
{
	uint8_t pkt[32];
	size_t len;

	evt_reset();

	/* 30-50 ms, latency 4, 2.56 s supervision timeout: acceptable. */
	len = evt_pkt_conn_param_req(pkt, 0x0044, 0x0018, 0x0028, 0x0004,
	    0x0100);
	ATF_REQUIRE(send(evt_hci_sp[1], pkt, len, 0) == (ssize_t)len);
	blued_handle_hci_event(&evt_adp);

	ATF_CHECK_EQ_MSG(1, evt_count_opcode(OPCODE_CONN_PARAM_REPLY),
	    "an acceptable request must be answered with the Reply");
	ATF_CHECK_EQ(0, evt_count_opcode(OPCODE_CONN_PARAM_NEG_REPLY));
	ATF_REQUIRE(evt_ncmds >= 1);
	ATF_CHECK_EQ(evt_adp.hci_fd, evt_cmds[0].fd);
	/* The peer's own values are echoed back (§7.8.31 field order). */
	ATF_CHECK_EQ(14, evt_cmds[0].clen);
	ATF_CHECK_EQ(0x44, evt_cmds[0].cparam[0]);
	ATF_CHECK_EQ(0x18, evt_cmds[0].cparam[2]);
	ATF_CHECK_EQ(0x28, evt_cmds[0].cparam[4]);
	ATF_CHECK_EQ(0x04, evt_cmds[0].cparam[6]);
	ATF_CHECK_EQ(0x00, evt_cmds[0].cparam[8]);
	ATF_CHECK_EQ(0x01, evt_cmds[0].cparam[9]);

	/* A supervision timeout too short for the latency is refused. */
	evt_ncmds = 0;
	memset(evt_cmds, 0, sizeof(evt_cmds));
	len = evt_pkt_conn_param_req(pkt, 0x0044, 0x0018, 0x0028, 0x0004,
	    0x000A);
	ATF_REQUIRE(send(evt_hci_sp[1], pkt, len, 0) == (ssize_t)len);
	blued_handle_hci_event(&evt_adp);

	ATF_CHECK_EQ_MSG(1, evt_count_opcode(OPCODE_CONN_PARAM_NEG_REPLY),
	    "an unacceptable request must still be answered");
	ATF_CHECK_EQ(0, evt_count_opcode(OPCODE_CONN_PARAM_REPLY));
	ATF_REQUIRE(evt_ncmds >= 1);
	ATF_CHECK_EQ(3, evt_cmds[0].clen);
	ATF_CHECK_EQ(0x3b, evt_cmds[0].cparam[2]);

	/* A quiescing adapter declines -- but still answers. */
	evt_ncmds = 0;
	evt_adp.power_quiescing = true;
	len = evt_pkt_conn_param_req(pkt, 0x0044, 0x0018, 0x0028, 0x0004,
	    0x0100);
	ATF_REQUIRE(send(evt_hci_sp[1], pkt, len, 0) == (ssize_t)len);
	blued_handle_hci_event(&evt_adp);
	ATF_CHECK_EQ(1, evt_count_opcode(OPCODE_CONN_PARAM_NEG_REPLY));
	evt_adp.power_quiescing = false;

	evt_teardown();
}

/* ================================================================
 * Multi-report advertising events: one bad report costs one report
 * ================================================================ */

/*
 * Build an LE Advertising Report event (§7.7.65.2) carrying three legacy
 * reports, each with one Mesh Message AD structure.  Report 1 carries a
 * reserved Event_Type, which the host declines.
 *
 * Legacy report: event_type(1) addr_type(1) addr(6) data_len(1) data[]
 * rssi(1).
 */
static size_t
evt_pkt_mesh_adv_three(uint8_t *out, uint8_t bad_event_type)
{
	size_t off = 5;
	int i;

	out[0] = NG_HCI_EVENT_PKT;
	out[1] = 0x3e;
	out[3] = 0x02;			/* LE Advertising Report */
	out[4] = 3;			/* Num_Reports */
	for (i = 0; i < 3; i++) {
		out[off + 0] = (i == 1) ? bad_event_type : 0x03;
		out[off + 1] = 0x00;	/* address type: public */
		memset(out + off + 2, 0x10 + i, 6);
		out[off + 8] = 3;	/* Data_Length */
		out[off + 9] = 0x02;	/* AD length */
		out[off + 10] = 0x2a;	/* AD type: Mesh Message */
		out[off + 11] = (uint8_t)(0xA0 + i);
		out[off + 12] = (uint8_t)(int8_t)-60;	/* RSSI */
		off += 13;
	}
	out[2] = (uint8_t)(off - 3);
	return (off);
}

/*
 * Count the mesh reports delivered to a ctl client.  The client socket is a
 * byte stream, so frames coalesce; each report here carries a unique payload
 * octet (0xA0 + report index) and those are counted instead of read(2) calls.
 */
static unsigned int
evt_client_mesh_reports(int fd)
{
	uint8_t buf[1024];
	unsigned int n = 0;
	ssize_t got;
	size_t i;

	while ((got = recv(fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0)
		for (i = 0; i < (size_t)got; i++)
			if (buf[i] >= 0xA0 && buf[i] <= 0xA2)
				n++;
	return (n);
}

/*
 * §7.7.65.2 / §7.7.65.13 give no rule that authorises discarding an event
 * because ONE of its reports carries a value the host declines, and no
 * reference implementation does: NimBLE advances past the report and
 * continues, Zephyr keeps everything already delivered, BlueZ labels the value
 * "Reserved" and continues.  Each report's length is fully determined by its
 * own Data_Length, so a bad report is always skippable -- and dropping the
 * batch loses valid mesh beacons intermittently, on exactly the controllers
 * that coalesce reports.
 */
ATF_TC_WITHOUT_HEAD(mesh_adv_batch_skips_only_bad_report);
ATF_TC_BODY(mesh_adv_batch_skips_only_bad_report, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	uint8_t pkt[128];
	size_t len;

	evt_reset();
	evt_adp.mesh_scan_active = true;
	client = evt_make_client(sp);
	client->mesh_sub = true;

	/* Report 1's Event_Type 0x05 is outside the §7.7.65.2 range 0x00-0x04. */
	len = evt_pkt_mesh_adv_three(pkt, 0x05);
	ATF_REQUIRE(send(evt_hci_sp[1], pkt, len, 0) == (ssize_t)len);
	blued_handle_hci_event(&evt_adp);

	ATF_CHECK_EQ_MSG(2, evt_client_mesh_reports(sp[1]),
	    "a reserved value in one report must not discard the others");

	/* With every report well formed, all three are forwarded. */
	len = evt_pkt_mesh_adv_three(pkt, 0x03);
	ATF_REQUIRE(send(evt_hci_sp[1], pkt, len, 0) == (ssize_t)len);
	blued_handle_hci_event(&evt_adp);
	ATF_CHECK_EQ(3, evt_client_mesh_reports(sp[1]));

	/*
	 * A framing error is different: the next report's offset is unknown,
	 * so the walk stops.  Here report 0 declares more data than the event
	 * holds, and nothing is forwarded.
	 */
	len = evt_pkt_mesh_adv_three(pkt, 0x03);
	pkt[5 + 8] = 0x40;		/* Data_Length past the end */
	ATF_REQUIRE(send(evt_hci_sp[1], pkt, len, 0) == (ssize_t)len);
	blued_handle_hci_event(&evt_adp);
	ATF_CHECK_EQ(0, evt_client_mesh_reports(sp[1]));

	LIST_REMOVE(client, entries);
	free(client);
	close(sp[0]);
	close(sp[1]);
	evt_teardown();
}


/*
 * RPA rotation generates one address PER ADAPTER.
 *
 * A resolvable private address exists to stop an observer linking a device
 * across sightings (Core Vol 3 Part C §10.7).  Handing the SAME address to
 * every adapter has both adapters advertise, scan and initiate from one
 * address at the same time, so an observer that sees both sees one device --
 * defeating the mechanism for a multi-adapter host.
 */
ATF_TC_WITHOUT_HEAD(rpa_rotation_is_per_adapter);
ATF_TC_BODY(rpa_rotation_is_per_adapter, tc)
{
	struct blued_adapter second;
	struct kevent batch[1];

	evt_reset();
	evt_adp.privacy = true;

	memset(&second, 0, sizeof(second));
	second.hci_fd = evt_hci_sp[1];
	second.index = 1;
	second.active = true;
	second.powered = true;
	second.privacy = true;
	second.periph_listen_fd = -1;
	second.eatt_listen_fd = -1;
	strlcpy(second.name, "ubt1", sizeof(second.name));
	LIST_INSERT_HEAD(&blued_g.adapters, &second, entries);

	/* A non-zero IRK: ah() over an all-zero key is still a valid RPA,
	 * but a realistic identity keeps the generator honest. */
	memset(blued_local_irk, 0x5a, sizeof(blued_local_irk));

	EV_SET(&batch[0], 1, EVFILT_TIMER, 0, 0, 0, BLUED_KQ_RPA_TIMER);
	blued_event_batch_begin();
	(void)blued_event_dispatch_batch(batch, 1);

	ATF_REQUIRE_EQ_MSG(2, blued_stub.rotate_rpa_calls,
	    "both adapters must be rotated");
	ATF_CHECK_MSG(memcmp(blued_stub.rotate_rpa_addrs[0],
	    blued_stub.rotate_rpa_addrs[1], 6) != 0,
	    "adapters were given the SAME resolvable private address");
	ATF_CHECK(blued_stub.rotate_rpa_adapters[0] !=
	    blued_stub.rotate_rpa_adapters[1]);

	LIST_REMOVE(&second, entries);
	evt_teardown();
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, defer_bulk_reserve_holds_back_reports);
	ATF_TP_ADD_TC(tp, defer_priority_evicts_bulk_when_full);
	ATF_TP_ADD_TC(tp, defer_preserves_control_event_order);
	ATF_TP_ADD_TC(tp, defer_drops_packet_for_departed_adapter);
	ATF_TP_ADD_TC(tp, defer_replays_before_socket_read);
	ATF_TP_ADD_TC(tp, defer_rejects_malformed_lengths);
	ATF_TP_ADD_TC(tp, ltk_request_silent_while_smp_owns);
	ATF_TP_ADD_TC(tp, ltk_request_sc_bond_rejects_nonzero_ediv);
	ATF_TP_ADD_TC(tp, idle_rearm_allocates_fresh_ident);
	ATF_TP_ADD_TC(tp, idle_arm_is_peripheral_only);
	ATF_TP_ADD_TC(tp, reconnect_timer_rejects_stale_ident);
	ATF_TP_ADD_TC(tp, reconnect_timer_rejects_wrong_role_or_state);
	ATF_TP_ADD_TC(tp, timer_udata_demux);
	ATF_TP_ADD_TC(tp, signal_arm_hup_reloads_other_stops);
	ATF_TP_ADD_TC(tp, reaped_ctl_client_survives_its_batch);
	ATF_TP_ADD_TC(tp, ctl_client_ident_must_match_fd);
	ATF_TP_ADD_TC(tp, ctl_client_writable_eof_retires);
	ATF_TP_ADD_TC(tp, disconnect_defers_while_connecting);
	ATF_TP_ADD_TC(tp, disconnect_defers_while_att_ops_in_flight);
	ATF_TP_ADD_TC(tp, disconnect_is_noop_while_awaiting_reconnect);
	ATF_TP_ADD_TC(tp, disconnect_is_noop_when_idle);
	ATF_TP_ADD_TC(tp, disconnect_invalidates_handle_on_reconnect_backoff);
	ATF_TP_ADD_TC(tp, disconnect_reconnect_backoff_saturates);
	ATF_TP_ADD_TC(tp, sweep_defers_terminal_cleanup_while_connecting);
	ATF_TP_ADD_TC(tp, sweep_terminal_cleanup_waits_for_att_ops);
	ATF_TP_ADD_TC(tp, sweep_reconnect_arm_survives_pending_disconnect);
	ATF_TP_ADD_TC(tp, sweep_announces_active_conn_once);
	ATF_TP_ADD_TC(tp, adapter_loss_tears_down_and_is_idempotent);
	ATF_TP_ADD_TC(tp, unroutable_readable_event_is_dropped);
	ATF_TP_ADD_TC(tp, supervisor_loss_deregisters);
	ATF_TP_ADD_TC(tp, conn_param_request_is_answered);
	ATF_TP_ADD_TC(tp, mesh_adv_batch_skips_only_bad_report);
	ATF_TP_ADD_TC(tp, rpa_rotation_is_per_adapter);

	return (atf_no_error());
}
