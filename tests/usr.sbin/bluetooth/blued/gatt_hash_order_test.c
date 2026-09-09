/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * GATT Database Hash WIRE BYTE ORDER.
 *
 * Nothing in this directory asserted the octets blued actually puts in the
 * Database Hash characteristic value: the existing coverage stops at
 * attdb_compute_db_hash(), i.e. at the AES-CMAC result, and every publish site
 * copied that result to the wire unexamined.  That is exactly how the
 * BlueZ/Zephyr split (a genuine, deliberate disagreement about the octet order
 * of this one characteristic -- see spec_extref_db_hash.h) survived unnoticed.
 *
 * These cases drive the REAL server and client paths and compare against the
 * two external oracles:
 *
 *   bt_extref_db_hash_wire_bluez[]      what BlueZ transmits (raw AES-CMAC,
 *                                       most significant octet first)
 *   bt_extref_db_hash_wire_zephyr_pts[] what Zephyr transmits and what SIG
 *                                       qualification test GATT/SR/GAS/BV-02-C
 *                                       expects (the exact reverse)
 *
 * Both oracles are external to this tree; neither was produced by running
 * blued.  The default mode must match the first, the opt-in "reversed" mode
 * the second, and the underlying computation must be identical in both.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>

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

#include "spec_extref_db_hash.h"

/* The daemon harness links the real hci_*.c; keep the controller quiet. */
int	__wrap_bt_devreq(int s, struct bt_devreq *r, time_t to);

int
__wrap_bt_devreq(int s __unused, struct bt_devreq *r, time_t to __unused)
{

	if (r->rparam != NULL && r->rlen > 0)
		memset(r->rparam, 0, r->rlen);
	return (0);
}

#define	HO_MAX_ATTRS	48
#define	HO_VAL_SIZE	1024

static struct att_attr	 ho_attrs[HO_MAX_ATTRS];
static uint8_t		 ho_valbuf[HO_VAL_SIZE];

/*
 * Backing store for the daemon's shared peripheral database.  periph_gatt_db
 * itself comes from blued_daemon_stub.c; its arrays live in blued.c, which the
 * stub replaces, so the storage is supplied here (as blued_role_test.c does).
 */
static struct att_attr	 ho_periph_attrs[64];
static uint8_t		 ho_periph_valbuf[2048];

/*
 * Bring the daemon globals up far enough for the real peripheral/ctl objects
 * (the same seam blued_role_test.c uses) and reset the wire order to the
 * shipped default so no case can leak its setting into the next.
 */
static void
ho_reset(void)
{

	blued_stub_reset();
	memset(&blued_g, 0, sizeof(blued_g));
	blued_g.kq = -1;
	blued_g.ctl_fd = -1;
	blued_g.bond_fd = -1;
	blued_g.vhid_ctl_fd = -1;
	blued_g.persist_dirfd = -1;
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
	signal(SIGPIPE, SIG_IGN);
	gatt_set_db_hash_byte_order(GATT_DB_HASH_ORDER_BLUEZ);
}

/* Append one attribute exactly as att_server_hash.c consumes it. */
static void
ho_add(struct att_db *db, uint16_t handle, uint16_t uuid16, bool is_char_value,
    const uint8_t *value, uint16_t len, uint8_t perms)
{
	struct att_attr *a = &db->attrs[db->count++];

	memset(a, 0, sizeof(*a));
	a->handle = handle;
	a->uuid16 = uuid16;
	a->is_char_value = is_char_value;
	a->perms = perms;
	a->owner_fd = -1;
	if (len > 0) {
		a->value = db->val_store + db->val_used;
		memcpy(a->value, value, len);
		a->value_len = len;
		db->val_used += len;
	}
}

/*
 * Reproduce the Core 6.3 Vol 3 Part G Appendix B example database, whose hash
 * the specification publishes.  Identical in every hashed field to the
 * fixture in att_server_edge_test.c, except that the Database Hash
 * characteristic value is the full 16 octets a real server publishes (the
 * value of a characteristic is excluded from m, so the hash is unaffected --
 * every case below re-asserts that against the oracle) and is readable, so it
 * can be fetched through the ATT server.
 *
 * Returns the Database Hash characteristic VALUE handle.
 */
static uint16_t
ho_build_appendix_b(struct att_db *db)
{
	static const uint8_t zero16[GATT_DB_HASH_LEN] = { 0 };

	attdb_init(db, ho_attrs, HO_MAX_ATTRS, ho_valbuf, HO_VAL_SIZE);

	ho_add(db, 0x0001, 0x2800, false, (const uint8_t[]){0x00,0x18}, 2, 0);
	ho_add(db, 0x0002, 0x2803, false,
	    (const uint8_t[]){0x0A,0x03,0x00,0x00,0x2A}, 5, 0);
	ho_add(db, 0x0003, 0x2A00, true, (const uint8_t[]){0xDE,0xAD}, 2, 0);
	ho_add(db, 0x0004, 0x2803, false,
	    (const uint8_t[]){0x02,0x05,0x00,0x01,0x2A}, 5, 0);
	ho_add(db, 0x0005, 0x2A01, true, (const uint8_t[]){0x00,0x00}, 2, 0);
	ho_add(db, 0x0006, 0x2800, false, (const uint8_t[]){0x01,0x18}, 2, 0);
	ho_add(db, 0x0007, 0x2803, false,
	    (const uint8_t[]){0x20,0x08,0x00,0x05,0x2A}, 5, 0);
	ho_add(db, 0x0008, 0x2A05, true, (const uint8_t[]){0x00,0x00}, 2, 0);
	ho_add(db, 0x0009, 0x2902, false, (const uint8_t[]){0x02,0x00}, 2, 0);
	ho_add(db, 0x000A, 0x2803, false,
	    (const uint8_t[]){0x0A,0x0B,0x00,0x29,0x2B}, 5, 0);
	ho_add(db, 0x000B, 0x2B29, true, (const uint8_t[]){0x00}, 1, 0);
	ho_add(db, 0x000C, 0x2803, false,
	    (const uint8_t[]){0x02,0x0D,0x00,0x2A,0x2B}, 5, 0);
	/* 0x000D: the Database Hash characteristic value, readable, 16 bytes. */
	ho_add(db, 0x000D, BT_EXTREF_DB_HASH_UUID16, true, zero16,
	    GATT_DB_HASH_LEN, ATT_PERM_READ);
	ho_add(db, 0x000E, 0x2800, false, (const uint8_t[]){0x08,0x18}, 2, 0);
	ho_add(db, 0x000F, 0x2802, false,
	    (const uint8_t[]){0x14,0x00,0x16,0x00,0x0F,0x18}, 6, 0);
	ho_add(db, 0x0010, 0x2803, false,
	    (const uint8_t[]){0xA2,0x11,0x00,0x18,0x2A}, 5, 0);
	ho_add(db, 0x0011, 0x2A18, true, (const uint8_t[]){0x00}, 1, 0);
	ho_add(db, 0x0012, 0x2902, false, (const uint8_t[]){0x02,0x00}, 2, 0);
	ho_add(db, 0x0013, 0x2900, false, (const uint8_t[]){0x00,0x00}, 2, 0);
	ho_add(db, 0x0014, 0x2801, false, (const uint8_t[]){0x0F,0x18}, 2, 0);
	ho_add(db, 0x0015, 0x2803, false,
	    (const uint8_t[]){0x02,0x16,0x00,0x19,0x2A}, 5, 0);
	ho_add(db, 0x0016, 0x2A19, true, (const uint8_t[]){0x00}, 1, 0);

	return (0x000D);
}

/* A socketpair-backed server-side ATT connection. */
static void
ho_srv_pair(struct att_conn *ac, int *peer_fd)
{
	int fds[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(ac, 0, sizeof(*ac));
	ac->fd = fds[0];
	ac->bearer_fd = -1;
	ac->mtu = ATT_PDU_BUF_SIZE;
	ac->buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
	*peer_fd = fds[1];
}

static void
ho_srv_cleanup(struct att_conn *ac, int peer_fd)
{

	free(ac->buf);
	ac->buf = NULL;
	if (ac->fd >= 0)
		close(ac->fd);
	if (peer_fd >= 0)
		close(peer_fd);
}

/*
 * Perform a REAL ATT Read Request for handle and return the response value.
 * This is the server's own dispatcher writing to a real socket: whatever it
 * puts here is, byte for byte, what a peer would see.
 */
static void
ho_att_read_value(struct att_db *db, uint16_t handle,
    uint8_t out[GATT_DB_HASH_LEN])
{
	struct att_conn ac;
	uint8_t pdu[3], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	int peer;

	ho_srv_pair(&ac, &peer);
	pdu[0] = ATT_OP_READ_REQ;
	put_le16(pdu + 1, handle);
	att_server_handle(&ac, db, pdu, sizeof(pdu), -1, 0);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(n == 1 + GATT_DB_HASH_LEN,
	    "expected a 17-byte Read Response, got %zd (op 0x%02x)", n,
	    n > 0 ? rsp[0] : 0);
	ATF_REQUIRE_EQ(ATT_OP_READ_RSP, rsp[0]);
	memcpy(out, rsp + 1, GATT_DB_HASH_LEN);
	ho_srv_cleanup(&ac, peer);
}

/*
 * The same value fetched the way a robust-caching client actually fetches it:
 * Read By Type over the whole handle range (Core Spec Vol 3 Part G 7.3).
 */
static void
ho_att_read_by_type_value(struct att_db *db, uint8_t out[GATT_DB_HASH_LEN])
{
	struct att_conn ac;
	uint8_t pdu[7], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	int peer;

	ho_srv_pair(&ac, &peer);
	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, BT_EXTREF_DB_HASH_UUID16);
	att_server_handle(&ac, db, pdu, sizeof(pdu), -1, 0);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(n == 2 + 2 + GATT_DB_HASH_LEN,
	    "expected a 20-byte Read By Type Response, got %zd", n);
	ATF_REQUIRE_EQ(ATT_OP_READ_BY_TYPE_RSP, rsp[0]);
	ATF_REQUIRE_EQ(2 + GATT_DB_HASH_LEN, rsp[1]);
	memcpy(out, rsp + 4, GATT_DB_HASH_LEN);
	ho_srv_cleanup(&ac, peer);
}

/* Reverse of a 16-octet buffer, computed here so a case can state it. */
static void
ho_reverse(const uint8_t in[GATT_DB_HASH_LEN], uint8_t out[GATT_DB_HASH_LEN])
{
	int i;

	for (i = 0; i < GATT_DB_HASH_LEN; i++)
		out[i] = in[GATT_DB_HASH_LEN - 1 - i];
}

/* ================================================================
 * The oracles themselves
 * ================================================================ */

/*
 * Pins the premise of everything below: the two candidate wire encodings are
 * exact reverses of one another and are NOT the same octets, so "matches
 * BlueZ" and "passes PTS" cannot both be satisfied by one encoding.  Also
 * pins that the BlueZ candidate is the unmodified AES-CMAC output.
 */
ATF_TC_WITHOUT_HEAD(oracles_are_exact_reverses);
ATF_TC_BODY(oracles_are_exact_reverses, tc)
{
	uint8_t rev[GATT_DB_HASH_LEN];

	ATF_CHECK_EQ_MSG(0, memcmp(bt_extref_db_hash_wire_bluez,
	    bt_extref_db_hash_cmac, GATT_DB_HASH_LEN),
	    "the BlueZ wire encoding is the raw AES-CMAC output, unreversed");
	ho_reverse(bt_extref_db_hash_cmac, rev);
	ATF_CHECK_EQ_MSG(0, memcmp(bt_extref_db_hash_wire_zephyr_pts, rev,
	    GATT_DB_HASH_LEN),
	    "the Zephyr/PTS wire encoding is the AES-CMAC output reversed");
	ATF_CHECK_MSG(memcmp(bt_extref_db_hash_wire_bluez,
	    bt_extref_db_hash_wire_zephyr_pts, GATT_DB_HASH_LEN) != 0,
	    "the two encodings must differ, or there is nothing to choose");
	ATF_CHECK_EQ(0xf1, bt_extref_db_hash_wire_bluez[0]);
	ATF_CHECK_EQ(0x90, bt_extref_db_hash_wire_zephyr_pts[0]);
}

/* ================================================================
 * Server publish path (wire sites 1-3)
 * ================================================================ */

/*
 * DEFAULT MODE.  The Appendix B database, published by the daemon's own
 * publish primitive and fetched with a real ATT Read Request through the
 * server, must yield exactly the octets BlueZ transmits.  This is the
 * regression guard on the shipped default: if it ever flips, every already
 * deployed Linux peer's cached hash silently stops matching.
 */
ATF_TC_WITHOUT_HEAD(server_default_publishes_bluez_order);
ATF_TC_BODY(server_default_publishes_bluez_order, tc)
{
	struct att_db db;
	uint8_t computed[GATT_DB_HASH_LEN], wire[GATT_DB_HASH_LEN];
	uint16_t vh;

	ho_reset();
	vh = ho_build_appendix_b(&db);

	ATF_CHECK_EQ_MSG(GATT_DB_HASH_ORDER_BLUEZ,
	    gatt_get_db_hash_byte_order(),
	    "the shipped default must be the BlueZ order");

	attdb_compute_db_hash(&db, computed);
	ATF_CHECK_EQ_MSG(0, memcmp(computed, bt_extref_db_hash_cmac,
	    GATT_DB_HASH_LEN),
	    "computation must reproduce the Appendix B AES-CMAC value");

	gatt_db_publish_hash(&db);
	ho_att_read_value(&db, vh, wire);
	ATF_CHECK_EQ_MSG(0, memcmp(wire, bt_extref_db_hash_wire_bluez,
	    GATT_DB_HASH_LEN),
	    "default mode must transmit the BlueZ octets");

	ho_att_read_by_type_value(&db, wire);
	ATF_CHECK_EQ_MSG(0, memcmp(wire, bt_extref_db_hash_wire_bluez,
	    GATT_DB_HASH_LEN),
	    "Read By Type must transmit the same octets as Read Request");
}

/*
 * REVERSED MODE.  Same database, same computation, opposite octets: what a
 * SIG qualification run needs for GATT/SR/GAS/BV-02-C.  The computed CMAC is
 * re-asserted against Appendix B to pin that only the presentation changed.
 */
ATF_TC_WITHOUT_HEAD(server_reversed_publishes_pts_order);
ATF_TC_BODY(server_reversed_publishes_pts_order, tc)
{
	struct att_db db;
	uint8_t computed[GATT_DB_HASH_LEN], wire[GATT_DB_HASH_LEN];
	uint16_t vh;

	ho_reset();
	gatt_set_db_hash_byte_order(GATT_DB_HASH_ORDER_REVERSED);
	vh = ho_build_appendix_b(&db);

	attdb_compute_db_hash(&db, computed);
	ATF_CHECK_EQ_MSG(0, memcmp(computed, bt_extref_db_hash_cmac,
	    GATT_DB_HASH_LEN),
	    "the hash computation must NOT change with the wire order");

	gatt_db_publish_hash(&db);
	ho_att_read_value(&db, vh, wire);
	ATF_CHECK_EQ_MSG(0, memcmp(wire, bt_extref_db_hash_wire_zephyr_pts,
	    GATT_DB_HASH_LEN),
	    "reversed mode must transmit the Zephyr/PTS octets");

	ho_att_read_by_type_value(&db, wire);
	ATF_CHECK_EQ_MSG(0, memcmp(wire, bt_extref_db_hash_wire_zephyr_pts,
	    GATT_DB_HASH_LEN),
	    "Read By Type must transmit the same octets as Read Request");
}

/*
 * The two published values differ only by order, on the daemon's OWN
 * config-built peripheral database rather than the spec fixture -- so the
 * property is a property of the publish path, not of one hand-built table.
 */
ATF_TC_WITHOUT_HEAD(publish_orders_are_reverses_on_real_db);
ATF_TC_BODY(publish_orders_are_reverses_on_real_db, tc)
{
	uint8_t as_bluez[GATT_DB_HASH_LEN], as_pts[GATT_DB_HASH_LEN];
	uint8_t rev[GATT_DB_HASH_LEN];
	int i;

	ho_reset();
	peripheral_build_gattdb(&periph_gatt_db, ho_periph_attrs,
	    ho_periph_valbuf, sizeof(ho_periph_valbuf), NULL);
	i = -1;
	for (int j = 0; j < periph_gatt_db.count; j++) {
		if (periph_gatt_db.attrs[j].uuid16 == UUID_DATABASE_HASH &&
		    periph_gatt_db.attrs[j].value_len == GATT_DB_HASH_LEN)
			i = j;
	}
	ATF_REQUIRE_MSG(i >= 0, "built database has no Database Hash value");
	memcpy(as_bluez, periph_gatt_db.attrs[i].value, GATT_DB_HASH_LEN);

	gatt_set_db_hash_byte_order(GATT_DB_HASH_ORDER_REVERSED);
	gatt_db_publish_hash(&periph_gatt_db);
	memcpy(as_pts, periph_gatt_db.attrs[i].value, GATT_DB_HASH_LEN);

	ho_reverse(as_bluez, rev);
	ATF_CHECK_EQ_MSG(0, memcmp(as_pts, rev, GATT_DB_HASH_LEN),
	    "the two published encodings must be exact reverses");
	ATF_CHECK_MSG(memcmp(as_pts, as_bluez, GATT_DB_HASH_LEN) != 0,
	    "a non-palindromic hash must actually change");
}

/*
 * Wire site 2: the live recompute driven by a control-socket GATT mutation
 * (ctl_recompute_hash_and_notify) must publish in the configured order too --
 * a database changed at runtime is exactly when a peer re-reads the hash.
 */
ATF_TC_WITHOUT_HEAD(ctl_recompute_honours_order);
ATF_TC_BODY(ctl_recompute_honours_order, tc)
{
	uint8_t before[GATT_DB_HASH_LEN], after[GATT_DB_HASH_LEN];
	uint8_t computed[GATT_DB_HASH_LEN], rev[GATT_DB_HASH_LEN];
	uint16_t service = 0;
	int i;

	ho_reset();
	gatt_set_db_hash_byte_order(GATT_DB_HASH_ORDER_REVERSED);
	peripheral_build_gattdb(&periph_gatt_db, ho_periph_attrs,
	    ho_periph_valbuf, sizeof(ho_periph_valbuf), NULL);
	ctl_gatt_set_base_count();

	i = -1;
	for (int j = 0; j < periph_gatt_db.count; j++) {
		if (periph_gatt_db.attrs[j].uuid16 == UUID_DATABASE_HASH &&
		    periph_gatt_db.attrs[j].value_len == GATT_DB_HASH_LEN)
			i = j;
	}
	ATF_REQUIRE(i >= 0);
	memcpy(before, periph_gatt_db.attrs[i].value, GATT_DB_HASH_LEN);

	/* A runtime service add mutates the database and republishes. */
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(71, 0x1810,
	    NULL, &service));
	memcpy(after, periph_gatt_db.attrs[i].value, GATT_DB_HASH_LEN);
	ATF_CHECK_MSG(memcmp(before, after, GATT_DB_HASH_LEN) != 0,
	    "adding a service must change the published hash");

	attdb_compute_db_hash(&periph_gatt_db, computed);
	ho_reverse(computed, rev);
	ATF_CHECK_EQ_MSG(0, memcmp(after, rev, GATT_DB_HASH_LEN),
	    "the live recompute must publish in the configured (reversed) "
	    "order, not the raw CMAC order");
}

/* ================================================================
 * Client read path (wire site 4)
 * ================================================================ */

/*
 * Queue a Read By Type Response carrying wire_value, then let the real client
 * read it back.  Returns what gatt_read_database_hash() reported.
 */
static void
ho_client_read(const uint8_t wire_value[GATT_DB_HASH_LEN],
    uint8_t out[GATT_DB_HASH_LEN])
{
	struct att_conn ac;
	uint8_t rsp[2 + 2 + GATT_DB_HASH_LEN];
	int peer;

	ho_srv_pair(&ac, &peer);
	rsp[0] = ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 2 + GATT_DB_HASH_LEN;
	put_le16(rsp + 2, 0x000D);
	memcpy(rsp + 4, wire_value, GATT_DB_HASH_LEN);
	ATF_REQUIRE(send(peer, rsp, sizeof(rsp), 0) == (ssize_t)sizeof(rsp));

	memset(out, 0, GATT_DB_HASH_LEN);
	ATF_REQUIRE_EQ(0, gatt_read_database_hash(&ac, out));
	ho_srv_cleanup(&ac, peer);
}

/*
 * Symmetry: a peer's published value is interpreted in the SAME configured
 * order it would be published in, and the result handed to the rest of the
 * daemon is always in computation order.  An asymmetric implementation would
 * pass this only in one of the two modes.
 */
ATF_TC_WITHOUT_HEAD(client_read_interprets_configured_order);
ATF_TC_BODY(client_read_interprets_configured_order, tc)
{
	uint8_t got[GATT_DB_HASH_LEN], rev[GATT_DB_HASH_LEN];

	ho_reset();
	ho_client_read(bt_extref_db_hash_wire_bluez, got);
	ATF_CHECK_EQ_MSG(0, memcmp(got, bt_extref_db_hash_cmac,
	    GATT_DB_HASH_LEN),
	    "default mode must read a BlueZ peer's value as the CMAC value");

	gatt_set_db_hash_byte_order(GATT_DB_HASH_ORDER_REVERSED);
	ho_client_read(bt_extref_db_hash_wire_zephyr_pts, got);
	ATF_CHECK_EQ_MSG(0, memcmp(got, bt_extref_db_hash_cmac,
	    GATT_DB_HASH_LEN),
	    "reversed mode must read a Zephyr/PTS peer's value as the CMAC "
	    "value");

	/* Cross-mode: the wrong order really does yield the wrong value. */
	ho_client_read(bt_extref_db_hash_wire_bluez, got);
	ho_reverse(bt_extref_db_hash_cmac, rev);
	ATF_CHECK_EQ_MSG(0, memcmp(got, rev, GATT_DB_HASH_LEN),
	    "reading BlueZ octets in reversed mode must not silently agree");
}

/*
 * Full loop: what this daemon publishes, this daemon reads back to the value
 * it computed -- in both modes.  This is the property robust caching relies
 * on between two blued peers.
 */
ATF_TC_WITHOUT_HEAD(server_client_round_trip_both_modes);
ATF_TC_BODY(server_client_round_trip_both_modes, tc)
{
	static const uint8_t orders[] = {
		GATT_DB_HASH_ORDER_BLUEZ, GATT_DB_HASH_ORDER_REVERSED
	};
	struct att_db db;
	uint8_t computed[GATT_DB_HASH_LEN], wire[GATT_DB_HASH_LEN];
	uint8_t got[GATT_DB_HASH_LEN];
	uint16_t vh;
	size_t k;

	for (k = 0; k < nitems(orders); k++) {
		ho_reset();
		gatt_set_db_hash_byte_order(orders[k]);
		vh = ho_build_appendix_b(&db);
		attdb_compute_db_hash(&db, computed);
		gatt_db_publish_hash(&db);
		ho_att_read_value(&db, vh, wire);
		ho_client_read(wire, got);
		ATF_CHECK_EQ_MSG(0, memcmp(got, computed, GATT_DB_HASH_LEN),
		    "order %u: publish/read round trip must be lossless",
		    orders[k]);
		ATF_CHECK_EQ_MSG(0, memcmp(got, bt_extref_db_hash_cmac,
		    GATT_DB_HASH_LEN),
		    "order %u: round trip must land on the Appendix B value",
		    orders[k]);
	}
}

/* ================================================================
 * Stored bond hash: computation order, both sides, always
 * ================================================================ */

/*
 * The bonded-reconnect comparison in blued_peripheral.c compares a STORED bond
 * hash against a freshly computed one.  Both are in computation order by
 * decision (see gatt.h), so flipping the wire order must NOT make a bond's
 * stored hash look stale -- otherwise every bonded peer would be forced
 * through a full rediscovery merely because the operator changed an encoding.
 */
ATF_TC_WITHOUT_HEAD(bond_hash_survives_order_change);
ATF_TC_BODY(bond_hash_survives_order_change, tc)
{
	struct att_db db;
	uint8_t stored[GATT_DB_HASH_LEN], recomputed[GATT_DB_HASH_LEN];
	uint8_t published[GATT_DB_HASH_LEN];
	uint16_t vh;

	ho_reset();
	vh = ho_build_appendix_b(&db);
	gatt_db_publish_hash(&db);
	/* What the bond record stores on first connection after bonding. */
	attdb_compute_db_hash(&db, stored);
	ho_att_read_value(&db, vh, published);
	ATF_CHECK_EQ_MSG(0, memcmp(stored, bt_extref_db_hash_cmac,
	    GATT_DB_HASH_LEN),
	    "a stored bond hash is the raw CMAC value, not the wire value");

	/* Operator flips the knob and the daemon republishes. */
	gatt_set_db_hash_byte_order(GATT_DB_HASH_ORDER_REVERSED);
	gatt_db_publish_hash(&db);
	attdb_compute_db_hash(&db, recomputed);

	ATF_CHECK_EQ_MSG(0, memcmp(stored, recomputed, GATT_DB_HASH_LEN),
	    "the bonded-reconnect comparison must be unaffected by the wire "
	    "order");
	ho_att_read_value(&db, vh, published);
	ATF_CHECK_MSG(memcmp(published, stored, GATT_DB_HASH_LEN) != 0,
	    "the published value, unlike the stored one, must have changed");
	ATF_CHECK_EQ_MSG(0, memcmp(published, bt_extref_db_hash_wire_zephyr_pts,
	    GATT_DB_HASH_LEN), "and it must be the PTS encoding");
}

/*
 * The same decision seen from the client side: a hash read from a peer is
 * comparable with a stored bond hash in either mode, because both are
 * normalised to computation order.
 */
ATF_TC_WITHOUT_HEAD(bond_hash_matches_peer_read_in_both_modes);
ATF_TC_BODY(bond_hash_matches_peer_read_in_both_modes, tc)
{
	uint8_t got[GATT_DB_HASH_LEN];

	ho_reset();
	/* A bond stored while running in BlueZ order. */
	ho_client_read(bt_extref_db_hash_wire_bluez, got);
	ATF_CHECK_EQ(0, memcmp(got, bt_extref_db_hash_cmac, GATT_DB_HASH_LEN));

	/* The peer is later re-read while running in reversed order. */
	gatt_set_db_hash_byte_order(GATT_DB_HASH_ORDER_REVERSED);
	ho_client_read(bt_extref_db_hash_wire_zephyr_pts, got);
	ATF_CHECK_EQ_MSG(0, memcmp(got, bt_extref_db_hash_cmac,
	    GATT_DB_HASH_LEN),
	    "a stored bond hash stays comparable across a mode change");
}

/* ================================================================
 * Configuration knob and command-line flag
 * ================================================================ */

static void
ho_write_conf(const char *path, const char *body)
{
	FILE *f;

	f = fopen(path, "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fputs(body, f) >= 0);
	ATF_REQUIRE_EQ(0, fclose(f));
}

/* Every accepted spelling, and the default when the key is absent. */
ATF_TC_WITHOUT_HEAD(config_parses_byte_order_tokens);
ATF_TC_BODY(config_parses_byte_order_tokens, tc)
{
	static const struct {
		const char	*token;
		uint8_t		 expect;
	} cases[] = {
		{ "bluez",		BLUED_DB_HASH_ORDER_BLUEZ },
		{ "cmac",		BLUED_DB_HASH_ORDER_BLUEZ },
		{ "msb_first",		BLUED_DB_HASH_ORDER_BLUEZ },
		{ "msb-first",		BLUED_DB_HASH_ORDER_BLUEZ },
		{ "linux",		BLUED_DB_HASH_ORDER_BLUEZ },
		{ "BlueZ",		BLUED_DB_HASH_ORDER_BLUEZ },
		{ "reversed",		BLUED_DB_HASH_ORDER_REVERSED },
		{ "little_endian",	BLUED_DB_HASH_ORDER_REVERSED },
		{ "little-endian",	BLUED_DB_HASH_ORDER_REVERSED },
		{ "lsb_first",		BLUED_DB_HASH_ORDER_REVERSED },
		{ "pts",		BLUED_DB_HASH_ORDER_REVERSED },
		{ "zephyr",		BLUED_DB_HASH_ORDER_REVERSED },
	};
	struct blued_config cfg;
	char body[256];
	uint8_t order;
	size_t i;

	/* Absent key: the shipped default. */
	blued_config_defaults(&cfg);
	ATF_CHECK_EQ_MSG(BLUED_DB_HASH_ORDER_BLUEZ, cfg.db_hash_byte_order,
	    "the built-in default must stay BlueZ-compatible");
	ho_write_conf("noknob.conf", "features { eatt = true; }\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, "noknob.conf"));
	ATF_CHECK_EQ(BLUED_DB_HASH_ORDER_BLUEZ, cfg.db_hash_byte_order);

	for (i = 0; i < nitems(cases); i++) {
		blued_config_defaults(&cfg);
		snprintf(body, sizeof(body),
		    "gatt { database_hash_byte_order = \"%s\"; }\n",
		    cases[i].token);
		ho_write_conf("knob.conf", body);
		ATF_REQUIRE_EQ(0, blued_config_load(&cfg, "knob.conf"));
		ATF_CHECK_EQ_MSG(cases[i].expect, cfg.db_hash_byte_order,
		    "config token '%s' parsed wrong", cases[i].token);

		/* The same tokens through the parser entry point. */
		order = 0xFF;
		ATF_CHECK_EQ_MSG(0, blued_parse_db_hash_byte_order(
		    cases[i].token, &order), "token '%s' rejected",
		    cases[i].token);
		ATF_CHECK_EQ(cases[i].expect, order);
	}
}

/* An invalid value is rejected, not silently defaulted to either order. */
ATF_TC_WITHOUT_HEAD(config_rejects_invalid_byte_order);
ATF_TC_BODY(config_rejects_invalid_byte_order, tc)
{
	struct blued_config cfg;
	uint8_t order = BLUED_DB_HASH_ORDER_REVERSED;

	ATF_CHECK_MSG(blued_parse_db_hash_byte_order("bigendian", &order) != 0,
	    "an unknown token must be rejected");
	ATF_CHECK_EQ_MSG(BLUED_DB_HASH_ORDER_REVERSED, order,
	    "a rejected token must leave the value untouched");
	ATF_CHECK(blued_parse_db_hash_byte_order("", &order) != 0);
	ATF_CHECK(blued_parse_db_hash_byte_order(NULL, &order) != 0);
	ATF_CHECK(blued_parse_db_hash_byte_order("reversed", NULL) != 0);

	/*
	 * Through the config file: a bad value keeps the previous setting.
	 * The prior setting is seeded the way an accepted value leaves it --
	 * the order AND its override bit, which is what pins the knob against
	 * the compatibility profile (see blued(8) COMPATIBILITY PROFILES).
	 * Seeding the order alone would describe a state no code path
	 * produces.
	 */
	blued_config_defaults(&cfg);
	cfg.db_hash_byte_order = BLUED_DB_HASH_ORDER_REVERSED;
	cfg.compat_overrides |= BLUED_COMPAT_OVR_DB_HASH_ORDER;
	ho_write_conf("bad.conf",
	    "gatt { database_hash_byte_order = \"middle-endian\"; }\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, "bad.conf"));
	ATF_CHECK_EQ_MSG(BLUED_DB_HASH_ORDER_REVERSED, cfg.db_hash_byte_order,
	    "a bad config value must not silently change the wire encoding");

	/*
	 * And a rejected value must not pin the knob either: a profile named
	 * in the same file still governs it, rather than the knob silently
	 * freezing at the shipped default.
	 */
	blued_config_defaults(&cfg);
	ho_write_conf("badprof.conf",
	    "compatibility_profile = \"spec\";\n"
	    "gatt { database_hash_byte_order = \"middle-endian\"; }\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, "badprof.conf"));
	ATF_CHECK_EQ_MSG(0u,
	    cfg.compat_overrides & BLUED_COMPAT_OVR_DB_HASH_ORDER,
	    "a rejected value must not pin the knob");
	ATF_CHECK_EQ(BLUED_DB_HASH_ORDER_REVERSED, cfg.db_hash_byte_order);

	/* A non-string value is ignored the same way. */
	blued_config_defaults(&cfg);
	ho_write_conf("num.conf", "gatt { database_hash_byte_order = 1; }\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, "num.conf"));
	ATF_CHECK_EQ(BLUED_DB_HASH_ORDER_BLUEZ, cfg.db_hash_byte_order);
}

/*
 * The -H flag, including the property that makes it usable in a daemon: it is
 * applied by blued_config_apply_cli(), which SIGHUP re-runs over the saved
 * argv, so a reload cannot lose it.  Also pins that both getopt(3) passes
 * agree that -H takes an argument (they share BLUED_GETOPT_STRING).
 */
ATF_TC_WITHOUT_HEAD(cli_flag_selects_and_survives_reload);
ATF_TC_BODY(cli_flag_selects_and_survives_reload, tc)
{
	char *argv[] = { __DECONST(char *, "blued"),
	    __DECONST(char *, "-H"), __DECONST(char *, "reversed"),
	    __DECONST(char *, "-p"), NULL };
	char *argv_bluez[] = { __DECONST(char *, "blued"),
	    __DECONST(char *, "-H"), __DECONST(char *, "cmac"), NULL };
	struct blued_config cfg;

	ATF_CHECK_MSG(strstr(BLUED_GETOPT_STRING, "H:") != NULL,
	    "-H must be declared as taking an argument in the shared option "
	    "string used by both getopt passes");

	blued_config_defaults(&cfg);
	blued_config_apply_cli(&cfg, 4, argv);
	ATF_CHECK_EQ_MSG(BLUED_DB_HASH_ORDER_REVERSED, cfg.db_hash_byte_order,
	    "-H reversed must select the PTS order");
	ATF_CHECK_MSG(cfg.peripheral_mode,
	    "-H's argument must not swallow the following option");

	/* SIGHUP: defaults are reloaded, then the saved argv is re-applied. */
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(BLUED_DB_HASH_ORDER_BLUEZ, cfg.db_hash_byte_order);
	blued_config_apply_cli(&cfg, 4, argv);
	ATF_CHECK_EQ_MSG(BLUED_DB_HASH_ORDER_REVERSED, cfg.db_hash_byte_order,
	    "a config reload must not lose the command-line flag");

	blued_config_defaults(&cfg);
	cfg.db_hash_byte_order = BLUED_DB_HASH_ORDER_REVERSED;
	blued_config_apply_cli(&cfg, 3, argv_bluez);
	ATF_CHECK_EQ(BLUED_DB_HASH_ORDER_BLUEZ, cfg.db_hash_byte_order);
}

/* -H beats the configuration file, and a bad -H changes nothing. */
ATF_TC_WITHOUT_HEAD(cli_flag_overrides_config_and_rejects_garbage);
ATF_TC_BODY(cli_flag_overrides_config_and_rejects_garbage, tc)
{
	char *argv[] = { __DECONST(char *, "blued"),
	    __DECONST(char *, "-H"), __DECONST(char *, "pts"), NULL };
	char *bad[] = { __DECONST(char *, "blued"),
	    __DECONST(char *, "-H"), __DECONST(char *, "swapped"), NULL };
	struct blued_config cfg;

	blued_config_defaults(&cfg);
	ho_write_conf("cli.conf",
	    "gatt { database_hash_byte_order = \"bluez\"; }\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, "cli.conf"));
	ATF_REQUIRE_EQ(BLUED_DB_HASH_ORDER_BLUEZ, cfg.db_hash_byte_order);
	blued_config_apply_cli(&cfg, 3, argv);
	ATF_CHECK_EQ_MSG(BLUED_DB_HASH_ORDER_REVERSED, cfg.db_hash_byte_order,
	    "the command line must override the configuration file");

	blued_config_apply_cli(&cfg, 3, bad);
	ATF_CHECK_EQ_MSG(BLUED_DB_HASH_ORDER_REVERSED, cfg.db_hash_byte_order,
	    "an unparsable -H must leave the effective order untouched");
}

/*
 * The knob and the wire are actually connected: a config value carried through
 * gatt_set_db_hash_byte_order() (what main() and the SIGHUP reload do) changes
 * the octets the server publishes.
 */
ATF_TC_WITHOUT_HEAD(config_value_reaches_the_wire);
ATF_TC_BODY(config_value_reaches_the_wire, tc)
{
	struct blued_config cfg;
	struct att_db db;
	uint8_t wire[GATT_DB_HASH_LEN];
	uint16_t vh;

	ho_reset();
	blued_config_defaults(&cfg);
	ho_write_conf("wire.conf",
	    "gatt { database_hash_byte_order = \"pts\"; }\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, "wire.conf"));
	gatt_set_db_hash_byte_order(cfg.db_hash_byte_order);

	vh = ho_build_appendix_b(&db);
	gatt_db_publish_hash(&db);
	ho_att_read_value(&db, vh, wire);
	ATF_CHECK_EQ_MSG(0, memcmp(wire, bt_extref_db_hash_wire_zephyr_pts,
	    GATT_DB_HASH_LEN),
	    "a configured order must reach the published characteristic");

	/* And back again. */
	blued_config_defaults(&cfg);
	gatt_set_db_hash_byte_order(cfg.db_hash_byte_order);
	gatt_db_publish_hash(&db);
	ho_att_read_value(&db, vh, wire);
	ATF_CHECK_EQ(0, memcmp(wire, bt_extref_db_hash_wire_bluez,
	    GATT_DB_HASH_LEN));
}

/* An out-of-range order code must not produce a third behaviour. */
ATF_TC_WITHOUT_HEAD(unknown_order_code_falls_back_to_default);
ATF_TC_BODY(unknown_order_code_falls_back_to_default, tc)
{
	struct att_db db;
	uint8_t wire[GATT_DB_HASH_LEN];
	uint16_t vh;

	ho_reset();
	gatt_set_db_hash_byte_order(0x7F);
	ATF_CHECK_EQ_MSG(GATT_DB_HASH_ORDER_BLUEZ,
	    gatt_get_db_hash_byte_order(),
	    "an unknown order code must clamp to the default");
	vh = ho_build_appendix_b(&db);
	gatt_db_publish_hash(&db);
	ho_att_read_value(&db, vh, wire);
	ATF_CHECK_EQ(0, memcmp(wire, bt_extref_db_hash_wire_bluez,
	    GATT_DB_HASH_LEN));
}

/* ================================================================
 * Compatibility profile (blued(8) -P, `compatibility_profile`)
 *
 * The Database Hash order is one of the two behaviours the profile governs.
 * These cases assert the published characteristic OCTETS against the same
 * external oracles the rest of this file uses, so a profile that resolved
 * correctly but reached nothing would still fail.
 * ================================================================ */

/*
 * Resolve a configuration (file, then optional command line, exactly as
 * main() does) and publish the result, returning the octets the server would
 * put in the Database Hash characteristic value.
 */
static void
ho_profile_wire(const char *conf, int argc, char **argv, const char *name,
    uint8_t wire[GATT_DB_HASH_LEN])
{
	struct blued_config cfg;
	struct att_db db;
	uint16_t vh;

	ho_reset();
	blued_config_defaults(&cfg);
	ho_write_conf(name, conf);
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, name));
	if (argv != NULL)
		blued_config_apply_cli(&cfg, argc, argv);
	gatt_set_db_hash_byte_order(cfg.db_hash_byte_order);

	vh = ho_build_appendix_b(&db);
	gatt_db_publish_hash(&db);
	ho_att_read_value(&db, vh, wire);
}

/* Each profile reaches the octet order it claims. */
ATF_TC_WITHOUT_HEAD(profile_selects_published_hash_order);
ATF_TC_BODY(profile_selects_published_hash_order, tc)
{
	uint8_t wire[GATT_DB_HASH_LEN];

	/*
	 * No profile named: the shipped behaviour, which is BlueZ's order.
	 * This is the "upgrading changes nothing" promise measured on the
	 * wire rather than asserted about a struct field.
	 */
	ho_profile_wire("features { eatt = true; }\n", 0, NULL, "p_none.conf",
	    wire);
	ATF_CHECK_EQ_MSG(0, memcmp(wire, bt_extref_db_hash_wire_bluez,
	    GATT_DB_HASH_LEN),
	    "no profile must publish exactly what blued always published");

	ho_profile_wire("compatibility_profile = \"default\";\n", 0, NULL,
	    "p_default.conf", wire);
	ATF_CHECK_EQ_MSG(0, memcmp(wire, bt_extref_db_hash_wire_bluez,
	    GATT_DB_HASH_LEN),
	    "the default profile must publish the BlueZ order");

	ho_profile_wire("compatibility_profile = \"bluez\";\n", 0, NULL,
	    "p_bluez.conf", wire);
	ATF_CHECK_EQ_MSG(0, memcmp(wire, bt_extref_db_hash_wire_bluez,
	    GATT_DB_HASH_LEN),
	    "the bluez profile must publish the BlueZ order");

	ho_profile_wire("compatibility_profile = \"spec\";\n", 0, NULL,
	    "p_spec.conf", wire);
	ATF_CHECK_EQ_MSG(0, memcmp(wire, bt_extref_db_hash_wire_zephyr_pts,
	    GATT_DB_HASH_LEN),
	    "the spec profile must publish the order GATT/SR/GAS/BV-02-C "
	    "expects");

	/*
	 * The two are byte reverses, so no setting satisfies both: this is
	 * the tradeoff blued(8) states, asserted rather than described.
	 */
	ATF_CHECK(memcmp(bt_extref_db_hash_wire_bluez,
	    bt_extref_db_hash_wire_zephyr_pts, GATT_DB_HASH_LEN) != 0);
}

/* -P reaches the wire, and an unknown -P leaves the previous order alone. */
ATF_TC_WITHOUT_HEAD(profile_cli_selects_published_hash_order);
ATF_TC_BODY(profile_cli_selects_published_hash_order, tc)
{
	char *argv[] = { __DECONST(char *, "blued"),
	    __DECONST(char *, "-P"), __DECONST(char *, "qualification"),
	    NULL };
	char *argv_bad[] = { __DECONST(char *, "blued"),
	    __DECONST(char *, "-P"), __DECONST(char *, "specification"),
	    NULL };
	uint8_t wire[GATT_DB_HASH_LEN];

	ho_profile_wire("features { eatt = true; }\n", 3, argv, "pc.conf",
	    wire);
	ATF_CHECK_EQ_MSG(0, memcmp(wire, bt_extref_db_hash_wire_zephyr_pts,
	    GATT_DB_HASH_LEN), "-P must reach the published characteristic");

	ho_profile_wire("compatibility_profile = \"spec\";\n", 3, argv_bad,
	    "pcb.conf", wire);
	ATF_CHECK_EQ_MSG(0, memcmp(wire, bt_extref_db_hash_wire_zephyr_pts,
	    GATT_DB_HASH_LEN),
	    "an unparsable -P must leave the configured profile in force");
}

/*
 * The pre-existing knob still wins, in both spellings, and the command-line
 * spelling survives a reload.  This is the compatibility promise for the
 * operators who already set -H or database_hash_byte_order: the new profile
 * must not take their setting away.
 */
ATF_TC_WITHOUT_HEAD(hash_knob_overrides_profile_on_the_wire);
ATF_TC_BODY(hash_knob_overrides_profile_on_the_wire, tc)
{
	char *argv[] = { __DECONST(char *, "blued"),
	    __DECONST(char *, "-H"), __DECONST(char *, "bluez"), NULL };
	uint8_t wire[GATT_DB_HASH_LEN];
	int pass;

	/* Configuration key beats the profile. */
	ho_profile_wire("compatibility_profile = \"spec\";\n"
	    "gatt { database_hash_byte_order = \"bluez\"; }\n", 0, NULL,
	    "ko1.conf", wire);
	ATF_CHECK_EQ_MSG(0, memcmp(wire, bt_extref_db_hash_wire_bluez,
	    GATT_DB_HASH_LEN),
	    "database_hash_byte_order must beat the profile");

	ho_profile_wire("compatibility_profile = \"bluez\";\n"
	    "gatt { database_hash_byte_order = \"reversed\"; }\n", 0, NULL,
	    "ko2.conf", wire);
	ATF_CHECK_EQ_MSG(0, memcmp(wire, bt_extref_db_hash_wire_zephyr_pts,
	    GATT_DB_HASH_LEN),
	    "the override must work in the other direction too");

	/*
	 * -H beats a profile from the configuration file, on the startup pass
	 * and again on the reload pass -- the reload re-parses the file from
	 * defaults and re-applies the saved argv, which is what would lose an
	 * override that was not re-asserted.
	 */
	for (pass = 0; pass < 2; pass++) {
		ho_profile_wire("compatibility_profile = \"spec\";\n", 3,
		    argv, "ko3.conf", wire);
		ATF_CHECK_EQ_MSG(0, memcmp(wire,
		    bt_extref_db_hash_wire_bluez, GATT_DB_HASH_LEN),
		    "pass %d: -H must still beat the profile", pass);
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, oracles_are_exact_reverses);
	ATF_TP_ADD_TC(tp, server_default_publishes_bluez_order);
	ATF_TP_ADD_TC(tp, server_reversed_publishes_pts_order);
	ATF_TP_ADD_TC(tp, publish_orders_are_reverses_on_real_db);
	ATF_TP_ADD_TC(tp, ctl_recompute_honours_order);
	ATF_TP_ADD_TC(tp, client_read_interprets_configured_order);
	ATF_TP_ADD_TC(tp, server_client_round_trip_both_modes);
	ATF_TP_ADD_TC(tp, bond_hash_survives_order_change);
	ATF_TP_ADD_TC(tp, bond_hash_matches_peer_read_in_both_modes);
	ATF_TP_ADD_TC(tp, config_parses_byte_order_tokens);
	ATF_TP_ADD_TC(tp, config_rejects_invalid_byte_order);
	ATF_TP_ADD_TC(tp, cli_flag_selects_and_survives_reload);
	ATF_TP_ADD_TC(tp, cli_flag_overrides_config_and_rejects_garbage);
	ATF_TP_ADD_TC(tp, config_value_reaches_the_wire);
	ATF_TP_ADD_TC(tp, unknown_order_code_falls_back_to_default);

	ATF_TP_ADD_TC(tp, profile_selects_published_hash_order);
	ATF_TP_ADD_TC(tp, profile_cli_selects_published_hash_order);
	ATF_TP_ADD_TC(tp, hash_knob_overrides_profile_on_the_wire);

	return (atf_no_error());
}
