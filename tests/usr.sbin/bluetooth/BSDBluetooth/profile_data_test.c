/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * End-to-end tests that push the known GATT profile fixtures and golden data
 * vectors (profile_fixtures.c) through the real ATT server and GATT client.
 *
 * For every fixture:
 *   - build its attribute database with the real attdb_* API, then feed each
 *     golden request PDU to att_server_handle() over a SOCK_SEQPACKET
 *     socketpair and assert the exact expected response bytes (known-answer);
 *   - for the notify-capable profiles, emit a Handle Value Notification via
 *     att_send_notification() and assert the exact PDU bytes;
 *   - for the Battery profile, drive gatt_discover_primary_services() /
 *     gatt_discover_characteristics() / gatt_discover_descriptors() against a
 *     scripted server response and assert the discovered handles/UUIDs match
 *     the built fixture.
 *
 * SOCK_SEQPACKET on AF_UNIX coalesces queued sends on this platform, so every
 * exchange is strictly lockstep: send one request, let the server consume and
 * respond, drain exactly one response.  Client discovery follows the
 * gatt_client_test.c model: the daemon-side fd is O_NONBLOCK and preloaded
 * with a single response datagram, so discovery unwinds after one round.
 *
 * ORACLE: the expected response bytes (in profile_fixtures.c and the scripted
 * discovery responses below) are hand-encoded from the Bluetooth Core
 * Specification PDU definitions, never captured from the implementation.  A
 * mismatch between a spec-derived expectation and the stack's output is a
 * finding about the stack, not a reason to edit the expectation.
 *
 * Reference: Core Spec Vol 3 Part F (ATT), Part G (GATT).
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "gatt.h"
#include "hci_log.h"
#include "hci_util.h"

#include "profile_fixtures.h"
#include "spec_profile_data_oracles.h"
#include "test_common.h"

/* ================================================================
 * Server-side socketpair mock (blocking, full-MTU)
 * ================================================================ */

static void
srv_pair(struct att_conn *ac, int *peer)
{
	int fds[2];

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(ac, 0, sizeof(*ac));
	ac->fd = fds[0];
	ac->bearer_fd = -1;
	ac->mtu = ATT_PDU_BUF_SIZE;	/* 517: full values, no truncation */
	ac->buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
	*peer = fds[1];
}

static void
srv_cleanup(struct att_conn *ac, int peer)
{

	free(ac->buf);
	ac->buf = NULL;
	close(ac->fd);
	close(peer);
}

/*
 * Run every golden operation of a fixture as an isolated known-answer test.
 * The DB and connection are rebuilt per op so per-connection CCCD state and
 * any value writes never bleed between operations.
 */
static void
run_golden_ops(const struct profile_fixture *fx)
{
	size_t i;

	for (i = 0; i < fx->nops; i++) {
		const struct golden_op *op = &fx->ops[i];
		struct att_db db;
		struct att_conn ac;
		int peer;
		uint8_t sbuf[ATT_PDU_BUF_SIZE];
		uint8_t rsp[ATT_PDU_BUF_SIZE];
		ssize_t nr;

		fx->build(&db);
		srv_pair(&ac, &peer);

		ATF_REQUIRE_EQ((ssize_t)op->req_len,
		    send(peer, op->req, op->req_len, 0));

		nr = recv(ac.fd, sbuf, sizeof(sbuf), 0);
		ATF_REQUIRE(nr > 0);
		att_server_handle(&ac, &db, sbuf, (size_t)nr, -1, 0);

		nr = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
		ATF_REQUIRE_MSG(nr >= 0, "%s: %s: no response emitted",
		    fx->name, op->desc);
		ATF_REQUIRE_EQ_MSG(op->rsp_len, (size_t)nr,
		    "%s: %s: response length %zd != expected %zu",
		    fx->name, op->desc, nr, op->rsp_len);
		ATF_CHECK_EQ_MSG(0, memcmp(rsp, op->rsp, op->rsp_len),
		    "%s: %s: response bytes mismatch", fx->name, op->desc);

		/* Lockstep: exactly one response PDU, nothing queued behind it. */
		nr = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
		ATF_CHECK_MSG(nr < 0, "%s: %s: unexpected extra PDU",
		    fx->name, op->desc);

		srv_cleanup(&ac, peer);
	}
}

/* ================================================================
 * Golden known-answer tests, one per profile
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(golden_gap);
ATF_TC_BODY(golden_gap, tc)
{

	run_golden_ops(profile_fixture_gap());
}

ATF_TC_WITHOUT_HEAD(golden_gatt);
ATF_TC_BODY(golden_gatt, tc)
{

	run_golden_ops(profile_fixture_gatt());
}

ATF_TC_WITHOUT_HEAD(golden_dis);
ATF_TC_BODY(golden_dis, tc)
{

	run_golden_ops(profile_fixture_dis());
}

ATF_TC_WITHOUT_HEAD(golden_battery);
ATF_TC_BODY(golden_battery, tc)
{

	run_golden_ops(profile_fixture_battery());
}

ATF_TC_WITHOUT_HEAD(golden_heart_rate);
ATF_TC_BODY(golden_heart_rate, tc)
{

	run_golden_ops(profile_fixture_heart_rate());
}

ATF_TC_WITHOUT_HEAD(golden_hogp);
ATF_TC_BODY(golden_hogp, tc)
{

	run_golden_ops(profile_fixture_hogp());
}

/* ================================================================
 * Notification path: att_send_notification() emits the exact PDU
 * ================================================================ */

static void
check_notification(const struct profile_fixture *fx)
{
	struct att_conn ac;
	int peer;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t nr;
	int ret;

	ATF_REQUIRE(fx->has_notify);
	srv_pair(&ac, &peer);

	ret = att_send_notification(&ac, fx->notify_handle, fx->notify_value,
	    fx->notify_len);
	ATF_CHECK_EQ_MSG(0, ret, "%s: att_send_notification failed", fx->name);

	nr = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(nr >= 0, "%s: no notification emitted", fx->name);
	ATF_REQUIRE_EQ_MSG(fx->notify_pdu_len, (size_t)nr,
	    "%s: notification length %zd != expected %zu",
	    fx->name, nr, fx->notify_pdu_len);
	ATF_CHECK_EQ_MSG(0, memcmp(rsp, fx->notify_pdu, fx->notify_pdu_len),
	    "%s: notification bytes mismatch", fx->name);

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(notify_battery_level);
ATF_TC_BODY(notify_battery_level, tc)
{

	check_notification(profile_fixture_battery());
}

ATF_TC_WITHOUT_HEAD(notify_heart_rate);
ATF_TC_BODY(notify_heart_rate, tc)
{

	check_notification(profile_fixture_heart_rate());
}

ATF_TC_WITHOUT_HEAD(notify_hogp_report);
ATF_TC_BODY(notify_hogp_report, tc)
{

	check_notification(profile_fixture_hogp());
}

/* ================================================================
 * GATT Database Hash: real server READ returns the AES-CMAC over the DB
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(gatt_database_hash_read);
ATF_TC_BODY(gatt_database_hash_read, tc)
{
	const struct profile_fixture *fx = profile_fixture_gatt();
	struct att_db db;
	struct att_conn ac;
	int peer, i;
	uint16_t hash_handle = 0;
	const uint8_t *stored = NULL;
	uint8_t sbuf[ATT_PDU_BUF_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	uint8_t zero[16];
	ssize_t nr;

	fx->build(&db);

	for (i = 0; i < db.count; i++) {
		if (db.attrs[i].uuid16 == BT_PROFILE_SPEC_UUID_DATABASE_HASH &&
		    db.attrs[i].is_char_value) {
			hash_handle = db.attrs[i].handle;
			stored = db.attrs[i].value;
			break;
		}
	}
	ATF_REQUIRE_MSG(hash_handle != 0, "Database Hash characteristic absent");
	ATF_REQUIRE(stored != NULL);

	/* The stack must expose a non-zero computed hash. */
	memset(zero, 0, sizeof(zero));
	ATF_CHECK(memcmp(stored, zero, 16) != 0);

	srv_pair(&ac, &peer);

	{
		uint8_t req[3] = { BT_PROFILE_SPEC_ATT_READ_REQ, 0, 0 };
		put_le16(req + 1, hash_handle);
		ATF_REQUIRE_EQ((ssize_t)sizeof(req),
		    send(peer, req, sizeof(req), 0));
	}

	nr = recv(ac.fd, sbuf, sizeof(sbuf), 0);
	ATF_REQUIRE(nr > 0);
	att_server_handle(&ac, &db, sbuf, (size_t)nr, -1, 0);

	nr = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE_EQ(17, nr);			/* READ_RSP opcode + 16-byte hash */
	ATF_CHECK_EQ(BT_PROFILE_SPEC_ATT_READ_RSP, rsp[0]);
	ATF_CHECK_EQ(0, memcmp(rsp + 1, stored, 16));

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Client discovery round-trip against a scripted server response
 * (modelled on gatt_client_test.c), asserted against the Battery fixture.
 * ================================================================ */

static void
gc_pair(struct att_conn *ac, int *peer)
{
	int fds[2];

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	ATF_REQUIRE(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	memset(ac, 0, sizeof(*ac));
	ac->fd = fds[0];
	ac->bearer_fd = -1;
	ac->mtu = 517;
	ac->buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
	*peer = fds[1];
}

ATF_TC_WITHOUT_HEAD(client_roundtrip_battery);
ATF_TC_BODY(client_roundtrip_battery, tc)
{
	const struct profile_fixture *fx = profile_fixture_battery();
	struct att_db db;
	int i;

	/* Derive the fixture's real handle layout from the built DB. */
	uint16_t svc_start = 0, svc_end = 0, svc_uuid = 0;
	uint16_t decl_handle = 0, value_handle = 0, char_uuid = 0;
	uint8_t char_props = 0;
	uint16_t cccd_handle = 0;

	fx->build(&db);
	svc_end = db.attrs[db.count - 1].handle;	/* single service group */
	for (i = 0; i < db.count; i++) {
		struct att_attr *a = &db.attrs[i];

		if (a->uuid16 == BT_PROFILE_SPEC_UUID_PRIMARY_SERVICE) {
			svc_start = a->handle;
			svc_uuid = get_le16(a->value);
		} else if (a->uuid16 == BT_PROFILE_SPEC_UUID_CHARACTERISTIC) {
			decl_handle = a->handle;
			char_props = a->value[0];
			value_handle = get_le16(a->value + 1);
			char_uuid = get_le16(a->value + 3);
		} else if (a->uuid16 == BT_PROFILE_SPEC_UUID_CCCD) {
			cccd_handle = a->handle;
		}
	}
	ATF_REQUIRE(svc_start != 0 && value_handle != 0 && cccd_handle != 0);

	/* --- Primary service discovery --- */
	{
		struct att_conn ac;
		int peer;
		struct gatt_service svcs[4];
		int n = -1;
		uint8_t rsp[1 + 1 + 6];

		/*
		 * Read By Group Type Response (0x11), Vol 3 Part F §3.4.4.10:
		 * opcode | Length(1) | { Attribute Handle(2) | End Group
		 * Handle(2) | Value }.  Length = 6 for a 16-bit service UUID;
		 * one record describing the fixture's primary service group.
		 */
		gc_pair(&ac, &peer);
		rsp[0] = BT_PROFILE_SPEC_ATT_READ_BY_GROUP_RSP;
		rsp[1] = 6;
		put_le16(rsp + 2, svc_start);
		put_le16(rsp + 4, svc_end);
		put_le16(rsp + 6, svc_uuid);
		ATF_REQUIRE(send(peer, rsp, sizeof(rsp), 0) == (ssize_t)sizeof(rsp));

		ATF_CHECK_EQ(0,
		    gatt_discover_primary_services(&ac, svcs, 1, &n));
		ATF_CHECK_EQ(1, n);
		ATF_CHECK_EQ(svc_start, svcs[0].start_handle);
		ATF_CHECK_EQ(svc_end, svcs[0].end_handle);
		ATF_CHECK_EQ(svc_uuid, svcs[0].uuid16);

		free(ac.buf);
		close(ac.fd);
		close(peer);
	}

	/* --- Characteristic discovery --- */
	{
		struct att_conn ac;
		int peer;
		struct gatt_char chars[4];
		int n = -1;
		uint8_t rsp[1 + 1 + 7];

		/*
		 * Read By Type Response (0x09), Vol 3 Part F §3.4.4.2, carrying
		 * one Characteristic Declaration record (Vol 3 Part G §3.3.1):
		 * Length = 7 = 2 (declaration handle) + Properties(1) +
		 * Value Handle(2) + UUID(2).
		 */
		gc_pair(&ac, &peer);
		rsp[0] = BT_PROFILE_SPEC_ATT_READ_BY_TYPE_RSP;
		rsp[1] = 7;
		put_le16(rsp + 2, decl_handle);
		rsp[4] = char_props;
		put_le16(rsp + 5, value_handle);
		put_le16(rsp + 7, char_uuid);
		ATF_REQUIRE(send(peer, rsp, sizeof(rsp), 0) == (ssize_t)sizeof(rsp));

		ATF_CHECK_EQ(0, gatt_discover_characteristics(&ac, svc_start,
		    svc_end, chars, 1, &n));
		ATF_CHECK_EQ(1, n);
		ATF_CHECK_EQ(decl_handle, chars[0].decl_handle);
		ATF_CHECK_EQ(value_handle, chars[0].value_handle);
		ATF_CHECK_EQ(char_props, chars[0].properties);
		ATF_CHECK_EQ(char_uuid, chars[0].uuid16);

		free(ac.buf);
		close(ac.fd);
		close(peer);
	}

	/* --- Descriptor discovery (finds the CCCD) --- */
	{
		struct att_conn ac;
		int peer;
		struct gatt_desc descs[4];
		int n = -1;
		uint8_t rsp[1 + 1 + 4];

		/*
		 * Find Information Response (0x05), Vol 3 Part F §3.4.3.2:
		 * opcode | Format(1) | Information Data.  Format 0x01 = 16-bit
		 * UUIDs, each record = Handle(2) | UUID(2); one CCCD (0x2902).
		 */
		gc_pair(&ac, &peer);
		rsp[0] = BT_PROFILE_SPEC_ATT_FIND_INFO_RSP;
		rsp[1] = 1;			/* format 1: 16-bit UUIDs */
		put_le16(rsp + 2, cccd_handle);
		put_le16(rsp + 4, BT_PROFILE_SPEC_UUID_CCCD);
		ATF_REQUIRE(send(peer, rsp, sizeof(rsp), 0) == (ssize_t)sizeof(rsp));

		ATF_CHECK_EQ(0, gatt_discover_descriptors(&ac,
		    (uint16_t)(value_handle + 1), svc_end, descs, 1, &n));
		ATF_CHECK_EQ(1, n);
		ATF_CHECK_EQ(cccd_handle, descs[0].handle);
		ATF_CHECK_EQ(BT_PROFILE_SPEC_UUID_CCCD, descs[0].uuid16);

		free(ac.buf);
		close(ac.fd);
		close(peer);
	}
}

/* ================================================================
 * Sanity: every fixture builds a non-empty, well-formed DB
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(all_profiles_build);
ATF_TC_BODY(all_profiles_build, tc)
{
	const struct profile_fixture *const *all;
	size_t count, i;

	all = profile_fixtures_all(&count);
	ATF_CHECK_EQ(6, count);

	for (i = 0; i < count; i++) {
		const struct profile_fixture *fx = all[i];
		struct att_db db;
		bool found_service = false;
		int j;

		fx->build(&db);
		ATF_CHECK_MSG(db.count > 0, "%s: empty DB", fx->name);

		for (j = 0; j < db.count; j++) {
			if (db.attrs[j].uuid16 == BT_PROFILE_SPEC_UUID_PRIMARY_SERVICE &&
			    get_le16(db.attrs[j].value) == fx->service_uuid) {
				found_service = true;
				break;
			}
		}
		ATF_CHECK_MSG(found_service, "%s: primary service 0x%04x absent",
		    fx->name, fx->service_uuid);
		ATF_CHECK_MSG(fx->nops > 0, "%s: no golden operations", fx->name);
	}
}

/* ================================================================
 * Test plan
 * ================================================================ */

ATF_TP_ADD_TCS(tp)
{

	/* Golden known-answer per profile */
	ATF_TP_ADD_TC(tp, golden_gap);
	ATF_TP_ADD_TC(tp, golden_gatt);
	ATF_TP_ADD_TC(tp, golden_dis);
	ATF_TP_ADD_TC(tp, golden_battery);
	ATF_TP_ADD_TC(tp, golden_heart_rate);
	ATF_TP_ADD_TC(tp, golden_hogp);

	/* Notification paths */
	ATF_TP_ADD_TC(tp, notify_battery_level);
	ATF_TP_ADD_TC(tp, notify_heart_rate);
	ATF_TP_ADD_TC(tp, notify_hogp_report);

	/* Database Hash and client discovery round-trip */
	ATF_TP_ADD_TC(tp, gatt_database_hash_read);
	ATF_TP_ADD_TC(tp, client_roundtrip_battery);

	/* Fixture library sanity */
	ATF_TP_ADD_TC(tp, all_profiles_build);

	return (atf_no_error());
}
