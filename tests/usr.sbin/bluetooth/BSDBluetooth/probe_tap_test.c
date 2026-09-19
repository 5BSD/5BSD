/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the in-process probe tap (blued_probe_tap.[ch]).
 *
 * The production objects under test are compiled with -DWITH_PROBE_TAP so
 * that every BLUED_PROBE_x(...) call site appends a record to an in-process
 * ring buffer instead of firing a DTrace USDT probe.  Each test drives a
 * real protocol flow and asserts on the exact probe records -- name, integer
 * args, string arg, and their order.
 *
 * Flows exercised:
 *   - SMP method selection: smp_respond() consumes a crafted MITM+SC Pairing
 *     Request and reaches the smp_select_model dispatch, firing
 *     smp:phase("feature"), smp:method:select and smp:pair:start in order.
 *   - ATT error: att_send_error() fires att:error then att:send.
 *   - GATT discovery: gatt_discover_primary_services() fires gatt:disc:step
 *     once per ATT round-trip.
 *
 * Socketpair mechanics follow gatt_client_test.c / smp_negative_test.c: the
 * daemon-side fd is O_NONBLOCK, so once the preloaded datagram(s) drain the
 * next recv() returns EAGAIN and the routine unwinds -- no fork, no hang.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

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
#include "smp.h"
#include "smp_internal.h"

#include "blued_probe_tap.h"

#define TEST_LINKS_SMP
#include "test_common.h"

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif
#ifndef BDADDR_LE_RANDOM
#define BDADDR_LE_RANDOM	2
#endif

/* GATT discovery proc code, mirrored from gatt.c (GATT_DISC_PROC_PRIMARY). */
#define	PROC_PRIMARY	1

/* ================================================================
 * Stubs for hci_util.c symbols referenced by smp.c (not linked here).
 * ================================================================ */
int
hci_send_raw_cmd(int hci_fd __unused, uint16_t opcode __unused,
    const void *params __unused, uint8_t plen __unused)
{

	return (0);
}

int
hci_wait_encryption(int hci_fd __unused, uint16_t con_handle __unused,
    int timeout_sec __unused)
{

	return (0);
}

int
hci_le_ltk_request_reply(int hci_fd __unused, uint16_t con_handle __unused,
    const uint8_t ltk[16] __unused)
{

	return (0);
}

int
hci_le_ltk_request_neg_reply(int hci_fd __unused, uint16_t con_handle __unused)
{

	return (0);
}

/* ================================================================
 * att_conn helper on a nonblocking SOCK_SEQPACKET socketpair.
 * ================================================================ */
static void
ac_pair(struct att_conn *ac, int *peer_fd)
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
	*peer_fd = fds[1];
}

static void
ac_cleanup(struct att_conn *ac, int peer_fd)
{

	free(ac->buf);
	ac->buf = NULL;
	if (ac->fd >= 0)
		close(ac->fd);
	if (peer_fd >= 0)
		close(peer_fd);
}

static void
preload(int peer_fd, const uint8_t *pdu, size_t len)
{

	ATF_REQUIRE(send(peer_fd, pdu, len, 0) == (ssize_t)len);
}

static const uint8_t local_addr[6]  = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
static const uint8_t remote_addr[6] = { 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

/* ================================================================
 * 1. Tap API sanity: reset / rec* / count / get / find.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(tap_api_basics);
ATF_TC_BODY(tap_api_basics, tc)
{
	const struct probe_rec *r;
	size_t idx;

	probe_tap_reset();
	ATF_CHECK_EQ(0, probe_tap_count());
	/* find on empty ring returns count() (== 0), the end sentinel. */
	ATF_CHECK_EQ(0, probe_tap_find("nope", 0));

	probe_tap_rec0("a:one", "hello");
	probe_tap_rec3("b:two", NULL, 10, 20, 30);
	probe_tap_rec1("a:one", "world", 7);

	ATF_CHECK_EQ(3, probe_tap_count());

	r = probe_tap_get(0);
	ATF_REQUIRE(r != NULL);
	ATF_CHECK_STREQ("a:one", r->name);
	ATF_CHECK_EQ(1, r->has_str);
	ATF_CHECK_STREQ("hello", r->str);
	ATF_CHECK_EQ(0, r->nargs);

	r = probe_tap_get(1);
	ATF_REQUIRE(r != NULL);
	ATF_CHECK_STREQ("b:two", r->name);
	ATF_CHECK_EQ(0, r->has_str);
	ATF_CHECK_EQ(3, r->nargs);
	ATF_CHECK_EQ(10, r->args[0]);
	ATF_CHECK_EQ(20, r->args[1]);
	ATF_CHECK_EQ(30, r->args[2]);

	/* out-of-range get returns NULL. */
	ATF_CHECK(probe_tap_get(3) == NULL);

	/* find honours the "from" cursor and finds successive matches. */
	idx = probe_tap_find("a:one", 0);
	ATF_CHECK_EQ(0, idx);
	idx = probe_tap_find("a:one", idx + 1);
	ATF_CHECK_EQ(2, idx);
	idx = probe_tap_find("a:one", idx + 1);
	ATF_CHECK_EQ(3, idx);	/* == count(): no further match */

	probe_tap_reset();
	ATF_CHECK_EQ(0, probe_tap_count());
}

/* ================================================================
 * 2. ATT error: att_send_error() -> att:error then att:send.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(att_error_probe);
ATF_TC_BODY(att_error_probe, tc)
{
	struct att_conn ac;
	int peer;
	const struct probe_rec *err, *snd;
	size_t ei, si;

	ac_pair(&ac, &peer);
	probe_tap_reset();

	ATF_CHECK_EQ(0, att_send_error(&ac, ATT_OP_READ_REQ, 0x0021,
	    ATT_ERR_ATTR_NOT_FOUND));

	/* att:error carries (req_opcode, handle, code). */
	ei = probe_tap_find("att:error", 0);
	ATF_REQUIRE(ei < probe_tap_count());
	err = probe_tap_get(ei);
	ATF_REQUIRE(err != NULL);
	ATF_CHECK_EQ(3, err->nargs);
	ATF_CHECK_EQ(ATT_OP_READ_REQ, err->args[0]);
	ATF_CHECK_EQ(0x0021, err->args[1]);
	ATF_CHECK_EQ(ATT_ERR_ATTR_NOT_FOUND, err->args[2]);

	/* att:send for the Error Response PDU follows att:error. */
	si = probe_tap_find("att:send", 0);
	ATF_REQUIRE(si < probe_tap_count());
	ATF_CHECK(ei < si);		/* error probe precedes the send probe */
	snd = probe_tap_get(si);
	ATF_REQUIRE(snd != NULL);
	ATF_CHECK_EQ(ATT_OP_ERROR_RSP, snd->args[0]);
	ATF_CHECK_EQ(5, snd->args[1]);	/* Error Response PDU is 5 octets */

	ac_cleanup(&ac, peer);
}

/* ================================================================
 * 3. GATT discovery: gatt_discover_primary_services() -> gatt:disc:step.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(gatt_disc_step_probe);
ATF_TC_BODY(gatt_disc_step_probe, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[4];
	int n = -1;
	const struct probe_rec *step;
	size_t i;
	uint8_t rsp[1 + 1 + 2 * 6];

	ac_pair(&ac, &peer);

	/* Read By Group Type Response, entry_len = 6, two services. */
	rsp[0] = ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 6;
	put_le16(rsp + 2, 0x0001); put_le16(rsp + 4, 0x0005);
	put_le16(rsp + 6, 0x1800);
	put_le16(rsp + 8, 0x0006); put_le16(rsp + 10, 0x0009);
	put_le16(rsp + 12, 0x180F);
	preload(peer, rsp, sizeof(rsp));

	probe_tap_reset();
	/* maxsvcs == 2 terminates discovery after this single datagram. */
	ATF_CHECK_EQ(0, gatt_discover_primary_services(&ac, svcs, 2, &n));
	ATF_CHECK_EQ(2, n);

	/* First (and only) discovery step: proc=PRIMARY, 0x0001-0xFFFF, 0. */
	i = probe_tap_find("gatt:disc:step", 0);
	ATF_REQUIRE(i < probe_tap_count());
	step = probe_tap_get(i);
	ATF_REQUIRE(step != NULL);
	ATF_CHECK_EQ(4, step->nargs);
	ATF_CHECK_EQ(PROC_PRIMARY, step->args[0]);
	ATF_CHECK_EQ(0x0001, step->args[1]);	/* start */
	ATF_CHECK_EQ(0xFFFF, step->args[2]);	/* end */
	ATF_CHECK_EQ(0, step->args[3]);		/* found so far at step entry */

	ac_cleanup(&ac, peer);
}

/* ================================================================
 * 4. SMP method selection: smp_respond() reaches the model dispatch and
 *    fires smp:phase("feature"), smp:method:select, smp:pair:start in order.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(smp_method_select_probe);
ATF_TC_BODY(smp_method_select_probe, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	const struct probe_rec *ms;
	size_t feat, sel, start;
	uint8_t req[7];

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	/*
	 * Nonblocking DUT fd: after the Pairing Request is consumed and the
	 * responder proceeds into SC key exchange, the next recv() returns
	 * EAGAIN and smp_respond unwinds -- but only after the model-selection
	 * probes have already fired.
	 */
	ATF_REQUIRE(fcntl(smp_fds[0], F_SETFL, O_NONBLOCK) == 0);

	memset(&db, 0, sizeof(db));
	db.fd = -1;
	memset(&sc, 0, sizeof(sc));
	smp_seed_policy_defaults(&sc);
	sc.fd = smp_fds[0];
	sc.hci_fd = hci_fds[0];
	sc.con_handle = 0x0040;
	memcpy(sc.local_addr, local_addr, 6);
	sc.local_addr_type = BDADDR_LE_PUBLIC;
	memcpy(sc.remote_addr, remote_addr, 6);
	sc.remote_addr_type = BDADDR_LE_PUBLIC;
	sc.bond_db = &db;
	sc.io_capability = SMP_IO_DISPLAY_YESNO;	/* responder IO cap */
	sc.min_key_size = 16;

	/*
	 * Pairing Request: DisplayYesNo, MITM + Secure Connections, 16-byte
	 * key.  With the responder also DisplayYesNo, SC + MITM select
	 * Numeric Comparison (Core Spec Vol 3 Part H Table 2.8).
	 */
	req[0] = SMP_PAIRING_REQUEST;
	req[1] = SMP_IO_DISPLAY_YESNO;			/* initiator IO cap */
	req[2] = 0x00;					/* no OOB */
	req[3] = SMP_AUTH_BONDING | SMP_AUTH_MITM | SMP_AUTH_SC;
	req[4] = 16;					/* max key size */
	req[5] = SMP_KEY_DIST_ID_KEY | SMP_KEY_DIST_LEGACY_SIGN_KEY;
	req[6] = SMP_KEY_DIST_ID_KEY | SMP_KEY_DIST_LEGACY_SIGN_KEY;
	preload(smp_fds[1], req, sizeof(req));

	probe_tap_reset();
	(void)smp_respond(&sc);		/* returns -1 as SC exchange can't complete */

	/* Ordering: feature exchange -> method select -> pair start. */
	feat = probe_tap_find("smp:phase", 0);
	sel = probe_tap_find("smp:method:select", 0);
	start = probe_tap_find("smp:pair:start", 0);
	ATF_REQUIRE(sel < probe_tap_count());
	ATF_REQUIRE(start < probe_tap_count());
	ATF_REQUIRE(feat < probe_tap_count());
	ATF_CHECK(feat < sel);
	ATF_CHECK(sel < start);

	/* smp:phase before method:select is the "feature" phase. */
	ATF_CHECK_STREQ("feature", probe_tap_get(feat)->str);

	/* smp:method:select carries (init_io, resp_io, authreq, model). */
	ms = probe_tap_get(sel);
	ATF_REQUIRE(ms != NULL);
	ATF_CHECK_EQ(4, ms->nargs);
	ATF_CHECK_EQ(SMP_IO_DISPLAY_YESNO, ms->args[0]);	/* init_io */
	ATF_CHECK_EQ(SMP_IO_DISPLAY_YESNO, ms->args[1]);	/* resp_io */
	ATF_CHECK_EQ((uint64_t)req[3], ms->args[2]);		/* authreq */
	ATF_CHECK_EQ(SMP_MODEL_NUMERIC_COMPARISON, ms->args[3]);
	ATF_CHECK_EQ(1, ms->has_str);			/* remote address string */
	ATF_CHECK(ms->str[0] != '\0');

	/* smp:pair:start carries the selected model in arg 0. */
	ATF_CHECK_EQ(SMP_MODEL_NUMERIC_COMPARISON, probe_tap_get(start)->args[0]);

	close(smp_fds[0]); close(smp_fds[1]);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* ================================================================
 * 5. ATT notification: att_send_notification() -> att:notify carrying the
 *    value handle and the on-wire PDU length, followed by att:send.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(att_notify_probe);
ATF_TC_BODY(att_notify_probe, tc)
{
	struct att_conn ac;
	int peer;
	const struct probe_rec *ntf;
	size_t ni, si;
	static const uint8_t val[4] = { 0xde, 0xad, 0xbe, 0xef };

	ac_pair(&ac, &peer);
	probe_tap_reset();

	ATF_CHECK_EQ(0, att_send_notification(&ac, 0x0025, val, sizeof(val)));

	/* att:notify carries (handle, pdu_len == 3 + value_len). */
	ni = probe_tap_find("att:notify", 0);
	ATF_REQUIRE(ni < probe_tap_count());
	ntf = probe_tap_get(ni);
	ATF_REQUIRE(ntf != NULL);
	ATF_CHECK_EQ(2, ntf->nargs);
	ATF_CHECK_EQ(0x0025, ntf->args[0]);		/* value handle */
	ATF_CHECK_EQ(3 + sizeof(val), ntf->args[1]);	/* opcode+handle+value */

	/* The Handle Value Notification PDU was actually sent (att:send). */
	si = probe_tap_find("att:send", 0);
	ATF_REQUIRE(si < probe_tap_count());
	ATF_CHECK_EQ(ATT_OP_HANDLE_NOTIFY, probe_tap_get(si)->args[0]);

	ac_cleanup(&ac, peer);
}

/* ================================================================
 * 6. SMP PDU sequence: driving smp_respond() with a Pairing Request funnels
 *    every PDU through smp_log_send/smp_log_recv, so the tap captures the
 *    responder handshake order: rx(PairingRequest) -> tx(PairingResponse).
 *    (The SC Public Key is only sent after the initiator's Public Key is
 *    received, which this single-datagram harness does not preload, so the
 *    responder unwinds on EAGAIN right after the Pairing Response.)  This
 *    asserts the per-PDU tx/rx probes fire with the right opcodes/lengths in
 *    the right order.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(smp_pdu_sequence_probe);
ATF_TC_BODY(smp_pdu_sequence_probe, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	const struct probe_rec *rx, *tx;
	size_t rxi, txi;
	uint8_t req[7];

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	ATF_REQUIRE(fcntl(smp_fds[0], F_SETFL, O_NONBLOCK) == 0);

	memset(&db, 0, sizeof(db));
	db.fd = -1;
	memset(&sc, 0, sizeof(sc));
	smp_seed_policy_defaults(&sc);
	sc.fd = smp_fds[0];
	sc.hci_fd = hci_fds[0];
	sc.con_handle = 0x0040;
	memcpy(sc.local_addr, local_addr, 6);
	sc.local_addr_type = BDADDR_LE_PUBLIC;
	memcpy(sc.remote_addr, remote_addr, 6);
	sc.remote_addr_type = BDADDR_LE_PUBLIC;
	sc.bond_db = &db;
	sc.io_capability = SMP_IO_DISPLAY_YESNO;
	sc.min_key_size = 16;

	req[0] = SMP_PAIRING_REQUEST;
	req[1] = SMP_IO_DISPLAY_YESNO;
	req[2] = 0x00;
	req[3] = SMP_AUTH_BONDING | SMP_AUTH_MITM | SMP_AUTH_SC;
	req[4] = 16;
	req[5] = SMP_KEY_DIST_ID_KEY | SMP_KEY_DIST_LEGACY_SIGN_KEY;
	req[6] = SMP_KEY_DIST_ID_KEY | SMP_KEY_DIST_LEGACY_SIGN_KEY;
	preload(smp_fds[1], req, sizeof(req));

	probe_tap_reset();
	(void)smp_respond(&sc);

	/* First inbound PDU is the Pairing Request. */
	rxi = probe_tap_find("smp:pdu:rx", 0);
	ATF_REQUIRE(rxi < probe_tap_count());
	rx = probe_tap_get(rxi);
	ATF_CHECK_EQ(SMP_PAIRING_REQUEST, rx->args[0]);
	ATF_CHECK_EQ(sizeof(req), rx->args[1]);

	/* First outbound PDU is the 7-octet Pairing Response, after the request. */
	txi = probe_tap_find("smp:pdu:tx", 0);
	ATF_REQUIRE(txi < probe_tap_count());
	tx = probe_tap_get(txi);
	ATF_CHECK_EQ(SMP_PAIRING_RESPONSE, tx->args[0]);
	ATF_CHECK_EQ(7, tx->args[1]);		/* Pairing Response PDU length */
	ATF_CHECK(rxi < txi);			/* request precedes response */

	close(smp_fds[0]); close(smp_fds[1]);
	close(hci_fds[0]); close(hci_fds[1]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, tap_api_basics);
	ATF_TP_ADD_TC(tp, att_error_probe);
	ATF_TP_ADD_TC(tp, gatt_disc_step_probe);
	ATF_TP_ADD_TC(tp, smp_method_select_probe);
	ATF_TP_ADD_TC(tp, att_notify_probe);
	ATF_TP_ADD_TC(tp, smp_pdu_sequence_probe);

	return (atf_no_error());
}
