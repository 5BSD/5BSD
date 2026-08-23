/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF negative / malformed-input tests for the SMP pairing state machine.
 *
 * Where smp_pairing_test.c drives the happy path with a full mock peer over
 * fork(2), this file pushes truncated, out-of-range and hostile SMP wire
 * bytes through the responder (smp_respond) and initiator (smp_pair) at each
 * pairing state and asserts graceful rejection with no crash / no over-read.
 *
 * Technique: the L2CAP SMP channel is a SOCK_SEQPACKET socketpair.  Because
 * SEQPACKET preserves datagram boundaries, we PRELOAD the exact sequence of
 * peer PDUs into the socket before invoking the DUT -- no fork or mock-peer
 * process is needed for these single-shot rejection cases.  The DUT reads the
 * preloaded datagrams one recv() at a time exactly as it would off the wire,
 * rejects the malformed one, and returns.  For the "accepted" key-size
 * boundary cases the daemon fd is put in O_NONBLOCK so the responder unwinds
 * (recv -> EAGAIN) once the preloaded input drains instead of blocking.
 *
 * Each ATF test case runs in its own process (ATF forks per tc), so the
 * file-static pairing rate-limit table in smp.c starts fresh for every case
 * and never triggers BTNG_SMP_ERR_REPEATED_ATTEMPTS here.
 *
 * Links with: smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
 * Extra libs: -lcrypto (OpenSSL EVP/EC) -lpthread (bond_db lock type)
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "att.h"
#include "att_server.h"
#include "hci_log.h"
#include "hci_util.h"
#include "spec_oracles.h"
#include "spec_smp_timeout_oracles.h"
#include "smp.h"
#include "smp_internal.h"

#define TEST_LINKS_SMP
#include "test_common.h"

/*
 * Test-only SMP wire assignments generated from Bluetooth Core 6.3.
 * Keep hostile-peer stimuli and expected failure transcripts independent of
 * the production SMP_* constants in smp.h: otherwise the same wrong value in
 * the implementation and test could pass unnoticed.
 */
#define BTNG_ORACLE_ENUM(name, value) BTNG_##name = (value),
enum {
	BT_CORE63_SMP_COMMAND_ORACLES(BTNG_ORACLE_ENUM)
	BT_CORE63_SMP_FAILURE_ORACLES(BTNG_ORACLE_ENUM)
	BT_CORE63_SMP_SCALAR_ORACLES(BTNG_ORACLE_ENUM)
	BT_CORE63_SMP_KEY_DIST_ORACLES(BTNG_ORACLE_ENUM)
	BT_CORE63_PREVIOUSLY_USED_ORACLES(BTNG_ORACLE_ENUM)
	BTNG_SMP_MODEL_INVALID = -1	/* smp_select_model() API contract. */
};
#undef BTNG_ORACLE_ENUM

/* BDADDR_LE_* from ng_bluetooth.h; provide fallbacks like smp_pairing_test. */
#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif
#ifndef BDADDR_LE_RANDOM
#define BDADDR_LE_RANDOM	2
#endif

/*
 * smp_open()'s transport-failure test must not depend on whether the host has
 * a Bluetooth stack or a responding peer.  Fail only Bluetooth socket opens;
 * the suite's AF_UNIX socketpairs remain real.
 */
int __real_socket(int, int, int);
int __wrap_socket(int, int, int);

int
__wrap_socket(int domain, int type, int protocol)
{

	if (domain == AF_BLUETOOTH) {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	return (__real_socket(domain, type, protocol));
}

/* ================================================================
 * Stubs for external symbols referenced by smp.c (hci_util.c).
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
 * Helpers
 * ================================================================ */

static const uint8_t central_addr[6] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
static const uint8_t periph_addr[6]  = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
static uint64_t negative_vclock;

static void
negative_clock_hook(struct timespec *ts)
{

	ts->tv_sec = (time_t)negative_vclock;
	ts->tv_nsec = 0;
}

/* Decode generator-parsed Core big-endian coordinate strings. */
static void
core_hex_be(uint8_t *out, const char *hex, size_t len)
{
	size_t i;
	unsigned int byte;

	for (i = 0; i < len; i++) {
		ATF_REQUIRE_EQ(1, sscanf(hex + 2 * i, "%02x", &byte));
		out[i] = (uint8_t)byte;
	}
}

/*
 * Initialise an smp_conn for a responder/initiator test.
 * smp_fds[0] is the DUT side, smp_fds[1] is the "peer" side we preload.
 * The bond DB fd is -1 so smp_bond_db_save() is a harmless no-op (no file
 * I/O, no bond secret key file creation).
 */
static void
setup_sc(struct smp_conn *sc, struct smp_bond_db *db,
    int smp_fds[2], int hci_fds[2],
    const uint8_t *local_addr, uint8_t local_type,
    const uint8_t *remote_addr, uint8_t remote_type)
{

	signal(SIGPIPE, SIG_IGN);

	memset(db, 0, sizeof(*db));
	db->fd = -1;

	memset(sc, 0, sizeof(*sc));
	smp_seed_policy_defaults(sc);
	sc->fd = smp_fds[0];
	sc->hci_fd = hci_fds[0];
	sc->con_handle = 0x0040;
	memcpy(sc->local_addr, local_addr, 6);
	sc->local_addr_type = local_type;
	memcpy(sc->remote_addr, remote_addr, 6);
	sc->remote_addr_type = remote_type;
	sc->bond_db = db;
	sc->io_capability = BTNG_SMP_IO_NO_INPUT_NO_OUTPUT;
	sc->min_key_size = BT_CORE63_SMP_MIN_KEY_SIZE;

	/* Bound blocking recv()s so a diverging test never hangs. */
	{
		struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
		setsockopt(smp_fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
}

/* Preload one SMP PDU as a datagram onto the peer side of the pair. */
static void
preload(int peer_fd, const uint8_t *pdu, size_t len)
{

	ATF_REQUIRE(send(peer_fd, pdu, len, 0) == (ssize_t)len);
}

/*
 * Build a Just Works (NoInputNoOutput, no MITM, no SC) Pairing Request
 * with the given max_key_size.  This drives the legacy responder path.
 */
static void
build_jw_request(uint8_t r[7], uint8_t key_size)
{

	r[0] = BTNG_SMP_PAIRING_REQUEST;	/* Vol 3 Part H §3.3 Table 3.3. */
	r[1] = BTNG_SMP_IO_NO_INPUT_NO_OUTPUT; /* §3.5.1 Table 3.4. */
	r[2] = 0x00;			/* §3.5.1: OOB Authentication data not present. */
	r[3] = BTNG_SMP_AUTH_BONDING;	/* §3.5.1 Figure 3.3: Bonding only. */
	r[4] = key_size;
	r[5] = 0x00;			/* §3.6.1 Figure 3.11: no initiator keys. */
	r[6] = BTNG_SMP_KEY_DIST_ENC_KEY; /* §3.6.1 Figure 3.11: EncKey. */
}

/*
 * Drain the DUT's outbound PDUs (non-blocking) and report whether a
 * Pairing Failed with the given reason was seen.  Also returns the opcode
 * of the very first PDU via *first_op (or 0 if none).
 */
static bool
saw_pairing_failed(int peer_fd, uint8_t reason, uint8_t *first_op)
{
	uint8_t buf[64];
	ssize_t n;
	bool found = false;
	bool first = true;

	(void)fcntl(peer_fd, F_SETFL, O_NONBLOCK);
	if (first_op != NULL)
		*first_op = 0;

	while ((n = recv(peer_fd, buf, sizeof(buf), 0)) > 0) {
		if (first) {
			first = false;
			if (first_op != NULL)
				*first_op = buf[0];
		}
		if (n == 2 && buf[0] == BTNG_SMP_PAIRING_FAILED &&
		    buf[1] == reason)
			found = true;
	}
	return (found);
}

/* Require one exact outbound SMP datagram, in protocol order. */
static void
expect_pdu(int peer_fd, const uint8_t *expected, size_t expected_len)
{
	uint8_t actual[65];
	ssize_t n;

	(void)fcntl(peer_fd, F_SETFL, O_NONBLOCK);
	n = recv(peer_fd, actual, sizeof(actual), 0);
	ATF_REQUIRE_EQ_MSG(n, (ssize_t)expected_len,
	    "expected %zu-octet SMP PDU, received %zd", expected_len, n);
	ATF_CHECK_MSG(memcmp(actual, expected, expected_len) == 0,
	    "unexpected SMP PDU: got opcode 0x%02x, expected 0x%02x",
	    actual[0], expected[0]);
}

/* Require one PDU whose random cryptographic payload is not an oracle here. */
static void
expect_pdu_shape(int peer_fd, uint8_t opcode, size_t expected_len)
{
	uint8_t actual[65];
	ssize_t n;

	(void)fcntl(peer_fd, F_SETFL, O_NONBLOCK);
	n = recv(peer_fd, actual, sizeof(actual), 0);
	ATF_REQUIRE_EQ_MSG(n, (ssize_t)expected_len,
	    "expected %zu-octet SMP PDU, received %zd", expected_len, n);
	ATF_CHECK_EQ(actual[0], opcode);
}

static void
expect_no_pdu(int peer_fd)
{
	uint8_t actual[65];
	ssize_t n;

	(void)fcntl(peer_fd, F_SETFL, O_NONBLOCK);
	errno = 0;
	n = recv(peer_fd, actual, sizeof(actual), 0);
	ATF_CHECK_EQ_MSG(n, -1, "unexpected outbound SMP PDU opcode 0x%02x",
	    n > 0 ? actual[0] : 0);
	ATF_CHECK_MSG(errno == EAGAIN || errno == EWOULDBLOCK,
	    "empty outbound queue returned errno %d", errno);
}

/* Exact local feature PDUs for setup_sc()'s explicitly selected policy. */
static void
expect_pairing_request(int peer_fd, uint8_t io_capability)
{
	const uint8_t expected[7] = {
		BTNG_SMP_PAIRING_REQUEST,	/* Vol 3 Part H §3.3 Table 3.3. */
		io_capability,			/* §3.5.1 Table 3.4. */
		0x00,				/* §3.5.1: no OOB data. */
		BTNG_SMP_AUTH_BONDING | BTNG_SMP_AUTH_MITM |
		    BTNG_SMP_AUTH_SC | BTNG_SMP_AUTH_KEYPRESS |
		    BTNG_SMP_AUTH_CT2,		/* §3.5.1 Figure 3.3. */
		BT_CORE63_SMP_MAX_KEY_SIZE,	/* §3.5.1: 7..16 octets. */
		BT_CORE63_SMP_KEY_DIST_DEFAULT_MASK, /* §3.6.1 Figure 3.11. */
		BT_CORE63_SMP_KEY_DIST_DEFAULT_MASK
	};

	expect_pdu(peer_fd, expected, sizeof(expected));
}

static void
expect_default_pairing_request(int peer_fd)
{

	expect_pairing_request(peer_fd, BTNG_SMP_IO_NO_INPUT_NO_OUTPUT);
}

static void
expect_failure_after_default_request(int peer_fd, uint8_t reason)
{
	const uint8_t failed[2] = { BTNG_SMP_PAIRING_FAILED, reason };

	expect_default_pairing_request(peer_fd);
	expect_pdu(peer_fd, failed, sizeof(failed));
	expect_no_pdu(peer_fd);
}

static void
expect_pairing_response(int peer_fd, uint8_t io_capability, bool peer_sc)
{
	const uint8_t expected[7] = {
		BTNG_SMP_PAIRING_RESPONSE,	/* Vol 3 Part H §3.3 Table 3.3. */
		io_capability,			/* §3.5.1 Table 3.4. */
		0x00,				/* §3.5.1: no OOB data. */
		BTNG_SMP_AUTH_BONDING | BTNG_SMP_AUTH_MITM |
		    BTNG_SMP_AUTH_SC | BTNG_SMP_AUTH_KEYPRESS |
		    BTNG_SMP_AUTH_CT2,		/* §3.5.1 Figure 3.3. */
		BT_CORE63_SMP_MAX_KEY_SIZE,	/* §3.5.1: 7..16 octets. */
		0x00,				/* §3.6.1: offered InitKeyDist subset. */
		peer_sc ? 0x00 : BTNG_SMP_KEY_DIST_ENC_KEY
					/* §3.6.1: SC ignores EncKey. */
	};

	expect_pdu(peer_fd, expected, sizeof(expected));
}

static void
expect_default_legacy_pairing_response(int peer_fd)
{

	expect_pairing_response(peer_fd, BTNG_SMP_IO_NO_INPUT_NO_OUTPUT, false);
}

static void
expect_failure_after_response(int peer_fd, uint8_t io_capability,
    bool peer_sc, uint8_t reason)
{
	const uint8_t failed[2] = { BTNG_SMP_PAIRING_FAILED, reason };

	expect_pairing_response(peer_fd, io_capability, peer_sc);
	expect_pdu(peer_fd, failed, sizeof(failed));
	expect_no_pdu(peer_fd);
}

static void
close_pair(int fds[2])
{

	close(fds[0]);
	close(fds[1]);
}

static void build_pres(uint8_t [7], uint8_t, uint8_t, uint8_t);
static void build_req(uint8_t [7], uint8_t, uint8_t, uint8_t);

/* ================================================================
 * 1. Short Pairing Request (< 7 bytes) -> responder rejects.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_resp_short_request);
ATF_TC_BODY(test_resp_short_request, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t truncated[3] = { BTNG_SMP_PAIRING_REQUEST, 0x03, 0x00 };
	const uint8_t failed[2] = { BTNG_SMP_PAIRING_FAILED,
	    BTNG_SMP_ERR_INVALID_PARAMETERS };
	int saved_errno;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);

	preload(smp_fds[1], truncated, sizeof(truncated));

	ATF_CHECK_EQ(smp_respond(&sc), -1);
	saved_errno = errno;
	ATF_CHECK_EQ(saved_errno, EPROTO);
	expect_pdu(smp_fds[1], failed, sizeof(failed));
	expect_no_pdu(smp_fds[1]);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* ================================================================
 * 2. Short Pairing Response (< 7 bytes) -> initiator rejects.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_pair_short_response);
ATF_TC_BODY(test_pair_short_response, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t truncated[3] = { BTNG_SMP_PAIRING_RESPONSE, 0x03, 0x00 };
	const uint8_t failed[2] = { BTNG_SMP_PAIRING_FAILED,
	    BTNG_SMP_ERR_INVALID_PARAMETERS };
	int saved_errno;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);

	/*
	 * smp_pair() sends its Pairing Request first (buffered on the peer
	 * side, unread) then recv()s the response -- which is this short one.
	 */
	preload(smp_fds[1], truncated, sizeof(truncated));

	ATF_CHECK_EQ(smp_pair(&sc), -1);
	saved_errno = errno;
	ATF_CHECK_EQ(saved_errno, EPROTO);
	expect_default_pairing_request(smp_fds[1]);
	expect_pdu(smp_fds[1], failed, sizeof(failed));
	expect_no_pdu(smp_fds[1]);
	ATF_CHECK_EQ(db.count, 0);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* ================================================================
 * 3. Short Pairing Confirm (< 17) mid-flow -> responder rejects.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_resp_short_confirm);
ATF_TC_BODY(test_resp_short_confirm, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t req[7];
	uint8_t short_confirm[5] = { BTNG_SMP_PAIRING_CONFIRM, 0, 0, 0, 0 };
	int saved_errno;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);

	build_jw_request(req, 16);
	preload(smp_fds[1], req, sizeof(req));
	preload(smp_fds[1], short_confirm, sizeof(short_confirm));

	ATF_CHECK_EQ(smp_respond(&sc), -1);
	saved_errno = errno;
	ATF_CHECK_EQ(saved_errno, EPROTO);
	expect_default_legacy_pairing_response(smp_fds[1]);
	expect_no_pdu(smp_fds[1]);
	ATF_CHECK_EQ(db.count, 0);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* ================================================================
 * 4. Short Pairing Random (< 17) mid-flow -> responder rejects.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_resp_short_random);
ATF_TC_BODY(test_resp_short_random, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t req[7];
	uint8_t confirm[17];
	uint8_t short_random[5] = { BTNG_SMP_PAIRING_RANDOM, 0, 0, 0, 0 };
	int saved_errno;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);

	build_jw_request(req, 16);
	memset(confirm, 0xAB, sizeof(confirm));
	confirm[0] = BTNG_SMP_PAIRING_CONFIRM;	/* well-formed length so the
						 * responder advances to the
						 * random state */

	preload(smp_fds[1], req, sizeof(req));
	preload(smp_fds[1], confirm, sizeof(confirm));
	preload(smp_fds[1], short_random, sizeof(short_random));

	ATF_CHECK_EQ(smp_respond(&sc), -1);
	saved_errno = errno;
	ATF_CHECK_EQ(saved_errno, EPROTO);
	expect_default_legacy_pairing_response(smp_fds[1]);
	expect_pdu_shape(smp_fds[1], BTNG_SMP_PAIRING_CONFIRM, 17);
	expect_no_pdu(smp_fds[1]);
	ATF_CHECK_EQ(db.count, 0);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* ================================================================
 * 5. Unknown / invalid opcode as first PDU -> responder rejects
 *    with Command Not Supported.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_resp_unknown_opcode);
ATF_TC_BODY(test_resp_unknown_opcode, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t garbage[7] = { 0xEE, 0, 0, 0, 0, 0, 0 };
	const uint8_t failed[2] = { BTNG_SMP_PAIRING_FAILED,
	    BTNG_SMP_ERR_CMD_NOT_SUPPORTED };
	int saved_errno;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);

	preload(smp_fds[1], garbage, sizeof(garbage));

	ATF_CHECK_EQ(smp_respond(&sc), -1);
	saved_errno = errno;
	ATF_CHECK_EQ(saved_errno, EPROTO);
	expect_pdu(smp_fds[1], failed, sizeof(failed));
	expect_no_pdu(smp_fds[1]);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* ================================================================
 * 6. Pairing Failed injected mid-flow (where a Confirm is expected)
 *    -> responder aborts gracefully (EACCES).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_resp_pairing_failed_midflow);
ATF_TC_BODY(test_resp_pairing_failed_midflow, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t req[7];
	uint8_t failed[2] = { BTNG_SMP_PAIRING_FAILED, BTNG_SMP_ERR_UNSPECIFIED_REASON };
	int saved_errno;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);

	build_jw_request(req, 16);
	preload(smp_fds[1], req, sizeof(req));
	preload(smp_fds[1], failed, sizeof(failed));

	ATF_CHECK_EQ(smp_respond(&sc), -1);
	saved_errno = errno;
	ATF_CHECK_EQ(saved_errno, EACCES);
	expect_default_legacy_pairing_response(smp_fds[1]);
	expect_no_pdu(smp_fds[1]);
	ATF_CHECK_EQ(db.count, 0);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* ================================================================
 * 6b. Well-formed but OUT-OF-SEQUENCE PDU where a Pairing Confirm is
 *     expected -> responder replies with Pairing Failed (Unspecified
 *     Reason) rather than dropping silently.
 *
 * Core Spec Vol 3 Part H §3.5.5 / §3.4: a peer that sends a spec-legal
 * PDU in the wrong protocol state should be told the exchange is dead so
 * it does not wait out the SMP timeout.  Truncated garbage is a separate
 * case (left silent, see test_resp_short_confirm).
 *
 * Pre-fix the legacy responder set errno=EPROTO and aborted WITHOUT any
 * Pairing Failed; this test asserts the reply is now emitted.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_resp_out_of_sequence_confirm);
ATF_TC_BODY(test_resp_out_of_sequence_confirm, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t req[7];
	uint8_t wrong[17];
	const uint8_t failed[2] = { BTNG_SMP_PAIRING_FAILED,
	    BTNG_SMP_ERR_UNSPECIFIED_REASON };
	int saved_errno;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);

	/* Just Works legacy request; responder then expects a Pairing Confirm. */
	build_jw_request(req, 16);
	/* A full-length, spec-legal Pairing Random arrives out of sequence. */
	memset(wrong, 0xA5, sizeof(wrong));
	wrong[0] = BTNG_SMP_PAIRING_RANDOM;

	preload(smp_fds[1], req, sizeof(req));
	preload(smp_fds[1], wrong, sizeof(wrong));

	ATF_CHECK_EQ(smp_respond(&sc), -1);
	saved_errno = errno;
	ATF_CHECK_EQ(saved_errno, EPROTO);
	expect_default_legacy_pairing_response(smp_fds[1]);
	expect_pdu(smp_fds[1], failed, sizeof(failed));
	expect_no_pdu(smp_fds[1]);
	ATF_CHECK_EQ(db.count, 0);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* ================================================================
 * 6c. Legacy initiator Passkey Entry with no passkey callback ->
 *     smp_pair() must emit Pairing Failed (Pairing Not Supported)
 *     before aborting, matching the responder / SC-role behaviour.
 *
 * Core Spec Vol 3 Part H §3.5.5: without a UI to enter/display the
 * passkey the negotiated method cannot be fulfilled; the peer must be
 * told so it does not wait out the SMP timeout.  Pre-fix the initiator
 * set errno=ENOTSUP and returned with NO Pairing Failed on the wire.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_pair_legacy_passkey_no_cb_fails);
ATF_TC_BODY(test_pair_legacy_passkey_no_cb_fails, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t pres[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);
	/* We are KeyboardOnly (we would input) but provide NO passkey_cb. */
	sc.io_capability = BTNG_SMP_IO_KEYBOARD_ONLY;
	sc.passkey_cb = NULL;

	/*
	 * Peer response: DisplayOnly + MITM, no SC -> legacy Passkey Entry
	 * (Table 2.8).  smp_pair() sends its request first (buffered, unread)
	 * then reads this response and selects the passkey model.
	 */
	build_pres(pres, BTNG_SMP_IO_DISPLAY_ONLY,
	    BTNG_SMP_AUTH_BONDING | BTNG_SMP_AUTH_MITM,
	    BT_CORE63_SMP_MAX_KEY_SIZE);
	preload(smp_fds[1], pres, sizeof(pres));

	ATF_CHECK_EQ(smp_pair(&sc), -1);
	ATF_CHECK_EQ(errno, ENOTSUP);
	expect_pairing_request(smp_fds[1], BTNG_SMP_IO_KEYBOARD_ONLY);
	{
		const uint8_t failed[2] = { BTNG_SMP_PAIRING_FAILED,
		    BTNG_SMP_ERR_PAIRING_NOT_SUPPORTED };
		expect_pdu(smp_fds[1], failed, sizeof(failed));
	}
	expect_no_pdu(smp_fds[1]);
	ATF_CHECK_EQ(db.count, 0);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* ================================================================
 * Key-size negotiation boundaries (responder side).
 *
 * pres[4] is hard-coded to 16, so the negotiated size is min(16, peer).
 * Valid range is [7,16]; 6 and 17 are out of range.  min_key_size is 7.
 * ================================================================ */

/* Shared helper: run responder against a JW request carrying key_size and
 * report whether it was rejected on key-size grounds. */
static void
run_keysize_case(uint8_t key_size, bool expect_reject)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t req[7];
	uint8_t first_op = 0;
	bool rejected;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);

	/* Non-blocking so an accepted request unwinds once input drains. */
	(void)fcntl(smp_fds[0], F_SETFL, O_NONBLOCK);

	build_jw_request(req, key_size);
	preload(smp_fds[1], req, sizeof(req));

	/* smp_respond always returns -1 here (peer never completes), so the
	 * signal is whether a key-size/param Pairing Failed was emitted. */
	(void)smp_respond(&sc);
	rejected = saw_pairing_failed(smp_fds[1],
	    BT_CORE63_SMP_INVALID_PARAMETERS_ERROR,
	    &first_op);

	if (expect_reject) {
		ATF_CHECK_MSG(rejected,
		    "key_size %u: expected Invalid Parameters rejection",
		    key_size);
	} else {
		ATF_CHECK_MSG(!rejected,
		    "key_size %u: unexpected rejection", key_size);
		/* Accepted path still emits a Pairing Response first. */
		ATF_CHECK_EQ_MSG(first_op, BT_CORE63_SMP_PAIRING_RESPONSE_OPCODE,
		    "key_size %u: expected Pairing Response, got op 0x%02x",
		    key_size, first_op);
	}

	close_pair(smp_fds);
	close_pair(hci_fds);
}

ATF_TC_WITHOUT_HEAD(test_resp_keysize_min_7);
ATF_TC_BODY(test_resp_keysize_min_7, tc)
{
	run_keysize_case(BT_CORE63_SMP_MIN_KEY_SIZE, false);
}

ATF_TC_WITHOUT_HEAD(test_resp_keysize_max_16);
ATF_TC_BODY(test_resp_keysize_max_16, tc)
{
	run_keysize_case(BT_CORE63_SMP_MAX_KEY_SIZE, false);
}

ATF_TC_WITHOUT_HEAD(test_resp_keysize_below_min_6);
ATF_TC_BODY(test_resp_keysize_below_min_6, tc)
{
	run_keysize_case(BT_CORE63_SMP_MIN_KEY_SIZE - 1, true);
}

ATF_TC_WITHOUT_HEAD(test_resp_keysize_above_max_17);
ATF_TC_BODY(test_resp_keysize_above_max_17, tc)
{
	run_keysize_case(BT_CORE63_SMP_MAX_KEY_SIZE + 1, true);
}

/* ================================================================
 * IO-capability -> pairing-model selection (smp_select_model),
 * including invalid IO-cap values.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_select_model_invalid_iocap);
ATF_TC_BODY(test_select_model_invalid_iocap, tc)
{
	static const int legacy[5][5] = {
		BT_CORE63_SMP_ASSOC_LEGACY_MATRIX
	};
	static const int secure_connections[5][5] = {
		BT_CORE63_SMP_ASSOC_SC_MATRIX
	};
	unsigned int initiator, responder, reserved;

	/* Core Table 2.8: all 25 valid role combinations in both modes. */
	for (initiator = 0; initiator < 5; initiator++) {
		for (responder = 0; responder < 5; responder++) {
			ATF_CHECK_EQ(smp_select_model((uint8_t)initiator,
			    (uint8_t)responder, false),
			    legacy[responder][initiator]);
			ATF_CHECK_EQ(smp_select_model((uint8_t)initiator,
			    (uint8_t)responder, true),
			    secure_connections[responder][initiator]);
		}
	}

	/* Core Table 3.4: every reserved octet, both roles and both modes. */
	for (reserved = BT_CORE63_SMP_IO_RESERVED_FIRST;
	    reserved <= BT_CORE63_SMP_IO_RESERVED_LAST; reserved++) {
		ATF_CHECK_EQ(smp_select_model((uint8_t)reserved,
		    BTNG_SMP_IO_DISPLAY_ONLY, false), BTNG_SMP_MODEL_INVALID);
		ATF_CHECK_EQ(smp_select_model((uint8_t)reserved,
		    BTNG_SMP_IO_DISPLAY_ONLY, true), BTNG_SMP_MODEL_INVALID);
		ATF_CHECK_EQ(smp_select_model(BTNG_SMP_IO_DISPLAY_ONLY,
		    (uint8_t)reserved, false), BTNG_SMP_MODEL_INVALID);
		ATF_CHECK_EQ(smp_select_model(BTNG_SMP_IO_DISPLAY_ONLY,
		    (uint8_t)reserved, true), BTNG_SMP_MODEL_INVALID);
	}
}

/* ================================================================
 * Invalid peer IO capability in a real Pairing Request (MITM set so
 * model selection is actually exercised) -> responder rejects.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_resp_invalid_iocap_wire);
ATF_TC_BODY(test_resp_invalid_iocap_wire, tc)
{
	const uint8_t failed[2] = { BTNG_SMP_PAIRING_FAILED,
	    BTNG_SMP_ERR_INVALID_PARAMETERS };
	unsigned int reserved;

	/* Advance beyond the local 60-second pressure window per transcript. */
	smp_clock_hook = negative_clock_hook;
	for (reserved = BT_CORE63_SMP_IO_RESERVED_FIRST;
	    reserved <= BT_CORE63_SMP_IO_RESERVED_LAST; reserved++) {
		struct smp_conn sc;
		struct smp_bond_db db;
		int smp_fds[2], hci_fds[2];
		uint8_t req[7], peer_addr[6];
		int saved_errno;

		negative_vclock = (uint64_t)reserved *
		    (BT_SMP_IMPL_RATE_LIMIT_BASE_SECONDS + 1u);
		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0,
		    smp_fds) == 0);
		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0,
		    hci_fds) == 0);
		memcpy(peer_addr, central_addr, sizeof(peer_addr));
		peer_addr[0] = (uint8_t)reserved; /* isolate local rate keys. */
		setup_sc(&sc, &db, smp_fds, hci_fds,
		    periph_addr, BDADDR_LE_PUBLIC, peer_addr, BDADDR_LE_PUBLIC);

		req[0] = BTNG_SMP_PAIRING_REQUEST; /* §3.3 Table 3.3. */
		req[1] = (uint8_t)reserved;	/* §3.5.1 Table 3.4. */
		req[2] = 0x00;			/* §3.5.1: no OOB data. */
		req[3] = BTNG_SMP_AUTH_BONDING | BTNG_SMP_AUTH_MITM;
		req[4] = BT_CORE63_SMP_MAX_KEY_SIZE;
		req[5] = 0x00;			/* §3.6.1: no initiator keys. */
		req[6] = BTNG_SMP_KEY_DIST_ENC_KEY;
		preload(smp_fds[1], req, sizeof(req));

		ATF_CHECK_EQ(smp_respond(&sc), -1);
		saved_errno = errno;
		ATF_CHECK_EQ_MSG(saved_errno, EPROTO,
		    "reserved IO 0x%02x returned errno %d", reserved,
		    saved_errno);
		expect_default_legacy_pairing_response(smp_fds[1]);
		expect_pdu(smp_fds[1], failed, sizeof(failed));
		expect_no_pdu(smp_fds[1]);
		ATF_CHECK_EQ(db.count, 0);

		close_pair(smp_fds);
		close_pair(hci_fds);
	}
	smp_clock_hook = NULL;
}

/* ================================================================
 * Invalid ECDH public key rejection (smp_validate_public_key).
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(test_validate_public_key);
ATF_TC_BODY(test_validate_public_key, tc)
{
	uint8_t bad_x[32], bad_y[32];
	uint8_t sc_debug_pk_x[32], sc_debug_pk_y[32];
	uint8_t pk_raw[65];
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx;
	size_t pklen = sizeof(pk_raw);

	/* A point that is (almost certainly) not on P-256. */
	memset(bad_x, 0x01, sizeof(bad_x));
	memset(bad_y, 0x02, sizeof(bad_y));
	ATF_CHECK_EQ_MSG(smp_validate_public_key(bad_x, bad_y, NULL), -1,
	    "off-curve key must be rejected");

	/* All-zero coordinates are not on the curve either. */
	memset(bad_x, 0, sizeof(bad_x));
	memset(bad_y, 0, sizeof(bad_y));
	ATF_CHECK_EQ(smp_validate_public_key(bad_x, bad_y, NULL), -1);

	/* The SC Debug Public Key is on-curve but must be rejected. */
	core_hex_be(sc_debug_pk_x, BT_CORE63_SMP_SC_DEBUG_X_HEX,
	    sizeof(sc_debug_pk_x));
	core_hex_be(sc_debug_pk_y, BT_CORE63_SMP_SC_DEBUG_Y_HEX,
	    sizeof(sc_debug_pk_y));
	ATF_CHECK_EQ_MSG(smp_validate_public_key(sc_debug_pk_x, sc_debug_pk_y, NULL),
	    -1, "SC Debug Public Key must be rejected");

	/* A freshly generated, valid P-256 public key must be accepted. */
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	ATF_REQUIRE(pctx != NULL);
	ATF_REQUIRE(EVP_PKEY_keygen_init(pctx) > 0);
	ATF_REQUIRE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
	    NID_X9_62_prime256v1) > 0);
	ATF_REQUIRE(EVP_PKEY_keygen(pctx, &pkey) > 0);
	EVP_PKEY_CTX_free(pctx);
	ATF_REQUIRE(EVP_PKEY_get_octet_string_param(pkey,
	    OSSL_PKEY_PARAM_PUB_KEY, pk_raw, sizeof(pk_raw), &pklen) > 0);
	ATF_REQUIRE_EQ(pklen, 65);	/* 0x04 || X(32) || Y(32) big-endian */
	ATF_REQUIRE_EQ(pk_raw[0], 0x04);

	ATF_CHECK_EQ_MSG(smp_validate_public_key(pk_raw + 1, pk_raw + 33, NULL), 0,
	    "valid on-curve key must be accepted");

	EVP_PKEY_free(pkey);
}

/* ================================================================
 * Peer key-distribution receive with truncated PDUs
 * (smp_receive_peer_keys): assert no over-read and fields left unset.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_receive_peer_keys_truncated);
ATF_TC_BODY(test_receive_peer_keys_truncated, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	struct smp_bond bond;
	int smp_fds[2], hci_fds[2];
	uint8_t full_id_info[17];
	uint8_t short_id_info[10];	/* Identity Information, need >= 17 */
	uint8_t short_id_addr[5];	/* Identity Address Info, need >= 8 */
	uint8_t short_sign_info[9];	/* Signing Information, need >= 17 */
	uint8_t sentinel_addr[6];

	memset(sentinel_addr, 0xEE, sizeof(sentinel_addr));
	memset(full_id_info, 0x5A, sizeof(full_id_info));
	full_id_info[0] = BTNG_SMP_IDENTITY_INFORMATION;
	memset(short_id_info, 0xAA, sizeof(short_id_info));
	short_id_info[0] = BTNG_SMP_IDENTITY_INFORMATION;
	memset(short_id_addr, 0xBB, sizeof(short_id_addr));
	short_id_addr[0] = BTNG_SMP_IDENTITY_ADDRESS_INFO;
	memset(short_sign_info, 0xCC, sizeof(short_sign_info));
	short_sign_info[0] = BTNG_SMP_LEGACY_SIGNING_INFORMATION;

	/* §3.6.4 fixes Identity Information at opcode + 16-octet IRK. */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	memset(&bond, 0, sizeof(bond));
	memcpy(bond.addr, sentinel_addr, sizeof(bond.addr));
	preload(smp_fds[1], short_id_info, sizeof(short_id_info));
	ATF_CHECK_EQ(-1, smp_receive_peer_keys(&sc, &bond,
	    BTNG_SMP_KEY_DIST_ID_KEY, true));
	ATF_CHECK(!bond.has_irk);
	ATF_CHECK(memcmp(bond.addr, sentinel_addr, sizeof(bond.addr)) == 0);
	close_pair(smp_fds);
	close_pair(hci_fds);

	/* §3.6.5: reach the second-stage address length guard with a full IRK. */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	memset(&bond, 0, sizeof(bond));
	memcpy(bond.addr, sentinel_addr, sizeof(bond.addr));
	preload(smp_fds[1], full_id_info, sizeof(full_id_info));
	preload(smp_fds[1], short_id_addr, sizeof(short_id_addr));
	ATF_CHECK_EQ(-1, smp_receive_peer_keys(&sc, &bond,
	    BTNG_SMP_KEY_DIST_ID_KEY, true));
	ATF_CHECK_MSG(!bond.has_irk,
	    "truncated address must roll back the preceding full IRK");
	ATF_CHECK(memcmp(bond.addr, sentinel_addr, sizeof(bond.addr)) == 0);
	close_pair(smp_fds);
	close_pair(hci_fds);

	/* Vol 1 Part E §2.4.2 compatibility: signing PDU is 17 octets. */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	memset(&bond, 0, sizeof(bond));
	memcpy(bond.addr, sentinel_addr, sizeof(bond.addr));
	preload(smp_fds[1], short_sign_info, sizeof(short_sign_info));
	ATF_CHECK_EQ(-1, smp_receive_peer_keys(&sc, &bond,
	    BTNG_SMP_KEY_DIST_LEGACY_SIGN_KEY, true));
	ATF_CHECK(!bond.has_csrk);
	ATF_CHECK(memcmp(bond.addr, sentinel_addr, sizeof(bond.addr)) == 0);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* A lone Identity Information PDU is an incomplete IdKey sequence. */
ATF_TC_WITHOUT_HEAD(test_receive_peer_keys_valid_irk);
ATF_TC_BODY(test_receive_peer_keys_valid_irk, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	struct smp_bond bond, original;
	int smp_fds[2], hci_fds[2];
	uint8_t id_info[17];
	size_t i;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);

	/* §3.6.4 permits any 128-bit IRK; use a nonuniform test fixture. */
	id_info[0] = BTNG_SMP_IDENTITY_INFORMATION;
	for (i = 0; i < 16; i++)
		id_info[i + 1] = (uint8_t)(0xA0u + i);
	preload(smp_fds[1], id_info, sizeof(id_info));
	(void)fcntl(smp_fds[0], F_SETFL, O_NONBLOCK);

	memset(&bond, 0xC3, sizeof(bond));
	bond.has_irk = false;
	original = bond;
	ATF_CHECK_EQ(-1, smp_receive_peer_keys(&sc, &bond,
	    BTNG_SMP_KEY_DIST_ID_KEY, true));

	ATF_CHECK_MSG(memcmp(&bond, &original, sizeof(bond)) == 0,
	    "an incomplete IdKey transaction modified the bond record");

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* ================================================================
 * Initiator (smp_pair) rejection arms.  The DUT drives smp_pair(): it
 * sends its Pairing Request (buffered, unread on the peer side) and then
 * reads the single Pairing Response we preload.  The response we choose
 * steers the DUT into a specific reject arm.  Oracle: Core Spec Vol 3
 * Part H Table 3.7 (Pairing Failed reason codes) and §2.3.4/§3.5.5.
 * ================================================================ */

/* A passkey callback that refuses -> drives the PASSKEY_ENTRY_FAILED arm. */
static int
cb_passkey_reject(uint32_t *out __unused, bool display __unused,
    void *arg __unused)
{

	return (-1);
}

/* Build a Pairing Response with explicit IO/auth/key_size. */
static void
build_pres(uint8_t r[7], uint8_t io, uint8_t auth, uint8_t key_size)
{

	r[0] = BTNG_SMP_PAIRING_RESPONSE;
	r[1] = io;
	r[2] = 0x00;
	r[3] = auth;
	r[4] = key_size;
	r[5] = 0x00;
	r[6] = BTNG_SMP_KEY_DIST_ENC_KEY;
}

/* Peer answers our request with Pairing Failed -> EACCES, no reply. */
ATF_TC_WITHOUT_HEAD(test_pair_peer_pairing_failed);
ATF_TC_BODY(test_pair_peer_pairing_failed, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t fail[2] = { BTNG_SMP_PAIRING_FAILED, BTNG_SMP_ERR_AUTH_REQUIREMENTS };

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);

	preload(smp_fds[1], fail, sizeof(fail));

	ATF_CHECK_EQ(smp_pair(&sc), -1);
	ATF_CHECK_EQ_MSG(errno, EACCES,
	    "peer Pairing Failed must surface as EACCES");
	expect_default_pairing_request(smp_fds[1]);
	expect_no_pdu(smp_fds[1]);
	ATF_CHECK_EQ(db.count, 0);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* Peer answers with an unexpected opcode (not Response/Failed) ->
 * Command Not Supported, EPROTO. */
ATF_TC_WITHOUT_HEAD(test_pair_wrong_opcode_response);
ATF_TC_BODY(test_pair_wrong_opcode_response, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t bogus[7] = { BTNG_SMP_PAIRING_CONFIRM, 0, 0, 0, 0, 0, 0 };

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);

	preload(smp_fds[1], bogus, sizeof(bogus));

	ATF_CHECK_EQ(smp_pair(&sc), -1);
	ATF_CHECK_EQ(errno, EPROTO);
	expect_failure_after_default_request(smp_fds[1],
	    BTNG_SMP_ERR_CMD_NOT_SUPPORTED);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* Peer offers key size 17 (> 16) -> Invalid Parameters, EPROTO. */
ATF_TC_WITHOUT_HEAD(test_pair_keysize_high_17);
ATF_TC_BODY(test_pair_keysize_high_17, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t pres[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);

	build_pres(pres, BTNG_SMP_IO_NO_INPUT_NO_OUTPUT, BTNG_SMP_AUTH_BONDING,
	    BT_CORE63_SMP_MAX_KEY_SIZE + 1);
	preload(smp_fds[1], pres, sizeof(pres));

	ATF_CHECK_EQ(smp_pair(&sc), -1);
	ATF_CHECK_EQ(errno, EPROTO);
	expect_failure_after_default_request(smp_fds[1],
	    BTNG_SMP_ERR_INVALID_PARAMETERS);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* Peer offers key size 6 (< 7) -> Invalid Parameters. */
ATF_TC_WITHOUT_HEAD(test_pair_keysize_low_6);
ATF_TC_BODY(test_pair_keysize_low_6, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t pres[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);

	build_pres(pres, BTNG_SMP_IO_NO_INPUT_NO_OUTPUT, BTNG_SMP_AUTH_BONDING,
	    BT_CORE63_SMP_MIN_KEY_SIZE - 1);
	preload(smp_fds[1], pres, sizeof(pres));

	ATF_CHECK_EQ(smp_pair(&sc), -1);
	ATF_CHECK_EQ(errno, EPROTO);
	expect_failure_after_default_request(smp_fds[1],
	    BTNG_SMP_ERR_INVALID_PARAMETERS);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* SC pairing with a negotiated key size < 16 -> KNOB reject
 * (Encryption Key Size), EACCES.  Erratum 11838. */
ATF_TC_WITHOUT_HEAD(test_pair_sc_knob_reject);
ATF_TC_BODY(test_pair_sc_knob_reject, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t pres[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);

	/* SC on both sides but peer caps key size at 15 -> neg 15 < 16. */
	build_pres(pres, BTNG_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BTNG_SMP_AUTH_BONDING | BTNG_SMP_AUTH_SC,
	    BT_CORE63_SMP_MAX_KEY_SIZE - 1);
	preload(smp_fds[1], pres, sizeof(pres));

	ATF_CHECK_EQ(smp_pair(&sc), -1);
	ATF_CHECK_EQ_MSG(errno, EACCES, "SC KNOB reject must be EACCES");
	expect_failure_after_default_request(smp_fds[1],
	    BTNG_SMP_ERR_ENCRYPTION_KEY_SIZE);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* Legacy negotiated key size below our configured minimum -> reject. */
ATF_TC_WITHOUT_HEAD(test_pair_legacy_keysize_below_min);
ATF_TC_BODY(test_pair_legacy_keysize_below_min, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t pres[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);
	sc.min_key_size = 16;			/* demand full-strength legacy */

	/* Legacy (no SC), key size 10 < 16 -> Encryption Key Size reject. */
	build_pres(pres, BTNG_SMP_IO_NO_INPUT_NO_OUTPUT, BTNG_SMP_AUTH_BONDING, 10);
	preload(smp_fds[1], pres, sizeof(pres));

	ATF_CHECK_EQ(smp_pair(&sc), -1);
	ATF_CHECK_EQ_MSG(errno, EACCES, "legacy key size reject must be EACCES");
	expect_failure_after_default_request(smp_fds[1],
	    BTNG_SMP_ERR_ENCRYPTION_KEY_SIZE);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* sc_only initiator against a peer that does not support SC ->
 * Authentication Requirements, EACCES. */
ATF_TC_WITHOUT_HEAD(test_pair_sc_only_peer_no_sc);
ATF_TC_BODY(test_pair_sc_only_peer_no_sc, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t pres[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);
	sc.sc_only = true;

	/* Peer offers legacy only (no SC bit), valid key size. */
	build_pres(pres, BTNG_SMP_IO_NO_INPUT_NO_OUTPUT, BTNG_SMP_AUTH_BONDING, 16);
	preload(smp_fds[1], pres, sizeof(pres));

	ATF_CHECK_EQ(smp_pair(&sc), -1);
	ATF_CHECK_EQ_MSG(errno, EACCES, "sc_only reject must be EACCES");
	expect_failure_after_default_request(smp_fds[1],
	    BTNG_SMP_ERR_AUTH_REQUIREMENTS);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* Peer sends a reserved IO capability (0x05) with MITM (no SC) -> the
 * association-model lookup returns invalid -> Invalid Parameters, EPROTO. */
ATF_TC_WITHOUT_HEAD(test_pair_invalid_model_iocap);
ATF_TC_BODY(test_pair_invalid_model_iocap, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t pres[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);

	/* MITM (forces model lookup) but reserved IO cap 0x05, no SC. */
	build_pres(pres, BT_CORE63_SMP_IO_RESERVED_FIRST,
	    BTNG_SMP_AUTH_BONDING | BTNG_SMP_AUTH_MITM,
	    BT_CORE63_SMP_MAX_KEY_SIZE);
	preload(smp_fds[1], pres, sizeof(pres));

	ATF_CHECK_EQ(smp_pair(&sc), -1);
	ATF_CHECK_EQ(errno, EPROTO);
	expect_failure_after_default_request(smp_fds[1],
	    BTNG_SMP_ERR_INVALID_PARAMETERS);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* Legacy Passkey Entry where the local passkey callback refuses ->
 * Passkey Entry Failed, ECANCELED. */
ATF_TC_WITHOUT_HEAD(test_pair_legacy_passkey_cb_fail);
ATF_TC_BODY(test_pair_legacy_passkey_cb_fail, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t pres[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);
	sc.io_capability = BTNG_SMP_IO_KEYBOARD_ONLY;	/* we input */
	sc.passkey_cb = cb_passkey_reject;

	/* Peer DisplayOnly + MITM, no SC -> legacy Passkey Entry (Table 2.8). */
	build_pres(pres, BTNG_SMP_IO_DISPLAY_ONLY,
	    BTNG_SMP_AUTH_BONDING | BTNG_SMP_AUTH_MITM,
	    BT_CORE63_SMP_MAX_KEY_SIZE);
	preload(smp_fds[1], pres, sizeof(pres));

	ATF_CHECK_EQ(smp_pair(&sc), -1);
	ATF_CHECK_EQ(errno, ECANCELED);
	expect_pairing_request(smp_fds[1], BTNG_SMP_IO_KEYBOARD_ONLY);
	{
		const uint8_t failed[2] = { BTNG_SMP_PAIRING_FAILED,
		    BTNG_SMP_ERR_PASSKEY_ENTRY_FAILED };
		expect_pdu(smp_fds[1], failed, sizeof(failed));
	}
	expect_no_pdu(smp_fds[1]);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* ================================================================
 * Responder (smp_respond) rejection arms mirroring the initiator set.
 * The peer preloads a Pairing Request (or Security Request); the DUT reads
 * it, emits its Pairing Response, then hits the selected reject arm.
 * ================================================================ */

/* Build a Pairing Request with explicit IO/auth/key_size. */
static void
build_req(uint8_t r[7], uint8_t io, uint8_t auth, uint8_t key_size)
{

	r[0] = BTNG_SMP_PAIRING_REQUEST;
	r[1] = io;
	r[2] = 0x00;
	r[3] = auth;
	r[4] = key_size;
	r[5] = 0x00;
	r[6] = BTNG_SMP_KEY_DIST_ENC_KEY;
}

/* A 2-octet Security Request tells the responder to become central: EAGAIN. */
ATF_TC_WITHOUT_HEAD(test_resp_security_request);
ATF_TC_BODY(test_resp_security_request, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t secreq[2] = { BTNG_SMP_SECURITY_REQUEST, BTNG_SMP_AUTH_BONDING };

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);

	preload(smp_fds[1], secreq, sizeof(secreq));

	ATF_CHECK_EQ(smp_respond(&sc), -1);
	ATF_CHECK_EQ_MSG(errno, EAGAIN,
	    "Security Request must ask the caller to initiate (EAGAIN)");
	expect_no_pdu(smp_fds[1]);
	ATF_CHECK_EQ(db.count, 0);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* Responder SC with a negotiated key size < 16 -> KNOB reject. */
ATF_TC_WITHOUT_HEAD(test_resp_sc_knob_reject);
ATF_TC_BODY(test_resp_sc_knob_reject, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t req[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);

	build_req(req, BTNG_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BTNG_SMP_AUTH_BONDING | BTNG_SMP_AUTH_SC,
	    BT_CORE63_SMP_MAX_KEY_SIZE - 1);
	preload(smp_fds[1], req, sizeof(req));

	ATF_CHECK_EQ(smp_respond(&sc), -1);
	ATF_CHECK_EQ_MSG(errno, EACCES, "SC KNOB reject must be EACCES");
	expect_failure_after_response(smp_fds[1],
	    BTNG_SMP_IO_NO_INPUT_NO_OUTPUT, true,
	    BTNG_SMP_ERR_ENCRYPTION_KEY_SIZE);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* Responder legacy negotiated key size below configured minimum -> reject. */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_keysize_below_min);
ATF_TC_BODY(test_resp_legacy_keysize_below_min, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t req[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	sc.min_key_size = BT_CORE63_SMP_MAX_KEY_SIZE;

	build_req(req, BTNG_SMP_IO_NO_INPUT_NO_OUTPUT, BTNG_SMP_AUTH_BONDING, 10);
	preload(smp_fds[1], req, sizeof(req));

	ATF_CHECK_EQ(smp_respond(&sc), -1);
	ATF_CHECK_EQ_MSG(errno, EACCES, "legacy key size reject must be EACCES");
	expect_failure_after_response(smp_fds[1],
	    BTNG_SMP_IO_NO_INPUT_NO_OUTPUT, false,
	    BTNG_SMP_ERR_ENCRYPTION_KEY_SIZE);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* sc_only responder against a non-SC initiator -> Authentication Reqs. */
ATF_TC_WITHOUT_HEAD(test_resp_sc_only_peer_no_sc);
ATF_TC_BODY(test_resp_sc_only_peer_no_sc, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t req[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	sc.sc_only = true;

	build_req(req, BTNG_SMP_IO_NO_INPUT_NO_OUTPUT, BTNG_SMP_AUTH_BONDING,
	    BT_CORE63_SMP_MAX_KEY_SIZE);
	preload(smp_fds[1], req, sizeof(req));

	ATF_CHECK_EQ(smp_respond(&sc), -1);
	ATF_CHECK_EQ_MSG(errno, EACCES, "sc_only reject must be EACCES");
	expect_failure_after_response(smp_fds[1],
	    BTNG_SMP_IO_NO_INPUT_NO_OUTPUT, false,
	    BTNG_SMP_ERR_AUTH_REQUIREMENTS);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* Responder legacy Passkey Entry with no passkey callback -> Not Supported. */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_passkey_no_cb);
ATF_TC_BODY(test_resp_legacy_passkey_no_cb, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t req[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	sc.io_capability = BTNG_SMP_IO_DISPLAY_ONLY;	/* we display */
	sc.passkey_cb = NULL;

	/* Initiator KeyboardOnly + MITM, no SC -> legacy Passkey Entry. */
	build_req(req, BTNG_SMP_IO_KEYBOARD_ONLY,
	    BTNG_SMP_AUTH_BONDING | BTNG_SMP_AUTH_MITM, 16);
	preload(smp_fds[1], req, sizeof(req));

	ATF_CHECK_EQ(smp_respond(&sc), -1);
	ATF_CHECK_EQ(errno, ENOTSUP);
	expect_failure_after_response(smp_fds[1], BTNG_SMP_IO_DISPLAY_ONLY,
	    false, BTNG_SMP_ERR_PAIRING_NOT_SUPPORTED);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* Responder legacy Passkey Entry where the callback refuses -> Passkey Failed. */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_passkey_cb_fail);
ATF_TC_BODY(test_resp_legacy_passkey_cb_fail, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t req[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	sc.io_capability = BTNG_SMP_IO_DISPLAY_ONLY;
	sc.passkey_cb = cb_passkey_reject;

	build_req(req, BTNG_SMP_IO_KEYBOARD_ONLY,
	    BTNG_SMP_AUTH_BONDING | BTNG_SMP_AUTH_MITM, 16);
	preload(smp_fds[1], req, sizeof(req));

	ATF_CHECK_EQ(smp_respond(&sc), -1);
	ATF_CHECK_EQ(errno, ECANCELED);
	expect_failure_after_response(smp_fds[1], BTNG_SMP_IO_DISPLAY_ONLY,
	    false, BTNG_SMP_ERR_PASSKEY_ENTRY_FAILED);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* Four rapid attempts from one address trip the per-address rate limiter
 * with Repeated Attempts on the fourth. */
ATF_TC_WITHOUT_HEAD(test_resp_rate_limited_repeated);
ATF_TC_BODY(test_resp_rate_limited_repeated, tc)
{
	struct smp_bond_db db;
	uint8_t req[7];
	unsigned int attempt;

	build_req(req, BTNG_SMP_IO_NO_INPUT_NO_OUTPUT, BTNG_SMP_AUTH_BONDING,
	    BT_CORE63_SMP_MAX_KEY_SIZE);
	negative_vclock = 5000;
	smp_clock_hook = negative_clock_hook;

	for (attempt = 1;
	    attempt <= BT_SMP_IMPL_RATE_LIMIT_FIRST_REJECTED; attempt++) {
		struct smp_conn sc;
		int smp_fds[2], hci_fds[2];
		int rc, saved_errno;

		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
		setup_sc(&sc, &db, smp_fds, hci_fds,
		    periph_addr, BDADDR_LE_PUBLIC,
		    central_addr, BDADDR_LE_PUBLIC);
		/* Non-blocking: accepted attempts unwind quickly at recv. */
		(void)fcntl(smp_fds[0], F_SETFL, O_NONBLOCK);

		preload(smp_fds[1], req, sizeof(req));
		rc = smp_respond(&sc);
		saved_errno = errno;
		ATF_CHECK_EQ(rc, -1);
		if (attempt <= BT_SMP_IMPL_RATE_LIMIT_ADMITTED) {
			ATF_CHECK_EQ_MSG(saved_errno, EPROTO,
			    "admitted attempt %u returned errno %d", attempt,
			    saved_errno);
			expect_default_legacy_pairing_response(smp_fds[1]);
			expect_no_pdu(smp_fds[1]);
		} else {
			const uint8_t failed[2] = { BTNG_SMP_PAIRING_FAILED,
			    BTNG_SMP_ERR_REPEATED_ATTEMPTS };

			ATF_CHECK_EQ_MSG(saved_errno, EACCES,
			    "first rejected attempt %u returned errno %d", attempt,
			    saved_errno);
			expect_pdu(smp_fds[1], failed, sizeof(failed));
			expect_no_pdu(smp_fds[1]);
		}
		ATF_CHECK_EQ(db.count, 0);

		close_pair(smp_fds);
		close_pair(hci_fds);
	}
	smp_clock_hook = NULL;
}

/* ================================================================
 * LE Secure Connections Passkey Entry: callback-absent / callback-refused
 * arms on both roles.  These fire before (no-cb) or just after (cb refused)
 * the local passkey prompt, so no ECDH mock peer is needed.  Oracle: Core
 * Spec Vol 3 Part H §2.3.5.6.3 and Table 3.7.
 * ================================================================ */
static int
cb_passkey_ok(uint32_t *out, bool display __unused, void *arg __unused)
{

	*out = 123456;
	return (0);
}

/* Initiator selects SC Passkey but has no passkey callback -> Not Supported. */
ATF_TC_WITHOUT_HEAD(test_pair_sc_passkey_no_cb);
ATF_TC_BODY(test_pair_sc_passkey_no_cb, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t pres[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);
	sc.io_capability = BTNG_SMP_IO_DISPLAY_ONLY;
	sc.passkey_cb = NULL;

	/* Peer: KeyboardOnly + SC + MITM -> SC Passkey Entry (Table 2.8). */
	build_pres(pres, BTNG_SMP_IO_KEYBOARD_ONLY,
	    BTNG_SMP_AUTH_BONDING | BTNG_SMP_AUTH_MITM | BTNG_SMP_AUTH_SC, 16);
	preload(smp_fds[1], pres, sizeof(pres));

	ATF_CHECK_EQ(smp_pair(&sc), -1);
	ATF_CHECK_EQ_MSG(errno, ENOTSUP, "SC passkey no-cb must be ENOTSUP");
	expect_pairing_request(smp_fds[1], BTNG_SMP_IO_DISPLAY_ONLY);
	{
		const uint8_t failed[2] = { BTNG_SMP_PAIRING_FAILED,
		    BTNG_SMP_ERR_PAIRING_NOT_SUPPORTED };
		expect_pdu(smp_fds[1], failed, sizeof(failed));
	}
	expect_no_pdu(smp_fds[1]);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* Initiator SC Passkey callback refuses -> Passkey Entry Failed. */
ATF_TC_WITHOUT_HEAD(test_pair_sc_passkey_cb_fail);
ATF_TC_BODY(test_pair_sc_passkey_cb_fail, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t pres[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);
	sc.io_capability = BTNG_SMP_IO_DISPLAY_ONLY;
	sc.passkey_cb = cb_passkey_reject;

	build_pres(pres, BTNG_SMP_IO_KEYBOARD_ONLY,
	    BTNG_SMP_AUTH_BONDING | BTNG_SMP_AUTH_MITM | BTNG_SMP_AUTH_SC, 16);
	preload(smp_fds[1], pres, sizeof(pres));

	ATF_CHECK_EQ(smp_pair(&sc), -1);
	ATF_CHECK_EQ(errno, ECANCELED);
	expect_pairing_request(smp_fds[1], BTNG_SMP_IO_DISPLAY_ONLY);
	{
		const uint8_t failed[2] = { BTNG_SMP_PAIRING_FAILED,
		    BTNG_SMP_ERR_PASSKEY_ENTRY_FAILED };
		expect_pdu(smp_fds[1], failed, sizeof(failed));
	}
	expect_no_pdu(smp_fds[1]);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* Initiator SC Passkey: peer replies to our Public Key with a short/garbled
 * PDU -> EPROTO. */
ATF_TC_WITHOUT_HEAD(test_pair_sc_passkey_bad_peer_pk);
ATF_TC_BODY(test_pair_sc_passkey_bad_peer_pk, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t pres[7];
	uint8_t short_pk[10] = { BTNG_SMP_PAIRING_PUBLIC_KEY, 0 };

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);
	sc.io_capability = BTNG_SMP_IO_DISPLAY_ONLY;
	sc.passkey_cb = cb_passkey_ok;

	build_pres(pres, BTNG_SMP_IO_KEYBOARD_ONLY,
	    BTNG_SMP_AUTH_BONDING | BTNG_SMP_AUTH_MITM | BTNG_SMP_AUTH_SC, 16);
	preload(smp_fds[1], pres, sizeof(pres));
	/* After the DUT emits its Public Key, feed a truncated PK reply. */
	preload(smp_fds[1], short_pk, sizeof(short_pk));

	ATF_CHECK_EQ(smp_pair(&sc), -1);
	ATF_CHECK_EQ_MSG(errno, EPROTO,
	    "truncated peer Public Key must be EPROTO");
	expect_pairing_request(smp_fds[1], BTNG_SMP_IO_DISPLAY_ONLY);
	expect_pdu_shape(smp_fds[1], BTNG_SMP_PAIRING_PUBLIC_KEY, 65);
	{
		const uint8_t failed[2] = { BTNG_SMP_PAIRING_FAILED,
		    BTNG_SMP_ERR_INVALID_PARAMETERS };
		expect_pdu(smp_fds[1], failed, sizeof(failed));
	}
	expect_no_pdu(smp_fds[1]);
	ATF_CHECK_EQ(db.count, 0);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* Responder selects SC Passkey but has no passkey callback -> Not Supported. */
ATF_TC_WITHOUT_HEAD(test_resp_sc_passkey_no_cb);
ATF_TC_BODY(test_resp_sc_passkey_no_cb, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t req[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	sc.io_capability = BTNG_SMP_IO_DISPLAY_ONLY;	/* we display */
	sc.passkey_cb = NULL;

	/* Peer request: KeyboardOnly + SC + MITM -> SC Passkey (Table 2.8). */
	req[0] = BTNG_SMP_PAIRING_REQUEST;
	req[1] = BTNG_SMP_IO_KEYBOARD_ONLY;
	req[2] = 0x00;
	req[3] = BTNG_SMP_AUTH_BONDING | BTNG_SMP_AUTH_MITM | BTNG_SMP_AUTH_SC;
	req[4] = 16;
	req[5] = 0x00;
	req[6] = BTNG_SMP_KEY_DIST_ENC_KEY;
	preload(smp_fds[1], req, sizeof(req));

	ATF_CHECK_EQ(smp_respond(&sc), -1);
	ATF_CHECK_EQ(errno, ENOTSUP);
	expect_failure_after_response(smp_fds[1], BTNG_SMP_IO_DISPLAY_ONLY,
	    true, BTNG_SMP_ERR_PAIRING_NOT_SUPPORTED);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* Responder SC Passkey callback refuses -> Passkey Entry Failed. */
ATF_TC_WITHOUT_HEAD(test_resp_sc_passkey_cb_fail);
ATF_TC_BODY(test_resp_sc_passkey_cb_fail, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t req[7];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup_sc(&sc, &db, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	sc.io_capability = BTNG_SMP_IO_DISPLAY_ONLY;
	sc.passkey_cb = cb_passkey_reject;

	req[0] = BTNG_SMP_PAIRING_REQUEST;
	req[1] = BTNG_SMP_IO_KEYBOARD_ONLY;
	req[2] = 0x00;
	req[3] = BTNG_SMP_AUTH_BONDING | BTNG_SMP_AUTH_MITM | BTNG_SMP_AUTH_SC;
	req[4] = 16;
	req[5] = 0x00;
	req[6] = BTNG_SMP_KEY_DIST_ENC_KEY;
	preload(smp_fds[1], req, sizeof(req));

	ATF_CHECK_EQ(smp_respond(&sc), -1);
	ATF_CHECK_EQ(errno, ECANCELED);
	expect_failure_after_response(smp_fds[1], BTNG_SMP_IO_DISPLAY_ONLY,
	    true, BTNG_SMP_ERR_PASSKEY_ENTRY_FAILED);

	close_pair(smp_fds);
	close_pair(hci_fds);
}

/* smp_open returns promptly and preserves defaults when socket setup fails. */
ATF_TC_WITHOUT_HEAD(test_smp_open_no_stack_fails);
ATF_TC_BODY(test_smp_open_no_stack_fails, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int rc;

	memset(&db, 0, sizeof(db));
	db.fd = -1;
	rc = smp_open(&sc, periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC, -1, 0x0040, &db);
	ATF_CHECK_EQ_MSG(-1, rc, "injected Bluetooth socket failure must fail");
	ATF_CHECK_EQ_MSG(EAFNOSUPPORT, errno,
	    "injected Bluetooth socket failure errno must be preserved");
	ATF_CHECK_EQ_MSG(BT_CORE63_SMP_MAX_KEY_SIZE, sc.min_key_size,
	    "smp_open must default min_key_size to 16 (KNOB mitigation)");
	ATF_CHECK_EQ_MSG(0x0040, sc.con_handle,
	    "smp_open must set con_handle from its argument");
	ATF_CHECK_EQ_MSG(-1, sc.fd, "failed smp_open must leave fd == -1");
}

/* ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_smp_open_no_stack_fails);
	ATF_TP_ADD_TC(tp, test_resp_security_request);
	ATF_TP_ADD_TC(tp, test_resp_sc_knob_reject);
	ATF_TP_ADD_TC(tp, test_resp_legacy_keysize_below_min);
	ATF_TP_ADD_TC(tp, test_resp_sc_only_peer_no_sc);
	ATF_TP_ADD_TC(tp, test_resp_legacy_passkey_no_cb);
	ATF_TP_ADD_TC(tp, test_resp_legacy_passkey_cb_fail);
	ATF_TP_ADD_TC(tp, test_resp_rate_limited_repeated);
	ATF_TP_ADD_TC(tp, test_pair_sc_passkey_no_cb);
	ATF_TP_ADD_TC(tp, test_pair_sc_passkey_cb_fail);
	ATF_TP_ADD_TC(tp, test_pair_sc_passkey_bad_peer_pk);
	ATF_TP_ADD_TC(tp, test_resp_sc_passkey_no_cb);
	ATF_TP_ADD_TC(tp, test_resp_sc_passkey_cb_fail);
	ATF_TP_ADD_TC(tp, test_pair_peer_pairing_failed);
	ATF_TP_ADD_TC(tp, test_pair_wrong_opcode_response);
	ATF_TP_ADD_TC(tp, test_pair_keysize_high_17);
	ATF_TP_ADD_TC(tp, test_pair_keysize_low_6);
	ATF_TP_ADD_TC(tp, test_pair_sc_knob_reject);
	ATF_TP_ADD_TC(tp, test_pair_legacy_keysize_below_min);
	ATF_TP_ADD_TC(tp, test_pair_sc_only_peer_no_sc);
	ATF_TP_ADD_TC(tp, test_pair_invalid_model_iocap);
	ATF_TP_ADD_TC(tp, test_pair_legacy_passkey_cb_fail);
	ATF_TP_ADD_TC(tp, test_resp_short_request);
	ATF_TP_ADD_TC(tp, test_pair_short_response);
	ATF_TP_ADD_TC(tp, test_resp_short_confirm);
	ATF_TP_ADD_TC(tp, test_resp_short_random);
	ATF_TP_ADD_TC(tp, test_resp_unknown_opcode);
	ATF_TP_ADD_TC(tp, test_resp_pairing_failed_midflow);
	ATF_TP_ADD_TC(tp, test_resp_out_of_sequence_confirm);
	ATF_TP_ADD_TC(tp, test_pair_legacy_passkey_no_cb_fails);
	ATF_TP_ADD_TC(tp, test_resp_keysize_min_7);
	ATF_TP_ADD_TC(tp, test_resp_keysize_max_16);
	ATF_TP_ADD_TC(tp, test_resp_keysize_below_min_6);
	ATF_TP_ADD_TC(tp, test_resp_keysize_above_max_17);
	ATF_TP_ADD_TC(tp, test_select_model_invalid_iocap);
	ATF_TP_ADD_TC(tp, test_resp_invalid_iocap_wire);
	ATF_TP_ADD_TC(tp, test_validate_public_key);
	ATF_TP_ADD_TC(tp, test_receive_peer_keys_truncated);
	ATF_TP_ADD_TC(tp, test_receive_peer_keys_valid_irk);

	return (atf_no_error());
}
