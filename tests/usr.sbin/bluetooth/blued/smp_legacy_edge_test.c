/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF edge tests for the SMP state machine (smp.c) and the LE Legacy
 * responder (smp_legacy.c).
 *
 * These reach branches the happy-path and negative tests do not:
 *   - smp_respond() Security Request handling (-> EAGAIN),
 *   - smp_respond() SC-only rejection of a non-SC initiator,
 *   - the per-address pairing rate limiter (-> Repeated Attempts),
 *   - smp_encrypt_with_ltk() with and without a stored LTK,
 *   - a full LE Legacy Just Works responder exchange, including responder
 *     key distribution (Enc/Id/Sign) and receipt of the initiator's keys.
 *
 * The rate-limit table in smp.c is file-static and process-global; because
 * each ATF test case runs in its own process it starts fresh, so a single
 * case can drive the limiter to its threshold deterministically.
 *
 * Oracle: message ordering, failure reasons and the c1/s1 confirm math come
 * from the Core Spec (Vol 3 Part H, legacy pairing Section 2.3.5.5, state
 * machine Section 3.4/3.5.7), cited per case.
 *
 * Links with: smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
 * Extra libs: -lcrypto -lpthread
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "hci_log.h"
#include "hci_util.h"
#include "smp.h"
#include "smp_internal.h"
#include "spec_hci_emulator_enc_oracles.h"
#include "spec_smp_deep_misc_oracles.h"

#define TEST_LINKS_SMP
#include "test_common.h"

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif
#ifndef BDADDR_LE_RANDOM
#define BDADDR_LE_RANDOM	2
#endif

/* ================================================================
 * Stubs.  hci_send_raw_cmd echoes onto the hci socket so the caller can
 * confirm a command was issued (used by smp_encrypt_with_ltk).
 * ================================================================ */
int
hci_send_raw_cmd(int hci_fd, uint16_t opcode, const void *params, uint8_t plen)
{
	uint8_t buf[260];

	buf[0] = 0x01;
	buf[1] = (uint8_t)(opcode & 0xFF);
	buf[2] = (uint8_t)(opcode >> 8);
	buf[3] = plen;
	if (plen > 0 && params != NULL)
		memcpy(buf + 4, params, plen);
	return ((int)send(hci_fd, buf, 4 + plen, MSG_NOSIGNAL));
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

static const uint8_t central_addr[6] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
static const uint8_t periph_addr[6]  = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };

static void
assert_smp_legacy_edge_contract(void)
{

	ATF_CHECK_EQ(SMP_SECURITY_REQUEST, BT_CORE63_SMP_SECURITY_REQUEST);
	ATF_CHECK_EQ(SMP_PAIRING_REQUEST, BT_CORE63_SMP_PAIRING_REQUEST);
	ATF_CHECK_EQ(SMP_PAIRING_RESPONSE, BT_CORE63_SMP_PAIRING_RESPONSE);
	ATF_CHECK_EQ(SMP_PAIRING_CONFIRM, BT_CORE63_SMP_PAIRING_CONFIRM);
	ATF_CHECK_EQ(SMP_PAIRING_RANDOM, BT_CORE63_SMP_PAIRING_RANDOM);
	ATF_CHECK_EQ(SMP_PAIRING_FAILED, BT_CORE63_SMP_PAIRING_FAILED);
	ATF_CHECK_EQ(SMP_ENCRYPTION_INFORMATION,
	    BT_CORE63_SMP_ENCRYPTION_INFORMATION);
	ATF_CHECK_EQ(SMP_CENTRAL_IDENTIFICATION,
	    BT_CORE63_SMP_CENTRAL_IDENTIFICATION);
	ATF_CHECK_EQ(SMP_IDENTITY_INFORMATION,
	    BT_CORE63_SMP_IDENTITY_INFORMATION);
	ATF_CHECK_EQ(SMP_IDENTITY_ADDRESS_INFO,
	    BT_CORE63_SMP_IDENTITY_ADDRESS_INFO);
	ATF_CHECK_EQ(SMP_AUTH_SC, BT_CORE63_SMP_AUTH_SC);
	ATF_CHECK_EQ(SMP_KEY_DIST_ENC_KEY, BT_CORE63_SMP_KEY_DIST_ENC_KEY);
	ATF_CHECK_EQ(SMP_KEY_DIST_ID_KEY, BT_CORE63_SMP_KEY_DIST_ID_KEY);
	ATF_CHECK_EQ(SMP_ERR_AUTH_REQUIREMENTS,
	    BT_CORE63_SMP_ERR_AUTH_REQUIREMENTS);
	ATF_CHECK_EQ(SMP_ERR_REPEATED_ATTEMPTS,
	    BT_CORE63_SMP_ERR_REPEATED_ATTEMPTS);
	ATF_CHECK_EQ(HCI_OP_LE_START_ENCRYPTION,
	    BT_CORE63_HCI_OP_LE_ENABLE_ENCRYPTION);
}

static void
setup(struct smp_conn *sc, struct smp_bond_db *db, int bond_fd,
    int smp_fds[2], int hci_fds[2],
    const uint8_t *local, uint8_t ltype,
    const uint8_t *remote, uint8_t rtype)
{

	signal(SIGPIPE, SIG_IGN);
	memset(db, 0, sizeof(*db));
	db->fd = bond_fd;
	memset(sc, 0, sizeof(*sc));
	smp_seed_policy_defaults(sc);
	sc->fd = smp_fds[0];
	sc->hci_fd = hci_fds[0];
	sc->con_handle = 0x0040;
	memcpy(sc->local_addr, local, 6);
	sc->local_addr_type = ltype;
	memcpy(sc->remote_addr, remote, 6);
	sc->remote_addr_type = rtype;
	sc->bond_db = db;
	sc->io_capability = SMP_IO_NO_INPUT_NO_OUTPUT;
	sc->min_key_size = BT_CORE63_SMP_MIN_ENCRYPTION_KEY_SIZE;
	{
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
		setsockopt(smp_fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
}

static bool
drain_for_failed(int peer_fd, uint8_t reason)
{
	uint8_t buf[64];
	ssize_t n;
	bool found = false;

	(void)fcntl(peer_fd, F_SETFL, O_NONBLOCK);
	while ((n = recv(peer_fd, buf, sizeof(buf), 0)) > 0)
		if (n >= BT_CORE63_SMP_PAIRING_FAILED_PDU_SIZE &&
		    buf[0] == BT_CORE63_SMP_PAIRING_FAILED && buf[1] == reason)
			found = true;
	return (found);
}

/* ================================================================
 * smp_encrypt_with_ltk: no LTK -> ENOENT; with LTK -> issues the HCI
 * LE_Start_Encryption command.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_encrypt_with_ltk);
ATF_TC_BODY(test_encrypt_with_ltk, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	struct smp_bond bond;
	uint8_t buf[64];
	uint8_t rand_bytes[8];
	ssize_t n;

	assert_smp_legacy_edge_contract();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds, periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC);

	memset(&bond, 0, sizeof(bond));
	bond.has_ltk = false;
	ATF_CHECK_EQ(smp_encrypt_with_ltk(&sc, &bond), -1);
	ATF_CHECK_EQ_MSG(errno, ENOENT, "no LTK -> ENOENT");

	memset(bond.ltk, 0x7e, sizeof(bond.ltk));
	memset(&bond.rand, 0x3c, sizeof(bond.rand));
	memcpy(rand_bytes, &bond.rand, sizeof(rand_bytes));
	bond.has_ltk = true;
	bond.ediv = 0x1234;
	ATF_CHECK_EQ(smp_encrypt_with_ltk(&sc, &bond), 0);

	/* The HCI command must have been written to the hci socket. */
	n = recv(hci_fds[1], buf, sizeof(buf), 0);
	ATF_REQUIRE_EQ(n, 4 + BT_CORE63_HCI_LE_ENABLE_ENCRYPTION_PARAM_SIZE);
	ATF_CHECK_EQ(buf[0], BT_CORE63_HCI_COMMAND_PACKET);
	ATF_CHECK_EQ(le16dec(buf + 1), BT_CORE63_HCI_OP_LE_ENABLE_ENCRYPTION);
	ATF_CHECK_EQ(buf[3], BT_CORE63_HCI_LE_ENABLE_ENCRYPTION_PARAM_SIZE);
	ATF_CHECK_EQ(le16dec(buf + 4), sc.con_handle);
	ATF_CHECK(memcmp(buf + 6, rand_bytes, sizeof(rand_bytes)) == 0);
	ATF_CHECK_EQ(le16dec(buf + 14), bond.ediv);
	ATF_CHECK(memcmp(buf + 16, bond.ltk, sizeof(bond.ltk)) == 0);

	close(smp_fds[0]); close(smp_fds[1]);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* ================================================================
 * smp_respond: a Security Request (0x0B) as the first PDU is not a Pairing
 * Request; the responder returns EAGAIN (the central should initiate).
 * Core Spec Vol 3 Part H Section 3.5.7 / 2.4.6.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_respond_security_request);
ATF_TC_BODY(test_respond_security_request, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	/*
	 * A Security Request is a well-formed 2-octet PDU (Code | AuthReq,
	 * Vol 3 Part H §3.6.7).  Regression guard: smp_respond() must dispatch
	 * on the opcode before enforcing the 7-octet Pairing Request length, so
	 * the full 2-byte PDU yields EAGAIN (caller initiates as central), not
	 * EPROTO.  (Previously the n < 7 gate dropped it as a protocol error.)
	 */
	uint8_t secreq[BT_CORE63_SMP_SECURITY_REQUEST_PDU_SIZE] = {
	    BT_CORE63_SMP_SECURITY_REQUEST, BT_CORE63_SMP_AUTH_BONDING };

	assert_smp_legacy_edge_contract();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds, periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC);

	ATF_REQUIRE(send(smp_fds[1], secreq, sizeof(secreq), MSG_EOR) == 2);
	ATF_CHECK_EQ(smp_respond(&sc), -1);
	ATF_CHECK_EQ_MSG(errno, EAGAIN,
	    "2-byte Security Request must yield EAGAIN, not a protocol error");

	close(smp_fds[0]); close(smp_fds[1]);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* ================================================================
 * smp_respond: SC-only mode rejects a peer that does not advertise SC with
 * Authentication Requirements.  Core Spec Vol 3 Part H Section 2.3.5.1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_respond_sc_only_rejects_legacy);
ATF_TC_BODY(test_respond_sc_only_rejects_legacy, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t req[7];

	assert_smp_legacy_edge_contract();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds, periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC);
	sc.sc_only = true;

	req[0] = BT_CORE63_SMP_PAIRING_REQUEST;
	req[1] = BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT;
	req[2] = BT_CORE63_SMP_OOB_NOT_PRESENT;
	req[3] = BT_CORE63_SMP_AUTH_BONDING;	/* no SC bit */
	req[4] = BT_CORE63_SMP_MAX_ENCRYPTION_KEY_SIZE;
	req[5] = 0x00;
	req[6] = BT_CORE63_SMP_KEY_DIST_ENC_KEY;
	ATF_REQUIRE(send(smp_fds[1], req, sizeof(req), MSG_EOR) == 7);

	ATF_CHECK_EQ(smp_respond(&sc), -1);
	ATF_CHECK_EQ(errno, EACCES);
	ATF_CHECK_MSG(drain_for_failed(smp_fds[1],
	    BT_CORE63_SMP_ERR_AUTH_REQUIREMENTS),
	    "SC-only must reject with Authentication Requirements");

	close(smp_fds[0]); close(smp_fds[1]);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* ================================================================
 * Pairing rate limiter: repeated attempts from the same address are
 * eventually rejected with Repeated Attempts.  Core Spec Vol 3 Part H
 * Section 3.4.  SMP_RATE_LIMIT_MAX is 3, so the 4th attempt is limited.
 *
 * Each attempt uses an out-of-range key size so the responder returns
 * quickly (after the rate check) rather than blocking on the confirm.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_respond_rate_limit_repeated);
ATF_TC_BODY(test_respond_rate_limit_repeated, tc)
{
	int i;
	bool limited = false;

	assert_smp_legacy_edge_contract();
	for (i = 0; i < 6; i++) {
		struct smp_conn sc;
		struct smp_bond_db db;
		int smp_fds[2], hci_fds[2];
		uint8_t req[7];

		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
		setup(&sc, &db, -1, smp_fds, hci_fds,
		    periph_addr, BDADDR_LE_PUBLIC,
		    central_addr, BDADDR_LE_PUBLIC);

		req[0] = BT_CORE63_SMP_PAIRING_REQUEST;
		req[1] = BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT;
		req[2] = BT_CORE63_SMP_OOB_NOT_PRESENT;
		req[3] = BT_CORE63_SMP_AUTH_BONDING;
		req[4] = BT_CORE63_SMP_MIN_ENCRYPTION_KEY_SIZE - 1;
		req[5] = 0x00;
		req[6] = BT_CORE63_SMP_KEY_DIST_ENC_KEY;
		ATF_REQUIRE(send(smp_fds[1], req, sizeof(req), MSG_EOR) == 7);

		(void)smp_respond(&sc);
		if (drain_for_failed(smp_fds[1],
		    BT_CORE63_SMP_ERR_REPEATED_ATTEMPTS))
			limited = true;

		close(smp_fds[0]); close(smp_fds[1]);
		close(hci_fds[0]); close(hci_fds[1]);
	}

	ATF_CHECK_MSG(limited,
	    "repeated same-address attempts must hit Repeated Attempts");
}

/* ================================================================
 * Full LE Legacy Just Works responder exchange, driven by a fork(2)ed mock
 * central.  Exercises the smp_respond legacy dispatch, smp_respond_legacy
 * success path (c1/s1, LTK request reply), responder key distribution
 * (Enc/Id/Sign), and receipt of the initiator's keys.
 * Core Spec Vol 3 Part H Section 2.3.5.5.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_respond_legacy_jw_full);
ATF_TC_BODY(test_respond_legacy_jw_full, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_leg.XXXXXX";
	int bond_fd, bond_dir_fd;
	pid_t pid;

	assert_smp_legacy_edge_contract();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);
	bond_dir_fd = open("/tmp", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(bond_dir_fd >= 0);

	/* DUT is the peripheral (responder). */
	setup(&sc, &db, bond_fd, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	smp_bond_db_set_atomic(&db, bond_dir_fd, bond_path + strlen("/tmp/"));

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		/* Child: mock central (initiator). */
		int peer = smp_fds[1];
		uint8_t preq[BT_CORE63_SMP_PAIRING_FEATURE_PDU_SIZE];
		uint8_t pres[BT_CORE63_SMP_PAIRING_FEATURE_PDU_SIZE], pdu[65];
		uint8_t tk[BT_CORE63_SMP_128_BIT_VALUE_SIZE];
		uint8_t mrand[BT_CORE63_SMP_128_BIT_VALUE_SIZE];
		uint8_t srand[BT_CORE63_SMP_128_BIT_VALUE_SIZE];
		uint8_t mconfirm[BT_CORE63_SMP_128_BIT_VALUE_SIZE];
		uint8_t sconfirm[BT_CORE63_SMP_128_BIT_VALUE_SIZE];
		uint8_t verify[BT_CORE63_SMP_128_BIT_VALUE_SIZE];
		uint8_t iat = 0, rat = 0;	/* both public */
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		memset(tk, 0, sizeof(tk));

		/* 1. Send Pairing Request: NoIO, no MITM, no SC -> Just Works. */
		preq[0] = BT_CORE63_SMP_PAIRING_REQUEST;
		preq[1] = BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT;
		preq[2] = BT_CORE63_SMP_OOB_NOT_PRESENT;
		preq[3] = BT_CORE63_SMP_AUTH_BONDING;
		preq[4] = BT_CORE63_SMP_MAX_ENCRYPTION_KEY_SIZE;
		preq[5] = BT_CORE63_SMP_KEY_DIST_ENC_KEY |
		    BT_CORE63_SMP_KEY_DIST_ID_KEY;
		preq[6] = BT_CORE63_SMP_KEY_DIST_ENC_KEY |
		    BT_CORE63_SMP_KEY_DIST_ID_KEY;
		if (send(peer, preq, sizeof(preq), MSG_EOR) != sizeof(preq))
			_exit(1);

		/* 2. Receive Pairing Response. */
		n = recv(peer, pres, sizeof(pres), 0);
		if (n != sizeof(pres) ||
		    pres[0] != BT_CORE63_SMP_PAIRING_RESPONSE)
			_exit(2);

		/*
		 * Responder computes c1 with iat = its remote (=initiator)
		 * addr type and ia = initiator addr (central_addr); rat = its
		 * local addr type and ra = responder addr (periph_addr).
		 * Mirror exactly.
		 */
		arc4random_buf(mrand, sizeof(mrand));
		if (smp_c1(tk, mrand, preq, pres, iat, central_addr,
		    rat, periph_addr, mconfirm) < 0)
			_exit(3);

		/* 3. Send our Pairing Confirm. */
		pdu[0] = BT_CORE63_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, mconfirm, sizeof(mconfirm));
		if (send(peer, pdu, BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE,
		    MSG_EOR) != BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE)
			_exit(4);

		/* 4. Receive responder's Confirm. */
		n = recv(peer, pdu, BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE, 0);
		if (n != BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE ||
		    pdu[0] != BT_CORE63_SMP_PAIRING_CONFIRM)
			_exit(5);
		memcpy(sconfirm, pdu + 1, sizeof(sconfirm));

		/* 5. Send our Random. */
		pdu[0] = BT_CORE63_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, mrand, sizeof(mrand));
		if (send(peer, pdu, BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE,
		    MSG_EOR) != BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE)
			_exit(6);

		/* 6. Receive responder's Random and verify its confirm. */
		n = recv(peer, pdu, BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE, 0);
		if (n != BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE ||
		    pdu[0] != BT_CORE63_SMP_PAIRING_RANDOM)
			_exit(7);
		memcpy(srand, pdu + 1, sizeof(srand));
		if (smp_c1(tk, srand, preq, pres, iat, central_addr,
		    rat, periph_addr, verify) < 0)
			_exit(8);
		if (memcmp(verify, sconfirm, sizeof(verify)) != 0)
			_exit(9);

		/*
		 * 7. Responder now replies to the LTK request (stubbed),
		 * "encryption" completes, and it distributes its keys.
		 * Receive whatever the responder distributes (Enc/Id/Sign)
		 * then send our own initiator keys (Id) so the responder's
		 * smp_receive_peer_keys sees them.
		 */
		{
			uint8_t discard[64];
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			int got = 0;
			setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &tv,
			    sizeof(tv));
			/* pres[6] negotiated Enc+Id: 4 PDUs from responder. */
			while (got < 4 &&
			    recv(peer, discard, sizeof(discard), 0) > 0)
				got++;
		}

		/* Initiator distributes Enc then Id keys in the negotiated wire
		 * order.  The receiver commits them atomically only after every
		 * required PDU arrives. */
		pdu[0] = BT_CORE63_SMP_ENCRYPTION_INFORMATION;
		memset(pdu + 1, 0xa5, BT_CORE63_SMP_128_BIT_VALUE_SIZE);
		(void)send(peer, pdu, BT_CORE63_SMP_KEY_VALUE_PDU_SIZE, MSG_EOR);
		pdu[0] = BT_CORE63_SMP_CENTRAL_IDENTIFICATION;
		memset(pdu + 1, 0, 10);
		(void)send(peer, pdu, BT_CORE63_SMP_CENTRAL_ID_PDU_SIZE, MSG_EOR);

		pdu[0] = BT_CORE63_SMP_IDENTITY_INFORMATION;
		memset(pdu + 1, 0x5a, BT_CORE63_SMP_128_BIT_VALUE_SIZE);
		(void)send(peer, pdu, BT_CORE63_SMP_KEY_VALUE_PDU_SIZE, MSG_EOR);
		pdu[0] = BT_CORE63_SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = 0x00;
		memcpy(pdu + 2, central_addr, 6);
		(void)send(peer, pdu, BT_CORE63_SMP_ID_ADDR_PDU_SIZE, MSG_EOR);

		close(peer);
		_exit(0);
	}

	/* Parent: run the responder. */
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_respond(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "legacy JW responder must succeed (errno=%d)",
	    errno);
	ATF_CHECK_MSG(db.count > 0, "responder must store a bond");
	if (db.count > 0)
		ATF_CHECK(db.bonds[0].has_ltk);

	{
		int status;
		ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "mock central exited with status %d", status);
	}

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	close(bond_dir_fd);
	unlink(bond_path);
	{
		char key_path[sizeof(bond_path) + sizeof(".key")];
		snprintf(key_path, sizeof(key_path), "%s.key", bond_path);
		unlink(key_path);
	}
}

/* ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_encrypt_with_ltk);
	ATF_TP_ADD_TC(tp, test_respond_security_request);
	ATF_TP_ADD_TC(tp, test_respond_sc_only_rejects_legacy);
	ATF_TP_ADD_TC(tp, test_respond_rate_limit_repeated);
	ATF_TP_ADD_TC(tp, test_respond_legacy_jw_full);

	return (atf_no_error());
}
