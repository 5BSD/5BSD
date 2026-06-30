/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF unit tests for the SMP pairing state machine.
 *
 * Tests the full pairing handshake (not just crypto primitives, which are
 * covered in smp_crypto_test.c).  Uses socketpair(2) to mock the L2CAP
 * SMP channel and fork(2) to run both sides of the pairing protocol.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include "att.h"
#include "att_server.h"
#include "hci_log.h"
#include "hci_util.h"
#include "smp.h"

#define TEST_LINKS_SMP
#include "test_common.h"

/* Association model constants from smp.c (not exported via smp.h) */
#ifndef SMP_MODEL_INVALID
#define SMP_MODEL_INVALID	(-1)
#endif

/* ================================================================
 * Stubs for external symbols referenced by smp.c
 * ================================================================ */

/* hci_util.c stubs */
int
hci_send_raw_cmd(int hci_fd, uint16_t opcode,
    const void *params, uint8_t plen)
{
	uint8_t buf[260];

	/* Mirror what hci_util.c does: HCI command indicator + opcode + plen + params */
	buf[0] = 0x01;	/* HCI Command */
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
hci_le_ltk_request_neg_reply(int hci_fd __unused,
    uint16_t con_handle __unused)
{

	return (0);
}

/* ================================================================
 * Helpers
 * ================================================================ */

/*
 * Set up an smp_conn for testing.
 * smp_fds[0] is the DUT side, smp_fds[1] is the mock peer side.
 * hci_fds[0] is the DUT side (writes go into kernel buffer).
 */
static void
setup_conn(struct smp_conn *sc, struct smp_bond_db *db, int bond_fd,
    int smp_fds[2], int hci_fds[2],
    const uint8_t *local_addr, uint8_t local_type,
    const uint8_t *remote_addr, uint8_t remote_type)
{

	/* Ignore SIGPIPE — fork-based tests may write to closed peers */
	signal(SIGPIPE, SIG_IGN);

	memset(db, 0, sizeof(*db));
	db->fd = bond_fd;

	memset(sc, 0, sizeof(*sc));
	sc->fd = smp_fds[0];
	sc->hci_fd = hci_fds[0];
	sc->con_handle = 0x0040;
	memcpy(sc->local_addr, local_addr, 6);
	sc->local_addr_type = local_type;
	memcpy(sc->remote_addr, remote_addr, 6);
	sc->remote_addr_type = remote_type;
	sc->bond_db = db;

	/* Prevent infinite blocking in tests */
	{
		struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
		setsockopt(smp_fds[0], SOL_SOCKET, SO_RCVTIMEO,
		    &tv, sizeof(tv));
		setsockopt(hci_fds[0], SOL_SOCKET, SO_RCVTIMEO,
		    &tv, sizeof(tv));
	}
}

/*
 * Wait for child process and check clean exit.
 */
static void
wait_child(pid_t pid)
{
	int status;

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child exited with status %d", status);
}

/* Address constants */
static const uint8_t central_addr[6] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
static const uint8_t periph_addr[6]  = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };

/* BDADDR_LE_PUBLIC from ng_bluetooth.h */
#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif
#ifndef BDADDR_LE_RANDOM
#define BDADDR_LE_RANDOM	2
#endif

/* ================================================================
 * Test 1: Legacy Just Works pairing — central (initiator) side
 *
 * Parent calls smp_pair(), child mocks the peripheral.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_pair_legacy_just_works);
ATF_TC_BODY(test_smp_pair_legacy_just_works, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_pair_jw.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: mock peripheral */
		int peer_fd = smp_fds[1];
		uint8_t pdu[65];
		uint8_t preq[7], pres[7];
		uint8_t tk[16], srand[16], mrand[16];
		uint8_t mconfirm[16], sconfirm[16];
		uint8_t our_ltk[16], our_irk[16];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);

		memset(tk, 0, sizeof(tk));

		/* 1. Receive Pairing Request */
		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != SMP_PAIRING_REQUEST)
			_exit(1);

		/* 2. Send Pairing Response (NoInputNoOutput, no MITM => Just Works) */
		pres[0] = SMP_PAIRING_RESPONSE;
		pres[1] = SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;	/* no OOB */
		pres[3] = SMP_AUTH_BONDING;	/* no MITM, no SC */
		pres[4] = 16;		/* max key size */
		pres[5] = 0x00;		/* init key dist: none */
		pres[6] = SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), 0) < 0)
			_exit(2);

		/*
		 * Note: smp_pair uses iat/rat based on addr_type.
		 * Central is initiator: iat = central_addr_type mapped,
		 * rat = periph_addr_type mapped.
		 * Both are BDADDR_LE_PUBLIC (1) which maps to iat=0, rat=0
		 * in the code: (addr_type == BDADDR_LE_RANDOM) ? 1 : 0
		 */
		uint8_t iat = 0;  /* central is public */
		uint8_t rat = 0;  /* periph is public */

		/* 3. Receive Pairing Confirm from central */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(mconfirm, pdu + 1, 16);

		/* 4. Generate our random and compute confirm */
		arc4random_buf(srand, sizeof(srand));
		smp_c1(tk, srand, preq, pres, iat, central_addr,
		    rat, periph_addr, sconfirm);

		/* Send our confirm */
		pdu[0] = SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(4);

		/* 5. Receive Pairing Random from central */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM)
			_exit(5);
		memcpy(mrand, pdu + 1, 16);

		/* Verify central's confirm */
		{
			uint8_t verify[16];
			smp_c1(tk, mrand, preq, pres, iat, central_addr,
			    rat, periph_addr, verify);
			if (memcmp(verify, mconfirm, 16) != 0)
				_exit(6);
		}

		/* 6. Send our random */
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(7);

		/*
		 * At this point the central derives STK, sends
		 * HCI LE_Start_Encryption (on hci_fd, not here),
		 * and our hci_wait_encryption stub returns 0.
		 *
		 * 7. Send key distribution PDUs.
		 */
		arc4random_buf(our_ltk, sizeof(our_ltk));
		memset(our_irk, 0, sizeof(our_irk));

		/* Encryption Info */
		pdu[0] = SMP_ENCRYPTION_INFORMATION;
		memcpy(pdu + 1, our_ltk, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(8);

		/* Central Identification */
		pdu[0] = SMP_CENTRAL_IDENTIFICATION;
		memset(pdu + 1, 0, 2);	 /* ediv = 0 */
		memset(pdu + 3, 0, 8);	 /* rand = 0 */
		if (send(peer_fd, pdu, 11, 0) < 0)
			_exit(9);

		/* Identity Information */
		pdu[0] = SMP_IDENTITY_INFORMATION;
		memcpy(pdu + 1, our_irk, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(10);

		/* Identity Address */
		pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = 0x00;	/* public */
		memcpy(pdu + 2, periph_addr, 6);
		if (send(peer_fd, pdu, 8, 0) < 0)
			_exit(11);

		/*
		 * Receive and discard initiator key distribution PDUs.
		 * The central now distributes its own keys after receiving ours.
		 */
		{
			uint8_t discard[64];
			struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
			while (recv(peer_fd, discard, sizeof(discard), 0) > 0)
				;
		}

		close(peer_fd);
		_exit(0);
	}

	/* Parent: central */
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "smp_pair returned %d (errno=%d)", ret, errno);
	ATF_CHECK_MSG(db.count > 0, "expected bond stored, got count=%d",
	    db.count);
	if (db.count > 0)
		ATF_CHECK(db.bonds[0].has_ltk);

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test 2: Peer sends SMP_PAIRING_FAILED in response
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_pair_legacy_peer_rejects);
ATF_TC_BODY(test_smp_pair_legacy_peer_rejects, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_pair_rej.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pdu[2];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);

		/* Receive Pairing Request */
		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != SMP_PAIRING_REQUEST)
			_exit(1);

		/* Send Pairing Failed */
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_PAIRING_NOT_SUPPORTED;
		send(peer_fd, pdu, 2, 0);

		close(peer_fd);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK(ret == -1);
	ATF_CHECK_EQ(db.count, 0);

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test 3: Peer responds with invalid key size (< 7)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_pair_invalid_key_size);
ATF_TC_BODY(test_smp_pair_invalid_key_size, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_pair_ks.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);

		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != SMP_PAIRING_REQUEST)
			_exit(1);

		/* Send response with max_key_size=6 (below minimum) */
		pres[0] = SMP_PAIRING_RESPONSE;
		pres[1] = SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = SMP_AUTH_BONDING;
		pres[4] = 6;		/* INVALID: below minimum of 7 */
		pres[5] = 0x00;
		pres[6] = SMP_KEY_DIST_ENC_KEY;
		send(peer_fd, pres, sizeof(pres), 0);

		/*
		 * Central should send Pairing Failed back.
		 * Drain it so we don't get SIGPIPE.
		 */
		{
			uint8_t buf[65];
			recv(peer_fd, buf, sizeof(buf), 0);
		}

		close(peer_fd);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK(ret == -1);
	ATF_CHECK_EQ(db.count, 0);

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test 4: Peer sends wrong opcode instead of Pairing Response
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_pair_wrong_opcode);
ATF_TC_BODY(test_smp_pair_wrong_opcode, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_pair_wo.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], garbage[7];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);

		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != SMP_PAIRING_REQUEST)
			_exit(1);

		/* Send a Pairing Confirm instead of Pairing Response */
		memset(garbage, 0, sizeof(garbage));
		garbage[0] = SMP_PAIRING_CONFIRM;
		send(peer_fd, garbage, sizeof(garbage), 0);

		close(peer_fd);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK(ret == -1);

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test 5: Legacy Just Works — responder (peripheral) side
 *
 * Parent calls smp_respond(), child mocks the central.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_respond_legacy_just_works);
ATF_TC_BODY(test_smp_respond_legacy_just_works, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_resp_jw.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: mock central (initiator) */
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[65];
		uint8_t tk[16], mrand[16], srand[16];
		uint8_t mconfirm[16], sconfirm[16];
		ssize_t n;
		int expected_pdus, i;

		close(smp_fds[0]);
		close(hci_fds[0]);

		/* Prevent blocking forever if protocol diverges */
		{
			struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
		}

		memset(tk, 0, sizeof(tk));

		/*
		 * Send Pairing Request.
		 * Use NoInputNoOutput + no MITM + no SC => Just Works legacy.
		 */
		preq[0] = SMP_PAIRING_REQUEST;
		preq[1] = SMP_IO_NO_INPUT_NO_OUTPUT;
		preq[2] = 0x00;
		preq[3] = SMP_AUTH_BONDING;  /* no MITM, no SC */
		preq[4] = 16;
		preq[5] = 0x00;  /* we don't distribute keys */
		preq[6] = SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, preq, sizeof(preq), 0) < 0)
			_exit(1);

		/* Receive Pairing Response */
		n = recv(peer_fd, pres, sizeof(pres), 0);
		if (n < 7 || pres[0] != SMP_PAIRING_RESPONSE)
			_exit(2);

		/*
		 * iat = initiator (central) = remote of responder.
		 * For responder: iat = remote_addr_type (central),
		 * rat = local_addr_type (periph).
		 * Both public: iat=0, rat=0.
		 */
		uint8_t iat = 0;
		uint8_t rat = 0;

		/* Generate our random, compute confirm */
		arc4random_buf(mrand, sizeof(mrand));
		smp_c1(tk, mrand, preq, pres, iat, central_addr,
		    rat, periph_addr, mconfirm);

		/* Send Pairing Confirm */
		pdu[0] = SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, mconfirm, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(3);

		/* Receive responder's Pairing Confirm */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM)
			_exit(4);
		memcpy(sconfirm, pdu + 1, 16);

		/* Send Pairing Random */
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, mrand, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(5);

		/* Receive responder's Pairing Random */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM)
			_exit(6);
		memcpy(srand, pdu + 1, 16);

		/* Verify responder's confirm */
		{
			uint8_t verify[16];
			smp_c1(tk, srand, preq, pres, iat, central_addr,
			    rat, periph_addr, verify);
			if (memcmp(verify, sconfirm, 16) != 0)
				_exit(7);
		}

		/*
		 * Encryption phase: responder calls hci_le_ltk_request_reply
		 * (stubbed to return 0) then hci_wait_encryption (stubbed).
		 *
		 * Receive key distribution from responder.
		 */
		expected_pdus = 0;
		if (pres[6] & SMP_KEY_DIST_ENC_KEY)
			expected_pdus += 2;
		if (pres[6] & SMP_KEY_DIST_ID_KEY)
			expected_pdus += 2;

		for (i = 0; i < expected_pdus; i++) {
			n = recv(peer_fd, pdu, sizeof(pdu), 0);
			if (n < 1)
				_exit(8);

			/* Verify responder sends non-zero IRK (H5 fix) */
			if (pdu[0] == SMP_IDENTITY_INFORMATION && n >= 17) {
				uint8_t zero_irk[16];
				memset(zero_irk, 0, sizeof(zero_irk));
				if (memcmp(pdu + 1, zero_irk, 16) == 0)
					_exit(99);  /* fail: responder sent all-zero IRK */
			}
		}

		close(peer_fd);
		_exit(0);
	}

	/* Parent: responder (peripheral) */
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_respond(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "smp_respond returned %d (errno=%d)",
	    ret, errno);
	ATF_CHECK_MSG(db.count > 0, "expected bond stored, got count=%d",
	    db.count);
	if (db.count > 0)
		ATF_CHECK(db.bonds[0].has_ltk);

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test 6: Responder receives garbage instead of Pairing Request
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_respond_peer_bad_request);
ATF_TC_BODY(test_smp_respond_peer_bad_request, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_resp_bad.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t garbage[7];

		close(smp_fds[0]);
		close(hci_fds[0]);

		/* Send garbage (wrong opcode) */
		memset(garbage, 0xAA, sizeof(garbage));
		garbage[0] = SMP_PAIRING_CONFIRM; /* wrong opcode */
		send(peer_fd, garbage, sizeof(garbage), 0);

		/* Drain any response (with timeout to avoid deadlock) */
		{
			uint8_t buf[65];
			struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
			recv(peer_fd, buf, sizeof(buf), 0);
		}

		close(peer_fd);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_respond(&sc);
	ATF_CHECK(ret == -1);

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test 7: Bond find by address — store 3 bonds, find specific one
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_find_by_addr);
ATF_TC_BODY(test_bond_find_by_addr, tc)
{
	struct smp_bond_db db;
	struct smp_bond bond, *found;
	char path[] = "/tmp/blued_test_find.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	memset(&db, 0, sizeof(db));
	db.fd = fd;

	/* Store 3 bonds with different addresses */
	memset(&bond, 0, sizeof(bond));
	bond.has_ltk = true;

	memset(bond.addr, 0xAA, 6);
	bond.addr_type = BDADDR_LE_PUBLIC;
	memset(bond.ltk, 0x11, 16);
	smp_bond_db_store(&db, &bond);

	memset(bond.addr, 0xBB, 6);
	bond.addr_type = BDADDR_LE_PUBLIC;
	memset(bond.ltk, 0x22, 16);
	smp_bond_db_store(&db, &bond);

	memset(bond.addr, 0xCC, 6);
	bond.addr_type = BDADDR_LE_RANDOM;
	memset(bond.ltk, 0x33, 16);
	smp_bond_db_store(&db, &bond);

	ATF_CHECK_EQ(db.count, 3);

	/* Find the middle one */
	{
		uint8_t addr[6];
		memset(addr, 0xBB, 6);
		found = smp_find_bond(&db, addr, BDADDR_LE_PUBLIC);
		ATF_REQUIRE(found != NULL);
		ATF_CHECK_EQ(found->ltk[0], 0x22);
	}

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test 8: Bond find — address not found
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_find_not_found);
ATF_TC_BODY(test_bond_find_not_found, tc)
{
	struct smp_bond_db db;
	struct smp_bond bond, *found;
	char path[] = "/tmp/blued_test_nf.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	memset(&db, 0, sizeof(db));
	db.fd = fd;

	memset(&bond, 0, sizeof(bond));
	memset(bond.addr, 0xAA, 6);
	bond.addr_type = BDADDR_LE_PUBLIC;
	bond.has_ltk = true;
	smp_bond_db_store(&db, &bond);

	/* Search for non-existent address */
	{
		uint8_t addr[6];
		memset(addr, 0xFF, 6);
		found = smp_find_bond(&db, addr, BDADDR_LE_PUBLIC);
		ATF_CHECK(found == NULL);
	}

	/* Search with wrong address type */
	{
		uint8_t addr[6];
		memset(addr, 0xAA, 6);
		found = smp_find_bond(&db, addr, BDADDR_LE_RANDOM);
		ATF_CHECK(found == NULL);
	}

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test 9: Bond upsert — store, modify, store again; verify no dup
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_upsert);
ATF_TC_BODY(test_bond_upsert, tc)
{
	struct smp_bond_db db;
	struct smp_bond bond;
	char path[] = "/tmp/blued_test_upsert.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	memset(&db, 0, sizeof(db));
	db.fd = fd;

	/* Store initial bond */
	memset(&bond, 0, sizeof(bond));
	memset(bond.addr, 0xAA, 6);
	bond.addr_type = BDADDR_LE_PUBLIC;
	bond.has_ltk = true;
	memset(bond.ltk, 0x11, 16);
	smp_bond_db_store(&db, &bond);
	ATF_CHECK_EQ(db.count, 1);

	/* Store again with same address but different LTK */
	memset(bond.ltk, 0x22, 16);
	bond.has_irk = true;
	memset(bond.irk, 0x33, 16);
	smp_bond_db_store(&db, &bond);

	/* Should update in place, not add duplicate */
	ATF_CHECK_EQ(db.count, 1);
	ATF_CHECK_EQ(db.bonds[0].ltk[0], 0x22);
	ATF_CHECK(db.bonds[0].has_irk);
	ATF_CHECK_EQ(db.bonds[0].irk[0], 0x33);

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test 10: Save and load empty DB
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_save_load_empty);
ATF_TC_BODY(test_bond_save_load_empty, tc)
{
	struct smp_bond_db db1, db2;
	char path[] = "/tmp/blued_test_empty.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	memset(&db1, 0, sizeof(db1));
	db1.fd = fd;
	db1.count = 0;

	ATF_CHECK_EQ(smp_bond_db_save(&db1), 0);

	memset(&db2, 0, sizeof(db2));
	ATF_CHECK_EQ(smp_bond_db_load(&db2, fd), 0);
	ATF_CHECK_EQ(db2.count, 0);

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test 11: Save bond with IRK, verify IRK round-trips
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_save_load_irk);
ATF_TC_BODY(test_bond_save_load_irk, tc)
{
	struct smp_bond_db db1, db2;
	char path[] = "/tmp/blued_test_irk.XXXXXX";
	int fd;
	uint8_t test_irk[16];

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	/* Use a known IRK pattern */
	arc4random_buf(test_irk, sizeof(test_irk));

	memset(&db1, 0, sizeof(db1));
	db1.fd = fd;
	db1.count = 1;
	memset(db1.bonds[0].addr, 0xDD, 6);
	db1.bonds[0].addr_type = BDADDR_LE_RANDOM;
	db1.bonds[0].has_ltk = true;
	memset(db1.bonds[0].ltk, 0x42, 16);
	db1.bonds[0].has_irk = true;
	memcpy(db1.bonds[0].irk, test_irk, 16);
	db1.bonds[0].is_sc = true;

	ATF_CHECK_EQ(smp_bond_db_save(&db1), 0);

	memset(&db2, 0, sizeof(db2));
	ATF_CHECK_EQ(smp_bond_db_load(&db2, fd), 0);
	ATF_CHECK_EQ(db2.count, 1);
	ATF_CHECK(db2.bonds[0].has_irk);
	ATF_CHECK(memcmp(db2.bonds[0].irk, test_irk, 16) == 0);
	ATF_CHECK(db2.bonds[0].is_sc);

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test 12: Legacy file without BOND header — should discard
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_legacy_file);
ATF_TC_BODY(test_bond_legacy_file, tc)
{
	struct smp_bond_db db;
	char path[] = "/tmp/blued_test_legacy.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	/* Write raw struct without header (simulates old format) */
	{
		struct smp_bond bond;
		memset(&bond, 0, sizeof(bond));
		bond.has_ltk = true;
		pwrite(fd, &bond, sizeof(bond), 0);
	}

	memset(&db, 0, sizeof(db));
	ATF_CHECK_EQ(smp_bond_db_load(&db, fd), 0);
	ATF_CHECK_EQ_MSG(db.count, 0,
	    "legacy headerless file should start fresh, got count=%d",
	    db.count);

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test 13: Corrupt header — wrong rec_size
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_corrupt_size);
ATF_TC_BODY(test_bond_corrupt_size, tc)
{
	struct smp_bond_db db;
	char path[] = "/tmp/blued_test_corrupt.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	/* Write valid magic but wrong record size */
	{
		uint8_t hdr[8];
		uint32_t wrong_size = 99;  /* definitely not sizeof(smp_bond) */

		memcpy(hdr, "BOND", 4);
		memcpy(hdr + 4, &wrong_size, 4);
		pwrite(fd, hdr, sizeof(hdr), 0);

		/* Write some garbage bond data after the header */
		uint8_t junk[256];
		memset(junk, 0xFF, sizeof(junk));
		pwrite(fd, junk, sizeof(junk), sizeof(hdr));
	}

	memset(&db, 0, sizeof(db));
	ATF_CHECK_EQ(smp_bond_db_load(&db, fd), 0);
	ATF_CHECK_EQ_MSG(db.count, 0,
	    "corrupt rec_size should start fresh, got count=%d", db.count);

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test 14: CCCD save — build att_db with CCCDs, save to bond
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_save_cccds);
ATF_TC_BODY(test_bond_save_cccds, tc)
{
	struct smp_bond bond;
	struct att_conn ac;

	memset(&bond, 0, sizeof(bond));
	memset(&ac, 0, sizeof(ac));

	/*
	 * Set up per-connection CCCD state with 2 entries.
	 * smp_bond_save_cccds now reads from ac->cccds[].
	 */
	ac.cccds[0].handle = 0x0003;
	ac.cccds[0].value = 0x0001;	/* notifications enabled */
	ac.cccds[1].handle = 0x0006;
	ac.cccds[1].value = 0x0002;	/* indications enabled */
	ac.cccd_count = 2;

	smp_bond_save_cccds(&bond, &ac);

	ATF_CHECK_EQ(bond.num_cccds, 2);
	ATF_CHECK_EQ(bond.cccds[0].handle, 0x0003);
	ATF_CHECK_EQ(bond.cccds[0].value, 0x0001);	/* notifications */
	ATF_CHECK_EQ(bond.cccds[1].handle, 0x0006);
	ATF_CHECK_EQ(bond.cccds[1].value, 0x0002);	/* indications */
}

/* ================================================================
 * Test 15: CCCD restore — set entries in bond, restore to att_conn
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_restore_cccds);
ATF_TC_BODY(test_bond_restore_cccds, tc)
{
	struct smp_bond bond;
	struct att_conn ac;

	memset(&bond, 0, sizeof(bond));
	memset(&ac, 0, sizeof(ac));

	/* Set up bond with saved CCCD values */
	bond.num_cccds = 2;
	bond.cccds[0].handle = 0x0010;
	bond.cccds[0].value = 0x0001;	/* notifications */
	bond.cccds[1].handle = 0x0020;
	bond.cccds[1].value = 0x0003;	/* both notifications + indications */

	smp_bond_restore_cccds(&bond, &ac);

	ATF_CHECK_EQ(ac.cccd_count, 2);
	ATF_CHECK_EQ(ac.cccds[0].handle, 0x0010);
	ATF_CHECK_EQ(ac.cccds[0].value, 0x0001);
	ATF_CHECK_EQ(ac.cccds[1].handle, 0x0020);
	ATF_CHECK_EQ(ac.cccds[1].value, 0x0003);
}

/* ================================================================
 * Test: smp_open_accepted sets up connection correctly
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_open_accepted);
ATF_TC_BODY(test_smp_open_accepted, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);

	memset(&db, 0, sizeof(db));
	db.fd = -1;

	int ret = smp_open_accepted(&sc, smp_fds[0],
	    periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_RANDOM,
	    hci_fds[0], 0x0042, &db);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(sc.fd, smp_fds[0]);
	ATF_CHECK_EQ(sc.hci_fd, hci_fds[0]);
	ATF_CHECK_EQ(sc.con_handle, 0x0042);
	ATF_CHECK(memcmp(sc.local_addr, periph_addr, 6) == 0);
	ATF_CHECK_EQ(sc.local_addr_type, BDADDR_LE_PUBLIC);
	ATF_CHECK(memcmp(sc.remote_addr, central_addr, 6) == 0);
	ATF_CHECK_EQ(sc.remote_addr_type, BDADDR_LE_RANDOM);
	ATF_CHECK(sc.bond_db == &db);

	close(smp_fds[0]);
	close(smp_fds[1]);
	close(hci_fds[0]);
	close(hci_fds[1]);
}

/* ================================================================
 * Test: smp_encrypt_with_ltk sends HCI command and succeeds
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_encrypt_with_ltk);
ATF_TC_BODY(test_smp_encrypt_with_ltk, tc)
{
	struct smp_conn sc;
	struct smp_bond bond;
	int hci_fds[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);

	memset(&sc, 0, sizeof(sc));
	sc.hci_fd = hci_fds[0];
	sc.con_handle = 0x0040;

	/* Bond with LTK */
	memset(&bond, 0, sizeof(bond));
	bond.has_ltk = true;
	memset(bond.ltk, 0x42, 16);
	bond.rand = 0x1234567890ABCDEFULL;
	bond.ediv = 0xBEEF;

	int ret = smp_encrypt_with_ltk(&sc, &bond);
	ATF_CHECK_EQ(ret, 0);

	/* Verify HCI command was sent to hci_fds[1] */
	{
		uint8_t buf[64];
		ssize_t n;

		n = recv(hci_fds[1], buf, sizeof(buf), MSG_DONTWAIT);
		ATF_CHECK(n > 0);
		/* buf[0] = 0x01 (HCI command), buf[1..2] = opcode */
		if (n > 0)
			ATF_CHECK_EQ(buf[0], 0x01);
	}

	close(hci_fds[0]);
	close(hci_fds[1]);
}

/* ================================================================
 * Test: smp_encrypt_with_ltk fails when bond has no LTK
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_encrypt_with_ltk_no_ltk);
ATF_TC_BODY(test_smp_encrypt_with_ltk_no_ltk, tc)
{
	struct smp_conn sc;
	struct smp_bond bond;
	int hci_fds[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);

	memset(&sc, 0, sizeof(sc));
	sc.hci_fd = hci_fds[0];
	sc.con_handle = 0x0040;

	memset(&bond, 0, sizeof(bond));
	bond.has_ltk = false;

	int ret = smp_encrypt_with_ltk(&sc, &bond);
	ATF_CHECK(ret == -1);
	ATF_CHECK_EQ(errno, ENOENT);

	close(hci_fds[0]);
	close(hci_fds[1]);
}

/* ================================================================
 * SC test helpers — ECDH key generation and DHKey computation
 * ================================================================ */

/*
 * Generate a P-256 key pair for the mock peer.
 * Stores the uncompressed public key (65 bytes, big-endian: 0x04||X||Y)
 * in pk_raw_out and the EVP_PKEY in *pkey_out.
 * Returns 0 on success, -1 on failure.
 */
static int
sc_generate_keypair(EVP_PKEY **pkey_out, uint8_t pk_raw_out[65])
{
	EVP_PKEY_CTX *pctx;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pctx == NULL)
		return (-1);
	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
	if (EVP_PKEY_keygen(pctx, pkey_out) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return (-1);
	}
	EVP_PKEY_CTX_free(pctx);

	{
		size_t pklen = 65;
		if (EVP_PKEY_get_octet_string_param(*pkey_out,
		    OSSL_PKEY_PARAM_PUB_KEY, pk_raw_out,
		    65, &pklen) <= 0) {
			EVP_PKEY_free(*pkey_out);
			*pkey_out = NULL;
			return (-1);
		}
	}
	return (0);
}

/*
 * Compute ECDH shared secret between our_key and peer's raw public key.
 * dhkey_le_out receives the 32-byte shared secret in little-endian.
 * Returns 0 on success.
 */
static int
sc_compute_dhkey(EVP_PKEY *our_key, const uint8_t peer_pk_raw[65],
    uint8_t dhkey_le_out[32])
{
	EVP_PKEY *peer_key = NULL;
	EVP_PKEY_CTX *fctx, *dctx;
	OSSL_PARAM params[3];
	uint8_t dhkey_be[32];
	size_t dh_len;
	static char curve[] = "prime256v1";

	params[0] = OSSL_PARAM_construct_utf8_string(
	    OSSL_PKEY_PARAM_GROUP_NAME, curve, 0);
	params[1] = OSSL_PARAM_construct_octet_string(
	    OSSL_PKEY_PARAM_PUB_KEY, (void *)(uintptr_t)peer_pk_raw, 65);
	params[2] = OSSL_PARAM_construct_end();

	fctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	EVP_PKEY_fromdata_init(fctx);
	EVP_PKEY_fromdata(fctx, &peer_key, EVP_PKEY_PUBLIC_KEY, params);
	EVP_PKEY_CTX_free(fctx);
	if (peer_key == NULL)
		return (-1);

	dctx = EVP_PKEY_CTX_new(our_key, NULL);
	EVP_PKEY_derive_init(dctx);
	EVP_PKEY_derive_set_peer(dctx, peer_key);
	dh_len = sizeof(dhkey_be);
	if (EVP_PKEY_derive(dctx, dhkey_be, &dh_len) <= 0) {
		EVP_PKEY_CTX_free(dctx);
		EVP_PKEY_free(peer_key);
		return (-1);
	}
	EVP_PKEY_CTX_free(dctx);
	EVP_PKEY_free(peer_key);

	smp_swap_buf(dhkey_le_out, dhkey_be, 32);
	return (0);
}

/*
 * Build the 7-byte packed address for f5/f6: [addr(6), type_bit(1)].
 */
static void
test_pack_addr(uint8_t out[7], const uint8_t addr[6], uint8_t addr_type)
{
	memcpy(out, addr, 6);
	out[6] = (addr_type == BDADDR_LE_RANDOM) ? 0x01 : 0x00;
}

/*
 * Passkey callback for tests — sets/overrides the passkey to a fixed value.
 * When display=true, the daemon generated a random passkey; we override
 * it with the fixed test value so the mock peer can predict it.
 * When display=false, we provide the passkey to the daemon.
 * The arg is a pointer to the uint32_t passkey value.
 */
static int
test_passkey_cb(uint32_t *passkey_out, bool display __unused, void *arg)
{
	uint32_t *fixed = (uint32_t *)arg;

	*passkey_out = *fixed;
	return (0);
}

/*
 * Numeric comparison callback that always accepts.
 */
static int
test_numcmp_accept_cb(uint32_t value __unused, void *arg __unused)
{

	return (0);
}

/* ================================================================
 * Test 19: SC Just Works pairing — central (initiator) side
 *
 * Full LE Secure Connections pairing with ECDH key exchange,
 * Just Works association model (NoInputNoOutput on both sides).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_pair_sc_just_works);
ATF_TC_BODY(test_smp_pair_sc_just_works, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_sc_jw.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: mock peripheral for SC Just Works */
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[66];
		ssize_t n;

		EVP_PKEY *peer_key = NULL;
		uint8_t peer_pk_raw[65];	/* BE: 0x04 || X || Y */
		uint8_t central_pk_raw[65];
		uint8_t pka_le[32], pkb_le[32];	/* LE x-coords */
		uint8_t dhkey_le[32];
		uint8_t na[16], nb[16];
		uint8_t mackey[16], ltk[16];
		uint8_t ea[16], eb[16];
		uint8_t a1[7], a2[7];
		uint8_t iocap_a[3], iocap_b[3];
		uint8_t r[16];
		uint8_t cb[16];

		close(smp_fds[0]);
		close(hci_fds[0]);

		/* 1. Receive Pairing Request */
		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != SMP_PAIRING_REQUEST)
			_exit(1);

		/* 2. Send Pairing Response: SC + NoInputNoOutput => Just Works */
		pres[0] = SMP_PAIRING_RESPONSE;
		pres[1] = SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = SMP_AUTH_BONDING | SMP_AUTH_SC;
		pres[4] = 16;
		pres[5] = 0x00;
		pres[6] = SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), 0) < 0)
			_exit(2);

		/* 3. Generate our ECDH key pair */
		if (sc_generate_keypair(&peer_key, peer_pk_raw) != 0)
			_exit(3);

		/* 4. Receive central's public key (wire = LE) */
		n = recv(peer_fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY)
			_exit(4);
		/* Convert central's PK from wire LE to OpenSSL BE */
		central_pk_raw[0] = 0x04;
		smp_swap_buf(central_pk_raw + 1, pdu + 1, 32);
		smp_swap_buf(central_pk_raw + 33, pdu + 33, 32);
		memcpy(pka_le, pdu + 1, 32);

		/* 5. Send our public key (BE -> wire LE) */
		pdu[0] = SMP_PAIRING_PUBLIC_KEY;
		smp_swap_buf(pdu + 1, peer_pk_raw + 1, 32);
		smp_swap_buf(pdu + 33, peer_pk_raw + 33, 32);
		memcpy(pkb_le, pdu + 1, 32);
		if (send(peer_fd, pdu, 65, 0) < 0) {
			EVP_PKEY_free(peer_key);
			_exit(5);
		}

		/* 6. Compute DHKey */
		if (sc_compute_dhkey(peer_key, central_pk_raw, dhkey_le) != 0) {
			EVP_PKEY_free(peer_key);
			_exit(6);
		}
		EVP_PKEY_free(peer_key);

		/*
		 * 7. SC Just Works Stage 1 (responder):
		 *    Compute Cb = f4(PKbx, PKax, Nb, 0), send Cb
		 *    Receive Na, send Nb
		 */
		arc4random_buf(nb, sizeof(nb));
		smp_f4(pkb_le, pka_le, nb, 0, cb);

		pdu[0] = SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, cb, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(7);

		/* Receive Na */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM)
			_exit(8);
		memcpy(na, pdu + 1, 16);

		/* Send Nb */
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, nb, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(9);

		/*
		 * 8. Stage 2: Compute MacKey + LTK, DHKey checks.
		 *    a1 = initiator (central), a2 = responder (periph)
		 */
		test_pack_addr(a1, central_addr, BDADDR_LE_PUBLIC);
		test_pack_addr(a2, periph_addr, BDADDR_LE_PUBLIC);

		iocap_a[0] = preq[1]; iocap_a[1] = preq[2];
		iocap_a[2] = preq[3];
		iocap_b[0] = pres[1]; iocap_b[1] = pres[2];
		iocap_b[2] = pres[3];

		memset(r, 0, sizeof(r));

		smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
		smp_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
		smp_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);

		/* Receive Ea from central, verify */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_DHKEY_CHECK)
			_exit(10);
		if (memcmp(pdu + 1, ea, 16) != 0)
			_exit(11);

		/* Send Eb */
		pdu[0] = SMP_PAIRING_DHKEY_CHECK;
		memcpy(pdu + 1, eb, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(12);

		/* 9. Key distribution: send IRK + Identity Address */
		pdu[0] = SMP_IDENTITY_INFORMATION;
		memset(pdu + 1, 0, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(13);

		pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = 0x00;	/* public */
		memcpy(pdu + 2, periph_addr, 6);
		if (send(peer_fd, pdu, 8, 0) < 0)
			_exit(14);

		close(peer_fd);
		_exit(0);
	}

	/* Parent: central */
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "smp_pair returned %d (errno=%d)", ret, errno);
	ATF_CHECK_MSG(db.count > 0, "expected bond stored, got count=%d",
	    db.count);
	if (db.count > 0) {
		ATF_CHECK(db.bonds[0].has_ltk);
		ATF_CHECK(db.bonds[0].is_sc);
	}

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test 20: SC Passkey Entry — central (initiator) side
 *
 * Central has KeyboardDisplay (IO=4), peer has KeyboardOnly (IO=2).
 * SC Table 2.8: KbdDisp vs KbdOnly => Passkey Entry.
 * Central displays, peer inputs. 20 rounds of confirm/nonce.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_pair_sc_passkey_entry);
ATF_TC_BODY(test_smp_pair_sc_passkey_entry, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_sc_pk.XXXXXX";
	int bond_fd;
	pid_t pid;
	uint32_t test_passkey = 123456;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	sc.passkey_cb = test_passkey_cb;
	sc.passkey_cb_arg = &test_passkey;

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: mock peripheral for SC Passkey Entry */
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[66];
		ssize_t n;

		EVP_PKEY *peer_key = NULL;
		uint8_t peer_pk_raw[65];
		uint8_t central_pk_raw[65];
		uint8_t pka_le[32], pkb_le[32];
		uint8_t dhkey_le[32];
		uint8_t na[16], nb[16];
		uint8_t mackey[16], ltk[16];
		uint8_t ea[16], eb[16];
		uint8_t a1[7], a2[7];
		uint8_t iocap_a[3], iocap_b[3];
		uint8_t ra[16];
		uint32_t passkey = 123456;
		int i;

		close(smp_fds[0]);
		close(hci_fds[0]);

		/* 1. Receive Pairing Request */
		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != SMP_PAIRING_REQUEST)
			_exit(1);

		/* 2. Send Pairing Response: SC + KbdOnly + MITM */
		pres[0] = SMP_PAIRING_RESPONSE;
		pres[1] = SMP_IO_KEYBOARD_ONLY;
		pres[2] = 0x00;
		pres[3] = SMP_AUTH_BONDING | SMP_AUTH_MITM | SMP_AUTH_SC;
		pres[4] = 16;
		pres[5] = 0x00;
		pres[6] = SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), 0) < 0)
			_exit(2);

		/* 3. Generate ECDH key pair */
		if (sc_generate_keypair(&peer_key, peer_pk_raw) != 0)
			_exit(3);

		/* 4. Receive central's PK */
		n = recv(peer_fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY)
			_exit(4);
		central_pk_raw[0] = 0x04;
		smp_swap_buf(central_pk_raw + 1, pdu + 1, 32);
		smp_swap_buf(central_pk_raw + 33, pdu + 33, 32);
		memcpy(pka_le, pdu + 1, 32);

		/* 5. Send our PK */
		pdu[0] = SMP_PAIRING_PUBLIC_KEY;
		smp_swap_buf(pdu + 1, peer_pk_raw + 1, 32);
		smp_swap_buf(pdu + 33, peer_pk_raw + 33, 32);
		memcpy(pkb_le, pdu + 1, 32);
		if (send(peer_fd, pdu, 65, 0) < 0) {
			EVP_PKEY_free(peer_key);
			_exit(5);
		}

		/* 6. Compute DHKey */
		if (sc_compute_dhkey(peer_key, central_pk_raw, dhkey_le) != 0) {
			EVP_PKEY_free(peer_key);
			_exit(6);
		}
		EVP_PKEY_free(peer_key);

		/*
		 * 7. 20-round Passkey Entry.
		 * For each bit i: ri = 0x80 | ((passkey >> i) & 1)
		 * Receive Cai, send Cbi, receive Nai, verify, send Nbi.
		 */
		for (i = 0; i < 20; i++) {
			uint8_t nai[16], nbi[16];
			uint8_t cai_recv[16], cbi[16], cai_verify[16];
			uint8_t ri;

			ri = 0x80 | ((passkey >> i) & 1);

			/* Receive Cai (initiator confirm) */
			n = recv(peer_fd, pdu, 17, 0);
			if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM)
				_exit(20 + i);
			memcpy(cai_recv, pdu + 1, 16);

			/* Compute and send Cbi */
			arc4random_buf(nbi, sizeof(nbi));
			smp_f4(pkb_le, pka_le, nbi, ri, cbi);
			pdu[0] = SMP_PAIRING_CONFIRM;
			memcpy(pdu + 1, cbi, 16);
			if (send(peer_fd, pdu, 17, 0) < 0)
				_exit(60 + i);

			/* Receive Nai */
			n = recv(peer_fd, pdu, 17, 0);
			if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM)
				_exit(80 + i);
			memcpy(nai, pdu + 1, 16);

			/* Verify Cai = f4(PKax, PKbx, Nai, ri) */
			smp_f4(pka_le, pkb_le, nai, ri, cai_verify);
			if (memcmp(cai_recv, cai_verify, 16) != 0)
				_exit(100 + i);

			/* Send Nbi */
			pdu[0] = SMP_PAIRING_RANDOM;
			memcpy(pdu + 1, nbi, 16);
			if (send(peer_fd, pdu, 17, 0) < 0)
				_exit(120 + i);

			/* Keep last round nonces */
			memcpy(na, nai, 16);
			memcpy(nb, nbi, 16);
		}

		/* 8. Stage 2: DHKey checks */
		test_pack_addr(a1, central_addr, BDADDR_LE_PUBLIC);
		test_pack_addr(a2, periph_addr, BDADDR_LE_PUBLIC);

		iocap_a[0] = preq[1]; iocap_a[1] = preq[2];
		iocap_a[2] = preq[3];
		iocap_b[0] = pres[1]; iocap_b[1] = pres[2];
		iocap_b[2] = pres[3];

		/* ra = passkey as 128-bit LE */
		memset(ra, 0, sizeof(ra));
		ra[0] = passkey & 0xFF;
		ra[1] = (passkey >> 8) & 0xFF;
		ra[2] = (passkey >> 16) & 0xFF;

		smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
		smp_f6(mackey, na, nb, ra, iocap_a, a1, a2, ea);
		smp_f6(mackey, nb, na, ra, iocap_b, a2, a1, eb);

		/* Receive Ea, verify */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_DHKEY_CHECK)
			_exit(141);
		if (memcmp(pdu + 1, ea, 16) != 0)
			_exit(142);

		/* Send Eb */
		pdu[0] = SMP_PAIRING_DHKEY_CHECK;
		memcpy(pdu + 1, eb, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(143);

		/* Key distribution: IRK + Identity */
		pdu[0] = SMP_IDENTITY_INFORMATION;
		memset(pdu + 1, 0, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(144);

		pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = 0x00;
		memcpy(pdu + 2, periph_addr, 6);
		if (send(peer_fd, pdu, 8, 0) < 0)
			_exit(145);

		close(peer_fd);
		_exit(0);
	}

	/* Parent: central */
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "smp_pair returned %d (errno=%d)", ret, errno);
	ATF_CHECK_MSG(db.count > 0, "expected bond, got count=%d", db.count);
	if (db.count > 0) {
		ATF_CHECK(db.bonds[0].has_ltk);
		ATF_CHECK(db.bonds[0].is_sc);
	}

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test 21: SC Numeric Comparison — central (initiator) side
 *
 * Both sides have DisplayYesNo IO caps.
 * SC Table 2.8: DispYN vs DispYN => Numeric Comparison (model 2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_pair_sc_numeric_comparison);
ATF_TC_BODY(test_smp_pair_sc_numeric_comparison, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_sc_nc.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	sc.numcmp_cb = test_numcmp_accept_cb;
	sc.numcmp_cb_arg = NULL;

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: mock peripheral for SC Numeric Comparison */
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[66];
		ssize_t n;

		EVP_PKEY *peer_key = NULL;
		uint8_t peer_pk_raw[65];
		uint8_t central_pk_raw[65];
		uint8_t pka_le[32], pkb_le[32];
		uint8_t dhkey_le[32];
		uint8_t na[16], nb[16];
		uint8_t mackey[16], ltk[16];
		uint8_t ea[16], eb[16];
		uint8_t a1[7], a2[7];
		uint8_t iocap_a[3], iocap_b[3];
		uint8_t r[16];
		uint8_t cb[16];

		close(smp_fds[0]);
		close(hci_fds[0]);

		/* 1. Receive Pairing Request */
		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != SMP_PAIRING_REQUEST)
			_exit(1);

		/* 2. Send Pairing Response: SC + DisplayYesNo + MITM */
		pres[0] = SMP_PAIRING_RESPONSE;
		pres[1] = SMP_IO_DISPLAY_YESNO;
		pres[2] = 0x00;
		pres[3] = SMP_AUTH_BONDING | SMP_AUTH_MITM | SMP_AUTH_SC;
		pres[4] = 16;
		pres[5] = 0x00;
		pres[6] = SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), 0) < 0)
			_exit(2);

		/* 3. Generate ECDH key pair */
		if (sc_generate_keypair(&peer_key, peer_pk_raw) != 0)
			_exit(3);

		/* 4. Receive central's PK */
		n = recv(peer_fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY)
			_exit(4);
		central_pk_raw[0] = 0x04;
		smp_swap_buf(central_pk_raw + 1, pdu + 1, 32);
		smp_swap_buf(central_pk_raw + 33, pdu + 33, 32);
		memcpy(pka_le, pdu + 1, 32);

		/* 5. Send our PK */
		pdu[0] = SMP_PAIRING_PUBLIC_KEY;
		smp_swap_buf(pdu + 1, peer_pk_raw + 1, 32);
		smp_swap_buf(pdu + 33, peer_pk_raw + 33, 32);
		memcpy(pkb_le, pdu + 1, 32);
		if (send(peer_fd, pdu, 65, 0) < 0) {
			EVP_PKEY_free(peer_key);
			_exit(5);
		}

		/* 6. Compute DHKey */
		if (sc_compute_dhkey(peer_key, central_pk_raw, dhkey_le) != 0) {
			EVP_PKEY_free(peer_key);
			_exit(6);
		}
		EVP_PKEY_free(peer_key);

		/*
		 * 7. Stage 1: Just Works/NumCmp confirm exchange.
		 *    Responder: compute Cb, send Cb, recv Na, send Nb.
		 */
		arc4random_buf(nb, sizeof(nb));
		smp_f4(pkb_le, pka_le, nb, 0, cb);

		pdu[0] = SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, cb, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(7);

		/* Receive Na */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM)
			_exit(8);
		memcpy(na, pdu + 1, 16);

		/* Send Nb */
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, nb, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(9);

		/* (Numeric comparison happens on both sides — no PDU) */

		/* 8. Stage 2: DHKey checks */
		test_pack_addr(a1, central_addr, BDADDR_LE_PUBLIC);
		test_pack_addr(a2, periph_addr, BDADDR_LE_PUBLIC);

		iocap_a[0] = preq[1]; iocap_a[1] = preq[2];
		iocap_a[2] = preq[3];
		iocap_b[0] = pres[1]; iocap_b[1] = pres[2];
		iocap_b[2] = pres[3];

		memset(r, 0, sizeof(r));

		smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
		smp_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
		smp_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);

		/* Receive Ea, verify */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_DHKEY_CHECK)
			_exit(10);
		if (memcmp(pdu + 1, ea, 16) != 0)
			_exit(11);

		/* Send Eb */
		pdu[0] = SMP_PAIRING_DHKEY_CHECK;
		memcpy(pdu + 1, eb, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(12);

		/* Key distribution */
		pdu[0] = SMP_IDENTITY_INFORMATION;
		memset(pdu + 1, 0, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(13);

		pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = 0x00;
		memcpy(pdu + 2, periph_addr, 6);
		if (send(peer_fd, pdu, 8, 0) < 0)
			_exit(14);

		close(peer_fd);
		_exit(0);
	}

	/* Parent: central */
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "smp_pair returned %d (errno=%d)", ret, errno);
	ATF_CHECK_MSG(db.count > 0, "expected bond, got count=%d", db.count);
	if (db.count > 0) {
		ATF_CHECK(db.bonds[0].has_ltk);
		ATF_CHECK(db.bonds[0].is_sc);
	}

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test 22: SC Debug Public Key is rejected
 *
 * Peer sends the well-known SC Debug Public Key.
 * Central must detect it and fail pairing.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_pair_sc_debug_key_rejected);
ATF_TC_BODY(test_smp_pair_sc_debug_key_rejected, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_sc_dbg.XXXXXX";
	int bond_fd;
	pid_t pid;

	/* SC Debug Key coordinates in big-endian */
	static const uint8_t debug_pk_x_be[32] = {
		0x20, 0xb0, 0x03, 0xd2, 0xf2, 0x97, 0xbe, 0x2c,
		0x5e, 0x2c, 0x83, 0xa7, 0xe9, 0xf9, 0xa5, 0xb9,
		0xef, 0xf4, 0x91, 0x11, 0xac, 0xf4, 0xfd, 0xdb,
		0xcc, 0x03, 0x01, 0x48, 0x0e, 0x35, 0x9d, 0xe6
	};
	static const uint8_t debug_pk_y_be[32] = {
		0xdc, 0x80, 0x96, 0x42, 0xf7, 0x6e, 0x7e, 0x77,
		0x64, 0x65, 0xdf, 0xf2, 0x31, 0x95, 0xf1, 0xa1,
		0x38, 0x79, 0xa3, 0xc1, 0xe6, 0x0e, 0xfb, 0x7a,
		0xa8, 0xfc, 0xe4, 0x1b, 0x64, 0xff, 0x3d, 0x07
	};

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[66];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);

		/* Receive Pairing Request */
		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != SMP_PAIRING_REQUEST)
			_exit(1);

		/* Send Pairing Response with SC */
		pres[0] = SMP_PAIRING_RESPONSE;
		pres[1] = SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = SMP_AUTH_BONDING | SMP_AUTH_SC;
		pres[4] = 16;
		pres[5] = 0x00;
		pres[6] = SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), 0) < 0)
			_exit(2);

		/* Receive central's PK (don't care about content) */
		n = recv(peer_fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY)
			_exit(3);

		/* Send the Debug Public Key (BE -> wire LE) */
		pdu[0] = SMP_PAIRING_PUBLIC_KEY;
		smp_swap_buf(pdu + 1, debug_pk_x_be, 32);
		smp_swap_buf(pdu + 33, debug_pk_y_be, 32);
		if (send(peer_fd, pdu, 65, 0) < 0)
			_exit(4);

		/*
		 * Central should reject — drain any Pairing Failed PDU
		 * to avoid SIGPIPE.
		 */
		{
			uint8_t buf[65];
			struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
			recv(peer_fd, buf, sizeof(buf), 0);
		}

		close(peer_fd);
		_exit(0);
	}

	/* Parent: central */
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, -1,
	    "expected smp_pair to reject debug key, got %d", ret);
	ATF_CHECK_EQ(db.count, 0);

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test 23: SC key size < 16 is rejected (KNOB mitigation)
 *
 * Peer responds with SC flag set but max_key_size=7.
 * Negotiated key size = min(16, 7) = 7 < 16, must be rejected.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_pair_sc_key_size_rejected);
ATF_TC_BODY(test_smp_pair_sc_key_size_rejected, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_sc_knob.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);

		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != SMP_PAIRING_REQUEST)
			_exit(1);

		/* SC response with max_key_size=7 */
		pres[0] = SMP_PAIRING_RESPONSE;
		pres[1] = SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = SMP_AUTH_BONDING | SMP_AUTH_SC;
		pres[4] = 7;		/* Too small for SC */
		pres[5] = 0x00;
		pres[6] = SMP_KEY_DIST_ID_KEY;
		send(peer_fd, pres, sizeof(pres), 0);

		/* Drain Pairing Failed */
		{
			uint8_t buf[65];
			struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
			recv(peer_fd, buf, sizeof(buf), 0);
		}

		close(peer_fd);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, -1,
	    "expected smp_pair to reject SC key_size=7, got %d", ret);
	ATF_CHECK_EQ(db.count, 0);

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test: sc_only mode rejects legacy pairing
 *
 * When sc->sc_only=true, smp_pair must reject a peer that responds
 * without SMP_AUTH_SC set, sending SMP_PAIRING_FAILED with reason
 * SMP_ERR_AUTH_REQUIREMENTS.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_sc_only_rejects_legacy);
ATF_TC_BODY(test_smp_sc_only_rejects_legacy, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_sconly.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	/* Enable SC Only mode — must reject peers without SC support */
	sc.sc_only = true;

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[65];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);

		{
			struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
		}

		/* Receive Pairing Request */
		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != SMP_PAIRING_REQUEST)
			_exit(1);

		/*
		 * Send Pairing Response WITHOUT SMP_AUTH_SC.
		 * This is a legacy-only peer.
		 */
		pres[0] = SMP_PAIRING_RESPONSE;
		pres[1] = SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = SMP_AUTH_BONDING;	/* no SC flag */
		pres[4] = 16;
		pres[5] = 0x00;
		pres[6] = SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), 0) < 0)
			_exit(2);

		/*
		 * Expect to receive SMP_PAIRING_FAILED with reason
		 * SMP_ERR_AUTH_REQUIREMENTS from the DUT.
		 */
		n = recv(peer_fd, pdu, sizeof(pdu), 0);
		if (n < 2)
			_exit(3);
		if (pdu[0] != SMP_PAIRING_FAILED)
			_exit(4);
		if (pdu[1] != SMP_ERR_AUTH_REQUIREMENTS)
			_exit(5);

		close(peer_fd);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, -1,
	    "expected smp_pair to reject legacy peer in sc_only mode, got %d",
	    ret);
	ATF_CHECK_EQ(db.count, 0);

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test: smp_select_model rejects reserved IO capability values
 *
 * Core Spec Vol 3, Part H, Table 3.4 defines IO capabilities 0-4.
 * Values > 4 are reserved and must return SMP_MODEL_INVALID.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_invalid_io_capability);
ATF_TC_BODY(test_smp_invalid_io_capability, tc)
{
	int model;

	/* init_io=5 (reserved), resp_io=0 (valid) */
	model = smp_select_model(5, 0, false);
	ATF_CHECK_EQ_MSG(model, SMP_MODEL_INVALID,
	    "init_io=5, resp_io=0: expected INVALID(%d), got %d",
	    SMP_MODEL_INVALID, model);

	/* init_io=0 (valid), resp_io=5 (reserved) */
	model = smp_select_model(0, 5, false);
	ATF_CHECK_EQ_MSG(model, SMP_MODEL_INVALID,
	    "init_io=0, resp_io=5: expected INVALID(%d), got %d",
	    SMP_MODEL_INVALID, model);

	/* Both reserved (0xFF) */
	model = smp_select_model(0xFF, 0xFF, true);
	ATF_CHECK_EQ_MSG(model, SMP_MODEL_INVALID,
	    "init_io=0xFF, resp_io=0xFF: expected INVALID(%d), got %d",
	    SMP_MODEL_INVALID, model);

	/* Both valid (4, 4) — should NOT be INVALID */
	model = smp_select_model(4, 4, false);
	ATF_CHECK_MSG(model != SMP_MODEL_INVALID,
	    "init_io=4, resp_io=4: expected valid model, got INVALID(%d)",
	    model);

	/* Same check with SC enabled */
	model = smp_select_model(4, 4, true);
	ATF_CHECK_MSG(model != SMP_MODEL_INVALID,
	    "init_io=4, resp_io=4 (SC): expected valid model, got INVALID(%d)",
	    model);
}

/* ================================================================
 * Test 24: CTKD requires MITM — non-MITM bond should not derive
 *
 * Create an SC bond with is_mitm=false.  smp_ctkd_derive_link_key
 * should return 0 but not set has_link_key.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_ctkd_requires_mitm);
ATF_TC_BODY(test_smp_ctkd_requires_mitm, tc)
{
	struct smp_bond bond;

	memset(&bond, 0, sizeof(bond));
	bond.is_sc = true;
	bond.has_ltk = true;
	memset(bond.ltk, 0x42, 16);
	bond.is_mitm = false;

	int ret = smp_ctkd_derive_link_key(&bond, false);
	ATF_CHECK_EQ_MSG(ret, 0,
	    "ctkd should succeed (but skip derivation), got %d", ret);
	ATF_CHECK_MSG(!bond.has_link_key,
	    "link key should NOT be derived without MITM");
}

/* ================================================================
 * Test 25: CTKD with MITM — link key should be derived
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_ctkd_with_mitm);
ATF_TC_BODY(test_smp_ctkd_with_mitm, tc)
{
	struct smp_bond bond;
	uint8_t zero_key[16];

	memset(&bond, 0, sizeof(bond));
	bond.is_sc = true;
	bond.has_ltk = true;
	memset(bond.ltk, 0x42, 16);
	bond.is_mitm = true;

	memset(zero_key, 0, sizeof(zero_key));

	/* Test CT2=false path (h6) */
	int ret = smp_ctkd_derive_link_key(&bond, false);
	ATF_CHECK_EQ_MSG(ret, 0, "ctkd ct2=false failed, got %d", ret);
	ATF_CHECK_MSG(bond.has_link_key,
	    "link key should be derived with MITM");
	ATF_CHECK_MSG(memcmp(bond.link_key, zero_key, 16) != 0,
	    "link key should be non-zero");

	/* Test CT2=true path (h7) */
	bond.has_link_key = false;
	memset(bond.link_key, 0, 16);
	ret = smp_ctkd_derive_link_key(&bond, true);
	ATF_CHECK_EQ_MSG(ret, 0, "ctkd ct2=true failed, got %d", ret);
	ATF_CHECK_MSG(bond.has_link_key,
	    "link key should be derived with CT2");
	ATF_CHECK_MSG(memcmp(bond.link_key, zero_key, 16) != 0,
	    "link key should be non-zero");
}

/* ================================================================
 * Test 26: smp_generate_sc_oob produces non-zero confirm/random
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_generate_sc_oob);
ATF_TC_BODY(test_smp_generate_sc_oob, tc)
{
	uint8_t confirm[16], random[16];
	uint8_t pk_x[32];
	uint8_t zero16[16];

	memset(zero16, 0, sizeof(zero16));
	/* Use a fake PK x-coordinate */
	arc4random_buf(pk_x, sizeof(pk_x));

	int ret = smp_generate_sc_oob(confirm, random, pk_x);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_MSG(memcmp(random, zero16, 16) != 0,
	    "OOB random should be non-zero");
	ATF_CHECK_MSG(memcmp(confirm, zero16, 16) != 0,
	    "OOB confirm should be non-zero");

	/* Verify confirm = f4(pk_x, pk_x, random, 0) */
	{
		uint8_t verify[16];
		smp_f4(pk_x, pk_x, random, 0, verify);
		ATF_CHECK_MSG(memcmp(confirm, verify, 16) == 0,
		    "OOB confirm should match f4(PKx, PKx, r, 0)");
	}
}

/* ================================================================
 * Test 27: Legacy Passkey Entry — central (initiator) side
 *
 * Central has DisplayOnly (IO=0), peer has KeyboardOnly (IO=2).
 * Legacy Table 2.6: DispOnly vs KbdOnly => Passkey Entry.
 * Central displays passkey; peer inputs it.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_pair_legacy_passkey_entry);
ATF_TC_BODY(test_smp_pair_legacy_passkey_entry, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_lpk.XXXXXX";
	int bond_fd;
	pid_t pid;
	uint32_t test_passkey = 654321;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	sc.passkey_cb = test_passkey_cb;
	sc.passkey_cb_arg = &test_passkey;

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: mock peripheral for legacy passkey entry */
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[65];
		uint8_t tk[16], srand_val[16], mrand_val[16];
		uint8_t mconfirm[16], sconfirm[16];
		ssize_t n;
		uint32_t passkey = 654321;

		close(smp_fds[0]);
		close(hci_fds[0]);

		/* TK = passkey as 128-bit LE integer */
		memset(tk, 0, sizeof(tk));
		tk[0] = passkey & 0xFF;
		tk[1] = (passkey >> 8) & 0xFF;
		tk[2] = (passkey >> 16) & 0xFF;

		/* 1. Receive Pairing Request */
		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != SMP_PAIRING_REQUEST)
			_exit(1);

		/*
		 * 2. Send Pairing Response: KbdOnly + MITM, no SC.
		 * Because central offers SC but we don't, this falls
		 * back to legacy.  We set no SC flag.
		 */
		pres[0] = SMP_PAIRING_RESPONSE;
		pres[1] = SMP_IO_KEYBOARD_ONLY;
		pres[2] = 0x00;
		pres[3] = SMP_AUTH_BONDING | SMP_AUTH_MITM;	/* no SC */
		pres[4] = 16;
		pres[5] = 0x00;
		pres[6] = SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), 0) < 0)
			_exit(2);

		uint8_t iat = 0;	/* central is public */
		uint8_t rat = 0;	/* periph is public */

		/*
		 * 3. Receive central's Pairing Confirm.
		 * Skip any Keypress Notification PDUs (opcode 0x0E) that
		 * the central may send when keypress notification is
		 * negotiated.
		 */
		for (;;) {
			n = recv(peer_fd, pdu, 17, 0);
			if (n < 1)
				_exit(3);
			if (pdu[0] == SMP_PAIRING_KEYPRESS_NOTIFY)
				continue;
			break;
		}
		if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(mconfirm, pdu + 1, 16);

		/* 4. Generate our random and compute confirm */
		arc4random_buf(srand_val, sizeof(srand_val));
		smp_c1(tk, srand_val, preq, pres, iat, central_addr,
		    rat, periph_addr, sconfirm);

		/* Send confirm (skip keypress notifications) */
		pdu[0] = SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(4);

		/* 5. Receive central's random */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM)
			_exit(5);
		memcpy(mrand_val, pdu + 1, 16);

		/* Verify central's confirm */
		{
			uint8_t verify[16];
			smp_c1(tk, mrand_val, preq, pres, iat, central_addr,
			    rat, periph_addr, verify);
			if (memcmp(verify, mconfirm, 16) != 0)
				_exit(6);
		}

		/* 6. Send our random */
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand_val, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(7);

		/* 7. Key distribution */
		{
			uint8_t ltk_val[16];
			arc4random_buf(ltk_val, sizeof(ltk_val));

			pdu[0] = SMP_ENCRYPTION_INFORMATION;
			memcpy(pdu + 1, ltk_val, 16);
			if (send(peer_fd, pdu, 17, 0) < 0)
				_exit(8);

			pdu[0] = SMP_CENTRAL_IDENTIFICATION;
			memset(pdu + 1, 0, 2);
			memset(pdu + 3, 0, 8);
			if (send(peer_fd, pdu, 11, 0) < 0)
				_exit(9);

			pdu[0] = SMP_IDENTITY_INFORMATION;
			memset(pdu + 1, 0, 16);
			if (send(peer_fd, pdu, 17, 0) < 0)
				_exit(10);

			pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
			pdu[1] = 0x00;
			memcpy(pdu + 2, periph_addr, 6);
			if (send(peer_fd, pdu, 8, 0) < 0)
				_exit(11);
		}

		close(peer_fd);
		_exit(0);
	}

	/* Parent: central */
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "smp_pair returned %d (errno=%d)", ret, errno);
	ATF_CHECK_MSG(db.count > 0, "expected bond, got count=%d", db.count);
	if (db.count > 0)
		ATF_CHECK(db.bonds[0].has_ltk);

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test 28: SC Just Works — responder (peripheral) side
 *
 * Parent calls smp_respond(), child mocks the SC central.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_respond_sc_just_works);
ATF_TC_BODY(test_smp_respond_sc_just_works, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_rsc_jw.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	/* Responder: local=periph, remote=central */
	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: mock SC central (initiator) */
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[66];
		ssize_t n;

		EVP_PKEY *peer_key = NULL;
		uint8_t peer_pk_raw[65];
		uint8_t resp_pk_raw[65];
		uint8_t pka_le[32], pkb_le[32];
		uint8_t dhkey_le[32];
		uint8_t na[16], nb[16];
		uint8_t mackey[16], ltk[16];
		uint8_t ea[16], eb[16];
		uint8_t a1[7], a2[7];
		uint8_t iocap_a[3], iocap_b[3];
		uint8_t r[16];
		uint8_t cb_recv[16], cb_verify[16];

		close(smp_fds[0]);
		close(hci_fds[0]);

		{
			struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
		}

		/* Generate ECDH key pair for initiator */
		if (sc_generate_keypair(&peer_key, peer_pk_raw) != 0)
			_exit(1);

		/*
		 * Send Pairing Request: SC + NoInputNoOutput.
		 * No MITM so model = Just Works.
		 */
		preq[0] = SMP_PAIRING_REQUEST;
		preq[1] = SMP_IO_NO_INPUT_NO_OUTPUT;
		preq[2] = 0x00;
		preq[3] = SMP_AUTH_BONDING | SMP_AUTH_SC;
		preq[4] = 16;
		preq[5] = 0x00;
		preq[6] = SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, preq, sizeof(preq), 0) < 0)
			_exit(2);

		/* Receive Pairing Response */
		n = recv(peer_fd, pres, sizeof(pres), 0);
		if (n < 7 || pres[0] != SMP_PAIRING_RESPONSE)
			_exit(3);

		/*
		 * SC PK exchange: initiator sends first, responder second.
		 * Send our PK (BE -> LE wire).
		 */
		pdu[0] = SMP_PAIRING_PUBLIC_KEY;
		smp_swap_buf(pdu + 1, peer_pk_raw + 1, 32);
		smp_swap_buf(pdu + 33, peer_pk_raw + 33, 32);
		memcpy(pka_le, pdu + 1, 32);	/* initiator PK x LE */
		if (send(peer_fd, pdu, 65, 0) < 0) {
			EVP_PKEY_free(peer_key);
			_exit(4);
		}

		/* Receive responder's PK */
		n = recv(peer_fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY) {
			EVP_PKEY_free(peer_key);
			_exit(5);
		}
		resp_pk_raw[0] = 0x04;
		smp_swap_buf(resp_pk_raw + 1, pdu + 1, 32);
		smp_swap_buf(resp_pk_raw + 33, pdu + 33, 32);
		memcpy(pkb_le, pdu + 1, 32);	/* responder PK x LE */

		/* Compute DHKey */
		if (sc_compute_dhkey(peer_key, resp_pk_raw, dhkey_le) != 0) {
			EVP_PKEY_free(peer_key);
			_exit(6);
		}
		EVP_PKEY_free(peer_key);

		/*
		 * Stage 1: Initiator receives Cb, sends Na, receives Nb.
		 */
		/* Receive Cb from responder */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM)
			_exit(7);
		memcpy(cb_recv, pdu + 1, 16);

		/* Generate and send Na */
		arc4random_buf(na, sizeof(na));
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, na, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(8);

		/* Receive Nb */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM)
			_exit(9);
		memcpy(nb, pdu + 1, 16);

		/* Verify Cb = f4(PKbx, PKax, Nb, 0) */
		smp_f4(pkb_le, pka_le, nb, 0, cb_verify);
		if (memcmp(cb_recv, cb_verify, 16) != 0)
			_exit(10);

		/*
		 * Stage 2: DHKey checks.
		 * a1 = initiator (central = remote of responder)
		 * a2 = responder (periph = local of responder)
		 */
		test_pack_addr(a1, central_addr, BDADDR_LE_PUBLIC);
		test_pack_addr(a2, periph_addr, BDADDR_LE_PUBLIC);

		iocap_a[0] = preq[1]; iocap_a[1] = preq[2];
		iocap_a[2] = preq[3];
		iocap_b[0] = pres[1]; iocap_b[1] = pres[2];
		iocap_b[2] = pres[3];

		memset(r, 0, sizeof(r));

		smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
		smp_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
		smp_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);

		/* Send Ea */
		pdu[0] = SMP_PAIRING_DHKEY_CHECK;
		memcpy(pdu + 1, ea, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(11);

		/* Receive Eb, verify */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_DHKEY_CHECK)
			_exit(12);
		if (memcmp(pdu + 1, eb, 16) != 0)
			_exit(13);

		/*
		 * Receive key distribution from responder (IdKey).
		 * The responder distributes first in SC mode.
		 */
		{
			int exp = 0;
			if (pres[6] & SMP_KEY_DIST_ID_KEY)
				exp += 2;
			int j;
			for (j = 0; j < exp; j++) {
				n = recv(peer_fd, pdu, sizeof(pdu), 0);
				if (n < 1)
					break;

				/* Verify responder sends non-zero IRK (H5 fix) */
				if (pdu[0] == SMP_IDENTITY_INFORMATION &&
				    n >= 17) {
					uint8_t zero_irk[16];
					memset(zero_irk, 0, sizeof(zero_irk));
					if (memcmp(pdu + 1, zero_irk, 16) == 0)
						_exit(99);
				}
			}
		}

		close(peer_fd);
		_exit(0);
	}

	/* Parent: responder */
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_respond(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "smp_respond returned %d (errno=%d)",
	    ret, errno);
	ATF_CHECK_MSG(db.count > 0, "expected bond stored, got count=%d",
	    db.count);
	if (db.count > 0) {
		ATF_CHECK(db.bonds[0].has_ltk);
		ATF_CHECK(db.bonds[0].is_sc);
	}

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test: SC Numeric Comparison — responder (peripheral) side
 *
 * Parent calls smp_respond(), child mocks the SC central.
 * Both sides have DisplayYesNo (IO=1) with MITM.
 * SC Table 2.8: DispYN vs DispYN => Numeric Comparison (model 2).
 * The DUT (responder) will call numcmp_cb to confirm the value.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_respond_sc_numeric_comparison);
ATF_TC_BODY(test_smp_respond_sc_numeric_comparison, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_rsc_nc.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	/* Responder: local=periph, remote=central */
	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC);

	/* Set DisplayYesNo IO cap and auto-accept numeric comparison */
	sc.io_capability = SMP_IO_DISPLAY_YESNO;
	sc.numcmp_cb = test_numcmp_accept_cb;
	sc.numcmp_cb_arg = NULL;

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: mock SC central (initiator) for Numeric Comparison */
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[66];
		ssize_t n;

		EVP_PKEY *peer_key = NULL;
		uint8_t peer_pk_raw[65];
		uint8_t resp_pk_raw[65];
		uint8_t pka_le[32], pkb_le[32];
		uint8_t dhkey_le[32];
		uint8_t na[16], nb[16];
		uint8_t mackey[16], ltk[16];
		uint8_t ea[16], eb[16];
		uint8_t a1[7], a2[7];
		uint8_t iocap_a[3], iocap_b[3];
		uint8_t r[16];
		uint8_t cb_recv[16], cb_verify[16];

		close(smp_fds[0]);
		close(hci_fds[0]);

		{
			struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
		}

		/* Generate ECDH key pair for initiator */
		if (sc_generate_keypair(&peer_key, peer_pk_raw) != 0)
			_exit(1);

		/*
		 * Send Pairing Request: SC + DisplayYesNo + MITM.
		 * DispYN vs DispYN => Numeric Comparison.
		 */
		preq[0] = SMP_PAIRING_REQUEST;
		preq[1] = SMP_IO_DISPLAY_YESNO;
		preq[2] = 0x00;
		preq[3] = SMP_AUTH_BONDING | SMP_AUTH_MITM | SMP_AUTH_SC;
		preq[4] = 16;
		preq[5] = 0x00;
		preq[6] = SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, preq, sizeof(preq), 0) < 0)
			_exit(2);

		/* Receive Pairing Response */
		n = recv(peer_fd, pres, sizeof(pres), 0);
		if (n < 7 || pres[0] != SMP_PAIRING_RESPONSE)
			_exit(3);

		/*
		 * SC PK exchange: initiator sends first, responder second.
		 * Send our PK (BE -> LE wire).
		 */
		pdu[0] = SMP_PAIRING_PUBLIC_KEY;
		smp_swap_buf(pdu + 1, peer_pk_raw + 1, 32);
		smp_swap_buf(pdu + 33, peer_pk_raw + 33, 32);
		memcpy(pka_le, pdu + 1, 32);	/* initiator PK x LE */
		if (send(peer_fd, pdu, 65, 0) < 0) {
			EVP_PKEY_free(peer_key);
			_exit(4);
		}

		/* Receive responder's PK */
		n = recv(peer_fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY) {
			EVP_PKEY_free(peer_key);
			_exit(5);
		}
		resp_pk_raw[0] = 0x04;
		smp_swap_buf(resp_pk_raw + 1, pdu + 1, 32);
		smp_swap_buf(resp_pk_raw + 33, pdu + 33, 32);
		memcpy(pkb_le, pdu + 1, 32);	/* responder PK x LE */

		/* Compute DHKey */
		if (sc_compute_dhkey(peer_key, resp_pk_raw, dhkey_le) != 0) {
			EVP_PKEY_free(peer_key);
			_exit(6);
		}
		EVP_PKEY_free(peer_key);

		/*
		 * Stage 1: Numeric Comparison uses the same confirm/nonce
		 * exchange as Just Works.
		 * Initiator receives Cb, sends Na, receives Nb.
		 */
		/* Receive Cb from responder */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM)
			_exit(7);
		memcpy(cb_recv, pdu + 1, 16);

		/* Generate and send Na */
		arc4random_buf(na, sizeof(na));
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, na, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(8);

		/* Receive Nb */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM)
			_exit(9);
		memcpy(nb, pdu + 1, 16);

		/* Verify Cb = f4(PKbx, PKax, Nb, 0) */
		smp_f4(pkb_le, pka_le, nb, 0, cb_verify);
		if (memcmp(cb_recv, cb_verify, 16) != 0)
			_exit(10);

		/*
		 * Numeric comparison: both sides compute g2 and confirm.
		 * No PDU exchanged — just local UI confirmation.
		 * The DUT calls test_numcmp_accept_cb which returns 0.
		 */

		/*
		 * Stage 2: DHKey checks.
		 * a1 = initiator (central = remote of responder)
		 * a2 = responder (periph = local of responder)
		 */
		test_pack_addr(a1, central_addr, BDADDR_LE_PUBLIC);
		test_pack_addr(a2, periph_addr, BDADDR_LE_PUBLIC);

		iocap_a[0] = preq[1]; iocap_a[1] = preq[2];
		iocap_a[2] = preq[3];
		iocap_b[0] = pres[1]; iocap_b[1] = pres[2];
		iocap_b[2] = pres[3];

		memset(r, 0, sizeof(r));

		smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
		smp_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
		smp_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);

		/* Send Ea */
		pdu[0] = SMP_PAIRING_DHKEY_CHECK;
		memcpy(pdu + 1, ea, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(11);

		/* Receive Eb, verify */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_DHKEY_CHECK)
			_exit(12);
		if (memcmp(pdu + 1, eb, 16) != 0)
			_exit(13);

		/*
		 * Receive key distribution from responder (IdKey).
		 * The responder distributes first in SC mode.
		 */
		{
			int exp = 0;
			if (pres[6] & SMP_KEY_DIST_ID_KEY)
				exp += 2;
			int j;
			for (j = 0; j < exp; j++) {
				n = recv(peer_fd, pdu, sizeof(pdu), 0);
				if (n < 1)
					break;
			}
		}

		close(peer_fd);
		_exit(0);
	}

	/* Parent: responder */
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_respond(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "smp_respond returned %d (errno=%d)",
	    ret, errno);
	ATF_CHECK_MSG(db.count > 0, "expected bond stored, got count=%d",
	    db.count);
	if (db.count > 0) {
		ATF_CHECK(db.bonds[0].has_ltk);
		ATF_CHECK(db.bonds[0].is_sc);
	}

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test 29: SC Passkey Entry — responder (peripheral) side
 *
 * Parent calls smp_respond(), child mocks the SC central.
 * Central has KeyboardDisplay (IO=4), responder has KeyboardDisplay (IO=4).
 * SC Table 2.8: KbdDisp vs KbdDisp => Passkey Entry.
 * 20 rounds of confirm/nonce exchange.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_respond_sc_passkey_entry);
ATF_TC_BODY(test_smp_respond_sc_passkey_entry, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_rsc_pk.XXXXXX";
	int bond_fd;
	pid_t pid;
	uint32_t test_passkey = 123456;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	/* Responder: local=periph, remote=central */
	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC);

	sc.io_capability = SMP_IO_KEYBOARD_DISPLAY;
	sc.sc_only = false;
	sc.passkey_cb = test_passkey_cb;
	sc.passkey_cb_arg = &test_passkey;

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: mock SC central (initiator) for Passkey Entry */
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[66];
		ssize_t n;

		EVP_PKEY *peer_key = NULL;
		uint8_t peer_pk_raw[65];
		uint8_t resp_pk_raw[65];
		uint8_t pka_le[32], pkb_le[32];
		uint8_t dhkey_le[32];
		uint8_t na[16], nb[16];
		uint8_t mackey[16], ltk[16];
		uint8_t ea[16], eb[16];
		uint8_t a1[7], a2[7];
		uint8_t iocap_a[3], iocap_b[3];
		uint8_t ra[16];
		uint32_t passkey = 123456;
		int i;

		close(smp_fds[0]);
		close(hci_fds[0]);

		{
			struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
		}

		/* Generate ECDH key pair for initiator */
		if (sc_generate_keypair(&peer_key, peer_pk_raw) != 0)
			_exit(1);

		/*
		 * Send Pairing Request: SC + KeyboardOnly + MITM.
		 * KbdOnly vs KbdDisp => Passkey Entry (Table 2.8).
		 */
		preq[0] = SMP_PAIRING_REQUEST;
		preq[1] = SMP_IO_KEYBOARD_ONLY;
		preq[2] = 0x00;
		preq[3] = SMP_AUTH_BONDING | SMP_AUTH_MITM | SMP_AUTH_SC;
		preq[4] = 16;
		preq[5] = 0x00;
		preq[6] = SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, preq, sizeof(preq), 0) < 0)
			_exit(2);

		/* Receive Pairing Response */
		n = recv(peer_fd, pres, sizeof(pres), 0);
		if (n < 7 || pres[0] != SMP_PAIRING_RESPONSE)
			_exit(3);

		/*
		 * SC PK exchange: initiator sends first, responder second.
		 */
		pdu[0] = SMP_PAIRING_PUBLIC_KEY;
		smp_swap_buf(pdu + 1, peer_pk_raw + 1, 32);
		smp_swap_buf(pdu + 33, peer_pk_raw + 33, 32);
		memcpy(pka_le, pdu + 1, 32);
		if (send(peer_fd, pdu, 65, 0) < 0) {
			EVP_PKEY_free(peer_key);
			_exit(4);
		}

		/* Receive responder's PK */
		n = recv(peer_fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY) {
			EVP_PKEY_free(peer_key);
			_exit(5);
		}
		resp_pk_raw[0] = 0x04;
		smp_swap_buf(resp_pk_raw + 1, pdu + 1, 32);
		smp_swap_buf(resp_pk_raw + 33, pdu + 33, 32);
		memcpy(pkb_le, pdu + 1, 32);

		/* Compute DHKey */
		if (sc_compute_dhkey(peer_key, resp_pk_raw, dhkey_le) != 0) {
			EVP_PKEY_free(peer_key);
			_exit(6);
		}
		EVP_PKEY_free(peer_key);

		/*
		 * 20-round Passkey Entry (initiator side).
		 * For each bit i: ri = 0x80 | ((passkey >> i) & 1)
		 * Initiator: compute Cai, send Cai, receive Cbi,
		 *            send Nai, receive Nbi, verify Cbi.
		 */
		for (i = 0; i < 20; i++) {
			uint8_t nai[16], nbi[16];
			uint8_t cai[16], cbi_recv[16], cbi_verify[16];
			uint8_t ri;

			ri = 0x80 | ((passkey >> i) & 1);

			/* Compute and send Cai = f4(PKax, PKbx, Nai, ri) */
			arc4random_buf(nai, sizeof(nai));
			smp_f4(pka_le, pkb_le, nai, ri, cai);
			pdu[0] = SMP_PAIRING_CONFIRM;
			memcpy(pdu + 1, cai, 16);
			if (send(peer_fd, pdu, 17, 0) < 0)
				_exit(20 + i);

			/* Receive Cbi (responder confirm) */
			n = recv(peer_fd, pdu, 17, 0);
			if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM)
				_exit(40 + i);
			memcpy(cbi_recv, pdu + 1, 16);

			/* Send Nai */
			pdu[0] = SMP_PAIRING_RANDOM;
			memcpy(pdu + 1, nai, 16);
			if (send(peer_fd, pdu, 17, 0) < 0)
				_exit(60 + i);

			/* Receive Nbi */
			n = recv(peer_fd, pdu, 17, 0);
			if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM)
				_exit(80 + i);
			memcpy(nbi, pdu + 1, 16);

			/* Verify Cbi = f4(PKbx, PKax, Nbi, ri) */
			smp_f4(pkb_le, pka_le, nbi, ri, cbi_verify);
			if (memcmp(cbi_recv, cbi_verify, 16) != 0)
				_exit(100 + i);

			/* Keep last round nonces */
			memcpy(na, nai, 16);
			memcpy(nb, nbi, 16);
		}

		/* Stage 2: DHKey checks */
		test_pack_addr(a1, central_addr, BDADDR_LE_PUBLIC);
		test_pack_addr(a2, periph_addr, BDADDR_LE_PUBLIC);

		iocap_a[0] = preq[1]; iocap_a[1] = preq[2];
		iocap_a[2] = preq[3];
		iocap_b[0] = pres[1]; iocap_b[1] = pres[2];
		iocap_b[2] = pres[3];

		/* ra = passkey as 128-bit LE */
		memset(ra, 0, sizeof(ra));
		ra[0] = passkey & 0xFF;
		ra[1] = (passkey >> 8) & 0xFF;
		ra[2] = (passkey >> 16) & 0xFF;

		smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
		smp_f6(mackey, na, nb, ra, iocap_a, a1, a2, ea);
		smp_f6(mackey, nb, na, ra, iocap_b, a2, a1, eb);

		/* Send Ea */
		pdu[0] = SMP_PAIRING_DHKEY_CHECK;
		memcpy(pdu + 1, ea, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(141);

		/* Receive Eb, verify */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_DHKEY_CHECK)
			_exit(142);
		if (memcmp(pdu + 1, eb, 16) != 0)
			_exit(143);

		/*
		 * Receive key distribution from responder (IdKey).
		 */
		{
			int exp = 0;
			if (pres[6] & SMP_KEY_DIST_ID_KEY)
				exp += 2;
			int j;
			for (j = 0; j < exp; j++) {
				n = recv(peer_fd, pdu, sizeof(pdu), 0);
				if (n < 1)
					break;
			}
		}

		close(peer_fd);
		_exit(0);
	}

	/* Parent: responder */
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_respond(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "smp_respond returned %d (errno=%d)",
	    ret, errno);
	ATF_CHECK_MSG(db.count > 0, "expected bond stored, got count=%d",
	    db.count);
	if (db.count > 0) {
		ATF_CHECK(db.bonds[0].has_ltk);
		ATF_CHECK(db.bonds[0].is_sc);
	}

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test: Global rate limiter rejects after 30 attempts
 *
 * smp_rate_check() is static in smp.c, so we exercise it indirectly
 * via smp_respond().  Each call sends a valid Pairing Request from a
 * unique address, triggering the global counter.  The first 30
 * attempts pass rate-checking (they may fail later in the handshake
 * because we close the peer), but attempt #31 must be rejected by
 * the rate limiter with errno == EACCES.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_rate_limit_global);
ATF_TC_BODY(test_smp_rate_limit_global, tc)
{
	int i;
	char bond_path[] = "/tmp/blued_test_ratelim.XXXXXX";
	int bond_fd;

	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	/*
	 * Ignore SIGPIPE: after rate-checking passes, smp_respond
	 * tries to send a Pairing Response to the peer socket.  We
	 * close the peer side after sending the request, so the
	 * response write hits a broken pipe.
	 */
	signal(SIGPIPE, SIG_IGN);

	/*
	 * Send 31 pairing attempts, each from a unique address.
	 * The global rate limit (SMP_RATE_LIMIT_GLOBAL_MAX = 30) should
	 * allow the first 30 and reject the 31st.
	 */
	for (i = 0; i < 31; i++) {
		struct smp_conn sc;
		struct smp_bond_db db;
		int smp_fds[2], hci_fds[2];
		uint8_t remote[6];
		uint8_t preq[7];
		int ret;

		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0,
		    smp_fds) == 0);
		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0,
		    hci_fds) == 0);

		/* Unique remote address for each attempt */
		memset(remote, 0, sizeof(remote));
		remote[0] = (uint8_t)(i + 1);
		remote[1] = (uint8_t)((i + 1) >> 8);

		setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
		    periph_addr, BDADDR_LE_PUBLIC,
		    remote, BDADDR_LE_PUBLIC);

		/* Send a valid Pairing Request from the peer side */
		preq[0] = SMP_PAIRING_REQUEST;
		preq[1] = SMP_IO_NO_INPUT_NO_OUTPUT;
		preq[2] = 0x00;
		preq[3] = SMP_AUTH_BONDING;
		preq[4] = 16;
		preq[5] = 0x00;
		preq[6] = SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY;
		ATF_REQUIRE(send(smp_fds[1], preq, sizeof(preq), 0) ==
		    (ssize_t)sizeof(preq));

		/*
		 * Close the peer side so the handshake fails after
		 * rate-checking.  We only care whether smp_respond()
		 * rejects due to rate limiting vs some other error.
		 */
		close(smp_fds[1]);
		close(hci_fds[1]);

		ret = smp_respond(&sc);

		if (i < 30) {
			/*
			 * First 30 attempts pass the rate limiter but
			 * fail later (peer closed).  Verify the error
			 * is NOT EACCES (which would mean rate-limited).
			 */
			ATF_CHECK_MSG(errno != EACCES,
			    "attempt %d: unexpectedly rate-limited", i);
		} else {
			/*
			 * Attempt #31: must be rejected by the global
			 * rate limiter (errno == EACCES).
			 */
			ATF_CHECK_EQ_MSG(ret, -1,
			    "attempt %d: expected rejection", i);
			ATF_CHECK_EQ_MSG(errno, EACCES,
			    "attempt %d: expected EACCES, got %d",
			    i, errno);
		}

		close(smp_fds[0]);
		close(hci_fds[0]);
	}

	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test: initiator distributes LTK + IRK in key distribution phase.
 *
 * After legacy Just Works pairing completes, verify the bond database
 * contains an LTK (has_ltk).  The init_key_dist field in the Pairing
 * Request controls what the initiator sends.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_init_key_distribution);
ATF_TC_BODY(test_smp_init_key_distribution, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_kd.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[65];
		uint8_t tk[16], srand[16], mrand[16];
		uint8_t mconfirm[16], sconfirm[16];
		uint8_t our_ltk[16], our_irk[16];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		memset(tk, 0, sizeof(tk));

		/* Receive Pairing Request */
		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != SMP_PAIRING_REQUEST)
			_exit(1);

		/* Verify initiator requests LTK+IRK distribution */
		ATF_REQUIRE((preq[5] & SMP_KEY_DIST_ENC_KEY) != 0 ||
		    (preq[6] & SMP_KEY_DIST_ENC_KEY) != 0);

		/* Send response requesting LTK+IRK from responder */
		pres[0] = SMP_PAIRING_RESPONSE;
		pres[1] = SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = SMP_AUTH_BONDING;
		pres[4] = 16;
		pres[5] = 0x00;
		pres[6] = SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), 0) < 0)
			_exit(2);

		uint8_t iat = 0, rat = 0;

		/* Receive confirm */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(mconfirm, pdu + 1, 16);

		/* Generate random, compute confirm, send it */
		arc4random_buf(srand, sizeof(srand));
		smp_c1(tk, srand, preq, pres, iat, central_addr,
		    rat, periph_addr, sconfirm);

		pdu[0] = SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(4);

		/* Receive random */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM)
			_exit(5);
		memcpy(mrand, pdu + 1, 16);

		/* Verify confirm */
		{
			uint8_t verify[16];
			smp_c1(tk, mrand, preq, pres, iat, central_addr,
			    rat, periph_addr, verify);
			if (memcmp(verify, mconfirm, 16) != 0)
				_exit(6);
		}

		/* Send our random */
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(7);

		/* Send key distribution */
		arc4random_buf(our_ltk, sizeof(our_ltk));
		memset(our_irk, 0, sizeof(our_irk));

		pdu[0] = SMP_ENCRYPTION_INFORMATION;
		memcpy(pdu + 1, our_ltk, 16);
		send(peer_fd, pdu, 17, 0);

		pdu[0] = SMP_CENTRAL_IDENTIFICATION;
		memset(pdu + 1, 0, 10);
		send(peer_fd, pdu, 11, 0);

		pdu[0] = SMP_IDENTITY_INFORMATION;
		memcpy(pdu + 1, our_irk, 16);
		send(peer_fd, pdu, 17, 0);

		pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = 0x00;
		memcpy(pdu + 2, periph_addr, 6);
		send(peer_fd, pdu, 8, 0);

		close(peer_fd);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "smp_pair returned %d", ret);
	ATF_CHECK_MSG(db.count > 0, "bond should be stored");
	if (db.count > 0) {
		ATF_CHECK(db.bonds[0].has_ltk);
	}

	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test: min_key_size field is used during pairing.
 *
 * Set sc.min_key_size = 12 (> 7), then pair with a peer that offers
 * max_key_size = 10.  The central should reject with
 * SMP_ERR_ENCRYPTION_KEY_SIZE.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_min_key_size_configurable);
ATF_TC_BODY(test_smp_min_key_size_configurable, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_mks.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);
	sc.min_key_size = 12; /* require at least 12 */

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);

		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != SMP_PAIRING_REQUEST)
			_exit(1);

		/* Respond with max_key_size=10 (below our min of 12) */
		pres[0] = SMP_PAIRING_RESPONSE;
		pres[1] = SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = SMP_AUTH_BONDING;
		pres[4] = 10; /* peer's max key size */
		pres[5] = 0x00;
		pres[6] = SMP_KEY_DIST_ENC_KEY;
		send(peer_fd, pres, sizeof(pres), 0);

		/* Drain any error response */
		{
			uint8_t buf[65];
			recv(peer_fd, buf, sizeof(buf), 0);
		}

		close(peer_fd);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK(ret == -1);
	ATF_CHECK_EQ(db.count, 0);

	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test: SMP rate limiter — verify the global counter persists.
 *
 * After test_smp_rate_limit_global burns through 30 attempts,
 * subsequent attempts from new addresses are also rejected.
 * This test uses the same approach but checks that the 31st attempt
 * is rejected (same as the global test but verifies the counter
 * doesn't reset between calls).
 *
 * Note: We reduce the recv timeout to 1s to keep the test fast.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_rate_limit_backoff);
ATF_TC_BODY(test_smp_rate_limit_backoff, tc)
{
	char bond_path[] = "/tmp/blued_test_rlbo.XXXXXX";
	int bond_fd;
	int i;
	int reject_count = 0;

	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);
	signal(SIGPIPE, SIG_IGN);

	/*
	 * Send 32 pairing attempts.  Use 1s recv timeout instead of 5s
	 * to keep the test fast.  After 30 attempts, the rate limiter
	 * should reject with EACCES immediately (no recv delay).
	 */
	for (i = 0; i < 32; i++) {
		struct smp_conn sc;
		struct smp_bond_db db;
		int smp_fds[2], hci_fds[2];
		uint8_t remote[6];
		uint8_t preq[7];
		int ret;

		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0,
		    smp_fds) == 0);
		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0,
		    hci_fds) == 0);

		memset(remote, 0, sizeof(remote));
		remote[0] = (uint8_t)(i + 1);
		remote[1] = (uint8_t)((i + 1) >> 8);

		setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
		    periph_addr, BDADDR_LE_PUBLIC,
		    remote, BDADDR_LE_PUBLIC);

		/* Use 1s timeout to speed up the test */
		{
			struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
			setsockopt(smp_fds[0], SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
		}

		preq[0] = SMP_PAIRING_REQUEST;
		preq[1] = SMP_IO_NO_INPUT_NO_OUTPUT;
		preq[2] = 0x00;
		preq[3] = SMP_AUTH_BONDING;
		preq[4] = 16;
		preq[5] = 0x00;
		preq[6] = SMP_KEY_DIST_ENC_KEY;
		send(smp_fds[1], preq, sizeof(preq), 0);

		ret = smp_respond(&sc);
		if (ret == -1 && errno == EACCES)
			reject_count++;

		close(smp_fds[0]);
		close(smp_fds[1]);
		close(hci_fds[0]);
		close(hci_fds[1]);
	}

	ATF_CHECK_MSG(reject_count >= 2,
	    "expected at least 2 rate-limited rejections, got %d",
	    reject_count);

	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test: smp_close zeroes local and remote addresses
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_close_zeros_addresses);
ATF_TC_BODY(test_smp_close_zeros_addresses, tc)
{
	struct smp_conn sc;
	uint8_t zero[6];
	int smp_fds[2];

	memset(zero, 0, sizeof(zero));
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);

	memset(&sc, 0, sizeof(sc));
	sc.fd = smp_fds[0];
	memset(sc.local_addr, 0xAA, 6);
	memset(sc.remote_addr, 0xBB, 6);

	smp_close(&sc);

	ATF_CHECK_EQ(sc.fd, -1);
	ATF_CHECK(memcmp(sc.local_addr, zero, 6) == 0);
	ATF_CHECK(memcmp(sc.remote_addr, zero, 6) == 0);

	close(smp_fds[1]);
}

/* ================================================================
 * Test: smp_rpa_matches with known IRK and generated RPA
 *
 * Generate an RPA from a known IRK using the spec algorithm
 * (ah function), then verify smp_rpa_matches returns true.
 * Also verify a non-matching address returns false.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_rpa_matches);
ATF_TC_BODY(test_smp_rpa_matches, tc)
{
	/*
	 * Use a known IRK from the Bluetooth spec test vectors.
	 * Core Spec Vol 3 Part H Section 2.2.2:
	 *   IRK = 0x0102030405060708090A0B0C0D0E0F10 (big-endian)
	 * In little-endian wire order: reversed.
	 */
	uint8_t irk[16] = {
		0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09,
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
	};
	uint8_t prand[3], plaintext[16], cipher[16];
	uint8_t rpa[6];

	/*
	 * Generate an RPA:
	 * 1. Choose prand with upper 2 bits = 01 (resolvable)
	 * 2. Compute ah(IRK, prand) = AES128(IRK, prand_padded)[0..2]
	 * 3. RPA = hash(3) || prand(3)
	 */
	prand[0] = 0xDE;
	prand[1] = 0xAD;
	prand[2] = 0x42;  /* bits[7:6] = 01 => resolvable */

	memset(plaintext, 0, sizeof(plaintext));
	plaintext[0] = prand[0];
	plaintext[1] = prand[1];
	plaintext[2] = prand[2];
	ATF_REQUIRE(smp_aes128(irk, plaintext, cipher) == 0);

	rpa[0] = cipher[0];
	rpa[1] = cipher[1];
	rpa[2] = cipher[2];
	rpa[3] = prand[0];
	rpa[4] = prand[1];
	rpa[5] = prand[2];

	/* Should match */
	ATF_CHECK(smp_rpa_matches(irk, rpa));

	/* Different IRK should NOT match */
	uint8_t wrong_irk[16];
	memset(wrong_irk, 0xAA, sizeof(wrong_irk));
	ATF_CHECK(!smp_rpa_matches(wrong_irk, rpa));

	/* Corrupted hash byte should NOT match */
	uint8_t bad_rpa[6];
	memcpy(bad_rpa, rpa, 6);
	bad_rpa[0] ^= 0xFF;
	ATF_CHECK(!smp_rpa_matches(irk, bad_rpa));
}

/* ================================================================
 * Test: Legacy OOB pairing — central (initiator) side
 *
 * OOB pairing uses a pre-shared TK (Temporary Key) exchanged out of band.
 * When both sides have OOB data, the pairing confirm/random exchange uses
 * the OOB TK instead of a passkey or zero.
 * Core Spec Vol 3 Part H Section 2.3.5.3
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_pair_oob_legacy);
ATF_TC_BODY(test_smp_pair_oob_legacy, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_pair_oob.XXXXXX";
	int bond_fd;
	pid_t pid;
	static const uint8_t oob_tk[16] = {
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
	};
	struct smp_oob_legacy oob_legacy;
	struct smp_oob_data oob_data;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	/* Set up OOB data with known TK */
	memcpy(oob_legacy.tk, oob_tk, 16);
	memset(&oob_data, 0, sizeof(oob_data));
	oob_data.legacy = &oob_legacy;
	sc.oob = &oob_data;
	sc.io_capability = SMP_IO_NO_INPUT_NO_OUTPUT;

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: mock peripheral that also has the OOB TK */
		int peer_fd = smp_fds[1];
		uint8_t pdu[65];
		uint8_t preq[7], pres[7];
		uint8_t srand[16], mrand[16];
		uint8_t mconfirm[16], sconfirm[16];
		uint8_t our_ltk[16], our_irk[16];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);

		/* 1. Receive Pairing Request */
		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != SMP_PAIRING_REQUEST)
			_exit(1);

		/* Verify OOB flag is set in pairing request */
		if (preq[2] != 0x01)	/* OOB Data Flag */
			_exit(2);

		/* 2. Send Pairing Response with OOB flag set */
		pres[0] = SMP_PAIRING_RESPONSE;
		pres[1] = SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x01;	/* OOB data present */
		pres[3] = SMP_AUTH_BONDING;
		pres[4] = 16;		/* max key size */
		pres[5] = 0x00;
		pres[6] = SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), 0) < 0)
			_exit(3);

		uint8_t iat = 0;  /* central is public */
		uint8_t rat = 0;  /* periph is public */

		/* 3. Receive Pairing Confirm from central */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM)
			_exit(4);
		memcpy(mconfirm, pdu + 1, 16);

		/* 4. Generate our random and compute confirm using OOB TK */
		arc4random_buf(srand, sizeof(srand));
		smp_c1(oob_tk, srand, preq, pres, iat, central_addr,
		    rat, periph_addr, sconfirm);

		pdu[0] = SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(5);

		/* 5. Receive Pairing Random from central */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM)
			_exit(6);
		memcpy(mrand, pdu + 1, 16);

		/* Verify central's confirm using OOB TK */
		{
			uint8_t verify[16];
			smp_c1(oob_tk, mrand, preq, pres, iat, central_addr,
			    rat, periph_addr, verify);
			if (memcmp(verify, mconfirm, 16) != 0)
				_exit(7);
		}

		/* 6. Send our random */
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(8);

		/* 7. Key distribution */
		arc4random_buf(our_ltk, sizeof(our_ltk));
		memset(our_irk, 0, sizeof(our_irk));

		pdu[0] = SMP_ENCRYPTION_INFORMATION;
		memcpy(pdu + 1, our_ltk, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(9);

		pdu[0] = SMP_CENTRAL_IDENTIFICATION;
		memset(pdu + 1, 0, 2);
		memset(pdu + 3, 0, 8);
		if (send(peer_fd, pdu, 11, 0) < 0)
			_exit(10);

		pdu[0] = SMP_IDENTITY_INFORMATION;
		memcpy(pdu + 1, our_irk, 16);
		if (send(peer_fd, pdu, 17, 0) < 0)
			_exit(11);

		pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = 0x00;	/* public */
		memcpy(pdu + 2, periph_addr, 6);
		if (send(peer_fd, pdu, 8, 0) < 0)
			_exit(12);

		close(peer_fd);
		_exit(0);
	}

	/* Parent: central side */
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "smp_pair with OOB TK should succeed");

	/* Verify bond was stored */
	struct smp_bond *bond = smp_find_bond(&db, periph_addr,
	    BDADDR_LE_PUBLIC);
	ATF_CHECK_MSG(bond != NULL, "bond should exist after OOB pairing");
	if (bond != NULL)
		ATF_CHECK(bond->has_ltk);

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* SMP pairing handshake tests — central (initiator) */
	ATF_TP_ADD_TC(tp, test_smp_pair_legacy_just_works);
	ATF_TP_ADD_TC(tp, test_smp_pair_legacy_peer_rejects);
	ATF_TP_ADD_TC(tp, test_smp_pair_invalid_key_size);
	ATF_TP_ADD_TC(tp, test_smp_pair_wrong_opcode);

	/* SMP pairing handshake tests — peripheral (responder) */
	ATF_TP_ADD_TC(tp, test_smp_respond_legacy_just_works);
	ATF_TP_ADD_TC(tp, test_smp_respond_peer_bad_request);

	/* Bond database extended tests */
	ATF_TP_ADD_TC(tp, test_bond_find_by_addr);
	ATF_TP_ADD_TC(tp, test_bond_find_not_found);
	ATF_TP_ADD_TC(tp, test_bond_upsert);
	ATF_TP_ADD_TC(tp, test_bond_save_load_empty);
	ATF_TP_ADD_TC(tp, test_bond_save_load_irk);
	ATF_TP_ADD_TC(tp, test_bond_legacy_file);
	ATF_TP_ADD_TC(tp, test_bond_corrupt_size);

	/* CCCD persistence tests */
	ATF_TP_ADD_TC(tp, test_bond_save_cccds);
	ATF_TP_ADD_TC(tp, test_bond_restore_cccds);

	/* smp_open_accepted and encrypt_with_ltk */
	ATF_TP_ADD_TC(tp, test_smp_open_accepted);
	ATF_TP_ADD_TC(tp, test_smp_encrypt_with_ltk);
	ATF_TP_ADD_TC(tp, test_smp_encrypt_with_ltk_no_ltk);

	/* SC (Secure Connections) pairing tests — central */
	ATF_TP_ADD_TC(tp, test_smp_pair_sc_just_works);
	ATF_TP_ADD_TC(tp, test_smp_pair_sc_passkey_entry);
	ATF_TP_ADD_TC(tp, test_smp_pair_sc_numeric_comparison);
	ATF_TP_ADD_TC(tp, test_smp_pair_sc_debug_key_rejected);
	ATF_TP_ADD_TC(tp, test_smp_pair_sc_key_size_rejected);
	ATF_TP_ADD_TC(tp, test_smp_sc_only_rejects_legacy);

	/* CTKD tests */
	ATF_TP_ADD_TC(tp, test_smp_ctkd_requires_mitm);
	ATF_TP_ADD_TC(tp, test_smp_ctkd_with_mitm);

	/* SC OOB data generation */
	ATF_TP_ADD_TC(tp, test_smp_generate_sc_oob);

	/* Legacy Passkey Entry */
	ATF_TP_ADD_TC(tp, test_smp_pair_legacy_passkey_entry);

	/* IO capability validation */
	ATF_TP_ADD_TC(tp, test_smp_invalid_io_capability);

	/* SC pairing — peripheral (responder) */
	ATF_TP_ADD_TC(tp, test_smp_respond_sc_just_works);
	ATF_TP_ADD_TC(tp, test_smp_respond_sc_numeric_comparison);
	ATF_TP_ADD_TC(tp, test_smp_respond_sc_passkey_entry);

	/* Rate limiting */
	ATF_TP_ADD_TC(tp, test_smp_rate_limit_global);

	/* Key distribution and configuration */
	ATF_TP_ADD_TC(tp, test_smp_init_key_distribution);
	ATF_TP_ADD_TC(tp, test_smp_min_key_size_configurable);
	ATF_TP_ADD_TC(tp, test_smp_rate_limit_backoff);
	ATF_TP_ADD_TC(tp, test_smp_close_zeros_addresses);

	/* RPA resolution */
	ATF_TP_ADD_TC(tp, test_smp_rpa_matches);

	/* Legacy OOB pairing */
	ATF_TP_ADD_TC(tp, test_smp_pair_oob_legacy);

	return (atf_no_error());
}
