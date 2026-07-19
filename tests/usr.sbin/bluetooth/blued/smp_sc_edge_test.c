/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF edge / negative tests for LE Secure Connections pairing (smp_sc.c).
 *
 * These drive the four SC entry points directly
 *   smp_pair_sc()            initiator Just Works / Numeric Comparison / OOB
 *   smp_pair_sc_passkey()    initiator Passkey Entry
 *   smp_respond_sc()         responder Just Works / Numeric Comparison / OOB
 *   smp_respond_sc_passkey() responder Passkey Entry
 * so that error and abort branches that the happy-path pairing tests never
 * reach are exercised: missing passkey / numeric-comparison callbacks and
 * user cancellation, OOB-not-available, invalid / unexpected mid-flow
 * opcodes, injected Pairing Failed, confirm-value mismatch, and DHKey-check
 * failure.
 *
 * A fork(2)ed mock peer speaks the minimum of the protocol needed to steer
 * the device-under-test to each branch.  The L2CAP SMP channel is a
 * SOCK_SEQPACKET socketpair.  Because SEQPACKET coalesces queued sends on
 * this platform, the peer exchanges one PDU at a time in lockstep.
 *
 * Oracle: message ordering and failure reasons come from the Core Spec
 * (Vol 3 Part H Section 2.3.5.6, LE Secure Connections), cited per case.
 * These entry points do not touch the file-static pairing rate limiter, so
 * no Repeated Attempts interference occurs.
 *
 * Links with: smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
 * Extra libs: -lcrypto (OpenSSL EVP/EC) -lpthread (bond_db lock type)
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

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include "att.h"
#include "att_server.h"
#include "hci_log.h"
#include "hci_util.h"
#include "smp.h"
#include "smp_internal.h"
#include "spec_smp_sc_edge_oracles.h"

#define TEST_LINKS_SMP
#include "test_common.h"

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif
#ifndef BDADDR_LE_RANDOM
#define BDADDR_LE_RANDOM	2
#endif

/* ================================================================
 * Stubs for external symbols referenced by smp.c / smp_sc.c.
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
 * Addresses and callbacks.
 * ================================================================ */
static const uint8_t central_addr[6] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
static const uint8_t periph_addr[6]  = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };

/* SC Debug Public Key coordinates (Core Spec Vol 3 Part H 2.3.5.6.1);
 * on-curve but must be rejected as publicly known. */
static const uint8_t sc_debug_pk_x[32] = {
	0x20, 0xb0, 0x03, 0xd2, 0xf2, 0x97, 0xbe, 0x2c,
	0x5e, 0x2c, 0x83, 0xa7, 0xe9, 0xf9, 0xa5, 0xb9,
	0xef, 0xf4, 0x91, 0x11, 0xac, 0xf4, 0xfd, 0xdb,
	0xcc, 0x03, 0x01, 0x48, 0x0e, 0x35, 0x9d, 0xe6
};
static const uint8_t sc_debug_pk_y[32] = {
	0xdc, 0x80, 0x9c, 0x49, 0x65, 0x2a, 0xeb, 0x6d,
	0x63, 0x32, 0x9a, 0xbf, 0x5a, 0x52, 0x15, 0x5c,
	0x76, 0x63, 0x45, 0xc2, 0x8f, 0xed, 0x30, 0x24,
	0x74, 0x1c, 0x8e, 0xd0, 0x15, 0x89, 0xd2, 0x8b
};

static int
cb_passkey_fixed(uint32_t *out, bool display __unused, void *arg)
{

	*out = *(uint32_t *)arg;
	return (0);
}

static int
cb_passkey_cancel(uint32_t *out __unused, bool display __unused,
    void *arg __unused)
{

	return (-1);	/* user cancelled */
}

static int
cb_numcmp_reject(uint32_t value __unused, void *arg __unused)
{

	return (-1);	/* values do not match */
}

/* Convert a 32-octet big-endian P-256 coordinate to SMP little-endian wire. */
static void
spec_reverse32(uint8_t out[32], const uint8_t in[32])
{
	size_t i;

	for (i = 0; i < 32; i++)
		out[i] = in[31 - i];
}

/* ================================================================
 * Test harness.
 * ================================================================ */
static void
sc_setup(struct smp_conn *sc, struct smp_bond_db *db,
    int smp_fds[2], int hci_fds[2],
    const uint8_t *local, uint8_t ltype,
    const uint8_t *remote, uint8_t rtype)
{

	signal(SIGPIPE, SIG_IGN);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);

	memset(db, 0, sizeof(*db));
	db->fd = -1;

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
	sc->io_capability = BT_SC_SPEC_IO_NO_INPUT_NO_OUTPUT;
	sc->min_key_size = BT_SC_SPEC_MAX_ENCRYPTION_KEY_SIZE;

	{
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
		setsockopt(smp_fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
}

static void
wait_child(pid_t pid)
{
	int status;

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	/* The child asserts its own protocol expectations via exit code. */
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "mock peer exited with status %d", status);
}

/* Standard SC Just Works PDUs (NoInputNoOutput, SC, no MITM). */
static void
build_sc_pdus(uint8_t preq[7], uint8_t pres[7], uint8_t init_io,
    uint8_t resp_io, uint8_t auth)
{
	preq[0] = BT_SC_SPEC_PAIRING_REQUEST;
	preq[1] = init_io;
	preq[2] = 0x00;
	preq[3] = auth;
	preq[4] = BT_SC_SPEC_MAX_ENCRYPTION_KEY_SIZE;
	preq[5] = 0x00;
	preq[6] = BT_SC_SPEC_KEY_DIST_ID_KEY;

	pres[0] = BT_SC_SPEC_PAIRING_RESPONSE;
	pres[1] = resp_io;
	pres[2] = 0x00;
	pres[3] = auth;
	pres[4] = BT_SC_SPEC_MAX_ENCRYPTION_KEY_SIZE;
	pres[5] = 0x00;
	pres[6] = BT_SC_SPEC_KEY_DIST_ID_KEY;
}

/* ---- mock-peer ECDH helpers (child side) ---- */
static int
child_keygen(EVP_PKEY **pkey, uint8_t pk_raw[65])
{
	EVP_PKEY_CTX *pctx;
	size_t pklen = 65;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pctx == NULL)
		return (-1);
	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
	if (EVP_PKEY_keygen(pctx, pkey) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return (-1);
	}
	EVP_PKEY_CTX_free(pctx);
	if (EVP_PKEY_get_octet_string_param(*pkey, OSSL_PKEY_PARAM_PUB_KEY,
	    pk_raw, 65, &pklen) <= 0)
		return (-1);
	return (0);
}

/* ================================================================
 * Passkey callback missing / cancelled — no PK exchange needed.
 * Core Spec Vol 3 Part H 2.3.5.6.3.
 * ================================================================ */

/*
 * Initiator passkey with no callback registered -> ENOTSUP, and a Pairing
 * Failed is sent so the peer is not left waiting.  Core Spec Vol 3 Part H
 * §3.5.5.  The reason (Pairing Not Supported, 0x05) matches the responder
 * path (test_respond_sc_passkey_no_cb) for cross-role consistency.
 */
ATF_TC_WITHOUT_HEAD(test_pair_sc_passkey_no_cb);
ATF_TC_BODY(test_pair_sc_passkey_no_cb, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[7], pres[7], out[8];
	ssize_t n;

	sc_setup(&sc, &db, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);
	build_sc_pdus(preq, pres, BT_SC_SPEC_IO_KEYBOARD_DISPLAY, BT_SC_SPEC_IO_KEYBOARD_ONLY,
	    BT_SC_SPEC_AUTH_BONDING | BT_SC_SPEC_AUTH_MITM | BT_SC_SPEC_AUTH_SECURE_CONNECTIONS);
	sc.passkey_cb = NULL;

	ATF_CHECK_EQ(smp_pair_sc_passkey(&sc, preq, pres), -1);
	ATF_CHECK_EQ_MSG(errno, ENOTSUP, "missing passkey cb -> ENOTSUP");

	n = recv(smp_fds[1], out, sizeof(out), 0);
	ATF_REQUIRE_EQ(BT_SC_SPEC_FAILED_PDU_LEN, n);
	ATF_CHECK_EQ(out[0], BT_SC_SPEC_PAIRING_FAILED);
	ATF_CHECK_EQ_MSG(out[1], BT_SC_SPEC_ERR_PAIRING_NOT_SUPPORTED,
	    "missing passkey cb must send Pairing Failed / Not Supported");

	close(smp_fds[0]); close(smp_fds[1]);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* Initiator passkey, user cancels -> Pairing Failed (Passkey Entry Failed). */
ATF_TC_WITHOUT_HEAD(test_pair_sc_passkey_cancel);
ATF_TC_BODY(test_pair_sc_passkey_cancel, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[7], pres[7], out[8];
	ssize_t n;

	sc_setup(&sc, &db, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);
	build_sc_pdus(preq, pres, BT_SC_SPEC_IO_KEYBOARD_DISPLAY, BT_SC_SPEC_IO_KEYBOARD_ONLY,
	    BT_SC_SPEC_AUTH_BONDING | BT_SC_SPEC_AUTH_MITM | BT_SC_SPEC_AUTH_SECURE_CONNECTIONS);
	sc.passkey_cb = cb_passkey_cancel;

	ATF_CHECK_EQ(smp_pair_sc_passkey(&sc, preq, pres), -1);
	ATF_CHECK_EQ(errno, ECANCELED);

	n = recv(smp_fds[1], out, sizeof(out), 0);
	ATF_REQUIRE_EQ(BT_SC_SPEC_FAILED_PDU_LEN, n);
	ATF_CHECK_EQ(out[0], BT_SC_SPEC_PAIRING_FAILED);
	ATF_CHECK_EQ_MSG(out[1], BT_SC_SPEC_ERR_PASSKEY_ENTRY_FAILED,
	    "cancel must send Passkey Entry Failed");

	close(smp_fds[0]); close(smp_fds[1]);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* Responder passkey with no callback -> Pairing Failed (Not Supported). */
ATF_TC_WITHOUT_HEAD(test_respond_sc_passkey_no_cb);
ATF_TC_BODY(test_respond_sc_passkey_no_cb, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[7], pres[7], out[8];
	ssize_t n;

	sc_setup(&sc, &db, smp_fds, hci_fds, periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC);
	build_sc_pdus(preq, pres, BT_SC_SPEC_IO_KEYBOARD_ONLY, BT_SC_SPEC_IO_DISPLAY_ONLY,
	    BT_SC_SPEC_AUTH_BONDING | BT_SC_SPEC_AUTH_MITM | BT_SC_SPEC_AUTH_SECURE_CONNECTIONS);
	sc.passkey_cb = NULL;

	ATF_CHECK_EQ(smp_respond_sc_passkey(&sc, preq, pres), -1);
	ATF_CHECK_EQ(errno, ENOTSUP);

	n = recv(smp_fds[1], out, sizeof(out), 0);
	ATF_REQUIRE_EQ(BT_SC_SPEC_FAILED_PDU_LEN, n);
	ATF_CHECK_EQ(out[0], BT_SC_SPEC_PAIRING_FAILED);
	ATF_CHECK_EQ(out[1], BT_SC_SPEC_ERR_PAIRING_NOT_SUPPORTED);

	close(smp_fds[0]); close(smp_fds[1]);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* ================================================================
 * Responder receives an invalid first public key (SC Debug Key) ->
 * Pairing Failed (DHKey Check Failed).  No child needed: preload the key.
 * Core Spec Vol 3 Part H 2.3.5.6.1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_respond_sc_debug_key_rejected);
ATF_TC_BODY(test_respond_sc_debug_key_rejected, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[7], pres[7], pk[65], out[8];
	ssize_t n;

	sc_setup(&sc, &db, smp_fds, hci_fds, periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC);
	build_sc_pdus(preq, pres, BT_SC_SPEC_IO_NO_INPUT_NO_OUTPUT,
	    BT_SC_SPEC_IO_NO_INPUT_NO_OUTPUT, BT_SC_SPEC_AUTH_BONDING | BT_SC_SPEC_AUTH_SECURE_CONNECTIONS);

	/* Wire is little-endian: swap the big-endian spec coordinates. */
	pk[0] = BT_SC_SPEC_PAIRING_PUBLIC_KEY;
	spec_reverse32(pk + 1, sc_debug_pk_x);
	spec_reverse32(pk + 33, sc_debug_pk_y);
	ATF_REQUIRE(send(smp_fds[1], pk, BT_SC_SPEC_PUBLIC_KEY_PDU_LEN,
	    MSG_EOR) == BT_SC_SPEC_PUBLIC_KEY_PDU_LEN);

	ATF_CHECK_EQ(smp_respond_sc(&sc, preq, pres, SMP_MODEL_JUST_WORKS), -1);

	n = recv(smp_fds[1], out, sizeof(out), 0);
	ATF_REQUIRE_EQ(BT_SC_SPEC_FAILED_PDU_LEN, n);
	ATF_CHECK_EQ(out[0], BT_SC_SPEC_PAIRING_FAILED);
	ATF_CHECK_EQ_MSG(out[1], BT_SC_SPEC_ERR_DHKEY_CHECK_FAILED,
	    "debug public key must be rejected");

	close(smp_fds[0]); close(smp_fds[1]);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* ================================================================
 * A mock peer that performs a valid public-key exchange as the RESPONDER
 * side (it receives the initiator PK, replies with its own) then runs a
 * caller-selected divergence.  Used to steer smp_pair_sc()/passkey.
 * ================================================================ */
enum peer_mode {
	PM_PK_ONLY,		/* exchange PK, then close (OOB-not-avail) */
	PM_BAD_OPCODE,		/* exchange PK, send wrong opcode for Cb */
	PM_INJECT_FAILED,	/* exchange PK, send Pairing Failed */
	PM_JW_WRONG_CONFIRM,	/* JW: bad Cb, then nonce exchange */
	PM_JW_GOOD_STAGE1,	/* JW/NC: correct Cb + nonce, then close */
	PM_JW_BAD_DHKEY,	/* JW: full stage1 + recv Ea, send wrong Eb */
	PM_PK_PASSKEY_BAD_CONFIRM /* passkey: PK, round0 bad Cbi + nonce */
};

/*
 * Child mock peer (responder role toward smp_pair_sc / passkey initiator).
 * Exits 0 on the expected exchange, non-zero on protocol surprise.
 */
static void
child_pair_peer(int peer_fd, enum peer_mode mode, uint8_t preq[7] __unused,
    uint8_t pres[7] __unused, uint8_t expect_fail_reason)
{
	EVP_PKEY *pkey = NULL;
	uint8_t our_pk[65], pdu[66];
	uint8_t pka_le[32], pkb_le[32], nb[16], cb[16];
	ssize_t n;

	if (child_keygen(&pkey, our_pk) != 0)
		_exit(10);

	/* Receive initiator PK. */
	n = recv(peer_fd, pdu, BT_SC_SPEC_PUBLIC_KEY_PDU_LEN, 0);
	if (n != BT_SC_SPEC_PUBLIC_KEY_PDU_LEN ||
	    pdu[0] != BT_SC_SPEC_PAIRING_PUBLIC_KEY)
		_exit(11);
	memcpy(pka_le, pdu + 1, 32);

	/* Send our PK. */
	pdu[0] = BT_SC_SPEC_PAIRING_PUBLIC_KEY;
	spec_reverse32(pdu + 1, our_pk + 1);
	spec_reverse32(pdu + 33, our_pk + 33);
	memcpy(pkb_le, pdu + 1, 32);
	if (send(peer_fd, pdu, BT_SC_SPEC_PUBLIC_KEY_PDU_LEN, MSG_EOR) !=
	    BT_SC_SPEC_PUBLIC_KEY_PDU_LEN)
		_exit(12);
	EVP_PKEY_free(pkey);

	switch (mode) {
	case PM_PK_ONLY:
		break;
	case PM_BAD_OPCODE:
		pdu[0] = 0xEE;			/* not Pairing Confirm */
		memset(pdu + 1, 0, 16);
		(void)send(peer_fd, pdu, 17, MSG_EOR);
		break;
	case PM_INJECT_FAILED:
		pdu[0] = BT_SC_SPEC_PAIRING_FAILED;
		pdu[1] = BT_SC_SPEC_ERR_UNSPECIFIED_REASON;
		(void)send(peer_fd, pdu, 2, MSG_EOR);
		break;
	case PM_JW_WRONG_CONFIRM:
		/* Send an intentionally wrong Cb. */
		pdu[0] = BT_SC_SPEC_PAIRING_CONFIRM;
		memset(pdu + 1, 0xA5, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) != 17)
			_exit(13);
		/* recv Na, send an arbitrary Nb so the initiator reaches the
		 * confirm verification and fails it. */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BT_SC_SPEC_PAIRING_RANDOM)
			_exit(14);
		pdu[0] = BT_SC_SPEC_PAIRING_RANDOM;
		memset(pdu + 1, 0x5A, 16);
		(void)send(peer_fd, pdu, 17, MSG_EOR);
		break;
	case PM_JW_GOOD_STAGE1:
	case PM_JW_BAD_DHKEY:
		/* Correct Cb = f4(PKbx, PKax, Nb, 0), then nonce exchange. */
		arc4random_buf(nb, sizeof(nb));
		smp_f4(pkb_le, pka_le, nb, 0, cb);
		pdu[0] = BT_SC_SPEC_PAIRING_CONFIRM;
		memcpy(pdu + 1, cb, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) != 17)
			_exit(15);
		n = recv(peer_fd, pdu, 17, 0);	/* Na */
		if (n < 17 || pdu[0] != BT_SC_SPEC_PAIRING_RANDOM)
			_exit(16);
		pdu[0] = BT_SC_SPEC_PAIRING_RANDOM;
		memcpy(pdu + 1, nb, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) != 17)
			_exit(17);
		if (mode == PM_JW_BAD_DHKEY) {
			/* Receive Ea, reply with a bogus Eb. */
			n = recv(peer_fd, pdu, 17, 0);
			if (n < 17 || pdu[0] != BT_SC_SPEC_PAIRING_DHKEY_CHECK)
				_exit(18);
			pdu[0] = BT_SC_SPEC_PAIRING_DHKEY_CHECK;
			memset(pdu + 1, 0x33, 16);
			(void)send(peer_fd, pdu, 17, MSG_EOR);
		}
		break;
	case PM_PK_PASSKEY_BAD_CONFIRM:
		/*
		 * Passkey round 0: recv Cai, send a wrong Cbi, recv Nai,
		 * send an arbitrary Nbi -> initiator's Cbi verification fails.
		 */
		n = recv(peer_fd, pdu, 17, 0);	/* Cai */
		if (n < 17 || pdu[0] != BT_SC_SPEC_PAIRING_CONFIRM)
			_exit(19);
		pdu[0] = BT_SC_SPEC_PAIRING_CONFIRM;
		memset(pdu + 1, 0xC3, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) != 17)
			_exit(20);
		n = recv(peer_fd, pdu, 17, 0);	/* Nai */
		if (n < 17 || pdu[0] != BT_SC_SPEC_PAIRING_RANDOM)
			_exit(21);
		pdu[0] = BT_SC_SPEC_PAIRING_RANDOM;
		memset(pdu + 1, 0x3C, 16);
		(void)send(peer_fd, pdu, 17, MSG_EOR);
		break;
	}

	/*
	 * Drain anything the DUT emits after failing.  When a specific
	 * Pairing Failed reason is expected, verify the DUT actually sent it
	 * (the failure PDU is delivered to this peer side, not the parent).
	 */
	{
		uint8_t junk[64];
		ssize_t rn;
		bool saw = false;
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
		setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		while ((rn = recv(peer_fd, junk, sizeof(junk), 0)) > 0) {
			if (rn == BT_SC_SPEC_FAILED_PDU_LEN &&
			    junk[0] == BT_SC_SPEC_PAIRING_FAILED &&
			    junk[1] == expect_fail_reason)
				saw = true;
		}
		if (expect_fail_reason != 0 && !saw)
			_exit(40);	/* expected failure reason not seen */
	}
	_exit(0);
}

/* Fork a mock peer running the given mode; parent keeps smp_fds[0]. */
static pid_t
fork_pair_peer(int smp_fds[2], int hci_fds[2], enum peer_mode mode,
    uint8_t preq[7], uint8_t pres[7], uint8_t expect_fail_reason)
{
	pid_t pid = fork();

	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		child_pair_peer(smp_fds[1], mode, preq, pres,
		    expect_fail_reason);
		_exit(0);	/* not reached */
	}
	close(smp_fds[1]);
	return (pid);
}

/* ---- OOB not available (initiator) ---- */
ATF_TC_WITHOUT_HEAD(test_pair_sc_oob_not_available);
ATF_TC_BODY(test_pair_sc_oob_not_available, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	struct smp_oob_data oob;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[7], pres[7];
	pid_t pid;

	sc_setup(&sc, &db, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);
	build_sc_pdus(preq, pres, BT_SC_SPEC_IO_NO_INPUT_NO_OUTPUT,
	    BT_SC_SPEC_IO_NO_INPUT_NO_OUTPUT, BT_SC_SPEC_AUTH_BONDING | BT_SC_SPEC_AUTH_SECURE_CONNECTIONS);
	/* An OOB container without SC material is unavailable too.  Keep the
	 * direct-null responder case below to cover the other short-circuit arm. */
	memset(&oob, 0, sizeof(oob));
	sc.oob = &oob;

	/*
	 * Vol 3 Part H §3.5.5 / Table 3.7: OOB pairing selected but no OOB
	 * data available => Pairing Failed with reason "OOB Not Available"
	 * (0x02).  The child verifies the on-wire reason code.
	 */
	pid = fork_pair_peer(smp_fds, hci_fds, PM_PK_ONLY, preq, pres,
	    BT_SC_SPEC_ERR_OOB_NOT_AVAILABLE);

	ATF_CHECK_EQ(smp_pair_sc(&sc, preq, pres, SMP_MODEL_OOB), -1);
	ATF_CHECK_EQ(errno, ENOTSUP);

	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	wait_child(pid);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* ---- OOB not available (responder) ---- */
ATF_TC_WITHOUT_HEAD(test_respond_sc_oob_not_available);
ATF_TC_BODY(test_respond_sc_oob_not_available, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[7], pres[7];
	pid_t pid;

	sc_setup(&sc, &db, smp_fds, hci_fds, periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC);
	build_sc_pdus(preq, pres, BT_SC_SPEC_IO_NO_INPUT_NO_OUTPUT,
	    BT_SC_SPEC_IO_NO_INPUT_NO_OUTPUT, BT_SC_SPEC_AUTH_BONDING | BT_SC_SPEC_AUTH_SECURE_CONNECTIONS);
	sc.oob = NULL;

	/*
	 * Responder receives PK first.  Reuse the pair-peer child but as the
	 * INITIATOR toward us: it must send its PK first, then read ours.
	 * child_pair_peer expects to receive first, so instead run a tiny
	 * inline initiator here via fork.
	 */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int peer_fd = smp_fds[1];
		EVP_PKEY *pkey = NULL;
		uint8_t our_pk[65], pdu[66];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		if (child_keygen(&pkey, our_pk) != 0)
			_exit(10);
		pdu[0] = BT_SC_SPEC_PAIRING_PUBLIC_KEY;
		spec_reverse32(pdu + 1, our_pk + 1);
		spec_reverse32(pdu + 33, our_pk + 33);
		if (send(peer_fd, pdu, BT_SC_SPEC_PUBLIC_KEY_PDU_LEN,
		    MSG_EOR) != BT_SC_SPEC_PUBLIC_KEY_PDU_LEN)
			_exit(11);
		EVP_PKEY_free(pkey);
		n = recv(peer_fd, pdu, BT_SC_SPEC_PUBLIC_KEY_PDU_LEN, 0);
		if (n != BT_SC_SPEC_PUBLIC_KEY_PDU_LEN)
			_exit(12);
		/*
		 * Then the DUT fails OOB.  Vol 3 Part H §3.5.5 / Table 3.7:
		 * verify it emits Pairing Failed "OOB Not Available" (0x02).
		 */
		{
			uint8_t junk[64];
			ssize_t rn;
			bool saw = false;
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
			while ((rn = recv(peer_fd, junk, sizeof(junk), 0)) > 0) {
				if (rn == BT_SC_SPEC_FAILED_PDU_LEN &&
				    junk[0] == BT_SC_SPEC_PAIRING_FAILED &&
				    junk[1] == BT_SC_SPEC_ERR_OOB_NOT_AVAILABLE)
					saw = true;
			}
			if (!saw)
				_exit(13);
		}
		_exit(0);
	}
	close(smp_fds[1]);

	ATF_CHECK_EQ(smp_respond_sc(&sc, preq, pres, SMP_MODEL_OOB), -1);
	ATF_CHECK_EQ(errno, ENOTSUP);

	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	wait_child(pid);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* ---- Unexpected opcode where Pairing Confirm is expected -> EPROTO ---- */
ATF_TC_WITHOUT_HEAD(test_pair_sc_bad_opcode_midflow);
ATF_TC_BODY(test_pair_sc_bad_opcode_midflow, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[7], pres[7];
	pid_t pid;

	sc_setup(&sc, &db, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);
	build_sc_pdus(preq, pres, BT_SC_SPEC_IO_NO_INPUT_NO_OUTPUT,
	    BT_SC_SPEC_IO_NO_INPUT_NO_OUTPUT, BT_SC_SPEC_AUTH_BONDING | BT_SC_SPEC_AUTH_SECURE_CONNECTIONS);

	pid = fork_pair_peer(smp_fds, hci_fds, PM_BAD_OPCODE, preq, pres, 0);

	ATF_CHECK_EQ(smp_pair_sc(&sc, preq, pres, SMP_MODEL_JUST_WORKS), -1);
	ATF_CHECK_EQ_MSG(errno, EPROTO, "unexpected opcode -> EPROTO");

	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	wait_child(pid);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* ---- Injected Pairing Failed where a Confirm is expected -> EACCES ---- */
ATF_TC_WITHOUT_HEAD(test_pair_sc_injected_failed);
ATF_TC_BODY(test_pair_sc_injected_failed, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[7], pres[7];
	pid_t pid;

	sc_setup(&sc, &db, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);
	build_sc_pdus(preq, pres, BT_SC_SPEC_IO_NO_INPUT_NO_OUTPUT,
	    BT_SC_SPEC_IO_NO_INPUT_NO_OUTPUT, BT_SC_SPEC_AUTH_BONDING | BT_SC_SPEC_AUTH_SECURE_CONNECTIONS);

	pid = fork_pair_peer(smp_fds, hci_fds, PM_INJECT_FAILED, preq, pres, 0);

	ATF_CHECK_EQ(smp_pair_sc(&sc, preq, pres, SMP_MODEL_JUST_WORKS), -1);
	ATF_CHECK_EQ_MSG(errno, EACCES, "peer Pairing Failed -> EACCES");

	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	wait_child(pid);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* ---- JW confirm value mismatch -> Pairing Failed (Confirm Value) ---- */
ATF_TC_WITHOUT_HEAD(test_pair_sc_confirm_mismatch);
ATF_TC_BODY(test_pair_sc_confirm_mismatch, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[7], pres[7];
	pid_t pid;

	sc_setup(&sc, &db, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);
	build_sc_pdus(preq, pres, BT_SC_SPEC_IO_NO_INPUT_NO_OUTPUT,
	    BT_SC_SPEC_IO_NO_INPUT_NO_OUTPUT, BT_SC_SPEC_AUTH_BONDING | BT_SC_SPEC_AUTH_SECURE_CONNECTIONS);

	pid = fork_pair_peer(smp_fds, hci_fds, PM_JW_WRONG_CONFIRM, preq, pres,
	    BT_SC_SPEC_ERR_CONFIRM_VALUE_FAILED);

	ATF_CHECK_EQ(smp_pair_sc(&sc, preq, pres, SMP_MODEL_JUST_WORKS), -1);
	ATF_CHECK_EQ(errno, EACCES);

	/* The mock peer verifies the Confirm Value Failed PDU (its exit code). */
	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	wait_child(pid);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* ---- JW DHKey check failure -> Pairing Failed (DHKey Check) ---- */
ATF_TC_WITHOUT_HEAD(test_pair_sc_dhkey_check_fail);
ATF_TC_BODY(test_pair_sc_dhkey_check_fail, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[7], pres[7];
	pid_t pid;

	sc_setup(&sc, &db, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);
	build_sc_pdus(preq, pres, BT_SC_SPEC_IO_NO_INPUT_NO_OUTPUT,
	    BT_SC_SPEC_IO_NO_INPUT_NO_OUTPUT, BT_SC_SPEC_AUTH_BONDING | BT_SC_SPEC_AUTH_SECURE_CONNECTIONS);

	pid = fork_pair_peer(smp_fds, hci_fds, PM_JW_BAD_DHKEY, preq, pres,
	    BT_SC_SPEC_ERR_DHKEY_CHECK_FAILED);

	ATF_CHECK_EQ(smp_pair_sc(&sc, preq, pres, SMP_MODEL_JUST_WORKS), -1);
	ATF_CHECK_EQ(errno, EACCES);

	/* The mock peer verifies the DHKey Check Failed PDU (its exit code). */
	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	wait_child(pid);
	close(hci_fds[0]); close(hci_fds[1]);
}

/*
 * Numeric Comparison: no callback -> ENOTSUP, and a Pairing Failed (Numeric
 * Comparison Failed, 0x0C) is sent so the peer is not left waiting for the
 * DHKey Check.  Core Spec Vol 3 Part H §3.5.5.  The reason matches the
 * responder path (test_respond_sc_numcmp_reject / smp_respond_sc) for
 * cross-role consistency; the mock peer verifies the reason code.
 */
ATF_TC_WITHOUT_HEAD(test_pair_sc_numcmp_no_cb);
ATF_TC_BODY(test_pair_sc_numcmp_no_cb, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[7], pres[7];
	pid_t pid;

	sc_setup(&sc, &db, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);
	build_sc_pdus(preq, pres, BT_SC_SPEC_IO_DISPLAY_YESNO, BT_SC_SPEC_IO_DISPLAY_YESNO,
	    BT_SC_SPEC_AUTH_BONDING | BT_SC_SPEC_AUTH_MITM | BT_SC_SPEC_AUTH_SECURE_CONNECTIONS);
	sc.numcmp_cb = NULL;

	pid = fork_pair_peer(smp_fds, hci_fds, PM_JW_GOOD_STAGE1, preq, pres,
	    BT_SC_SPEC_ERR_NUMERIC_COMP_FAILED);

	ATF_CHECK_EQ(smp_pair_sc(&sc, preq, pres,
	    SMP_MODEL_NUMERIC_COMPARISON), -1);
	ATF_CHECK_EQ_MSG(errno, ENOTSUP, "no numcmp cb -> ENOTSUP");

	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	wait_child(pid);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* ---- Numeric Comparison: user rejects -> Pairing Failed (Numeric) ---- */
ATF_TC_WITHOUT_HEAD(test_pair_sc_numcmp_reject);
ATF_TC_BODY(test_pair_sc_numcmp_reject, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[7], pres[7];
	pid_t pid;

	sc_setup(&sc, &db, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);
	build_sc_pdus(preq, pres, BT_SC_SPEC_IO_DISPLAY_YESNO, BT_SC_SPEC_IO_DISPLAY_YESNO,
	    BT_SC_SPEC_AUTH_BONDING | BT_SC_SPEC_AUTH_MITM | BT_SC_SPEC_AUTH_SECURE_CONNECTIONS);
	sc.numcmp_cb = cb_numcmp_reject;

	pid = fork_pair_peer(smp_fds, hci_fds, PM_JW_GOOD_STAGE1, preq, pres,
	    BT_SC_SPEC_ERR_NUMERIC_COMP_FAILED);

	ATF_CHECK_EQ(smp_pair_sc(&sc, preq, pres,
	    SMP_MODEL_NUMERIC_COMPARISON), -1);
	ATF_CHECK_EQ(errno, EACCES);

	/* The mock peer verifies the Numeric Comparison Failed PDU. */
	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	wait_child(pid);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* ---- Passkey Entry confirm mismatch (initiator) ---- */
ATF_TC_WITHOUT_HEAD(test_pair_sc_passkey_confirm_mismatch);
ATF_TC_BODY(test_pair_sc_passkey_confirm_mismatch, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[7], pres[7];
	uint32_t passkey = 654321;
	pid_t pid;

	sc_setup(&sc, &db, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);
	/* Initiator KeyboardDisplay, responder KeyboardOnly -> Passkey. */
	build_sc_pdus(preq, pres, BT_SC_SPEC_IO_KEYBOARD_DISPLAY, BT_SC_SPEC_IO_KEYBOARD_ONLY,
	    BT_SC_SPEC_AUTH_BONDING | BT_SC_SPEC_AUTH_MITM | BT_SC_SPEC_AUTH_SECURE_CONNECTIONS);
	sc.passkey_cb = cb_passkey_fixed;
	sc.passkey_cb_arg = &passkey;

	pid = fork_pair_peer(smp_fds, hci_fds, PM_PK_PASSKEY_BAD_CONFIRM,
	    preq, pres, BT_SC_SPEC_ERR_CONFIRM_VALUE_FAILED);

	ATF_CHECK_EQ(smp_pair_sc_passkey(&sc, preq, pres), -1);
	ATF_CHECK_EQ(errno, EACCES);

	/* The mock peer verifies the Confirm Value Failed PDU. */
	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	wait_child(pid);
	close(hci_fds[0]); close(hci_fds[1]);
}

/* ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_pair_sc_passkey_no_cb);
	ATF_TP_ADD_TC(tp, test_pair_sc_passkey_cancel);
	ATF_TP_ADD_TC(tp, test_respond_sc_passkey_no_cb);
	ATF_TP_ADD_TC(tp, test_respond_sc_debug_key_rejected);
	ATF_TP_ADD_TC(tp, test_pair_sc_oob_not_available);
	ATF_TP_ADD_TC(tp, test_respond_sc_oob_not_available);
	ATF_TP_ADD_TC(tp, test_pair_sc_bad_opcode_midflow);
	ATF_TP_ADD_TC(tp, test_pair_sc_injected_failed);
	ATF_TP_ADD_TC(tp, test_pair_sc_confirm_mismatch);
	ATF_TP_ADD_TC(tp, test_pair_sc_dhkey_check_fail);
	ATF_TP_ADD_TC(tp, test_pair_sc_numcmp_no_cb);
	ATF_TP_ADD_TC(tp, test_pair_sc_numcmp_reject);
	ATF_TP_ADD_TC(tp, test_pair_sc_passkey_confirm_mismatch);

	return (atf_no_error());
}
