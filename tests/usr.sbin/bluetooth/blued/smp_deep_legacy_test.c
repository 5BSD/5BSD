/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Deep-coverage ATF tests for the LE Legacy pairing paths (smp_legacy.c and
 * the legacy branches of smp.c smp_pair()).  These drive branches the
 * happy-path and existing edge tests leave uncovered:
 *
 *   - random (0x01) SMP address-type packing on both ends,
 *   - responder distribution of Enc + Id + Sign keys with a RANDOM identity
 *     address, and receipt of all five initiator key PDUs,
 *   - initiator (smp_pair) legacy key-receive via the shared
 *     smp_receive_peer_keys() parser, including malformed key distribution
 *     rejection,
 *   - CT2-flagged CTKD invocation from the legacy tails,
 *   - confirm-value mismatch and wrong-opcode / injected-Pairing-Failed at
 *     each receive step,
 *   - HCI LTK-reply and encryption-wait failures (stub-controlled),
 *   - send failures staged by closing the mock peer mid-exchange.
 *
 * Oracle: Core Spec Vol 3 Part H legacy pairing (Section 2.3.5.5), key
 * distribution (Section 3.6.1), and Pairing Failed reasons (Section 3.5.5).
 *
 * Links with: smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
 * Extra libs: -lbluetooth -lcrypto -lpthread
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

#include <openssl/evp.h>

#include "att.h"
#include "att_server.h"
#include "hci_log.h"
#include "hci_util.h"
#include "spec_oracles.h"
#include "smp.h"
#include "smp_internal.h"

#define TEST_LINKS_SMP
#include "test_common.h"

/* Generator-derived test-only wire assignments, independent of smp.h. */
#define BTDL_ORACLE_ENUM(name, value) BTDL_##name = (value),
enum {
	BT_CORE63_SMP_COMMAND_ORACLES(BTDL_ORACLE_ENUM)
	BT_CORE63_SMP_FAILURE_ORACLES(BTDL_ORACLE_ENUM)
	BT_CORE63_SMP_SCALAR_ORACLES(BTDL_ORACLE_ENUM)
	BT_CORE63_SMP_KEY_DIST_ORACLES(BTDL_ORACLE_ENUM)
	BT_CORE63_PREVIOUSLY_USED_ORACLES(BTDL_ORACLE_ENUM)
};
#undef BTDL_ORACLE_ENUM

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif
#ifndef BDADDR_LE_RANDOM
#define BDADDR_LE_RANDOM	2
#endif

/* ================================================================
 * Stubs — HCI results are steerable so the encryption tails can be
 * driven down their failure arms.
 * ================================================================ */
static int g_ltk_reply_ret = 0;
static int g_wait_enc_ret = 0;
static int g_hci_send_ret = 1;	/* >=0 success */
static const char *g_crypto_fail_op;
static int legacy_clock_calls;
static int legacy_clock_expire_after;
static int p17_last_bond_mitm;

static void
legacy_clock_hook(struct timespec *now)
{

	legacy_clock_calls++;
	now->tv_sec = (legacy_clock_calls >= legacy_clock_expire_after) ? 31 : 0;
	now->tv_nsec = 0;
}

static int
legacy_crypto_fail_hook(const char *operation)
{

	return (g_crypto_fail_op != NULL &&
	    (strcmp(operation, g_crypto_fail_op) == 0 ||
	    (strcmp(g_crypto_fail_op, "c1") == 0 &&
	    strncmp(operation, "c1-", 3) == 0)) ? -1 : 0);
}

int
hci_send_raw_cmd(int hci_fd __unused, uint16_t opcode __unused,
    const void *params __unused, uint8_t plen __unused)
{

	return (g_hci_send_ret);
}

int
hci_wait_encryption(int hci_fd __unused, uint16_t con_handle __unused,
    int timeout_sec __unused)
{

	return (g_wait_enc_ret);
}

int
hci_le_ltk_request_reply(int hci_fd __unused, uint16_t con_handle __unused,
    const uint8_t ltk[16] __unused)
{

	return (g_ltk_reply_ret);
}

int
hci_le_ltk_request_neg_reply(int hci_fd __unused, uint16_t con_handle __unused)
{

	return (0);
}

static const uint8_t central_addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
static const uint8_t periph_addr[6]  = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 };

static void
core_hex_le(uint8_t *out, const char *hex, size_t len)
{
	size_t i;
	unsigned int byte;

	for (i = 0; i < len; i++) {
		ATF_REQUIRE_EQ(1, sscanf(hex + 2 * i, "%02x", &byte));
		out[len - 1 - i] = (uint8_t)byte;
	}
}

static int
reference_aes128_le(const uint8_t key_le[16], const uint8_t in_le[16],
    uint8_t out_le[16])
{
	EVP_CIPHER_CTX *ctx;
	uint8_t key_be[16], input_be[16], output_be[32];
	int out_len, final_len, i, rc;

	for (i = 0; i < 16; i++) {
		key_be[i] = key_le[15 - i];
		input_be[i] = in_le[15 - i];
	}
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return (-1);
	rc = -1;
	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key_be, NULL) != 1 ||
	    EVP_CIPHER_CTX_set_padding(ctx, 0) != 1 ||
	    EVP_EncryptUpdate(ctx, output_be, &out_len, input_be, 16) != 1 ||
	    EVP_EncryptFinal_ex(ctx, output_be + out_len, &final_len) != 1 ||
	    out_len + final_len != 16)
		goto out;
	for (i = 0; i < 16; i++)
		out_le[i] = output_be[15 - i];
	rc = 0;
out:
	EVP_CIPHER_CTX_free(ctx);
	explicit_bzero(key_be, sizeof(key_be));
	explicit_bzero(output_be, sizeof(output_be));
	return (rc);
}

/* Bluetooth Core 6.3 Vol 3 Part H §2.2.3, independent of production c1. */
static int
reference_c1(const uint8_t key[16], const uint8_t random[16],
    const uint8_t preq[7], const uint8_t pres[7], uint8_t iat,
    const uint8_t ia[6], uint8_t rat, const uint8_t ra[6],
    uint8_t confirm[16])
{
	uint8_t p1[16], p2[16], tmp[16];
	int i;

	p1[0] = iat;
	p1[1] = rat;
	memcpy(p1 + 2, preq, 7);
	memcpy(p1 + 9, pres, 7);
	memcpy(p2, ra, 6);
	memcpy(p2 + 6, ia, 6);
	memset(p2 + 12, 0, 4);
	for (i = 0; i < 16; i++)
		tmp[i] = random[i] ^ p1[i];
	if (reference_aes128_le(key, tmp, tmp) != 0)
		return (-1);
	for (i = 0; i < 16; i++)
		tmp[i] ^= p2[i];
	return (reference_aes128_le(key, tmp, confirm));
}

static bool
reference_c1_matches_core(void)
{
	uint8_t key[16], random[16], preq[7], pres[7], iat[1], rat[1];
	uint8_t ia[6], ra[6], expected[16], actual[16];

	core_hex_le(key, BT_CORE63_SMP_C1_KEY_HEX, sizeof(key));
	core_hex_le(random, BT_CORE63_SMP_C1_R_HEX, sizeof(random));
	core_hex_le(preq, BT_CORE63_SMP_C1_PREQ_HEX, sizeof(preq));
	core_hex_le(pres, BT_CORE63_SMP_C1_PRES_HEX, sizeof(pres));
	core_hex_le(iat, BT_CORE63_SMP_C1_IAT_HEX, sizeof(iat));
	core_hex_le(rat, BT_CORE63_SMP_C1_RAT_HEX, sizeof(rat));
	core_hex_le(ia, BT_CORE63_SMP_C1_IA_HEX, sizeof(ia));
	core_hex_le(ra, BT_CORE63_SMP_C1_RA_HEX, sizeof(ra));
	core_hex_le(expected, BT_CORE63_SMP_C1_OUT_HEX, sizeof(expected));
	return (reference_c1(key, random, preq, pres, iat[0], ia, rat[0], ra,
	    actual) == 0 && memcmp(actual, expected, sizeof(actual)) == 0);
}

static void
setup(struct smp_conn *sc, struct smp_bond_db *db, int bond_fd,
    int smp_fds[2], int hci_fds[2],
    const uint8_t *local, uint8_t ltype,
    const uint8_t *remote, uint8_t rtype)
{

	ATF_REQUIRE_MSG(reference_c1_matches_core(),
	    "independent c1 peer failed the Core §2.2.3 worked example");
	signal(SIGPIPE, SIG_IGN);
	/* Cover enabled production SMP diagnostic guards while retaining the
	 * same wire-level pairing assertions. */
	atomic_store(&blued_verbose, 2);
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
	sc->io_capability = BTDL_SMP_IO_NO_INPUT_NO_OUTPUT;
	sc->min_key_size = BT_CORE63_SMP_MIN_KEY_SIZE;
	{
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
		setsockopt(smp_fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
}

static void
reset_hci_stubs(void)
{

	g_ltk_reply_ret = 0;
	g_wait_enc_ret = 0;
	g_hci_send_ret = 1;
	g_crypto_fail_op = NULL;
	smp_legacy_crypto_hook = NULL;
	legacy_clock_calls = 0;
	legacy_clock_expire_after = 0;
	smp_clock_hook = NULL;
}

static void
wait_child(pid_t pid)
{
	int status;

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "mock peer exited with status %d", status);
}

/*
 * Paced send for key-distribution bursts.  On this platform AF_UNIX
 * SOCK_SEQPACKET may coalesce sends that queue before the peer reads
 * them; a short pause lets the DUT consume each PDU before the next
 * arrives, preserving one-PDU-per-recv semantics.
 */
static bool
psend(int fd, const void *buf, size_t len)
{
	ssize_t n;

	n = send(fd, buf, len, MSG_EOR);
	usleep(6000);
	return (n == (ssize_t)len);
}

/*
 * Fixed SMP PDU sizes and command assignments come from Core 6.3 Vol 3
 * Part H Table 3.3 and §§3.5.2--3.6.6.  Keep these peer checks independent
 * of production structure sizes and command macros.
 */
static bool
peer_recv_shape(int fd, uint8_t *pdu, size_t capacity, size_t expected_len,
    uint8_t expected_command)
{
	ssize_t n;

	n = recv(fd, pdu, capacity, 0);
	return (n == (ssize_t)expected_len && pdu[0] == expected_command);
}

static bool
peer_recv_identity_address(int fd, uint8_t *pdu, size_t capacity,
    uint8_t expected_type, const uint8_t expected_addr[6])
{

	return (peer_recv_shape(fd, pdu, capacity, 8,
	    BTDL_SMP_IDENTITY_ADDRESS_INFO) && pdu[1] == expected_type &&
	    memcmp(pdu + 2, expected_addr, 6) == 0);
}

/* ================================================================
 * Responder full legacy exchange, RANDOM addresses, Enc+Id+Sign key
 * distribution both ways, CT2 flags set.  Drives smp_respond_legacy()
 * directly so preq/pres are fully controlled.
 *
 * Covers (smp_legacy.c): the (addr_type==RANDOM) packing on iat/rat, the
 * RANDOM identity-address-info byte, the Sign-key distribution block with
 * a non-NULL bond_db, the pres[5] Id/Sign receive accounting, and the
 * CT2 && CT2 CTKD argument evaluation.  Also drives smp_keys.c
 * smp_receive_peer_keys Id + Sign arms.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_random_all_keys_ct2);
ATF_TC_BODY(test_resp_legacy_random_all_keys_ct2, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_deep_leg_rand.XXXXXX";
	int bond_fd;
	pid_t pid;
	uint8_t preq[7], pres[7], tk[16];

	reset_hci_stubs();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	/* DUT = responder (peripheral), both addresses RANDOM. */
	setup(&sc, &db, bond_fd, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_RANDOM, central_addr, BDADDR_LE_RANDOM);

	memset(tk, 0, sizeof(tk));
	/* preq/pres as smp_respond would have built them: full key dist, CT2. */
	preq[0] = BTDL_SMP_PAIRING_REQUEST;
	preq[1] = BTDL_SMP_IO_NO_INPUT_NO_OUTPUT;
	preq[2] = 0x00;
	preq[3] = BTDL_SMP_AUTH_BONDING | BTDL_SMP_AUTH_CT2;
	preq[4] = BT_CORE63_SMP_MAX_KEY_SIZE;
	preq[5] = BTDL_SMP_KEY_DIST_ENC_KEY | BTDL_SMP_KEY_DIST_ID_KEY |
	    BTDL_SMP_KEY_DIST_LEGACY_SIGN_KEY;
	preq[6] = BTDL_SMP_KEY_DIST_ENC_KEY | BTDL_SMP_KEY_DIST_ID_KEY |
	    BTDL_SMP_KEY_DIST_LEGACY_SIGN_KEY;
	memcpy(pres, preq, 7);
	pres[0] = BTDL_SMP_PAIRING_RESPONSE;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int peer = smp_fds[1];
		uint8_t pdu[65], mrand[16], srand[16];
		uint8_t mconfirm[16], sconfirm[16], verify[16];
		uint8_t iat = BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM;
		uint8_t rat = BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM;	/* both RANDOM */
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		/* Compute and send our (initiator) confirm. */
		arc4random_buf(mrand, sizeof(mrand));
		if (reference_c1(tk, mrand, preq, pres, iat, central_addr,
		    rat, periph_addr, mconfirm) < 0)
			_exit(1);
		pdu[0] = BTDL_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, mconfirm, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(2);

		/* Receive responder confirm. */
		n = recv(peer, pdu, 17, 0);
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(sconfirm, pdu + 1, 16);

		/* Send our random. */
		pdu[0] = BTDL_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, mrand, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(4);
		/* Receive responder random, verify its confirm. */
		n = recv(peer, pdu, 17, 0);
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_RANDOM)
			_exit(5);
		memcpy(srand, pdu + 1, 16);
		if (reference_c1(tk, srand, preq, pres, iat, central_addr,
		    rat, periph_addr, verify) < 0)
			_exit(6);
		if (memcmp(verify, sconfirm, 16) != 0)
			_exit(7);

		/*
		 * Core §3.6.1 orders EncKey, IdKey, then the previously-used
		 * SignKey; §§3.6.2--3.6.6 define these five exact PDU shapes.
		 */
		if (!peer_recv_shape(peer, pdu, sizeof(pdu), 17,
		    BTDL_SMP_ENCRYPTION_INFORMATION) ||
		    !peer_recv_shape(peer, pdu, sizeof(pdu), 11,
		    BTDL_SMP_CENTRAL_IDENTIFICATION) ||
		    !peer_recv_shape(peer, pdu, sizeof(pdu), 17,
		    BTDL_SMP_IDENTITY_INFORMATION) ||
		    !peer_recv_identity_address(peer, pdu, sizeof(pdu),
		    BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM, periph_addr) ||
		    !peer_recv_shape(peer, pdu, sizeof(pdu), 17,
		    BTDL_SMP_LEGACY_SIGNING_INFORMATION))
			_exit(8);

		/* Distribute our initiator keys: Enc(2) + Id(2) + Sign(1). */
		pdu[0] = BTDL_SMP_ENCRYPTION_INFORMATION;
		memset(pdu + 1, 0x11, 16);
		if (!psend(peer, pdu, 17)) _exit(9);
		pdu[0] = BTDL_SMP_CENTRAL_IDENTIFICATION;
		memset(pdu + 1, 0x22, 10);
		if (!psend(peer, pdu, 11)) _exit(10);
		pdu[0] = BTDL_SMP_IDENTITY_INFORMATION;
		memset(pdu + 1, 0x33, 16);
		if (!psend(peer, pdu, 17)) _exit(11);
		pdu[0] = BTDL_SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM;	/* random */
		memcpy(pdu + 2, central_addr, 6);
		if (!psend(peer, pdu, 8)) _exit(12);
		pdu[0] = BTDL_SMP_LEGACY_SIGNING_INFORMATION;
		memset(pdu + 1, 0x44, 16);
		if (!psend(peer, pdu, 17)) _exit(13);

		close(peer);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_respond_legacy(&sc, preq, pres, tk);
	ATF_CHECK_EQ_MSG(ret, 0, "legacy responder must succeed (errno=%d)",
	    errno);
	ATF_CHECK_MSG(db.count > 0, "responder must store a bond");
	if (db.count > 0) {
		uint8_t exp_irk[16], exp_csrk[16];

		memset(exp_irk, 0x33, 16);	/* initiator Identity Info payload */
		memset(exp_csrk, 0x44, 16);	/* initiator Signing Info payload */
		ATF_CHECK(db.bonds[0].has_ltk);
		ATF_CHECK(db.bonds[0].has_irk);
		ATF_CHECK(db.bonds[0].has_csrk);
		/*
		 * Vol 3 Part H §3.6.3/§3.6.6: stored IRK/CSRK equal the values
		 * the initiator carried in its Identity/Signing Information PDUs.
		 */
		ATF_CHECK(memcmp(db.bonds[0].irk, exp_irk, 16) == 0);
		ATF_CHECK(memcmp(db.bonds[0].csrk, exp_csrk, 16) == 0);
		/*
		 * Vol 3 Part H §3.6.5: Identity Address Information carries the
		 * peer identity address (central_addr) with type octet 0x01,
		 * which must be recorded as BDADDR_LE_RANDOM (2).  The responder
		 * path (smp_receive_peer_keys, smp_keys.c) maps it correctly.
		 */
		ATF_CHECK(memcmp(db.bonds[0].addr, central_addr, 6) == 0);
		ATF_CHECK_EQ(db.bonds[0].addr_type, BDADDR_LE_RANDOM);
		/*
		 * NoInputNoOutput with no MITM negotiates Just Works, which is
		 * unauthenticated (LE security mode 1 level 2, Core Spec Vol 3
		 * Part C §10.2.1); is_mitm must stay false.
		 */
		ATF_CHECK(!db.bonds[0].is_mitm);
	}
	/* Sign-key distribution must have persisted the local CSRK. */
	ATF_CHECK(db.has_local_csrk);

	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Responder legacy: initiator's Pairing Random does not match its
 * Pairing Confirm -> responder must send Pairing Failed / Confirm Value
 * Failed and return EACCES.  Core Spec Vol 3 Part H 3.5.5 reason 0x04.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_confirm_mismatch);
ATF_TC_BODY(test_resp_legacy_confirm_mismatch, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;
	uint8_t preq[7], pres[7], tk[16];

	reset_hci_stubs();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);

	memset(tk, 0, sizeof(tk));
	preq[0] = BTDL_SMP_PAIRING_REQUEST; preq[1] = BTDL_SMP_IO_NO_INPUT_NO_OUTPUT;
	preq[2] = 0; preq[3] = BTDL_SMP_AUTH_BONDING; preq[4] = BT_CORE63_SMP_MAX_KEY_SIZE;
	preq[5] = 0; preq[6] = 0;
	memcpy(pres, preq, 7); pres[0] = BTDL_SMP_PAIRING_RESPONSE;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int peer = smp_fds[1];
		uint8_t pdu[65];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);

		/* Send a bogus confirm. */
		pdu[0] = BTDL_SMP_PAIRING_CONFIRM;
		memset(pdu + 1, 0xAB, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(1);
		/* Receive responder confirm. */
		n = recv(peer, pdu, 17, 0);
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_CONFIRM)
			_exit(2);
		/* Send a random that will NOT match the bogus confirm. */
		pdu[0] = BTDL_SMP_PAIRING_RANDOM;
		memset(pdu + 1, 0x00, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(3);
		/* Expect a Pairing Failed / Confirm Value Failed. */
		n = recv(peer, pdu, sizeof(pdu), 0);
		if (n != 2 || pdu[0] != BTDL_SMP_PAIRING_FAILED ||
		    pdu[1] != BTDL_SMP_ERR_CONFIRM_VALUE_FAILED)
			_exit(4);
		close(peer);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);
	int ret = smp_respond_legacy(&sc, preq, pres, tk);
	ATF_CHECK_EQ(ret, -1);
	ATF_CHECK_EQ(errno, EACCES);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

/* ================================================================
 * Responder legacy: wrong opcode where a Pairing Confirm is expected
 * (first receive) -> EPROTO.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_wrong_confirm_opcode);
ATF_TC_BODY(test_resp_legacy_wrong_confirm_opcode, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;
	uint8_t preq[7], pres[7], tk[16];

	reset_hci_stubs();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	memset(tk, 0, sizeof(tk));
	preq[0] = BTDL_SMP_PAIRING_REQUEST; preq[1] = BTDL_SMP_IO_NO_INPUT_NO_OUTPUT; preq[2] = 0;
	preq[3] = BTDL_SMP_AUTH_BONDING; preq[4] = BT_CORE63_SMP_MAX_KEY_SIZE; preq[5] = 0; preq[6] = 0;
	memcpy(pres, preq, 7); pres[0] = BTDL_SMP_PAIRING_RESPONSE;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int peer = smp_fds[1];
		uint8_t pdu[17];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		/*
		 * Core 6.3 Vol 3 Part H Table 3.3 assigns Identity
		 * Information command code 0x08; it is invalid at the §2.3.5.5
		 * Pairing Confirm boundary.  §3.5.5 Table 3.7 assigns
		 * Unspecified Reason value 0x08.
		 */
		pdu[0] = BTDL_SMP_IDENTITY_INFORMATION;
		memset(pdu + 1, 0, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(1);
		n = recv(peer, pdu, sizeof(pdu), 0);
		if (n != 2 || pdu[0] != BTDL_SMP_PAIRING_FAILED ||
		    pdu[1] != BTDL_SMP_ERR_UNSPECIFIED_REASON)
			_exit(2);
		close(peer);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	int ret = smp_respond_legacy(&sc, preq, pres, tk);
	ATF_CHECK_EQ(ret, -1);
	ATF_CHECK_EQ(errno, EPROTO);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

/* The §3.4 cumulative deadline applies before the very first legacy Phase 2
 * receive; expiry disconnects rather than emitting a Pairing Failed. */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_times_out_before_confirm);
ATF_TC_BODY(test_resp_legacy_times_out_before_confirm, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[7] = { BTDL_SMP_PAIRING_REQUEST, BTDL_SMP_IO_NO_INPUT_NO_OUTPUT, 0, BTDL_SMP_AUTH_BONDING,
	    BT_CORE63_SMP_MAX_KEY_SIZE, 0, 0 };
	uint8_t pres[7] = { BTDL_SMP_PAIRING_RESPONSE, BTDL_SMP_IO_NO_INPUT_NO_OUTPUT, 0, BTDL_SMP_AUTH_BONDING,
	    BT_CORE63_SMP_MAX_KEY_SIZE, 0, 0 };
	uint8_t tk[16] = { 0 };

	reset_hci_stubs();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds, periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC);
	legacy_clock_expire_after = 2; /* arm at t=0; first receive check t=31 */
	smp_clock_hook = legacy_clock_hook;
	ATF_CHECK_EQ(smp_respond_legacy(&sc, preq, pres, tk), -1);
	ATF_CHECK_EQ(errno, ETIMEDOUT);
	close(smp_fds[0]);
	close(smp_fds[1]);
	close(hci_fds[0]);
	close(hci_fds[1]);
	reset_hci_stubs();
}

/* The same deadline remains in force between the Confirm and Random receives;
 * receiving a valid Confirm does not restart the spec's 30-second timer. */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_times_out_before_random);
ATF_TC_BODY(test_resp_legacy_times_out_before_random, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[7] = { BTDL_SMP_PAIRING_REQUEST, BTDL_SMP_IO_NO_INPUT_NO_OUTPUT, 0, BTDL_SMP_AUTH_BONDING,
	    BT_CORE63_SMP_MAX_KEY_SIZE, 0, 0 };
	uint8_t pres[7] = { BTDL_SMP_PAIRING_RESPONSE, BTDL_SMP_IO_NO_INPUT_NO_OUTPUT, 0, BTDL_SMP_AUTH_BONDING,
	    BT_CORE63_SMP_MAX_KEY_SIZE, 0, 0 };
	uint8_t tk[16] = { 0 };
	pid_t pid;

	reset_hci_stubs();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds, periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		uint8_t pdu[17], mrand[16], mconfirm[16];

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		arc4random_buf(mrand, sizeof(mrand));
		if (reference_c1(tk, mrand, preq, pres, BT_CORE63_SMP_ID_ADDR_PUBLIC, central_addr,
		    BT_CORE63_SMP_ID_ADDR_PUBLIC, periph_addr, mconfirm) < 0)
			_exit(1);
		pdu[0] = BTDL_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, mconfirm, 16);
		if (send(smp_fds[1], pdu, sizeof(pdu), MSG_EOR) != sizeof(pdu))
			_exit(2);
		if (recv(smp_fds[1], pdu, sizeof(pdu), 0) != 17 ||
		    pdu[0] != BTDL_SMP_PAIRING_CONFIRM)
			_exit(3);
		close(smp_fds[1]);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	legacy_clock_expire_after = 4;
	smp_clock_hook = legacy_clock_hook;
	ATF_CHECK_EQ(smp_respond_legacy(&sc, preq, pres, tk), -1);
	ATF_CHECK_EQ(errno, ETIMEDOUT);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
	reset_hci_stubs();
}

/* ================================================================
 * Responder legacy: injected Pairing Failed where a Pairing Random is
 * expected (second receive) -> EACCES (the n>0 && FAILED ternary arm).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_injected_failed_at_random);
ATF_TC_BODY(test_resp_legacy_injected_failed_at_random, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;
	uint8_t preq[7], pres[7], tk[16];

	reset_hci_stubs();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	memset(tk, 0, sizeof(tk));
	preq[0] = BTDL_SMP_PAIRING_REQUEST; preq[1] = BTDL_SMP_IO_NO_INPUT_NO_OUTPUT; preq[2] = 0;
	preq[3] = BTDL_SMP_AUTH_BONDING; preq[4] = BT_CORE63_SMP_MAX_KEY_SIZE; preq[5] = 0; preq[6] = 0;
	memcpy(pres, preq, 7); pres[0] = BTDL_SMP_PAIRING_RESPONSE;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int peer = smp_fds[1];
		uint8_t pdu[65];
		uint8_t mrand[16], mconfirm[16];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		/* Valid confirm so the first receive passes. */
		arc4random_buf(mrand, sizeof(mrand));
		if (reference_c1(tk, mrand, preq, pres, BT_CORE63_SMP_ID_ADDR_PUBLIC, central_addr,
		    BT_CORE63_SMP_ID_ADDR_PUBLIC, periph_addr, mconfirm) < 0)
			_exit(1);
		pdu[0] = BTDL_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, mconfirm, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(2);
		n = recv(peer, pdu, 17, 0);	/* responder confirm */
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_CONFIRM)
			_exit(3);
		/* Inject Pairing Failed where a Random is expected. */
		pdu[0] = BTDL_SMP_PAIRING_FAILED;
		pdu[1] = BTDL_SMP_ERR_UNSPECIFIED_REASON;
		(void)send(peer, pdu, 2, MSG_EOR);
		close(peer);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	int ret = smp_respond_legacy(&sc, preq, pres, tk);
	ATF_CHECK_EQ(ret, -1);
	ATF_CHECK_EQ(errno, EACCES);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

/* A complete but out-of-sequence PDU at the Random boundary receives the
 * spec-compatible Unspecified Reason response; this is distinct from a peer
 * Pairing Failed, which is propagated without a reply. */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_wrong_random_opcode);
ATF_TC_BODY(test_resp_legacy_wrong_random_opcode, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;
	uint8_t preq[7] = { BTDL_SMP_PAIRING_REQUEST, BTDL_SMP_IO_NO_INPUT_NO_OUTPUT, 0, BTDL_SMP_AUTH_BONDING,
	    BT_CORE63_SMP_MAX_KEY_SIZE, 0, 0 };
	uint8_t pres[7] = { BTDL_SMP_PAIRING_RESPONSE, BTDL_SMP_IO_NO_INPUT_NO_OUTPUT, 0, BTDL_SMP_AUTH_BONDING,
	    BT_CORE63_SMP_MAX_KEY_SIZE, 0, 0 };
	uint8_t tk[16] = { 0 };

	reset_hci_stubs();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds, periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		uint8_t pdu[17], mrand[16], mconfirm[16];

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		arc4random_buf(mrand, sizeof(mrand));
		if (reference_c1(tk, mrand, preq, pres, BT_CORE63_SMP_ID_ADDR_PUBLIC, central_addr,
		    BT_CORE63_SMP_ID_ADDR_PUBLIC, periph_addr, mconfirm) < 0)
			_exit(1);
		pdu[0] = BTDL_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, mconfirm, 16);
		if (send(smp_fds[1], pdu, sizeof(pdu), MSG_EOR) != sizeof(pdu))
			_exit(2);
		if (recv(smp_fds[1], pdu, sizeof(pdu), 0) != 17 ||
		    pdu[0] != BTDL_SMP_PAIRING_CONFIRM)
			_exit(3);
		pdu[0] = BTDL_SMP_IDENTITY_INFORMATION;
		memset(pdu + 1, 0, 16);
		if (send(smp_fds[1], pdu, sizeof(pdu), MSG_EOR) != sizeof(pdu))
			_exit(4);
		if (recv(smp_fds[1], pdu, sizeof(pdu), 0) != 2 ||
		    pdu[0] != BTDL_SMP_PAIRING_FAILED ||
		    pdu[1] != BTDL_SMP_ERR_UNSPECIFIED_REASON)
			_exit(5);
		close(smp_fds[1]);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	ATF_CHECK_EQ(smp_respond_legacy(&sc, preq, pres, tk), -1);
	ATF_CHECK_EQ(errno, EPROTO);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

/* ================================================================
 * Responder legacy: HCI LTK-reply failure and encryption-wait failure
 * abort the flow after the confirm/random exchange succeeds.
 * ================================================================ */
static void
run_resp_legacy_hci_fail(bool fail_wait)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;
	uint8_t preq[7], pres[7], tk[16];

	reset_hci_stubs();
	if (fail_wait)
		g_wait_enc_ret = -1;
	else
		g_ltk_reply_ret = -1;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	memset(tk, 0, sizeof(tk));
	preq[0] = BTDL_SMP_PAIRING_REQUEST; preq[1] = BTDL_SMP_IO_NO_INPUT_NO_OUTPUT; preq[2] = 0;
	preq[3] = BTDL_SMP_AUTH_BONDING; preq[4] = BT_CORE63_SMP_MAX_KEY_SIZE; preq[5] = 0; preq[6] = 0;
	memcpy(pres, preq, 7); pres[0] = BTDL_SMP_PAIRING_RESPONSE;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int peer = smp_fds[1];
		uint8_t pdu[65], mrand[16], mconfirm[16], sconfirm[16];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		arc4random_buf(mrand, sizeof(mrand));
		if (reference_c1(tk, mrand, preq, pres, BT_CORE63_SMP_ID_ADDR_PUBLIC, central_addr,
		    BT_CORE63_SMP_ID_ADDR_PUBLIC, periph_addr, mconfirm) < 0)
			_exit(1);
		pdu[0] = BTDL_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, mconfirm, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(2);
		n = recv(peer, pdu, 17, 0);
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(sconfirm, pdu + 1, 16);
		pdu[0] = BTDL_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, mrand, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(4);
		/* DUT verifies, sends its random, then hits the HCI stub. */
		n = recv(peer, pdu, 17, 0);
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_RANDOM)
			_exit(5);
		close(peer);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	int ret = smp_respond_legacy(&sc, preq, pres, tk);
	ATF_CHECK_EQ_MSG(ret, -1, "HCI failure must abort pairing");
	ATF_CHECK_MSG(db.count == 0, "no bond on HCI failure");
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
	reset_hci_stubs();
}

ATF_TC_WITHOUT_HEAD(test_resp_legacy_ltk_reply_fail);
ATF_TC_BODY(test_resp_legacy_ltk_reply_fail, tc)
{

	run_resp_legacy_hci_fail(false);
}

ATF_TC_WITHOUT_HEAD(test_resp_legacy_wait_enc_fail);
ATF_TC_BODY(test_resp_legacy_wait_enc_fail, tc)
{

	run_resp_legacy_hci_fail(true);
}

/* ================================================================
 * Responder legacy: peer closes right after sending a valid confirm, so
 * the responder's own Pairing Confirm send fails.  Exercises the
 * smp_log_send() < 0 arm on the confirm send.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_send_confirm_fails);
ATF_TC_BODY(test_resp_legacy_send_confirm_fails, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;
	uint8_t preq[7], pres[7], tk[16];

	reset_hci_stubs();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	memset(tk, 0, sizeof(tk));
	preq[0] = BTDL_SMP_PAIRING_REQUEST; preq[1] = BTDL_SMP_IO_NO_INPUT_NO_OUTPUT; preq[2] = 0;
	preq[3] = BTDL_SMP_AUTH_BONDING; preq[4] = BT_CORE63_SMP_MAX_KEY_SIZE; preq[5] = 0; preq[6] = 0;
	memcpy(pres, preq, 7); pres[0] = BTDL_SMP_PAIRING_RESPONSE;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int peer = smp_fds[1];
		uint8_t pdu[17];

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		/* Valid confirm, then immediately close so DUT's send fails. */
		pdu[0] = BTDL_SMP_PAIRING_CONFIRM;
		memset(pdu + 1, 0x5A, 16);
		(void)send(peer, pdu, 17, MSG_EOR);
		close(peer);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	int ret = smp_respond_legacy(&sc, preq, pres, tk);
	ATF_CHECK_EQ(ret, -1);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

/* ================================================================
 * Initiator (smp_pair) legacy: peer distributes EVERY key PDU type plus
 * an unknown opcode, with RANDOM addresses.  Exercises the smp_pair()
 * key-receive switch arms (Encryption Info, Central Identification,
 * Identity Info/Address, Signing Info, default) and initiator key
 * distribution of the current Enc+Id keys via smp_distribute_init_keys().
 *
 * The peer offers Just Works (NoInputNoOutput, no MITM, no SC).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_pair_legacy_full_keydist_random);
ATF_TC_BODY(test_pair_legacy_full_keydist_random, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_deep_pair_leg.XXXXXX";
	int bond_fd;
	pid_t pid;

	reset_hci_stubs();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	/* DUT = initiator (central), both RANDOM addresses. */
	setup(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_RANDOM, periph_addr, BDADDR_LE_RANDOM);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int peer = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[65];
		uint8_t tk[16], mrand[16], srand[16];
		uint8_t mconfirm[16], sconfirm[16], verify[16];
		uint8_t iat = BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM;
		uint8_t rat = BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM;	/* initiator=central random,
						 * responder=periph random.
						 * In smp_pair: iat=local(central),
						 * rat=remote(periph). */
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		memset(tk, 0, sizeof(tk));

		/* Receive Pairing Request. */
		n = recv(peer, preq, 7, 0);
		if (n != 7 || preq[0] != BTDL_SMP_PAIRING_REQUEST)
			_exit(1);
		/* Respond: NoIO, no MITM, no SC -> Just Works; offer all keys. */
		pres[0] = BTDL_SMP_PAIRING_RESPONSE;
		pres[1] = BTDL_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = BTDL_SMP_AUTH_BONDING;
		pres[4] = BT_CORE63_SMP_MAX_KEY_SIZE;
		pres[5] = BTDL_SMP_KEY_DIST_ENC_KEY | BTDL_SMP_KEY_DIST_ID_KEY |
		    BTDL_SMP_KEY_DIST_LEGACY_SIGN_KEY;
		pres[6] = BTDL_SMP_KEY_DIST_ENC_KEY | BTDL_SMP_KEY_DIST_ID_KEY |
		    BTDL_SMP_KEY_DIST_LEGACY_SIGN_KEY;
		if (send(peer, pres, 7, MSG_EOR) != 7)
			_exit(2);

		/* Receive initiator confirm. */
		n = recv(peer, pdu, 17, 0);
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(mconfirm, pdu + 1, 16);

		/* Send our (responder) confirm. */
		arc4random_buf(srand, sizeof(srand));
		if (reference_c1(tk, srand, preq, pres, iat, central_addr,
		    rat, periph_addr, sconfirm) < 0)
			_exit(4);
		pdu[0] = BTDL_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(5);

		/* Receive initiator random, verify its confirm. */
		n = recv(peer, pdu, 17, 0);
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_RANDOM)
			_exit(6);
		memcpy(mrand, pdu + 1, 16);
		if (reference_c1(tk, mrand, preq, pres, iat, central_addr,
		    rat, periph_addr, verify) < 0)
			_exit(7);
		if (memcmp(verify, mconfirm, 16) != 0)
			_exit(8);

		/* Send our random. */
		pdu[0] = BTDL_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(9);

		/*
		 * Distribute EVERY key PDU type plus an unknown opcode so the
		 * initiator's receive switch takes every arm.  pres[6] had
		 * Enc+Id+Sign -> expected_pdus = 5; send exactly 5 recognised
		 * PDUs (the unknown opcode replaces nothing, so send it as one
		 * of the Id slots is not possible; instead send Enc, CentralId,
		 * IdInfo, IdAddr, Signing = 5).
		 */
		pdu[0] = BTDL_SMP_ENCRYPTION_INFORMATION;
		memset(pdu + 1, 0x11, 16);
		if (!psend(peer, pdu, 17)) _exit(10);
		pdu[0] = BTDL_SMP_CENTRAL_IDENTIFICATION;
		memset(pdu + 1, 0x22, 10);
		if (!psend(peer, pdu, 11)) _exit(11);
		pdu[0] = BTDL_SMP_IDENTITY_INFORMATION;
		memset(pdu + 1, 0x33, 16);
		if (!psend(peer, pdu, 17)) _exit(12);
		pdu[0] = BTDL_SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM;
		memcpy(pdu + 2, periph_addr, 6);
		if (!psend(peer, pdu, 8)) _exit(13);
		pdu[0] = BTDL_SMP_LEGACY_SIGNING_INFORMATION;
		memset(pdu + 1, 0x44, 16);
		if (!psend(peer, pdu, 17)) _exit(14);

		/*
		 * Core 6.3 §3.6.1 advertises the current EncKey and IdKey bits in
		 * this initiator's captured Request.  The formerly assigned
		 * SignKey bit (0x04) is intentionally absent, so the exact current
		 * sequence ends after Identity Address Information.
		 */
		if ((preq[5] & BTDL_SMP_KEY_DIST_LEGACY_SIGN_KEY) != 0)
			_exit(15);
		if (!peer_recv_shape(peer, pdu, sizeof(pdu), 17,
		    BTDL_SMP_ENCRYPTION_INFORMATION))
			_exit(16);
		if (!peer_recv_shape(peer, pdu, sizeof(pdu), 11,
		    BTDL_SMP_CENTRAL_IDENTIFICATION))
			_exit(17);
		if (!peer_recv_shape(peer, pdu, sizeof(pdu), 17,
		    BTDL_SMP_IDENTITY_INFORMATION))
			_exit(18);
		if (!peer_recv_identity_address(peer, pdu, sizeof(pdu),
		    BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM, central_addr))
			_exit(19);
		close(peer);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "legacy initiator must succeed (errno=%d)",
	    errno);
	ATF_CHECK_MSG(db.count > 0, "initiator must store a bond");
	if (db.count > 0) {
		uint8_t exp_ltk[16], exp_irk[16], exp_csrk[16];

		memset(exp_ltk, 0x11, 16);	/* peer Encryption Info payload */
		memset(exp_irk, 0x33, 16);	/* peer Identity Info payload */
		memset(exp_csrk, 0x44, 16);	/* peer Signing Info payload */
		ATF_CHECK(db.bonds[0].has_ltk);
		ATF_CHECK(db.bonds[0].has_irk);
		ATF_CHECK(db.bonds[0].has_csrk);
		/*
		 * Vol 3 Part H §3.6.2/§3.6.3/§3.6.6: the stored keys must equal
		 * the 128-bit values carried in the peer's key-distribution
		 * PDUs (Encryption/Identity/Signing Information).
		 */
		ATF_CHECK(memcmp(db.bonds[0].ltk, exp_ltk, 16) == 0);
		ATF_CHECK(memcmp(db.bonds[0].irk, exp_irk, 16) == 0);
		ATF_CHECK(memcmp(db.bonds[0].csrk, exp_csrk, 16) == 0);
		/*
		 * Vol 3 Part H §3.6.5: Identity Address Information carries the
		 * peer's identity address (here == periph_addr).
		 */
		ATF_CHECK(memcmp(db.bonds[0].addr, periph_addr, 6) == 0);
		/*
		 * Just Works is not MITM-protected (LE security mode 1 level 2,
		 * Core Spec Vol 3 Part C §10.2.1), so is_mitm must stay false.
		 */
		ATF_CHECK(!db.bonds[0].is_mitm);
		/*
		 * Vol 3 Part H §3.6.5: the Address Type octet 0x01 denotes a
		 * static random identity address, which must be recorded as
		 * BDADDR_LE_RANDOM (2).  smp.c maps the SMP wire octet to the
		 * internal BDADDR_LE_* enum the same way smp_receive_peer_keys()
		 * (smp_keys.c) does; storing the raw octet would mis-record a
		 * random identity address as BDADDR_LE_PUBLIC (1) and break bond
		 * lookup / RPA resolution.  Regression guard for bug #16.
		 */
		ATF_CHECK_EQ(db.bonds[0].addr_type, BDADDR_LE_RANDOM);
	}
	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	close(hci_fds[0]);
	wait_child(pid);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Initiator (smp_pair) legacy: an unknown opcode in the key-receive
 * stream exercises the switch default arm without aborting.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_pair_legacy_unknown_keydist_opcode);
ATF_TC_BODY(test_pair_legacy_unknown_keydist_opcode, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_deep_pair_leg2.XXXXXX";
	int bond_fd;
	pid_t pid;

	reset_hci_stubs();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);
	setup(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int peer = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[65];
		uint8_t tk[16], mrand[16], srand[16];
		uint8_t mconfirm[16], sconfirm[16], verify[16];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		memset(tk, 0, sizeof(tk));

		n = recv(peer, preq, 7, 0);
		if (n != 7 || preq[0] != BTDL_SMP_PAIRING_REQUEST)
			_exit(1);
		pres[0] = BTDL_SMP_PAIRING_RESPONSE;
		pres[1] = BTDL_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0; pres[3] = BTDL_SMP_AUTH_BONDING; pres[4] = BT_CORE63_SMP_MAX_KEY_SIZE;
		pres[5] = 0;
		pres[6] = BTDL_SMP_KEY_DIST_ENC_KEY;	/* expected_pdus = 2 */
		if (send(peer, pres, 7, MSG_EOR) != 7)
			_exit(2);
		n = recv(peer, pdu, 17, 0);
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(mconfirm, pdu + 1, 16);
		arc4random_buf(srand, sizeof(srand));
		if (reference_c1(tk, srand, preq, pres, BT_CORE63_SMP_ID_ADDR_PUBLIC, central_addr,
		    BT_CORE63_SMP_ID_ADDR_PUBLIC, periph_addr, sconfirm) < 0)
			_exit(4);
		pdu[0] = BTDL_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(5);
		n = recv(peer, pdu, 17, 0);
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_RANDOM)
			_exit(6);
		memcpy(mrand, pdu + 1, 16);
		if (reference_c1(tk, mrand, preq, pres, BT_CORE63_SMP_ID_ADDR_PUBLIC, central_addr,
		    BT_CORE63_SMP_ID_ADDR_PUBLIC, periph_addr, verify) < 0)
			_exit(7);
		if (memcmp(verify, mconfirm, 16) != 0)
			_exit(8);
		pdu[0] = BTDL_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(9);

		/* Two PDUs expected: send an unknown opcode + a short one. */
		pdu[0] = BTDL_SMP_PAIRING_KEYPRESS_NOTIFY;	/* unknown in this ctx */
		pdu[1] = 0x00;
		if (send(peer, pdu, 2, MSG_EOR) != 2)
			_exit(10);
		pdu[0] = BTDL_SMP_ENCRYPTION_INFORMATION;	/* short (<17) */
		if (send(peer, pdu, 5, MSG_EOR) != 5)
			_exit(11);

		{
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			uint8_t discard[64];
			setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &tv,
			    sizeof(tv));
			n = recv(peer, discard, sizeof(discard), 0);
			if (n != 2 || discard[0] != BTDL_SMP_PAIRING_FAILED ||
			    discard[1] != BTDL_SMP_ERR_INVALID_PARAMETERS)
				_exit(12);
			while (recv(peer, discard, sizeof(discard), 0) > 0)
				;
		}
		close(peer);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, -1,
	    "malformed negotiated key distribution must abort pairing");
	ATF_CHECK_EQ(errno, EPROTO);
	ATF_CHECK_MSG(db.count == 0,
	    "malformed key distribution must not persist a partial bond");
	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	close(hci_fds[0]);
	wait_child(pid);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Encryption Key Size masking (Core Spec Vol 3 Part H §2.3.4).
 *
 * When the negotiated key size is shorter than 16 octets, the LTK the
 * responder generates and distributes "shall be masked" by zeroing the
 * most significant (16 - key_size) octets before it is distributed or
 * stored.  Keys are held in wire (little-endian) order, so the most
 * significant octets are the highest array indices.  With a negotiated
 * size of 7, indices [7..15] of the stored LTK must be zero and the low 7
 * octets must carry the (random) key material.  This fails before the fix
 * (unmasked random 16-octet LTK) and passes after.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_ltk_masked_to_keysize);
ATF_TC_BODY(test_resp_legacy_ltk_masked_to_keysize, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_deep_leg_mask.XXXXXX";
	int bond_fd;
	pid_t pid;
	uint8_t preq[7], pres[7], tk[16];

	reset_hci_stubs();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup(&sc, &db, bond_fd, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	/*
	 * Simulate the size smp_respond() would have negotiated and stored on
	 * the connection (min(preq[4], pres[4]) = 7).
	 */
	sc.neg_key_size = BT_CORE63_SMP_MIN_KEY_SIZE;

	memset(tk, 0, sizeof(tk));
	preq[0] = BTDL_SMP_PAIRING_REQUEST;
	preq[1] = BTDL_SMP_IO_NO_INPUT_NO_OUTPUT;
	preq[2] = 0x00;
	preq[3] = BTDL_SMP_AUTH_BONDING;
	preq[4] = BT_CORE63_SMP_MIN_KEY_SIZE;			/* negotiated key size 7 */
	preq[5] = 0;			/* initiator distributes nothing */
	preq[6] = BTDL_SMP_KEY_DIST_ENC_KEY;	/* responder distributes EncKey */
	memcpy(pres, preq, 7);
	pres[0] = BTDL_SMP_PAIRING_RESPONSE;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int peer = smp_fds[1];
		uint8_t pdu[65], mrand[16], srand[16];
		uint8_t mconfirm[16], sconfirm[16], verify[16];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		arc4random_buf(mrand, sizeof(mrand));
		if (reference_c1(tk, mrand, preq, pres, BT_CORE63_SMP_ID_ADDR_PUBLIC, central_addr,
		    BT_CORE63_SMP_ID_ADDR_PUBLIC, periph_addr, mconfirm) < 0)
			_exit(1);
		pdu[0] = BTDL_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, mconfirm, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(2);
		n = recv(peer, pdu, 17, 0);
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(sconfirm, pdu + 1, 16);
		pdu[0] = BTDL_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, mrand, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(4);
		n = recv(peer, pdu, 17, 0);
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_RANDOM)
			_exit(5);
		memcpy(srand, pdu + 1, 16);
		if (reference_c1(tk, srand, preq, pres, BT_CORE63_SMP_ID_ADDR_PUBLIC, central_addr,
		    BT_CORE63_SMP_ID_ADDR_PUBLIC, periph_addr, verify) < 0)
			_exit(6);
		if (memcmp(verify, sconfirm, 16) != 0)
			_exit(7);

		/*
		 * Core §2.3.4 masks the most-significant 16-key_size octets of
		 * the distributed LTK itself, not merely the stored copy.
		 */
		if (!peer_recv_shape(peer, pdu, sizeof(pdu), 17,
		    BTDL_SMP_ENCRYPTION_INFORMATION))
			_exit(8);
		for (int i = BT_CORE63_SMP_MIN_KEY_SIZE;
		    i < BT_CORE63_SMP_MAX_KEY_SIZE; i++) {
			if (pdu[i + 1] != 0)
				_exit(9);
		}
		if (!peer_recv_shape(peer, pdu, sizeof(pdu), 11,
		    BTDL_SMP_CENTRAL_IDENTIFICATION))
			_exit(10);
		close(peer);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_respond_legacy(&sc, preq, pres, tk);
	ATF_CHECK_EQ_MSG(ret, 0, "legacy responder must succeed (errno=%d)",
	    errno);
	ATF_REQUIRE_MSG(db.count > 0, "responder must store a bond");
	ATF_CHECK(db.bonds[0].has_ltk);

	/* §2.3.4: MS (16 - 7) = 9 octets masked to zero. */
	for (int i = 7; i < 16; i++)
		ATF_CHECK_EQ_MSG(db.bonds[0].ltk[i], 0,
		    "LTK octet %d (most-significant) must be masked to 0", i);
	/* Low 7 octets carry random key material (not all zero). */
	{
		int nz = 0;
		for (int i = 0; i < 7; i++)
			nz |= db.bonds[0].ltk[i];
		ATF_CHECK_MSG(nz != 0, "masked LTK retains its low 7 octets");
	}

	/*
	 * §2.3.4: the negotiated key size must also be PERSISTED on the bond
	 * so the true encryption strength can be reported after an Encryption
	 * Change (blued_event.c) instead of assuming a full 16 octets.  Fails
	 * before the fix (key_size left 0 by the memset); passes after.
	 */
	ATF_CHECK_EQ_MSG(db.bonds[0].key_size, BT_CORE63_SMP_MIN_KEY_SIZE,
	    "bond must persist the negotiated key size (7), got %u",
	    db.bonds[0].key_size);

	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Bond authentication level (is_mitm) recording for legacy pairing.
 *
 * Legacy Passkey Entry is an MITM-protected association model, so the
 * resulting bond is "Authenticated pairing with encryption" — LE
 * security mode 1 level 3 (Core Spec Vol 3 Part C §10.2.1; the model
 * mapping is Vol 3 Part H Table 2.8 / §2.3.5.1).  Just Works provides
 * no MITM protection (level 2).  The stored bond's is_mitm flag must
 * reflect this so the daemon does not later mis-classify an
 * authenticated legacy bond as unauthenticated.
 * ================================================================ */

/* Passkey UI stub: we are the input side (display == false). */
static uint32_t g_test_passkey = 424242;
static int
test_passkey_input_cb(uint32_t *passkey_out, bool display, void *arg __unused)
{

	if (!display)
		*passkey_out = g_test_passkey;
	return (0);
}

/*
 * Initiator (smp_pair) legacy Passkey Entry.  We advertise KeyboardOnly
 * and the peer advertises DisplayOnly with MITM set, which selects
 * Passkey Entry (Table 2.8) — an authenticated model.  The peer must
 * distribute an LTK for the bond to be stored.  The stored bond must
 * record is_mitm == true (and is_sc == false).
 */
ATF_TC_WITHOUT_HEAD(test_pair_legacy_passkey_is_mitm);
ATF_TC_BODY(test_pair_legacy_passkey_is_mitm, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_deep_pair_pk.XXXXXX";
	int bond_fd;
	pid_t pid;

	reset_hci_stubs();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_RANDOM, periph_addr, BDADDR_LE_RANDOM);
	sc.io_capability = BTDL_SMP_IO_KEYBOARD_ONLY;	/* we input */
	sc.passkey_cb = test_passkey_input_cb;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int peer = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[65];
		uint8_t tk[16], mrand[16], srand[16];
		uint8_t mconfirm[16], sconfirm[16], verify[16];
		uint8_t iat = BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM;
		uint8_t rat = BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM;
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);

		/* TK = passkey as a 128-bit little-endian integer. */
		memset(tk, 0, sizeof(tk));
		tk[0] = g_test_passkey & 0xFF;
		tk[1] = (g_test_passkey >> 8) & 0xFF;
		tk[2] = (g_test_passkey >> 16) & 0xFF;

		/* Receive Pairing Request. */
		n = recv(peer, preq, 7, 0);
		if (n != 7 || preq[0] != BTDL_SMP_PAIRING_REQUEST)
			_exit(1);
		/* Respond: DisplayOnly + MITM, no SC -> legacy Passkey Entry. */
		pres[0] = BTDL_SMP_PAIRING_RESPONSE;
		pres[1] = BTDL_SMP_IO_DISPLAY_ONLY;
		pres[2] = 0x00;
		pres[3] = BTDL_SMP_AUTH_BONDING | BTDL_SMP_AUTH_MITM;
		pres[4] = BT_CORE63_SMP_MAX_KEY_SIZE;
		pres[5] = 0x00;			/* initiator distributes nothing */
		pres[6] = BTDL_SMP_KEY_DIST_ENC_KEY;	/* we distribute an LTK */
		if (send(peer, pres, 7, MSG_EOR) != 7)
			_exit(2);

		/* Receive initiator confirm. */
		n = recv(peer, pdu, 17, 0);
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(mconfirm, pdu + 1, 16);

		/* Send our (responder) confirm using the same passkey TK. */
		arc4random_buf(srand, sizeof(srand));
		if (reference_c1(tk, srand, preq, pres, iat, central_addr,
		    rat, periph_addr, sconfirm) < 0)
			_exit(4);
		pdu[0] = BTDL_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(5);

		/* Receive initiator random, verify its confirm. */
		n = recv(peer, pdu, 17, 0);
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_RANDOM)
			_exit(6);
		memcpy(mrand, pdu + 1, 16);
		if (reference_c1(tk, mrand, preq, pres, iat, central_addr,
		    rat, periph_addr, verify) < 0)
			_exit(7);
		if (memcmp(verify, mconfirm, 16) != 0)
			_exit(8);	/* passkey mismatch */

		/* Send our random. */
		pdu[0] = BTDL_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(9);

		/* Distribute our LTK (Encryption Info + Central Id). */
		pdu[0] = BTDL_SMP_ENCRYPTION_INFORMATION;
		memset(pdu + 1, 0x55, 16);
		if (!psend(peer, pdu, 17)) _exit(10);
		pdu[0] = BTDL_SMP_CENTRAL_IDENTIFICATION;
		memset(pdu + 1, 0x66, 10);
		if (!psend(peer, pdu, 11)) _exit(11);

		close(peer);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "legacy passkey initiator must succeed "
	    "(errno=%d)", errno);
	ATF_CHECK_MSG(db.count > 0, "initiator must store a bond");
	if (db.count > 0) {
		uint8_t expected_ltk[16];

		memset(expected_ltk, 0x55, sizeof(expected_ltk));
		ATF_CHECK(db.bonds[0].has_ltk);
		/* Core §3.6.2: persist the exact peer Encryption Information. */
		ATF_CHECK(memcmp(db.bonds[0].ltk, expected_ltk,
		    sizeof(expected_ltk)) == 0);
		/*
		 * Core Spec Vol 3 Part C §10.2.1: Passkey Entry is
		 * MITM-protected (level 3, authenticated).  Legacy pairing is
		 * not Secure Connections, so is_sc must remain false.
		 */
		ATF_CHECK_MSG(db.bonds[0].is_mitm,
		    "legacy Passkey Entry bond must record is_mitm");
		ATF_CHECK(!db.bonds[0].is_sc);
	}
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/*
 * Responder (smp_respond_legacy) legacy Passkey Entry.  preq/pres are
 * built as smp_respond() would after negotiating KeyboardOnly (peer) vs
 * DisplayOnly (us) with MITM — Passkey Entry, an authenticated model.
 * The stored bond must record is_mitm == true.
 */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_passkey_is_mitm);
ATF_TC_BODY(test_resp_legacy_passkey_is_mitm, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_deep_resp_pk.XXXXXX";
	int bond_fd;
	pid_t pid;
	uint8_t preq[7], pres[7], tk[16];

	reset_hci_stubs();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup(&sc, &db, bond_fd, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_RANDOM, central_addr, BDADDR_LE_RANDOM);

	/* TK = passkey (128-bit LE); smp_respond() would have set this. */
	memset(tk, 0, sizeof(tk));
	tk[0] = g_test_passkey & 0xFF;
	tk[1] = (g_test_passkey >> 8) & 0xFF;
	tk[2] = (g_test_passkey >> 16) & 0xFF;

	/* Initiator KeyboardOnly, responder (us) DisplayOnly.  The responder
	 * alone requests MITM; Table 2.8 still selects Passkey Entry, so the
	 * completed bond remains authenticated. */
	preq[0] = BTDL_SMP_PAIRING_REQUEST;
	preq[1] = BTDL_SMP_IO_KEYBOARD_ONLY;
	preq[2] = 0x00;
	preq[3] = BTDL_SMP_AUTH_BONDING;
	preq[4] = BT_CORE63_SMP_MAX_KEY_SIZE;
	preq[5] = 0x00;
	preq[6] = BTDL_SMP_KEY_DIST_ENC_KEY;
	memcpy(pres, preq, 7);
	pres[0] = BTDL_SMP_PAIRING_RESPONSE;
	pres[1] = BTDL_SMP_IO_DISPLAY_ONLY;
	pres[3] |= BTDL_SMP_AUTH_MITM;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int peer = smp_fds[1];
		uint8_t pdu[65], mrand[16], srand[16];
		uint8_t mconfirm[16], sconfirm[16], verify[16];
		uint8_t iat = BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM;
		uint8_t rat = BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM;
		uint8_t ctk[16];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);

		memset(ctk, 0, sizeof(ctk));
		ctk[0] = g_test_passkey & 0xFF;
		ctk[1] = (g_test_passkey >> 8) & 0xFF;
		ctk[2] = (g_test_passkey >> 16) & 0xFF;

		/* Send our (initiator) confirm. */
		arc4random_buf(mrand, sizeof(mrand));
		if (reference_c1(ctk, mrand, preq, pres, iat, central_addr,
		    rat, periph_addr, mconfirm) < 0)
			_exit(1);
		pdu[0] = BTDL_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, mconfirm, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(2);

		/* Receive responder confirm. */
		n = recv(peer, pdu, 17, 0);
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(sconfirm, pdu + 1, 16);

		/* Send our random. */
		pdu[0] = BTDL_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, mrand, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(4);

		/* Receive responder random, verify its confirm. */
		n = recv(peer, pdu, 17, 0);
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_RANDOM)
			_exit(5);
		memcpy(srand, pdu + 1, 16);
		if (reference_c1(ctk, srand, preq, pres, iat, central_addr,
		    rat, periph_addr, verify) < 0)
			_exit(6);
		if (memcmp(verify, sconfirm, 16) != 0)
			_exit(7);

		/* Core §§3.6.1, 3.6.2, and 3.6.4: exact EncKey pair. */
		if (!peer_recv_shape(peer, pdu, sizeof(pdu), 17,
		    BTDL_SMP_ENCRYPTION_INFORMATION) ||
		    !peer_recv_shape(peer, pdu, sizeof(pdu), 11,
		    BTDL_SMP_CENTRAL_IDENTIFICATION))
			_exit(8);
		close(peer);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_respond_legacy(&sc, preq, pres, tk);
	ATF_CHECK_EQ_MSG(ret, 0, "legacy passkey responder must succeed "
	    "(errno=%d)", errno);
	ATF_CHECK_MSG(db.count > 0, "responder must store a bond");
	if (db.count > 0) {
		/*
		 * Core Spec Vol 3 Part C §10.2.1: Passkey Entry yields an
		 * authenticated (MITM-protected) bond.  Legacy pairing is not
		 * Secure Connections.
		 */
		ATF_CHECK_MSG(db.bonds[0].is_mitm,
		    "legacy Passkey Entry bond must record is_mitm");
		ATF_CHECK(!db.bonds[0].is_sc);
	}

	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/*
 * P17 harness: run a full legacy Just Works responder exchange (no key
 * distribution either way) with a given Bonding advertisement on BOTH sides,
 * and return the number of bonds persisted.  `bonding` sets the Bonding flag
 * (Core Spec Vol 3 Part H §3.5.1) in preq[3] and pres[3]; everything else is
 * identical, isolating the persistence decision on the Bonding flag alone.
 */
static int
p17_run_legacy_jw(bool bonding, uint8_t responder_dist,
    bool fail_persistence, const char *crypto_fail_op, int *pair_ret)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_p17.XXXXXX";
	int bond_fd, count;
	pid_t pid;
	uint8_t preq[7], pres[7], tk[16];
	uint8_t auth = bonding ? BTDL_SMP_AUTH_BONDING : 0x00;

	reset_hci_stubs();
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	/* DUT = responder, both addresses PUBLIC, legacy Just Works. */
	setup(&sc, &db, bond_fd, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, central_addr, BDADDR_LE_PUBLIC);
	/* A responder may run without persistent storage (for example a
	 * session-only, non-bondable policy).  Requested local IdKey/SignKey
	 * distribution must then skip the database-backed material safely. */
	if (crypto_fail_op != NULL && strcmp(crypto_fail_op, "no-db") == 0)
		sc.bond_db = NULL;

	memset(tk, 0, sizeof(tk));
	preq[0] = BTDL_SMP_PAIRING_REQUEST;
	preq[1] = BTDL_SMP_IO_NO_INPUT_NO_OUTPUT;
	preq[2] = 0x00;
	preq[3] = auth;			/* Just Works: no MITM, no SC */
	preq[4] = BT_CORE63_SMP_MAX_KEY_SIZE;
	preq[5] = 0x00;			/* no key distribution either way */
	preq[6] = responder_dist;
	memcpy(pres, preq, 7);
	pres[0] = BTDL_SMP_PAIRING_RESPONSE;
	/* Exercise the legacy OOB authentication classification and the CT2
	 * negotiation rule independently: CT2 requires both peers, while OOB
	 * authentication requires both legacy OOB flags. */
	if (crypto_fail_op != NULL &&
	    strcmp(crypto_fail_op, "oob-ct2-mismatch") == 0) {
		preq[2] = pres[2] = 1;
		preq[3] |= BTDL_SMP_AUTH_CT2;
	}
	/* Legacy OOB authentication requires both peers to advertise OOB data.
	 * A one-sided advertisement remains Just Works (Vol 3 Part H Table 2.6),
	 * and must not mark the resulting bond MITM-protected. */
	if (crypto_fail_op != NULL &&
	    strcmp(crypto_fail_op, "one-sided-oob") == 0)
		preq[2] = 1;
	if (crypto_fail_op != NULL &&
	    strcmp(crypto_fail_op, "responder-mitm") == 0)
		pres[3] |= BTDL_SMP_AUTH_MITM;
	if (fail_persistence) {
		/* A configured but unusable atomic target makes the real bond
		 * persistence operation fail after the protocol has completed.
		 * fd 0 is deliberately not a directory, so openat(2) must reject
		 * the final atomic-save step without relying on host permissions. */
		smp_bond_db_set_atomic(&db, STDIN_FILENO, "bonds");
	}
	if (crypto_fail_op != NULL) {
		g_crypto_fail_op = crypto_fail_op;
		smp_legacy_crypto_hook = legacy_crypto_fail_hook;
	}

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int peer = smp_fds[1];
		uint8_t pdu[65], mrand[16], sconfirm[16], mconfirm[16];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		if (crypto_fail_op != NULL || fail_persistence) {
			struct timeval tv = { .tv_sec = 1,
			    .tv_usec = 0 };
			setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		}

		arc4random_buf(mrand, sizeof(mrand));
		if (reference_c1(tk, mrand, preq, pres, BT_CORE63_SMP_ID_ADDR_PUBLIC, central_addr,
		    BT_CORE63_SMP_ID_ADDR_PUBLIC, periph_addr, mconfirm) < 0)
			_exit(1);
		pdu[0] = BTDL_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, mconfirm, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(2);

		n = recv(peer, pdu, 17, 0);
		if (crypto_fail_op != NULL && strcmp(crypto_fail_op, "c1") == 0) {
			/* The responder must abort immediately on a c1 failure. */
			if (n > 0)
				_exit(3);
			close(peer);
			_exit(0);
		}
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(sconfirm, pdu + 1, 16);
		/* A transport EOF at a mandatory receive boundary is distinct from
		 * the peer's explicit Pairing Failed PDU. */
		if (crypto_fail_op != NULL &&
		    strcmp(crypto_fail_op, "eof-random") == 0) {
			close(peer);
			_exit(0);
		}

		pdu[0] = BTDL_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, mrand, 16);
		if (send(peer, pdu, 17, MSG_EOR) != 17)
			_exit(4);
		if (crypto_fail_op != NULL &&
		    strcmp(crypto_fail_op, "c1-verify") == 0) {
			close(peer);
			_exit(0);
		}
		/* Closing at this protocol boundary makes the responder's next
		 * mandatory transmission (its Pairing Random) fail.  This is the
		 * transport-error path after confirm verification, distinct from
		 * the existing failure while sending Pairing Confirm. */
		if (crypto_fail_op != NULL &&
		    strcmp(crypto_fail_op, "send-random") == 0) {
			close(peer);
			_exit(0);
		}

		n = recv(peer, pdu, 17, 0);	/* responder random */
		if (n != 17 || pdu[0] != BTDL_SMP_PAIRING_RANDOM)
			_exit(5);
		/*
		 * A negotiated IdKey cannot be advertised unless its local IRK is
		 * retained (§3.6.3).  Persistence failure or an absent database
		 * must therefore produce no Identity Information PDU.
		 */
		if ((fail_persistence &&
		    (responder_dist & BTDL_SMP_KEY_DIST_ID_KEY) != 0) ||
		    (crypto_fail_op != NULL &&
		    strcmp(crypto_fail_op, "no-db") == 0)) {
			n = recv(peer, pdu, sizeof(pdu), 0);
			if (n > 0)
				_exit(6);
			close(peer);
			_exit(0);
		}
		/* s1 is reached only after both random values are exchanged. */
		if (crypto_fail_op != NULL && strcmp(crypto_fail_op, "s1") == 0) {
			close(peer);
			_exit(0);
		}

		close(peer);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	{
		int ret = smp_respond_legacy(&sc, preq, pres, tk);
		if (pair_ret != NULL)
			*pair_ret = ret;
		else
			ATF_CHECK_EQ_MSG(ret, 0,
			    "legacy JW responder must complete (errno=%d)", errno);
	}
	count = db.count;
	p17_last_bond_mitm = count == 0 ? -1 : db.bonds[0].is_mitm;

	wait_child(pid);
	g_crypto_fail_op = NULL;
	smp_legacy_crypto_hook = NULL;
	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
	return (count);
}

/*
 * P17: a "No Bonding" peer's keys must be session-only — the bond must NOT be
 * persisted even though an LTK exists (Core Spec Vol 3 Part H §3.5.1 /
 * §2.3.5.1).  With both sides advertising Bonding the bond IS persisted.  The
 * two runs are identical except for the Bonding flag.
 */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_no_bonding_not_persisted);
ATF_TC_BODY(test_resp_legacy_no_bonding_not_persisted, tc)
{

	ATF_CHECK_EQ_MSG(p17_run_legacy_jw(false, 0, false, NULL, NULL), 0,
	    "No-Bonding pairing must NOT persist a bond (keys session-only)");
	ATF_CHECK_EQ_MSG(p17_run_legacy_jw(true, 0, false, NULL, NULL), 1,
	    "Bonding pairing must persist exactly one bond");
}

/* A failed identity-key persistence must abort before either identity PDU is
 * emitted; continuing would advertise key material which cannot be retained. */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_identity_persist_failure);
ATF_TC_BODY(test_resp_legacy_identity_persist_failure, tc)
{
	int ret = 0;

	ATF_CHECK_EQ(p17_run_legacy_jw(true, BTDL_SMP_KEY_DIST_ID_KEY, true, NULL, &ret),
	    0);
	ATF_CHECK_EQ(ret, -1);
}

/* A bond-store failure after encryption must roll the in-memory append back
 * and report pairing failure rather than claim a durable bond. */
ATF_TC_WITHOUT_HEAD(test_resp_legacy_bond_store_failure);
ATF_TC_BODY(test_resp_legacy_bond_store_failure, tc)
{
	int ret = 0;

	ATF_CHECK_EQ(p17_run_legacy_jw(true, 0, true, NULL, &ret), 0);
	ATF_CHECK_EQ(ret, -1);
}

ATF_TC_WITHOUT_HEAD(test_resp_legacy_c1_crypto_failure);
ATF_TC_BODY(test_resp_legacy_c1_crypto_failure, tc)
{
	int ret = 0;

	ATF_CHECK_EQ(p17_run_legacy_jw(true, 0, false, "c1", &ret), 0);
	ATF_CHECK_EQ(ret, -1);
}

ATF_TC_WITHOUT_HEAD(test_resp_legacy_verify_c1_crypto_failure);
ATF_TC_BODY(test_resp_legacy_verify_c1_crypto_failure, tc)
{
	int ret;

	ATF_CHECK_EQ(p17_run_legacy_jw(true, 0, false, "c1-verify", &ret), 0);
	ATF_CHECK_EQ(ret, -1);
}

ATF_TC_WITHOUT_HEAD(test_resp_legacy_s1_crypto_failure);
ATF_TC_BODY(test_resp_legacy_s1_crypto_failure, tc)
{
	int ret = 0;

	ATF_CHECK_EQ(p17_run_legacy_jw(true, 0, false, "s1", &ret), 0);
	ATF_CHECK_EQ(ret, -1);
}

ATF_TC_WITHOUT_HEAD(test_resp_legacy_send_random_fails);
ATF_TC_BODY(test_resp_legacy_send_random_fails, tc)
{
	int ret = 0;

	ATF_CHECK_EQ(p17_run_legacy_jw(true, 0, false, "send-random", &ret),
	    0);
	ATF_CHECK_EQ(ret, -1);
}

ATF_TC_WITHOUT_HEAD(test_resp_legacy_eof_at_random);
ATF_TC_BODY(test_resp_legacy_eof_at_random, tc)
{
	int ret;

	ATF_CHECK_EQ(p17_run_legacy_jw(true, 0, false, "eof-random", &ret), 0);
	ATF_CHECK_EQ(ret, -1);
}

ATF_TC_WITHOUT_HEAD(test_resp_legacy_keydist_without_database);
ATF_TC_BODY(test_resp_legacy_keydist_without_database, tc)
{
	int ret;

	ATF_CHECK_EQ(p17_run_legacy_jw(false,
	    BTDL_SMP_KEY_DIST_ID_KEY | BTDL_SMP_KEY_DIST_LEGACY_SIGN_KEY, false, "no-db", &ret),
	    0);
	ATF_CHECK_EQ_MSG(ret, -1,
	    "negotiated persistent key distribution without a database must abort");
}

ATF_TC_WITHOUT_HEAD(test_resp_legacy_oob_ct2_negotiation);
ATF_TC_BODY(test_resp_legacy_oob_ct2_negotiation, tc)
{

	ATF_CHECK_EQ(p17_run_legacy_jw(true, 0, false, "oob-ct2-mismatch", NULL),
	    1);
}

ATF_TC_WITHOUT_HEAD(test_resp_legacy_one_sided_mitm_jw);
ATF_TC_BODY(test_resp_legacy_one_sided_mitm_jw, tc)
{

	/* With neither side capable of authenticated input/output, Table 2.6
	 * remains Just Works even if the responder asks for MITM protection. */
	ATF_CHECK_EQ(p17_run_legacy_jw(true, 0, false, "responder-mitm", NULL),
	    1);
}

ATF_TC_WITHOUT_HEAD(test_resp_legacy_one_sided_oob_jw);
ATF_TC_BODY(test_resp_legacy_one_sided_oob_jw, tc)
{

	/* The daemonized diagnostic path is a supported deployment mode.  This
	 * complete Just Works exchange also verifies that it does not alter the
	 * Table 2.6 association-model result. */
	blued_daemonized = 1;
	ATF_CHECK_EQ(p17_run_legacy_jw(true, 0, false, "one-sided-oob", NULL),
	    1);
	blued_daemonized = 0;
	ATF_CHECK_EQ(p17_last_bond_mitm, 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_resp_legacy_no_bonding_not_persisted);
	ATF_TP_ADD_TC(tp, test_resp_legacy_identity_persist_failure);
	ATF_TP_ADD_TC(tp, test_resp_legacy_bond_store_failure);
	ATF_TP_ADD_TC(tp, test_resp_legacy_c1_crypto_failure);
	ATF_TP_ADD_TC(tp, test_resp_legacy_verify_c1_crypto_failure);
	ATF_TP_ADD_TC(tp, test_resp_legacy_s1_crypto_failure);
	ATF_TP_ADD_TC(tp, test_resp_legacy_send_random_fails);
	ATF_TP_ADD_TC(tp, test_resp_legacy_eof_at_random);
	ATF_TP_ADD_TC(tp, test_resp_legacy_keydist_without_database);
	ATF_TP_ADD_TC(tp, test_resp_legacy_oob_ct2_negotiation);
	ATF_TP_ADD_TC(tp, test_resp_legacy_one_sided_mitm_jw);
	ATF_TP_ADD_TC(tp, test_resp_legacy_one_sided_oob_jw);
	ATF_TP_ADD_TC(tp, test_resp_legacy_random_all_keys_ct2);
	ATF_TP_ADD_TC(tp, test_resp_legacy_confirm_mismatch);
	ATF_TP_ADD_TC(tp, test_resp_legacy_wrong_confirm_opcode);
	ATF_TP_ADD_TC(tp, test_resp_legacy_times_out_before_confirm);
	ATF_TP_ADD_TC(tp, test_resp_legacy_times_out_before_random);
	ATF_TP_ADD_TC(tp, test_resp_legacy_injected_failed_at_random);
	ATF_TP_ADD_TC(tp, test_resp_legacy_wrong_random_opcode);
	ATF_TP_ADD_TC(tp, test_resp_legacy_ltk_reply_fail);
	ATF_TP_ADD_TC(tp, test_resp_legacy_wait_enc_fail);
	ATF_TP_ADD_TC(tp, test_resp_legacy_send_confirm_fails);
	ATF_TP_ADD_TC(tp, test_pair_legacy_full_keydist_random);
	ATF_TP_ADD_TC(tp, test_pair_legacy_unknown_keydist_opcode);
	ATF_TP_ADD_TC(tp, test_resp_legacy_ltk_masked_to_keysize);
	ATF_TP_ADD_TC(tp, test_pair_legacy_passkey_is_mitm);
	ATF_TP_ADD_TC(tp, test_resp_legacy_passkey_is_mitm);

	return (atf_no_error());
}
