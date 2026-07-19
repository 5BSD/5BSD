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
#include <fcntl.h>
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
#include "smp_internal.h"	/* smp_clock_hook (frozen-clock seam) */
#include "spec_bond_db_contract_oracles.h"
#include "spec_core63_generated.h"
#include "spec_hci_emulator_enc_oracles.h"
#include "spec_oracles.h"
#include "spec_privacy_oracles.h"
#include "spec_smp_timeout_oracles.h"

#define TEST_LINKS_SMP
#include "test_common.h"

/* Expand generated Core assignments into test-only names, keeping wire
 * stimuli and expectations independent from production smp.h constants. */
#define SMP_PAIRING_COMMAND_ORACLE(name, value) BTPR_##name = (value),
enum { BT_CORE63_SMP_COMMAND_ORACLES(SMP_PAIRING_COMMAND_ORACLE) };
#undef SMP_PAIRING_COMMAND_ORACLE
#define SMP_PAIRING_SCALAR_ORACLE(name, value) BTPR_##name = (value),
enum { BT_CORE63_SMP_SCALAR_ORACLES(SMP_PAIRING_SCALAR_ORACLE) };
#undef SMP_PAIRING_SCALAR_ORACLE
#define SMP_PAIRING_KEYPRESS_ORACLE(name, value) BTPR_##name = (value),
enum { BT_CORE63_SMP_KEYPRESS_ORACLES(SMP_PAIRING_KEYPRESS_ORACLE) };
#undef SMP_PAIRING_KEYPRESS_ORACLE
#define SMP_PAIRING_FAILURE_ORACLE(name, value) BTPR_##name = (value),
enum { BT_CORE63_SMP_FAILURE_ORACLES(SMP_PAIRING_FAILURE_ORACLE) };
#undef SMP_PAIRING_FAILURE_ORACLE
#define SMP_PAIRING_KEYDIST_ORACLE(name, value) BTPR_##name = (value),
enum { BT_CORE63_SMP_KEY_DIST_ORACLES(SMP_PAIRING_KEYDIST_ORACLE) };
#undef SMP_PAIRING_KEYDIST_ORACLE
#define SMP_PAIRING_PREVIOUS_ORACLE(name, value) BTPR_##name = (value),
enum { BT_CORE63_PREVIOUSLY_USED_ORACLES(SMP_PAIRING_PREVIOUS_ORACLE) };
#undef SMP_PAIRING_PREVIOUS_ORACLE

static void
enable_atomic_bond_save(struct smp_bond_db *db, const char *path)
{
	int dir_fd;

	dir_fd = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(dir_fd >= 0);
	smp_bond_db_set_atomic(db, dir_fd, path);
}

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

/* Decode the Core appendix's published big-endian hex, then reverse it into
 * the little-octet-first arrays consumed by the SMP implementation. */
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

static void
reverse_copy(uint8_t *out, const uint8_t *in, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		out[i] = in[len - 1 - i];
}

static int
reference_cmac_be(const uint8_t key[16], const uint8_t *message,
    size_t message_len, uint8_t mac[16])
{
	size_t mac_len;

	mac_len = 0;
	return (EVP_Q_mac(NULL, "CMAC", NULL, "AES-128-CBC", NULL,
	    key, 16, message, message_len, mac, 16, &mac_len) != NULL &&
	    mac_len == 16 ? 0 : -1);
}

/* Independent Core 6.3 Vol 3 Part H §2.2.6 f4 oracle.  This uses OpenSSL's
 * one-shot CMAC directly and does not call any blued crypto helper. */
static int
reference_f4(const uint8_t u_le[32], const uint8_t v_le[32],
    const uint8_t x_le[16], uint8_t z, uint8_t out_le[16])
{
	uint8_t key_be[16], message[65], mac_be[16];
	size_t i, out_len;

	for (i = 0; i < 32; i++) {
		message[i] = u_le[31 - i];
		message[32 + i] = v_le[31 - i];
	}
	message[64] = z;
	for (i = 0; i < 16; i++)
		key_be[i] = x_le[15 - i];
	out_len = 0;
	if (EVP_Q_mac(NULL, "CMAC", NULL, "AES-128-CBC", NULL,
	    key_be, sizeof(key_be), message, sizeof(message), mac_be,
	    sizeof(mac_be), &out_len) == NULL || out_len != sizeof(mac_be))
		return (-1);
	for (i = 0; i < 16; i++)
		out_le[i] = mac_be[15 - i];
	explicit_bzero(key_be, sizeof(key_be));
	explicit_bzero(mac_be, sizeof(mac_be));
	return (0);
}

/* Independent Core 6.3 Vol 3 Part H §2.2.7 f5 oracle.  SALT and ASCII
 * keyID "btle" are the exact constants printed by that section. */
static int
reference_f5(const uint8_t w_le[32], const uint8_t n1_le[16],
    const uint8_t n2_le[16], const uint8_t a1_le[7],
    const uint8_t a2_le[7], uint8_t mackey_le[16], uint8_t ltk_le[16])
{
	static const uint8_t salt[16] = {
		0x6c, 0x88, 0x83, 0x91, 0xaa, 0xf5, 0xa5, 0x38,
		0x60, 0x37, 0x0b, 0xdb, 0x5a, 0x60, 0x83, 0xbe
	};
	static const uint8_t keyid_btle[4] = { 0x62, 0x74, 0x6c, 0x65 };
	uint8_t t[16], w_be[32], message[53], mac[16];
	int rc;

	reverse_copy(w_be, w_le, sizeof(w_be));
	if (reference_cmac_be(salt, w_be, sizeof(w_be), t) != 0)
		return (-1);
	message[0] = 0;
	memcpy(message + 1, keyid_btle, sizeof(keyid_btle));
	reverse_copy(message + 5, n1_le, 16);
	reverse_copy(message + 21, n2_le, 16);
	reverse_copy(message + 37, a1_le, 7);
	reverse_copy(message + 44, a2_le, 7);
	message[51] = 0x01;
	message[52] = 0x00;
	rc = reference_cmac_be(t, message, sizeof(message), mac);
	if (rc == 0)
		reverse_copy(mackey_le, mac, 16);
	message[0] = 1;
	if (rc == 0)
		rc = reference_cmac_be(t, message, sizeof(message), mac);
	if (rc == 0)
		reverse_copy(ltk_le, mac, 16);
	explicit_bzero(t, sizeof(t));
	explicit_bzero(mac, sizeof(mac));
	return (rc);
}

/* Independent Core 6.3 Vol 3 Part H §2.2.8 f6 oracle. */
static int
reference_f6(const uint8_t w_le[16], const uint8_t n1_le[16],
    const uint8_t n2_le[16], const uint8_t r_le[16],
    const uint8_t iocap_le[3], const uint8_t a1_le[7],
    const uint8_t a2_le[7], uint8_t out_le[16])
{
	uint8_t key_be[16], message[65], mac[16];
	int rc;

	reverse_copy(key_be, w_le, 16);
	reverse_copy(message, n1_le, 16);
	reverse_copy(message + 16, n2_le, 16);
	reverse_copy(message + 32, r_le, 16);
	reverse_copy(message + 48, iocap_le, 3);
	reverse_copy(message + 51, a1_le, 7);
	reverse_copy(message + 58, a2_le, 7);
	rc = reference_cmac_be(key_be, message, sizeof(message), mac);
	if (rc == 0)
		reverse_copy(out_le, mac, 16);
	explicit_bzero(key_be, sizeof(key_be));
	explicit_bzero(mac, sizeof(mac));
	return (rc);
}

/* Independent AES-128-ECB adapter for SMP's little-octet-first convention. */
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

/* Core 6.3 Vol 3 Part H §2.2.3 c1, independent of production reference_c1(). */
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

/* Prove the independent SC peer primitives against the published Appendix
 * D.2-D.4 KATs before using them as transcript oracles. */
static bool
reference_sc_oracles_match_core(void)
{
	uint8_t u[32], v[32], x[16], f4_expected[16], f4_out[16];
	uint8_t w[32], n1[16], n2[16], a1[7], a2[7];
	uint8_t mackey_expected[16], ltk_expected[16], mackey[16], ltk[16];
	uint8_t r[16], iocap[3], f6_expected[16], f6_out[16];

	core_hex_le(u, BT_CORE63_SMP_D2_U_HEX, sizeof(u));
	core_hex_le(v, BT_CORE63_SMP_D2_V_HEX, sizeof(v));
	core_hex_le(x, BT_CORE63_SMP_D2_X_HEX, sizeof(x));
	core_hex_le(f4_expected, BT_CORE63_SMP_D2_OUT_HEX,
	    sizeof(f4_expected));
	if (reference_f4(u, v, x, BT_CORE63_SMP_D2_Z, f4_out) != 0 ||
	    memcmp(f4_out, f4_expected, sizeof(f4_out)) != 0)
		return (false);

	core_hex_le(w, BT_CORE63_SMP_D3_DHKEY_HEX, sizeof(w));
	core_hex_le(n1, BT_CORE63_SMP_D3_N1_HEX, sizeof(n1));
	core_hex_le(n2, BT_CORE63_SMP_D3_N2_HEX, sizeof(n2));
	core_hex_le(a1, BT_CORE63_SMP_D3_A1_HEX, sizeof(a1));
	core_hex_le(a2, BT_CORE63_SMP_D3_A2_HEX, sizeof(a2));
	core_hex_le(mackey_expected, BT_CORE63_SMP_D3_MACKEY_HEX,
	    sizeof(mackey_expected));
	core_hex_le(ltk_expected, BT_CORE63_SMP_D3_LTK_HEX,
	    sizeof(ltk_expected));
	if (reference_f5(w, n1, n2, a1, a2, mackey, ltk) != 0 ||
	    memcmp(mackey, mackey_expected, sizeof(mackey)) != 0 ||
	    memcmp(ltk, ltk_expected, sizeof(ltk)) != 0)
		return (false);

	core_hex_le(n1, BT_CORE63_SMP_D4_N1_HEX, sizeof(n1));
	core_hex_le(n2, BT_CORE63_SMP_D4_N2_HEX, sizeof(n2));
	core_hex_le(mackey, BT_CORE63_SMP_D4_MACKEY_HEX, sizeof(mackey));
	core_hex_le(r, BT_CORE63_SMP_D4_R_HEX, sizeof(r));
	core_hex_le(iocap, BT_CORE63_SMP_D4_IOCAP_HEX, sizeof(iocap));
	core_hex_le(a1, BT_CORE63_SMP_D4_A1_HEX, sizeof(a1));
	core_hex_le(a2, BT_CORE63_SMP_D4_A2_HEX, sizeof(a2));
	core_hex_le(f6_expected, BT_CORE63_SMP_D4_OUT_HEX,
	    sizeof(f6_expected));
	return (reference_f6(mackey, n1, n2, r, iocap, a1, a2, f6_out) == 0 &&
	    memcmp(f6_out, f6_expected, sizeof(f6_out)) == 0);
}

/* ================================================================
 * Helpers
 * ================================================================ */

/*
 * Set up an smp_conn for testing.
 * smp_fds[0] is the DUT side, smp_fds[1] is the mock peer side.
 * hci_fds[0] is the DUT side (writes go into kernel buffer).
 */
/*
 * Freeze the SMP monotonic clock for the duration of the test.  smp.c enforces
 * a 30 s cumulative §3.4 pairing deadline off CLOCK_MONOTONIC; under parallel
 * kyua the forked-peer handshake can take wall-clock seconds to be scheduled,
 * which would spuriously trip that product timer and fail an otherwise-correct
 * exchange.  These tests exercise the handshake itself, not the §3.4 deadline
 * (smp_timeout_test owns that with its own virtual clock), so a frozen clock
 * decouples the deadline from scheduler latency without weakening any check.
 * The generous SO_RCVTIMEO guard below remains the bounded hard cap that still
 * fails a genuine peer deadlock.
 */
static time_t smp_test_now = 1000;

static void
smp_test_frozen_clock(struct timespec *ts)
{

	ts->tv_sec = smp_test_now;
	ts->tv_nsec = 0;
}

static void
setup_conn(struct smp_conn *sc, struct smp_bond_db *db, int bond_fd,
    int smp_fds[2], int hci_fds[2],
    const uint8_t *local_addr, uint8_t local_type,
    const uint8_t *remote_addr, uint8_t remote_type)
{

	/* Ignore SIGPIPE — fork-based tests may write to closed peers */
	signal(SIGPIPE, SIG_IGN);
	smp_clock_hook = smp_test_frozen_clock;

	memset(db, 0, sizeof(*db));
	db->fd = bond_fd;

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
	sc->neg_key_size = 16;

	/* Prevent infinite blocking in tests */
	{
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
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
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/* 2. Send Pairing Response (NoInputNoOutput, no MITM => Just Works) */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;	/* no OOB */
		pres[3] = BTPR_SMP_AUTH_BONDING;	/* no MITM, no SC */
		pres[4] = 16;		/* max key size */
		pres[5] = 0x00;		/* init key dist: none */
		pres[6] = BTPR_SMP_KEY_DIST_ENC_KEY | BTPR_SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), MSG_EOR) < 0)
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
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(mconfirm, pdu + 1, 16);

		/* 4. Generate our random and compute confirm */
		arc4random_buf(srand, sizeof(srand));
		reference_c1(tk, srand, preq, pres, iat, central_addr,
		    rat, periph_addr, sconfirm);

		/* Send our confirm */
		pdu[0] = BTPR_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(4);

		/* 5. Receive Pairing Random from central */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_RANDOM)
			_exit(5);
		memcpy(mrand, pdu + 1, 16);

		/* Verify central's confirm */
		{
			uint8_t verify[16];
			reference_c1(tk, mrand, preq, pres, iat, central_addr,
			    rat, periph_addr, verify);
			if (memcmp(verify, mconfirm, 16) != 0)
				_exit(6);
		}

		/* 6. Send our random */
		pdu[0] = BTPR_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
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
		pdu[0] = BTPR_SMP_ENCRYPTION_INFORMATION;
		memcpy(pdu + 1, our_ltk, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(8);

		/* Central Identification */
		pdu[0] = BTPR_SMP_CENTRAL_IDENTIFICATION;
		memset(pdu + 1, 0, 2);	 /* ediv = 0 */
		memset(pdu + 3, 0, 8);	 /* rand = 0 */
		if (send(peer_fd, pdu, 11, MSG_EOR) < 0)
			_exit(9);

		/* Identity Information */
		pdu[0] = BTPR_SMP_IDENTITY_INFORMATION;
		memcpy(pdu + 1, our_irk, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(10);

		/* Identity Address */
		pdu[0] = BTPR_SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = 0x00;	/* public */
		memcpy(pdu + 2, periph_addr, 6);
		if (send(peer_fd, pdu, 8, MSG_EOR) < 0)
			_exit(11);

		/*
		 * Receive and discard initiator key distribution PDUs.
		 * The central now distributes its own keys after receiving ours.
		 */
		{
			uint8_t discard[64];
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
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

	/*
	 * Close the DUT side before reaping so the peer's drain-until-EOF loop
	 * ends immediately on EOF instead of waiting out its recv guard; the
	 * guard is then a pure backstop, not the handshake's synchronisation.
	 */
	close(smp_fds[0]);
	close(hci_fds[0]);
	wait_child(pid);

	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test 2: Peer sends BTPR_SMP_PAIRING_FAILED in response
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
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/* Send Pairing Failed */
		pdu[0] = BTPR_SMP_PAIRING_FAILED;
		pdu[1] = BTPR_SMP_ERR_PAIRING_NOT_SUPPORTED;
		send(peer_fd, pdu, 2, MSG_EOR);

		close(peer_fd);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK(ret == -1);
	ATF_CHECK_EQ(EACCES, errno);
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
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/* Send the generated first-below-minimum key size. */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = BTPR_SMP_AUTH_BONDING;
		pres[4] = BT_CORE63_SMP_MIN_KEY_SIZE - 1;
		pres[5] = 0x00;
		pres[6] = BTPR_SMP_KEY_DIST_ENC_KEY;
		send(peer_fd, pres, sizeof(pres), MSG_EOR);

		/*
		 * Central must reject with Pairing Failed.  Vol 3 Part H
		 * §2.3.4 / Table 3.7: a Max_Encryption_Key_Size outside the
		 * [7,16] range is an out-of-range parameter => reason
		 * "Invalid Parameters" (0x0A).
		 */
		{
			uint8_t buf[65];
			ssize_t rn = recv(peer_fd, buf, sizeof(buf), 0);
			if (rn < 2 || buf[0] != BTPR_SMP_PAIRING_FAILED)
				_exit(20);
			if (buf[1] != BTPR_SMP_ERR_INVALID_PARAMETERS)
				_exit(21);
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
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/* Send a generated Pairing Confirm instead of Pairing Response. */
		memset(garbage, 0, sizeof(garbage));
		garbage[0] = BTPR_SMP_PAIRING_CONFIRM;
		send(peer_fd, garbage, sizeof(garbage), MSG_EOR);
		{
			uint8_t fail[2];

			n = recv(peer_fd, fail, sizeof(fail), 0);
			if (n != (ssize_t)sizeof(fail) ||
			    fail[0] != BTPR_SMP_PAIRING_FAILED ||
			    fail[1] != BTPR_SMP_ERR_CMD_NOT_SUPPORTED)
				_exit(2);
		}

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
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
		}

		memset(tk, 0, sizeof(tk));

		/*
		 * Send Pairing Request.
		 * Use NoInputNoOutput + no MITM + no SC => Just Works legacy.
		 */
		preq[0] = BTPR_SMP_PAIRING_REQUEST;
		preq[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		preq[2] = 0x00;
		preq[3] = BTPR_SMP_AUTH_BONDING;  /* no MITM, no SC */
		preq[4] = 16;
		preq[5] = 0x00;  /* we don't distribute keys */
		preq[6] = BTPR_SMP_KEY_DIST_ENC_KEY | BTPR_SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, preq, sizeof(preq), MSG_EOR) < 0)
			_exit(1);

		/* Receive Pairing Response */
		n = recv(peer_fd, pres, sizeof(pres), 0);
		if (n < 7 || pres[0] != BTPR_SMP_PAIRING_RESPONSE)
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
		reference_c1(tk, mrand, preq, pres, iat, central_addr,
		    rat, periph_addr, mconfirm);

		/* Send Pairing Confirm */
		pdu[0] = BTPR_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, mconfirm, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(3);

		/* Receive responder's Pairing Confirm */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_CONFIRM)
			_exit(4);
		memcpy(sconfirm, pdu + 1, 16);

		/* Send Pairing Random */
		pdu[0] = BTPR_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, mrand, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(5);

		/* Receive responder's Pairing Random */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_RANDOM)
			_exit(6);
		memcpy(srand, pdu + 1, 16);

		/* Verify responder's confirm */
		{
			uint8_t verify[16];
			reference_c1(tk, srand, preq, pres, iat, central_addr,
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
		if (pres[6] & BTPR_SMP_KEY_DIST_ENC_KEY)
			expected_pdus += 2;
		if (pres[6] & BTPR_SMP_KEY_DIST_ID_KEY)
			expected_pdus += 2;

		for (i = 0; i < expected_pdus; i++) {
			n = recv(peer_fd, pdu, sizeof(pdu), 0);
			if (n < 1)
				_exit(8);

			/* Verify responder sends non-zero IRK (H5 fix) */
			if (pdu[0] == BTPR_SMP_IDENTITY_INFORMATION && n >= 17) {
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

/*
 * Operator PAIRABLE gate: when sc.reject_pairing is set, the responder declines
 * an incoming Pairing Request with Pairing Failed / "Pairing Not Supported"
 * (Core Spec Vol 3 Part H §3.5.1) instead of proceeding, and returns -1.
 */
ATF_TC_WITHOUT_HEAD(test_smp_respond_not_pairable);
ATF_TC_BODY(test_smp_respond_not_pairable, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_resp_np.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC,
	    central_addr, BDADDR_LE_PUBLIC);
	sc.reject_pairing = true;	/* PAIRABLE off */

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], rsp[4];
		ssize_t n;
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };

		close(smp_fds[0]);
		close(hci_fds[0]);
		setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

		preq[0] = BTPR_SMP_PAIRING_REQUEST;
		preq[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		preq[2] = 0x00;
		preq[3] = BTPR_SMP_AUTH_BONDING;
		preq[4] = 16;
		preq[5] = 0x00;
		preq[6] = BTPR_SMP_KEY_DIST_ENC_KEY;
		if (send(peer_fd, preq, sizeof(preq), MSG_EOR) < 0)
			_exit(1);

		/* Expect Pairing Failed / Pairing Not Supported. */
		n = recv(peer_fd, rsp, sizeof(rsp), 0);
		if (n < 2 || rsp[0] != BTPR_SMP_PAIRING_FAILED ||
		    rsp[1] != BTPR_SMP_ERR_PAIRING_NOT_SUPPORTED)
			_exit(2);
		close(peer_fd);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_respond(&sc);
	ATF_CHECK_EQ_MSG(-1, ret, "responder must decline (ret=%d)", ret);
	ATF_CHECK_EQ_MSG(0, db.count, "no bond stored when not pairable");

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
		uint8_t garbage[7], fail[2];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);

		/* Send garbage (wrong opcode) */
		memset(garbage, 0xAA, sizeof(garbage));
		garbage[0] = BTPR_SMP_PAIRING_CONFIRM; /* wrong opcode */
		send(peer_fd, garbage, sizeof(garbage), MSG_EOR);

		/* Core 6.3 Vol 3 Part H §3.3/Table 3.3 and §3.5.5/Table
		 * 3.7: a command invalid in this state gets Command Not Supported. */
		{
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
			n = recv(peer_fd, fail, sizeof(fail), 0);
		}
		if (n != (ssize_t)sizeof(fail) ||
		    fail[0] != BTPR_SMP_PAIRING_FAILED ||
		    fail[1] != BTPR_SMP_ERR_CMD_NOT_SUPPORTED)
			_exit(1);

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
	bond.addr_type = BLUED_BOND_ADDR_PUBLIC;
	memset(bond.ltk, 0x11, 16);
	smp_bond_db_store(&db, &bond);

	memset(bond.addr, 0xBB, 6);
	bond.addr_type = BLUED_BOND_ADDR_PUBLIC;
	memset(bond.ltk, 0x22, 16);
	smp_bond_db_store(&db, &bond);

	memset(bond.addr, 0xCC, 6);
	bond.addr_type = BLUED_BOND_ADDR_RANDOM;
	memset(bond.ltk, 0x33, 16);
	smp_bond_db_store(&db, &bond);

	ATF_CHECK_EQ(db.count, 3);

	/* Find the middle one */
	{
		uint8_t addr[6];
		memset(addr, 0xBB, 6);
		found = smp_find_bond(&db, addr, BLUED_BOND_ADDR_PUBLIC);
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
	bond.addr_type = BLUED_BOND_ADDR_PUBLIC;
	bond.has_ltk = true;
	smp_bond_db_store(&db, &bond);

	/* Search for non-existent address */
	{
		uint8_t addr[6];
		memset(addr, 0xFF, 6);
		found = smp_find_bond(&db, addr, BLUED_BOND_ADDR_PUBLIC);
		ATF_CHECK(found == NULL);
	}

	/* Search with wrong address type */
	{
		uint8_t addr[6];
		memset(addr, 0xAA, 6);
		found = smp_find_bond(&db, addr, BLUED_BOND_ADDR_RANDOM);
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
	bond.addr_type = BLUED_BOND_ADDR_PUBLIC;
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
 * BLE key refresh (controlled re-bond): smp_bond_db_replace_keys.
 *
 * Security-critical properties per Core Spec Vol 3 Part H §2.4:
 *  - after a refresh the OLD LTK is gone (single slot holds the new key);
 *  - the peer record (name, DB hash, GATT handle cache, CCCDs, sign
 *    counter) is PRESERVED, not reset;
 *  - the bond COUNT is stable (replace in place, no add/delete);
 *  - a rotated IRK lands in the record;
 *  - replace on a non-existent identity address is a no-op error (a first
 *    pair, not a refresh) — the caller must not be fooled into losing the
 *    "no keyless window" guarantee.
 * ================================================================ */

/* Populate a bond with keys AND peer metadata for the preserve/replace tests. */
static void
kr_seed_bond(struct smp_bond *b, const uint8_t addr[6], uint8_t ltk_fill,
    uint8_t irk_fill)
{

	memset(b, 0, sizeof(*b));
	memcpy(b->addr, addr, 6);
	b->addr_type = BLUED_BOND_ADDR_PUBLIC;
	memset(b->ltk, ltk_fill, 16);
	b->has_ltk = true;
	b->ediv = 0x1111;
	b->rand = 0x2222222222222222ULL;
	memset(b->irk, irk_fill, 16);
	b->has_irk = true;
	memset(b->csrk, 0x5a, 16);
	b->has_csrk = true;
	b->is_sc = true;
	b->is_mitm = true;
	b->key_size = 16;

	/* Peer metadata that MUST survive a key refresh. */
	strlcpy(b->name, "Keeb", sizeof(b->name));
	b->has_name = true;
	memset(b->db_hash, 0xD1, 16);
	b->has_db_hash = true;
	b->has_handle_cache = true;
	b->hid_svc_start = 0x0010;
	b->hid_svc_end = 0x001f;
	b->num_reports = 2;
	b->report_handles[0] = 0x0013;
	b->report_handles[1] = 0x0017;
	b->num_cccds = 1;
	b->cccds[0].handle = 0x0014;
	b->cccds[0].value = BT_CORE63_CCCD_NOTIFY_ENABLED;
	b->peer_sign_counter = 77;
}

ATF_TC_WITHOUT_HEAD(test_bond_replace_keys_old_ltk_invalid);
ATF_TC_BODY(test_bond_replace_keys_old_ltk_invalid, tc)
{
	struct smp_bond_db db;
	struct smp_bond old, fresh;
	static const uint8_t a[6] = { 1, 2, 3, 4, 5, 6 };
	char path[] = "/tmp/blued_test_kr_ltk.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	memset(&db, 0, sizeof(db));
	db.fd = fd;

	kr_seed_bond(&old, a, 0x11, 0xAA);
	smp_bond_db_store(&db, &old);
	ATF_REQUIRE_EQ(db.count, 1);

	/* Fresh pairing distributes a different LTK/EDIV/RAND. */
	kr_seed_bond(&fresh, a, 0x99, 0xAA);
	fresh.ediv = 0x3333;
	fresh.rand = 0x4444444444444444ULL;
	ATF_REQUIRE_EQ(smp_bond_db_replace_keys(&db, &fresh), 0);

	/* New LTK is the only one present; the old value is gone. */
	ATF_CHECK_EQ_MSG(db.bonds[0].ltk[0], 0x99,
	    "refreshed bond must hold the new LTK");
	ATF_CHECK_MSG(db.bonds[0].ltk[0] != 0x11,
	    "old LTK must not survive the single-slot swap");
	ATF_CHECK_EQ(db.bonds[0].ediv, 0x3333);
	ATF_CHECK(db.bonds[0].rand == 0x4444444444444444ULL);

	/* A find must return the new key material. */
	{
		struct smp_bond *f = smp_find_bond(&db, a,
		    BLUED_BOND_ADDR_PUBLIC);
		ATF_REQUIRE(f != NULL);
		ATF_CHECK_EQ(f->ltk[0], 0x99);
	}

	close(fd);
	unlink(path);
}

ATF_TC_WITHOUT_HEAD(test_bond_replace_keys_preserves_metadata);
ATF_TC_BODY(test_bond_replace_keys_preserves_metadata, tc)
{
	struct smp_bond_db db;
	struct smp_bond old, fresh;
	static const uint8_t a[6] = { 1, 2, 3, 4, 5, 6 };
	char path[] = "/tmp/blued_test_kr_meta.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	memset(&db, 0, sizeof(db));
	db.fd = fd;

	kr_seed_bond(&old, a, 0x11, 0xAA);
	smp_bond_db_store(&db, &old);

	/* The re-pair carries only keys (no name/cache/CCCDs). */
	memset(&fresh, 0, sizeof(fresh));
	memcpy(fresh.addr, a, 6);
	fresh.addr_type = BLUED_BOND_ADDR_PUBLIC;
	memset(fresh.ltk, 0x99, 16);
	fresh.has_ltk = true;
	memset(fresh.irk, 0xBB, 16);	/* rotated IRK */
	fresh.has_irk = true;
	fresh.is_sc = true;
	fresh.key_size = 16;

	ATF_REQUIRE_EQ(smp_bond_db_replace_keys(&db, &fresh), 0);

	/* Keys rotate... */
	ATF_CHECK_EQ(db.bonds[0].ltk[0], 0x99);
	ATF_CHECK_EQ_MSG(db.bonds[0].irk[0], 0xBB,
	    "rotated IRK must land in the record");

	/* ...but every piece of peer metadata is preserved. */
	ATF_CHECK_MSG(strcmp(db.bonds[0].name, "Keeb") == 0,
	    "device name must survive the refresh");
	ATF_CHECK(db.bonds[0].has_name);
	ATF_CHECK(db.bonds[0].has_db_hash && db.bonds[0].db_hash[0] == 0xD1);
	ATF_CHECK_MSG(db.bonds[0].has_handle_cache,
	    "GATT handle cache must survive the refresh");
	ATF_CHECK_EQ(db.bonds[0].hid_svc_start, 0x0010);
	ATF_CHECK_EQ(db.bonds[0].num_reports, 2);
	ATF_CHECK_EQ(db.bonds[0].report_handles[0], 0x0013);
	ATF_CHECK_EQ_MSG(db.bonds[0].num_cccds, 1,
	    "CCCD subscriptions must survive the refresh");
	ATF_CHECK_EQ(db.bonds[0].cccds[0].handle, 0x0014);
	ATF_CHECK_EQ(db.bonds[0].cccds[0].value,
	    BT_CORE63_CCCD_NOTIFY_ENABLED);
	ATF_CHECK_EQ_MSG(db.bonds[0].peer_sign_counter, 77,
	    "sign counter must survive the refresh");

	close(fd);
	unlink(path);
}

ATF_TC_WITHOUT_HEAD(test_bond_replace_keys_count_stable);
ATF_TC_BODY(test_bond_replace_keys_count_stable, tc)
{
	struct smp_bond_db db;
	struct smp_bond b;
	static const uint8_t a[6] = { 1, 2, 3, 4, 5, 6 };
	static const uint8_t bb[6] = { 9, 9, 9, 9, 9, 9 };
	char path[] = "/tmp/blued_test_kr_cnt.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	memset(&db, 0, sizeof(db));
	db.fd = fd;

	kr_seed_bond(&b, a, 0x11, 0xAA);
	smp_bond_db_store(&db, &b);
	kr_seed_bond(&b, bb, 0x22, 0xCC);
	smp_bond_db_store(&db, &b);
	ATF_REQUIRE_EQ(db.count, 2);

	/* Refresh the first peer: count must stay 2 (no add/delete). */
	kr_seed_bond(&b, a, 0x99, 0xAA);
	ATF_REQUIRE_EQ(smp_bond_db_replace_keys(&db, &b), 0);
	ATF_CHECK_EQ_MSG(db.count, 2,
	    "a key refresh replaces in place — count must be stable");

	/* Replace on an unknown identity address: no-op error, count intact. */
	{
		struct smp_bond miss;
		static const uint8_t zz[6] = { 0xFE, 0, 0, 0, 0, 0 };
		kr_seed_bond(&miss, zz, 0x33, 0xEE);
		ATF_CHECK_EQ_MSG(smp_bond_db_replace_keys(&db, &miss), -1,
		    "replace on a non-existent peer must report no match");
		ATF_CHECK_EQ(db.count, 2);
	}

	/* NULL guards. */
	ATF_CHECK_EQ(smp_bond_db_replace_keys(NULL, &b), -1);
	ATF_CHECK_EQ(smp_bond_db_replace_keys(&db, NULL), -1);

	close(fd);
	unlink(path);
}

/*
 * The in-place update path of smp_bond_db_store (used by every completed
 * re-pair, including the reactive auth-error path) must also preserve peer
 * metadata — otherwise a re-pair silently wipes the GATT cache/CCCDs.
 */
ATF_TC_WITHOUT_HEAD(test_bond_store_inplace_preserves_metadata);
ATF_TC_BODY(test_bond_store_inplace_preserves_metadata, tc)
{
	struct smp_bond_db db;
	struct smp_bond old, fresh;
	static const uint8_t a[6] = { 7, 7, 7, 7, 7, 7 };
	char path[] = "/tmp/blued_test_kr_store.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	memset(&db, 0, sizeof(db));
	db.fd = fd;

	kr_seed_bond(&old, a, 0x11, 0xAA);
	smp_bond_db_store(&db, &old);

	memset(&fresh, 0, sizeof(fresh));
	memcpy(fresh.addr, a, 6);
	fresh.addr_type = BLUED_BOND_ADDR_PUBLIC;
	memset(fresh.ltk, 0x99, 16);
	fresh.has_ltk = true;
	smp_bond_db_store(&db, &fresh);

	ATF_CHECK_EQ(db.count, 1);
	ATF_CHECK_EQ(db.bonds[0].ltk[0], 0x99);
	ATF_CHECK_MSG(strcmp(db.bonds[0].name, "Keeb") == 0,
	    "store in-place must preserve the device name");
	ATF_CHECK_EQ_MSG(db.bonds[0].num_cccds, 1,
	    "store in-place must preserve CCCD subscriptions");
	ATF_CHECK(db.bonds[0].has_handle_cache);

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

	enable_atomic_bond_save(&db1, path);
	ATF_CHECK_EQ(smp_bond_db_save(&db1), 0);

	memset(&db2, 0, sizeof(db2));
	enable_atomic_bond_save(&db2, path);
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
	db1.bonds[0].addr_type = BLUED_BOND_ADDR_RANDOM;
	db1.bonds[0].has_ltk = true;
	memset(db1.bonds[0].ltk, 0x42, 16);
	db1.bonds[0].has_irk = true;
	memcpy(db1.bonds[0].irk, test_irk, 16);
	db1.bonds[0].is_sc = true;

	enable_atomic_bond_save(&db1, path);
	ATF_CHECK_EQ(smp_bond_db_save(&db1), 0);

	memset(&db2, 0, sizeof(db2));
	enable_atomic_bond_save(&db2, path);
	ATF_CHECK_EQ(smp_bond_db_load(&db2, fd), 0);
	ATF_CHECK_EQ(db2.count, 1);
	ATF_CHECK(db2.bonds[0].has_irk);
	ATF_CHECK(memcmp(db2.bonds[0].irk, test_irk, 16) == 0);
	ATF_CHECK(db2.bonds[0].is_sc);

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test 12: A headerless file is rejected.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_headerless_file);
ATF_TC_BODY(test_bond_headerless_file, tc)
{
	struct smp_bond_db db;
	char path[] = "/tmp/blued_test_headerless.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	/* Write a raw struct without the required encrypted header. */
	{
		struct smp_bond bond;
		memset(&bond, 0, sizeof(bond));
		bond.has_ltk = true;
		pwrite(fd, &bond, sizeof(bond), 0);
	}

	memset(&db, 0, sizeof(db));
	ATF_CHECK_EQ(smp_bond_db_load(&db, fd), -1);
	ATF_CHECK_EQ_MSG(db.count, 0,
	    "headerless file should start fresh, got count=%d",
	    db.count);

	close(fd);
	unlink(path);
}

/* Current encrypted-v5 header with a corrupt ciphertext length is rejected. */
ATF_TC_WITHOUT_HEAD(test_bond_corrupt_size);
ATF_TC_BODY(test_bond_corrupt_size, tc)
{
	struct smp_bond_db db1, db2;
	char path[] = "/tmp/blued_test_corrupt.XXXXXX";
	uint8_t header[BLUED_BOND_DB_ENCRYPTED_HEADER_LEN];
	uint32_t wrong_len;
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	memset(&db1, 0, sizeof(db1));
	db1.fd = fd;
	db1.count = 1;
	db1.bonds[0].addr_type = BLUED_BOND_ADDR_PUBLIC;
	db1.bonds[0].has_ltk = true;
	memset(db1.bonds[0].ltk, 0x5a, sizeof(db1.bonds[0].ltk));
	enable_atomic_bond_save(&db1, path);
	ATF_REQUIRE_EQ(smp_bond_db_save(&db1), 0);
	ATF_REQUIRE_EQ(pread(fd, header, sizeof(header), 0),
	    (ssize_t)sizeof(header));
	ATF_REQUIRE_EQ(memcmp(header, BLUED_BOND_DB_ENCRYPTED_MAGIC,
	    BLUED_BOND_DB_ENCRYPTED_MAGIC_LEN), 0);

	/* The independent v5 layout puts uint32_le ciphertext_len at byte 53. */
	wrong_len = htole32(1);
	ATF_REQUIRE_EQ(pwrite(fd, &wrong_len, sizeof(wrong_len),
	    BLUED_BOND_DB_CIPHERTEXT_LEN_OFFSET), (ssize_t)sizeof(wrong_len));

	memset(&db2, 0, sizeof(db2));
	ATF_CHECK_EQ(smp_bond_db_load(&db2, fd), -1);
	ATF_CHECK_EQ_MSG(db2.count, 0,
	    "invalid ciphertext length must leave an empty DB, got count=%d",
	    db2.count);

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
	ac.cccds[0].value = BT_CORE63_CCCD_NOTIFY_ENABLED;
	ac.cccds[1].handle = 0x0006;
	ac.cccds[1].value = BT_CORE63_CCCD_INDICATE_ENABLED;
	ac.cccd_count = 2;

	smp_bond_save_cccds(&bond, &ac);

	ATF_CHECK_EQ(bond.num_cccds, 2);
	ATF_CHECK_EQ(bond.cccds[0].handle, 0x0003);
	ATF_CHECK_EQ(bond.cccds[0].value, BT_CORE63_CCCD_NOTIFY_ENABLED);
	ATF_CHECK_EQ(bond.cccds[1].handle, 0x0006);
	ATF_CHECK_EQ(bond.cccds[1].value, BT_CORE63_CCCD_INDICATE_ENABLED);
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
	bond.cccds[0].value = BT_CORE63_CCCD_NOTIFY_ENABLED;
	bond.cccds[1].handle = 0x0020;
	bond.cccds[1].value = BT_CORE63_CCCD_NOTIFY_AND_INDICATE_ENABLED;

	smp_bond_restore_cccds(&bond, &ac);

	ATF_CHECK_EQ(ac.cccd_count, 2);
	ATF_CHECK_EQ(ac.cccds[0].handle, 0x0010);
	ATF_CHECK_EQ(ac.cccds[0].value, BT_CORE63_CCCD_NOTIFY_ENABLED);
	ATF_CHECK_EQ(ac.cccds[1].handle, 0x0020);
	ATF_CHECK_EQ(ac.cccds[1].value,
	    BT_CORE63_CCCD_NOTIFY_AND_INDICATE_ENABLED);
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
	static const uint8_t ltk[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};
	/* Core 6.3 Vol 4 Part E §7.8.24: packet indicator, opcode 0x2019,
	 * 28-byte parameters, handle, Rand, EDIV, then the 128-bit LTK. */
	static const uint8_t expected[] = {
		BT_CORE63_HCI_COMMAND_PACKET, 0x19, 0x20,
		BT_CORE63_HCI_LE_ENABLE_ENCRYPTION_PARAM_SIZE,
		0x42, 0x0a,
		0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
		0xef, 0xbe,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};
	int hci_fds[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);

	memset(&sc, 0, sizeof(sc));
	sc.hci_fd = hci_fds[0];
	sc.con_handle = 0x0a42;

	/* Bond with LTK */
	memset(&bond, 0, sizeof(bond));
	bond.has_ltk = true;
	memcpy(bond.ltk, ltk, sizeof(ltk));
	bond.rand = 0x0123456789abcdefULL;
	bond.ediv = 0xbeef;

	int ret = smp_encrypt_with_ltk(&sc, &bond);
	ATF_CHECK_EQ(ret, 0);

	/* Verify HCI command was sent to hci_fds[1] */
	{
		uint8_t buf[sizeof(expected)];
		ssize_t n;

		n = recv(hci_fds[1], buf, sizeof(buf), 0);
		ATF_REQUIRE_EQ((ssize_t)sizeof(expected), n);
		ATF_CHECK_EQ_MSG(0, memcmp(buf, expected, sizeof(expected)),
		    "LE Enable Encryption command differs from §7.8.24");
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
	{
		uint8_t byte;

		errno = 0;
		ATF_CHECK_EQ(-1, recv(hci_fds[1], &byte, sizeof(byte),
		    MSG_DONTWAIT));
		ATF_CHECK_EQ(EAGAIN, errno);
	}

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

	reverse_copy(dhkey_le_out, dhkey_be, 32);
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
	ATF_REQUIRE_MSG(reference_sc_oracles_match_core(),
	    "independent SC peer failed Core Appendix D.2-D.4 KATs");
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
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/* 2. Send Pairing Response: SC + NoInputNoOutput => Just Works */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = BTPR_SMP_AUTH_BONDING | BTPR_SMP_AUTH_SC;
		pres[4] = 16;
		pres[5] = 0x00;
		pres[6] = BTPR_SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), MSG_EOR) < 0)
			_exit(2);

		/* 3. Generate our ECDH key pair */
		if (sc_generate_keypair(&peer_key, peer_pk_raw) != 0)
			_exit(3);

		/* 4. Receive central's public key (wire = LE) */
		n = recv(peer_fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != BTPR_SMP_PAIRING_PUBLIC_KEY)
			_exit(4);
		/* Convert central's PK from wire LE to OpenSSL BE */
		central_pk_raw[0] = 0x04;
		reverse_copy(central_pk_raw + 1, pdu + 1, 32);
		reverse_copy(central_pk_raw + 33, pdu + 33, 32);
		memcpy(pka_le, pdu + 1, 32);

		/* 5. Send our public key (BE -> wire LE) */
		pdu[0] = BTPR_SMP_PAIRING_PUBLIC_KEY;
		reverse_copy(pdu + 1, peer_pk_raw + 1, 32);
		reverse_copy(pdu + 33, peer_pk_raw + 33, 32);
		memcpy(pkb_le, pdu + 1, 32);
		if (send(peer_fd, pdu, 65, MSG_EOR) < 0) {
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
		reference_f4(pkb_le, pka_le, nb, 0, cb);

		pdu[0] = BTPR_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, cb, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(7);

		/* Receive Na */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_RANDOM)
			_exit(8);
		memcpy(na, pdu + 1, 16);

		/* Send Nb */
		pdu[0] = BTPR_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, nb, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
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

		reference_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
		reference_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
		reference_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);

		/* Receive Ea from central, verify */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_DHKEY_CHECK)
			_exit(10);
		if (memcmp(pdu + 1, ea, 16) != 0)
			_exit(11);

		/* Send Eb */
		pdu[0] = BTPR_SMP_PAIRING_DHKEY_CHECK;
		memcpy(pdu + 1, eb, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(12);

		/* 9. Key distribution: send IRK + Identity Address */
		pdu[0] = BTPR_SMP_IDENTITY_INFORMATION;
		memset(pdu + 1, 0, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(13);

		pdu[0] = BTPR_SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = 0x00;	/* public */
		memcpy(pdu + 2, periph_addr, 6);
		if (send(peer_fd, pdu, 8, MSG_EOR) < 0)
			_exit(14);

		/*
		 * Stay open and drain the initiator's own key distribution
		 * until the parent closes.  Closing here races the DUT's
		 * key-distribution sends, which under parallel load would fault
		 * with EPIPE and make smp_pair() return -1.
		 */
		{
			uint8_t discard[64];

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
	if (db.count > 0) {
		ATF_CHECK(db.bonds[0].has_ltk);
		ATF_CHECK(db.bonds[0].is_sc);
	}

	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	close(hci_fds[0]);
	wait_child(pid);
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
	ATF_REQUIRE_MSG(reference_sc_oracles_match_core(),
	    "independent SC peer failed Core Appendix D.2-D.4 KATs");
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
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/* 2. Send Pairing Response: SC + KbdOnly + MITM */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_KEYBOARD_ONLY;
		pres[2] = 0x00;
		pres[3] = BTPR_SMP_AUTH_BONDING | BTPR_SMP_AUTH_MITM | BTPR_SMP_AUTH_SC;
		pres[4] = 16;
		pres[5] = 0x00;
		pres[6] = BTPR_SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), MSG_EOR) < 0)
			_exit(2);

		/* 3. Generate ECDH key pair */
		if (sc_generate_keypair(&peer_key, peer_pk_raw) != 0)
			_exit(3);

		/* 4. Receive central's PK */
		n = recv(peer_fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != BTPR_SMP_PAIRING_PUBLIC_KEY)
			_exit(4);
		central_pk_raw[0] = 0x04;
		reverse_copy(central_pk_raw + 1, pdu + 1, 32);
		reverse_copy(central_pk_raw + 33, pdu + 33, 32);
		memcpy(pka_le, pdu + 1, 32);

		/* 5. Send our PK */
		pdu[0] = BTPR_SMP_PAIRING_PUBLIC_KEY;
		reverse_copy(pdu + 1, peer_pk_raw + 1, 32);
		reverse_copy(pdu + 33, peer_pk_raw + 33, 32);
		memcpy(pkb_le, pdu + 1, 32);
		if (send(peer_fd, pdu, 65, MSG_EOR) < 0) {
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
			if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_CONFIRM)
				_exit(20 + i);
			memcpy(cai_recv, pdu + 1, 16);

			/* Compute and send Cbi */
			arc4random_buf(nbi, sizeof(nbi));
			reference_f4(pkb_le, pka_le, nbi, ri, cbi);
			pdu[0] = BTPR_SMP_PAIRING_CONFIRM;
			memcpy(pdu + 1, cbi, 16);
			if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
				_exit(60 + i);

			/* Receive Nai */
			n = recv(peer_fd, pdu, 17, 0);
			if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_RANDOM)
				_exit(80 + i);
			memcpy(nai, pdu + 1, 16);

			/* Verify Cai = f4(PKax, PKbx, Nai, ri) */
			reference_f4(pka_le, pkb_le, nai, ri, cai_verify);
			if (memcmp(cai_recv, cai_verify, 16) != 0)
				_exit(100 + i);

			/* Send Nbi */
			pdu[0] = BTPR_SMP_PAIRING_RANDOM;
			memcpy(pdu + 1, nbi, 16);
			if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
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

		reference_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
		reference_f6(mackey, na, nb, ra, iocap_a, a1, a2, ea);
		reference_f6(mackey, nb, na, ra, iocap_b, a2, a1, eb);

		/* Receive Ea, verify */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_DHKEY_CHECK)
			_exit(141);
		if (memcmp(pdu + 1, ea, 16) != 0)
			_exit(142);

		/* Send Eb */
		pdu[0] = BTPR_SMP_PAIRING_DHKEY_CHECK;
		memcpy(pdu + 1, eb, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(143);

		/* Key distribution: IRK + Identity */
		pdu[0] = BTPR_SMP_IDENTITY_INFORMATION;
		memset(pdu + 1, 0, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(144);

		pdu[0] = BTPR_SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = 0x00;
		memcpy(pdu + 2, periph_addr, 6);
		if (send(peer_fd, pdu, 8, MSG_EOR) < 0)
			_exit(145);

		/*
		 * Stay open and drain the initiator's own key distribution
		 * until the parent closes.  Closing here races the DUT's
		 * key-distribution sends, which under parallel load would fault
		 * with EPIPE and make smp_pair() return -1.
		 */
		{
			uint8_t discard[64];

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
	ATF_CHECK_MSG(db.count > 0, "expected bond, got count=%d", db.count);
	if (db.count > 0) {
		ATF_CHECK(db.bonds[0].has_ltk);
		ATF_CHECK(db.bonds[0].is_sc);
	}

	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	close(hci_fds[0]);
	wait_child(pid);
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
	ATF_REQUIRE_MSG(reference_sc_oracles_match_core(),
	    "independent SC peer failed Core Appendix D.2-D.4 KATs");
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
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/* 2. Send Pairing Response: SC + DisplayYesNo + MITM */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_DISPLAY_YESNO;
		pres[2] = 0x00;
		pres[3] = BTPR_SMP_AUTH_BONDING | BTPR_SMP_AUTH_MITM | BTPR_SMP_AUTH_SC;
		pres[4] = 16;
		pres[5] = 0x00;
		pres[6] = BTPR_SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), MSG_EOR) < 0)
			_exit(2);

		/* 3. Generate ECDH key pair */
		if (sc_generate_keypair(&peer_key, peer_pk_raw) != 0)
			_exit(3);

		/* 4. Receive central's PK */
		n = recv(peer_fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != BTPR_SMP_PAIRING_PUBLIC_KEY)
			_exit(4);
		central_pk_raw[0] = 0x04;
		reverse_copy(central_pk_raw + 1, pdu + 1, 32);
		reverse_copy(central_pk_raw + 33, pdu + 33, 32);
		memcpy(pka_le, pdu + 1, 32);

		/* 5. Send our PK */
		pdu[0] = BTPR_SMP_PAIRING_PUBLIC_KEY;
		reverse_copy(pdu + 1, peer_pk_raw + 1, 32);
		reverse_copy(pdu + 33, peer_pk_raw + 33, 32);
		memcpy(pkb_le, pdu + 1, 32);
		if (send(peer_fd, pdu, 65, MSG_EOR) < 0) {
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
		reference_f4(pkb_le, pka_le, nb, 0, cb);

		pdu[0] = BTPR_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, cb, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(7);

		/* Receive Na */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_RANDOM)
			_exit(8);
		memcpy(na, pdu + 1, 16);

		/* Send Nb */
		pdu[0] = BTPR_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, nb, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
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

		reference_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
		reference_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
		reference_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);

		/* Receive Ea, verify */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_DHKEY_CHECK)
			_exit(10);
		if (memcmp(pdu + 1, ea, 16) != 0)
			_exit(11);

		/* Send Eb */
		pdu[0] = BTPR_SMP_PAIRING_DHKEY_CHECK;
		memcpy(pdu + 1, eb, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(12);

		/* Key distribution */
		pdu[0] = BTPR_SMP_IDENTITY_INFORMATION;
		memset(pdu + 1, 0, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(13);

		pdu[0] = BTPR_SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = 0x00;
		memcpy(pdu + 2, periph_addr, 6);
		if (send(peer_fd, pdu, 8, MSG_EOR) < 0)
			_exit(14);

		/*
		 * Stay open and drain the initiator's own key distribution
		 * until the parent closes.  Closing here races the DUT's
		 * key-distribution sends, which under parallel load would fault
		 * with EPIPE and make smp_pair() return -1.
		 */
		{
			uint8_t discard[64];

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
	ATF_CHECK_MSG(db.count > 0, "expected bond, got count=%d", db.count);
	if (db.count > 0) {
		ATF_CHECK(db.bonds[0].has_ltk);
		ATF_CHECK(db.bonds[0].is_sc);
	}

	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	close(hci_fds[0]);
	wait_child(pid);
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

	uint8_t debug_pk_x_le[32], debug_pk_y_le[32];

	/* Generator-parsed Core 6.3 Vol 3 Part H §2.3.5.6.1 debug key,
	 * decoded directly into the little-octet-first SMP public-key PDU. */
	core_hex_le(debug_pk_x_le, BT_CORE63_SMP_SC_DEBUG_X_HEX,
	    sizeof(debug_pk_x_le));
	core_hex_le(debug_pk_y_le, BT_CORE63_SMP_SC_DEBUG_Y_HEX,
	    sizeof(debug_pk_y_le));

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
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/* Send Pairing Response with SC */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = BTPR_SMP_AUTH_BONDING | BTPR_SMP_AUTH_SC;
		pres[4] = 16;
		pres[5] = 0x00;
		pres[6] = BTPR_SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), MSG_EOR) < 0)
			_exit(2);

		/* Receive central's PK (don't care about content) */
		n = recv(peer_fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != BTPR_SMP_PAIRING_PUBLIC_KEY)
			_exit(3);

		/* Send the exact generated Debug Public Key in wire order. */
		pdu[0] = BTPR_SMP_PAIRING_PUBLIC_KEY;
		memcpy(pdu + 1, debug_pk_x_le, sizeof(debug_pk_x_le));
		memcpy(pdu + 33, debug_pk_y_le, sizeof(debug_pk_y_le));
		if (send(peer_fd, pdu, 65, MSG_EOR) < 0)
			_exit(4);

		/* §3.5.5 Table 3.7: invalid peer public-key validation maps to
		 * DHKey Check Failed in this implementation path. */
		{
			uint8_t fail[2];
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
			n = recv(peer_fd, fail, sizeof(fail), 0);
			if (n != (ssize_t)sizeof(fail) ||
			    fail[0] != BTPR_SMP_PAIRING_FAILED ||
			    fail[1] != BTPR_SMP_ERR_DHKEY_CHECK_FAILED)
				_exit(5);
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
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/* SC response with the generated Core minimum; blued's hardened SC
		 * policy requires the generated maximum. */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = BTPR_SMP_AUTH_BONDING | BTPR_SMP_AUTH_SC;
		pres[4] = BT_CORE63_SMP_MIN_KEY_SIZE;
		pres[5] = 0x00;
		pres[6] = BTPR_SMP_KEY_DIST_ID_KEY;
		send(peer_fd, pres, sizeof(pres), MSG_EOR);

		/*
		 * Vol 3 Part H §2.3.4 / Table 3.7: a negotiated SC key size
		 * below the required minimum => Pairing Failed with reason
		 * "Encryption Key Size" (0x06).
		 */
		{
			uint8_t buf[65];
			ssize_t rn;
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
			rn = recv(peer_fd, buf, sizeof(buf), 0);
			if (rn < 2 || buf[0] != BTPR_SMP_PAIRING_FAILED)
				_exit(20);
			if (buf[1] != BTPR_SMP_ERR_ENCRYPTION_KEY_SIZE)
				_exit(21);
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
 * without BTPR_SMP_AUTH_SC set, sending BTPR_SMP_PAIRING_FAILED with reason
 * BTPR_SMP_ERR_AUTH_REQUIREMENTS.
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
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
		}

		/* Receive Pairing Request */
		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/*
		 * Send Pairing Response WITHOUT BTPR_SMP_AUTH_SC.
		 * This is a legacy-only peer.
		 */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = BTPR_SMP_AUTH_BONDING;	/* no SC flag */
		pres[4] = 16;
		pres[5] = 0x00;
		pres[6] = BTPR_SMP_KEY_DIST_ENC_KEY | BTPR_SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), MSG_EOR) < 0)
			_exit(2);

		/*
		 * Expect to receive BTPR_SMP_PAIRING_FAILED with reason
		 * BTPR_SMP_ERR_AUTH_REQUIREMENTS from the DUT.
		 */
		n = recv(peer_fd, pdu, sizeof(pdu), 0);
		if (n < 2)
			_exit(3);
		if (pdu[0] != BTPR_SMP_PAIRING_FAILED)
			_exit(4);
		if (pdu[1] != BTPR_SMP_ERR_AUTH_REQUIREMENTS)
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
	uint16_t io;
	int sc;

	/* Core 6.3 Vol 3 Part H §3.5.1 Table 3.4 assigns 0x00-0x04;
	 * exhaust every reserved octet, in either field and either pairing mode. */
	for (io = BT_CORE63_SMP_IO_RESERVED_FIRST;
	    io <= BT_CORE63_SMP_IO_RESERVED_LAST; io++) {
		for (sc = 0; sc <= 1; sc++) {
			ATF_CHECK_EQ_MSG(SMP_MODEL_INVALID,
			    smp_select_model((uint8_t)io,
			    BTPR_SMP_IO_DISPLAY_ONLY, sc != 0),
			    "reserved initiator IO 0x%02x accepted (SC=%d)",
			    io, sc);
			ATF_CHECK_EQ_MSG(SMP_MODEL_INVALID,
			    smp_select_model(BTPR_SMP_IO_DISPLAY_ONLY,
			    (uint8_t)io, sc != 0),
			    "reserved responder IO 0x%02x accepted (SC=%d)",
			    io, sc);
		}
	}
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
	uint8_t ltk[16], expected[16];

	memset(&bond, 0, sizeof(bond));
	bond.is_sc = true;
	bond.has_ltk = true;
	bond.is_mitm = true;

	/* Core 6.3 Vol 3 Part H Appendix D.10: CT2=0 h6/h6 path. */
	core_hex_le(ltk, BT_CORE63_SMP_D10_LTK_HEX, sizeof(ltk));
	core_hex_le(expected, BT_CORE63_SMP_D10_LINK_KEY_HEX,
	    sizeof(expected));
	memcpy(bond.ltk, ltk, sizeof(ltk));
	int ret = smp_ctkd_derive_link_key(&bond, false);
	ATF_CHECK_EQ_MSG(ret, 0, "ctkd ct2=false failed, got %d", ret);
	ATF_CHECK_MSG(bond.has_link_key,
	    "link key should be derived with MITM");
	ATF_CHECK_EQ_MSG(0, memcmp(bond.link_key, expected, sizeof(expected)),
	    "CT2=0 link key differs from Appendix D.10");

	/* Core 6.3 Vol 3 Part H Appendix D.9: CT2=1 h7/h6 path. */
	bond.has_link_key = false;
	memset(bond.link_key, 0, sizeof(bond.link_key));
	core_hex_le(ltk, BT_CORE63_SMP_D9_LTK_HEX, sizeof(ltk));
	core_hex_le(expected, BT_CORE63_SMP_D9_LINK_KEY_HEX,
	    sizeof(expected));
	memcpy(bond.ltk, ltk, sizeof(ltk));
	ret = smp_ctkd_derive_link_key(&bond, true);
	ATF_CHECK_EQ_MSG(ret, 0, "ctkd ct2=true failed, got %d", ret);
	ATF_CHECK_MSG(bond.has_link_key,
	    "link key should be derived with CT2");
	ATF_CHECK_EQ_MSG(0, memcmp(bond.link_key, expected, sizeof(expected)),
	    "CT2=1 link key differs from Appendix D.9");
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
	uint8_t expected[16];
	size_t i;

	memset(zero16, 0, sizeof(zero16));
	/* A nonuniform little-octet-first public-key x-coordinate makes byte
	 * reversal errors observable while the random output remains generated. */
	for (i = 0; i < sizeof(pk_x); i++)
		pk_x[i] = (uint8_t)(0x5b + 7 * i);

	int ret = smp_generate_sc_oob(confirm, random, pk_x);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_MSG(memcmp(random, zero16, 16) != 0,
	    "OOB random should be non-zero");
	ATF_CHECK_MSG(memcmp(confirm, zero16, 16) != 0,
	    "OOB confirm should be non-zero");

	/* Core 6.3 Vol 3 Part H §2.3.5.6.4 uses
	 * C = f4(PKx, PKx, r, 0); reference_f4 is independent OpenSSL CMAC. */
	ATF_REQUIRE_EQ(0, reference_f4(pk_x, pk_x, random,
	    BT_CORE63_SMP_D2_Z, expected));
	ATF_CHECK_EQ_MSG(0, memcmp(confirm, expected, sizeof(expected)),
	    "SC OOB confirm differs from independently computed f4");
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
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/*
		 * 2. Send Pairing Response: KbdOnly + MITM, no SC.
		 * Because central offers SC but we don't, this falls
		 * back to legacy.  We set no SC flag.
		 */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_KEYBOARD_ONLY;
		pres[2] = 0x00;
		pres[3] = BTPR_SMP_AUTH_BONDING | BTPR_SMP_AUTH_MITM;	/* no SC */
		pres[4] = 16;
		pres[5] = 0x00;
		pres[6] = BTPR_SMP_KEY_DIST_ENC_KEY | BTPR_SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), MSG_EOR) < 0)
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
			if (pdu[0] == BTPR_SMP_PAIRING_KEYPRESS_NOTIFY)
				continue;
			break;
		}
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(mconfirm, pdu + 1, 16);

		/* 4. Generate our random and compute confirm */
		arc4random_buf(srand_val, sizeof(srand_val));
		reference_c1(tk, srand_val, preq, pres, iat, central_addr,
		    rat, periph_addr, sconfirm);

		/* Send confirm (skip keypress notifications) */
		pdu[0] = BTPR_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(4);

		/* 5. Receive central's random */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_RANDOM)
			_exit(5);
		memcpy(mrand_val, pdu + 1, 16);

		/* Verify central's confirm */
		{
			uint8_t verify[16];
			reference_c1(tk, mrand_val, preq, pres, iat, central_addr,
			    rat, periph_addr, verify);
			if (memcmp(verify, mconfirm, 16) != 0)
				_exit(6);
		}

		/* 6. Send our random */
		pdu[0] = BTPR_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand_val, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(7);

		/* 7. Key distribution */
		{
			uint8_t ltk_val[16];
			arc4random_buf(ltk_val, sizeof(ltk_val));

			pdu[0] = BTPR_SMP_ENCRYPTION_INFORMATION;
			memcpy(pdu + 1, ltk_val, 16);
			if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
				_exit(8);

			pdu[0] = BTPR_SMP_CENTRAL_IDENTIFICATION;
			memset(pdu + 1, 0, 2);
			memset(pdu + 3, 0, 8);
			if (send(peer_fd, pdu, 11, MSG_EOR) < 0)
				_exit(9);

			pdu[0] = BTPR_SMP_IDENTITY_INFORMATION;
			memset(pdu + 1, 0, 16);
			if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
				_exit(10);

			pdu[0] = BTPR_SMP_IDENTITY_ADDRESS_INFO;
			pdu[1] = 0x00;
			memcpy(pdu + 2, periph_addr, 6);
			if (send(peer_fd, pdu, 8, MSG_EOR) < 0)
				_exit(11);
		}

		/*
		 * Stay open and drain the initiator's own key distribution
		 * until the parent closes.  Closing here races the DUT's
		 * key-distribution sends, which under parallel load would fault
		 * with EPIPE and make smp_pair() return -1.
		 */
		{
			uint8_t discard[64];

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
	ATF_CHECK_MSG(db.count > 0, "expected bond, got count=%d", db.count);
	if (db.count > 0)
		ATF_CHECK(db.bonds[0].has_ltk);

	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	close(hci_fds[0]);
	wait_child(pid);
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
	ATF_REQUIRE_MSG(reference_sc_oracles_match_core(),
	    "independent SC peer failed Core Appendix D.2-D.4 KATs");
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
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
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
		preq[0] = BTPR_SMP_PAIRING_REQUEST;
		preq[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		preq[2] = 0x00;
		preq[3] = BTPR_SMP_AUTH_BONDING | BTPR_SMP_AUTH_SC;
		preq[4] = 16;
		preq[5] = 0x00;
		preq[6] = BTPR_SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, preq, sizeof(preq), MSG_EOR) < 0)
			_exit(2);

		/* Receive Pairing Response */
		n = recv(peer_fd, pres, sizeof(pres), 0);
		if (n < 7 || pres[0] != BTPR_SMP_PAIRING_RESPONSE)
			_exit(3);

		/*
		 * SC PK exchange: initiator sends first, responder second.
		 * Send our PK (BE -> LE wire).
		 */
		pdu[0] = BTPR_SMP_PAIRING_PUBLIC_KEY;
		reverse_copy(pdu + 1, peer_pk_raw + 1, 32);
		reverse_copy(pdu + 33, peer_pk_raw + 33, 32);
		memcpy(pka_le, pdu + 1, 32);	/* initiator PK x LE */
		if (send(peer_fd, pdu, 65, MSG_EOR) < 0) {
			EVP_PKEY_free(peer_key);
			_exit(4);
		}

		/* Receive responder's PK */
		n = recv(peer_fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != BTPR_SMP_PAIRING_PUBLIC_KEY) {
			EVP_PKEY_free(peer_key);
			_exit(5);
		}
		resp_pk_raw[0] = 0x04;
		reverse_copy(resp_pk_raw + 1, pdu + 1, 32);
		reverse_copy(resp_pk_raw + 33, pdu + 33, 32);
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
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_CONFIRM)
			_exit(7);
		memcpy(cb_recv, pdu + 1, 16);

		/* Generate and send Na */
		arc4random_buf(na, sizeof(na));
		pdu[0] = BTPR_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, na, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(8);

		/* Receive Nb */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_RANDOM)
			_exit(9);
		memcpy(nb, pdu + 1, 16);

		/* Verify Cb = f4(PKbx, PKax, Nb, 0) */
		reference_f4(pkb_le, pka_le, nb, 0, cb_verify);
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

		reference_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
		reference_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
		reference_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);

		/* Send Ea */
		pdu[0] = BTPR_SMP_PAIRING_DHKEY_CHECK;
		memcpy(pdu + 1, ea, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(11);

		/* Receive Eb, verify */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_DHKEY_CHECK)
			_exit(12);
		if (memcmp(pdu + 1, eb, 16) != 0)
			_exit(13);

		/*
		 * Receive key distribution from responder (IdKey).
		 * The responder distributes first in SC mode.
		 */
		{
			int exp = 0;
			if (pres[6] & BTPR_SMP_KEY_DIST_ID_KEY)
				exp += 2;
			int j;
			for (j = 0; j < exp; j++) {
				n = recv(peer_fd, pdu, sizeof(pdu), 0);
				if (n < 1)
					break;

				/* Verify responder sends non-zero IRK (H5 fix) */
				if (pdu[0] == BTPR_SMP_IDENTITY_INFORMATION &&
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
	ATF_REQUIRE_MSG(reference_sc_oracles_match_core(),
	    "independent SC peer failed Core Appendix D.2-D.4 KATs");
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
	sc.io_capability = BTPR_SMP_IO_DISPLAY_YESNO;
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
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
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
		preq[0] = BTPR_SMP_PAIRING_REQUEST;
		preq[1] = BTPR_SMP_IO_DISPLAY_YESNO;
		preq[2] = 0x00;
		preq[3] = BTPR_SMP_AUTH_BONDING | BTPR_SMP_AUTH_MITM | BTPR_SMP_AUTH_SC;
		preq[4] = 16;
		preq[5] = 0x00;
		preq[6] = BTPR_SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, preq, sizeof(preq), MSG_EOR) < 0)
			_exit(2);

		/* Receive Pairing Response */
		n = recv(peer_fd, pres, sizeof(pres), 0);
		if (n < 7 || pres[0] != BTPR_SMP_PAIRING_RESPONSE)
			_exit(3);

		/*
		 * SC PK exchange: initiator sends first, responder second.
		 * Send our PK (BE -> LE wire).
		 */
		pdu[0] = BTPR_SMP_PAIRING_PUBLIC_KEY;
		reverse_copy(pdu + 1, peer_pk_raw + 1, 32);
		reverse_copy(pdu + 33, peer_pk_raw + 33, 32);
		memcpy(pka_le, pdu + 1, 32);	/* initiator PK x LE */
		if (send(peer_fd, pdu, 65, MSG_EOR) < 0) {
			EVP_PKEY_free(peer_key);
			_exit(4);
		}

		/* Receive responder's PK */
		n = recv(peer_fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != BTPR_SMP_PAIRING_PUBLIC_KEY) {
			EVP_PKEY_free(peer_key);
			_exit(5);
		}
		resp_pk_raw[0] = 0x04;
		reverse_copy(resp_pk_raw + 1, pdu + 1, 32);
		reverse_copy(resp_pk_raw + 33, pdu + 33, 32);
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
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_CONFIRM)
			_exit(7);
		memcpy(cb_recv, pdu + 1, 16);

		/* Generate and send Na */
		arc4random_buf(na, sizeof(na));
		pdu[0] = BTPR_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, na, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(8);

		/* Receive Nb */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_RANDOM)
			_exit(9);
		memcpy(nb, pdu + 1, 16);

		/* Verify Cb = f4(PKbx, PKax, Nb, 0) */
		reference_f4(pkb_le, pka_le, nb, 0, cb_verify);
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

		reference_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
		reference_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
		reference_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);

		/* Send Ea */
		pdu[0] = BTPR_SMP_PAIRING_DHKEY_CHECK;
		memcpy(pdu + 1, ea, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(11);

		/* Receive Eb, verify */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_DHKEY_CHECK)
			_exit(12);
		if (memcmp(pdu + 1, eb, 16) != 0)
			_exit(13);

		/*
		 * Receive key distribution from responder (IdKey).
		 * The responder distributes first in SC mode.
		 */
		{
			int exp = 0;
			if (pres[6] & BTPR_SMP_KEY_DIST_ID_KEY)
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
	ATF_REQUIRE_MSG(reference_sc_oracles_match_core(),
	    "independent SC peer failed Core Appendix D.2-D.4 KATs");
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

	sc.io_capability = BTPR_SMP_IO_KEYBOARD_DISPLAY;
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
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
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
		preq[0] = BTPR_SMP_PAIRING_REQUEST;
		preq[1] = BTPR_SMP_IO_KEYBOARD_ONLY;
		preq[2] = 0x00;
		preq[3] = BTPR_SMP_AUTH_BONDING | BTPR_SMP_AUTH_MITM | BTPR_SMP_AUTH_SC;
		preq[4] = 16;
		preq[5] = 0x00;
		preq[6] = BTPR_SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, preq, sizeof(preq), MSG_EOR) < 0)
			_exit(2);

		/* Receive Pairing Response */
		n = recv(peer_fd, pres, sizeof(pres), 0);
		if (n < 7 || pres[0] != BTPR_SMP_PAIRING_RESPONSE)
			_exit(3);

		/*
		 * SC PK exchange: initiator sends first, responder second.
		 */
		pdu[0] = BTPR_SMP_PAIRING_PUBLIC_KEY;
		reverse_copy(pdu + 1, peer_pk_raw + 1, 32);
		reverse_copy(pdu + 33, peer_pk_raw + 33, 32);
		memcpy(pka_le, pdu + 1, 32);
		if (send(peer_fd, pdu, 65, MSG_EOR) < 0) {
			EVP_PKEY_free(peer_key);
			_exit(4);
		}

		/* Receive responder's PK */
		n = recv(peer_fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != BTPR_SMP_PAIRING_PUBLIC_KEY) {
			EVP_PKEY_free(peer_key);
			_exit(5);
		}
		resp_pk_raw[0] = 0x04;
		reverse_copy(resp_pk_raw + 1, pdu + 1, 32);
		reverse_copy(resp_pk_raw + 33, pdu + 33, 32);
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
			reference_f4(pka_le, pkb_le, nai, ri, cai);
			pdu[0] = BTPR_SMP_PAIRING_CONFIRM;
			memcpy(pdu + 1, cai, 16);
			if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
				_exit(20 + i);

			/* Receive Cbi (responder confirm) */
			n = recv(peer_fd, pdu, 17, 0);
			if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_CONFIRM)
				_exit(40 + i);
			memcpy(cbi_recv, pdu + 1, 16);

			/* Send Nai */
			pdu[0] = BTPR_SMP_PAIRING_RANDOM;
			memcpy(pdu + 1, nai, 16);
			if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
				_exit(60 + i);

			/* Receive Nbi */
			n = recv(peer_fd, pdu, 17, 0);
			if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_RANDOM)
				_exit(80 + i);
			memcpy(nbi, pdu + 1, 16);

			/* Verify Cbi = f4(PKbx, PKax, Nbi, ri) */
			reference_f4(pkb_le, pka_le, nbi, ri, cbi_verify);
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

		reference_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
		reference_f6(mackey, na, nb, ra, iocap_a, a1, a2, ea);
		reference_f6(mackey, nb, na, ra, iocap_b, a2, a1, eb);

		/* Send Ea */
		pdu[0] = BTPR_SMP_PAIRING_DHKEY_CHECK;
		memcpy(pdu + 1, ea, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(141);

		/* Receive Eb, verify */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_DHKEY_CHECK)
			_exit(142);
		if (memcmp(pdu + 1, eb, 16) != 0)
			_exit(143);

		/*
		 * Receive key distribution from responder (IdKey).
		 */
		{
			int exp = 0;
			if (pres[6] & BTPR_SMP_KEY_DIST_ID_KEY)
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
/*
 * Drive one responder-side pairing attempt from `remote`, closing the peer
 * so the handshake fails right after the rate gate.  Returns smp_respond()'s
 * value; *err_out receives the resulting errno (EACCES == rate-limited).
 * The rate table is a process-global static, so successive calls accumulate
 * (ATF runs each test case in its own process, so the table starts fresh).
 */
static int
rate_one_attempt(int bond_fd, const uint8_t *remote, uint8_t rtype,
    int *err_out)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2], ret;
	uint8_t preq[7];

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) != 0 ||
	    socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) != 0)
		return (-99);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, remote, rtype);

	preq[0] = BTPR_SMP_PAIRING_REQUEST;
	preq[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
	preq[2] = 0x00;
	preq[3] = BTPR_SMP_AUTH_BONDING;
	preq[4] = 16;
	preq[5] = 0x00;
	preq[6] = BTPR_SMP_KEY_DIST_ENC_KEY | BTPR_SMP_KEY_DIST_ID_KEY;
	(void)send(smp_fds[1], preq, sizeof(preq), MSG_EOR);
	close(smp_fds[1]);
	close(hci_fds[1]);

	errno = 0;
	ret = smp_respond(&sc);
	if (err_out != NULL)
		*err_out = errno;

	close(smp_fds[0]);
	close(hci_fds[0]);
	return (ret);
}

/*
 * F14: the global pairing rate limit must DEGRADE (throttle) rather than
 * hard-deny.  A host-wide hard rejection once total attempts exceed the cap
 * would let a single peer block pairing for EVERY device with ~31 requests a
 * minute.  Flood 40 attempts, each from a UNIQUE address so the per-address
 * cap never trips, well past SMP_RATE_LIMIT_GLOBAL_MAX (30).  NONE may be
 * rejected with EACCES: each must pass the rate gate (and fail later on the
 * closed peer, e.g. EPIPE/EPROTO), proving the global cap no longer denies.
 */
ATF_TC_WITHOUT_HEAD(test_smp_rate_limit_global);
ATF_TC_BODY(test_smp_rate_limit_global, tc)
{
	int i, err;
	char bond_path[] = "/tmp/blued_test_ratelim.XXXXXX";
	int bond_fd;

	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);
	signal(SIGPIPE, SIG_IGN);

	for (i = 0; i < 57; i++) {
		uint8_t remote[6];

		memset(remote, 0, sizeof(remote));
		remote[0] = (uint8_t)(i + 1);
		remote[1] = (uint8_t)((i + 1) >> 8);

		err = 0;
		(void)rate_one_attempt(bond_fd, remote, BDADDR_LE_PUBLIC, &err);
		ATF_CHECK_MSG(err != EACCES,
		    "attempt %d: global limit must throttle, not hard-deny "
		    "(host-wide pairing denial is a DoS lever)", i);
	}

	close(bond_fd);
	unlink(bond_path);
}

/*
 * F14: unauthenticated address churn must not evict a tracked offender's rate
 * slot.  Drive address A past the per-address cap so it is rate-limited
 * (EACCES), then flood many distinct churn addresses — more than the slot
 * table holds — then re-attempt A.  A must STILL be rate-limited, proving its
 * offender slot was protected from eviction (the old evict-oldest policy would
 * have discarded A, the oldest entry, on the first overflow and reset it).
 */
ATF_TC_WITHOUT_HEAD(test_smp_rate_limit_offender_not_evicted);
ATF_TC_BODY(test_smp_rate_limit_offender_not_evicted, tc)
{
	int i, err;
	char bond_path[] = "/tmp/blued_test_ratelim2.XXXXXX";
	int bond_fd;
	uint8_t off[6] = { 0xAA, 0, 0, 0, 0, 0 };

	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);
	signal(SIGPIPE, SIG_IGN);

	/* Push A over the per-address cap: it becomes a rate-limited offender. */
	err = 0;
	for (i = 0; i < 5; i++)
		(void)rate_one_attempt(bond_fd, off, BDADDR_LE_PUBLIC, &err);
	ATF_CHECK_EQ_MSG(err, EACCES,
	    "offender must be rate-limited after exceeding the per-address cap");

	/* Churn well past the 32-slot table with distinct fresh addresses. */
	for (i = 0; i < 40; i++) {
		uint8_t churn[6];

		memset(churn, 0, sizeof(churn));
		churn[0] = 0x01;
		churn[1] = (uint8_t)(i + 1);
		churn[2] = (uint8_t)((i + 1) >> 8);
		(void)rate_one_attempt(bond_fd, churn, BDADDR_LE_PUBLIC, NULL);
	}

	/* A must remain rate-limited: its offender slot survived the churn. */
	err = 0;
	(void)rate_one_attempt(bond_fd, off, BDADDR_LE_PUBLIC, &err);
	ATF_CHECK_EQ_MSG(err, EACCES,
	    "offender slot must survive unauthenticated churn (not be "
	    "evicted) — F14");

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
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/* Core 6.3 Vol 3 Part H §3.6.1 Figure 3.11: the initiator
		 * distribution field independently requests both EncKey and IdKey. */
		if ((preq[5] & (BTPR_SMP_KEY_DIST_ENC_KEY |
		    BTPR_SMP_KEY_DIST_ID_KEY)) !=
		    (BTPR_SMP_KEY_DIST_ENC_KEY | BTPR_SMP_KEY_DIST_ID_KEY))
			_exit(15);

		/* Send response requesting LTK+IRK from responder */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = BTPR_SMP_AUTH_BONDING;
		pres[4] = 16;
		pres[5] = BTPR_SMP_KEY_DIST_ENC_KEY |
		    BTPR_SMP_KEY_DIST_ID_KEY;
		pres[6] = BTPR_SMP_KEY_DIST_ENC_KEY | BTPR_SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), MSG_EOR) < 0)
			_exit(2);

		uint8_t iat = 0, rat = 0;

		/* Receive confirm */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(mconfirm, pdu + 1, 16);

		/* Generate random, compute confirm, send it */
		arc4random_buf(srand, sizeof(srand));
		reference_c1(tk, srand, preq, pres, iat, central_addr,
		    rat, periph_addr, sconfirm);

		pdu[0] = BTPR_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(4);

		/* Receive random */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_RANDOM)
			_exit(5);
		memcpy(mrand, pdu + 1, 16);

		/* Verify confirm */
		{
			uint8_t verify[16];
			reference_c1(tk, mrand, preq, pres, iat, central_addr,
			    rat, periph_addr, verify);
			if (memcmp(verify, mconfirm, 16) != 0)
				_exit(6);
		}

		/* Send our random */
		pdu[0] = BTPR_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(7);

		/* Send key distribution */
		arc4random_buf(our_ltk, sizeof(our_ltk));
		memset(our_irk, 0, sizeof(our_irk));

		pdu[0] = BTPR_SMP_ENCRYPTION_INFORMATION;
		memcpy(pdu + 1, our_ltk, 16);
		send(peer_fd, pdu, 17, MSG_EOR);

		pdu[0] = BTPR_SMP_CENTRAL_IDENTIFICATION;
		memset(pdu + 1, 0, 10);
		send(peer_fd, pdu, 11, MSG_EOR);

		pdu[0] = BTPR_SMP_IDENTITY_INFORMATION;
		memcpy(pdu + 1, our_irk, 16);
		send(peer_fd, pdu, 17, MSG_EOR);

		pdu[0] = BTPR_SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = 0x00;
		memcpy(pdu + 2, periph_addr, 6);
		send(peer_fd, pdu, 8, MSG_EOR);

		/* §3.6.1: initiator EncKey then IdKey distribution, with exact
		 * current-command PDU sizes and local public identity. */
		n = recv(peer_fd, pdu, sizeof(pdu), 0);
		if (n != 17 || pdu[0] != BTPR_SMP_ENCRYPTION_INFORMATION)
			_exit(8);
		n = recv(peer_fd, pdu, sizeof(pdu), 0);
		if (n != 11 || pdu[0] != BTPR_SMP_CENTRAL_IDENTIFICATION)
			_exit(9);
		n = recv(peer_fd, pdu, sizeof(pdu), 0);
		if (n != 17 || pdu[0] != BTPR_SMP_IDENTITY_INFORMATION)
			_exit(10);
		n = recv(peer_fd, pdu, sizeof(pdu), 0);
		if (n != 8 || pdu[0] != BTPR_SMP_IDENTITY_ADDRESS_INFO ||
		    pdu[1] != BT_CORE63_SMP_ID_ADDR_PUBLIC ||
		    memcmp(pdu + 2, central_addr, sizeof(central_addr)) != 0)
			_exit(11);
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

	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	close(hci_fds[0]);
	wait_child(pid);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test: min_key_size field is used during pairing.
 *
 * Set sc.min_key_size = 12 (> 7), then pair with a peer that offers
 * max_key_size = 10.  The central should reject with
 * BTPR_SMP_ERR_ENCRYPTION_KEY_SIZE.
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
	sc.min_key_size = BT_CORE63_SMP_MAX_KEY_SIZE - 4;

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);

		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/* Respond two octets below the independently derived local floor. */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = BTPR_SMP_AUTH_BONDING;
		pres[4] = BT_CORE63_SMP_MAX_KEY_SIZE - 6;
		pres[5] = 0x00;
		pres[6] = BTPR_SMP_KEY_DIST_ENC_KEY;
		send(peer_fd, pres, sizeof(pres), MSG_EOR);

		/*
		 * Vol 3 Part H §2.3.4 / Table 3.7: the resultant key size
		 * (min(local_max, 10) = 10) is below the local minimum (12),
		 * so the device must send Pairing Failed with reason
		 * "Encryption Key Size" (0x06).
		 */
		{
			uint8_t buf[65];
			ssize_t rn = recv(peer_fd, buf, sizeof(buf), 0);
			if (rn < 2 || buf[0] != BTPR_SMP_PAIRING_FAILED)
				_exit(20);
			if (buf[1] != BTPR_SMP_ERR_ENCRYPTION_KEY_SIZE)
				_exit(21);
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
 * Test: repeated failures extend the per-identity lockout window.
 * Core Spec Vol 3 Part H §2.3.5.5 requires protection against repeated
 * pairing attempts.  A virtual monotonic clock makes the backoff exact.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_rate_limit_backoff);
ATF_TC_BODY(test_smp_rate_limit_backoff, tc)
{
	char bond_path[] = "/tmp/blued_test_rlbo.XXXXXX";
	int bond_fd;
	int err, i;
	uint8_t remote[6] = { 0xBA, 0xC0, 0xFF, 0xEE, 0, 1 };

	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);
	signal(SIGPIPE, SIG_IGN);

	smp_test_now = 1000;
	/* Four excess attempts raise failures to four: effective window 120 s. */
	for (i = 0; i < 7; i++)
		(void)rate_one_attempt(bond_fd, remote, BDADDR_LE_PUBLIC, &err);
	ATF_REQUIRE_EQ(err, EACCES);

	/* The base 60-second window elapsed, but exponential backoff has not. */
	smp_test_now += 61;
	(void)rate_one_attempt(bond_fd, remote, BDADDR_LE_PUBLIC, &err);
	ATF_CHECK_EQ_MSG(err, EACCES,
	    "repeated-attempt backoff must extend beyond the base window");

	/* The rejected retry raises the next backoff to 240 seconds. */
	smp_test_now += 180;
	(void)rate_one_attempt(bond_fd, remote, BDADDR_LE_PUBLIC, &err);
	ATF_CHECK_MSG(err != EACCES,
	    "pairing must be admitted after the extended backoff expires");

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
	uint8_t wrong_irk[16], bad_rpa[6];

	/* Exact Core 6.3 Vol 3 Part H Appendix D.7 ah vector:
	 * IRK ec0234...397d9b, RPA hash||prand 0dfbaa||708194. */
	ATF_CHECK(smp_rpa_matches(bt_privacy_d7_irk_le,
	    bt_privacy_d7_rpa_le));

	/* Different IRK should NOT match */
	memset(wrong_irk, 0xAA, sizeof(wrong_irk));
	ATF_CHECK(!smp_rpa_matches(wrong_irk, bt_privacy_d7_rpa_le));

	/* Corrupted hash byte should NOT match */
	memcpy(bad_rpa, bt_privacy_d7_rpa_le, sizeof(bad_rpa));
	bad_rpa[0] ^= 0xFF;
	ATF_CHECK(!smp_rpa_matches(bt_privacy_d7_irk_le, bad_rpa));
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
	sc.io_capability = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;

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
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/* Verify OOB flag is set in pairing request */
		if (preq[2] != 0x01)	/* OOB Data Flag */
			_exit(2);

		/* 2. Send Pairing Response with OOB flag set */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x01;	/* OOB data present */
		pres[3] = BTPR_SMP_AUTH_BONDING;
		pres[4] = 16;		/* max key size */
		pres[5] = 0x00;
		pres[6] = BTPR_SMP_KEY_DIST_ENC_KEY | BTPR_SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), MSG_EOR) < 0)
			_exit(3);

		uint8_t iat = 0;  /* central is public */
		uint8_t rat = 0;  /* periph is public */

		/* 3. Receive Pairing Confirm from central */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_CONFIRM)
			_exit(4);
		memcpy(mconfirm, pdu + 1, 16);

		/* 4. Generate our random and compute confirm using OOB TK */
		arc4random_buf(srand, sizeof(srand));
		reference_c1(oob_tk, srand, preq, pres, iat, central_addr,
		    rat, periph_addr, sconfirm);

		pdu[0] = BTPR_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(5);

		/* 5. Receive Pairing Random from central */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_RANDOM)
			_exit(6);
		memcpy(mrand, pdu + 1, 16);

		/* Verify central's confirm using OOB TK */
		{
			uint8_t verify[16];
			reference_c1(oob_tk, mrand, preq, pres, iat, central_addr,
			    rat, periph_addr, verify);
			if (memcmp(verify, mconfirm, 16) != 0)
				_exit(7);
		}

		/* 6. Send our random */
		pdu[0] = BTPR_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(8);

		/* 7. Key distribution */
		arc4random_buf(our_ltk, sizeof(our_ltk));
		memset(our_irk, 0, sizeof(our_irk));

		pdu[0] = BTPR_SMP_ENCRYPTION_INFORMATION;
		memcpy(pdu + 1, our_ltk, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(9);

		pdu[0] = BTPR_SMP_CENTRAL_IDENTIFICATION;
		memset(pdu + 1, 0, 2);
		memset(pdu + 3, 0, 8);
		if (send(peer_fd, pdu, 11, MSG_EOR) < 0)
			_exit(10);

		pdu[0] = BTPR_SMP_IDENTITY_INFORMATION;
		memcpy(pdu + 1, our_irk, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(11);

		pdu[0] = BTPR_SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = 0x00;	/* public */
		memcpy(pdu + 2, periph_addr, 6);
		if (send(peer_fd, pdu, 8, MSG_EOR) < 0)
			_exit(12);

		/*
		 * Stay open and drain the initiator's own key distribution
		 * until the parent closes.  Closing here races the DUT's
		 * key-distribution sends, which under parallel load would fault
		 * with EPIPE and make smp_pair() return -1.
		 */
		{
			uint8_t discard[64];

			while (recv(peer_fd, discard, sizeof(discard), 0) > 0)
				;
		}
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

	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	close(hci_fds[0]);
	wait_child(pid);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test: SC OOB full pairing flow.
 *
 * Both sides pre-exchange OOB data (confirm + random) generated via
 * smp_generate_sc_oob.  The pairing uses SC with OOB association model.
 * Core Spec Vol 3 Part H Section 2.3.5.6.4
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_pair_oob_sc);
ATF_TC_BODY(test_smp_pair_oob_sc, tc)
{
	ATF_REQUIRE_MSG(reference_sc_oracles_match_core(),
	    "independent SC peer failed Core Appendix D.2-D.4 KATs");
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_pair_oob_sc.XXXXXX";
	int bond_fd;
	pid_t pid;

	/* Pre-generate OOB data for both sides */
	uint8_t local_confirm[16], local_random[16];
	uint8_t peer_confirm[16], peer_random[16];
	uint8_t local_pk_x[32], peer_pk_x[32], peer_pk_raw[65];
	EVP_PKEY *peer_key = NULL;

	struct smp_oob_sc oob_sc;
	struct smp_oob_data oob_data;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	/* Generate the peer key before fork so its OOB confirm matches the key
	 * that the mock actually sends during this pairing. */
	ATF_REQUIRE(sc_generate_keypair(&peer_key, peer_pk_raw) == 0);
	reverse_copy(peer_pk_x, peer_pk_raw + 1, sizeof(peer_pk_x));
	arc4random_buf(peer_random, sizeof(peer_random));
	ATF_REQUIRE(reference_f4(peer_pk_x, peer_pk_x, peer_random, 0,
	    peer_confirm) == 0);

	/* This also pins the generated local ephemeral for the next SC pairing. */
	ATF_REQUIRE(smp_sc_oob_generate_local(local_confirm, local_random,
	    local_pk_x) == 0);

	/* Set up OOB data: peer's confirm/random, our local_random */
	memcpy(oob_sc.confirm, peer_confirm, 16);
	memcpy(oob_sc.random, peer_random, 16);
	memcpy(oob_sc.local_random, local_random, 16);
	memset(&oob_data, 0, sizeof(oob_data));
	oob_data.sc = &oob_sc;
	sc.oob = &oob_data;
	sc.io_capability = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: mock peripheral for SC OOB pairing */
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[66];
		ssize_t n;

		uint8_t central_pk_raw[65];
		uint8_t pka_le[32], pkb_le[32];
		uint8_t dhkey_le[32];
		uint8_t na[16], nb[16];
		uint8_t mackey[16], ltk[16];
		uint8_t ea[16], eb[16];
		uint8_t a1[7], a2[7];
		uint8_t iocap_a[3], iocap_b[3];
		uint8_t r[16];

		close(smp_fds[0]);
		close(hci_fds[0]);

		/* 1. Receive Pairing Request */
		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/* Verify OOB + SC flags set in pairing request */
		if (preq[2] != 0x01)	/* OOB Data Flag */
			_exit(2);
		if (!(preq[3] & BTPR_SMP_AUTH_SC))
			_exit(3);

		/* 2. Send Pairing Response: SC + OOB */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x01;	/* OOB data present */
		pres[3] = BTPR_SMP_AUTH_BONDING | BTPR_SMP_AUTH_SC;
		pres[4] = 16;		/* max key size */
		pres[5] = 0x00;
		pres[6] = BTPR_SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), MSG_EOR) < 0)
			_exit(4);

		/* 3. Receive central's public key. */
		n = recv(peer_fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != BTPR_SMP_PAIRING_PUBLIC_KEY)
			_exit(5);
		central_pk_raw[0] = 0x04;
		reverse_copy(central_pk_raw + 1, pdu + 1, 32);
		reverse_copy(central_pk_raw + 33, pdu + 33, 32);
		memcpy(pka_le, pdu + 1, 32);

		/* 4. Send the public key used to generate the peer OOB data. */
		pdu[0] = BTPR_SMP_PAIRING_PUBLIC_KEY;
		reverse_copy(pdu + 1, peer_pk_raw + 1, 32);
		reverse_copy(pdu + 33, peer_pk_raw + 33, 32);
		memcpy(pkb_le, pdu + 1, 32);
		if (send(peer_fd, pdu, 65, MSG_EOR) < 0) {
			EVP_PKEY_free(peer_key);
			_exit(6);
		}

		/* 5. Compute DHKey. */
		if (sc_compute_dhkey(peer_key, central_pk_raw, dhkey_le) != 0) {
			EVP_PKEY_free(peer_key);
			_exit(7);
		}
		EVP_PKEY_free(peer_key);

		/*
		 * 6. SC OOB Stage 1: confirms were exchanged out of band, so
		 *    there is no Pairing Confirm PDU.  Receive Na, then send Nb.
		 */
		arc4random_buf(nb, sizeof(nb));

		/* Receive Na (central's random) */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_RANDOM)
			_exit(8);
		memcpy(na, pdu + 1, 16);

		/* Send Nb */
		pdu[0] = BTPR_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, nb, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(9);

		/*
		 * 8. Stage 2: Compute MacKey + LTK, DHKey checks.
		 */
		test_pack_addr(a1, central_addr, BDADDR_LE_PUBLIC);
		test_pack_addr(a2, periph_addr, BDADDR_LE_PUBLIC);

		iocap_a[0] = preq[1]; iocap_a[1] = preq[2];
		iocap_a[2] = preq[3];
		iocap_b[0] = pres[1]; iocap_b[1] = pres[2];
		iocap_b[2] = pres[3];

		reference_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
		memcpy(r, peer_random, sizeof(r));
		reference_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
		memcpy(r, local_random, sizeof(r));
		reference_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);

		/* Receive Ea from central, verify */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_DHKEY_CHECK)
			_exit(10);
		if (memcmp(pdu + 1, ea, 16) != 0)
			_exit(11);

		/* Send Eb */
		pdu[0] = BTPR_SMP_PAIRING_DHKEY_CHECK;
		memcpy(pdu + 1, eb, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(12);

		/* 9. Key distribution: send IRK + Identity Address */
		pdu[0] = BTPR_SMP_IDENTITY_INFORMATION;
		memset(pdu + 1, 0, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(13);

		pdu[0] = BTPR_SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = 0x00;	/* public */
		memcpy(pdu + 2, periph_addr, 6);
		if (send(peer_fd, pdu, 8, MSG_EOR) < 0)
			_exit(14);

		close(peer_fd);
		_exit(0);
	}

	/* Parent: central side */
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "smp_pair with SC OOB should succeed");

	/* Verify bond was stored and marked as SC */
	struct smp_bond *bond = smp_find_bond(&db, periph_addr,
	    BDADDR_LE_PUBLIC);
	ATF_CHECK_MSG(bond != NULL, "bond should exist after SC OOB pairing");
	if (bond != NULL) {
		ATF_CHECK(bond->has_ltk);
		ATF_CHECK(bond->is_sc);
	}

	wait_child(pid);
	EVP_PKEY_free(peer_key);
	smp_sc_oob_clear_local();

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test: Key distribution mask — responder masks its KeyDist to
 * the initiator's requested set.
 *
 * The responder's key distribution field in the Pairing Response
 * is masked: resp_dist &= init_requested.  Verify the initiator
 * observes this by checking pres[6] in the Pairing Response.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_key_dist_mask_responder);
ATF_TC_BODY(test_key_dist_mask_responder, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_kdm.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	signal(SIGPIPE, SIG_IGN);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[65];
		uint8_t tk[16], srand[16], mrand[16];
		uint8_t sconfirm[16], mconfirm[16];
		uint8_t our_ltk[16];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		memset(tk, 0, sizeof(tk));

		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/*
		 * The initiator requested EncKey|IdKey|SignKey in preq[6].
		 * Respond with only EncKey — the response must be masked
		 * to at most what the initiator requested.
		 */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = BTPR_SMP_AUTH_BONDING;
		pres[4] = 16;
		pres[5] = 0x00;
		pres[6] = BTPR_SMP_KEY_DIST_ENC_KEY;  /* only EncKey */
		if (send(peer_fd, pres, sizeof(pres), MSG_EOR) < 0)
			_exit(2);

		/* Confirm exchange */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(mconfirm, pdu + 1, 16);

		arc4random_buf(srand, sizeof(srand));
		reference_c1(tk, srand, preq, pres, 0, central_addr,
		    0, periph_addr, sconfirm);
		pdu[0] = BTPR_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(4);

		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_RANDOM)
			_exit(5);
		memcpy(mrand, pdu + 1, 16);

		{
			uint8_t verify[16];
			reference_c1(tk, mrand, preq, pres, 0, central_addr,
			    0, periph_addr, verify);
			if (memcmp(verify, mconfirm, 16) != 0)
				_exit(6);
		}

		pdu[0] = BTPR_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(7);

		/* Distribute only EncKey (LTK + Master ID) */
		arc4random_buf(our_ltk, sizeof(our_ltk));
		pdu[0] = BTPR_SMP_ENCRYPTION_INFORMATION;
		memcpy(pdu + 1, our_ltk, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(8);

		pdu[0] = BTPR_SMP_CENTRAL_IDENTIFICATION;
		memset(pdu + 1, 0, 10);
		if (send(peer_fd, pdu, 11, MSG_EOR) < 0)
			_exit(9);

		/* Drain initiator's key distribution */
		{
			uint8_t discard[64];
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
			while (recv(peer_fd, discard, sizeof(discard), 0) > 0)
				;
		}

		close(peer_fd);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, 0,
	    "pairing with masked key dist should succeed (ret=%d)", ret);

	/* Verify bond stored with LTK (from responder EncKey) */
	ATF_CHECK_MSG(db.count > 0, "bond should be stored");
	if (db.count > 0) {
		ATF_CHECK(db.bonds[0].has_ltk);
		/* No IRK from responder (was not in pres[6]) */
		ATF_CHECK(!db.bonds[0].has_irk);
	}

	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	close(hci_fds[0]);
	wait_child(pid);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test: EncKey distribution in legacy mode produces correct PDUs.
 *
 * Verify the initiator distributes Encryption Info + Master ID
 * when preq[5] requests BTPR_SMP_KEY_DIST_ENC_KEY.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_key_dist_enckey_legacy);
ATF_TC_BODY(test_key_dist_enckey_legacy, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_ekl.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	signal(SIGPIPE, SIG_IGN);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[65];
		uint8_t tk[16], srand[16], mrand[16];
		uint8_t sconfirm[16], mconfirm[16];
		uint8_t our_ltk[16];
		ssize_t n;
		bool got_enc_info = false, got_master_id = false;

		close(smp_fds[0]);
		close(hci_fds[0]);
		memset(tk, 0, sizeof(tk));

		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/* Accept initiator EncKey distribution */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = BTPR_SMP_AUTH_BONDING;
		pres[4] = 16;
		pres[5] = BTPR_SMP_KEY_DIST_ENC_KEY;	/* request initiator EncKey */
		pres[6] = BTPR_SMP_KEY_DIST_ENC_KEY;
		if (send(peer_fd, pres, sizeof(pres), MSG_EOR) < 0)
			_exit(2);

		/* Legacy confirm/random exchange */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(mconfirm, pdu + 1, 16);

		arc4random_buf(srand, sizeof(srand));
		reference_c1(tk, srand, preq, pres, 0, central_addr,
		    0, periph_addr, sconfirm);
		pdu[0] = BTPR_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(4);

		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_RANDOM)
			_exit(5);
		memcpy(mrand, pdu + 1, 16);

		{
			uint8_t verify[16];
			reference_c1(tk, mrand, preq, pres, 0, central_addr,
			    0, periph_addr, verify);
			if (memcmp(verify, mconfirm, 16) != 0)
				_exit(6);
		}

		pdu[0] = BTPR_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(7);

		/* Distribute our (responder) EncKey first */
		arc4random_buf(our_ltk, sizeof(our_ltk));
		pdu[0] = BTPR_SMP_ENCRYPTION_INFORMATION;
		memcpy(pdu + 1, our_ltk, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(8);

		pdu[0] = BTPR_SMP_CENTRAL_IDENTIFICATION;
		memset(pdu + 1, 0, 10);
		if (send(peer_fd, pdu, 11, MSG_EOR) < 0)
			_exit(9);

		/*
		 * Now receive initiator's key distribution PDUs.
		 * Expect BTPR_SMP_ENCRYPTION_INFORMATION (17 bytes) and
		 * BTPR_SMP_CENTRAL_IDENTIFICATION (11 bytes).
		 */
		{
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
		}
		for (int i = 0; i < 5; i++) {
			n = recv(peer_fd, pdu, sizeof(pdu), 0);
			if (n <= 0)
				break;
			if (pdu[0] == BTPR_SMP_ENCRYPTION_INFORMATION && n == 17)
				got_enc_info = true;
			if (pdu[0] == BTPR_SMP_CENTRAL_IDENTIFICATION && n == 11)
				got_master_id = true;
		}

		if (!got_enc_info || !got_master_id)
			_exit(10);

		close(peer_fd);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, 0,
	    "legacy EncKey distribution should succeed (ret=%d)", ret);

	/* End the peer's bounded drain before waiting for it to exit. */
	close(smp_fds[0]);
	close(hci_fds[0]);
	wait_child(pid);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test: SignKey (CSRK) distribution produces correct PDU format.
 *
 * When BTPR_SMP_KEY_DIST_LEGACY_SIGN_KEY is negotiated, the initiator sends
 * SMP_LEGACY_SIGNING_INFORMATION (opcode 0x0A) with a 16-byte CSRK.
 * Total PDU = 17 bytes.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_key_dist_signkey);
ATF_TC_BODY(test_key_dist_signkey, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_sk.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	signal(SIGPIPE, SIG_IGN);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC);
	/* Explicit pre-Core-5.1 compatibility opt-in; not a current default. */
	sc.our_key_dist |= BTPR_SMP_KEY_DIST_LEGACY_SIGN_KEY;

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[65];
		uint8_t tk[16], srand[16], mrand[16];
		uint8_t sconfirm[16], mconfirm[16];
		uint8_t our_ltk[16];
		ssize_t n;
		bool got_signing_info = false;

		close(smp_fds[0]);
		close(hci_fds[0]);
		memset(tk, 0, sizeof(tk));

		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		/* Request initiator SignKey distribution */
		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = BTPR_SMP_AUTH_BONDING;
		pres[4] = 16;
		/* Core 6.3 §3.6.1 Figure 3.11: deliberately request removed bit. */
		pres[5] = BT_CORE63_LEGACY_SMP_SIGN_KEY_MASK;
		pres[6] = BTPR_SMP_KEY_DIST_ENC_KEY;
		if (send(peer_fd, pres, sizeof(pres), MSG_EOR) < 0)
			_exit(2);

		/* Legacy confirm/random exchange */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(mconfirm, pdu + 1, 16);

		arc4random_buf(srand, sizeof(srand));
		reference_c1(tk, srand, preq, pres, 0, central_addr,
		    0, periph_addr, sconfirm);
		pdu[0] = BTPR_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(4);

		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTPR_SMP_PAIRING_RANDOM)
			_exit(5);
		memcpy(mrand, pdu + 1, 16);

		{
			uint8_t verify[16];
			reference_c1(tk, mrand, preq, pres, 0, central_addr,
			    0, periph_addr, verify);
			if (memcmp(verify, mconfirm, 16) != 0)
				_exit(6);
		}

		pdu[0] = BTPR_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(7);

		/* Distribute responder EncKey */
		arc4random_buf(our_ltk, sizeof(our_ltk));
		pdu[0] = BTPR_SMP_ENCRYPTION_INFORMATION;
		memcpy(pdu + 1, our_ltk, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(8);

		pdu[0] = BTPR_SMP_CENTRAL_IDENTIFICATION;
		memset(pdu + 1, 0, 10);
		if (send(peer_fd, pdu, 11, MSG_EOR) < 0)
			_exit(9);

		/* Receive initiator key distribution -- look for SignKey */
		{
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
		}
		for (int i = 0; i < 10; i++) {
			n = recv(peer_fd, pdu, sizeof(pdu), 0);
			if (n <= 0)
				break;
			if (pdu[0] == BT_CORE63_LEGACY_SMP_SIGNING_OPCODE && n >= 17) {
				got_signing_info = true;
				/* Verify PDU is exactly 17 bytes (opcode + CSRK) */
				if (n != 17)
					_exit(11);
			}
		}

		if (!got_signing_info)
			_exit(12);

		close(peer_fd);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, 0,
	    "pairing with SignKey dist should succeed (ret=%d)", ret);

	/* End the peer's bounded drain before waiting for it to exit. */
	close(smp_fds[0]);
	close(hci_fds[0]);
	wait_child(pid);
	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Test: IO capability all 25 combinations (5x5 grid).
 *
 * Core Spec Vol 3 Part H Table 2.8 defines the pairing method
 * for all IO capability combinations. This test verifies all 25
 * for both legacy (Table 2.6) and SC (Table 2.7) in a single test.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_io_cap_all_25_combinations);
ATF_TC_BODY(test_io_cap_all_25_combinations, tc)
{
	/* Generated directly from Core 6.3 Vol 3 Part H §2.3.5.1 Table 2.8;
	 * rows are responder IO and columns are initiator IO. */
	static const int legacy_expected[5][5] = {
		BT_CORE63_SMP_ASSOC_LEGACY_MATRIX
	};
	static const int sc_expected[5][5] = {
		BT_CORE63_SMP_ASSOC_SC_MATRIX
	};

	int failures = 0;

	/* Legacy: verify all 25 combinations */
	for (int i = 0; i < 5; i++) {
		for (int r = 0; r < 5; r++) {
			int got = smp_select_model(i, r, false);
			if (got != legacy_expected[r][i]) {
				failures++;
				ATF_CHECK_MSG(0,
				    "legacy[init=%d][resp=%d]: "
				    "expected %d, got %d",
				    i, r, legacy_expected[r][i], got);
			}
		}
	}

	/* SC: verify all 25 combinations */
	for (int i = 0; i < 5; i++) {
		for (int r = 0; r < 5; r++) {
			int got = smp_select_model(i, r, true);
			if (got != sc_expected[r][i]) {
				failures++;
				ATF_CHECK_MSG(0,
				    "sc[init=%d][resp=%d]: "
				    "expected %d, got %d",
				    i, r, sc_expected[r][i], got);
			}
		}
	}

	ATF_CHECK_EQ_MSG(failures, 0,
	    "%d IO capability combinations produced wrong pairing method",
	    failures);
}

/* ================================================================
 * Test: runtime pairing-agent IO-capability override selects the model.
 *
 * A registered pairing agent (BlueZ AgentManager1) supplies the responder IO
 * capability that blued feeds into smp_conn.io_capability via
 * blued_ctl_effective_io_cap().  For a fixed initiator (KeyboardDisplay, LE
 * Secure Connections) the association model the agent's capability selects
 * differs from the daemon's static default — proving the override changes the
 * pairing method (Core Spec Vol 3 Part H §2.3.5.1, Table 2.7).
 * 0 = Just Works, 1 = Passkey Entry, 2 = Numeric Comparison.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_agent_iocap_override_selects_model);
ATF_TC_BODY(test_agent_iocap_override_selects_model, tc)
{
	static const int sc_expected[5][5] = {
		BT_CORE63_SMP_ASSOC_SC_MATRIX
	};
	const uint8_t init = BTPR_SMP_IO_KEYBOARD_DISPLAY;

	/* Static default NoInputNoOutput -> Just Works (unauthenticated). */
	ATF_CHECK_EQ(sc_expected[BTPR_SMP_IO_NO_INPUT_NO_OUTPUT][init],
	    smp_select_model(init, BTPR_SMP_IO_NO_INPUT_NO_OUTPUT, true));

	/* Agent override DisplayYesNo -> Numeric Comparison (MITM). */
	ATF_CHECK_EQ(sc_expected[BTPR_SMP_IO_DISPLAY_YESNO][init],
	    smp_select_model(init, BTPR_SMP_IO_DISPLAY_YESNO, true));

	/* Agent override KeyboardOnly -> Passkey Entry (MITM). */
	ATF_CHECK_EQ(sc_expected[BTPR_SMP_IO_KEYBOARD_ONLY][init],
	    smp_select_model(init, BTPR_SMP_IO_KEYBOARD_ONLY, true));
}

/* ================================================================
 * Test: Rate limiting — rejects fast retry from same address.
 *
 * Send >3 pairing attempts from the same address within the
 * 60-second window. The 4th attempt should be rejected by the
 * per-address rate limiter.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_rate_limit_rejects_fast_retry);
ATF_TC_BODY(test_rate_limit_rejects_fast_retry, tc)
{
	char bond_path[] = "/tmp/blued_test_rlfast.XXXXXX";
	int bond_fd;
	int i;

	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);
	signal(SIGPIPE, SIG_IGN);

	/*
	 * Send 4 pairing attempts from the SAME address.
	 * SMP_RATE_LIMIT_MAX = 3, so the 4th should fail.
	 */
	uint8_t same_addr[6] = { 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE };

	for (i = 0; i < 4; i++) {
		struct smp_conn sc;
		struct smp_bond_db db;
		int smp_fds[2], hci_fds[2];
		uint8_t preq[7];
		int ret;

		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0,
		    smp_fds) == 0);
		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0,
		    hci_fds) == 0);

		setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
		    periph_addr, BDADDR_LE_PUBLIC,
		    same_addr, BDADDR_LE_PUBLIC);

		{
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			setsockopt(smp_fds[0], SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
		}

		preq[0] = BTPR_SMP_PAIRING_REQUEST;
		preq[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		preq[2] = 0x00;
		preq[3] = BTPR_SMP_AUTH_BONDING;
		preq[4] = 16;
		preq[5] = 0x00;
		preq[6] = BTPR_SMP_KEY_DIST_ENC_KEY;
		send(smp_fds[1], preq, sizeof(preq), MSG_EOR);
		close(smp_fds[1]);
		close(hci_fds[1]);

		ret = smp_respond(&sc);

		if (i >= 3) {
			/*
			 * 4th attempt from same address: rate-limited.
			 */
			ATF_CHECK_EQ_MSG(ret, -1,
			    "attempt %d: should be rate-limited", i);
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
 * Test: Rate limiting — allows after delay (window expiry).
 *
 * Core §3.4 requires an appropriate delay but does not assign 60 seconds;
 * that duration and the three-attempt allowance are explicit blued policy.
 * The virtual monotonic clock tests the exact open/closed boundary without
 * sleeping.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_rate_limit_allows_after_delay);
ATF_TC_BODY(test_rate_limit_allows_after_delay, tc)
{
	char bond_path[] = "/tmp/blued_test_rldelay.XXXXXX";
	int bond_fd;
	int err, i;
	uint8_t remote[6] = { 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56 };

	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);
	signal(SIGPIPE, SIG_IGN);

	smp_test_now = 1000;
	for (i = 0; i < (int)BT_SMP_IMPL_RATE_LIMIT_FIRST_REJECTED; i++) {
		err = 0;
		(void)rate_one_attempt(bond_fd, remote, BDADDR_LE_PUBLIC, &err);
	}
	ATF_REQUIRE_EQ_MSG(EACCES, err,
	    "the independently specified fourth attempt must be rejected");

	/* The implementation expires only when elapsed > 60, so the exact
	 * 60-second boundary remains closed. */
	smp_test_now += BT_SMP_IMPL_RATE_LIMIT_BASE_SECONDS;
	(void)rate_one_attempt(bond_fd, remote, BDADDR_LE_PUBLIC, &err);
	ATF_CHECK_EQ_MSG(EACCES, err, "base-window endpoint admitted early");

	/* Move beyond the closed 60-second endpoint measured from the original
	 * instant; this case has not yet accumulated enough failures to double it. */
	smp_test_now += 1;
	(void)rate_one_attempt(bond_fd, remote, BDADDR_LE_PUBLIC, &err);
	ATF_CHECK_MSG(err != EACCES,
	    "attempt after the independently specified backoff was rejected");

	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * SR1: minimum-security-for-pairing policy
 * ================================================================ */

/* Pure policy truth table (Core Spec Vol 3 Part H §2.3.5.1). */
ATF_TC_WITHOUT_HEAD(test_smp_policy_permits);
ATF_TC_BODY(test_smp_policy_permits, tc)
{

	/* none / enc: no association-model floor. */
	ATF_CHECK(smp_policy_permits(SMP_SEC_NONE, false, false));
	ATF_CHECK(smp_policy_permits(SMP_SEC_ENC, false, false));
	ATF_CHECK(smp_policy_permits(SMP_SEC_ENC, false, true));

	/* auth: reject unauthenticated Just Works, accept authenticated. */
	ATF_CHECK(!smp_policy_permits(SMP_SEC_AUTH, false, false));
	ATF_CHECK(smp_policy_permits(SMP_SEC_AUTH, true, false));
	ATF_CHECK(smp_policy_permits(SMP_SEC_AUTH, true, true));

	/* sc: reject legacy (even authenticated) and reject SC Just Works. */
	ATF_CHECK(!smp_policy_permits(SMP_SEC_SC, true, false));
	ATF_CHECK(!smp_policy_permits(SMP_SEC_SC, false, true));
	ATF_CHECK(smp_policy_permits(SMP_SEC_SC, true, true));
}

/*
 * With min_pairing_security = auth, a peer offering only Just Works (no MITM)
 * is rejected with Pairing Failed / Authentication Requirements and smp_pair()
 * fails.  Proves the policy is wired into the pairing handshake.
 */
ATF_TC_WITHOUT_HEAD(test_smp_pair_rejects_jw_under_auth);
ATF_TC_BODY(test_smp_pair_rejects_jw_under_auth, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_minsec.XXXXXX";
	int bond_fd, ret;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup_conn(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC);
	sc.io_capability = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
	sc.min_pairing_security = SMP_SEC_AUTH;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], fail[8];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);

		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != BTPR_SMP_PAIRING_REQUEST)
			_exit(1);

		pres[0] = BTPR_SMP_PAIRING_RESPONSE;
		pres[1] = BTPR_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;			/* no OOB */
		pres[3] = BTPR_SMP_AUTH_BONDING;	/* no MITM, no SC -> Just Works */
		pres[4] = 16;
		pres[5] = 0x00;
		pres[6] = BTPR_SMP_KEY_DIST_ENC_KEY | BTPR_SMP_KEY_DIST_ID_KEY;
		if (send(peer_fd, pres, sizeof(pres), MSG_EOR) < 0)
			_exit(2);

		/* Expect Pairing Failed(Authentication Requirements). */
		n = recv(peer_fd, fail, sizeof(fail), 0);
		if (n < 2 || fail[0] != BTPR_SMP_PAIRING_FAILED ||
		    fail[1] != BTPR_SMP_ERR_AUTH_REQUIREMENTS)
			_exit(3);
		close(peer_fd);
		_exit(0);
	}

	/* Parent: central */
	close(smp_fds[1]);
	close(hci_fds[1]);

	ret = smp_pair(&sc);
	ATF_CHECK_MSG(ret < 0,
	    "smp_pair must fail under auth floor vs Just Works (ret=%d)", ret);
	ATF_CHECK_EQ_MSG(errno, EACCES, "expected EACCES, got errno=%d", errno);
	ATF_CHECK_EQ_MSG(db.count, 0, "no bond may be stored on rejection");

	wait_child(pid);

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* The transport logger is shared by every SMP procedure.  Exercise its
 * capture-enabled arms directly so pairing traces retain both directions. */
ATF_TC_WITHOUT_HEAD(test_smp_transport_capture_logging);
ATF_TC_BODY(test_smp_transport_capture_logging, tc)
{
	struct smp_conn sc;
	uint8_t tx[] = { BTPR_SMP_PAIRING_REQUEST, 0x01 };
	uint8_t rx[] = { BTPR_SMP_PAIRING_RESPONSE, 0x02 };
	uint8_t got[sizeof(rx)];
	int sp[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp));
	memset(&sc, 0, sizeof(sc));
	sc.fd = sp[0];
	sc.con_handle = 0x0040;
	test_hci_log_on = true;
	test_hci_log_l2cap_calls = 0;

	ATF_REQUIRE_EQ((ssize_t)sizeof(tx), smp_log_send(&sc, tx, sizeof(tx)));
	ATF_REQUIRE_EQ((ssize_t)sizeof(tx), recv(sp[1], got, sizeof(got), 0));
	ATF_REQUIRE_EQ((ssize_t)sizeof(rx), send(sp[1], rx, sizeof(rx), 0));
	ATF_REQUIRE_EQ((ssize_t)sizeof(rx), smp_log_recv(&sc, got, sizeof(got)));
	ATF_CHECK_EQ(2U, test_hci_log_l2cap_calls);

	test_hci_log_on = false;
	close(sp[1]);
	/* A peer can disappear between SMP PDUs.  The shared logger must surface
	 * the transport failure to the pairing state machine rather than report a
	 * successful send. */
	signal(SIGPIPE, SIG_IGN);
	ATF_CHECK(smp_log_send(&sc, tx, sizeof(tx)) < 0);
	close(sp[0]);
}

ATF_TC_WITHOUT_HEAD(test_smp_log_recv_rejects_truncated_record);
ATF_TC_BODY(test_smp_log_recv_rejects_truncated_record, tc)
{

	ATF_CHECK(smp_record_is_truncated(AF_BLUETOOTH, MSG_TRUNC));
	ATF_CHECK(!smp_record_is_truncated(AF_BLUETOOTH, 0));
	ATF_CHECK(!smp_record_is_truncated(AF_UNIX, MSG_TRUNC));
}

/* Direct policy helpers encode the Core Specification AuthReq and Table 2.8
 * rules used before any pairing PDU is sent. */
ATF_TC_WITHOUT_HEAD(test_smp_authreq_and_passkey_helpers);
ATF_TC_BODY(test_smp_authreq_and_passkey_helpers, tc)
{
	struct smp_conn sc;

	memset(&sc, 0, sizeof(sc));
	ATF_CHECK_EQ(BTPR_SMP_AUTH_CT2, smp_build_authreq(&sc));
	sc.bondable = true;
	sc.require_mitm = true;
	sc.sc_enabled = true;
	sc.keypress = true;
	ATF_CHECK_EQ(BTPR_SMP_AUTH_BONDING | BTPR_SMP_AUTH_MITM |
	    BTPR_SMP_AUTH_SC | BTPR_SMP_AUTH_KEYPRESS | BTPR_SMP_AUTH_CT2,
	    smp_build_authreq(&sc));

	/* Input-only, peer-display-only, one-sided display, and dual-display
	 * tie-break cases respectively cover every Table 2.8 helper decision. */
	ATF_CHECK(!smp_passkey_we_display(BTPR_SMP_IO_KEYBOARD_ONLY,
	    BTPR_SMP_IO_DISPLAY_ONLY, true));
	ATF_CHECK(!smp_passkey_we_display(BTPR_SMP_IO_DISPLAY_ONLY,
	    BTPR_SMP_IO_DISPLAY_ONLY, true));
	ATF_CHECK(smp_passkey_we_display(BTPR_SMP_IO_DISPLAY_ONLY,
	    BTPR_SMP_IO_KEYBOARD_ONLY, false));
	ATF_CHECK(smp_passkey_we_display(BTPR_SMP_IO_KEYBOARD_DISPLAY,
	    BTPR_SMP_IO_KEYBOARD_DISPLAY, true));
	ATF_CHECK(!smp_passkey_we_display(BTPR_SMP_IO_KEYBOARD_DISPLAY,
	    BTPR_SMP_IO_KEYBOARD_DISPLAY, false));
}

/* Core 6.3 Vol 3 Part H §3.6.1, Figure 3.11. */
ATF_TC_WITHOUT_HEAD(test_smp_key_dist_current_defaults);
ATF_TC_BODY(test_smp_key_dist_current_defaults, tc)
{
	struct smp_conn sc;

	memset(&sc, 0, sizeof(sc));
	smp_seed_policy_defaults(&sc);
	ATF_CHECK_EQ(BT_CORE63_SMP_KEY_DIST_DEFAULT_MASK, sc.our_key_dist);
	ATF_CHECK_EQ(BT_CORE63_SMP_KEY_DIST_DEFAULT_MASK, sc.their_key_dist);
	ATF_CHECK_EQ(0, sc.our_key_dist &
	    BT_CORE63_SMP_KEY_DIST_PREVIOUSLY_USED_MASK);
	ATF_CHECK_EQ(0, sc.their_key_dist &
	    BT_CORE63_SMP_KEY_DIST_PREVIOUSLY_USED_MASK);
}

static unsigned int test_keypress_callbacks;
static uint8_t test_last_keypress;

static void
test_keypress_callback(uint8_t type, void *arg)
{

	ATF_CHECK_EQ(arg, (void *)&test_keypress_callbacks);
	test_keypress_callbacks++;
	test_last_keypress = type;
}

ATF_TC_WITHOUT_HEAD(test_smp_recv_keypress_callback);
ATF_TC_BODY(test_smp_recv_keypress_callback, tc)
{
	struct smp_conn sc;
	uint8_t keypress[] = { BTPR_SMP_PAIRING_KEYPRESS_NOTIFY,
	    BTPR_SMP_KEYPRESS_DIGIT_ENTERED };
	uint8_t response[] = { BTPR_SMP_PAIRING_CONFIRM, 0xa5 };
	uint8_t got[sizeof(response)];
	ssize_t n;
	int sp[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp));
	memset(&sc, 0, sizeof(sc));
	sc.fd = sp[0];
	sc.keypress_cb = test_keypress_callback;
	sc.keypress_cb_arg = &test_keypress_callbacks;
	test_keypress_callbacks = 0;
	test_last_keypress = 0;
	ATF_REQUIRE_EQ((ssize_t)sizeof(keypress),
	    send(sp[1], keypress, sizeof(keypress), 0));
	ATF_REQUIRE_EQ((ssize_t)sizeof(response),
	    send(sp[1], response, sizeof(response), 0));
	n = smp_recv_skip_keypress(&sc, got, sizeof(got));
	ATF_REQUIRE_EQ_MSG((ssize_t)sizeof(response), n,
	    "keypress receive returned %zd (errno=%d)", n, errno);
	ATF_CHECK_EQ(BTPR_SMP_PAIRING_CONFIRM, got[0]);
	ATF_CHECK_EQ(1U, test_keypress_callbacks);
	ATF_CHECK_EQ(BTPR_SMP_KEYPRESS_DIGIT_ENTERED, test_last_keypress);
	close(sp[0]);
	close(sp[1]);
}

/* A keypress PDU is informational, but it must not let a peer keep a pairing
 * procedure alive forever.  The receiver has a bounded discard loop in
 * addition to the Core Spec §3.4 procedure timer. */
ATF_TC_WITHOUT_HEAD(test_smp_recv_keypress_flood_is_bounded);
ATF_TC_BODY(test_smp_recv_keypress_flood_is_bounded, tc)
{
	struct smp_conn sc;
	uint8_t keypress[] = { BTPR_SMP_PAIRING_KEYPRESS_NOTIFY,
	    BTPR_SMP_KEYPRESS_DIGIT_ENTERED };
	uint8_t got[sizeof(keypress)];
	int sp[2], i;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp));
	memset(&sc, 0, sizeof(sc));
	sc.fd = sp[0];
	for (i = 0; i < 101; i++)
		ATF_REQUIRE_EQ((ssize_t)sizeof(keypress),
		    send(sp[1], keypress, sizeof(keypress), 0));
	ATF_CHECK_EQ(-1, smp_recv_skip_keypress(&sc, got, sizeof(got)));
	close(sp[0]);
	close(sp[1]);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* SR1 minimum-security-for-pairing policy */
	ATF_TP_ADD_TC(tp, test_smp_policy_permits);
	ATF_TP_ADD_TC(tp, test_smp_pair_rejects_jw_under_auth);
	ATF_TP_ADD_TC(tp, test_smp_transport_capture_logging);
	ATF_TP_ADD_TC(tp, test_smp_log_recv_rejects_truncated_record);
	ATF_TP_ADD_TC(tp, test_smp_authreq_and_passkey_helpers);
	ATF_TP_ADD_TC(tp, test_smp_key_dist_current_defaults);
	ATF_TP_ADD_TC(tp, test_smp_recv_keypress_callback);
	ATF_TP_ADD_TC(tp, test_smp_recv_keypress_flood_is_bounded);

	/* SMP pairing handshake tests — central (initiator) */
	ATF_TP_ADD_TC(tp, test_smp_pair_legacy_just_works);
	ATF_TP_ADD_TC(tp, test_smp_pair_legacy_peer_rejects);
	ATF_TP_ADD_TC(tp, test_smp_pair_invalid_key_size);
	ATF_TP_ADD_TC(tp, test_smp_pair_wrong_opcode);

	/* SMP pairing handshake tests — peripheral (responder) */
	ATF_TP_ADD_TC(tp, test_smp_respond_legacy_just_works);
	ATF_TP_ADD_TC(tp, test_smp_respond_not_pairable);
	ATF_TP_ADD_TC(tp, test_smp_respond_peer_bad_request);

	/* Bond database extended tests */
	ATF_TP_ADD_TC(tp, test_bond_find_by_addr);
	ATF_TP_ADD_TC(tp, test_bond_find_not_found);
	ATF_TP_ADD_TC(tp, test_bond_upsert);
	ATF_TP_ADD_TC(tp, test_bond_save_load_empty);
	ATF_TP_ADD_TC(tp, test_bond_save_load_irk);
	ATF_TP_ADD_TC(tp, test_bond_headerless_file);
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
	ATF_TP_ADD_TC(tp, test_smp_rate_limit_offender_not_evicted);

	/* Key distribution and configuration */
	ATF_TP_ADD_TC(tp, test_smp_init_key_distribution);
	ATF_TP_ADD_TC(tp, test_smp_min_key_size_configurable);
	ATF_TP_ADD_TC(tp, test_smp_rate_limit_backoff);
	ATF_TP_ADD_TC(tp, test_smp_close_zeros_addresses);

	/* RPA resolution */
	ATF_TP_ADD_TC(tp, test_smp_rpa_matches);

	/* Legacy OOB pairing */
	ATF_TP_ADD_TC(tp, test_smp_pair_oob_legacy);

	/* SC OOB pairing */
	ATF_TP_ADD_TC(tp, test_smp_pair_oob_sc);

	/* Key distribution tests */
	ATF_TP_ADD_TC(tp, test_key_dist_mask_responder);
	ATF_TP_ADD_TC(tp, test_key_dist_enckey_legacy);
	ATF_TP_ADD_TC(tp, test_key_dist_signkey);

	/* IO capability full 25-combination test */
	ATF_TP_ADD_TC(tp, test_io_cap_all_25_combinations);
	ATF_TP_ADD_TC(tp, test_agent_iocap_override_selects_model);

	/* Rate limiting */
	ATF_TP_ADD_TC(tp, test_rate_limit_rejects_fast_retry);
	ATF_TP_ADD_TC(tp, test_rate_limit_allows_after_delay);

	/* BLE key refresh (controlled re-bond): keys-only replace semantics */
	ATF_TP_ADD_TC(tp, test_bond_replace_keys_old_ltk_invalid);
	ATF_TP_ADD_TC(tp, test_bond_replace_keys_preserves_metadata);
	ATF_TP_ADD_TC(tp, test_bond_replace_keys_count_stable);
	ATF_TP_ADD_TC(tp, test_bond_store_inplace_preserves_metadata);

	return (atf_no_error());
}
