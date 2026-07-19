/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Deep-coverage ATF tests for LE Secure Connections pairing (smp_sc.c) and
 * the SC-key-distribution / CTKD tails in smp_keys.c.
 *
 * These drive the full smp_pair()/smp_respond() entry points so that the
 * SC success tails the happy-path tests leave uncovered are exercised:
 *
 *   - RANDOM SMP address packing (smp_pack_addr type bit),
 *   - Numeric Comparison and Passkey Entry to completion on BOTH sides,
 *   - Identity key distribution in both directions and LinkKey negotiation
 *     (so smp_distribute_init_keys / smp_receive_peer_keys IdKey paths run),
 *   - CT2-negotiated Cross-Transport Key Derivation from an SC MITM bond
 *     (the h7 ILK path in smp_ctkd_derive_link_key).
 *
 * A fork(2)ed mock peer speaks the protocol in lockstep over a
 * SOCK_SEQPACKET socketpair; key-distribution bursts are paced because this
 * platform can coalesce queued SEQPACKET sends.
 *
 * Oracle: Core Spec Vol 3 Part H Section 2.3.5.6 (LE Secure Connections),
 * Table 2.8 (association-model selection), Section 2.4.2.4 (CTKD).
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
#include "spec_smp_deep_sc_oracles.h"

#define TEST_LINKS_SMP
#include "test_common.h"

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif
#ifndef BDADDR_LE_RANDOM
#define BDADDR_LE_RANDOM	2
#endif

/* ================================================================ */
static int g_hci_send_fail;
static int g_hci_wait_fail;
static int g_bond_store_fail;
static int g_jw_bad_confirm;
static int g_jw_abort_random;
static int g_jw_bad_dhkey;
static int g_jw_truncated_dhkey;
static int g_jw_truncated_random;

int
hci_send_raw_cmd(int hci_fd __unused, uint16_t opcode __unused,
    const void *params __unused, uint8_t plen __unused)
{

	return (g_hci_send_fail ? -1 : 0);
}

int
hci_wait_encryption(int hci_fd __unused, uint16_t con_handle __unused,
    int timeout_sec __unused)
{

	return (g_hci_wait_fail ? -1 : 0);
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

static const uint8_t central_addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
static const uint8_t periph_addr[6]  = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 };

static uint32_t g_passkey = 424242;

static int
cb_passkey(uint32_t *out, bool display __unused, void *arg __unused)
{

	*out = g_passkey;
	return (0);
}

static int
cb_numcmp_accept(uint32_t v __unused, void *arg __unused)
{

	return (0);
}

static void
setup(struct smp_conn *sc, struct smp_bond_db *db, int bond_fd,
    int smp_fds[2], int hci_fds[2],
    const uint8_t *local, uint8_t ltype,
    const uint8_t *remote, uint8_t rtype, uint8_t io)
{

	signal(SIGPIPE, SIG_IGN);
	/* Exercise the enabled side of production SMP log guards; peer protocol
	 * assertions below remain independent of diagnostic output. */
	atomic_store(&blued_verbose, 2);
	/* Pairing runs in both foreground and daemonized services.  The scenario
	 * harness keeps the foreground route; this deep matrix covers syslog. */
	blued_daemonized = 1;
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
	sc->io_capability = io;
	sc->min_key_size = 16;
	sc->passkey_cb = cb_passkey;
	sc->numcmp_cb = cb_numcmp_accept;
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
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "mock peer exited with status %d", status);
}

static void
psend(int fd, const void *buf, size_t len)
{

	(void)send(fd, buf, len, MSG_EOR);
	usleep(6000);
}

/* ---- independent mock-peer cryptographic helpers ---- */
static void
ref_reverse(uint8_t *dst, const uint8_t *src, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		dst[i] = src[len - 1 - i];
}

/* RFC 4493 AES-CMAC through OpenSSL's one-shot provider interface. */
static int
ref_cmac(const uint8_t key[BTDS_SC_VALUE_LEN], const uint8_t *msg,
    size_t len, uint8_t out[BTDS_SC_VALUE_LEN])
{
	size_t outlen;

	outlen = 0;
	if (EVP_Q_mac(NULL, "CMAC", NULL, "AES-128-CBC", NULL, key,
	    BTDS_SC_VALUE_LEN, msg, len, out, BTDS_SC_VALUE_LEN,
	    &outlen) == NULL || outlen != BTDS_SC_VALUE_LEN)
		return (-1);
	return (0);
}

/* Core 6.3 Vol 3 Part H §2.2.6: f4(U,V,X,Z). */
static int
ref_f4(const uint8_t u[32], const uint8_t v[32],
    const uint8_t x[BTDS_SC_VALUE_LEN], uint8_t z,
    uint8_t out[BTDS_SC_VALUE_LEN])
{
	uint8_t key[BTDS_SC_VALUE_LEN], msg[65], mac[BTDS_SC_VALUE_LEN];

	ref_reverse(msg, u, 32);
	ref_reverse(msg + 32, v, 32);
	msg[64] = z;
	ref_reverse(key, x, sizeof(key));
	if (ref_cmac(key, msg, sizeof(msg), mac) != 0)
		return (-1);
	ref_reverse(out, mac, BTDS_SC_VALUE_LEN);
	return (0);
}

/* Core 6.3 Vol 3 Part H §2.2.7: f5(W,N1,N2,A1,A2). */
static int
ref_f5(const uint8_t w[32], const uint8_t n1[BTDS_SC_VALUE_LEN],
    const uint8_t n2[BTDS_SC_VALUE_LEN], const uint8_t a1[7],
    const uint8_t a2[7], uint8_t mackey[BTDS_SC_VALUE_LEN],
    uint8_t ltk[BTDS_SC_VALUE_LEN])
{
	static const uint8_t salt[BTDS_SC_VALUE_LEN] = {
		0x6c, 0x88, 0x83, 0x91, 0xaa, 0xf5, 0xa5, 0x38,
		0x60, 0x37, 0x0b, 0xdb, 0x5a, 0x60, 0x83, 0xbe
	};
	static const uint8_t key_id[] = { 0x62, 0x74, 0x6c, 0x65 };
	uint8_t w_be[32], t[BTDS_SC_VALUE_LEN], msg[53];
	uint8_t mac[BTDS_SC_VALUE_LEN];

	ref_reverse(w_be, w, sizeof(w_be));
	if (ref_cmac(salt, w_be, sizeof(w_be), t) != 0)
		return (-1);
	msg[0] = 0;
	memcpy(msg + 1, key_id, sizeof(key_id));
	ref_reverse(msg + 5, n1, BTDS_SC_VALUE_LEN);
	ref_reverse(msg + 21, n2, BTDS_SC_VALUE_LEN);
	ref_reverse(msg + 37, a1, 7);
	ref_reverse(msg + 44, a2, 7);
	msg[51] = 0x01;
	msg[52] = 0x00;
	if (ref_cmac(t, msg, sizeof(msg), mac) != 0)
		return (-1);
	ref_reverse(mackey, mac, BTDS_SC_VALUE_LEN);
	msg[0] = 1;
	if (ref_cmac(t, msg, sizeof(msg), mac) != 0)
		return (-1);
	ref_reverse(ltk, mac, BTDS_SC_VALUE_LEN);
	return (0);
}

/* Core 6.3 Vol 3 Part H §2.2.8: f6(W,N1,N2,R,IOcap,A1,A2). */
static int
ref_f6(const uint8_t w[BTDS_SC_VALUE_LEN],
    const uint8_t n1[BTDS_SC_VALUE_LEN],
    const uint8_t n2[BTDS_SC_VALUE_LEN],
    const uint8_t r[BTDS_SC_VALUE_LEN], const uint8_t iocap[3],
    const uint8_t a1[7], const uint8_t a2[7],
    uint8_t out[BTDS_SC_VALUE_LEN])
{
	uint8_t key[BTDS_SC_VALUE_LEN], msg[65], mac[BTDS_SC_VALUE_LEN];

	ref_reverse(key, w, BTDS_SC_VALUE_LEN);
	ref_reverse(msg, n1, BTDS_SC_VALUE_LEN);
	ref_reverse(msg + 16, n2, BTDS_SC_VALUE_LEN);
	ref_reverse(msg + 32, r, BTDS_SC_VALUE_LEN);
	ref_reverse(msg + 48, iocap, 3);
	ref_reverse(msg + 51, a1, 7);
	ref_reverse(msg + 58, a2, 7);
	if (ref_cmac(key, msg, sizeof(msg), mac) != 0)
		return (-1);
	ref_reverse(out, mac, BTDS_SC_VALUE_LEN);
	return (0);
}

/* Parse a published most-significant-octet-first hex string into wire LE. */
static int
ref_hex_le(const char *hex, uint8_t *out, size_t len)
{
	size_t i;
	unsigned int value;

	if (strlen(hex) != len * 2)
		return (-1);
	for (i = 0; i < len; i++) {
		if (sscanf(hex + i * 2, "%2x", &value) != 1)
			return (-1);
		out[len - 1 - i] = (uint8_t)value;
	}
	return (0);
}

/* ---- mock-peer ECDH helpers ---- */
static int
peer_keygen(EVP_PKEY **pkey, uint8_t pk_raw[BTDS_P256_UNCOMPRESSED_LEN])
{
	EVP_PKEY_CTX *pctx;
	size_t pklen = BTDS_P256_UNCOMPRESSED_LEN;

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
	    pk_raw, BTDS_P256_UNCOMPRESSED_LEN, &pklen) <= 0)
		return (-1);
	return (0);
}

static int
peer_dh(EVP_PKEY *our_key,
    const uint8_t peer_pk_raw[BTDS_P256_UNCOMPRESSED_LEN],
    uint8_t dhkey_le[BTDS_P256_COORD_LEN])
{
	EVP_PKEY *pk = NULL;
	EVP_PKEY_CTX *fctx, *dctx;
	OSSL_PARAM params[3];
	uint8_t dhkey_be[BTDS_P256_COORD_LEN];
	size_t dh_len = BTDS_P256_COORD_LEN;
	static char curve[] = "prime256v1";

	params[0] = OSSL_PARAM_construct_utf8_string(
	    OSSL_PKEY_PARAM_GROUP_NAME, curve, 0);
	params[1] = OSSL_PARAM_construct_octet_string(
	    OSSL_PKEY_PARAM_PUB_KEY, (void *)(uintptr_t)peer_pk_raw,
	    BTDS_P256_UNCOMPRESSED_LEN);
	params[2] = OSSL_PARAM_construct_end();
	fctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	EVP_PKEY_fromdata_init(fctx);
	EVP_PKEY_fromdata(fctx, &pk, EVP_PKEY_PUBLIC_KEY, params);
	EVP_PKEY_CTX_free(fctx);
	if (pk == NULL)
		return (-1);
	dctx = EVP_PKEY_CTX_new(our_key, NULL);
	EVP_PKEY_derive_init(dctx);
	EVP_PKEY_derive_set_peer(dctx, pk);
	if (EVP_PKEY_derive(dctx, dhkey_be, &dh_len) <= 0) {
		EVP_PKEY_CTX_free(dctx);
		EVP_PKEY_free(pk);
		return (-1);
	}
	EVP_PKEY_CTX_free(dctx);
	EVP_PKEY_free(pk);
	ref_reverse(dhkey_le, dhkey_be, BTDS_P256_COORD_LEN);
	return (0);
}

static void
pack_addr(uint8_t out[7], const uint8_t addr[6], uint8_t t)
{

	memcpy(out, addr, 6);
	out[6] = t == BDADDR_LE_RANDOM ? BTDS_ID_ADDR_STATIC_RANDOM :
	    BTDS_ID_ADDR_PUBLIC;
}

/* Send the initiator's distributed identity keys to the DUT, paced. */
static void
peer_send_id(int fd, const uint8_t *idaddr, uint8_t idtype)
{
	uint8_t pdu[BTDS_IDENTITY_INFO_PDU_LEN];

	pdu[0] = BTDS_SMP_IDENTITY_INFORMATION;
	memset(pdu + 1, 0x77, BTDS_SC_VALUE_LEN);
	psend(fd, pdu, BTDS_IDENTITY_INFO_PDU_LEN);
	pdu[0] = BTDS_SMP_IDENTITY_ADDRESS_INFO;
	pdu[1] = idtype == BDADDR_LE_RANDOM ? BTDS_ID_ADDR_STATIC_RANDOM :
	    BTDS_ID_ADDR_PUBLIC;
	memcpy(pdu + 2, idaddr, 6);
	psend(fd, pdu, 8);
}

/*
 * Core 6.3 Vol 3 Part H §§3.6.4-3.6.5, Figures 3.14-3.15:
 * IdKey distribution is IRK first, then identity address information.
 */
static int
peer_recv_id(int fd, const uint8_t expected_addr[6], uint8_t addr_type)
{
	uint8_t pdu[BTDS_IDENTITY_INFO_PDU_LEN];
	struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
	ssize_t n;
	uint8_t expected_type;

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	n = recv(fd, pdu, sizeof(pdu), 0);
	if (n != BTDS_IDENTITY_INFO_PDU_LEN ||
	    pdu[0] != BTDS_SMP_IDENTITY_INFORMATION)
		return (-1);
	n = recv(fd, pdu, sizeof(pdu), 0);
	expected_type = addr_type == BDADDR_LE_RANDOM ?
	    BTDS_ID_ADDR_STATIC_RANDOM : BTDS_ID_ADDR_PUBLIC;
	if (n != BTDS_IDENTITY_ADDR_PDU_LEN ||
	    pdu[0] != BTDS_SMP_IDENTITY_ADDRESS_INFO ||
	    pdu[1] != expected_type ||
	    memcmp(pdu + 2, expected_addr, 6) != 0)
		return (-1);
	return (0);
}

/*
 * Validate the test-only peer crypto before it is used as an oracle.  These
 * are the published Core 6.3 Vol 3 Part H Appendix D.2-D.4 vectors, supplied
 * by the generated Core oracle header rather than by production code.
 */
ATF_TC_WITHOUT_HEAD(reference_crypto_kat);
ATF_TC_BODY(reference_crypto_kat, tc)
{
	uint8_t u[32], v[32], x[16], f4_expected[16], f4_out[16];
	uint8_t dhkey[32], n1[16], n2[16], a1[7], a2[7];
	uint8_t mackey_expected[16], ltk_expected[16];
	uint8_t mackey[16], ltk[16], r[16], iocap[3];
	uint8_t f6_expected[16], f6_out[16];

	ATF_REQUIRE_EQ(0, ref_hex_le(BT_CORE63_SMP_D2_U_HEX, u, sizeof(u)));
	ATF_REQUIRE_EQ(0, ref_hex_le(BT_CORE63_SMP_D2_V_HEX, v, sizeof(v)));
	ATF_REQUIRE_EQ(0, ref_hex_le(BT_CORE63_SMP_D2_X_HEX, x, sizeof(x)));
	ATF_REQUIRE_EQ(0, ref_hex_le(BT_CORE63_SMP_D2_OUT_HEX, f4_expected,
	    sizeof(f4_expected)));
	ATF_REQUIRE_EQ(0, ref_f4(u, v, x, BT_CORE63_SMP_D2_Z, f4_out));
	ATF_CHECK_EQ(0, memcmp(f4_out, f4_expected, sizeof(f4_out)));

	ATF_REQUIRE_EQ(0, ref_hex_le(BT_CORE63_SMP_D3_DHKEY_HEX, dhkey,
	    sizeof(dhkey)));
	ATF_REQUIRE_EQ(0, ref_hex_le(BT_CORE63_SMP_D3_N1_HEX, n1, sizeof(n1)));
	ATF_REQUIRE_EQ(0, ref_hex_le(BT_CORE63_SMP_D3_N2_HEX, n2, sizeof(n2)));
	ATF_REQUIRE_EQ(0, ref_hex_le(BT_CORE63_SMP_D3_A1_HEX, a1, sizeof(a1)));
	ATF_REQUIRE_EQ(0, ref_hex_le(BT_CORE63_SMP_D3_A2_HEX, a2, sizeof(a2)));
	ATF_REQUIRE_EQ(0, ref_hex_le(BT_CORE63_SMP_D3_MACKEY_HEX,
	    mackey_expected, sizeof(mackey_expected)));
	ATF_REQUIRE_EQ(0, ref_hex_le(BT_CORE63_SMP_D3_LTK_HEX, ltk_expected,
	    sizeof(ltk_expected)));
	ATF_REQUIRE_EQ(0, ref_f5(dhkey, n1, n2, a1, a2, mackey, ltk));
	ATF_CHECK_EQ(0, memcmp(mackey, mackey_expected, sizeof(mackey)));
	ATF_CHECK_EQ(0, memcmp(ltk, ltk_expected, sizeof(ltk)));

	ATF_REQUIRE_EQ(0, ref_hex_le(BT_CORE63_SMP_D4_R_HEX, r, sizeof(r)));
	ATF_REQUIRE_EQ(0, ref_hex_le(BT_CORE63_SMP_D4_IOCAP_HEX, iocap,
	    sizeof(iocap)));
	ATF_REQUIRE_EQ(0, ref_hex_le(BT_CORE63_SMP_D4_OUT_HEX, f6_expected,
	    sizeof(f6_expected)));
	ATF_REQUIRE_EQ(0, ref_f6(mackey, n1, n2, r, iocap, a1, a2, f6_out));
	ATF_CHECK_EQ(0, memcmp(f6_out, f6_expected, sizeof(f6_out)));
}

/* ================================================================
 * RESPONDER-side full flows: DUT runs smp_respond(); peer is the SC
 * initiator.  auth carries MITM/CT2 as needed; init_io drives model.
 * ================================================================ */
static void
run_respond_sc(int model_hint, uint8_t dut_io, uint8_t peer_io,
    uint8_t auth, uint8_t ltype, uint8_t rtype)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_deep_rsc.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	/* DUT responder: local=periph, remote=central. */
	setup(&sc, &db, bond_fd, smp_fds, hci_fds,
	    periph_addr, ltype, central_addr, rtype, dut_io);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd = smp_fds[1];
		uint8_t preq[BTDS_PAIRING_FEATURE_PDU_LEN], pres[BTDS_PAIRING_FEATURE_PDU_LEN], pdu[66];
		EVP_PKEY *ok = NULL;
		uint8_t opk[65], ppk_be[65];
		uint8_t pka_le[32], pkb_le[32], dh[32];
		uint8_t na[16], nb[16], mackey[16], ltk[16];
		uint8_t ea[16], eb[16], a1[7], a2[7];
		uint8_t iocap_a[3], iocap_b[3], r[16];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		{
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		}
		if (peer_keygen(&ok, opk) != 0)
			_exit(1);

		/* Core 6.3 Part H §3.6.1: offer IdKey + LinkKey for SC. */
		preq[0] = BTDS_SMP_PAIRING_REQUEST;
		preq[1] = peer_io;
		preq[2] = BTDS_OOB_NOT_PRESENT;
		preq[3] = auth;
		preq[4] = BTDS_MAX_ENCRYPTION_KEY_SIZE;
		preq[5] = BTDS_SMP_KEY_DIST_ID_KEY | BTDS_SMP_KEY_DIST_LINK_KEY;
		preq[6] = BTDS_SMP_KEY_DIST_ID_KEY | BTDS_SMP_KEY_DIST_LINK_KEY;
		if (send(fd, preq, BTDS_PAIRING_FEATURE_PDU_LEN, MSG_EOR) != BTDS_PAIRING_FEATURE_PDU_LEN) { EVP_PKEY_free(ok); _exit(2); }
		n = recv(fd, pres, BTDS_PAIRING_FEATURE_PDU_LEN, 0);
		if (n < BTDS_PAIRING_FEATURE_PDU_LEN || pres[0] != BTDS_SMP_PAIRING_RESPONSE) {
			EVP_PKEY_free(ok); _exit(3);
		}

		/* PK exchange: initiator sends first. */
		pdu[0] = BTDS_SMP_PAIRING_PUBLIC_KEY;
		ref_reverse(pdu + 1, opk + 1, 32);
		ref_reverse(pdu + 33, opk + 33, 32);
		memcpy(pka_le, pdu + 1, 32);
		if (send(fd, pdu, BTDS_PUBLIC_KEY_PDU_LEN, MSG_EOR) < 0) { EVP_PKEY_free(ok); _exit(4); }
		n = recv(fd, pdu, BTDS_PUBLIC_KEY_PDU_LEN, 0);
		if (n < BTDS_PUBLIC_KEY_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_PUBLIC_KEY) {
			EVP_PKEY_free(ok); _exit(5);
		}
		ppk_be[0] = 0x04;
		ref_reverse(ppk_be + 1, pdu + 1, 32);
		ref_reverse(ppk_be + 33, pdu + 33, 32);
		memcpy(pkb_le, pdu + 1, 32);
		if (peer_dh(ok, ppk_be, dh) != 0) { EVP_PKEY_free(ok); _exit(6); }
		EVP_PKEY_free(ok);

		iocap_a[0] = preq[1]; iocap_a[1] = preq[2]; iocap_a[2] = preq[3];
		iocap_b[0] = pres[1]; iocap_b[1] = pres[2]; iocap_b[2] = pres[3];
		pack_addr(a1, central_addr, rtype);	/* initiator */
		pack_addr(a2, periph_addr, ltype);	/* responder */

		if (model_hint == SMP_MODEL_PASSKEY_ENTRY) {
			int i;
			uint8_t nai[16], nbi[16], cbi_recv[16], cai[16], cai_v[16];
			uint8_t ri;

			for (i = 0; i < 20; i++) {
				ri = BTDS_F4_PASSKEY_Z_BASE | ((g_passkey >> i) & 1);
				arc4random_buf(nai, 16);
				ref_f4(pka_le, pkb_le, nai, ri, cai);
				/* send Cai */
				pdu[0] = BTDS_SMP_PAIRING_CONFIRM;
				memcpy(pdu + 1, cai, 16);
				if (send(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, MSG_EOR) < 0) _exit(10);
				/* recv Cbi */
				n = recv(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, 0);
				if (n < BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_CONFIRM)
					_exit(11);
				memcpy(cbi_recv, pdu + 1, 16);
				/* send Nai */
				pdu[0] = BTDS_SMP_PAIRING_RANDOM;
				memcpy(pdu + 1, nai, 16);
				if (send(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, MSG_EOR) < 0) _exit(12);
				/* recv Nbi */
				n = recv(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, 0);
				if (n < BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_RANDOM)
					_exit(13);
				memcpy(nbi, pdu + 1, 16);
				/* verify Cbi = f4(pkb,pka,Nbi,ri) */
				ref_f4(pkb_le, pka_le, nbi, ri, cai_v);
				if (memcmp(cbi_recv, cai_v, 16) != 0)
					_exit(14);
				memcpy(na, nai, 16);
				memcpy(nb, nbi, 16);
			}
			memset(r, 0, sizeof(r));
			r[0] = g_passkey & 0xFF;
			r[1] = (g_passkey >> 8) & 0xFF;
			r[2] = (g_passkey >> 16) & 0xFF;
			ref_f5(dh, na, nb, a1, a2, mackey, ltk);
			ref_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
			ref_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);
			/* send Ea */
			pdu[0] = BTDS_SMP_PAIRING_DHKEY_CHECK;
			memcpy(pdu + 1, ea, 16);
			if (send(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, MSG_EOR) < 0) _exit(15);
			/* recv Eb */
			n = recv(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, 0);
			if (n < BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_DHKEY_CHECK)
				_exit(16);
			if (memcmp(pdu + 1, eb, 16) != 0) _exit(17);
		} else {
			uint8_t cb_recv[16], cb_v[16];

			/* recv Cb */
			n = recv(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, 0);
			if (n < BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_CONFIRM) _exit(20);
			memcpy(cb_recv, pdu + 1, 16);
			/* send Na */
			arc4random_buf(na, 16);
			pdu[0] = BTDS_SMP_PAIRING_RANDOM;
			memcpy(pdu + 1, na, 16);
			if (send(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, MSG_EOR) < 0) _exit(21);
			/* recv Nb */
			n = recv(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, 0);
			if (n < BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_RANDOM) _exit(22);
			memcpy(nb, pdu + 1, 16);
			ref_f4(pkb_le, pka_le, nb, 0, cb_v);
			if (memcmp(cb_recv, cb_v, 16) != 0) _exit(23);
			memset(r, 0, sizeof(r));
			ref_f5(dh, na, nb, a1, a2, mackey, ltk);
			ref_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
			ref_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);
			/* send Ea */
			pdu[0] = BTDS_SMP_PAIRING_DHKEY_CHECK;
			memcpy(pdu + 1, ea, 16);
			if (send(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, MSG_EOR) < 0) _exit(24);
			/* recv Eb */
			n = recv(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, 0);
			if (n < BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_DHKEY_CHECK) _exit(25);
			if (memcmp(pdu + 1, eb, 16) != 0) _exit(26);
		}

		/* Responder distributes its IdKey PDUs; LinkKey has no PDU. */
		if (peer_recv_id(fd, periph_addr, ltype) != 0)
			_exit(27);
		/* Then send our two initiator IdKey PDUs. */
		peer_send_id(fd, central_addr, rtype);

		close(fd);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_respond(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "responder SC must succeed (errno=%d)", errno);
	ATF_CHECK_MSG(db.count > 0, "responder must store a bond");
	if (db.count > 0) {
		ATF_CHECK(db.bonds[0].has_ltk);
		ATF_CHECK(db.bonds[0].is_sc);
		if (model_hint != SMP_MODEL_JUST_WORKS)
			ATF_CHECK_MSG(db.bonds[0].is_mitm,
			    "MITM model must mark bond authenticated");
	}
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

ATF_TC_WITHOUT_HEAD(test_respond_sc_jw_random_allkeys);
ATF_TC_BODY(test_respond_sc_jw_random_allkeys, tc)
{

	/* NoInputNoOutput both, no MITM -> Just Works.  CT2 set. Random addr. */
	run_respond_sc(SMP_MODEL_JUST_WORKS,
	    BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC | BTDS_SMP_AUTH_CT2,
	    BDADDR_LE_RANDOM, BDADDR_LE_RANDOM);
}

ATF_TC_WITHOUT_HEAD(test_respond_sc_numcmp_accept);
ATF_TC_BODY(test_respond_sc_numcmp_accept, tc)
{

	/* DisplayYesNo both, MITM -> Numeric Comparison.  CT2 set. */
	run_respond_sc(SMP_MODEL_NUMERIC_COMPARISON,
	    BTDS_SMP_IO_DISPLAY_YESNO, BTDS_SMP_IO_DISPLAY_YESNO,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC | BTDS_SMP_AUTH_MITM | BTDS_SMP_AUTH_CT2,
	    BDADDR_LE_PUBLIC, BDADDR_LE_PUBLIC);
}

ATF_TC_WITHOUT_HEAD(test_respond_sc_passkey_success);
ATF_TC_BODY(test_respond_sc_passkey_success, tc)
{

	/*
	 * DUT(responder)=KeyboardOnly, peer(initiator)=DisplayOnly, MITM.
	 * SC Table 2.8 I:DispOnly x R:KbdOnly -> Passkey Entry.  CT2 set.
	 */
	run_respond_sc(SMP_MODEL_PASSKEY_ENTRY,
	    BTDS_SMP_IO_KEYBOARD_ONLY, BTDS_SMP_IO_DISPLAY_ONLY,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC | BTDS_SMP_AUTH_MITM | BTDS_SMP_AUTH_CT2,
	    BDADDR_LE_PUBLIC, BDADDR_LE_PUBLIC);
}

/* ================================================================
 * INITIATOR-side full flows: DUT runs smp_pair(); peer is the SC
 * responder.  smp_pair offers EncKey+IdKey+LinkKey and CT2, so the peer
 * accepts IdKey+LinkKey and (for MITM models) selects the association model
 * via its IO capability.
 * ================================================================ */
static void
run_pair_sc_kp(int model_hint, uint8_t dut_io, uint8_t peer_io,
    uint8_t peer_auth, uint8_t ltype, uint8_t rtype, bool inject_keypress,
    bool hci_send_fail, bool hci_wait_fail)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_deep_isc.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	/* DUT initiator: local=central, remote=periph. */
	setup(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, ltype, periph_addr, rtype, dut_io);
	if (g_bond_store_fail) {
		/* A configured non-directory target deterministically fails the final
		 * atomic save after all authenticated SMP traffic has completed. */
		smp_bond_db_set_atomic(&db, STDIN_FILENO, "bonds");
	}

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd = smp_fds[1];
		uint8_t preq[BTDS_PAIRING_FEATURE_PDU_LEN], pres[BTDS_PAIRING_FEATURE_PDU_LEN], pdu[66];
		EVP_PKEY *ok = NULL;
		uint8_t opk[65], ppk_be[65];
		uint8_t pka_le[32], pkb_le[32], dh[32];
		uint8_t na[16], nb[16], mackey[16], ltk[16];
		uint8_t ea[16], eb[16], a1[7], a2[7];
		uint8_t iocap_a[3], iocap_b[3], r[16];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		{
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		}
		if (peer_keygen(&ok, opk) != 0)
			_exit(1);

		/* recv Pairing Request */
		n = recv(fd, preq, BTDS_PAIRING_FEATURE_PDU_LEN, 0);
		if (n < BTDS_PAIRING_FEATURE_PDU_LEN || preq[0] != BTDS_SMP_PAIRING_REQUEST) {
			EVP_PKEY_free(ok); _exit(2);
		}
		/* Pairing Response: accept IdKey+LinkKey, SC + requested auth. */
		pres[0] = BTDS_SMP_PAIRING_RESPONSE;
		pres[1] = peer_io;
		pres[2] = BTDS_OOB_NOT_PRESENT;
		pres[3] = peer_auth;
		pres[4] = BTDS_MAX_ENCRYPTION_KEY_SIZE;
		pres[5] = BTDS_SMP_KEY_DIST_ID_KEY | BTDS_SMP_KEY_DIST_LINK_KEY;
		pres[6] = BTDS_SMP_KEY_DIST_ID_KEY | BTDS_SMP_KEY_DIST_LINK_KEY;
		if (send(fd, pres, BTDS_PAIRING_FEATURE_PDU_LEN, MSG_EOR) != BTDS_PAIRING_FEATURE_PDU_LEN) { EVP_PKEY_free(ok); _exit(3); }

		/* PK exchange: initiator (DUT) sends first. */
		n = recv(fd, pdu, BTDS_PUBLIC_KEY_PDU_LEN, 0);
		if (n < BTDS_PUBLIC_KEY_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_PUBLIC_KEY) {
			EVP_PKEY_free(ok); _exit(4);
		}
		ppk_be[0] = 0x04;
		ref_reverse(ppk_be + 1, pdu + 1, 32);
		ref_reverse(ppk_be + 33, pdu + 33, 32);
		memcpy(pka_le, pdu + 1, 32);	/* initiator (DUT) x */
		/* send our PK */
		pdu[0] = BTDS_SMP_PAIRING_PUBLIC_KEY;
		ref_reverse(pdu + 1, opk + 1, 32);
		ref_reverse(pdu + 33, opk + 33, 32);
		memcpy(pkb_le, pdu + 1, 32);	/* responder (peer) x */
		if (send(fd, pdu, BTDS_PUBLIC_KEY_PDU_LEN, MSG_EOR) < 0) { EVP_PKEY_free(ok); _exit(5); }
		if (peer_dh(ok, ppk_be, dh) != 0) { EVP_PKEY_free(ok); _exit(6); }
		EVP_PKEY_free(ok);

		iocap_a[0] = preq[1]; iocap_a[1] = preq[2]; iocap_a[2] = preq[3];
		iocap_b[0] = pres[1]; iocap_b[1] = pres[2]; iocap_b[2] = pres[3];
		pack_addr(a1, central_addr, ltype);	/* initiator = DUT */
		pack_addr(a2, periph_addr, rtype);	/* responder = peer */

		if (model_hint == SMP_MODEL_PASSKEY_ENTRY) {
			int i;
			uint8_t nai[16], nbi[16], cai_recv[16], cbi[16], cai_v[16];
			uint8_t ri;

			for (i = 0; i < 20; i++) {
				ri = BTDS_F4_PASSKEY_Z_BASE | ((g_passkey >> i) & 1);
				arc4random_buf(nbi, 16);
				/* recv Cai */
				n = recv(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, 0);
				if (n < BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_CONFIRM)
					_exit(10);
				memcpy(cai_recv, pdu + 1, 16);
				/*
				 * Inject a spec-legal Keypress Notification
				 * (Vol 3 Part H §3.5.8) before the round-0
				 * confirm.  The DUT must consume it and still
				 * complete the exchange; pre-fix it read the
				 * keypress as the confirm and failed EPROTO.
				 */
				if (inject_keypress && i == 0) {
					uint8_t kp[BTDS_KEYPRESS_PDU_LEN] = {
					    BTDS_SMP_PAIRING_KEYPRESS_NOTIFY,
					    BTDS_KEYPRESS_STARTED };
					if (send(fd, kp, BTDS_KEYPRESS_PDU_LEN, MSG_EOR) < 0)
						_exit(30);
					usleep(4000);
				}
				/* send Cbi = f4(pkb,pka,nbi,ri) */
				ref_f4(pkb_le, pka_le, nbi, ri, cbi);
				pdu[0] = BTDS_SMP_PAIRING_CONFIRM;
				memcpy(pdu + 1, cbi, 16);
				if (send(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, MSG_EOR) < 0) _exit(11);
				/* recv Nai */
				n = recv(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, 0);
				if (n < BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_RANDOM)
					_exit(12);
				memcpy(nai, pdu + 1, 16);
				/* verify Cai = f4(pka,pkb,nai,ri) */
				ref_f4(pka_le, pkb_le, nai, ri, cai_v);
				if (memcmp(cai_recv, cai_v, 16) != 0) _exit(13);
				/* send Nbi */
				pdu[0] = BTDS_SMP_PAIRING_RANDOM;
				memcpy(pdu + 1, nbi, 16);
				if (send(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, MSG_EOR) < 0) _exit(14);
				memcpy(na, nai, 16);
				memcpy(nb, nbi, 16);
			}
			memset(r, 0, sizeof(r));
			r[0] = g_passkey & 0xFF;
			r[1] = (g_passkey >> 8) & 0xFF;
			r[2] = (g_passkey >> 16) & 0xFF;
			ref_f5(dh, na, nb, a1, a2, mackey, ltk);
			ref_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
			ref_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);
			/* recv Ea */
			n = recv(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, 0);
			if (n < BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_DHKEY_CHECK) _exit(15);
			if (memcmp(pdu + 1, ea, 16) != 0) _exit(16);
			/* send Eb */
			pdu[0] = BTDS_SMP_PAIRING_DHKEY_CHECK;
			memcpy(pdu + 1, eb, 16);
			if (send(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, MSG_EOR) < 0) _exit(17);
			if (hci_send_fail || hci_wait_fail)
				_exit(0);
		} else {
			uint8_t cb[16];

			/* responder sends Cb first */
			arc4random_buf(nb, 16);
			ref_f4(pkb_le, pka_le, nb, 0, cb);
			if (g_jw_bad_confirm)
				cb[0] ^= 0x01;
			pdu[0] = BTDS_SMP_PAIRING_CONFIRM;
			memcpy(pdu + 1, cb, 16);
			if (send(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, MSG_EOR) < 0) _exit(20);
			if (g_jw_bad_confirm) {
				n = recv(fd, pdu, sizeof(pdu), 0);
				if (n < BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_RANDOM)
					_exit(26);
				pdu[0] = BTDS_SMP_PAIRING_RANDOM;
				memcpy(pdu + 1, nb, 16);
				if (send(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, MSG_EOR) < 0)
					_exit(27);
				n = recv(fd, pdu, sizeof(pdu), 0);
				if (n < BTDS_PAIRING_FAILED_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_FAILED ||
				    pdu[1] != BTDS_SMP_ERR_CONFIRM_VALUE_FAILED)
					_exit(28);
				close(fd);
				_exit(0);
			}
			/* recv Na */
			n = recv(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, 0);
			if (n < BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_RANDOM) _exit(21);
			memcpy(na, pdu + 1, 16);
			if (g_jw_abort_random) {
				pdu[0] = BTDS_SMP_PAIRING_FAILED;
				pdu[1] = BTDS_SMP_ERR_UNSPECIFIED_REASON;
				if (send(fd, pdu, BTDS_PAIRING_FAILED_PDU_LEN, MSG_EOR) < 0)
					_exit(29);
				close(fd);
				_exit(0);
			}
			/* send Nb */
			pdu[0] = BTDS_SMP_PAIRING_RANDOM;
			memcpy(pdu + 1, nb, 16);
			if (send(fd, pdu, g_jw_truncated_random ? BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN - 1 : BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN,
			    MSG_EOR) < 0)
				_exit(22);
			if (g_jw_truncated_random) {
				n = recv(fd, pdu, sizeof(pdu), 0);
				if (n != BTDS_PAIRING_FAILED_PDU_LEN ||
				    pdu[0] != BTDS_SMP_PAIRING_FAILED ||
				    pdu[1] != BTDS_SMP_ERR_INVALID_PARAMETERS)
					_exit(33);
				close(fd);
				_exit(0);
			}
			memset(r, 0, sizeof(r));
			ref_f5(dh, na, nb, a1, a2, mackey, ltk);
			ref_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
			ref_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);
			/* recv Ea */
			n = recv(fd, pdu, BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN, 0);
			if (n < BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_DHKEY_CHECK) _exit(23);
			if (memcmp(pdu + 1, ea, 16) != 0) _exit(24);
			/* send Eb */
			pdu[0] = BTDS_SMP_PAIRING_DHKEY_CHECK;
			memcpy(pdu + 1, eb, 16);
			if (g_jw_bad_dhkey)
				pdu[1] ^= 0x01;
			if (send(fd, pdu, g_jw_truncated_dhkey ? BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN - 1 : BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN,
			    MSG_EOR) < 0)
				_exit(25);
			if (g_jw_truncated_dhkey) {
				n = recv(fd, pdu, sizeof(pdu), 0);
				if (n != BTDS_PAIRING_FAILED_PDU_LEN ||
				    pdu[0] != BTDS_SMP_PAIRING_FAILED ||
				    pdu[1] != BTDS_SMP_ERR_INVALID_PARAMETERS)
					_exit(34);
			}
			if (g_jw_bad_dhkey) {
				n = recv(fd, pdu, sizeof(pdu), 0);
				if (n < BTDS_PAIRING_FAILED_PDU_LEN || pdu[0] != BTDS_SMP_PAIRING_FAILED ||
				    pdu[1] != BTDS_SMP_ERR_DHKEY_CHECK_FAILED)
					_exit(31);
				close(fd);
				_exit(0);
			}
			if (g_jw_truncated_dhkey) {
				close(fd);
				_exit(0);
			}
			if (hci_send_fail || hci_wait_fail)
				_exit(0);
		}

		/*
		 * Initiator receives peer keys first, then distributes.
		 * Send our responder IdKey PDUs, then drain the DUT's IdKey PDUs.
		 * LinkKey is locally derived and has no SMP key-distribution PDU.
		 */
		peer_send_id(fd, periph_addr, rtype);
		if (g_bond_store_fail)
			_exit(0);
		if (peer_recv_id(fd, central_addr, ltype) != 0)
			_exit(32);

		close(fd);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);

	g_hci_send_fail = hci_send_fail;
	g_hci_wait_fail = hci_wait_fail;
	int ret = smp_pair(&sc);
	g_hci_send_fail = 0;
	g_hci_wait_fail = 0;
	ATF_CHECK_EQ_MSG(ret,
	    (hci_send_fail || hci_wait_fail || g_bond_store_fail ||
	    g_jw_bad_confirm || g_jw_abort_random || g_jw_bad_dhkey ||
	    g_jw_truncated_dhkey || g_jw_truncated_random) ? -1 : 0,
	    "initiator SC result mismatch (errno=%d)", errno);
	ATF_CHECK_MSG((hci_send_fail || hci_wait_fail || g_bond_store_fail ||
	    g_jw_bad_confirm || g_jw_abort_random || g_jw_bad_dhkey ||
	    g_jw_truncated_dhkey || g_jw_truncated_random) ||
	    db.count > 0,
	    "successful initiator pairing must store a bond");
	if (!hci_send_fail && !hci_wait_fail && !g_bond_store_fail &&
	    !g_jw_bad_confirm && !g_jw_abort_random && !g_jw_bad_dhkey &&
	    !g_jw_truncated_dhkey && !g_jw_truncated_random &&
	    db.count > 0) {
		ATF_CHECK(db.bonds[0].has_ltk);
		ATF_CHECK(db.bonds[0].is_sc);
		ATF_CHECK(db.bonds[0].has_irk);
		ATF_CHECK(!db.bonds[0].has_csrk);
		if (model_hint != SMP_MODEL_JUST_WORKS)
			ATF_CHECK(db.bonds[0].has_link_key);
	}
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

/* Convenience wrapper for scenarios without Keypress Notification injection. */
static void
run_pair_sc(int model_hint, uint8_t dut_io, uint8_t peer_io, uint8_t peer_auth,
    uint8_t ltype, uint8_t rtype)
{

	run_pair_sc_kp(model_hint, dut_io, peer_io, peer_auth, ltype, rtype,
	    false, false, false);
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_jw_random_allkeys);
ATF_TC_BODY(test_pair_sc_jw_random_allkeys, tc)
{

	run_pair_sc(SMP_MODEL_JUST_WORKS,
	    BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC | BTDS_SMP_AUTH_CT2,
	    BDADDR_LE_RANDOM, BDADDR_LE_RANDOM);
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_numcmp_success);
ATF_TC_BODY(test_pair_sc_numcmp_success, tc)
{

	run_pair_sc(SMP_MODEL_NUMERIC_COMPARISON,
	    BTDS_SMP_IO_DISPLAY_YESNO, BTDS_SMP_IO_DISPLAY_YESNO,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC | BTDS_SMP_AUTH_MITM | BTDS_SMP_AUTH_CT2,
	    BDADDR_LE_PUBLIC, BDADDR_LE_PUBLIC);
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_passkey_success);
ATF_TC_BODY(test_pair_sc_passkey_success, tc)
{

	/*
	 * DUT(initiator)=KeyboardOnly, peer(responder)=DisplayOnly, MITM.
	 * SC Table 2.8 I:KbdOnly x R:DispOnly -> Passkey Entry.
	 */
	run_pair_sc(SMP_MODEL_PASSKEY_ENTRY,
	    BTDS_SMP_IO_KEYBOARD_ONLY, BTDS_SMP_IO_DISPLAY_ONLY,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC | BTDS_SMP_AUTH_MITM | BTDS_SMP_AUTH_CT2,
	    BDADDR_LE_PUBLIC, BDADDR_LE_PUBLIC);
}

/*
 * SC Passkey Entry with a Keypress Notification injected mid-exchange.
 *
 * Core Spec Vol 3 Part H §3.5.8: Keypress Notifications may arrive during
 * the passkey authentication stage and are informational.  The SC passkey
 * confirm/nonce receives must consume them (as the legacy path does) rather
 * than reject them as out-of-sequence.  Pre-fix the round confirm receive
 * used a plain recv and failed EPROTO on the injected keypress.
 */
ATF_TC_WITHOUT_HEAD(test_pair_sc_passkey_keypress);
ATF_TC_BODY(test_pair_sc_passkey_keypress, tc)
{

	run_pair_sc_kp(SMP_MODEL_PASSKEY_ENTRY,
	    BTDS_SMP_IO_KEYBOARD_ONLY, BTDS_SMP_IO_DISPLAY_ONLY,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC | BTDS_SMP_AUTH_MITM |
	    BTDS_SMP_AUTH_KEYPRESS | BTDS_SMP_AUTH_CT2,
	    BDADDR_LE_PUBLIC, BDADDR_LE_PUBLIC, true, false, false);
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_jw_start_encryption_failure);
ATF_TC_BODY(test_pair_sc_jw_start_encryption_failure, tc)
{

	run_pair_sc_kp(SMP_MODEL_JUST_WORKS,
	    BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC,
	    BDADDR_LE_PUBLIC, BDADDR_LE_PUBLIC, false, true, false);
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_jw_wait_encryption_failure);
ATF_TC_BODY(test_pair_sc_jw_wait_encryption_failure, tc)
{

	run_pair_sc_kp(SMP_MODEL_JUST_WORKS,
	    BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC,
	    BDADDR_LE_PUBLIC, BDADDR_LE_PUBLIC, false, false, true);
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_jw_bond_store_failure);
ATF_TC_BODY(test_pair_sc_jw_bond_store_failure, tc)
{

	g_bond_store_fail = 1;
	run_pair_sc(SMP_MODEL_JUST_WORKS,
	    BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC,
	    BDADDR_LE_PUBLIC, BDADDR_LE_PUBLIC);
	g_bond_store_fail = 0;
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_jw_confirm_mismatch);
ATF_TC_BODY(test_pair_sc_jw_confirm_mismatch, tc)
{

	g_jw_bad_confirm = 1;
	run_pair_sc(SMP_MODEL_JUST_WORKS,
	    BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC,
	    BDADDR_LE_PUBLIC, BDADDR_LE_PUBLIC);
	g_jw_bad_confirm = 0;
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_jw_peer_abort_at_random);
ATF_TC_BODY(test_pair_sc_jw_peer_abort_at_random, tc)
{

	g_jw_abort_random = 1;
	run_pair_sc(SMP_MODEL_JUST_WORKS,
	    BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC,
	    BDADDR_LE_PUBLIC, BDADDR_LE_PUBLIC);
	g_jw_abort_random = 0;
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_jw_dhkey_mismatch);
ATF_TC_BODY(test_pair_sc_jw_dhkey_mismatch, tc)
{

	g_jw_bad_dhkey = 1;
	run_pair_sc(SMP_MODEL_JUST_WORKS,
	    BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC,
	    BDADDR_LE_PUBLIC, BDADDR_LE_PUBLIC);
	g_jw_bad_dhkey = 0;
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_jw_truncated_dhkey);
ATF_TC_BODY(test_pair_sc_jw_truncated_dhkey, tc)
{

	g_jw_truncated_dhkey = 1;
	run_pair_sc(SMP_MODEL_JUST_WORKS,
	    BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC,
	    BDADDR_LE_PUBLIC, BDADDR_LE_PUBLIC);
	g_jw_truncated_dhkey = 0;
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_jw_truncated_random);
ATF_TC_BODY(test_pair_sc_jw_truncated_random, tc)
{

	g_jw_truncated_random = 1;
	run_pair_sc(SMP_MODEL_JUST_WORKS,
	    BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC,
	    BDADDR_LE_PUBLIC, BDADDR_LE_PUBLIC);
	g_jw_truncated_random = 0;
}

/* A peer may disappear immediately after feature exchange.  The SC passkey
 * initiator must surface failure of its mandatory Public Key transmission
 * rather than proceeding into the confirmation rounds. */
ATF_TC_WITHOUT_HEAD(test_pair_sc_passkey_public_key_send_failure);
ATF_TC_BODY(test_pair_sc_passkey_public_key_send_failure, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_REQUEST, BTDS_SMP_IO_KEYBOARD_ONLY, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC | BTDS_SMP_AUTH_MITM, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };
	uint8_t pres[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_RESPONSE, BTDS_SMP_IO_DISPLAY_ONLY, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC | BTDS_SMP_AUTH_MITM, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC, BTDS_SMP_IO_KEYBOARD_ONLY);
	close(smp_fds[1]);
	close(hci_fds[1]);
	ATF_CHECK_EQ(smp_pair_sc_passkey(&sc, preq, pres), -1);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

/* A peer-issued Pairing Failed while awaiting its public key is already a
 * terminal decision.  Propagate it as EACCES without manufacturing another
 * protocol response. */
ATF_TC_WITHOUT_HEAD(test_pair_sc_passkey_peer_aborts_public_key);
ATF_TC_BODY(test_pair_sc_passkey_peer_aborts_public_key, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;
	uint8_t preq[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_REQUEST, BTDS_SMP_IO_KEYBOARD_ONLY, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC | BTDS_SMP_AUTH_MITM, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };
	uint8_t pres[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_RESPONSE, BTDS_SMP_IO_DISPLAY_ONLY, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC | BTDS_SMP_AUTH_MITM, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC, BTDS_SMP_IO_KEYBOARD_ONLY);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		uint8_t pdu[BTDS_PUBLIC_KEY_PDU_LEN];

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		if (recv(smp_fds[1], pdu, sizeof(pdu), 0) != BTDS_PUBLIC_KEY_PDU_LEN ||
		    pdu[0] != BTDS_SMP_PAIRING_PUBLIC_KEY)
			_exit(1);
		pdu[0] = BTDS_SMP_PAIRING_FAILED;
		pdu[1] = BTDS_SMP_ERR_UNSPECIFIED_REASON;
		if (send(smp_fds[1], pdu, BTDS_PAIRING_FAILED_PDU_LEN, MSG_EOR) != BTDS_PAIRING_FAILED_PDU_LEN)
			_exit(2);
		close(smp_fds[1]);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	ATF_CHECK_EQ(smp_pair_sc_passkey(&sc, preq, pres), -1);
	ATF_CHECK_EQ(errno, EACCES);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_passkey_invalid_public_key);
ATF_TC_BODY(test_pair_sc_passkey_invalid_public_key, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;
	uint8_t preq[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_REQUEST, BTDS_SMP_IO_KEYBOARD_ONLY, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC | BTDS_SMP_AUTH_MITM, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };
	uint8_t pres[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_RESPONSE, BTDS_SMP_IO_DISPLAY_ONLY, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC | BTDS_SMP_AUTH_MITM, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC, BTDS_SMP_IO_KEYBOARD_ONLY);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		uint8_t pdu[BTDS_PUBLIC_KEY_PDU_LEN];

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		if (recv(smp_fds[1], pdu, sizeof(pdu), 0) != BTDS_PUBLIC_KEY_PDU_LEN ||
		    pdu[0] != BTDS_SMP_PAIRING_PUBLIC_KEY)
			_exit(1);
		memset(pdu, 0, sizeof(pdu));
		pdu[0] = BTDS_SMP_PAIRING_PUBLIC_KEY;
		if (send(smp_fds[1], pdu, sizeof(pdu), MSG_EOR) != sizeof(pdu))
			_exit(2);
		if (recv(smp_fds[1], pdu, sizeof(pdu), 0) < BTDS_PAIRING_FAILED_PDU_LEN ||
		    pdu[0] != BTDS_SMP_PAIRING_FAILED ||
		    pdu[1] != BTDS_SMP_ERR_DHKEY_CHECK_FAILED)
			_exit(3);
		close(smp_fds[1]);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	ATF_CHECK_EQ(smp_pair_sc_passkey(&sc, preq, pres), -1);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_passkey_truncated_public_key);
ATF_TC_BODY(test_pair_sc_passkey_truncated_public_key, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;
	uint8_t preq[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_REQUEST, BTDS_SMP_IO_KEYBOARD_ONLY, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC | BTDS_SMP_AUTH_MITM, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };
	uint8_t pres[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_RESPONSE, BTDS_SMP_IO_DISPLAY_ONLY, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC | BTDS_SMP_AUTH_MITM, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC, BTDS_SMP_IO_KEYBOARD_ONLY);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		uint8_t pdu[BTDS_PUBLIC_KEY_PDU_LEN] = { BTDS_SMP_PAIRING_PUBLIC_KEY };

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		if (recv(smp_fds[1], pdu, sizeof(pdu), 0) != BTDS_PUBLIC_KEY_PDU_LEN ||
		    pdu[0] != BTDS_SMP_PAIRING_PUBLIC_KEY)
			_exit(1);
		pdu[0] = BTDS_SMP_PAIRING_PUBLIC_KEY;
		if (send(smp_fds[1], pdu, 1, MSG_EOR) != 1)
			_exit(2);
		if (recv(smp_fds[1], pdu, sizeof(pdu), 0) !=
		    BTDS_PAIRING_FAILED_PDU_LEN ||
		    pdu[0] != BTDS_SMP_PAIRING_FAILED ||
		    pdu[1] != BTDS_SMP_ERR_INVALID_PARAMETERS)
			_exit(3);
		close(smp_fds[1]);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	ATF_CHECK_EQ(smp_pair_sc_passkey(&sc, preq, pres), -1);
	ATF_CHECK_EQ(errno, EPROTO);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_jw_public_key_send_failure);
ATF_TC_BODY(test_pair_sc_jw_public_key_send_failure, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t preq[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_REQUEST, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };
	uint8_t pres[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_RESPONSE, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT);
	close(smp_fds[1]);
	close(hci_fds[1]);
	ATF_CHECK_EQ(smp_pair_sc(&sc, preq, pres, SMP_MODEL_JUST_WORKS), -1);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_jw_peer_aborts_public_key);
ATF_TC_BODY(test_pair_sc_jw_peer_aborts_public_key, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;
	uint8_t preq[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_REQUEST, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };
	uint8_t pres[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_RESPONSE, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		uint8_t pdu[BTDS_PUBLIC_KEY_PDU_LEN];

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		if (recv(smp_fds[1], pdu, sizeof(pdu), 0) != BTDS_PUBLIC_KEY_PDU_LEN ||
		    pdu[0] != BTDS_SMP_PAIRING_PUBLIC_KEY)
			_exit(1);
		pdu[0] = BTDS_SMP_PAIRING_FAILED;
		pdu[1] = BTDS_SMP_ERR_UNSPECIFIED_REASON;
		if (send(smp_fds[1], pdu, BTDS_PAIRING_FAILED_PDU_LEN, MSG_EOR) != BTDS_PAIRING_FAILED_PDU_LEN)
			_exit(2);
		close(smp_fds[1]);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	ATF_CHECK_EQ(smp_pair_sc(&sc, preq, pres, SMP_MODEL_JUST_WORKS), -1);
	ATF_CHECK_EQ(errno, EACCES);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_jw_invalid_public_key);
ATF_TC_BODY(test_pair_sc_jw_invalid_public_key, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;
	uint8_t preq[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_REQUEST, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };
	uint8_t pres[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_RESPONSE, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		uint8_t pdu[BTDS_PUBLIC_KEY_PDU_LEN];

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		if (recv(smp_fds[1], pdu, sizeof(pdu), 0) != BTDS_PUBLIC_KEY_PDU_LEN ||
		    pdu[0] != BTDS_SMP_PAIRING_PUBLIC_KEY)
			_exit(1);
		memset(pdu, 0, sizeof(pdu));
		pdu[0] = BTDS_SMP_PAIRING_PUBLIC_KEY;
		if (send(smp_fds[1], pdu, sizeof(pdu), MSG_EOR) != sizeof(pdu))
			_exit(2);
		if (recv(smp_fds[1], pdu, sizeof(pdu), 0) < BTDS_PAIRING_FAILED_PDU_LEN ||
		    pdu[0] != BTDS_SMP_PAIRING_FAILED ||
		    pdu[1] != BTDS_SMP_ERR_DHKEY_CHECK_FAILED)
			_exit(3);
		close(smp_fds[1]);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	ATF_CHECK_EQ(smp_pair_sc(&sc, preq, pres, SMP_MODEL_JUST_WORKS), -1);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

/* Core Spec Vol 3 Part H §3.5.6 requires a 64-octet Public Key payload.
 * A truncated peer PDU is a protocol error, distinct from an invalid curve
 * point carried in an otherwise well-formed PDU. */
ATF_TC_WITHOUT_HEAD(test_pair_sc_jw_truncated_public_key);
ATF_TC_BODY(test_pair_sc_jw_truncated_public_key, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;
	uint8_t preq[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_REQUEST, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };
	uint8_t pres[BTDS_PAIRING_FEATURE_PDU_LEN] = { BTDS_SMP_PAIRING_RESPONSE, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT, BTDS_OOB_NOT_PRESENT,
	    BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC, BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE, BTDS_KEY_DIST_NONE };

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds, central_addr, BDADDR_LE_PUBLIC,
	    periph_addr, BDADDR_LE_PUBLIC, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		uint8_t pdu[BTDS_PUBLIC_KEY_PDU_LEN];

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		if (recv(smp_fds[1], pdu, sizeof(pdu), 0) != BTDS_PUBLIC_KEY_PDU_LEN ||
		    pdu[0] != BTDS_SMP_PAIRING_PUBLIC_KEY)
			_exit(1);
		memset(pdu, 0, sizeof(pdu));
		pdu[0] = BTDS_SMP_PAIRING_PUBLIC_KEY;
		if (send(smp_fds[1], pdu, sizeof(pdu) - 1, MSG_EOR) !=
		    sizeof(pdu) - 1)
			_exit(2);
		if (recv(smp_fds[1], pdu, sizeof(pdu), 0) !=
		    BTDS_PAIRING_FAILED_PDU_LEN ||
		    pdu[0] != BTDS_SMP_PAIRING_FAILED ||
		    pdu[1] != BTDS_SMP_ERR_INVALID_PARAMETERS)
			_exit(3);
		close(smp_fds[1]);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	ATF_CHECK_EQ(smp_pair_sc(&sc, preq, pres, SMP_MODEL_JUST_WORKS), -1);
	ATF_CHECK_EQ(errno, EPROTO);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

/*
 * Core 6.3 Vol 3 Part H §§3.5.5-3.5.6: the 64-octet public-key
 * payload is exact.  A formerly accepted trailing octet must produce
 * Pairing Failed / Invalid Parameters just like a short command.
 */
ATF_TC_WITHOUT_HEAD(test_pair_sc_jw_oversized_public_key);
ATF_TC_BODY(test_pair_sc_jw_oversized_public_key, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;
	uint8_t preq[BTDS_PAIRING_FEATURE_PDU_LEN] = {
		BTDS_SMP_PAIRING_REQUEST, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT,
		BTDS_OOB_NOT_PRESENT, BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC,
		BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE,
		BTDS_KEY_DIST_NONE
	};
	uint8_t pres[BTDS_PAIRING_FEATURE_PDU_LEN] = {
		BTDS_SMP_PAIRING_RESPONSE, BTDS_SMP_IO_NO_INPUT_NO_OUTPUT,
		BTDS_OOB_NOT_PRESENT, BTDS_SMP_AUTH_BONDING | BTDS_SMP_AUTH_SC,
		BTDS_MAX_ENCRYPTION_KEY_SIZE, BTDS_KEY_DIST_NONE,
		BTDS_KEY_DIST_NONE
	};

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	setup(&sc, &db, -1, smp_fds, hci_fds, central_addr,
	    BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC,
	    BTDS_SMP_IO_NO_INPUT_NO_OUTPUT);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		uint8_t pdu[BTDS_PUBLIC_KEY_PDU_LEN + 1];

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		if (recv(smp_fds[1], pdu, sizeof(pdu), 0) !=
		    BTDS_PUBLIC_KEY_PDU_LEN ||
		    pdu[0] != BTDS_SMP_PAIRING_PUBLIC_KEY)
			_exit(1);
		memset(pdu, 0, sizeof(pdu));
		pdu[0] = BTDS_SMP_PAIRING_PUBLIC_KEY;
		if (send(smp_fds[1], pdu, sizeof(pdu), MSG_EOR) != sizeof(pdu))
			_exit(2);
		if (recv(smp_fds[1], pdu, sizeof(pdu), 0) !=
		    BTDS_PAIRING_FAILED_PDU_LEN ||
		    pdu[0] != BTDS_SMP_PAIRING_FAILED ||
		    pdu[1] != BTDS_SMP_ERR_INVALID_PARAMETERS)
			_exit(3);
		close(smp_fds[1]);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	ATF_CHECK_EQ(smp_pair_sc(&sc, preq, pres, SMP_MODEL_JUST_WORKS), -1);
	ATF_CHECK_EQ(errno, EPROTO);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, reference_crypto_kat);
	ATF_TP_ADD_TC(tp, test_respond_sc_jw_random_allkeys);
	ATF_TP_ADD_TC(tp, test_respond_sc_numcmp_accept);
	ATF_TP_ADD_TC(tp, test_respond_sc_passkey_success);
	ATF_TP_ADD_TC(tp, test_pair_sc_jw_random_allkeys);
	ATF_TP_ADD_TC(tp, test_pair_sc_numcmp_success);
	ATF_TP_ADD_TC(tp, test_pair_sc_passkey_success);
	ATF_TP_ADD_TC(tp, test_pair_sc_passkey_keypress);
	ATF_TP_ADD_TC(tp, test_pair_sc_jw_start_encryption_failure);
	ATF_TP_ADD_TC(tp, test_pair_sc_jw_wait_encryption_failure);
	ATF_TP_ADD_TC(tp, test_pair_sc_jw_bond_store_failure);
	ATF_TP_ADD_TC(tp, test_pair_sc_jw_confirm_mismatch);
	ATF_TP_ADD_TC(tp, test_pair_sc_jw_peer_abort_at_random);
	ATF_TP_ADD_TC(tp, test_pair_sc_jw_dhkey_mismatch);
	ATF_TP_ADD_TC(tp, test_pair_sc_jw_truncated_dhkey);
	ATF_TP_ADD_TC(tp, test_pair_sc_jw_truncated_random);
	ATF_TP_ADD_TC(tp, test_pair_sc_passkey_public_key_send_failure);
	ATF_TP_ADD_TC(tp, test_pair_sc_passkey_peer_aborts_public_key);
	ATF_TP_ADD_TC(tp, test_pair_sc_passkey_invalid_public_key);
	ATF_TP_ADD_TC(tp, test_pair_sc_passkey_truncated_public_key);
	ATF_TP_ADD_TC(tp, test_pair_sc_jw_public_key_send_failure);
	ATF_TP_ADD_TC(tp, test_pair_sc_jw_peer_aborts_public_key);
	ATF_TP_ADD_TC(tp, test_pair_sc_jw_invalid_public_key);
	ATF_TP_ADD_TC(tp, test_pair_sc_jw_truncated_public_key);
	ATF_TP_ADD_TC(tp, test_pair_sc_jw_oversized_public_key);

	return (atf_no_error());
}
