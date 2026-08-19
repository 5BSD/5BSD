/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF unit tests for SMP cryptographic functions.
 *
 * Test vectors from Bluetooth Core Specification Version 6.3,
 * Vol 3 Part H Appendix D ("Sample data").
 *
 * The spec presents values in big-endian (MSB-first) order.
 * The SMP crypto functions in smp.c take inputs in little-endian
 * (wire) order, except for smp_aes_cmac which works in big-endian.
 * Helper macros below handle the conversion.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <stdlib.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "hci_log.h"
#include "hci_util.h"
#include "smp.h"
#include "smp_internal.h"
#include "spec_bond_db_contract_oracles.h"
#include "spec_crypto_external_oracles.h"
#include "spec_oracles.h"
#include "spec_smp_timeout_oracles.h"

#define TEST_LINKS_SMP
#include "test_common.h"

/* Expand generated Core command/scalar tables into test-only names. */
#define SMP_CRYPTO_COMMAND_ORACLE(name, value) BTCR_##name = (value),
enum { BT_CORE63_SMP_COMMAND_ORACLES(SMP_CRYPTO_COMMAND_ORACLE) };
#undef SMP_CRYPTO_COMMAND_ORACLE
#define SMP_CRYPTO_SCALAR_ORACLE(name, value) BTCR_##name = (value),
enum { BT_CORE63_SMP_SCALAR_ORACLES(SMP_CRYPTO_SCALAR_ORACLE) };
#undef SMP_CRYPTO_SCALAR_ORACLE
#define SMP_CRYPTO_KEYDIST_ORACLE(name, value) BTCR_##name = (value),
enum { BT_CORE63_SMP_KEY_DIST_ORACLES(SMP_CRYPTO_KEYDIST_ORACLE) };
#undef SMP_CRYPTO_KEYDIST_ORACLE

static void
enable_atomic_bond_save(struct smp_bond_db *db, const char *path)
{
	int dir_fd;

	dir_fd = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(dir_fd >= 0);
	smp_bond_db_set_atomic(db, dir_fd, path);
}

/* ================================================================
 * Stubs for external symbols referenced by smp.c but not needed
 * for crypto-only tests.
 * ================================================================ */

/* hci_util.c stubs — return success so full-pairing tests work */
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

/* ================================================================
 * Helper: convert a big-endian hex string to a byte array.
 * Writes exactly 'len' bytes to 'out'.
 * ================================================================ */
static void
hex_to_bytes(uint8_t *out, const char *hex, size_t len)
{
	size_t i;
	unsigned int b;

	for (i = 0; i < len; i++) {
		sscanf(hex + 2 * i, "%02x", &b);
		out[i] = (uint8_t)b;
	}
}

/*
 * Reverse 'len' bytes in place (big-endian <-> little-endian).
 */
static void
reverse_bytes(uint8_t *buf, size_t len)
{
	size_t i;
	uint8_t tmp;

	for (i = 0; i < len / 2; i++) {
		tmp = buf[i];
		buf[i] = buf[len - 1 - i];
		buf[len - 1 - i] = tmp;
	}
}

/* Independent RFC 4493 AES-CMAC oracle; calls no blued crypto helper. */
static int
reference_cmac(const uint8_t key[16], const uint8_t *msg, size_t len,
    uint8_t out[16])
{
	size_t out_len;

	out_len = 0;
	if (EVP_Q_mac(NULL, "CMAC", NULL, "AES-128-CBC", NULL, key, 16,
	    msg, len, out, 16, &out_len) == NULL || out_len != 16)
		return (-1);
	return (0);
}

/* Independent AES-128-ECB adapter for SMP's little-octet-first convention. */
static int
reference_aes128_le(const uint8_t key_le[16], const uint8_t in_le[16],
    uint8_t out_le[16])
{
	EVP_CIPHER_CTX *ctx;
	uint8_t key[16], input[16], output[32];
	int out_len, final_len, i, rc;

	for (i = 0; i < 16; i++) {
		key[i] = key_le[15 - i];
		input[i] = in_le[15 - i];
	}
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return (-1);
	rc = -1;
	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1 ||
	    EVP_CIPHER_CTX_set_padding(ctx, 0) != 1 ||
	    EVP_EncryptUpdate(ctx, output, &out_len, input, 16) != 1 ||
	    EVP_EncryptFinal_ex(ctx, output + out_len, &final_len) != 1 ||
	    out_len + final_len != 16)
		goto out;
	for (i = 0; i < 16; i++)
		out_le[i] = output[15 - i];
	rc = 0;
out:
	EVP_CIPHER_CTX_free(ctx);
	explicit_bzero(key, sizeof(key));
	explicit_bzero(output, sizeof(output));
	return (rc);
}

/* Core 6.3 Vol 3 Part H §2.2.3 c1, independent of smp_c1(). */
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

/*
 * ATT signing construction (Core Spec Vol 3 Part H §2.4.5), matching the
 * interoperable reference stacks (Linux net/bluetooth/smp.c, BlueZ
 * src/shared/crypto.c bt_crypto_sign_att).  This is an INDEPENDENT
 * reimplementation of the byte order used by smp_verify_signature (S-M3): the
 * CSRK and the whole (message || SignCounter_le32) buffer are byte-reversed
 * into the MSB order RFC 4493 AES-CMAC uses, and the wire signature is the low
 * 8 octets of the byte-reversed (LSB-first) 128-bit MAC.
 */
static int
reference_signature(const uint8_t csrk_le[16], const uint8_t *msg,
    size_t msg_len, uint32_t counter, uint8_t signature[8])
{
	uint8_t key[16], mac[16];
	uint8_t *input, *swapped;
	size_t i, n;
	int rc;

	if (msg_len > SIZE_MAX - 4)
		return (-1);
	n = msg_len + 4;
	input = malloc(n);
	swapped = malloc(n);
	if (input == NULL || swapped == NULL) {
		free(input);
		free(swapped);
		return (-1);
	}
	if (msg_len != 0)
		memcpy(input, msg, msg_len);
	input[msg_len] = (uint8_t)counter;
	input[msg_len + 1] = (uint8_t)(counter >> 8);
	input[msg_len + 2] = (uint8_t)(counter >> 16);
	input[msg_len + 3] = (uint8_t)(counter >> 24);
	/* Byte-reverse the whole message and the key into MSB order. */
	for (i = 0; i < n; i++)
		swapped[i] = input[n - 1 - i];
	for (i = 0; i < sizeof(key); i++)
		key[i] = csrk_le[sizeof(key) - 1 - i];
	rc = reference_cmac(key, swapped, n, mac);
	if (rc == 0) {
		/* Wire signature = low 8 octets of the LSB-first (reversed) MAC. */
		for (i = 0; i < 8; i++)
			signature[i] = mac[sizeof(mac) - 1 - i];
	}
	explicit_bzero(key, sizeof(key));
	explicit_bzero(mac, sizeof(mac));
	free(input);
	free(swapped);
	return (rc);
}

/*
 * Parse big-endian hex string to big-endian byte array.
 */
#define	HEX_BE(var, hexstr, len) \
	uint8_t var[len]; hex_to_bytes(var, hexstr, len)

/*
 * Parse big-endian hex string, then reverse to little-endian byte array.
 */
#define	HEX_LE(var, hexstr, len) \
	uint8_t var[len]; hex_to_bytes(var, hexstr, len); reverse_bytes(var, len)

/* ================================================================
 * Test: smp_swap_buf
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_swap_buf);
ATF_TC_BODY(test_smp_swap_buf, tc)
{
	uint8_t src[4] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t dst[4];
	uint8_t expected[4] = { 0x04, 0x03, 0x02, 0x01 };

	smp_swap_buf(dst, src, 4);
	ATF_CHECK_EQ(memcmp(dst, expected, 4), 0);
}

/* ================================================================
 * Test: smp_aes128 (security function e)
 * Core Spec Vol 3 Part H Section 2.2.1
 *
 * Derived from the worked s1 example in Section 2.2.4:
 *   s1(k, r1, r2) = e(k, r') where r' = r1' || r2'
 *   k  = 0x00000000000000000000000000000000
 *   r' = 0x112233445566778899AABBCCDDEEFF00 (big-endian)
 *   e output = 0x9a1fe1f0e8b0f49b5b4216ae796da062 (big-endian)
 *
 * smp_aes128 takes inputs in little-endian (wire) order.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_aes128);
ATF_TC_BODY(test_smp_aes128, tc)
{
	HEX_LE(k, BT_CORE63_SMP_S1_KEY_HEX, 16);
	HEX_LE(r1, BT_CORE63_SMP_S1_R1_HEX, 16);
	HEX_LE(r2, BT_CORE63_SMP_S1_R2_HEX, 16);
	HEX_LE(expected, BT_CORE63_SMP_S1_OUT_HEX, 16);
	uint8_t r[16];

	/* Section 2.2.4: r' = r1' || r2'; r is stored least-octet first. */
	memcpy(r, r2, 8);
	memcpy(r + 8, r1, 8);

	uint8_t out[16];
	ATF_REQUIRE(smp_aes128(k, r, out) == 0);

	ATF_CHECK_EQ_MSG(memcmp(out, expected, 16), 0,
	    "smp_aes128 output does not match spec s1 test vector");
}

/* ================================================================
 * Test: smp_c1 (confirm value generation for LE legacy pairing)
 * Core Spec Vol 3 Part H Section 2.2.3
 *
 * From page 1642:
 *   k = 0x00000000000000000000000000000000
 *   r = 0x5783D52156AD6F0E6388274EC6702EE0
 *   preq = 0x07071000000101 (7 bytes)
 *   pres = 0x05000800000302 (7 bytes)
 *   iat = 0x01
 *   ia = 0xA1A2A3A4A5A6
 *   rat = 0x00
 *   ra = 0xB1B2B3B4B5B6
 *   output = 0x1E1E3FEF878988EAD2A74DC5BEF13B86
 *
 * The spec shows p1 = 0x05000800000302 07071000000101 00 01
 *   = pres || preq || rat' || iat' in big-endian MSB-first.
 * In little-endian (LSB first), p1[0]=iat=0x01, p1[1]=rat=0x00,
 *   p1[2..8]=preq, p1[9..15]=pres.
 *
 * The spec example preq/pres values are given in big-endian with
 * MSB on the left.  We need to figure out the LE wire order.
 *
 * Looking at the spec's p1 value:
 *   p1 = 0x05000800000302070710000001010001
 * In the little-endian array format used by smp_c1:
 *   p1[0] = iat = 0x01
 *   p1[1] = rat = 0x00
 *   p1[2..8] = preq bytes
 *   p1[9..15] = pres bytes
 *
 * So from the BE value 0x05000800000302070710000001010001:
 * Read right-to-left: 01 00 01010000100707 02030000080005
 * p1[0]=0x01, p1[1]=0x00
 * preq = 01 01 00 00 10 07 07  (bytes 2-8)
 * pres = 02 03 00 00 08 00 05  (bytes 9-15)
 *
 * The spec also gives:
 * p2 = 0x00000000 A1A2A3A4A5A6 B1B2B3B4B5B6
 * In LE array: p2[0..5]=ra, p2[6..11]=ia, p2[12..15]=0
 * So ra = B6 B5 B4 B3 B2 B1 (LE) and ia = A6 A5 A4 A3 A2 A1 (LE)
 *
 * Wait - the spec says ia=0xA1A2A3A4A5A6 and ra=0xB1B2B3B4B5B6.
 * In the p2 construction, p2[0..5] = ra, meaning ra[0]=B6 in LE?
 * No - actually the addresses are just byte arrays.  The spec
 * shows them as 0xA1A2A3A4A5A6 meaning A1 is the MSB.  But for
 * Bluetooth, addresses on the wire are in little-endian, so the
 * address bytes as passed to smp_c1 would be {A6,A5,A4,A3,A2,A1}.
 *
 * Let's work from the known p2 value:
 *   p2 = 0x00000000A1A2A3A4A5A6B1B2B3B4B5B6 (BE)
 * As LE array: {B6,B5,B4,B3,B2,B1,A6,A5,A4,A3,A2,A1,00,00,00,00}
 * So ra = {B6,B5,B4,B3,B2,B1} and ia = {A6,A5,A4,A3,A2,A1}
 *
 * Similarly for p1:
 *   p1 = 0x05000800000302 07071000000101 00 01 (BE)
 * As LE array: {01,00,01,01,00,00,10,07,07,02,03,00,00,08,00,05}
 * So preq = {01,01,00,00,10,07,07} and pres = {02,03,00,00,08,00,05}
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_c1);
ATF_TC_BODY(test_smp_c1, tc)
{
	HEX_LE(k, BT_CORE63_SMP_C1_KEY_HEX, 16);
	HEX_LE(r, BT_CORE63_SMP_C1_R_HEX, 16);

	/*
	 * preq and pres as they appear in the LE p1 array.
	 * p1 BE = 0x050008000003020707100000010100 01
	 * p1 LE array: {0x01, 0x00, preq[7], pres[7]}
	 * preq = {0x01,0x01,0x00,0x00,0x10,0x07,0x07}
	 * pres = {0x02,0x03,0x00,0x00,0x08,0x00,0x05}
	 */
	HEX_LE(preq, BT_CORE63_SMP_C1_PREQ_HEX, 7);
	HEX_LE(pres, BT_CORE63_SMP_C1_PRES_HEX, 7);
	HEX_BE(iat_bytes, BT_CORE63_SMP_C1_IAT_HEX, 1);
	HEX_BE(rat_bytes, BT_CORE63_SMP_C1_RAT_HEX, 1);
	uint8_t iat = iat_bytes[0];
	uint8_t rat = rat_bytes[0];

	/*
	 * ia and ra from the p2 construction:
	 * p2 BE = 0x00000000A1A2A3A4A5A6B1B2B3B4B5B6
	 * p2 LE array = {ra[6], ia[6], padding[4]}
	 *            = {B6,B5,B4,B3,B2,B1, A6,A5,A4,A3,A2,A1, 00,00,00,00}
	 */
	HEX_LE(ia, BT_CORE63_SMP_C1_IA_HEX, 6);
	HEX_LE(ra, BT_CORE63_SMP_C1_RA_HEX, 6);

	/* Expected output from spec, converted to LE */
	HEX_LE(expected, BT_CORE63_SMP_C1_OUT_HEX, 16);

	uint8_t confirm[16];
	smp_c1(k, r, preq, pres, iat, ia, rat, ra, confirm);

	ATF_CHECK_EQ_MSG(memcmp(confirm, expected, 16), 0,
	    "smp_c1 output does not match spec Section 2.2.3 test vector");
}

/* ================================================================
 * Test: smp_s1 (key generation for LE legacy pairing)
 * Core Spec Vol 3 Part H Section 2.2.4
 *
 * From page 1643:
 *   k = 0x00000000000000000000000000000000
 *   r1 = 0x000F0E0D0C0B0A091122334455667788 (BE)
 *   r2 = 0x0102030405060708 99AABBCCDDEEFF00 (BE)
 *   r' = 0x11223344556677889 9AABBCCDDEEFF00 (BE)
 *       (r1' || r2' where r1'=lower 8 of r1, r2'=lower 8 of r2)
 *   output = 0x9a1fe1f0e8b0f49b5b4216ae796da062 (BE)
 *
 * smp_s1 takes r1, r2 in LE order.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_s1);
ATF_TC_BODY(test_smp_s1, tc)
{
	HEX_LE(k, BT_CORE63_SMP_S1_KEY_HEX, 16);
	HEX_LE(r1, BT_CORE63_SMP_S1_R1_HEX, 16);
	HEX_LE(r2, BT_CORE63_SMP_S1_R2_HEX, 16);
	HEX_LE(expected, BT_CORE63_SMP_S1_OUT_HEX, 16);

	uint8_t stk[16];
	smp_s1(k, r1, r2, stk);

	ATF_CHECK_EQ_MSG(memcmp(stk, expected, 16), 0,
	    "smp_s1 output does not match spec Section 2.2.4 test vector");
}

/* ================================================================
 * Test: smp_aes_cmac (RFC 4493 test vectors)
 * Core Spec Vol 3 Part H Appendix D.1
 *
 * smp_aes_cmac takes key and message in big-endian order directly
 * (no byte reversal like smp_aes128).
 *
 * D.1 key: 2b7e1516 28aed2a6 abf71588 09cf4f3c
 * ================================================================ */

/* D.1.1: Len = 0 (empty message) */
ATF_TC_WITHOUT_HEAD(test_smp_aes_cmac_len0);
ATF_TC_BODY(test_smp_aes_cmac_len0, tc)
{
	HEX_BE(key, BT_CORE63_SMP_D1_KEY_HEX, 16);
	HEX_BE(expected, BT_CORE63_SMP_D1_1_OUT_HEX, 16);

	uint8_t mac[16];
	smp_aes_cmac(key, NULL, 0, mac);

	ATF_CHECK_EQ_MSG(memcmp(mac, expected, 16), 0,
	    "AES-CMAC Len=0 does not match RFC 4493 / Spec D.1.1");
}

/* D.1.2: Len = 16 */
ATF_TC_WITHOUT_HEAD(test_smp_aes_cmac_len16);
ATF_TC_BODY(test_smp_aes_cmac_len16, tc)
{
	HEX_BE(key, BT_CORE63_SMP_D1_KEY_HEX, 16);
	HEX_BE(msg, BT_CORE63_SMP_D1_2_MSG_HEX, 16);
	HEX_BE(expected, BT_CORE63_SMP_D1_2_OUT_HEX, 16);

	uint8_t mac[16];
	smp_aes_cmac(key, msg, 16, mac);

	ATF_CHECK_EQ_MSG(memcmp(mac, expected, 16), 0,
	    "AES-CMAC Len=16 does not match RFC 4493 / Spec D.1.2");
}

/* D.1.3: Len = 40 */
ATF_TC_WITHOUT_HEAD(test_smp_aes_cmac_len40);
ATF_TC_BODY(test_smp_aes_cmac_len40, tc)
{
	HEX_BE(key, BT_CORE63_SMP_D1_KEY_HEX, 16);
	uint8_t msg[40];
	hex_to_bytes(msg, BT_CORE63_SMP_D1_3_MSG_HEX, 40);
	HEX_BE(expected, BT_CORE63_SMP_D1_3_OUT_HEX, 16);

	uint8_t mac[16];
	smp_aes_cmac(key, msg, 40, mac);

	ATF_CHECK_EQ_MSG(memcmp(mac, expected, 16), 0,
	    "AES-CMAC Len=40 does not match RFC 4493 / Spec D.1.3");
}

/* D.1.4: Len = 64 */
ATF_TC_WITHOUT_HEAD(test_smp_aes_cmac_len64);
ATF_TC_BODY(test_smp_aes_cmac_len64, tc)
{
	HEX_BE(key, BT_CORE63_SMP_D1_KEY_HEX, 16);
	uint8_t msg[64];
	hex_to_bytes(msg, BT_CORE63_SMP_D1_4_MSG_HEX, 64);
	HEX_BE(expected, BT_CORE63_SMP_D1_4_OUT_HEX, 16);

	uint8_t mac[16];
	smp_aes_cmac(key, msg, 64, mac);

	ATF_CHECK_EQ_MSG(memcmp(mac, expected, 16), 0,
	    "AES-CMAC Len=64 does not match RFC 4493 / Spec D.1.4");
}

/* ================================================================
 * Test: smp_f4 (LE SC confirm value generation)
 * Core Spec Vol 3 Part H Appendix D.2
 *
 * All inputs to smp_f4 are in little-endian (wire) order.
 * Spec values are in big-endian.
 *
 *   U = 20b003d2 f297be2c 5e2c83a7 e9f9a5b9
 *       eff49111 acf4fddb cc030148 0e359de6
 *   V = 55188b3d 32f6bb9a 900afcfb eed4e72a
 *       59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd
 *   X = d5cb8454 d177733e ffffb2ec 712baeab
 *   Z = 0x00
 *   AES_CMAC = f2c916f1 07a9bd1c f1eda1be a974872d
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_f4);
ATF_TC_BODY(test_smp_f4, tc)
{
	HEX_LE(u, BT_CORE63_SMP_D2_U_HEX, 32);
	HEX_LE(v, BT_CORE63_SMP_D2_V_HEX, 32);
	HEX_LE(x, BT_CORE63_SMP_D2_X_HEX, 16);
	uint8_t z = BT_CORE63_SMP_D2_Z;
	HEX_LE(expected, BT_CORE63_SMP_D2_OUT_HEX, 16);

	uint8_t out[16];
	smp_f4(u, v, x, z, out);

	ATF_CHECK_EQ_MSG(memcmp(out, expected, 16), 0,
	    "smp_f4 output does not match spec D.2 test vector");
}

/* ================================================================
 * Test: smp_f5 (LE SC key generation)
 * Core Spec Vol 3 Part H Appendix D.3
 *
 * All multi-byte inputs in little-endian (wire) order.
 *
 *   DHKey(W) = ec0234a3 57c8ad05 341010a6 0a397d9b
 *              99796b13 b4f866f1 868d34f3 73bfa698
 *   N1       = d5cb8454 d177733e ffffb2ec 712baeab
 *   N2       = a6e8e7cc 25a75f6e 216583f7 ff3dc4cf
 *   A1       = 00561237 37bfce
 *   A2       = 00a71370 2dcfc1
 *
 *   MacKey   = 2965f176 a1084a02 fd3f6a20 ce636e20  (Counter=0)
 *   LTK      = 69867911 69d7cd23 980522b5 94750a38  (Counter=1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_f5);
ATF_TC_BODY(test_smp_f5, tc)
{
	HEX_LE(dhkey, BT_CORE63_SMP_D3_DHKEY_HEX, 32);
	HEX_LE(n1, BT_CORE63_SMP_D3_N1_HEX, 16);
	HEX_LE(n2, BT_CORE63_SMP_D3_N2_HEX, 16);

	/*
	 * A1 and A2 are 7-byte "address info" fields: addr_type(1) || addr(6).
	 * Spec gives them in big-endian.  In LE wire order, we reverse.
	 */
	HEX_LE(a1, BT_CORE63_SMP_D3_A1_HEX, 7);
	HEX_LE(a2, BT_CORE63_SMP_D3_A2_HEX, 7);

	/*
	 * Per Core Spec Vol 3 Part H Section 2.2.7 and Appendix D.3:
	 * Counter=0 -> MacKey, Counter=1 -> LTK.
	 */
	HEX_LE(exp_mackey, BT_CORE63_SMP_D3_MACKEY_HEX, 16);
	HEX_LE(exp_ltk, BT_CORE63_SMP_D3_LTK_HEX, 16);

	uint8_t mackey[16], ltk[16];
	smp_f5(dhkey, n1, n2, a1, a2, mackey, ltk);

	ATF_CHECK_EQ_MSG(memcmp(mackey, exp_mackey, 16), 0,
	    "smp_f5 MacKey does not match spec D.3 test vector");
	ATF_CHECK_EQ_MSG(memcmp(ltk, exp_ltk, 16), 0,
	    "smp_f5 LTK does not match spec D.3 test vector");
}

/* ================================================================
 * Test: smp_f6 (LE SC check value generation)
 * Core Spec Vol 3 Part H Appendix D.4
 *
 * All multi-byte inputs in little-endian (wire) order.
 *
 *   N1     = d5cb8454 d177733e ffffb2ec 712baeab
 *   N2     = a6e8e7cc 25a75f6e 216583f7 ff3dc4cf
 *   MacKey = 2965f176 a1084a02 fd3f6a20 ce636e20
 *   R      = 12a3343b b453bb54 08da42d2 0c2d0fc8
 *   IOcap  = 010102
 *   A1     = 00561237 37bfce
 *   A2     = 00a71370 2dcfc1
 *
 *   AES_CMAC = e3c47398 9cd0e8c5 d26c0b09 da958f61
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_f6);
ATF_TC_BODY(test_smp_f6, tc)
{
	HEX_LE(n1, BT_CORE63_SMP_D4_N1_HEX, 16);
	HEX_LE(n2, BT_CORE63_SMP_D4_N2_HEX, 16);
	HEX_LE(mackey, BT_CORE63_SMP_D4_MACKEY_HEX, 16);
	HEX_LE(r, BT_CORE63_SMP_D4_R_HEX, 16);
	HEX_LE(iocap, BT_CORE63_SMP_D4_IOCAP_HEX, 3);
	HEX_LE(a1, BT_CORE63_SMP_D4_A1_HEX, 7);
	HEX_LE(a2, BT_CORE63_SMP_D4_A2_HEX, 7);
	HEX_LE(expected, BT_CORE63_SMP_D4_OUT_HEX, 16);

	uint8_t out[16];
	smp_f6(mackey, n1, n2, r, iocap, a1, a2, out);

	ATF_CHECK_EQ_MSG(memcmp(out, expected, 16), 0,
	    "smp_f6 output does not match spec D.4 test vector");
}

/* ================================================================
 * Test: smp_g2 (LE SC numeric comparison value)
 * Core Spec Vol 3 Part H Appendix D.5
 *
 * All multi-byte inputs in little-endian (wire) order.
 *
 *   U = 20b003d2 f297be2c 5e2c83a7 e9f9a5b9
 *       eff49111 acf4fddb cc030148 0e359de6
 *   V = 55188b3d 32f6bb9a 900afcfb eed4e72a
 *       59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd
 *   X = d5cb8454 d177733e ffffb2ec 712baeab
 *   Y = a6e8e7cc 25a75f6e 216583f7 ff3dc4cf
 *
 *   AES_CMAC = 1536d18d e3d20df9 9b7044c1 2f9ed5ba
 *   g2       = 2f9ed5ba  (least significant 32 bits, BE)
 *
 * The 6-digit numeric comparison value shown to the user is
 * g2 mod 10^6 (Core Spec Vol 3 Part H §2.3.5.6.4):
 *   0x2f9ed5ba = 798938554, mod 10^6 = 938554 (not tested here)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_g2);
ATF_TC_BODY(test_smp_g2, tc)
{
	HEX_LE(u, BT_CORE63_SMP_D5_U_HEX, 32);
	HEX_LE(v, BT_CORE63_SMP_D5_V_HEX, 32);
	HEX_LE(x, BT_CORE63_SMP_D5_X_HEX, 16);
	HEX_LE(y, BT_CORE63_SMP_D5_Y_HEX, 16);

	uint32_t result = 0;

	ATF_CHECK_EQ(0, smp_g2(u, v, x, y, &result));

	/* g2 returns the least significant 32 bits of the BE MAC = 0x2f9ed5ba */
	ATF_CHECK_EQ_MSG(result, BT_CORE63_SMP_D5_OUT_VALUE,
	    "smp_g2 result 0x%08x does not match spec D.5 (0x2f9ed5ba)",
	    result);
}

/* ================================================================
 * Test: smp_h6 (link key conversion function)
 * Core Spec Vol 3 Part H Appendix D.6
 *
 *   Key (W)  = ec0234a3 57c8ad05 341010a6 0a397d9b  (BE, use LE)
 *   keyID    = 6c656272                              (BE, stays BE)
 *   AES_CMAC = 2d9ae102 e76dc91c e8d3a9e2 80b16399  (BE, expect LE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_h6);
ATF_TC_BODY(test_smp_h6, tc)
{
	/* W in LE wire order */
	HEX_LE(w, BT_CORE63_SMP_D6_KEY_HEX, 16);

	/* keyID is in big-endian order (not reversed) */
	HEX_BE(keyid, BT_CORE63_SMP_D6_KEYID_HEX, 4);

	/* Expected output in LE */
	HEX_LE(expected, BT_CORE63_SMP_D6_OUT_HEX, 16);

	uint8_t out[16];
	smp_h6(w, keyid, out);

	ATF_CHECK_EQ_MSG(memcmp(out, expected, 16), 0,
	    "smp_h6 output does not match spec D.6 test vector");
}

/* ================================================================
 * Test: smp_h7 (link key conversion function, alternate)
 * Core Spec Vol 3 Part H Appendix D.8
 *
 *   Key (W)  = ec0234a3 57c8ad05 341010a6 0a397d9b  (BE, use LE)
 *   SALT     = 00000000 00000000 00000000 746D7031  (BE, stays BE)
 *   AES_CMAC = fb173597 c6a3c0ec d2998c2a 75a57011  (BE, expect LE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_h7);
ATF_TC_BODY(test_smp_h7, tc)
{
	/* W in LE wire order */
	HEX_LE(w, BT_CORE63_SMP_D8_KEY_HEX, 16);

	/* SALT is in big-endian order (not reversed per spec) */
	HEX_BE(salt, BT_CORE63_SMP_D8_SALT_HEX, 16);

	/* Expected output in LE */
	HEX_LE(expected, BT_CORE63_SMP_D8_OUT_HEX, 16);

	uint8_t out[16];
	smp_h7(salt, w, out);

	ATF_CHECK_EQ_MSG(memcmp(out, expected, 16), 0,
	    "smp_h7 output does not match spec D.8 test vector");
}

/* ================================================================
 * Test: smp_ctkd_derive_link_key (CT2=1 path)
 * Core Spec Vol 3 Part H Appendix D.9
 *
 *   LTK      = 368df9bc e3264b58 bd066c33 334fbf64  (BE)
 *   Link Key = 287ad379 dca40253 0a39f1f4 3047b835  (BE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_ctkd_ct2);
ATF_TC_BODY(test_smp_ctkd_ct2, tc)
{
	struct smp_bond bond;

	memset(&bond, 0, sizeof(bond));
	bond.is_sc = true;
	bond.has_ltk = true;
	bond.is_mitm = true;

	/* LTK in LE wire order */
	HEX_LE(ltk, BT_CORE63_SMP_D9_LTK_HEX, 16);
	memcpy(bond.ltk, ltk, 16);

	/* Expected link key in LE wire order */
	HEX_LE(expected, BT_CORE63_SMP_D9_LINK_KEY_HEX, 16);

	int ret = smp_ctkd_derive_link_key(&bond, true);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ_MSG(memcmp(bond.link_key, expected, 16), 0,
	    "CTKD CT2=1 link key does not match spec D.9");
}

/* ================================================================
 * Test: smp_ctkd_derive_link_key (CT2=0 path)
 * Core Spec Vol 3 Part H Appendix D.10
 *
 *   LTK      = 368df9bc e3264b58 bd066c33 334fbf64  (BE)
 *   Link Key = bc1ca4ef 633fc1bd 0d8230af ee388fb0  (BE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_ctkd_ct2_0);
ATF_TC_BODY(test_smp_ctkd_ct2_0, tc)
{
	struct smp_bond bond;

	memset(&bond, 0, sizeof(bond));
	bond.is_sc = true;
	bond.has_ltk = true;
	bond.is_mitm = true;

	HEX_LE(ltk, BT_CORE63_SMP_D10_LTK_HEX, 16);
	memcpy(bond.ltk, ltk, 16);

	HEX_LE(expected, BT_CORE63_SMP_D10_LINK_KEY_HEX, 16);

	int ret = smp_ctkd_derive_link_key(&bond, false);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ_MSG(memcmp(bond.link_key, expected, 16), 0,
	    "CTKD CT2=0 link key does not match spec D.10");
}

/* Core Vol 3 Part H §2.4.2.5 and Appendix D.11: Link Key -> LTK, CT2=1. */
ATF_TC_WITHOUT_HEAD(test_smp_ctkd_link_key_to_ltk_ct2);
ATF_TC_BODY(test_smp_ctkd_link_key_to_ltk_ct2, tc)
{
	struct smp_bond bond;

	memset(&bond, 0, sizeof(bond));
	bond.is_sc = true;
	bond.is_mitm = true;
	bond.has_link_key = true;
	HEX_LE(link_key, BT_CORE63_SMP_D11_LINK_KEY_HEX, 16);
	HEX_LE(expected, BT_CORE63_SMP_D11_LTK_HEX, 16);
	memcpy(bond.link_key, link_key, sizeof(bond.link_key));

	ATF_REQUIRE_EQ(smp_ctkd_derive_ltk(&bond, true), 0);
	ATF_CHECK(bond.has_ltk);
	ATF_CHECK_EQ_MSG(memcmp(bond.ltk, expected, sizeof(expected)), 0,
	    "CTKD CT2=1 LTK does not match Core Appendix D.11");
}

/* Core Vol 3 Part H §2.4.2.5 and Appendix D.12: Link Key -> LTK, CT2=0. */
ATF_TC_WITHOUT_HEAD(test_smp_ctkd_link_key_to_ltk_ct2_0);
ATF_TC_BODY(test_smp_ctkd_link_key_to_ltk_ct2_0, tc)
{
	struct smp_bond bond;

	memset(&bond, 0, sizeof(bond));
	bond.is_sc = true;
	bond.is_mitm = true;
	bond.has_link_key = true;
	HEX_LE(link_key, BT_CORE63_SMP_D12_LINK_KEY_HEX, 16);
	HEX_LE(expected, BT_CORE63_SMP_D12_LTK_HEX, 16);
	memcpy(bond.link_key, link_key, sizeof(bond.link_key));

	ATF_REQUIRE_EQ(smp_ctkd_derive_ltk(&bond, false), 0);
	ATF_CHECK(bond.has_ltk);
	ATF_CHECK_EQ_MSG(memcmp(bond.ltk, expected, sizeof(expected)), 0,
	    "CTKD CT2=0 LTK does not match Core Appendix D.12");
}

/* ================================================================
 * IO Capability Pairing Method Selection (Core Spec Vol 3 Part H §2.3.5.1)
 *
 * smp_select_model is defined in smp.c but not declared in smp.h
 * (internal function). Declare it here for testing.
 * ================================================================ */
/* Now declared in smp.h — no local declarations needed */

/* Legacy pairing association models: Table 2.8 (no Numeric Comparison). */
ATF_TC_WITHOUT_HEAD(test_smp_select_model_legacy);
ATF_TC_BODY(test_smp_select_model_legacy, tc)
{
	/* Generated from Table 2.8: [responder IO][initiator IO]. */
	static const int expected[5][5] = {
		BT_CORE63_SMP_ASSOC_LEGACY_MATRIX
	};

	for (int i = 0; i < 5; i++) {
		for (int r = 0; r < 5; r++) {
			int got = smp_select_model(i, r, false);
			ATF_CHECK_MSG(got == expected[r][i],
			    "legacy[%d][%d]: expected %d, got %d",
			    i, r, expected[r][i], got);
		}
	}
}

/* LE Secure Connections association models: Table 2.8. */
ATF_TC_WITHOUT_HEAD(test_smp_select_model_sc);
ATF_TC_BODY(test_smp_select_model_sc, tc)
{
	/* Generated from Table 2.8: [responder IO][initiator IO]. */
	static const int expected[5][5] = {
		BT_CORE63_SMP_ASSOC_SC_MATRIX
	};

	for (int i = 0; i < 5; i++) {
		for (int r = 0; r < 5; r++) {
			int got = smp_select_model(i, r, true);
			ATF_CHECK_MSG(got == expected[r][i],
			    "sc[%d][%d]: expected %d, got %d",
			    i, r, expected[r][i], got);
		}
	}
}

/* RPA matching: generate hash from known IRK, verify smp_rpa_matches */
ATF_TC_WITHOUT_HEAD(test_smp_rpa_resolve);
ATF_TC_BODY(test_smp_rpa_resolve, tc)
{
	/*
	 * RPA layout: addr[0..2] = hash, addr[3..5] = prand.
	 * addr[5] must have upper 2 bits = 01 (resolvable).
	 *
	 * ah(IRK, prand): plaintext is LE with prand at bytes [0..2],
	 * padding at [3..15].  Output hash is cipher[0..2] (LE).
	 */
	uint8_t irk[16];
	uint8_t prand[3] = { 0x42, 0x56,
	    BT_CORE63_RANDOM_ADDRESS_RESOLVABLE };
	uint8_t plaintext[16] = {0};
	uint8_t cipher[16];
	uint8_t rpa[6];

	arc4random_buf(irk, sizeof(irk));

	/* Compute ah(IRK, prand) — same as smp_rpa_matches does */
	plaintext[0] = prand[0];
	plaintext[1] = prand[1];
	plaintext[2] = prand[2];
	ATF_REQUIRE(smp_aes128(irk, plaintext, cipher) == 0);

	/* Build RPA: hash(3) || prand(3) */
	rpa[0] = cipher[0]; /* hash LSB */
	rpa[1] = cipher[1];
	rpa[2] = cipher[2]; /* hash MSB */
	rpa[3] = prand[0];
	rpa[4] = prand[1];
	rpa[5] = prand[2];  /* prand MSB, bits[7:6]=01 */

	/* smp_rpa_matches should return true */
	ATF_CHECK(smp_rpa_matches(irk, rpa) != 0);

	/* Different IRK should NOT match */
	uint8_t wrong_irk[16];
	memset(wrong_irk, 0xFF, sizeof(wrong_irk));
	ATF_CHECK(smp_rpa_matches(wrong_irk, rpa) == 0);
}

/* Bond save/load round-trip */
ATF_TC_WITHOUT_HEAD(test_bond_save_load);
ATF_TC_BODY(test_bond_save_load, tc)
{
	struct smp_bond_db db1, db2;
	char path[] = "/tmp/blued_test_bonds.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	memset(&db1, 0, sizeof(db1));
	db1.fd = fd;
	db1.count = 2;

	/* Bond 1: has LTK + IRK */
	memset(db1.bonds[0].addr, 0xAA, 6);
	db1.bonds[0].addr_type = BLUED_BOND_ADDR_RANDOM;
	memset(db1.bonds[0].ltk, 0x11, 16);
	db1.bonds[0].has_ltk = true;
	memset(db1.bonds[0].irk, 0x22, 16);
	db1.bonds[0].has_irk = true;
	db1.bonds[0].is_sc = true;

	/* Bond 2: has LTK only */
	memset(db1.bonds[1].addr, 0xBB, 6);
	db1.bonds[1].addr_type = BLUED_BOND_ADDR_PUBLIC;
	memset(db1.bonds[1].ltk, 0x33, 16);
	db1.bonds[1].has_ltk = true;

	enable_atomic_bond_save(&db1, path);
	ATF_CHECK_EQ(smp_bond_db_save(&db1), 0);

	/* Load into fresh db */
	memset(&db2, 0, sizeof(db2));
	enable_atomic_bond_save(&db2, path);
	ATF_CHECK_EQ(smp_bond_db_load(&db2, fd), 0);

	ATF_CHECK_EQ(db2.count, 2);
	ATF_CHECK(memcmp(db2.bonds[0].addr, db1.bonds[0].addr, 6) == 0);
	ATF_CHECK(db2.bonds[0].has_ltk == true);
	ATF_CHECK(db2.bonds[0].has_irk == true);
	ATF_CHECK(db2.bonds[0].is_sc == true);
	ATF_CHECK(memcmp(db2.bonds[0].ltk, db1.bonds[0].ltk, 16) == 0);
	ATF_CHECK(memcmp(db2.bonds[0].irk, db1.bonds[0].irk, 16) == 0);

	ATF_CHECK(memcmp(db2.bonds[1].addr, db1.bonds[1].addr, 6) == 0);
	ATF_CHECK(db2.bonds[1].has_ltk == true);
	ATF_CHECK(db2.bonds[1].has_irk == false);

	close(fd);
	unlink(path);
}

/* smp.h private contract: the database holds exactly 32 records. */
ATF_TC_WITHOUT_HEAD(test_bond_db_full);
ATF_TC_BODY(test_bond_db_full, tc)
{
	struct smp_bond_db db;
	struct smp_bond bond;
	char path[] = "/tmp/blued_test_full.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	memset(&db, 0, sizeof(db));
	db.fd = fd;

	/* Fill to capacity */
	ATF_REQUIRE_EQ(SMP_MAX_BONDS, BLUED_BOND_DB_MAX_RECORDS);
	for (int i = 0; i < BLUED_BOND_DB_MAX_RECORDS; i++) {
		memset(&bond, 0, sizeof(bond));
		bond.addr[0] = (uint8_t)i;
		bond.has_ltk = true;
		bond.addr_type = BLUED_BOND_ADDR_PUBLIC;
		memset(bond.ltk, (uint8_t)i, 16);
		smp_bond_db_store(&db, &bond);
	}
	ATF_CHECK_EQ(db.count, BLUED_BOND_DB_MAX_RECORDS);

	/* One more should NOT increase count */
	memset(&bond, 0, sizeof(bond));
	bond.addr[0] = 0xFF;
	bond.has_ltk = true;
	smp_bond_db_store(&db, &bond);
	ATF_CHECK_EQ(db.count, BLUED_BOND_DB_MAX_RECORDS);

	close(fd);
	unlink(path);
}

/* Core 6.3 Vol 3 Part H §2.2.7/D.3: counters 0 and 1 yield two outputs. */
ATF_TC_WITHOUT_HEAD(test_smp_f5_dual_output);
ATF_TC_BODY(test_smp_f5_dual_output, tc)
{
	HEX_LE(w, BT_CORE63_SMP_D3_DHKEY_HEX, 32);
	HEX_LE(n1, BT_CORE63_SMP_D3_N1_HEX, 16);
	HEX_LE(n2, BT_CORE63_SMP_D3_N2_HEX, 16);
	HEX_LE(a1, BT_CORE63_SMP_D3_A1_HEX, 7);
	HEX_LE(a2, BT_CORE63_SMP_D3_A2_HEX, 7);
	HEX_LE(expected_mackey, BT_CORE63_SMP_D3_MACKEY_HEX, 16);
	HEX_LE(expected_ltk, BT_CORE63_SMP_D3_LTK_HEX, 16);
	uint8_t mackey[16], ltk[16];

	ATF_REQUIRE(smp_f5(w, n1, n2, a1, a2, mackey, ltk) == 0);
	ATF_CHECK_EQ(memcmp(mackey, expected_mackey, sizeof(mackey)), 0);
	ATF_CHECK_EQ(memcmp(ltk, expected_ltk, sizeof(ltk)), 0);
	ATF_CHECK(memcmp(mackey, ltk, sizeof(mackey)) != 0);
}

/* ================================================================
 * Test: smp_verify_signature with known-good data
 *
 * Build a message, compute the CMAC using a known CSRK, then verify
 * smp_verify_signature returns true.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_verify_signature_valid);
ATF_TC_BODY(test_smp_verify_signature_valid, tc)
{
	uint8_t csrk[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};
	uint8_t msg[16];
	uint8_t mac[8];
	uint32_t counter = 42;

	memset(msg, 0xAA, sizeof(msg));
	ATF_REQUIRE(reference_signature(csrk, msg, sizeof(msg), counter,
	    mac) == 0);

	ATF_CHECK(smp_verify_signature(csrk, msg, sizeof(msg),
	    mac, counter));
}

/* Test: smp_verify_signature with tampered MAC */
ATF_TC_WITHOUT_HEAD(test_smp_verify_signature_invalid);
ATF_TC_BODY(test_smp_verify_signature_invalid, tc)
{
	uint8_t csrk[16] = { 1 };
	uint8_t msg[16];
	uint8_t mac[8];

	memset(msg, 0xAA, sizeof(msg));
	ATF_REQUIRE(reference_signature(csrk, msg, sizeof(msg), 0, mac) == 0);
	mac[3] ^= 0x01; /* A one-bit authentication-signature mutation must fail. */

	ATF_CHECK(!smp_verify_signature(csrk, msg, sizeof(msg), mac, 0));
}

/* Test: smp_verify_signature with wrong counter */
ATF_TC_WITHOUT_HEAD(test_smp_verify_signature_wrong_counter);
ATF_TC_BODY(test_smp_verify_signature_wrong_counter, tc)
{
	uint8_t csrk[16] = {
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
		0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
	};
	uint8_t msg[4] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t mac[8];
	uint32_t correct_counter = 100;
	uint32_t wrong_counter = 999;

	ATF_REQUIRE(reference_signature(csrk, msg, sizeof(msg),
	    correct_counter, mac) == 0);

	/* Verify with correct counter succeeds */
	ATF_CHECK(smp_verify_signature(csrk, msg, sizeof(msg),
	    mac, correct_counter));

	/* Verify with wrong counter fails */
	ATF_CHECK(!smp_verify_signature(csrk, msg, sizeof(msg),
	    mac, wrong_counter));
}

/* Test: smp_aes128 with all-zero key */
ATF_TC_WITHOUT_HEAD(test_smp_aes128_zero_key);
ATF_TC_BODY(test_smp_aes128_zero_key, tc)
{
	uint8_t key[16], in[16], out[16];
	HEX_LE(expected, NIST_AES128_ZERO_CIPHERTEXT_HEX, 16);

	memset(key, 0, sizeof(key));
	memset(in, 0, sizeof(in));

	ATF_REQUIRE(smp_aes128(key, in, out) == 0);
	ATF_CHECK_EQ_MSG(memcmp(out, expected, sizeof(out)), 0,
	    "AES-128 zero-key known-answer mismatch");
}

/* Test: smp_aes_cmac with message exactly 16 bytes (block boundary) */
ATF_TC_WITHOUT_HEAD(test_smp_aes_cmac_block_boundary);
ATF_TC_BODY(test_smp_aes_cmac_block_boundary, tc)
{
	/*
	 * This is already covered by test_smp_aes_cmac_len16 (D.1.2),
	 * but we add an independent test with a different key to ensure
	 * the single-block path works generically.
	 */
	uint8_t key[16], msg[16], mac[16], expected[16];

	memset(key, 0x42, sizeof(key));
	memset(msg, 0xBB, sizeof(msg));
	ATF_REQUIRE(reference_cmac(key, msg, sizeof(msg), expected) == 0);
	ATF_REQUIRE(smp_aes_cmac(key, msg, sizeof(msg), mac) == 0);
	ATF_CHECK_EQ_MSG(memcmp(mac, expected, sizeof(mac)), 0,
	    "complete-block CMAC differs from independent RFC 4493 oracle");
}

/* Bluetooth Core 6.3, Vol 3, Part H, §3.4: pairing timeout is 30 s. */
ATF_TC_WITHOUT_HEAD(test_smp_pairing_expired);
ATF_TC_BODY(test_smp_pairing_expired, tc)
{
	const struct timespec start = { .tv_sec = 100, .tv_nsec = 900000000 };
	struct timespec now;

	/* One nanosecond before the independently generated 30 s boundary. */
	now.tv_sec = start.tv_sec + BT_CORE63_SMP_PAIRING_TIMEOUT_SECONDS;
	now.tv_nsec = start.tv_nsec - 1;
	ATF_CHECK(!smp_pairing_expired_at(&start, &now));

	/* Exactly 30 s is the timeout boundary specified by §3.4. */
	now.tv_nsec = start.tv_nsec;
	ATF_CHECK(smp_pairing_expired_at(&start, &now));

	/* A normalized timestamp after nanosecond rollover remains expired. */
	now.tv_sec++;
	now.tv_nsec = 0;
	ATF_CHECK(smp_pairing_expired_at(&start, &now));
}

/* ================================================================
 * Test: bond DB save/load round-trip with comprehensive fields.
 *
 * Create a bond_db with 2 bonds populated with LTK, IRK, CSRK,
 * name, db_hash, CCCDs, and handle cache.  Save, reload, verify.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_db_save_load_roundtrip);
ATF_TC_BODY(test_bond_db_save_load_roundtrip, tc)
{
	struct smp_bond_db db1, db2;
	char path[] = "/tmp/blued_test_rt.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	memset(&db1, 0, sizeof(db1));
	db1.fd = fd;
	db1.count = 2;

	/* Local IRK/CSRK */
	memset(db1.local_irk, 0xF0, 16);
	db1.has_local_irk = true;
	memset(db1.local_csrk, 0xF1, 16);
	db1.has_local_csrk = true;

	/* Bond 0: fully populated */
	{
		struct smp_bond *b = &db1.bonds[0];
		memset(b->addr, 0xAA, 6);
		b->addr_type = BLUED_BOND_ADDR_RANDOM;
		memset(b->ltk, 0x11, 16);
		b->has_ltk = true;
		memset(b->irk, 0x22, 16);
		b->has_irk = true;
		memset(b->csrk, 0x33, 16);
		b->has_csrk = true;
		b->peer_sign_counter = 42;
		strlcpy(b->name, "TestDevice", sizeof(b->name));
		b->has_name = true;
		memset(b->db_hash, 0x44, 16);
		b->has_db_hash = true;
		b->is_sc = true;
		b->is_mitm = true;
		/* CCCDs */
		b->num_cccds = 2;
		b->cccds[0].handle = 0x0010;
		b->cccds[0].value = BT_CORE63_CCCD_NOTIFY_ENABLED;
		b->cccds[1].handle = 0x0020;
		b->cccds[1].value = BT_CORE63_CCCD_INDICATE_ENABLED;
		/* Handle cache */
		b->has_handle_cache = true;
		b->hid_svc_start = 0x0100;
		b->hid_svc_end = 0x0120;
		b->bat_svc_start = 0x0200;
		b->bat_svc_end = 0x0210;
		b->report_map_handle = 0x0105;
		b->hid_info_handle = 0x0106;
		b->protocol_mode_handle = 0x0107;
		b->num_reports = 1;
		b->report_handles[0] = 0x0110;
		b->report_cccd_handles[0] = 0x0111;
		b->report_types[0] = 1;
		b->report_ids[0] = 0;
		b->battery_level_handle = 0x0205;
		b->battery_cccd_handle = 0x0206;
	}

	/* Bond 1: minimal — only LTK */
	{
		struct smp_bond *b = &db1.bonds[1];
		memset(b->addr, 0xBB, 6);
		b->addr_type = BLUED_BOND_ADDR_PUBLIC;
		memset(b->ltk, 0x55, 16);
		b->has_ltk = true;
	}

	enable_atomic_bond_save(&db1, path);
	ATF_REQUIRE_EQ(smp_bond_db_save(&db1), 0);

	/* Load into fresh db */
	memset(&db2, 0, sizeof(db2));
	enable_atomic_bond_save(&db2, path);
	ATF_REQUIRE_EQ(smp_bond_db_load(&db2, fd), 0);

	/* Verify count */
	ATF_CHECK_EQ(db2.count, 2);
	ATF_CHECK(db2.has_local_irk);
	ATF_CHECK(memcmp(db2.local_irk, db1.local_irk, 16) == 0);
	ATF_CHECK(db2.has_local_csrk);
	ATF_CHECK(memcmp(db2.local_csrk, db1.local_csrk, 16) == 0);

	/* Verify bond 0 fields */
	{
		struct smp_bond *b = &db2.bonds[0];
		ATF_CHECK(memcmp(b->addr, db1.bonds[0].addr, 6) == 0);
		ATF_CHECK_EQ(b->addr_type, BLUED_BOND_ADDR_RANDOM);
		ATF_CHECK(b->has_ltk);
		ATF_CHECK(memcmp(b->ltk, db1.bonds[0].ltk, 16) == 0);
		ATF_CHECK(b->has_irk);
		ATF_CHECK(memcmp(b->irk, db1.bonds[0].irk, 16) == 0);
		ATF_CHECK(b->has_csrk);
		ATF_CHECK(memcmp(b->csrk, db1.bonds[0].csrk, 16) == 0);
		ATF_CHECK_EQ(b->peer_sign_counter, 42u);
		ATF_CHECK(b->has_name);
		ATF_CHECK_STREQ(b->name, "TestDevice");
		ATF_CHECK(b->has_db_hash);
		ATF_CHECK(memcmp(b->db_hash, db1.bonds[0].db_hash, 16) == 0);
		ATF_CHECK(b->is_sc);
		ATF_CHECK(b->is_mitm);
		ATF_CHECK_EQ(b->num_cccds, 2);
		ATF_CHECK_EQ(b->cccds[0].handle, 0x0010);
		ATF_CHECK_EQ(b->cccds[0].value, BT_CORE63_CCCD_NOTIFY_ENABLED);
		ATF_CHECK_EQ(b->cccds[1].handle, 0x0020);
		ATF_CHECK_EQ(b->cccds[1].value, BT_CORE63_CCCD_INDICATE_ENABLED);
		ATF_CHECK(b->has_handle_cache);
		ATF_CHECK_EQ(b->hid_svc_start, 0x0100);
		ATF_CHECK_EQ(b->hid_svc_end, 0x0120);
		ATF_CHECK_EQ(b->bat_svc_start, 0x0200);
		ATF_CHECK_EQ(b->bat_svc_end, 0x0210);
		ATF_CHECK_EQ(b->report_map_handle, 0x0105);
		ATF_CHECK_EQ(b->num_reports, 1);
		ATF_CHECK_EQ(b->report_handles[0], 0x0110);
		ATF_CHECK_EQ(b->battery_level_handle, 0x0205);
		ATF_CHECK_EQ(b->battery_cccd_handle, 0x0206);
	}

	/* Verify bond 1 fields */
	{
		struct smp_bond *b = &db2.bonds[1];
		ATF_CHECK(memcmp(b->addr, db1.bonds[1].addr, 6) == 0);
		ATF_CHECK_EQ(b->addr_type, BLUED_BOND_ADDR_PUBLIC);
		ATF_CHECK(b->has_ltk);
		ATF_CHECK(memcmp(b->ltk, db1.bonds[1].ltk, 16) == 0);
		ATF_CHECK(!b->has_irk);
		ATF_CHECK(!b->has_csrk);
		ATF_CHECK(!b->has_name);
		ATF_CHECK(!b->has_db_hash);
	}

	/* Verify local IRK was round-tripped */
	ATF_CHECK(db2.has_local_irk);
	ATF_CHECK(memcmp(db2.local_irk, db1.local_irk, 16) == 0);

	close(fd);
	unlink(path);
}

/* Current encrypted format round-trip; no older schema is accepted. */
ATF_TC_WITHOUT_HEAD(test_bond_db_current_format_roundtrip);
ATF_TC_BODY(test_bond_db_current_format_roundtrip, tc)
{
	struct smp_bond_db db1, db2;
	char path[] = "/tmp/blued_test_current.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	memset(&db1, 0, sizeof(db1));
	db1.fd = fd;
	db1.count = 1;

	/* Populate a bond with known values */
	memset(db1.bonds[0].addr, 0xCC, 6);
	db1.bonds[0].addr_type = BLUED_BOND_ADDR_RANDOM;
	memset(db1.bonds[0].ltk, 0x77, 16);
	db1.bonds[0].has_ltk = true;
	db1.bonds[0].is_sc = true;

	/* Save and load the exact current record layout. */
	enable_atomic_bond_save(&db1, path);
	ATF_REQUIRE_EQ(smp_bond_db_save(&db1), 0);

	memset(&db2, 0, sizeof(db2));
	enable_atomic_bond_save(&db2, path);
	ATF_REQUIRE_EQ(smp_bond_db_load(&db2, fd), 0);

	ATF_CHECK_EQ(db2.count, 1);
	ATF_CHECK(memcmp(db2.bonds[0].addr, db1.bonds[0].addr, 6) == 0);
	ATF_CHECK(db2.bonds[0].has_ltk);
	ATF_CHECK(db2.bonds[0].is_sc);

	/* Fields not set in the original remain zero. */
	ATF_CHECK(!db2.bonds[0].has_irk);
	ATF_CHECK(!db2.bonds[0].has_csrk);
	ATF_CHECK(!db2.bonds[0].has_name);
	ATF_CHECK(!db2.bonds[0].has_db_hash);
	ATF_CHECK(!db2.bonds[0].has_handle_cache);
	ATF_CHECK_EQ(db2.bonds[0].num_cccds, 0);

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test: smp_generate_rpa produces a valid RPA that resolves
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_generate_rpa);
ATF_TC_BODY(test_smp_generate_rpa, tc)
{
	HEX_LE(irk, BT_CORE63_SMP_D7_IRK_HEX, 16);
	uint8_t rpa[6];

	smp_generate_rpa(irk, rpa);

	/* Upper 2 bits of MSB must be 01 (RPA marker) */
	ATF_CHECK_EQ(rpa[5] & BT_CORE63_RANDOM_ADDRESS_TYPE_MASK,
	    BT_CORE63_RANDOM_ADDRESS_RESOLVABLE);

	/* Generated RPA must resolve against the same IRK */
	ATF_CHECK(smp_rpa_matches(irk, rpa));

	/* Must NOT resolve against a different IRK */
	{
		uint8_t wrong_irk[16];
		memset(wrong_irk, 0xFF, sizeof(wrong_irk));
		ATF_CHECK(!smp_rpa_matches(wrong_irk, rpa));
	}

	/* Two consecutive generations should produce different RPAs */
	{
		uint8_t rpa2[6];
		smp_generate_rpa(irk, rpa2);
		ATF_CHECK(memcmp(rpa, rpa2, 6) != 0);
	}
}

/* ================================================================
 * Test: smp_swap_buf with zero length — should not crash.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_swap_buf_zero_len);
ATF_TC_BODY(test_smp_swap_buf_zero_len, tc)
{
	uint8_t src[4] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t dst[4] = { 0xFF, 0xFF, 0xFF, 0xFF };

	smp_swap_buf(dst, src, 0);
	/* dst should be unchanged */
	ATF_CHECK_EQ(dst[0], 0xFF);
}

/* ================================================================
 * Test: smp_swap_buf with odd length.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_swap_buf_odd_len);
ATF_TC_BODY(test_smp_swap_buf_odd_len, tc)
{
	uint8_t src[5] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
	uint8_t dst[5];
	uint8_t expected[5] = { 0x05, 0x04, 0x03, 0x02, 0x01 };

	smp_swap_buf(dst, src, 5);
	ATF_CHECK_EQ(memcmp(dst, expected, 5), 0);
}

/* ================================================================
 * Test: smp_c1 with non-zero TK (passkey entry case).
 *
 * This tests the code path where TK is not all zeros, which is
 * the Passkey Entry case in LE Legacy Pairing.
 * Bug #3 (passkey TK byte-order): verify TK is correctly XOR'd.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_c1_nonzero_tk);
ATF_TC_BODY(test_smp_c1_nonzero_tk, tc)
{
	uint8_t r[16];
	uint8_t preq[7], pres[7];
	uint8_t ia[6], ra[6];
	uint8_t confirm1[16], confirm2[16];

	/* Core §2.3.5.3: passkey 019655 maps to this 128-bit TK. */
	HEX_LE(k, BT_CORE63_SMP_LEGACY_PASSKEY_TK_HEX, 16);

	arc4random_buf(r, sizeof(r));
	memset(preq, 0x07, sizeof(preq));
	memset(pres, 0x05, sizeof(pres));
	memset(ia, 0xA1, sizeof(ia));
	memset(ra, 0xB1, sizeof(ra));

	ATF_REQUIRE(smp_c1(k, r, preq, pres, 0x01, ia, 0x00, ra,
	    confirm1) == 0);

	/* Same inputs must produce same output (deterministic) */
	ATF_REQUIRE(smp_c1(k, r, preq, pres, 0x01, ia, 0x00, ra,
	    confirm2) == 0);
	ATF_CHECK_EQ(memcmp(confirm1, confirm2, 16), 0);

	/* Different TK must produce different confirm */
	k[0] ^= 0x01;
	ATF_REQUIRE(smp_c1(k, r, preq, pres, 0x01, ia, 0x00, ra,
	    confirm2) == 0);
	ATF_CHECK(memcmp(confirm1, confirm2, 16) != 0);
}

/* ================================================================
 * Test: smp_select_model with out-of-range IO capabilities.
 *
 * Bug #13: IO capability values > 4 are reserved. The function
 * must return SMP_MODEL_INVALID (-1) to trigger rejection.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_select_model_invalid_io);
ATF_TC_BODY(test_smp_select_model_invalid_io, tc)
{
	unsigned int io;

	/* Core Table 3.4 reserves every one-octet value from 0x05 to 0xff. */
	for (io = BT_CORE63_SMP_IO_RESERVED_FIRST;
	    io <= BT_CORE63_SMP_IO_RESERVED_LAST; io++) {
		ATF_CHECK_EQ(smp_select_model((uint8_t)io,
		    SMP_IO_DISPLAY_ONLY, false), SMP_MODEL_INVALID);
		ATF_CHECK_EQ(smp_select_model((uint8_t)io,
		    SMP_IO_DISPLAY_ONLY, true), SMP_MODEL_INVALID);
		ATF_CHECK_EQ(smp_select_model(SMP_IO_DISPLAY_ONLY,
		    (uint8_t)io, false), SMP_MODEL_INVALID);
		ATF_CHECK_EQ(smp_select_model(SMP_IO_DISPLAY_ONLY,
		    (uint8_t)io, true), SMP_MODEL_INVALID);
	}
}

/* ================================================================
 * Test: smp_f4 with the passkey Z values from Core Section 2.2.6.
 *
 * Bug #14: During SC passkey entry, f4 is called with z = 0x80 | bit_i
 * for each passkey bit. Ensure the function handles z != 0 correctly.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_f4_passkey_bit);
ATF_TC_BODY(test_smp_f4_passkey_bit, tc)
{
	uint8_t u[32], v[32], x[16];
	uint8_t out_z0[16], out_z80[16], out_z81[16];

	memset(u, 0x42, sizeof(u));
	memset(v, 0x43, sizeof(v));
	memset(x, 0x44, sizeof(x));

	ATF_CHECK_EQ(SMP_F4_PASSKEY_Z(0),
	    BT_CORE63_SMP_F4_Z_PASSKEY_ZERO);
	ATF_CHECK_EQ(SMP_F4_PASSKEY_Z(1),
	    BT_CORE63_SMP_F4_Z_PASSKEY_ONE);
	smp_f4(u, v, x, BT_CORE63_SMP_F4_Z_NUMERIC_OOB, out_z0);
	smp_f4(u, v, x, BT_CORE63_SMP_F4_Z_PASSKEY_ZERO, out_z80);
	smp_f4(u, v, x, BT_CORE63_SMP_F4_Z_PASSKEY_ONE, out_z81);

	/* Different z values must produce different outputs */
	ATF_CHECK(memcmp(out_z0, out_z80, 16) != 0);
	ATF_CHECK(memcmp(out_z80, out_z81, 16) != 0);
	ATF_CHECK(memcmp(out_z0, out_z81, 16) != 0);
}

/* ================================================================
 * Test: bond_db_store updates existing bond in-place.
 *
 * Bug #6: Without proper locking/update, bond_db_store might
 * append a duplicate instead of updating. Verify that storing
 * a bond for the same address replaces the existing entry.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_db_store_update_existing);
ATF_TC_BODY(test_bond_db_store_update_existing, tc)
{
	struct smp_bond_db db;
	struct smp_bond bond;
	char path[] = "/tmp/blued_test_upd.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	memset(&db, 0, sizeof(db));
	db.fd = fd;

	/* Store initial bond */
	memset(&bond, 0, sizeof(bond));
	bond.addr[0] = 0xAA;
	bond.addr_type = BLUED_BOND_ADDR_RANDOM;
	memset(bond.ltk, 0x11, 16);
	bond.has_ltk = true;
	smp_bond_db_store(&db, &bond);
	ATF_CHECK_EQ(db.count, 1);

	/* Update same bond with different LTK */
	memset(bond.ltk, 0x22, 16);
	smp_bond_db_store(&db, &bond);

	/* Count must remain 1, not 2 */
	ATF_CHECK_EQ(db.count, 1);
	/* LTK must be the updated value */
	ATF_CHECK_EQ(db.bonds[0].ltk[0], 0x22);

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test: bond_db_store eviction — when full, the oldest bond is
 * evicted and the new bond goes at the end.
 *
 * Bug #7: Eviction with memmove could leave stale data if not
 * zero'd before overwrite.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_db_eviction_order);
ATF_TC_BODY(test_bond_db_eviction_order, tc)
{
	struct smp_bond_db db;
	struct smp_bond bond;
	char path[] = "/tmp/blued_test_evict.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	memset(&db, 0, sizeof(db));
	db.fd = fd;

	/* Fill to capacity */
	ATF_REQUIRE_EQ(SMP_MAX_BONDS, BLUED_BOND_DB_MAX_RECORDS);
	for (int i = 0; i < BLUED_BOND_DB_MAX_RECORDS; i++) {
		memset(&bond, 0, sizeof(bond));
		bond.addr[0] = (uint8_t)i;
		bond.addr_type = BLUED_BOND_ADDR_PUBLIC;
		bond.has_ltk = true;
		memset(bond.ltk, (uint8_t)i, 16);
		smp_bond_db_store(&db, &bond);
	}
	ATF_CHECK_EQ(db.count, BLUED_BOND_DB_MAX_RECORDS);

	/* Verify first entry is addr[0]=0 */
	ATF_CHECK_EQ(db.bonds[0].addr[0], 0x00);

	/* Store one more — should evict bonds[0] (addr=0) */
	memset(&bond, 0, sizeof(bond));
	bond.addr[0] = 0xFF;
	bond.addr_type = BLUED_BOND_ADDR_PUBLIC;
	bond.has_ltk = true;
	memset(bond.ltk, 0xFF, 16);
	smp_bond_db_store(&db, &bond);

	ATF_CHECK_EQ(db.count, BLUED_BOND_DB_MAX_RECORDS);
	/* First entry should now be addr[0]=1 (shifted up) */
	ATF_CHECK_EQ(db.bonds[0].addr[0], 0x01);
	/* Last entry should be the new bond */
	ATF_CHECK_EQ(db.bonds[BLUED_BOND_DB_MAX_RECORDS - 1].addr[0], 0xFF);
	ATF_CHECK_EQ(db.bonds[BLUED_BOND_DB_MAX_RECORDS - 1].ltk[0], 0xFF);

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test: smp_rpa_matches with non-resolvable address returns false.
 *
 * RPA has upper 2 bits of addr[5] = 01. A static random address
 * (bits = 11) should never match any IRK.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_rpa_not_resolvable);
ATF_TC_BODY(test_smp_rpa_not_resolvable, tc)
{
	uint8_t irk[16];
	uint8_t addr[6];

	arc4random_buf(irk, sizeof(irk));
	arc4random_buf(addr, sizeof(addr));

	/* Static random address: upper 2 bits = 11 */
	addr[5] = (addr[5] &
	    (uint8_t)~BT_CORE63_RANDOM_ADDRESS_TYPE_MASK) |
	    BT_CORE63_RANDOM_ADDRESS_STATIC;
	ATF_CHECK(!smp_rpa_matches(irk, addr));

	/* Non-resolvable private address: upper 2 bits = 00 */
	addr[5] = (addr[5] &
	    (uint8_t)~BT_CORE63_RANDOM_ADDRESS_TYPE_MASK) |
	    BT_CORE63_RANDOM_ADDRESS_NONRESOLVABLE;
	ATF_CHECK(!smp_rpa_matches(irk, addr));
}

/* ================================================================
 * Test: smp_find_bond returns NULL when db is empty.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_find_bond_empty);
ATF_TC_BODY(test_smp_find_bond_empty, tc)
{
	struct smp_bond_db db;
	uint8_t addr[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

	memset(&db, 0, sizeof(db));
	ATF_CHECK(smp_find_bond(&db, addr,
	    BLUED_BOND_ADDR_PUBLIC) == NULL);
}

/* ================================================================
 * Test: smp_find_bond matches on both address AND addr_type.
 *
 * Bug #5: A bond for public address AA:BB:... should NOT match
 * a random address AA:BB:... — addr_type must be compared.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_find_bond_addr_type_matters);
ATF_TC_BODY(test_smp_find_bond_addr_type_matters, tc)
{
	struct smp_bond_db db;
	struct smp_bond bond;
	struct smp_bond *found;
	uint8_t addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	char path[] = "/tmp/blued_test_atm.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	memset(&db, 0, sizeof(db));
	db.fd = fd;

	/* Store bond with addr_type = public (0x00) */
	memset(&bond, 0, sizeof(bond));
	memcpy(bond.addr, addr, 6);
	bond.addr_type = BLUED_BOND_ADDR_PUBLIC;
	bond.has_ltk = true;
	smp_bond_db_store(&db, &bond);

	/* Look up with same addr but random type (0x01) — should NOT find */
	found = smp_find_bond(&db, addr, BLUED_BOND_ADDR_RANDOM);
	ATF_CHECK(found == NULL);

	/* Look up with correct type — should find */
	found = smp_find_bond(&db, addr, BLUED_BOND_ADDR_PUBLIC);
	ATF_CHECK(found != NULL);

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test: smp_aes128 byte-order adapter against a fixed external KAT.
 *
 * Bug #10: smp_aes128 reverses input/output for SMP's LE convention.
 * Verify exact little-octet-first adaptation around the FIPS 197 example.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_aes128_byte_order_roundtrip);
ATF_TC_BODY(test_smp_aes128_byte_order_roundtrip, tc)
{
	/*
	 * Known AES-128 ECB test vector (NIST FIPS 197 Appendix B):
	 * Key (BE):   2b7e1516 28aed2a6 abf71588 09cf4f3c
	 * Plain (BE): 3243f6a8 885a308d 313198a2 e0370734
	 * Cipher(BE): 3925841d 02dc09fb dc118597 196a0b32
	 *
	 * smp_aes128 takes LE inputs and produces LE output.
	 */
	HEX_LE(key, "2b7e151628aed2a6abf7158809cf4f3c", 16);
	HEX_LE(plain, "3243f6a8885a308d313198a2e0370734", 16);
	HEX_LE(expected, "3925841d02dc09fbdc118597196a0b32", 16);

	uint8_t out[16];
	ATF_REQUIRE(smp_aes128(key, plain, out) == 0);
	ATF_CHECK_EQ_MSG(memcmp(out, expected, 16), 0,
	    "smp_aes128 byte-order round-trip failed with NIST vector");
}

/* ================================================================
 * Test: smp_ctkd_derive_link_key requires SC bond.
 *
 * Bug #15: CTKD should fail for legacy (non-SC) bonds.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_ctkd_requires_sc);
ATF_TC_BODY(test_smp_ctkd_requires_sc, tc)
{
	struct smp_bond bond;

	memset(&bond, 0, sizeof(bond));
	bond.is_sc = false;		/* legacy bond */
	bond.has_ltk = true;
	bond.is_mitm = true;
	memset(bond.ltk, 0x42, 16);

	/* CTKD should fail for non-SC bonds */
	int ret = smp_ctkd_derive_link_key(&bond, true);
	ATF_CHECK(ret != 0);

	/* bond.has_link_key should remain false */
	ATF_CHECK(!bond.has_link_key);
}

/* ================================================================
 * Test: smp_ctkd_derive_link_key requires MITM.
 *
 * Local hardening policy: current Core permits same-strength derivation from
 * Secure Connections material, including unauthenticated material; blued is
 * deliberately stricter and declines to promote a Just Works key.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_ctkd_requires_mitm);
ATF_TC_BODY(test_smp_ctkd_requires_mitm, tc)
{
	struct smp_bond bond;

	memset(&bond, 0, sizeof(bond));
	bond.is_sc = true;
	bond.has_ltk = true;
	bond.is_mitm = false;	/* no MITM */
	memset(bond.ltk, 0x42, 16);

	int ret = smp_ctkd_derive_link_key(&bond, true);
	/* Function returns 0 (success) but skips derivation when !is_mitm */
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK(!bond.has_link_key);
}

/* ================================================================
 * Test: smp_verify_signature with zero-length message.
 *
 * Edge case: the Signed Write protocol uses msg = (ATT opcode
 * + handle + value), so empty value means msg_len could be as
 * small as 3 bytes. But verify the zero-length edge doesn't crash.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_verify_signature_empty_msg);
ATF_TC_BODY(test_smp_verify_signature_empty_msg, tc)
{
	uint8_t csrk[16] = {
		0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
		0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0
	};
	uint8_t mac[8];
	uint32_t counter = 0;

	ATF_REQUIRE(reference_signature(csrk, NULL, 0, counter, mac) == 0);

	ATF_CHECK(smp_verify_signature(csrk, NULL, 0, mac, counter));

	/* Invalid pointers and overflowing msg_len fail before allocation/copy. */
	ATF_CHECK(!smp_verify_signature(NULL, NULL, 0, mac, counter));
	ATF_CHECK(!smp_verify_signature(csrk, csrk, 1, NULL, counter));
	ATF_CHECK(!smp_verify_signature(csrk, NULL, 1, mac, counter));
	ATF_CHECK(!smp_verify_signature(csrk, csrk, SIZE_MAX, mac, counter));
}

/* ================================================================
 * Test: bond DB save/load round-trip with CCCD persistence.
 *
 * Bug #4: CCCD values must survive save/load for bonded devices.
 * Core 6.3 Vol 3 Part G §3.3.3.3 requires the descriptor value to be
 * persistent across connections for bonded devices; Table 3.11 assigns
 * notification bit 0 and indication bit 1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_cccd_persistence);
ATF_TC_BODY(test_bond_cccd_persistence, tc)
{
	struct smp_bond_db db1, db2;
	char path[] = "/tmp/blued_test_cccd.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	memset(&db1, 0, sizeof(db1));
	db1.fd = fd;
	db1.count = 1;

	/* Bond with 3 CCCDs */
	memset(db1.bonds[0].addr, 0xAA, 6);
	db1.bonds[0].addr_type = BLUED_BOND_ADDR_RANDOM;
	db1.bonds[0].has_ltk = true;
	memset(db1.bonds[0].ltk, 0x11, 16);
	db1.bonds[0].num_cccds = 3;
	db1.bonds[0].cccds[0].handle = 0x0010;
	db1.bonds[0].cccds[0].value = BT_CORE63_CCCD_NOTIFY_ENABLED;
	db1.bonds[0].cccds[1].handle = 0x0020;
	db1.bonds[0].cccds[1].value = BT_CORE63_CCCD_INDICATE_ENABLED;
	db1.bonds[0].cccds[2].handle = 0x0030;
	db1.bonds[0].cccds[2].value =
	    BT_CORE63_CCCD_NOTIFY_AND_INDICATE_ENABLED;

	enable_atomic_bond_save(&db1, path);
	ATF_REQUIRE_EQ(smp_bond_db_save(&db1), 0);

	/* Reload */
	memset(&db2, 0, sizeof(db2));
	enable_atomic_bond_save(&db2, path);
	ATF_REQUIRE_EQ(smp_bond_db_load(&db2, fd), 0);

	ATF_CHECK_EQ(db2.count, 1);
	ATF_CHECK_EQ(db2.bonds[0].num_cccds, 3);
	ATF_CHECK_EQ(db2.bonds[0].cccds[0].handle, 0x0010);
	ATF_CHECK_EQ(db2.bonds[0].cccds[0].value,
	    BT_CORE63_CCCD_NOTIFY_ENABLED);
	ATF_CHECK_EQ(db2.bonds[0].cccds[1].handle, 0x0020);
	ATF_CHECK_EQ(db2.bonds[0].cccds[1].value,
	    BT_CORE63_CCCD_INDICATE_ENABLED);
	ATF_CHECK_EQ(db2.bonds[0].cccds[2].handle, 0x0030);
	ATF_CHECK_EQ(db2.bonds[0].cccds[2].value,
	    BT_CORE63_CCCD_NOTIFY_AND_INDICATE_ENABLED);

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test: smp_aes_cmac with 1-byte message (not block-aligned).
 *
 * Tests the CMAC padding path for messages shorter than 16 bytes
 * but non-empty and non-block-aligned.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_aes_cmac_len1);
ATF_TC_BODY(test_smp_aes_cmac_len1, tc)
{
	uint8_t key[16], mac[16], expected[16];

	memset(key, 0x42, sizeof(key));

	uint8_t msg = 0xAA;
	ATF_REQUIRE(reference_cmac(key, &msg, 1, expected) == 0);
	ATF_REQUIRE(smp_aes_cmac(key, &msg, 1, mac) == 0);
	ATF_CHECK_EQ_MSG(memcmp(mac, expected, sizeof(mac)), 0,
	    "one-octet CMAC differs from independent RFC 4493 oracle");
}

/* ================================================================
 * Test: smp_f4 spec vector (Core Spec Vol 3 Part H Appendix D.2)
 *
 * Independently verifies f4 against the published test vector.
 * Uses the exact hex values from the spec, converted to LE wire
 * order, and verifies the AES-CMAC output matches byte-for-byte.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_f4_spec_vector);
ATF_TC_BODY(test_smp_f4_spec_vector, tc)
{
	/*
	 * D.2 values (big-endian in spec, reversed to LE for smp_f4):
	 *   U = 20b003d2 f297be2c 5e2c83a7 e9f9a5b9
	 *       eff49111 acf4fddb cc030148 0e359de6
	 *   V = 55188b3d 32f6bb9a 900afcfb eed4e72a
	 *       59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd
	 *   X = d5cb8454 d177733e ffffb2ec 712baeab
	 *   Z = 0x00
	 *   AES_CMAC = f2c916f1 07a9bd1c f1eda1be a974872d
	 */
	HEX_LE(u, BT_CORE63_SMP_D2_U_HEX, 32);
	HEX_LE(v, BT_CORE63_SMP_D2_V_HEX, 32);
	HEX_LE(x, BT_CORE63_SMP_D2_X_HEX, 16);
	HEX_LE(expected, BT_CORE63_SMP_D2_OUT_HEX, 16);

	uint8_t out[16];
	smp_f4(u, v, x, BT_CORE63_SMP_D2_Z, out);

	ATF_CHECK_EQ_MSG(memcmp(out, expected, 16), 0,
	    "smp_f4 spec vector D.2: output mismatch");
}

/* ================================================================
 * Test: smp_f6 spec vector (Core Spec Vol 3 Part H Appendix D.4)
 *
 * Verifies f6 against the published D.4 test vector.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_f6_spec_vector);
ATF_TC_BODY(test_smp_f6_spec_vector, tc)
{
	/*
	 * D.4 values (big-endian in spec, reversed to LE):
	 *   MacKey = 2965f176 a1084a02 fd3f6a20 ce636e20
	 *   N1     = d5cb8454 d177733e ffffb2ec 712baeab
	 *   N2     = a6e8e7cc 25a75f6e 216583f7 ff3dc4cf
	 *   R      = 12a3343b b453bb54 08da42d2 0c2d0fc8
	 *   IOcap  = 010102
	 *   A1     = 00561237 37bfce
	 *   A2     = 00a71370 2dcfc1
	 *   AES_CMAC = e3c47398 9cd0e8c5 d26c0b09 da958f61
	 */
	HEX_LE(mackey, BT_CORE63_SMP_D4_MACKEY_HEX, 16);
	HEX_LE(n1, BT_CORE63_SMP_D4_N1_HEX, 16);
	HEX_LE(n2, BT_CORE63_SMP_D4_N2_HEX, 16);
	HEX_LE(r, BT_CORE63_SMP_D4_R_HEX, 16);
	HEX_LE(iocap, BT_CORE63_SMP_D4_IOCAP_HEX, 3);
	HEX_LE(a1, BT_CORE63_SMP_D4_A1_HEX, 7);
	HEX_LE(a2, BT_CORE63_SMP_D4_A2_HEX, 7);
	HEX_LE(expected, BT_CORE63_SMP_D4_OUT_HEX, 16);

	uint8_t out[16];
	smp_f6(mackey, n1, n2, r, iocap, a1, a2, out);

	ATF_CHECK_EQ_MSG(memcmp(out, expected, 16), 0,
	    "smp_f6 spec vector D.4: output mismatch");
}

/* ================================================================
 * Test: smp_g2 spec vector (Core Spec Vol 3 Part H Appendix D.5)
 *
 * Verifies g2 returns the correct 32-bit numeric comparison value.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_g2_spec_vector);
ATF_TC_BODY(test_smp_g2_spec_vector, tc)
{
	/*
	 * D.5 values (big-endian in spec, reversed to LE):
	 *   U = 20b003d2...0e359de6 (same as D.2)
	 *   V = 55188b3d...f47fc5fd (same as D.2)
	 *   X = d5cb8454 d177733e ffffb2ec 712baeab
	 *   Y = a6e8e7cc 25a75f6e 216583f7 ff3dc4cf
	 *   g2 = 0x2f9ed5ba
	 */
	HEX_LE(u, BT_CORE63_SMP_D5_U_HEX, 32);
	HEX_LE(v, BT_CORE63_SMP_D5_V_HEX, 32);
	HEX_LE(x, BT_CORE63_SMP_D5_X_HEX, 16);
	HEX_LE(y, BT_CORE63_SMP_D5_Y_HEX, 16);

	uint32_t result = 0;

	ATF_CHECK_EQ(0, smp_g2(u, v, x, y, &result));

	ATF_CHECK_EQ_MSG(result, BT_CORE63_SMP_D5_OUT_VALUE,
	    "smp_g2 spec vector D.5: expected 0x2f9ed5ba, got 0x%08x",
	    result);
}

/* ================================================================
 * Test: smp_h6 spec vector (Core Spec Vol 3 Part H Appendix D.6)
 *
 * h6(W, keyID) = AES-CMAC_W(keyID)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_h6_spec_vector);
ATF_TC_BODY(test_smp_h6_spec_vector, tc)
{
	/*
	 * D.6:
	 *   Key (W) = ec0234a3 57c8ad05 341010a6 0a397d9b (BE -> LE)
	 *   keyID   = 6c656272 (BE, stays BE per spec)
	 *   AES_CMAC = 2d9ae102 e76dc91c e8d3a9e2 80b16399 (BE -> LE)
	 */
	HEX_LE(w, BT_CORE63_SMP_D6_KEY_HEX, 16);
	HEX_BE(keyid, BT_CORE63_SMP_D6_KEYID_HEX, 4);
	HEX_LE(expected, BT_CORE63_SMP_D6_OUT_HEX, 16);

	uint8_t out[16];
	smp_h6(w, keyid, out);

	ATF_CHECK_EQ_MSG(memcmp(out, expected, 16), 0,
	    "smp_h6 spec vector D.6: output mismatch");
}

/* ================================================================
 * Test: smp_h7 spec vector (Core Spec Vol 3 Part H Appendix D.8)
 *
 * Note: in the spec's table of contents, D.7 is "ah" and D.8 is "h7".
 * h7(SALT, W) = AES-CMAC_SALT(W)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_h7_spec_vector);
ATF_TC_BODY(test_smp_h7_spec_vector, tc)
{
	/*
	 * D.8:
	 *   Key (W) = ec0234a3 57c8ad05 341010a6 0a397d9b (BE -> LE)
	 *   SALT    = 00000000 00000000 00000000 746D7031 (BE, stays BE)
	 *   AES_CMAC = fb173597 c6a3c0ec d2998c2a 75a57011 (BE -> LE)
	 */
	HEX_LE(w, BT_CORE63_SMP_D8_KEY_HEX, 16);
	HEX_BE(salt, BT_CORE63_SMP_D8_SALT_HEX, 16);
	HEX_LE(expected, BT_CORE63_SMP_D8_OUT_HEX, 16);

	uint8_t out[16];
	smp_h7(salt, w, out);

	ATF_CHECK_EQ_MSG(memcmp(out, expected, 16), 0,
	    "smp_h7 spec vector D.8: output mismatch");
}

/* ================================================================
 * Test: ah (RPA hash function) spec vector
 * Core Spec Vol 3 Part H Appendix D.7
 *
 * ah(k, r) = E(k, r') mod 2^24
 *   r' = padding(13 bytes of 0x00) || prand(3 bytes)
 *
 * D.7 test vector:
 *   IRK   = ec0234a3 57c8ad05 341010a6 0a397d9b (BE)
 *   prand = 708194 (3 bytes, big-endian order in spec)
 *   AES_128 output = 159d5fb7 2ebe2311 a48c1bdc c40dfbaa (BE)
 *   ah    = 0dfbaa (3 least significant bytes of AES output)
 *
 * The ah function is not directly exposed as smp_ah(), but is
 * implemented inline in smp_rpa_matches() and smp_generate_rpa().
 * We replicate the spec computation using smp_aes128 and verify
 * the hash output matches.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_ah_spec_vector);
ATF_TC_BODY(test_smp_ah_spec_vector, tc)
{
	/*
	 * IRK from D.7 in LE wire order (reversed from spec BE).
	 * BE: ec0234a3 57c8ad05 341010a6 0a397d9b
	 */
	HEX_LE(irk, BT_CORE63_SMP_D7_IRK_HEX, 16);

	/*
	 * prand from D.7: the spec shows the full 16-byte plaintext as
	 *   00000000 00000000 00000000 00708194
	 * In LE wire order (byte[0] = LSB), prand occupies bytes [0..2]:
	 *   BE "00708194" -> full plaintext reversed = 94810700...00
	 * Actually, prand is 3 bytes: spec shows "708194" reading
	 * right-to-left from the 16-byte value.
	 *
	 * smp_rpa_matches places prand in plaintext[0..2] in LE order:
	 *   plaintext[0] = prand[0] (LSB)
	 *   plaintext[1] = prand[1]
	 *   plaintext[2] = prand[2] (MSB, has bits[7:6]=01)
	 *
	 * From the D.7 full plaintext in BE:
	 *   00000000 00000000 00000000 00708194
	 * In LE (reversed): 94810700 00000000 00000000 00000000
	 * So plaintext[0]=0x94, plaintext[1]=0x81, plaintext[2]=0x70
	 */
	HEX_LE(plaintext, BT_CORE63_SMP_D7_PRAND_HEX, 16);
	HEX_LE(expected_cipher, BT_CORE63_SMP_D7_AES_OUT_HEX, 16);
	HEX_LE(expected_ah, BT_CORE63_SMP_D7_AH_HEX, 3);
	uint8_t cipher[16];

	ATF_REQUIRE(smp_aes128(irk, plaintext, cipher) == 0);

	/*
	 * Expected AES output in BE: 159d5fb7 2ebe2311 a48c1bdc c40dfbaa
	 * In LE (reversed): aafb0dc4 dc1b8ca4 1123be2e b75f9d15
	 * So cipher[0]=0xaa, cipher[1]=0xfb, cipher[2]=0x0d
	 *
	 * ah = least significant 24 bits = cipher[0..2] in LE
	 * Expected ah from spec: 0dfbaa (BE) -> {0xaa, 0xfb, 0x0d} in LE
	 */
	ATF_CHECK_EQ_MSG(memcmp(cipher, expected_cipher, sizeof(cipher)), 0,
	    "ah D.7 full AES-128 output mismatch");
	ATF_CHECK_EQ_MSG(memcmp(cipher, expected_ah, sizeof(expected_ah)), 0,
	    "ah D.7 truncated hash mismatch");

	/*
	 * Also verify via smp_rpa_matches: build an RPA from this
	 * D.7 test vector and confirm it resolves against the IRK.
	 */
	uint8_t rpa[6];
	rpa[0] = expected_ah[0];
	rpa[1] = expected_ah[1];
	rpa[2] = expected_ah[2];
	rpa[3] = plaintext[0];	/* prand LSB = 0x94 */
	rpa[4] = plaintext[1];	/* prand     = 0x81 */
	rpa[5] = plaintext[2];	/* prand MSB = 0x70, bits[7:6]=01 */

	ATF_CHECK_MSG(smp_rpa_matches(irk, rpa),
	    "RPA built from D.7 spec vector does not resolve against IRK");
}

/* ================================================================
 * SC Debug Key rejection tests.
 *
 * smp_validate_public_key (smp_crypto.c) must reject the well-known
 * SC Debug Public Key (Core Spec Vol 3 Part H Section 2.3.5.6.1).
 * Declared in smp_internal.h — provide local declaration for tests.
 * ================================================================ */

/* Forward-declare smp_validate_public_key (from smp_internal.h) */
int	smp_validate_public_key(const uint8_t *, const uint8_t *);

ATF_TC_WITHOUT_HEAD(test_sc_debug_key_x_match);
ATF_TC_BODY(test_sc_debug_key_x_match, tc)
{
	HEX_BE(sc_debug_x, BT_CORE63_SMP_SC_DEBUG_X_HEX, 32);
	HEX_BE(sc_debug_y, BT_CORE63_SMP_SC_DEBUG_Y_HEX, 32);

	/*
	 * Both X and Y match the debug key -- must be rejected.
	 */
	ATF_CHECK_EQ_MSG(smp_validate_public_key(sc_debug_x, sc_debug_y), -1,
	    "smp_validate_public_key must reject the SC Debug Public Key");
}

ATF_TC_WITHOUT_HEAD(test_sc_debug_key_y_match);
ATF_TC_BODY(test_sc_debug_key_y_match, tc)
{
	HEX_BE(sc_debug_x, BT_CORE63_SMP_SC_DEBUG_X_HEX, 32);
	HEX_BE(sc_debug_y, BT_CORE63_SMP_SC_DEBUG_Y_HEX, 32);
	/*
	 * Only X matches the debug key, Y is different -- the point is
	 * not the debug key, and if the (X, modified-Y) is on the curve,
	 * it should be accepted.  If it is not on the curve, it will be
	 * rejected for that reason, not because it is the debug key.
	 *
	 * The important invariant: BOTH coordinates must match for the
	 * debug key rejection to trigger.  A random Y with debug X is
	 * overwhelmingly likely to be off-curve and thus rejected, but
	 * the rejection reason is "not on curve", not "debug key".
	 *
	 * Verify that a modified Y (still with debug X) is rejected
	 * (it will be off-curve):
	 */
	uint8_t modified_y[32];
	memcpy(modified_y, sc_debug_y, 32);
	modified_y[0] ^= 0xFF;	/* flip a byte */

	ATF_CHECK_EQ_MSG(smp_validate_public_key(sc_debug_x, modified_y), -1,
	    "modified debug key Y should be rejected (off-curve)");
}

ATF_TC_WITHOUT_HEAD(test_sc_debug_key_normal_key_accepted);
ATF_TC_BODY(test_sc_debug_key_normal_key_accepted, tc)
{
	/*
	 * Generate a valid P-256 key pair and verify that
	 * smp_validate_public_key accepts it.
	 *
	 * Use the same key generation approach as smp_pairing_test.c:
	 * get the raw public key as an uncompressed octet string
	 * (0x04 || X[32] || Y[32]), then extract X and Y.
	 */
	EVP_PKEY_CTX *pctx;
	EVP_PKEY *pkey = NULL;
	uint8_t pk_raw[65];	/* 0x04 || X || Y */
	size_t pklen;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	ATF_REQUIRE(pctx != NULL);
	ATF_REQUIRE(EVP_PKEY_keygen_init(pctx) > 0);
	ATF_REQUIRE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
	    NID_X9_62_prime256v1) > 0);
	ATF_REQUIRE(EVP_PKEY_keygen(pctx, &pkey) > 0);
	EVP_PKEY_CTX_free(pctx);

	pklen = sizeof(pk_raw);
	ATF_REQUIRE(EVP_PKEY_get_octet_string_param(pkey,
	    OSSL_PKEY_PARAM_PUB_KEY, pk_raw, sizeof(pk_raw), &pklen) > 0);
	ATF_REQUIRE_EQ(pklen, 65u);
	ATF_REQUIRE_EQ(pk_raw[0], 0x04);	/* uncompressed point format */

	/* X = pk_raw[1..32], Y = pk_raw[33..64] (big-endian) */
	ATF_CHECK_EQ_MSG(smp_validate_public_key(pk_raw + 1, pk_raw + 33), 0,
	    "valid P-256 key should be accepted by smp_validate_public_key");

	EVP_PKEY_free(pkey);
}

/* ================================================================
 * KNOB mitigation tests.
 *
 * Core Spec Erratum 11838: SC pairing requires negotiated key size
 * of exactly 16 bytes. Legacy pairing allows the original spec
 * minimum of 7 bytes.
 *
 * smp_pair() enforces this in the key size negotiation logic
 * (smp.c). Here we test the policy at the unit level by verifying
 * the behavior through the smp_pair() call with mock peers.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_knob_min_key_size_16);
ATF_TC_BODY(test_knob_min_key_size_16, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_knob16.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	signal(SIGPIPE, SIG_IGN);

	memset(&db, 0, sizeof(db));
	db.fd = bond_fd;
	memset(&sc, 0, sizeof(sc));
	smp_seed_policy_defaults(&sc);
	sc.fd = smp_fds[0];
	sc.hci_fd = hci_fds[0];
	sc.con_handle = 0x0040;
	memset(sc.local_addr, 0x11, 6);
	sc.local_addr_type = 1; /* BDADDR_LE_PUBLIC */
	memset(sc.remote_addr, 0x22, 6);
	sc.remote_addr_type = 1;
	sc.bond_db = &db;
	sc.io_capability = SMP_IO_NO_INPUT_NO_OUTPUT;
	sc.min_key_size = BT_CORE63_SMP_MAX_KEY_SIZE;

	{
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
		setsockopt(smp_fds[0], SOL_SOCKET, SO_RCVTIMEO,
		    &tv, sizeof(tv));
	}

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);

		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != BT_CORE63_SMP_PAIRING_REQUEST_OPCODE)
			_exit(1);

		/*
		 * Respond with SC flag set but max_key_size = 15.
		 * Negotiated = min(16, 15) = 15 < 16 for SC -> reject.
		 */
		pres[0] = BT_CORE63_SMP_PAIRING_RESPONSE_OPCODE;
		pres[1] = SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = BT_CORE63_SMP_AUTH_BONDING | BT_CORE63_SMP_AUTH_SC;
		pres[4] = BT_CORE63_SMP_MAX_KEY_SIZE - 1;
		pres[5] = 0x00;
		pres[6] = SMP_KEY_DIST_ID_KEY;
		send(peer_fd, pres, sizeof(pres), MSG_EOR);

		/*
		 * Spec-mandated observable: when the resultant encryption key
		 * size is shorter than the device minimum, the device shall
		 * send Pairing Failed with reason "Encryption Key Size" (0x06)
		 * -- Core Spec Vol 3 Part H §2.3.4, Table 3.7.
		 */
		{
			uint8_t buf[65];
			ssize_t m;
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
			m = recv(peer_fd, buf, sizeof(buf), 0);
			if (m < 2 ||
			    buf[0] != BT_CORE63_SMP_PAIRING_FAILED_OPCODE)
				_exit(10);
			if (buf[1] != BT_CORE63_SMP_ENCRYPTION_KEY_SIZE_ERROR)
				_exit(11);
		}

		close(peer_fd);
		_exit(0);
	}

	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, -1,
	    "SC pairing with key size 15 must be rejected (KNOB)");
	ATF_CHECK_EQ_MSG(db.count, 0,
	    "no bond should be stored on KNOB rejection");

	{
		int status;
		waitpid(pid, &status, 0);
		/*
		 * The peer child exits 0 only if it observed Pairing Failed
		 * with reason Encryption Key Size (0x06) per Vol 3 Part H
		 * §2.3.4; 10/11 indicate a wrong/absent reason code.
		 */
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "peer must receive Pairing Failed reason "
		    "Encryption Key Size (0x06) per §2.3.4 (child exit=%d)",
		    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	}

	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
}

ATF_TC_WITHOUT_HEAD(test_knob_legacy_allows_7);
ATF_TC_BODY(test_knob_legacy_allows_7, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_test_knob7.XXXXXX";
	int bond_fd;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	signal(SIGPIPE, SIG_IGN);

	memset(&db, 0, sizeof(db));
	db.fd = bond_fd;
	memset(&sc, 0, sizeof(sc));
	smp_seed_policy_defaults(&sc);
	sc.fd = smp_fds[0];
	sc.hci_fd = hci_fds[0];
	sc.con_handle = 0x0040;
	memset(sc.local_addr, 0x11, 6);
	sc.local_addr_type = 1;
	memset(sc.remote_addr, 0x22, 6);
	sc.remote_addr_type = 1;
	sc.bond_db = &db;
	sc.io_capability = SMP_IO_NO_INPUT_NO_OUTPUT;
	sc.min_key_size = BT_CORE63_SMP_MIN_KEY_SIZE;

	{
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
		setsockopt(smp_fds[0], SOL_SOCKET, SO_RCVTIMEO,
		    &tv, sizeof(tv));
		setsockopt(hci_fds[0], SOL_SOCKET, SO_RCVTIMEO,
		    &tv, sizeof(tv));
	}

	pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		int peer_fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[65];
		uint8_t tk[16], srand[16];
		uint8_t sconfirm[16], mconfirm[16], mrand[16];
		uint8_t our_ltk[16];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		memset(tk, 0, sizeof(tk));

		n = recv(peer_fd, preq, sizeof(preq), 0);
		if (n < 7 || preq[0] != BTCR_SMP_PAIRING_REQUEST)
			_exit(1);

		/*
		 * Respond with NO SC flag and max_key_size = 7.
		 * Legacy pairing with min_key_size=7 should accept this.
		 */
		pres[0] = BTCR_SMP_PAIRING_RESPONSE;
		pres[1] = BTCR_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = 0x00;
		pres[3] = BTCR_SMP_AUTH_BONDING;	/* no SC flag */
		pres[4] = BT_CORE63_SMP_MIN_KEY_SIZE;
		pres[5] = 0x00;
		pres[6] = BTCR_SMP_KEY_DIST_ENC_KEY;
		if (send(peer_fd, pres, sizeof(pres), MSG_EOR) < 0)
			_exit(2);

		/* Receive confirm */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTCR_SMP_PAIRING_CONFIRM)
			_exit(3);
		memcpy(mconfirm, pdu + 1, 16);

		/* Send our confirm */
		arc4random_buf(srand, sizeof(srand));
		if (reference_c1(tk, srand, preq, pres,
		    BT_CORE63_DEVICE_ADDR_PUBLIC_WIRE, sc.local_addr,
		    BT_CORE63_DEVICE_ADDR_PUBLIC_WIRE, sc.remote_addr,
		    sconfirm) != 0)
			_exit(4);
		pdu[0] = BTCR_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(4);

		/* Receive random */
		n = recv(peer_fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BTCR_SMP_PAIRING_RANDOM)
			_exit(5);
		memcpy(mrand, pdu + 1, 16);

		/* Verify confirm */
		{
			uint8_t verify[16];
			if (reference_c1(tk, mrand, preq, pres,
			    BT_CORE63_DEVICE_ADDR_PUBLIC_WIRE, sc.local_addr,
			    BT_CORE63_DEVICE_ADDR_PUBLIC_WIRE, sc.remote_addr,
			    verify) != 0)
				_exit(6);
			if (memcmp(verify, mconfirm, 16) != 0)
				_exit(6);
		}

		/* Send our random */
		pdu[0] = BTCR_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(7);

		/* Send EncKey distribution */
		arc4random_buf(our_ltk, sizeof(our_ltk));
		pdu[0] = BTCR_SMP_ENCRYPTION_INFORMATION;
		memcpy(pdu + 1, our_ltk, 16);
		if (send(peer_fd, pdu, 17, MSG_EOR) < 0)
			_exit(8);

		pdu[0] = BTCR_SMP_CENTRAL_IDENTIFICATION;
		memset(pdu + 1, 0, 10);
		if (send(peer_fd, pdu, 11, MSG_EOR) < 0)
			_exit(9);

		/* Drain initiator keys */
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
	/*
	 * Legacy pairing with key size 7 should succeed when
	 * min_key_size is set to 7 (the spec minimum).
	 */
	ATF_CHECK_EQ_MSG(ret, 0,
	    "legacy pairing with key size 7 should succeed (ret=%d errno=%d)",
	    ret, errno);

	/* Close the DUT side first so the peer's drain ends on EOF, not a guard. */
	close(smp_fds[0]);
	close(hci_fds[0]);
	{
		int status;
		waitpid(pid, &status, 0);
	}

	close(bond_fd);
	unlink(bond_path);
}

/* ================================================================
 * Bond database tests
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(test_bond_db_save_load_roundtrip2);
ATF_TC_BODY(test_bond_db_save_load_roundtrip2, tc)
{
	struct smp_bond_db db1, db2;
	char path[] = "/tmp/blued_test_rt2.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	memset(&db1, 0, sizeof(db1));
	db1.fd = fd;
	db1.count = 3;

	/* Local IRK/CSRK */
	arc4random_buf(db1.local_irk, 16);
	db1.has_local_irk = true;
	arc4random_buf(db1.local_csrk, 16);
	db1.has_local_csrk = true;

	/* Bond 0: SC with MITM, CSRK, name */
	{
		struct smp_bond *b = &db1.bonds[0];
		memset(b->addr, 0xAA, 6);
		b->addr_type = BLUED_BOND_ADDR_RANDOM;
		arc4random_buf(b->ltk, 16);
		b->has_ltk = true;
		arc4random_buf(b->irk, 16);
		b->has_irk = true;
		arc4random_buf(b->csrk, 16);
		b->has_csrk = true;
		b->peer_sign_counter = 99;
		b->is_sc = true;
		b->is_mitm = true;
		strlcpy(b->name, "Headphones", sizeof(b->name));
		b->has_name = true;
	}

	/* Bond 1: legacy with LTK + rand/ediv */
	{
		struct smp_bond *b = &db1.bonds[1];
		memset(b->addr, 0xBB, 6);
		b->addr_type = BLUED_BOND_ADDR_PUBLIC;
		arc4random_buf(b->ltk, 16);
		b->has_ltk = true;
		b->rand = 0x123456789ABCDEF0ULL;
		b->ediv = 0xABCD;
	}

	/* Bond 2: minimal -- IRK only */
	{
		struct smp_bond *b = &db1.bonds[2];
		memset(b->addr, 0xCC, 6);
		b->addr_type = BLUED_BOND_ADDR_RANDOM;
		arc4random_buf(b->irk, 16);
		b->has_irk = true;
	}

	enable_atomic_bond_save(&db1, path);
	ATF_REQUIRE_EQ(smp_bond_db_save(&db1), 0);

	/* Reload into fresh db */
	memset(&db2, 0, sizeof(db2));
	enable_atomic_bond_save(&db2, path);
	ATF_REQUIRE_EQ(smp_bond_db_load(&db2, fd), 0);

	ATF_CHECK_EQ(db2.count, 3);
	ATF_CHECK(db2.has_local_csrk);
	ATF_CHECK(memcmp(db2.local_csrk, db1.local_csrk, 16) == 0);

	/* Verify all bonds */
	for (int i = 0; i < 3; i++) {
		ATF_CHECK_MSG(
		    memcmp(db2.bonds[i].addr, db1.bonds[i].addr, 6) == 0,
		    "bond %d: addr mismatch", i);
		ATF_CHECK_EQ(db2.bonds[i].addr_type, db1.bonds[i].addr_type);
		ATF_CHECK_EQ(db2.bonds[i].has_ltk, db1.bonds[i].has_ltk);
		if (db1.bonds[i].has_ltk)
			ATF_CHECK_MSG(
			    memcmp(db2.bonds[i].ltk, db1.bonds[i].ltk, 16) == 0,
			    "bond %d: LTK mismatch", i);
		ATF_CHECK_EQ(db2.bonds[i].has_irk, db1.bonds[i].has_irk);
		if (db1.bonds[i].has_irk)
			ATF_CHECK_MSG(
			    memcmp(db2.bonds[i].irk, db1.bonds[i].irk, 16) == 0,
			    "bond %d: IRK mismatch", i);
		ATF_CHECK_EQ(db2.bonds[i].has_csrk, db1.bonds[i].has_csrk);
		if (db1.bonds[i].has_csrk)
			ATF_CHECK_MSG(
			    memcmp(db2.bonds[i].csrk, db1.bonds[i].csrk, 16) == 0,
			    "bond %d: CSRK mismatch", i);
		ATF_CHECK_EQ(db2.bonds[i].is_sc, db1.bonds[i].is_sc);
		ATF_CHECK_EQ(db2.bonds[i].is_mitm, db1.bonds[i].is_mitm);
	}

	/* Verify local IRK */
	ATF_CHECK(db2.has_local_irk);
	ATF_CHECK(memcmp(db2.local_irk, db1.local_irk, 16) == 0);

	close(fd);
	unlink(path);
}

ATF_TC_WITHOUT_HEAD(test_bond_db_encryption);
ATF_TC_BODY(test_bond_db_encryption, tc)
{
	struct smp_bond_db db;
	char path[] = "/tmp/blued_test_enc.XXXXXX";
	int fd;
	uint8_t raw[256];
	ssize_t n;
	uint8_t ltk_value[16];

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	memset(&db, 0, sizeof(db));
	db.fd = fd;
	db.count = 1;

	/* Store a bond with a known LTK */
	memset(db.bonds[0].addr, 0xDE, 6);
	db.bonds[0].addr_type = BLUED_BOND_ADDR_RANDOM;
	memset(db.bonds[0].ltk, 0x42, 16);
	memcpy(ltk_value, db.bonds[0].ltk, 16);
	db.bonds[0].has_ltk = true;

	enable_atomic_bond_save(&db, path);
	ATF_REQUIRE_EQ(smp_bond_db_save(&db), 0);

	/*
	 * Read the raw file and verify the LTK does NOT appear in
	 * plaintext.  The bond DB uses AES-256-GCM encryption (v4),
	 * so the LTK bytes should not be present in the file.
	 */
	n = pread(fd, raw, sizeof(raw), 0);
	ATF_REQUIRE(n > 0);

	/*
	 * Search for the 16-byte LTK pattern in the raw file.
	 * It should NOT be found if encryption is working.
	 */
	bool found_ltk = false;
	for (ssize_t i = 0; i <= n - 16; i++) {
		if (memcmp(raw + i, ltk_value, 16) == 0) {
			found_ltk = true;
			break;
		}
	}

	ATF_CHECK_MSG(!found_ltk,
	    "LTK found in plaintext in bond file -- "
	    "encryption may not be working");

	/*
	 * Also verify the file starts with the encrypted magic "BONDE".
	 */
	ATF_CHECK_MSG(n >= BLUED_BOND_DB_ENCRYPTED_MAGIC_LEN &&
	    memcmp(raw, BLUED_BOND_DB_ENCRYPTED_MAGIC,
	    BLUED_BOND_DB_ENCRYPTED_MAGIC_LEN) == 0,
	    "bond file should start with BONDE magic for encrypted format");

	close(fd);
	unlink(path);
}

ATF_TC_WITHOUT_HEAD(test_bond_db_max_bonds);
ATF_TC_BODY(test_bond_db_max_bonds, tc)
{
	struct smp_bond_db db;
	struct smp_bond bond;
	char path[] = "/tmp/blued_test_max.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	memset(&db, 0, sizeof(db));
	db.fd = fd;

	/* Fill to capacity, each with a unique address */
	ATF_REQUIRE_EQ(SMP_MAX_BONDS, BLUED_BOND_DB_MAX_RECORDS);
	for (int i = 0; i < BLUED_BOND_DB_MAX_RECORDS; i++) {
		memset(&bond, 0, sizeof(bond));
		bond.addr[0] = (uint8_t)(i & 0xFF);
		bond.addr[1] = (uint8_t)((i >> 8) & 0xFF);
		bond.addr_type = BLUED_BOND_ADDR_PUBLIC;
		bond.has_ltk = true;
		memset(bond.ltk, (uint8_t)i, 16);
		smp_bond_db_store(&db, &bond);
	}
	ATF_CHECK_EQ(db.count, BLUED_BOND_DB_MAX_RECORDS);

	/* Verify the first (oldest) bond has addr[0]=0 */
	ATF_CHECK_EQ(db.bonds[0].addr[0], 0x00);

	/* Add one more -- should evict the oldest (addr[0]=0) */
	memset(&bond, 0, sizeof(bond));
	bond.addr[0] = 0xFE;
	bond.addr[1] = 0xFF;
	bond.addr_type = BLUED_BOND_ADDR_PUBLIC;
	bond.has_ltk = true;
	memset(bond.ltk, 0xFE, 16);
	smp_bond_db_store(&db, &bond);

	/* Count stays at max */
	ATF_CHECK_EQ(db.count, BLUED_BOND_DB_MAX_RECORDS);

	/* First bond should now be what was formerly the second (addr[0]=1) */
	ATF_CHECK_EQ(db.bonds[0].addr[0], 0x01);

	/* Last bond should be the newly added one */
	ATF_CHECK_EQ(db.bonds[BLUED_BOND_DB_MAX_RECORDS - 1].addr[0], 0xFE);
	ATF_CHECK_EQ(db.bonds[BLUED_BOND_DB_MAX_RECORDS - 1].ltk[0], 0xFE);

	/* Original bond with addr[0]=0 should no longer be findable */
	{
		uint8_t old_addr[6] = {0};
		ATF_CHECK(smp_find_bond(&db, old_addr,
		    BLUED_BOND_ADDR_PUBLIC) == NULL);
	}

	close(fd);
	unlink(path);
}

ATF_TC_WITHOUT_HEAD(test_bond_db_duplicate_update);
ATF_TC_BODY(test_bond_db_duplicate_update, tc)
{
	struct smp_bond_db db;
	struct smp_bond bond;
	char path[] = "/tmp/blued_test_dup.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	memset(&db, 0, sizeof(db));
	db.fd = fd;

	/* Store initial bond */
	memset(&bond, 0, sizeof(bond));
	bond.addr[0] = 0xAA;
	bond.addr[1] = 0xBB;
	bond.addr_type = BLUED_BOND_ADDR_RANDOM;
	memset(bond.ltk, 0x11, 16);
	bond.has_ltk = true;
	bond.is_sc = false;
	smp_bond_db_store(&db, &bond);
	ATF_CHECK_EQ(db.count, 1);

	/* Store same address again with different data */
	memset(bond.ltk, 0x22, 16);
	bond.is_sc = true;
	bond.has_irk = true;
	memset(bond.irk, 0x33, 16);
	smp_bond_db_store(&db, &bond);

	/* Must update in-place, not add a duplicate */
	ATF_CHECK_EQ_MSG(db.count, 1,
	    "storing same address twice should update, not duplicate "
	    "(count=%d)", db.count);

	/* Verify updated fields */
	ATF_CHECK_EQ(db.bonds[0].ltk[0], 0x22);
	ATF_CHECK(db.bonds[0].is_sc);
	ATF_CHECK(db.bonds[0].has_irk);
	ATF_CHECK_EQ(db.bonds[0].irk[0], 0x33);

	close(fd);
	unlink(path);
}

/* ================================================================
 * RPA (Resolvable Private Address) function tests
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(test_rpa_generate_format);
ATF_TC_BODY(test_rpa_generate_format, tc)
{
	uint8_t irk[16];
	uint8_t rpa[6];
	int i;

	arc4random_buf(irk, sizeof(irk));

	/*
	 * Generate multiple RPAs and verify all have the correct format:
	 * Address[47:46] must be the resolvable subtype from Core Table 1.2.
	 */
	for (i = 0; i < 10; i++) {
		smp_generate_rpa(irk, rpa);
		ATF_CHECK_EQ_MSG(rpa[5] & BT_CORE63_RANDOM_ADDRESS_TYPE_MASK,
		    BT_CORE63_RANDOM_ADDRESS_RESOLVABLE,
		    "RPA iteration %d: addr[5]=0x%02x, top 2 bits != 01",
		    i, rpa[5]);
	}
}

ATF_TC_WITHOUT_HEAD(test_rpa_matches_correct_irk);
ATF_TC_BODY(test_rpa_matches_correct_irk, tc)
{
	uint8_t irk[16];
	uint8_t rpa[6];

	arc4random_buf(irk, sizeof(irk));
	smp_generate_rpa(irk, rpa);

	ATF_CHECK_MSG(smp_rpa_matches(irk, rpa),
	    "RPA generated from IRK must resolve against the same IRK");
}

ATF_TC_WITHOUT_HEAD(test_rpa_rejects_wrong_irk);
ATF_TC_BODY(test_rpa_rejects_wrong_irk, tc)
{
	uint8_t irk[16], wrong_irk[16];
	uint8_t rpa[6];

	arc4random_buf(irk, sizeof(irk));
	smp_generate_rpa(irk, rpa);

	/* A completely different IRK must not resolve the RPA */
	memset(wrong_irk, 0xFF, sizeof(wrong_irk));
	ATF_CHECK_MSG(!smp_rpa_matches(wrong_irk, rpa),
	    "RPA must not resolve against a different IRK");

	/* An IRK that differs by one bit must also fail */
	memcpy(wrong_irk, irk, sizeof(wrong_irk));
	wrong_irk[0] ^= 0x01;
	ATF_CHECK_MSG(!smp_rpa_matches(wrong_irk, rpa),
	    "RPA must not resolve against IRK differing by one bit");
}

ATF_TC_WITHOUT_HEAD(test_rpa_rejects_non_rpa);
ATF_TC_BODY(test_rpa_rejects_non_rpa, tc)
{
	uint8_t irk[16];
	uint8_t addr[6];

	arc4random_buf(irk, sizeof(irk));

	/* Static random address: upper 2 bits = 11 */
	arc4random_buf(addr, sizeof(addr));
	addr[5] = (addr[5] &
	    (uint8_t)~BT_CORE63_RANDOM_ADDRESS_TYPE_MASK) |
	    BT_CORE63_RANDOM_ADDRESS_STATIC;
	ATF_CHECK_MSG(!smp_rpa_matches(irk, addr),
	    "static random address (bits=11) must not match any IRK");

	/* Non-resolvable private address: upper 2 bits = 00 */
	addr[5] = (addr[5] &
	    (uint8_t)~BT_CORE63_RANDOM_ADDRESS_TYPE_MASK) |
	    BT_CORE63_RANDOM_ADDRESS_NONRESOLVABLE;
	ATF_CHECK_MSG(!smp_rpa_matches(irk, addr),
	    "non-resolvable address (bits=00) must not match any IRK");

	/* Address[47:46] = 0b10 is reserved by Core Table 1.2. */
	addr[5] = (addr[5] &
	    (uint8_t)~BT_CORE63_RANDOM_ADDRESS_TYPE_MASK) |
	    BT_CORE63_RANDOM_ADDRESS_RESERVED;
	ATF_CHECK_MSG(!smp_rpa_matches(irk, addr),
	    "address with bits=10 must not match any IRK");
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_smp_swap_buf);
	ATF_TP_ADD_TC(tp, test_smp_aes128);
	ATF_TP_ADD_TC(tp, test_smp_c1);
	ATF_TP_ADD_TC(tp, test_smp_s1);
	ATF_TP_ADD_TC(tp, test_smp_aes_cmac_len0);
	ATF_TP_ADD_TC(tp, test_smp_aes_cmac_len16);
	ATF_TP_ADD_TC(tp, test_smp_aes_cmac_len40);
	ATF_TP_ADD_TC(tp, test_smp_aes_cmac_len64);
	ATF_TP_ADD_TC(tp, test_smp_f4);
	ATF_TP_ADD_TC(tp, test_smp_f5);
	ATF_TP_ADD_TC(tp, test_smp_f6);
	ATF_TP_ADD_TC(tp, test_smp_g2);
	ATF_TP_ADD_TC(tp, test_smp_h6);
	ATF_TP_ADD_TC(tp, test_smp_h7);
	ATF_TP_ADD_TC(tp, test_smp_ctkd_ct2);
	ATF_TP_ADD_TC(tp, test_smp_ctkd_ct2_0);
	ATF_TP_ADD_TC(tp, test_smp_ctkd_link_key_to_ltk_ct2);
	ATF_TP_ADD_TC(tp, test_smp_ctkd_link_key_to_ltk_ct2_0);

	/* IO capability matrix tests */
	ATF_TP_ADD_TC(tp, test_smp_select_model_legacy);
	ATF_TP_ADD_TC(tp, test_smp_select_model_sc);

	/* RPA resolution */
	ATF_TP_ADD_TC(tp, test_smp_rpa_resolve);

	/* Bond persistence */
	ATF_TP_ADD_TC(tp, test_bond_save_load);
	ATF_TP_ADD_TC(tp, test_bond_db_full);

	/* BLE 4.2 SC crypto */
	ATF_TP_ADD_TC(tp, test_smp_f5_dual_output);

	/* Signature verification */
	ATF_TP_ADD_TC(tp, test_smp_verify_signature_valid);
	ATF_TP_ADD_TC(tp, test_smp_verify_signature_invalid);
	ATF_TP_ADD_TC(tp, test_smp_verify_signature_wrong_counter);

	/* AES edge cases */
	ATF_TP_ADD_TC(tp, test_smp_aes128_zero_key);
	ATF_TP_ADD_TC(tp, test_smp_aes_cmac_block_boundary);

	/* Pairing timer */
	ATF_TP_ADD_TC(tp, test_smp_pairing_expired);

	/* Bond DB comprehensive round-trip */
	ATF_TP_ADD_TC(tp, test_bond_db_save_load_roundtrip);
	ATF_TP_ADD_TC(tp, test_bond_db_current_format_roundtrip);

	/* RPA generation */
	ATF_TP_ADD_TC(tp, test_smp_generate_rpa);

	/* Swap edge cases */
	ATF_TP_ADD_TC(tp, test_smp_swap_buf_zero_len);
	ATF_TP_ADD_TC(tp, test_smp_swap_buf_odd_len);

	/* Crypto correctness / byte-order */
	ATF_TP_ADD_TC(tp, test_smp_c1_nonzero_tk);
	ATF_TP_ADD_TC(tp, test_smp_aes128_byte_order_roundtrip);
	ATF_TP_ADD_TC(tp, test_smp_aes_cmac_len1);
	ATF_TP_ADD_TC(tp, test_smp_f4_passkey_bit);

	/* IO capability validation */
	ATF_TP_ADD_TC(tp, test_smp_select_model_invalid_io);

	/* Bond DB edge cases */
	ATF_TP_ADD_TC(tp, test_bond_db_store_update_existing);
	ATF_TP_ADD_TC(tp, test_bond_db_eviction_order);
	ATF_TP_ADD_TC(tp, test_bond_cccd_persistence);

	/* RPA edge cases */
	ATF_TP_ADD_TC(tp, test_smp_rpa_not_resolvable);

	/* Bond lookup */
	ATF_TP_ADD_TC(tp, test_smp_find_bond_empty);
	ATF_TP_ADD_TC(tp, test_smp_find_bond_addr_type_matters);

	/* CTKD gating */
	ATF_TP_ADD_TC(tp, test_smp_ctkd_requires_sc);
	ATF_TP_ADD_TC(tp, test_smp_ctkd_requires_mitm);

	/* Signature edge cases */
	ATF_TP_ADD_TC(tp, test_smp_verify_signature_empty_msg);

	/* Spec test vectors (explicit Appendix D references) */
	ATF_TP_ADD_TC(tp, test_smp_f4_spec_vector);
	ATF_TP_ADD_TC(tp, test_smp_f6_spec_vector);
	ATF_TP_ADD_TC(tp, test_smp_g2_spec_vector);
	ATF_TP_ADD_TC(tp, test_smp_h6_spec_vector);
	ATF_TP_ADD_TC(tp, test_smp_h7_spec_vector);
	ATF_TP_ADD_TC(tp, test_smp_ah_spec_vector);

	/* SC Debug Key rejection */
	ATF_TP_ADD_TC(tp, test_sc_debug_key_x_match);
	ATF_TP_ADD_TC(tp, test_sc_debug_key_y_match);
	ATF_TP_ADD_TC(tp, test_sc_debug_key_normal_key_accepted);

	/* KNOB mitigation */
	ATF_TP_ADD_TC(tp, test_knob_min_key_size_16);
	ATF_TP_ADD_TC(tp, test_knob_legacy_allows_7);

	/* Bond database security */
	ATF_TP_ADD_TC(tp, test_bond_db_save_load_roundtrip2);
	ATF_TP_ADD_TC(tp, test_bond_db_encryption);
	ATF_TP_ADD_TC(tp, test_bond_db_max_bonds);
	ATF_TP_ADD_TC(tp, test_bond_db_duplicate_update);

	/* RPA functions */
	ATF_TP_ADD_TC(tp, test_rpa_generate_format);
	ATF_TP_ADD_TC(tp, test_rpa_matches_correct_irk);
	ATF_TP_ADD_TC(tp, test_rpa_rejects_wrong_irk);
	ATF_TP_ADD_TC(tp, test_rpa_rejects_non_rpa);

	return (atf_no_error());
}
