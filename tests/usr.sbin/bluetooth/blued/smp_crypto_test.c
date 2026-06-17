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

#include <atf-c.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "hci_log.h"
#include "hci_util.h"
#include "smp.h"

/* ================================================================
 * Stubs for external symbols referenced by smp.c but not needed
 * for crypto-only tests.
 * ================================================================ */

/* ble_util.h globals — extern declared in ble_util.h, defined here */
extern int blued_verbose;
extern int blued_daemonized;
int blued_verbose;
int blued_daemonized;

/* hci_log.c stubs */
bool
hci_log_enabled(void)
{

	return (false);
}

void
hci_log_l2cap(uint16_t con_handle __unused, uint16_t cid __unused,
    const uint8_t *data __unused, uint16_t len __unused,
    bool incoming __unused)
{
}

void
hci_log_packet(uint8_t type __unused, const uint8_t *data __unused,
    uint16_t len __unused, bool incoming __unused)
{
}

/* hci_util.c stubs */
int
hci_wait_encryption(int hci_fd __unused, uint16_t con_handle __unused,
    int timeout_sec __unused)
{

	return (-1);
}

int
hci_le_ltk_request_reply(int hci_fd __unused, uint16_t con_handle __unused,
    const uint8_t ltk[16] __unused)
{

	return (-1);
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
 * Test: swap_buf
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_swap_buf);
ATF_TC_BODY(test_swap_buf, tc)
{
	uint8_t src[4] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t dst[4];
	uint8_t expected[4] = { 0x04, 0x03, 0x02, 0x01 };

	swap_buf(dst, src, 4);
	ATF_CHECK_EQ(memcmp(dst, expected, 4), 0);
}

/* ================================================================
 * Test: smp_aes128 (security function e)
 * Core Spec Vol 3 Part H Section 2.2.1
 *
 * Derived from the s1 test vector (Section 2.2.4, Appendix D):
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
	/* k = all zeros (same in LE and BE) */
	uint8_t k[16];
	memset(k, 0, 16);

	/* r' in big-endian from spec s1 test, reverse to LE */
	HEX_LE(r, "112233445566778899AABBCCDDEEFF00", 16);

	/* Expected output in big-endian from spec, reverse to LE */
	HEX_LE(expected, "9a1fe1f0e8b0f49b5b4216ae796da062", 16);

	uint8_t out[16];
	smp_aes128(k, r, out);

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
	uint8_t k[16];
	memset(k, 0, 16);

	/* r from spec in BE, convert to LE */
	HEX_LE(r, "5783D52156AD6F0E6388274EC6702EE0", 16);

	/*
	 * preq and pres as they appear in the LE p1 array.
	 * p1 BE = 0x050008000003020707100000010100 01
	 * p1 LE array: {0x01, 0x00, preq[7], pres[7]}
	 * preq = {0x01,0x01,0x00,0x00,0x10,0x07,0x07}
	 * pres = {0x02,0x03,0x00,0x00,0x08,0x00,0x05}
	 */
	uint8_t preq[7] = { 0x01, 0x01, 0x00, 0x00, 0x10, 0x07, 0x07 };
	uint8_t pres[7] = { 0x02, 0x03, 0x00, 0x00, 0x08, 0x00, 0x05 };
	uint8_t iat = 0x01;
	uint8_t rat = 0x00;

	/*
	 * ia and ra from the p2 construction:
	 * p2 BE = 0x00000000A1A2A3A4A5A6B1B2B3B4B5B6
	 * p2 LE array = {ra[6], ia[6], padding[4]}
	 *            = {B6,B5,B4,B3,B2,B1, A6,A5,A4,A3,A2,A1, 00,00,00,00}
	 */
	uint8_t ia[6] = { 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1 };
	uint8_t ra[6] = { 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1 };

	/* Expected output from spec, converted to LE */
	HEX_LE(expected, "1E1E3FEF878988EAD2A74DC5BEF13B86", 16);

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
	uint8_t k[16];
	memset(k, 0, 16);

	HEX_LE(r1, "000F0E0D0C0B0A091122334455667788", 16);
	HEX_LE(r2, "010203040506070899AABBCCDDEEFF00", 16);

	HEX_LE(expected, "9a1fe1f0e8b0f49b5b4216ae796da062", 16);

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
	HEX_BE(key, "2b7e151628aed2a6abf7158809cf4f3c", 16);
	HEX_BE(expected, "bb1d6929e95937287fa37d129b756746", 16);

	uint8_t mac[16];
	smp_aes_cmac(key, NULL, 0, mac);

	ATF_CHECK_EQ_MSG(memcmp(mac, expected, 16), 0,
	    "AES-CMAC Len=0 does not match RFC 4493 / Spec D.1.1");
}

/* D.1.2: Len = 16 */
ATF_TC_WITHOUT_HEAD(test_smp_aes_cmac_len16);
ATF_TC_BODY(test_smp_aes_cmac_len16, tc)
{
	HEX_BE(key, "2b7e151628aed2a6abf7158809cf4f3c", 16);
	HEX_BE(msg, "6bc1bee22e409f96e93d7e117393172a", 16);
	HEX_BE(expected, "070a16b46b4d4144f79bdd9dd04a287c", 16);

	uint8_t mac[16];
	smp_aes_cmac(key, msg, 16, mac);

	ATF_CHECK_EQ_MSG(memcmp(mac, expected, 16), 0,
	    "AES-CMAC Len=16 does not match RFC 4493 / Spec D.1.2");
}

/* D.1.3: Len = 40 */
ATF_TC_WITHOUT_HEAD(test_smp_aes_cmac_len40);
ATF_TC_BODY(test_smp_aes_cmac_len40, tc)
{
	HEX_BE(key, "2b7e151628aed2a6abf7158809cf4f3c", 16);
	uint8_t msg[40];
	hex_to_bytes(msg,
	    "6bc1bee22e409f96e93d7e117393172a"
	    "ae2d8a571e03ac9c9eb76fac45af8e51"
	    "30c81c46a35ce411", 40);
	HEX_BE(expected, "dfa66747de9ae63030ca32611497c827", 16);

	uint8_t mac[16];
	smp_aes_cmac(key, msg, 40, mac);

	ATF_CHECK_EQ_MSG(memcmp(mac, expected, 16), 0,
	    "AES-CMAC Len=40 does not match RFC 4493 / Spec D.1.3");
}

/* D.1.4: Len = 64 */
ATF_TC_WITHOUT_HEAD(test_smp_aes_cmac_len64);
ATF_TC_BODY(test_smp_aes_cmac_len64, tc)
{
	HEX_BE(key, "2b7e151628aed2a6abf7158809cf4f3c", 16);
	uint8_t msg[64];
	hex_to_bytes(msg,
	    "6bc1bee22e409f96e93d7e117393172a"
	    "ae2d8a571e03ac9c9eb76fac45af8e51"
	    "30c81c46a35ce411e5fbc1191a0a52ef"
	    "f69f2445df4f9b17ad2b417be66c3710", 64);
	HEX_BE(expected, "51f0bebf7e3b9d92fc49741779363cfe", 16);

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
	HEX_LE(u,
	    "20b003d2f297be2c5e2c83a7e9f9a5b9"
	    "eff49111acf4fddbcc0301480e359de6", 32);
	HEX_LE(v,
	    "55188b3d32f6bb9a900afcfbeed4e72a"
	    "59cb9ac2f19d7cfb6b4fdd49f47fc5fd", 32);
	HEX_LE(x, "d5cb8454d177733effffb2ec712baeab", 16);
	uint8_t z = 0x00;

	HEX_LE(expected, "f2c916f107a9bd1cf1eda1bea974872d", 16);

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
	HEX_LE(dhkey,
	    "ec0234a357c8ad05341010a60a397d9b"
	    "99796b13b4f866f1868d34f373bfa698", 32);
	HEX_LE(n1, "d5cb8454d177733effffb2ec712baeab", 16);
	HEX_LE(n2, "a6e8e7cc25a75f6e216583f7ff3dc4cf", 16);

	/*
	 * A1 and A2 are 7-byte "address info" fields: addr_type(1) || addr(6).
	 * Spec gives them in big-endian.  In LE wire order, we reverse.
	 */
	HEX_LE(a1, "0056123737bfce", 7);
	HEX_LE(a2, "00a713702dcfc1", 7);

	/*
	 * Per Core Spec Vol 3 Part H Section 2.2.7 and Appendix D.3:
	 * Counter=0 -> MacKey, Counter=1 -> LTK.
	 */
	HEX_LE(exp_mackey, "2965f176a1084a02fd3f6a20ce636e20", 16);
	HEX_LE(exp_ltk, "6986791169d7cd23980522b594750a38", 16);

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
	HEX_LE(n1, "d5cb8454d177733effffb2ec712baeab", 16);
	HEX_LE(n2, "a6e8e7cc25a75f6e216583f7ff3dc4cf", 16);
	HEX_LE(mackey, "2965f176a1084a02fd3f6a20ce636e20", 16);
	HEX_LE(r, "12a3343bb453bb5408da42d20c2d0fc8", 16);
	HEX_LE(iocap, "010102", 3);
	HEX_LE(a1, "0056123737bfce", 7);
	HEX_LE(a2, "00a713702dcfc1", 7);

	HEX_LE(expected, "e3c473989cd0e8c5d26c0b09da958f61", 16);

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
 * The decimal value for display is:
 *   0x2f9ed5ba = 800228794, mod 10^6 = 228794 (not tested here)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_smp_g2);
ATF_TC_BODY(test_smp_g2, tc)
{
	HEX_LE(u,
	    "20b003d2f297be2c5e2c83a7e9f9a5b9"
	    "eff49111acf4fddbcc0301480e359de6", 32);
	HEX_LE(v,
	    "55188b3d32f6bb9a900afcfbeed4e72a"
	    "59cb9ac2f19d7cfb6b4fdd49f47fc5fd", 32);
	HEX_LE(x, "d5cb8454d177733effffb2ec712baeab", 16);
	HEX_LE(y, "a6e8e7cc25a75f6e216583f7ff3dc4cf", 16);

	uint32_t result = smp_g2(u, v, x, y);

	/* g2 returns the least significant 32 bits of the BE MAC = 0x2f9ed5ba */
	ATF_CHECK_EQ_MSG(result, 0x2f9ed5ba,
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
	HEX_LE(w, "ec0234a357c8ad05341010a60a397d9b", 16);

	/* keyID is in big-endian order (not reversed) */
	HEX_BE(keyid, "6c656272", 4);

	/* Expected output in LE */
	HEX_LE(expected, "2d9ae102e76dc91ce8d3a9e280b16399", 16);

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
	HEX_LE(w, "ec0234a357c8ad05341010a60a397d9b", 16);

	/* SALT is in big-endian order (not reversed per spec) */
	HEX_BE(salt, "000000000000000000000000746D7031", 16);

	/* Expected output in LE */
	HEX_LE(expected, "fb173597c6a3c0ecd2998c2a75a57011", 16);

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

	/* LTK in LE wire order */
	HEX_LE(ltk, "368df9bce3264b58bd066c33334fbf64", 16);
	memcpy(bond.ltk, ltk, 16);

	/* Expected link key in LE wire order */
	HEX_LE(expected, "287ad379dca402530a39f1f43047b835", 16);

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

	HEX_LE(ltk, "368df9bce3264b58bd066c33334fbf64", 16);
	memcpy(bond.ltk, ltk, 16);

	HEX_LE(expected, "bc1ca4ef633fc1bd0d8230afee388fb0", 16);

	int ret = smp_ctkd_derive_link_key(&bond, false);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ_MSG(memcmp(bond.link_key, expected, 16), 0,
	    "CTKD CT2=0 link key does not match spec D.10");
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_swap_buf);
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

	return (atf_no_error());
}
