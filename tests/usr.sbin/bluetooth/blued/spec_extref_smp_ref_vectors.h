/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * EXTERNAL REFERENCE ORACLE: Security Manager cryptographic vectors as they
 * appear in the unit tests of OTHER Bluetooth host stacks.
 *
 * spec_extref_smp_vectors.h already carries the Core 6.3 Vol 3 Part H
 * Appendix D sample data and BlueZ's own arrays.  This header is the
 * SECOND AND THIRD OPINION: the same primitives as tested by Zephyr and by
 * Apache NimBLE, transcribed verbatim from their sources.
 *
 * Every array below is a literal copy of bytes that already existed in a
 * foreign tree.  None of it was produced by reading, running or reasoning
 * about blued, libble, or any other 5BSD source, and none of it was
 * "corrected" to agree with anything in this tree.
 *
 * SOURCES
 * -------
 *   [ZEPHYR]  zephyrproject-rtos/zephyr, snapshot commit
 *             2665fcca3cced3aefb7202d6289991d8cc1dfcac.
 *   [NIMBLE]  apache/mynewt-nimble, snapshot commit
 *             1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845.
 *   [BLUEZ]   git.kernel.org/pub/scm/bluetooth/bluez.git, snapshot commit
 *             92305dc06ab8a6d89af2dae1d725cc4d51462ad1.
 *   [SPEC]    /usr/src/bluetooth-specs/Core_Specification_6_3.txt.
 *
 * BYTE ORDER
 * ----------
 * Every array here is in LITTLE-ENDIAN (on-air / in-memory) order, index 0 =
 * least significant octet, because that is the order all three reference
 * stacks use at their SMP API boundary and the order blued's smp_* functions
 * take.  This is the exact reverse of the spec's printed hex.  Nothing has
 * been silently reversed: where a value also appears in
 * spec_extref_smp_vectors.h in spec display order, the accompanying test
 * asserts that the two are reverses of one another, so a transcription slip
 * in EITHER file is caught rather than hidden.
 *
 * INDEPENDENCE, STATED HONESTLY
 * -----------------------------
 * Zephyr's and NimBLE's f4/f5/f6/g2 arrays are byte-identical to each other,
 * including whitespace and array formatting.  They are therefore NOT two
 * independent transcriptions of the specification -- one is descended from
 * the other.  Treat {Zephyr, NimBLE} as ONE opinion for those four
 * functions.  It is still an opinion arrived at without reference to BlueZ,
 * to the Core specification text extractor used elsewhere in this tree, or
 * to blued, so it remains a real cross-check; it just is not three.
 *
 * Where the sources genuinely are independent the header says so at the
 * vector.
 */

#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_SMP_REF_VECTORS_H
#define TESTS_BLUETOOTH_SPEC_EXTREF_SMP_REF_VECTORS_H

#include <stdint.h>

/*
 * ================================================================
 * f4 -- LE Secure Connections confirm value generation.
 *
 * [ZEPHYR] subsys/bluetooth/host/smp.c:5530-5558, smp_f4_test().
 * [NIMBLE] nimble/host/test/src/ble_sm_test.c:37-60,
 *          ble_sm_test_case_f4.
 *
 * Both call their f4 with (u, v, x, z) and compare 16 octets.  The values
 * are the byte-reverse of [SPEC] Vol 3, Part H, Appendix D.2.
 * ================================================================
 */
static const uint8_t bt_extref_ref_f4_u[32] = {
	0xe6, 0x9d, 0x35, 0x0e, 0x48, 0x01, 0x03, 0xcc,
	0xdb, 0xfd, 0xf4, 0xac, 0x11, 0x91, 0xf4, 0xef,
	0xb9, 0xa5, 0xf9, 0xe9, 0xa7, 0x83, 0x2c, 0x5e,
	0x2c, 0xbe, 0x97, 0xf2, 0xd2, 0x03, 0xb0, 0x20,
};
static const uint8_t bt_extref_ref_f4_v[32] = {
	0xfd, 0xc5, 0x7f, 0xf4, 0x49, 0xdd, 0x4f, 0x6b,
	0xfb, 0x7c, 0x9d, 0xf1, 0xc2, 0x9a, 0xcb, 0x59,
	0x2a, 0xe7, 0xd4, 0xee, 0xfb, 0xfc, 0x0a, 0x90,
	0x9a, 0xbb, 0xf6, 0x32, 0x3d, 0x8b, 0x18, 0x55,
};
static const uint8_t bt_extref_ref_f4_x[16] = {
	0xab, 0xae, 0x2b, 0x71, 0xec, 0xb2, 0xff, 0xff,
	0x3e, 0x73, 0x77, 0xd1, 0x54, 0x84, 0xcb, 0xd5,
};
#define BT_EXTREF_REF_F4_Z	0x00
static const uint8_t bt_extref_ref_f4_out[16] = {
	0x2d, 0x87, 0x74, 0xa9, 0xbe, 0xa1, 0xed, 0xf1,
	0x1c, 0xbd, 0xa9, 0x07, 0xf1, 0x16, 0xc9, 0xf2,
};

/*
 * ================================================================
 * f5 -- LE Secure Connections key generation (MacKey and LTK).
 *
 * [ZEPHYR] subsys/bluetooth/host/smp.c:5560-5593, smp_f5_test().
 * [NIMBLE] nimble/host/test/src/ble_sm_test.c:62-92,
 *          ble_sm_test_case_f5.
 *
 * The address arguments are reproduced EXACTLY as the two references write
 * them: a type octet passed separately (0x00, public) and a six-octet
 * address array in on-air, least-significant-octet-first order.  Zephyr
 * spells this bt_addr_le_t{.type, .a.val}; NimBLE spells it (a1t, a1).
 * Neither ships a pre-composed 7-octet field, so neither does this header --
 * composing it is the caller's job and the shape of that composition is
 * precisely what differs between stacks, so it must stay visible at the call
 * site rather than being baked in here.
 *
 * For reference, the specification's A1 field ([SPEC] Appendix D.3) is
 * type || address most significant octet first: 00 56 12 37 37 bf ce.
 * ================================================================
 */
static const uint8_t bt_extref_ref_f5_w[32] = {
	0x98, 0xa6, 0xbf, 0x73, 0xf3, 0x34, 0x8d, 0x86,
	0xf1, 0x66, 0xf8, 0xb4, 0x13, 0x6b, 0x79, 0x99,
	0x9b, 0x7d, 0x39, 0x0a, 0xa6, 0x10, 0x10, 0x34,
	0x05, 0xad, 0xc8, 0x57, 0xa3, 0x34, 0x02, 0xec,
};
static const uint8_t bt_extref_ref_f5_n1[16] = {
	0xab, 0xae, 0x2b, 0x71, 0xec, 0xb2, 0xff, 0xff,
	0x3e, 0x73, 0x77, 0xd1, 0x54, 0x84, 0xcb, 0xd5,
};
static const uint8_t bt_extref_ref_f5_n2[16] = {
	0xcf, 0xc4, 0x3d, 0xff, 0xf7, 0x83, 0x65, 0x21,
	0x6e, 0x5f, 0xa7, 0x25, 0xcc, 0xe7, 0xe8, 0xa6,
};
#define BT_EXTREF_REF_F5_A1_TYPE	0x00
static const uint8_t bt_extref_ref_f5_a1_addr[6] = {
	0xce, 0xbf, 0x37, 0x37, 0x12, 0x56,
};
#define BT_EXTREF_REF_F5_A2_TYPE	0x00
static const uint8_t bt_extref_ref_f5_a2_addr[6] = {
	0xc1, 0xcf, 0x2d, 0x70, 0x13, 0xa7,
};
static const uint8_t bt_extref_ref_f5_mackey[16] = {
	0x20, 0x6e, 0x63, 0xce, 0x20, 0x6a, 0x3f, 0xfd,
	0x02, 0x4a, 0x08, 0xa1, 0x76, 0xf1, 0x65, 0x29,
};
static const uint8_t bt_extref_ref_f5_ltk[16] = {
	0x38, 0x0a, 0x75, 0x94, 0xb5, 0x22, 0x05, 0x98,
	0x23, 0xcd, 0xd7, 0x69, 0x11, 0x79, 0x86, 0x69,
};

/*
 * ================================================================
 * f6 -- LE Secure Connections check value generation.
 *
 * [ZEPHYR] subsys/bluetooth/host/smp.c:5595-5625, smp_f6_test().
 * [NIMBLE] nimble/host/test/src/ble_sm_test.c:94-124,
 *          ble_sm_test_case_f6.
 *
 * Note io_cap: both references write { 0x02, 0x01, 0x01 }, which is the
 * byte-reverse of [SPEC] Appendix D.4's printed "IOcap 010102".  The IOcap
 * field is IOcapA || OOB || AuthReq and it is NOT a little-endian integer;
 * it is a byte string that the reference stacks nevertheless reverse along
 * with everything else on the way into CMAC.  Get this backwards and f6
 * still produces a plausible-looking 16 octets, which is why it has a vector.
 * ================================================================
 */
static const uint8_t bt_extref_ref_f6_w[16] = {
	0x20, 0x6e, 0x63, 0xce, 0x20, 0x6a, 0x3f, 0xfd,
	0x02, 0x4a, 0x08, 0xa1, 0x76, 0xf1, 0x65, 0x29,
};
static const uint8_t bt_extref_ref_f6_n1[16] = {
	0xab, 0xae, 0x2b, 0x71, 0xec, 0xb2, 0xff, 0xff,
	0x3e, 0x73, 0x77, 0xd1, 0x54, 0x84, 0xcb, 0xd5,
};
static const uint8_t bt_extref_ref_f6_n2[16] = {
	0xcf, 0xc4, 0x3d, 0xff, 0xf7, 0x83, 0x65, 0x21,
	0x6e, 0x5f, 0xa7, 0x25, 0xcc, 0xe7, 0xe8, 0xa6,
};
static const uint8_t bt_extref_ref_f6_r[16] = {
	0xc8, 0x0f, 0x2d, 0x0c, 0xd2, 0x42, 0xda, 0x08,
	0x54, 0xbb, 0x53, 0xb4, 0x3b, 0x34, 0xa3, 0x12,
};
static const uint8_t bt_extref_ref_f6_iocap[3] = {
	0x02, 0x01, 0x01,
};
#define BT_EXTREF_REF_F6_A1_TYPE	0x00
static const uint8_t bt_extref_ref_f6_a1_addr[6] = {
	0xce, 0xbf, 0x37, 0x37, 0x12, 0x56,
};
#define BT_EXTREF_REF_F6_A2_TYPE	0x00
static const uint8_t bt_extref_ref_f6_a2_addr[6] = {
	0xc1, 0xcf, 0x2d, 0x70, 0x13, 0xa7,
};
static const uint8_t bt_extref_ref_f6_out[16] = {
	0x61, 0x8f, 0x95, 0xda, 0x09, 0x0b, 0x6c, 0xd2,
	0xc5, 0xe8, 0xd0, 0x9c, 0x98, 0x73, 0xc4, 0xe3,
};

/*
 * ================================================================
 * g2 -- LE Secure Connections numeric comparison value.
 *
 * [ZEPHYR] subsys/bluetooth/host/smp.c:5627-5656, smp_g2_test().
 * [NIMBLE] nimble/host/test/src/ble_sm_test.c:126-149,
 *          ble_sm_test_case_g2.
 *
 * Both write the expectation as the EXPRESSION 0x2f9ed5ba % 1000000 rather
 * than as a decimal literal, so both are asserting two things at once: that
 * the 32-bit value taken out of the CMAC is 0x2F9ED5BA, and that the
 * displayed passkey is that value reduced mod 10^6.  Reproduced here as both
 * halves so a test can check them separately -- taking the wrong 32 bits and
 * then reducing can still land on a six-digit number.
 *
 * u, v, x are bt_extref_ref_f4_u / _v / _x; y is bt_extref_ref_f5_n2.
 * ================================================================
 */
#define BT_EXTREF_REF_G2_CMAC_LOW32	0x2f9ed5bau
#define BT_EXTREF_REF_G2_MODULUS	1000000u
#define BT_EXTREF_REF_G2_VALUE		(BT_EXTREF_REF_G2_CMAC_LOW32 % \
					    BT_EXTREF_REF_G2_MODULUS)

/*
 * ================================================================
 * h6 -- LE Secure Connections link key conversion.
 *
 * [ZEPHYR] subsys/bluetooth/host/smp.c:5658-5678, smp_h6_test()
 *          (compiled only under CONFIG_BT_CLASSIC).
 * [BLUEZ]  unit/test-crypto.c:29-64, test_h6.
 *
 * These two ARE independent of each other, and they agree byte for byte.
 * NimBLE's host tree has no h6 test; its controller tree has one
 * (nimble/controller/test/src/ble_ll_crypto_test.c) for the BIG key
 * hierarchy, not for the SMP link key conversion.
 *
 * keyID is the ASCII string "lebr" ([SPEC] Appendix D.6 prints keyID
 * 6c656272); as a little-endian array that is { 'r','b','e','l' }.  It is
 * NOT reversed a second time on its way into CMAC by these stacks -- they
 * reverse it exactly once, like every other argument.
 * ================================================================
 */
static const uint8_t bt_extref_ref_h6_w[16] = {
	0x9b, 0x7d, 0x39, 0x0a, 0xa6, 0x10, 0x10, 0x34,
	0x05, 0xad, 0xc8, 0x57, 0xa3, 0x34, 0x02, 0xec,
};
static const uint8_t bt_extref_ref_h6_keyid[4] = {
	0x72, 0x62, 0x65, 0x6c,
};
static const uint8_t bt_extref_ref_h6_out[16] = {
	0x99, 0x63, 0xb1, 0x80, 0xe2, 0xa9, 0xd3, 0xe8,
	0x1c, 0xc9, 0x6d, 0xe7, 0x02, 0xe1, 0x9a, 0x2d,
};

/*
 * ================================================================
 * h7 -- LE Secure Connections link key conversion with a salt.
 *
 * [ZEPHYR] subsys/bluetooth/host/smp.c:5680-5702, smp_h7_test()
 *          (compiled only under CONFIG_BT_CLASSIC).
 *
 * Uncorroborated by any other reference: BlueZ's unit/test-crypto.c has no
 * h7 case and NimBLE's host tree has no h7 at all.  The only other source
 * for this value is [SPEC] Appendix D.8, of which this is the byte-reverse.
 *
 * The SALT is the ASCII string "tmp1" in the four LEAST significant octets
 * and zero elsewhere, i.e. little-endian { '1','p','m','t', 0 x 12 }.
 * ================================================================
 */
static const uint8_t bt_extref_ref_h7_salt[16] = {
	0x31, 0x70, 0x6d, 0x74, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t bt_extref_ref_h7_w[16] = {
	0x9b, 0x7d, 0x39, 0x0a, 0xa6, 0x10, 0x10, 0x34,
	0x05, 0xad, 0xc8, 0x57, 0xa3, 0x34, 0x02, 0xec,
};
static const uint8_t bt_extref_ref_h7_out[16] = {
	0x11, 0x70, 0xa5, 0x75, 0x2a, 0x8c, 0x99, 0xd2,
	0xec, 0xc0, 0xa3, 0xc6, 0x97, 0x35, 0x17, 0xfb,
};

/*
 * ================================================================
 * ah -- the random address hash function, via CSIS sih.
 *
 * [BLUEZ]  unit/test-crypto.c:352-380, test_sih.
 * [NIMBLE] nimble/host/test/src/ble_sm_test.c:151-165,
 *          ble_sm_test_case_csis_sih.
 *
 * This is the one genuinely independent SECOND vector for ah in the whole
 * ecosystem, and it took looking somewhere unexpected to find it.  Neither
 * BlueZ nor NimBLE ships a test for ah under that name; both ship one for
 * the Coordinated Set Identification Service hash sih, and CSIS sih IS ah:
 * [SPEC] Vol 3, Part H, Section 2.2.2 defines ah(k, r) = e(k, r') mod 2^24
 * with r' = padding || r, and the CSIS specification defines
 * sih(SIRK, prand) as exactly that function with the SIRK as the key.  The
 * two implementations were written by different teams and agree byte for
 * byte on input and output.
 *
 * Everything else in the ecosystem tests ah only through [SPEC] Appendix
 * D.7, so without this the primitive that decides whether a private address
 * resolves would rest on a single transcribed value.
 *
 * Layout: k is the IRK (here the SIRK) little-endian; r is the 3-octet prand
 * little-endian; out is the 3-octet hash little-endian.  A resolvable
 * private address is hash || prand, so the six on-air octets are
 * out[0..2] followed by r[0..2] -- and note that r[2] == 0x69 has its two
 * most significant bits set to 0b01, which is what makes this a well-formed
 * RPA ([SPEC] Vol 6, Part B, Section 1.3.2.2) rather than merely a hash
 * input.
 * ================================================================
 */
static const uint8_t bt_extref_ref_ah_k[16] = {
	0xcd, 0xcc, 0x72, 0xdd, 0x86, 0x8c, 0xcd, 0xce,
	0x22, 0xfd, 0xa1, 0x21, 0x09, 0x7d, 0x7d, 0x45,
};
static const uint8_t bt_extref_ref_ah_r[3] = {
	0x63, 0xf5, 0x69,
};
static const uint8_t bt_extref_ref_ah_out[3] = {
	0xda, 0x48, 0x19,
};
/* The resolvable private address these compose, in on-air octet order. */
static const uint8_t bt_extref_ref_ah_rpa[6] = {
	0xda, 0x48, 0x19, 0x63, 0xf5, 0x69,
};

/*
 * ================================================================
 * The ATT signing construction -- Core 6.3 Vol 3 Part H Section 2.4.5.
 *
 * [ZEPHYR] subsys/bluetooth/host/smp.c:5483-5528, smp_sign_test().
 * [BLUEZ]  unit/test-crypto.c:74-167 and :179-196, test_sign.
 *
 * THIS IS THE POINT OF THIS ENTIRE HEADER.
 *
 * The specification publishes NO sample data for the signing construction.
 * Appendix D stops at the link key conversions.  So the truncation rule --
 * which 64 of the 128 CMAC bits become the signature, and in which order
 * they go on the wire -- has no normative worked example anywhere, and an
 * implementation that takes the WRONG half produces output that is the right
 * length, is deterministic, and verifies perfectly against itself.  That is
 * precisely the failure mode a self-derived oracle cannot see.
 *
 * Two independent stacks do publish vectors, and they agree byte for byte:
 * Zephyr's sig1..sig4 are identical to BlueZ's t_msg_1..t_msg_4.  These are
 * those four values.  They are reproducible from RFC 4493 alone with no
 * Bluetooth code of any kind, which is the strongest provenance available
 * for anything in this tree: the key is the RFC 4493 key and the messages
 * are the RFC 4493 messages, both byte-reversed, so a reader with nothing
 * but an AES-CMAC implementation can regenerate every octet.
 *
 * Signature layout, 12 octets: SignCounter as a 32-bit little-endian
 * integer in octets 0..3, then 8 octets of MAC in octets 4..11.  The MAC
 * octets are the MOST significant 8 octets of the RFC 4493 CMAC output
 * (MSB-first truncation), transmitted least significant first -- i.e. if the
 * CMAC output is T[0..15] with T[0] most significant, then
 * signature[4..11] = T[7], T[6], ..., T[0].
 *
 * All four vectors below use SignCounter 0, which is why octets 0..3 are
 * zero; bt_extref_ref_sign5_* below uses SignCounter 1 and pins that the
 * counter really is little-endian and really is covered by the MAC.
 * ================================================================
 */

/*
 * The signing key, little-endian.  Its byte-reverse is
 * 2b7e151628aed2a6abf7158809cf4f3c, the RFC 4493 Section 4 key K.
 */
static const uint8_t bt_extref_ref_sign_key[16] = {
	0x3c, 0x4f, 0xcf, 0x09, 0x88, 0x15, 0xf7, 0xab,
	0xa6, 0xd2, 0xae, 0x28, 0x16, 0x15, 0x7e, 0x2b,
};

/*
 * The message buffer.  Both references keep one 64-octet array and sign
 * prefixes of it of length 0, 16, 40 and 64 -- the four RFC 4493 example
 * lengths.  Unlike the key this array is NOT reversed: it is the RFC 4493
 * message in the order the RFC prints it, and the reversal happens inside
 * the signing function, over (message || SignCounter) as a whole.
 */
static const uint8_t bt_extref_ref_sign_msg[64] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
	0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
	0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};

/* len = 0.  [ZEPHYR] smp.c:5485 sig1 == [BLUEZ] test-crypto.c:81 t_msg_1. */
static const uint8_t bt_extref_ref_sign_len0[12] = {
	0x00, 0x00, 0x00, 0x00, 0xb3, 0xa8, 0x59, 0x41,
	0x27, 0xeb, 0xc2, 0xc0,
};
/* len = 16. [ZEPHYR] smp.c:5489 sig2 == [BLUEZ] test-crypto.c:98 t_msg_2. */
static const uint8_t bt_extref_ref_sign_len16[12] = {
	0x00, 0x00, 0x00, 0x00, 0x27, 0x39, 0x74, 0xf4,
	0x39, 0x2a, 0x23, 0x2a,
};
/* len = 40. [ZEPHYR] smp.c:5493 sig3 == [BLUEZ] test-crypto.c:116 t_msg_3. */
static const uint8_t bt_extref_ref_sign_len40[12] = {
	0x00, 0x00, 0x00, 0x00, 0xb7, 0xca, 0x94, 0xab,
	0x87, 0xc7, 0x82, 0x18,
};
/* len = 64. [ZEPHYR] smp.c:5497 sig4 == [BLUEZ] test-crypto.c:136 t_msg_4. */
static const uint8_t bt_extref_ref_sign_len64[12] = {
	0x00, 0x00, 0x00, 0x00, 0x44, 0xe1, 0xe6, 0xce,
	0x1d, 0xf5, 0x13, 0x68,
};

/*
 * A fifth vector, BlueZ only ([BLUEZ] unit/test-crypto.c:147-167).  Zephyr
 * has no counterpart.  It matters because it is the only published vector
 * with a NONZERO SignCounter, so it is the only one that can distinguish a
 * counter that is merely echoed into the signature from a counter that is
 * actually fed to the MAC.  The message is a real ATT Signed Write Command
 * body: opcode 0xD2, handle 0x0012, value 0x1337.
 */
static const uint8_t bt_extref_ref_sign5_key[16] = {
	0x50, 0x5e, 0x42, 0xdf, 0x96, 0x91, 0xec, 0x72,
	0xd3, 0x1f, 0xcd, 0xfb, 0xeb, 0x64, 0x1b, 0x61,
};
static const uint8_t bt_extref_ref_sign5_msg[5] = {
	0xd2, 0x12, 0x00, 0x13, 0x37,
};
#define BT_EXTREF_REF_SIGN5_COUNTER	1u
static const uint8_t bt_extref_ref_sign5_sig[12] = {
	0x01, 0x00, 0x00, 0x00, 0xf1, 0x87, 0x1e, 0x93,
	0x3c, 0x90, 0x0f, 0xf2,
};

/*
 * The complete signed PDU BlueZ verifies ([BLUEZ] unit/test-crypto.c:269-274,
 * verify_sign_pass_data), and the same PDU with the last octet corrupted
 * from 0xf2 to 0xf1, which must NOT verify (:281-286).  The one-octet delta
 * is the whole test: a verifier that compares fewer than 8 MAC octets, or
 * that compares them in the wrong order, still accepts the corrupt PDU.
 */
static const uint8_t bt_extref_ref_verify_pass_pdu[17] = {
	0xd2, 0x12, 0x00, 0x13, 0x37, 0x01, 0x00, 0x00,
	0x00, 0xf1, 0x87, 0x1e, 0x93, 0x3c, 0x90, 0x0f,
	0xf2,
};
static const uint8_t bt_extref_ref_verify_fail_pdu[17] = {
	0xd2, 0x12, 0x00, 0x13, 0x37, 0x01, 0x00, 0x00,
	0x00, 0xf1, 0x87, 0x1e, 0x93, 0x3c, 0x90, 0x0f,
	0xf1,
};

/*
 * ================================================================
 * A BEHAVIOUR, not a value: signing must not disturb the caller's message.
 *
 * [ZEPHYR] subsys/bluetooth/host/smp.c:5461-5469, inside sign_test(): after
 * calling smp_sign_buf() the test compares the first len + 4 octets of the
 * buffer against a saved copy and FAILS if they changed.  Zephyr needs this
 * because its smp_sign_buf() byte-swaps the message in place and must swap it
 * back; a stack that reverses in place and forgets to restore corrupts the
 * very PDU it is about to transmit, and no output-value assertion catches it.
 * ================================================================
 */
#define BT_EXTREF_REF_SIGN_PRESERVES_MESSAGE	1

/*
 * ================================================================
 * RECORDED DISAGREEMENT: Zephyr contradicts itself about h8.
 *
 * Not used by any assertion here -- blued does not implement h8, which is
 * the BIG group session key derivation of [SPEC] Vol 6, Part E, Section 1.1.1
 * and belongs to isochronous broadcast, not to SMP.  It is recorded because
 * it is a worked example of exactly the failure this corpus exists to catch,
 * found in a reference we are otherwise trusting.
 *
 *   [ZEPHYR] subsys/bluetooth/host/smp.c:5704-5727, smp_h8_test(), passes
 *     k  = ec 02 34 a3 57 c8 ad 05 34 10 10 a6 0a 39 7d 9b
 *     s  = 15 36 d1 8d e3 d2 0d f9 9b 70 44 c1 2f 9e d5 ba
 *     id = cc 03 01 48
 *   which is the specification's Appendix hex copied down the page in
 *   MOST-significant-first order -- into bt_crypto_h8(), whose siblings
 *   bt_crypto_h6() and bt_crypto_h7() in the same file are fed
 *   LEAST-significant-first values four functions earlier.
 *
 *   [ZEPHYR] tests/bluetooth/bt_crypto/src/test_bt_crypto.c:163-177,
 *     test_result_h8(), calls the SAME function with the byte-REVERSED
 *     values and the byte-reversed expectation.
 *
 * Both cannot be right.  Recomputing h8 with an AES-CMAC implementation that
 * has nothing to do with either stack shows the ztest is correct and
 * smp_self_test()'s h8 case is wrong: fed the big-endian inputs, h8 returns
 * 1b6f6fd8aab26a4a072a5d6f21c69818, not the e5e5bebaae7228e722a38904ed350f6d
 * the case asserts.  smp_h8_test() therefore cannot ever have passed.  It
 * survives because it is reachable only under CONFIG_BT_SMP_SELFTEST, which
 * is not set in any default configuration.
 *
 * The lesson for this tree, which is why it is written down here: a test that
 * nothing runs is worth exactly as much as no test, and a vector transcribed
 * in the wrong byte order looks perfectly respectable on the page.
 * ================================================================
 */

#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_SMP_REF_VECTORS_H */
