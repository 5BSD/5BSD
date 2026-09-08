/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * spec_extref_mesh_vectors.h - EXTERNAL reference vectors for Bluetooth Mesh
 * cryptography.
 *
 * PURPOSE / ANTI-DRIFT CONTRACT
 * =============================
 * /usr/src/bluetooth-specs contains no Mesh Profile specification, so the
 * in-tree mesh oracles have no external gate and could silently mirror the
 * blued implementation.  Every value in this header was transcribed from an
 * EXTERNAL source - the BlueZ 5.87 source tree - and NOT from any file under
 * /usr/src/usr.sbin/bluetooth.  No value here was produced by reading,
 * running, or reasoning about 5BSD mesh code.
 *
 * EXTERNAL SOURCE OF RECORD
 *   BlueZ, https://git.kernel.org/pub/scm/bluetooth/bluez.git
 *   configure.ac AC_INIT(bluez, 5.87)
 *   snapshot commit 92305dc06ab8a6d89af2dae1d725cc4d51462ad1
 *   Primary file: unit/test-mesh-crypto.c  (Copyright (C) 2019 Intel Corp.)
 *   Supporting file: mesh/crypto.c         (algorithm construction only)
 *
 * Each BlueZ test-vector struct in unit/test-mesh-crypto.c carries a .name
 * field naming the Mesh Profile v1.0.1 "Sample data" section it implements
 * (e.g. "8.1.3 k2 function (flooding)").  Those section numbers are BlueZ's
 * own citation of the specification and are reproduced verbatim below.  Line
 * numbers refer to the snapshot commit named above.
 *
 * BYTE ORDER - IMPORTANT, AND DIFFERENT FROM SMP
 * ==============================================
 * Bluetooth Mesh crypto is MSB-first (big-endian, wire order) end to end.  It
 * does NOT use the LSB-first convention that SMP uses.
 *
 * Evidence, read from the external tree, not assumed:
 *   - BlueZ SMP path src/shared/crypto.c defines swap_buf() at line 254 and
 *     calls it on key, message and result in bt_crypto_e/ah/f4/f5/g2
 *     (lines 284, 291, 318, 367, 375, 383, 627, 628, 633, 954, 961).  SMP
 *     values are therefore byte-reversed before hitting the cipher.
 *   - BlueZ mesh path mesh/crypto.c contains NO swap_buf, no bswap and no
 *     reversal of any kind.  aes_cmac_one() (mesh/crypto.c:56) and
 *     aes_ecb_one() (mesh/crypto.c:28) feed the caller's buffers to the
 *     cipher unmodified, and every multi-octet field is composed with the
 *     big-endian helpers l_put_be16/l_put_be32/l_put_be64 (e.g.
 *     mesh_crypto_network_nonce, mesh/crypto.c:314-326).
 *   - unit/test-mesh-crypto.c turns the hex strings below into bytes with
 *     l_util_from_hexstring(), which preserves written order, and compares
 *     with l_util_hexstring() of the raw buffer (verify_data(),
 *     unit/test-mesh-crypto.c:703).
 *
 * Consequence for consumers: EVERY array in this header is in transmission /
 * MSB-first order and must be passed to an AES-CMAC / AES-ECB / AES-CCM
 * primitive exactly as stored.  If a blued mesh routine needs a byte-reversed
 * buffer, the test must do the reversal explicitly - that would itself be a
 * finding worth reporting.
 *
 * INTENTIONAL OMISSIONS
 * =====================
 * Values that could not be traced to an external source are ABSENT rather
 * than guessed.  See the "GAP" comments in sections 9 and 10.
 *
 * Standalone: this header includes only <stdint.h> and depends on no blued
 * header.  It is idempotent under repeated inclusion.
 */
#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_MESH_VECTORS_H
#define TESTS_BLUETOOTH_SPEC_EXTREF_MESH_VECTORS_H

#include <stdint.h>

/* Provenance stamp, so a test can print what it is gated against. */
#define BT_EXTREF_MESH_SOURCE_PROJECT "BlueZ 5.87"
#define BT_EXTREF_MESH_SOURCE_COMMIT \
	"92305dc06ab8a6d89af2dae1d725cc4d51462ad1"
#define BT_EXTREF_MESH_SOURCE_FILE "unit/test-mesh-crypto.c"
#define BT_EXTREF_MESH_SPEC_CITED "Mesh Profile v1.0.1, Section 8 Sample Data"
/* All arrays below are MSB-first / wire order.  See header comment. */
#define BT_EXTREF_MESH_BYTE_ORDER_MSB_FIRST 1

/*
 * ===========================================================================
 * 1. s1 - SALT generation function.
 *
 * Construction: s1(M) = AES-CMAC(key = 0^128, M).
 *   BlueZ mesh/crypto.c:400 mesh_crypto_s1()
 *   Driver: unit/test-mesh-crypto.c:1918 check_s1(), invoked at line 2139.
 *
 * Mesh Profile section cited by BlueZ: 8.1.1 "s1 SALT generation function"
 *   (unit/test-mesh-crypto.c:99-103, struct s8_1_1).
 *
 * The input is the four ASCII octets "test", NOT a hex literal: check_s1()
 * passes keys->salt and strlen(keys->salt) straight through
 * (unit/test-mesh-crypto.c:1926).
 * ===========================================================================
 */
/* unit/test-mesh-crypto.c:101 .salt = "test" (ASCII 't','e','s','t'). */
static const uint8_t bt_extref_mesh_s8_1_1_s1_input[] = {
	0x74, 0x65, 0x73, 0x74
};
/* unit/test-mesh-crypto.c:102 .salt_out. */
static const uint8_t bt_extref_mesh_s8_1_1_s1_output[] = {
	0xb7, 0x3c, 0xef, 0xbd, 0x64, 0x1e, 0xf2, 0xea,
	0x59, 0x8c, 0x2b, 0x6e, 0xfb, 0x62, 0xf7, 0x9c
};
#define BT_EXTREF_MESH_S8_1_1_S1_INPUT_HEX "74657374"
#define BT_EXTREF_MESH_S8_1_1_S1_OUTPUT_HEX \
	"b73cefbd641ef2ea598c2b6efb62f79c"

/*
 * ===========================================================================
 * 2. k1 - derivation function.
 *
 * Construction: T = AES-CMAC(key = SALT, N); k1 = AES-CMAC(key = T, P).
 *   BlueZ mesh/crypto.c:132 mesh_crypto_k1()
 *   Driver: unit/test-mesh-crypto.c:1972 check_k1(), invoked at line 2140.
 *
 * Mesh Profile section cited by BlueZ: 8.1.2 "k1 function"
 *   (unit/test-mesh-crypto.c:105-111, struct s8_1_2).
 *
 * GAP, deliberate: BlueZ does NOT hardcode the 16-octet SALT and P operands.
 * check_k1() computes them at runtime as SALT = s1("salt") and P = s1("info")
 * (unit/test-mesh-crypto.c:1988 and :1994) from the ASCII strings at
 * unit/test-mesh-crypto.c:108-109.  The expanded 16-octet SALT/P values are
 * therefore NOT reproduced here - they are not present in any external source
 * available to this header, and computing them locally would defeat the
 * anti-drift purpose.  A consumer must derive them with its own (separately
 * gated, see section 1) s1 implementation.
 * ===========================================================================
 */
/* unit/test-mesh-crypto.c:107 .ikm - the N operand of k1. */
static const uint8_t bt_extref_mesh_s8_1_2_k1_n[] = {
	0x32, 0x16, 0xd1, 0x50, 0x98, 0x84, 0xb5, 0x33,
	0x24, 0x85, 0x41, 0x79, 0x2b, 0x87, 0x7f, 0x98
};
/* unit/test-mesh-crypto.c:108 .salt - ASCII "salt"; SALT operand = s1(this). */
static const uint8_t bt_extref_mesh_s8_1_2_k1_salt_ascii[] = {
	0x73, 0x61, 0x6c, 0x74
};
/* unit/test-mesh-crypto.c:109 .info - ASCII "info"; P operand = s1(this). */
static const uint8_t bt_extref_mesh_s8_1_2_k1_p_ascii[] = {
	0x69, 0x6e, 0x66, 0x6f
};
/* unit/test-mesh-crypto.c:110 .okm - expected k1 output. */
static const uint8_t bt_extref_mesh_s8_1_2_k1_okm[] = {
	0xf6, 0xed, 0x15, 0xa8, 0x93, 0x4a, 0xfb, 0xe7,
	0xd8, 0x3e, 0x8d, 0xcb, 0x57, 0xfc, 0xf5, 0xd7
};
#define BT_EXTREF_MESH_S8_1_2_K1_OKM_HEX "f6ed15a8934afbe7d83e8dcb57fcf5d7"

/*
 * ===========================================================================
 * 3. k2 - network key material: NID, encryption key, privacy key.
 *
 * Construction (BlueZ mesh/crypto.c:143 mesh_crypto_k2()):
 *   SALT = s1("smk2")                          mesh/crypto.c:158
 *   T    = AES-CMAC(key = SALT, N)             mesh/crypto.c:161
 *   T1   = AES-CMAC(key = T, P || 0x01)        mesh/crypto.c:168-171
 *   NID  = T1[15] & 0x7f                       mesh/crypto.c:174
 *   T2   = AES-CMAC(key = T, T1 || P || 0x02)  mesh/crypto.c:176-180
 *   EncryptionKey = T2                         mesh/crypto.c:183
 *   T3   = AES-CMAC(key = T, T2 || P || 0x03)  mesh/crypto.c:185-189
 *   PrivacyKey    = T3                         mesh/crypto.c:192
 *   Driver: unit/test-mesh-crypto.c:2010 check_k2(); invoked 2141,2142,
 *   2148, 2149.
 *
 * The friendship P operand is assembled by the driver as
 *   P = 0x01 || LPNAddress || FriendAddress || LPNCounter || FriendCounter
 * each field big-endian (unit/test-mesh-crypto.c:2039-2044), and the struct
 * also carries the assembled P as a literal, which is what is stored here.
 * ===========================================================================
 */

/* --- 8.1.3 k2 function (flooding), unit/test-mesh-crypto.c:113-120. ------ */
/* :115 .net_key */
static const uint8_t bt_extref_mesh_s8_1_3_k2_n[] = {
	0xf7, 0xa2, 0xa4, 0x4f, 0x8e, 0x8a, 0x80, 0x29,
	0x06, 0x4f, 0x17, 0x3d, 0xdc, 0x1e, 0x2b, 0x00
};
/* :116 .p - the master/flooding security material P = 0x00 */
static const uint8_t bt_extref_mesh_s8_1_3_k2_p[] = { 0x00 };
/* :117 .nid */
#define BT_EXTREF_MESH_S8_1_3_K2_NID 0x7f
/* :118 .enc_key */
static const uint8_t bt_extref_mesh_s8_1_3_k2_enc_key[] = {
	0x9f, 0x58, 0x91, 0x81, 0xa0, 0xf5, 0x0d, 0xe7,
	0x3c, 0x80, 0x70, 0xc7, 0xa6, 0xd2, 0x7f, 0x46
};
/* :119 .priv_key */
static const uint8_t bt_extref_mesh_s8_1_3_k2_priv_key[] = {
	0x4c, 0x71, 0x5b, 0xd4, 0xa6, 0x4b, 0x93, 0x8f,
	0x99, 0xb4, 0x53, 0x35, 0x16, 0x53, 0x12, 0x4f
};

/* --- 8.1.4 k2 function (friendship), unit/test-mesh-crypto.c:122-134. ---- */
/* :129 .net_key - same N as 8.1.3 */
static const uint8_t bt_extref_mesh_s8_1_4_k2_n[] = {
	0xf7, 0xa2, 0xa4, 0x4f, 0x8e, 0x8a, 0x80, 0x29,
	0x06, 0x4f, 0x17, 0x3d, 0xdc, 0x1e, 0x2b, 0x00
};
/* :125-:128 LPN addr 0203, Friend addr 0405, LPN cntr 0607, Friend cntr 0809 */
/* :130 .p - assembled friendship material */
static const uint8_t bt_extref_mesh_s8_1_4_k2_p[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
};
/* :131 .nid */
#define BT_EXTREF_MESH_S8_1_4_K2_NID 0x73
/* :132 .enc_key */
static const uint8_t bt_extref_mesh_s8_1_4_k2_enc_key[] = {
	0x11, 0xef, 0xec, 0x06, 0x42, 0x77, 0x49, 0x92,
	0x51, 0x0f, 0xb5, 0x92, 0x96, 0x46, 0xdf, 0x49
};
/* :133 .priv_key */
static const uint8_t bt_extref_mesh_s8_1_4_k2_priv_key[] = {
	0xd4, 0xd7, 0xcc, 0x0d, 0xfa, 0x77, 0x2d, 0x83,
	0x6a, 0x8d, 0xf9, 0xdf, 0x55, 0x10, 0xd7, 0xa7
};

/*
 * --- 8.2.2 Encryption and privacy keys (flooding),
 *     unit/test-mesh-crypto.c:161-168.
 * This is the network key used by every 8.3.x message vector below.
 */
/* :163 .net_key */
static const uint8_t bt_extref_mesh_s8_2_2_k2_n[] = {
	0x7d, 0xd7, 0x36, 0x4c, 0xd8, 0x42, 0xad, 0x18,
	0xc1, 0x7c, 0x2b, 0x82, 0x0c, 0x84, 0xc3, 0xd6
};
/* :164 .p */
static const uint8_t bt_extref_mesh_s8_2_2_k2_p[] = { 0x00 };
/* :165 .nid */
#define BT_EXTREF_MESH_S8_2_2_K2_NID 0x68
/* :166 .enc_key */
static const uint8_t bt_extref_mesh_s8_2_2_k2_enc_key[] = {
	0x09, 0x53, 0xfa, 0x93, 0xe7, 0xca, 0xac, 0x96,
	0x38, 0xf5, 0x88, 0x20, 0x22, 0x0a, 0x39, 0x8e
};
/* :167 .priv_key */
static const uint8_t bt_extref_mesh_s8_2_2_k2_priv_key[] = {
	0x8b, 0x84, 0xee, 0xde, 0xc1, 0x00, 0x06, 0x7d,
	0x67, 0x09, 0x71, 0xdd, 0x2a, 0xa7, 0x00, 0xcf
};

/*
 * --- 8.2.3 Encryption and privacy keys (Friendship),
 *     unit/test-mesh-crypto.c:170-182.
 */
/* :177 .net_key - same N as 8.2.2 */
static const uint8_t bt_extref_mesh_s8_2_3_k2_n[] = {
	0x7d, 0xd7, 0x36, 0x4c, 0xd8, 0x42, 0xad, 0x18,
	0xc1, 0x7c, 0x2b, 0x82, 0x0c, 0x84, 0xc3, 0xd6
};
/* :173-:176 LPN addr 1201, Friend addr 2345, LPN cntr 0000, Fn cntr 072f */
#define BT_EXTREF_MESH_S8_2_3_LPN_ADDR 0x1201
#define BT_EXTREF_MESH_S8_2_3_FRIEND_ADDR 0x2345
#define BT_EXTREF_MESH_S8_2_3_LPN_COUNTER 0x0000
#define BT_EXTREF_MESH_S8_2_3_FRIEND_COUNTER 0x072f
/* :178 .p */
static const uint8_t bt_extref_mesh_s8_2_3_k2_p[] = {
	0x01, 0x12, 0x01, 0x23, 0x45, 0x00, 0x00, 0x07, 0x2f
};
/* :179 .nid */
#define BT_EXTREF_MESH_S8_2_3_K2_NID 0x5e
/* :180 .enc_key */
static const uint8_t bt_extref_mesh_s8_2_3_k2_enc_key[] = {
	0xbe, 0x63, 0x51, 0x05, 0x43, 0x48, 0x59, 0xf4,
	0x84, 0xfc, 0x79, 0x8e, 0x04, 0x3c, 0xe4, 0x0e
};
/* :181 .priv_key */
static const uint8_t bt_extref_mesh_s8_2_3_k2_priv_key[] = {
	0x5d, 0x39, 0x6d, 0x4b, 0x54, 0xd3, 0xcb, 0xaf,
	0xe9, 0x43, 0xe0, 0x51, 0xfe, 0x9a, 0x4e, 0xb8
};

/*
 * ===========================================================================
 * 4. k3 - Network ID (8 octets).
 *
 * Construction (BlueZ mesh/crypto.c:252 mesh_crypto_k3()):
 *   SALT = s1("smk3"); T = AES-CMAC(key = SALT, N);
 *   k3   = AES-CMAC(key = T, "id64" || 0x01)[8..15]   (low 8 octets)
 *   Driver: unit/test-mesh-crypto.c:2065 check_k3(); invoked 2143 and 2150.
 * ===========================================================================
 */
/* Info operand, literal, mesh/crypto.c:254: 'i','d','6','4',0x01 */
static const uint8_t bt_extref_mesh_k3_info[] = {
	0x69, 0x64, 0x36, 0x34, 0x01
};
/* Salt operand ASCII, mesh/crypto.c:258 "smk3". */
static const uint8_t bt_extref_mesh_k3_salt_ascii[] = {
	0x73, 0x6d, 0x6b, 0x33
};

/* --- 8.1.5 k3 function, unit/test-mesh-crypto.c:136-142. ---------------- */
/* :138 .net_key (same N as 8.1.3) -> :141 .short_net_id */
static const uint8_t bt_extref_mesh_s8_1_5_k3_n[] = {
	0xf7, 0xa2, 0xa4, 0x4f, 0x8e, 0x8a, 0x80, 0x29,
	0x06, 0x4f, 0x17, 0x3d, 0xdc, 0x1e, 0x2b, 0x00
};
static const uint8_t bt_extref_mesh_s8_1_5_k3_out[] = {
	0xff, 0x04, 0x69, 0x58, 0x23, 0x3d, 0xb0, 0x14
};

/* --- 8.2.4 Network ID, unit/test-mesh-crypto.c:184-190. ----------------- */
/* :186 .net_key (same N as 8.2.2) -> :189 .short_net_id */
static const uint8_t bt_extref_mesh_s8_2_4_k3_n[] = {
	0x7d, 0xd7, 0x36, 0x4c, 0xd8, 0x42, 0xad, 0x18,
	0xc1, 0x7c, 0x2b, 0x82, 0x0c, 0x84, 0xc3, 0xd6
};
static const uint8_t bt_extref_mesh_s8_2_4_network_id[] = {
	0x3e, 0xca, 0xff, 0x67, 0x2f, 0x67, 0x33, 0x70
};

/*
 * ===========================================================================
 * 5. k4 - Application key identifier (AID, 6 bits).
 *
 * Construction (BlueZ mesh/crypto.c:272 mesh_crypto_k4()):
 *   SALT = s1("smk4"); T = AES-CMAC(key = SALT, A);
 *   AID  = AES-CMAC(key = T, "id6" || 0x01)[15] & 0x3f
 *   Driver: unit/test-mesh-crypto.c:2098 check_k4(); invoked 2144 and 2147.
 * ===========================================================================
 */
/* Info operand, literal, mesh/crypto.c:274: 'i','d','6',0x01 */
static const uint8_t bt_extref_mesh_k4_info[] = {
	0x69, 0x64, 0x36, 0x01
};
/* Salt operand ASCII, mesh/crypto.c:278 "smk4". */
static const uint8_t bt_extref_mesh_k4_salt_ascii[] = {
	0x73, 0x6d, 0x6b, 0x34
};
#define BT_EXTREF_MESH_K4_AID_MASK 0x3f

/* --- 8.1.6 k4 function, unit/test-mesh-crypto.c:144-150. ---------------- */
/* :146 .app_key -> :149 .aid */
static const uint8_t bt_extref_mesh_s8_1_6_k4_a[] = {
	0x32, 0x16, 0xd1, 0x50, 0x98, 0x84, 0xb5, 0x33,
	0x24, 0x85, 0x41, 0x79, 0x2b, 0x87, 0x7f, 0x98
};
#define BT_EXTREF_MESH_S8_1_6_K4_AID 0x38

/* --- 8.2.1 Application key AID, unit/test-mesh-crypto.c:153-159. -------- */
/* :155 .app_key -> :158 .aid.  This AppKey is used by 8.3.22 below. */
static const uint8_t bt_extref_mesh_s8_2_1_k4_a[] = {
	0x63, 0x96, 0x47, 0x71, 0x73, 0x4f, 0xbd, 0x76,
	0xe3, 0xb4, 0x05, 0x19, 0xd1, 0xd9, 0x4a, 0x48
};
#define BT_EXTREF_MESH_S8_2_1_K4_AID 0x26

/*
 * ===========================================================================
 * 6. k1-with-fixed-salt derivations: Identity Key and Beacon Key.
 *
 * Construction (BlueZ mesh/crypto.c:203 crypto_128()):
 *   out128 = k1(N, s1(<4-char salt string>), "id128" || 0x01)
 *   nkik -> Identity Key   mesh/crypto.c:214 mesh_crypto_nkik()
 *   nkbk -> Beacon Key     mesh/crypto.c:242 mesh_crypto_nkbk()
 *   nkpk -> Private Beacon Key mesh/crypto.c:247 mesh_crypto_nkpk()
 *   Driver: unit/test-mesh-crypto.c:1932 check_k128(); invoked 2151, 2152.
 * ===========================================================================
 */
/* Info operand, literal, mesh/crypto.c:205: 'i','d','1','2','8',0x01 */
static const uint8_t bt_extref_mesh_id128_info[] = {
	0x69, 0x64, 0x31, 0x32, 0x38, 0x01
};
/* Salt strings, mesh/crypto.c:216/244/249. */
static const uint8_t bt_extref_mesh_nkik_salt_ascii[] = {
	0x6e, 0x6b, 0x69, 0x6b			/* "nkik" */
};
static const uint8_t bt_extref_mesh_nkbk_salt_ascii[] = {
	0x6e, 0x6b, 0x62, 0x6b			/* "nkbk" */
};
static const uint8_t bt_extref_mesh_nkpk_salt_ascii[] = {
	0x6e, 0x6b, 0x70, 0x6b			/* "nkpk" */
};

/* --- 8.2.5 Identity Key, unit/test-mesh-crypto.c:192-198. --------------- */
/* :194 .net_key (same N as 8.2.2) -> :197 .enc_key (the identity key) */
static const uint8_t bt_extref_mesh_s8_2_5_identity_key[] = {
	0x84, 0x39, 0x6c, 0x43, 0x5a, 0xc4, 0x85, 0x60,
	0xb5, 0x96, 0x53, 0x85, 0x25, 0x3e, 0x21, 0x0c
};

/* --- 8.2.6 Beacon Key, unit/test-mesh-crypto.c:200-206. ----------------- */
/* :202 .net_key (same N as 8.2.2) -> :205 .enc_key (the beacon key) */
static const uint8_t bt_extref_mesh_s8_2_6_beacon_key[] = {
	0x54, 0x23, 0xd9, 0x67, 0xda, 0x63, 0x9a, 0x99,
	0xcb, 0x02, 0x23, 0x1a, 0x83, 0xf7, 0xd2, 0x54
};

/*
 * ===========================================================================
 * 7. Nonce constructions, obfuscation input (Privacy Random) and PECB.
 *
 * Network nonce, 13 octets (BlueZ mesh/crypto.c:314
 * mesh_crypto_network_nonce()):
 *   [0]     0x00                      (Network nonce type)
 *   [1]     (TTL & 0x7f) | (CTL ? 0x80 : 0)
 *   [2..4]  SEQ, 24 bits, big-endian
 *   [5..6]  SRC, big-endian
 *   [7..8]  0x0000                    (pad)
 *   [9..12] IV Index, 32 bits, big-endian
 *
 * Application nonce, 13 octets (mesh/crypto.c:328
 * mesh_crypto_application_nonce()): identical layout except
 *   [0] = 0x01 and [7..8] = DST (big-endian), [1] = ASZMIC ? 0x80 : 0.
 * Device nonce (mesh/crypto.c:342): identical to application nonce with
 *   [0] = 0x02.  Proxy nonce (mesh/crypto.c:356): [0] = 0x03, [7..8] = 0.
 *
 * Privacy Random / privacy counter, 16 octets (mesh/crypto.c:459
 * mesh_crypto_privacy_counter()):
 *   [0..4]   0x00 x 5
 *   [5..8]   IV Index, big-endian
 *   [9..15]  first 7 octets of the ENCRYPTED network payload
 *            (i.e. packet + 7: obfuscated-header-independent DST||TransportPDU
 *            after network encryption)
 *
 * PECB (mesh/crypto.c:468 mesh_crypto_pecb()):
 *   PECB = AES-ECB(key = PrivacyKey, PrivacyRandom)
 * Obfuscation (mesh/crypto.c:477 mesh_crypto_network_obfuscate()):
 *   the 6 octets CTL/TTL||SEQ||SRC at packet[1..6] are XORed with PECB[0..5].
 * De-obfuscation is the same XOR (mesh/crypto.c:500
 * mesh_crypto_network_clarify()).
 *
 * The worked examples in section 8 below supply concrete nonce and privacy
 * random values for these layouts.
 * ===========================================================================
 */
#define BT_EXTREF_MESH_NONCE_LEN 13
#define BT_EXTREF_MESH_NONCE_TYPE_NETWORK 0x00
#define BT_EXTREF_MESH_NONCE_TYPE_APPLICATION 0x01
#define BT_EXTREF_MESH_NONCE_TYPE_DEVICE 0x02
#define BT_EXTREF_MESH_NONCE_TYPE_PROXY 0x03
#define BT_EXTREF_MESH_PRIVACY_RANDOM_LEN 16
#define BT_EXTREF_MESH_PRIVACY_RANDOM_IVINDEX_OFFSET 5
#define BT_EXTREF_MESH_PRIVACY_RANDOM_PAYLOAD_OFFSET 9
#define BT_EXTREF_MESH_PRIVACY_RANDOM_PAYLOAD_LEN 7
#define BT_EXTREF_MESH_OBFUSCATED_HEADER_OFFSET 1
#define BT_EXTREF_MESH_OBFUSCATED_HEADER_LEN 6

/*
 * ===========================================================================
 * 8. Worked network/upper-transport examples.
 *
 * All three use the 8.2.2 network key material (NID 0x68 / EncKey / PrivKey)
 * unless noted.  Driver: unit/test-mesh-crypto.c:978 check_encrypt() and
 * :1500-ish check_decrypt(); invoked from main() lines 2155-2178.
 * Packet layout produced/consumed by the driver, MSB-first:
 *   [0]        (IVI << 7) | NID          (set at unit/test-mesh-crypto.c:970)
 *   [1..6]     obfuscated CTL/TTL||SEQ||SRC
 *   [7..8]     DST (encrypted)
 *   [9..]      encrypted Lower Transport PDU
 *   tail       NetMIC, 8 octets when CTL == 1, else 4 octets
 * ===========================================================================
 */

/* --- 8.3.1 Message #1, unit/test-mesh-crypto.c:208-235. ---------------- */
/* :214 .iv_index */
#define BT_EXTREF_MESH_S8_3_1_IV_INDEX 0x12345678u
/* :216-:219 TTL/SEQ/SRC/DST, :222 NID, :225 CTL */
#define BT_EXTREF_MESH_S8_3_1_TTL 0x00
#define BT_EXTREF_MESH_S8_3_1_SEQ 0x000001u
#define BT_EXTREF_MESH_S8_3_1_SRC 0x1201
#define BT_EXTREF_MESH_S8_3_1_DST 0xfffd
#define BT_EXTREF_MESH_S8_3_1_NID 0x68
#define BT_EXTREF_MESH_S8_3_1_CTL 1
/* :221 .trans_pkt - plaintext Lower Transport PDU (Friend Request) */
static const uint8_t bt_extref_mesh_s8_3_1_transport_pdu[] = {
	0x03, 0x4b, 0x50, 0x05, 0x7e, 0x40, 0x00, 0x00,
	0x01, 0x00, 0x00
};
/* :227 .net_nonce - network nonce, 13 octets */
static const uint8_t bt_extref_mesh_s8_3_1_network_nonce[] = {
	0x00, 0x80, 0x00, 0x00, 0x01, 0x12, 0x01, 0x00,
	0x00, 0x12, 0x34, 0x56, 0x78
};
/* :229 .priv_rand - privacy random / privacy counter, 16 octets */
static const uint8_t bt_extref_mesh_s8_3_1_privacy_random[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56,
	0x78, 0xb5, 0xe5, 0xbf, 0xda, 0xcb, 0xaf, 0x6c
};
/* :231 .net_msg - encrypted DST||TransportPDU (before obfuscation) */
static const uint8_t bt_extref_mesh_s8_3_1_encrypted_payload[] = {
	0xb5, 0xe5, 0xbf, 0xda, 0xcb, 0xaf, 0x6c, 0xb7,
	0xfb, 0x6b, 0xff, 0x87, 0x1f
};
/* :232 .net_mic64 - 64-bit NetMIC, big-endian on the wire */
#define BT_EXTREF_MESH_S8_3_1_NET_MIC64 0x035444ce83a670dfULL
static const uint8_t bt_extref_mesh_s8_3_1_net_mic64_be[] = {
	0x03, 0x54, 0x44, 0xce, 0x83, 0xa6, 0x70, 0xdf
};
/* :234 .packet - complete obfuscated network PDU */
static const uint8_t bt_extref_mesh_s8_3_1_packet[] = {
	0x68, 0xec, 0xa4, 0x87, 0x51, 0x67, 0x65, 0xb5,
	0xe5, 0xbf, 0xda, 0xcb, 0xaf, 0x6c, 0xb7, 0xfb,
	0x6b, 0xff, 0x87, 0x1f, 0x03, 0x54, 0x44, 0xce,
	0x83, 0xa6, 0x70, 0xdf
};

/*
 * --- 8.3.6 Message #6, unit/test-mesh-crypto.c:365-407.
 * Segmented access message encrypted with the DEVICE key (nonce type 0x02).
 * :213/:270/:335 .dev_key is shared by all 8.3.x vectors.
 */
static const uint8_t bt_extref_mesh_s8_3_device_key[] = {
	0x9d, 0x6d, 0xd0, 0xe9, 0x6e, 0xb2, 0x5d, 0xc1,
	0x9a, 0x40, 0xed, 0x99, 0x14, 0xf8, 0xf0, 0x3f
};
#define BT_EXTREF_MESH_S8_3_6_IV_INDEX 0x12345678u
#define BT_EXTREF_MESH_S8_3_6_TTL 0x04
#define BT_EXTREF_MESH_S8_3_6_SRC 0x0003
#define BT_EXTREF_MESH_S8_3_6_DST 0x1201
#define BT_EXTREF_MESH_S8_3_6_NID 0x68
#define BT_EXTREF_MESH_S8_3_6_APP_SEQ 0x3129abu	/* :376 .app_seq */
#define BT_EXTREF_MESH_S8_3_6_SEQ_SEG0 0x3129abu	/* :377 .net_seq[0] */
#define BT_EXTREF_MESH_S8_3_6_SEQ_SEG1 0x3129acu	/* :378 .net_seq[1] */
/* :381 .app_msg - plaintext Access PDU (Config AppKey Add) */
static const uint8_t bt_extref_mesh_s8_3_6_access_pdu[] = {
	0x00, 0x56, 0x34, 0x12, 0x63, 0x96, 0x47, 0x71,
	0x73, 0x4f, 0xbd, 0x76, 0xe3, 0xb4, 0x05, 0x19,
	0xd1, 0xd9, 0x4a, 0x48
};
/* :386 .app_nonce - DEVICE nonce (type 0x02); DST occupies octets [7..8] */
static const uint8_t bt_extref_mesh_s8_3_6_device_nonce[] = {
	0x02, 0x00, 0x31, 0x29, 0xab, 0x00, 0x03, 0x12,
	0x01, 0x12, 0x34, 0x56, 0x78
};
/* :382 .enc_msg - upper-transport ciphertext (without TransMIC) */
static const uint8_t bt_extref_mesh_s8_3_6_upper_ciphertext[] = {
	0xee, 0x9d, 0xdd, 0xfd, 0x21, 0x69, 0x32, 0x6d,
	0x23, 0xf3, 0xaf, 0xdf, 0xcf, 0xdc, 0x18, 0xc5,
	0x2f, 0xde, 0xf7, 0x72
};
/* :383 .app_mic32 - 32-bit TransMIC */
#define BT_EXTREF_MESH_S8_3_6_TRANS_MIC32 0xe0e17308u
/* :390-:391 .net_nonce[0..1] */
static const uint8_t bt_extref_mesh_s8_3_6_network_nonce_seg0[] = {
	0x00, 0x04, 0x31, 0x29, 0xab, 0x00, 0x03, 0x00,
	0x00, 0x12, 0x34, 0x56, 0x78
};
static const uint8_t bt_extref_mesh_s8_3_6_network_nonce_seg1[] = {
	0x00, 0x04, 0x31, 0x29, 0xac, 0x00, 0x03, 0x00,
	0x00, 0x12, 0x34, 0x56, 0x78
};
/* :393-:394 .priv_rand[0..1] */
static const uint8_t bt_extref_mesh_s8_3_6_privacy_random_seg0[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56,
	0x78, 0x0a, 0xfb, 0xa8, 0xc6, 0x3d, 0x4e, 0x68
};
static const uint8_t bt_extref_mesh_s8_3_6_privacy_random_seg1[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56,
	0x78, 0x6c, 0xae, 0x0c, 0x03, 0x2b, 0xf0, 0x74
};
/* :396-:397 .trans_pkt[0..1] - plaintext Lower Transport PDUs */
static const uint8_t bt_extref_mesh_s8_3_6_transport_pdu_seg0[] = {
	0x80, 0x26, 0xac, 0x01, 0xee, 0x9d, 0xdd, 0xfd,
	0x21, 0x69, 0x32, 0x6d, 0x23, 0xf3, 0xaf, 0xdf
};
static const uint8_t bt_extref_mesh_s8_3_6_transport_pdu_seg1[] = {
	0x80, 0x26, 0xac, 0x21, 0xcf, 0xdc, 0x18, 0xc5,
	0x2f, 0xde, 0xf7, 0x72, 0xe0, 0xe1, 0x73, 0x08
};
/* :402-:403 .net_mic32[0..1] */
#define BT_EXTREF_MESH_S8_3_6_NET_MIC32_SEG0 0x939cda0eu
#define BT_EXTREF_MESH_S8_3_6_NET_MIC32_SEG1 0xbeed49c0u
/* :405-:406 .packet[0..1] - complete obfuscated network PDUs */
static const uint8_t bt_extref_mesh_s8_3_6_packet_seg0[] = {
	0x68, 0xca, 0xb5, 0xc5, 0x34, 0x8a, 0x23, 0x0a,
	0xfb, 0xa8, 0xc6, 0x3d, 0x4e, 0x68, 0x63, 0x64,
	0x97, 0x9d, 0xea, 0xf4, 0xfd, 0x40, 0x96, 0x11,
	0x45, 0x93, 0x9c, 0xda, 0x0e
};
static const uint8_t bt_extref_mesh_s8_3_6_packet_seg1[] = {
	0x68, 0x16, 0x15, 0xb5, 0xdd, 0x4a, 0x84, 0x6c,
	0xae, 0x0c, 0x03, 0x2b, 0xf0, 0x74, 0x6f, 0x44,
	0xf1, 0xb8, 0xcc, 0x8c, 0xe5, 0xed, 0xc5, 0x7e,
	0x55, 0xbe, 0xed, 0x49, 0xc0
};

/*
 * --- 8.3.22 Message #22, unit/test-mesh-crypto.c:582-619.
 * Access message to a VIRTUAL address, encrypted with the AppKey of 8.2.1
 * (AID 0x26) using the APPLICATION nonce (type 0x01).  The 16-octet Label
 * UUID is passed as the CCM additional authenticated data
 * (unit/test-mesh-crypto.c:1014 -> :1091/:1101 mesh_crypto_payload_encrypt).
 * Note the IV Index here is 0x12345677, not 0x12345678.
 */
#define BT_EXTREF_MESH_S8_3_22_IV_INDEX 0x12345677u
#define BT_EXTREF_MESH_S8_3_22_TTL 0x03
#define BT_EXTREF_MESH_S8_3_22_SEQ 0x07080bu
#define BT_EXTREF_MESH_S8_3_22_SRC 0x1234
#define BT_EXTREF_MESH_S8_3_22_DST 0xb529	/* virtual address */
#define BT_EXTREF_MESH_S8_3_22_NID 0x68
#define BT_EXTREF_MESH_S8_3_22_AID 0x26		/* :598 .key_aid */
#define BT_EXTREF_MESH_S8_3_22_AKF 1		/* :597 .akf */
/* :596 .uuid - Label UUID, also the CCM AAD */
static const uint8_t bt_extref_mesh_s8_3_22_label_uuid[] = {
	0x00, 0x73, 0xe7, 0xe4, 0xd8, 0xb9, 0x44, 0x0f,
	0xaf, 0x84, 0x15, 0xdf, 0x4c, 0x56, 0xc0, 0xe1
};
/* :599 .app_msg - plaintext Access PDU */
static const uint8_t bt_extref_mesh_s8_3_22_access_pdu[] = {
	0xd5, 0x0a, 0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f
};
/* :604 .app_nonce - APPLICATION nonce; [7..8] carry DST 0xb529 */
static const uint8_t bt_extref_mesh_s8_3_22_application_nonce[] = {
	0x01, 0x00, 0x07, 0x08, 0x0b, 0x12, 0x34, 0xb5,
	0x29, 0x12, 0x34, 0x56, 0x77
};
/* :600 .enc_msg, :601 .app_mic32 */
static const uint8_t bt_extref_mesh_s8_3_22_upper_ciphertext[] = {
	0x38, 0x71, 0xb9, 0x04, 0xd4, 0x31, 0x52, 0x63
};
#define BT_EXTREF_MESH_S8_3_22_TRANS_MIC32 0x16ca48a0u
/* :608 .net_nonce */
static const uint8_t bt_extref_mesh_s8_3_22_network_nonce[] = {
	0x00, 0x03, 0x07, 0x08, 0x0b, 0x12, 0x34, 0x00,
	0x00, 0x12, 0x34, 0x56, 0x77
};
/* :610 .priv_rand */
static const uint8_t bt_extref_mesh_s8_3_22_privacy_random[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56,
	0x77, 0xed, 0x31, 0xf3, 0xfd, 0xcf, 0x88, 0xa4
};
/* :612 .trans_pkt - unsegmented Lower Transport PDU (AKF|AID = 0x66) */
static const uint8_t bt_extref_mesh_s8_3_22_transport_pdu[] = {
	0x66, 0x38, 0x71, 0xb9, 0x04, 0xd4, 0x31, 0x52,
	0x63, 0x16, 0xca, 0x48, 0xa0
};
/* :614 .net_msg, :616 .net_mic32 */
static const uint8_t bt_extref_mesh_s8_3_22_encrypted_payload[] = {
	0xed, 0x31, 0xf3, 0xfd, 0xcf, 0x88, 0xa4, 0x11,
	0x13, 0x5f, 0xea, 0x55, 0xdf, 0x73, 0x0b
};
#define BT_EXTREF_MESH_S8_3_22_NET_MIC32 0x6b28e255u
/* :618 .packet - complete obfuscated network PDU (IVI bit set: 0xe8) */
static const uint8_t bt_extref_mesh_s8_3_22_packet[] = {
	0xe8, 0xd8, 0x5c, 0xae, 0xce, 0xf1, 0xe3, 0xed,
	0x31, 0xf3, 0xfd, 0xcf, 0x88, 0xa4, 0x11, 0x13,
	0x5f, 0xea, 0x55, 0xdf, 0x73, 0x0b, 0x6b, 0x28,
	0xe2, 0x55
};

/*
 * ===========================================================================
 * 9. Virtual address hashing.
 *
 * Construction (BlueZ mesh/crypto.c:443 mesh_crypto_virtual_addr()):
 *   salt = s1("vtad")
 *   tmp  = AES-CMAC(key = salt, LabelUUID[16])
 *   addr = (be16(tmp + 14) & 0x3fff) | 0x8000
 *
 * ADVISORY, read the caveat: the Label UUID
 * bt_extref_mesh_s8_3_22_label_uuid and the destination address 0xb529 are
 * both published inside the SAME BlueZ vector struct cited as Mesh Profile
 * section 8.3.22 (unit/test-mesh-crypto.c:595 and :596).  BlueZ itself does
 * NOT feed that UUID through mesh_crypto_virtual_addr() in any unit test - it
 * only uses the UUID as CCM AAD - so this pairing is inferred from the two
 * fields of one spec sample section rather than asserted by an external test.
 * Treat a mismatch as a strong signal but confirm against the specification
 * before declaring an implementation bug.
 * ===========================================================================
 */
static const uint8_t bt_extref_mesh_vtad_salt_ascii[] = {
	0x76, 0x74, 0x61, 0x64			/* "vtad" */
};
#define BT_EXTREF_MESH_VIRTUAL_ADDR_MASK 0x3fff
#define BT_EXTREF_MESH_VIRTUAL_ADDR_BASE 0x8000
/* ADVISORY, see caveat above: expected virtual address for the 8.3.22 UUID. */
#define BT_EXTREF_MESH_S8_3_22_VIRTUAL_ADDR_ADVISORY 0xb529

/*
 * ===========================================================================
 * 10. Beacons and node identity.
 * ===========================================================================
 */

/*
 * --- 8.4.3 Secure Network Beacon, unit/test-mesh-crypto.c:621-634.
 * Construction (mesh/crypto.c:291 mesh_crypto_beacon_cmac()):
 *   msg[0]     = (KR ? 0x01 : 0) | (IVU ? 0x02 : 0)
 *   msg[1..8]  = Network ID (k3 output)
 *   msg[9..12] = IV Index, big-endian
 *   CMAC       = AES-CMAC(key = BeaconKey, msg)[0..7]   (first 8 octets)
 * Beacon on the wire (unit/test-mesh-crypto.c:1845-1859):
 *   0x01 || Flags || NetworkID(8) || IVIndex(4, BE) || CMAC(8) = 22 octets.
 * Beacon key is the 8.2.6 value; Network ID is the 8.2.4 value.
 */
#define BT_EXTREF_MESH_S8_4_3_BEACON_TYPE 0x01
#define BT_EXTREF_MESH_S8_4_3_BEACON_FLAGS 0x00
#define BT_EXTREF_MESH_S8_4_3_IV_INDEX 0x12345678u
#define BT_EXTREF_MESH_S8_4_3_BEACON_LEN 22
/* :632 .beacon_cmac */
static const uint8_t bt_extref_mesh_s8_4_3_beacon_cmac[] = {
	0x8e, 0xa2, 0x61, 0x58, 0x2f, 0x36, 0x4f, 0x6f
};
/* :633 .beacon */
static const uint8_t bt_extref_mesh_s8_4_3_beacon[] = {
	0x01, 0x00, 0x3e, 0xca, 0xff, 0x67, 0x2f, 0x67,
	0x33, 0x70, 0x12, 0x34, 0x56, 0x78, 0x8e, 0xa2,
	0x61, 0x58, 0x2f, 0x36, 0x4f, 0x6f
};

/*
 * --- 8.4.6.1 Private Beacon IVU, unit/test-mesh-crypto.c:636-649.
 * Construction (unit/test-mesh-crypto.c:1860-1869): the Private Beacon Key is
 * nkpk (mesh/crypto.c:247); the 13-octet Random is the AES-CCM nonce; the
 * 5-octet plaintext Flags||IVIndex(BE) is encrypted in place with an 8-octet
 * MIC.  Wire form: 0x02 || Random(13) || EncFlagsAndIv(5) || MIC(8) = 27.
 */
#define BT_EXTREF_MESH_S8_4_6_1_BEACON_TYPE 0x02
#define BT_EXTREF_MESH_S8_4_6_1_BEACON_FLAGS 0x02
#define BT_EXTREF_MESH_S8_4_6_1_IV_INDEX 0x1010abcdu
#define BT_EXTREF_MESH_PRIVATE_BEACON_LEN 27
/* :639 .net_key */
static const uint8_t bt_extref_mesh_s8_4_6_1_net_key[] = {
	0xf7, 0xa2, 0xa4, 0x4f, 0x8e, 0x8a, 0x80, 0x29,
	0x06, 0x4f, 0x17, 0x3d, 0xdc, 0x1e, 0x2b, 0x00
};
/* :642 .enc_key - Private Beacon Key = nkpk(NetKey) */
static const uint8_t bt_extref_mesh_s8_4_6_1_private_beacon_key[] = {
	0x6b, 0xe7, 0x68, 0x42, 0x46, 0x0b, 0x2d, 0x3a,
	0x58, 0x50, 0xd4, 0x69, 0x84, 0x09, 0xf1, 0xbb
};
/* :643 .rand - 13-octet CCM nonce */
static const uint8_t bt_extref_mesh_s8_4_6_1_random[] = {
	0x43, 0x5f, 0x18, 0xf8, 0x5c, 0xf7, 0x8a, 0x31,
	0x21, 0xf5, 0x84, 0x78, 0xa5
};
/* :647 .beacon_cmac - here the 8-octet CCM MIC */
static const uint8_t bt_extref_mesh_s8_4_6_1_mic[] = {
	0xf3, 0x17, 0x4f, 0x02, 0x2a, 0x51, 0x47, 0x41
};
/* :648 .beacon */
static const uint8_t bt_extref_mesh_s8_4_6_1_beacon[] = {
	0x02, 0x43, 0x5f, 0x18, 0xf8, 0x5c, 0xf7, 0x8a,
	0x31, 0x21, 0xf5, 0x84, 0x78, 0xa5, 0x61, 0xe4,
	0x88, 0xe7, 0xcb, 0xf3, 0x17, 0x4f, 0x02, 0x2a,
	0x51, 0x47, 0x41
};

/* --- 8.4.6.2 Private Beacon IVU Complete, unit/test-mesh-crypto.c:651-664. */
#define BT_EXTREF_MESH_S8_4_6_2_BEACON_TYPE 0x02
#define BT_EXTREF_MESH_S8_4_6_2_BEACON_FLAGS 0x00
#define BT_EXTREF_MESH_S8_4_6_2_IV_INDEX 0x00000000u
/* :654 .net_key */
static const uint8_t bt_extref_mesh_s8_4_6_2_net_key[] = {
	0x3b, 0xbb, 0x6f, 0x1f, 0xbd, 0x53, 0xe1, 0x57,
	0x41, 0x7f, 0x30, 0x8c, 0xe7, 0xae, 0xc5, 0x8f
};
/* :657 .enc_key - Private Beacon Key = nkpk(NetKey) */
static const uint8_t bt_extref_mesh_s8_4_6_2_private_beacon_key[] = {
	0xca, 0x47, 0x8c, 0xda, 0xc6, 0x26, 0xb7, 0xa8,
	0x52, 0x2d, 0x72, 0x72, 0xdd, 0x12, 0x4f, 0x26
};
/* :658 .rand */
static const uint8_t bt_extref_mesh_s8_4_6_2_random[] = {
	0x1b, 0x99, 0x8f, 0x82, 0x92, 0x75, 0x35, 0xea,
	0x6f, 0x30, 0x76, 0xf4, 0x22
};
/* :662 .beacon_cmac - 8-octet CCM MIC */
static const uint8_t bt_extref_mesh_s8_4_6_2_mic[] = {
	0x2f, 0x0f, 0xfb, 0x94, 0xcf, 0x97, 0xf8, 0x81
};
/* :663 .beacon */
static const uint8_t bt_extref_mesh_s8_4_6_2_beacon[] = {
	0x02, 0x1b, 0x99, 0x8f, 0x82, 0x92, 0x75, 0x35,
	0xea, 0x6f, 0x30, 0x76, 0xf4, 0x22, 0xce, 0x82,
	0x74, 0x08, 0xab, 0x2f, 0x0f, 0xfb, 0x94, 0xcf,
	0x97, 0xf8, 0x81
};

/*
 * --- 8.6.2 Service Data using Node Identity, unit/test-mesh-crypto.c:666-677.
 * Construction (unit/test-mesh-crypto.c:1879 check_id_beacon(); primitive at
 * mesh/crypto.c:219 mesh_crypto_identity()):
 *   IdentityResolvingKey = nkik(NetKey)                (= the 8.2.5 value)
 *   HashInput[0..5]   = 0x00 x 6
 *   HashInput[6..13]  = Random (8 octets)
 *   HashInput[14..15] = node unicast address, big-endian
 *   Hash = AES-ECB(key = IdentityResolvingKey, HashInput)[8..15]
 *   Service data = 0x01 || Hash(8) || Random(8)        (17 octets)
 */
#define BT_EXTREF_MESH_S8_6_2_SRC 0x1201
#define BT_EXTREF_MESH_S8_6_2_SERVICE_DATA_LEN 17
/* :671 .rand */
static const uint8_t bt_extref_mesh_s8_6_2_random[] = {
	0x34, 0xae, 0x60, 0x8f, 0xbb, 0xc1, 0xf2, 0xc6
};
/* :672 .ident_res_key */
static const uint8_t bt_extref_mesh_s8_6_2_identity_resolving_key[] = {
	0x84, 0x39, 0x6c, 0x43, 0x5a, 0xc4, 0x85, 0x60,
	0xb5, 0x96, 0x53, 0x85, 0x25, 0x3e, 0x21, 0x0c
};
/* :674 .hash_input */
static const uint8_t bt_extref_mesh_s8_6_2_hash_input[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0xae,
	0x60, 0x8f, 0xbb, 0xc1, 0xf2, 0xc6, 0x12, 0x01
};
/* :675 .identity_hash */
static const uint8_t bt_extref_mesh_s8_6_2_identity_hash[] = {
	0x00, 0x86, 0x17, 0x65, 0xae, 0xfc, 0xc5, 0x7b
};
/* :676 .beacon - Mesh Proxy Service Data (Node Identity) */
static const uint8_t bt_extref_mesh_s8_6_2_service_data[] = {
	0x01, 0x00, 0x86, 0x17, 0x65, 0xae, 0xfc, 0xc5,
	0x7b, 0x34, 0xae, 0x60, 0x8f, 0xbb, 0xc1, 0xf2,
	0xc6
};

/*
 * ===========================================================================
 * 11. Provisioning: CONSTRUCTION ONLY - NO EXTERNAL SAMPLE DATA AVAILABLE.
 *
 * GAP, stated explicitly rather than filled in with a guess:
 * BlueZ 5.87 ships NO unit test and NO sample-data table for provisioning.
 * unit/test-mesh-crypto.c stops at Mesh Profile section 8.6 (main() ends at
 * unit/test-mesh-crypto.c:2186) and its struct has no confirmation, ECDH
 * secret, provisioning-random or provisioning-salt fields at all.  The
 * provisioning primitives in mesh/crypto.c carry no sample-data comment and
 * no spec section number, and grepping the entire BlueZ tree for a
 * Confirmation Salt / Provisioning Salt sample value finds nothing.
 * tools/mesh-cfgtest.c likewise cites no section numbers.
 *
 * Therefore NO expected provisioning confirmation, confirmation salt or
 * provisioning salt value appears in this header.  Only the byte layout of
 * the derivations is captured, which IS externally traceable to BlueZ code.
 * Deriving the missing values would require the Mesh Profile section 8.5
 * sample data, which is not present in /usr/src/bluetooth-specs.
 *
 *   ConfirmationSalt: s1(ProvisioningInvite || ProvisioningCapabilities ||
 *                        ProvisioningStart || ProvisionerPublicKey ||
 *                        DevicePublicKey)
 *     - assembled by the provisioning state machines, not by mesh/crypto.c;
 *       see BlueZ mesh/prov-acceptor.c:243 and mesh/prov-initiator.c:259
 *       where the resulting 16 octets are printed as "ConfirmationSalt".
 *   ConfirmationKey: k1-shaped, mesh/crypto.c:419 mesh_crypto_prov_conf_key()
 *       ConfirmationKey = AES-CMAC(AES-CMAC(key = ConfirmationSalt,
 *                                           ECDHSecret[32]), "prck")
 *   ProvisioningSalt: mesh/crypto.c:405 mesh_crypto_prov_prov_salt()
 *       s1(ConfirmationSalt || ProvisionerRandom || DeviceRandom), i.e.
 *       AES-CMAC(key = 0^128, 48 octets of the three concatenated values).
 *   SessionKey:  mesh/crypto.c:369, AES-CMAC(AES-CMAC(key = ProvisioningSalt,
 *                ECDHSecret[32]), "prsk")
 *   SessionNonce: mesh/crypto.c:381, same shape with "prsn", keeping the
 *                LOW 13 octets (memcpy(nonce, tmp + 3, 13), line 395)
 *   DeviceKey:   mesh/crypto.c:431, same shape with "prdk"
 * The final Confirmation value itself is
 *   AES-CMAC(key = ConfirmationKey, Random || AuthValue)
 * which BlueZ computes inline in the provisioning state machines rather than
 * in mesh/crypto.c; no sample instance of it exists in the tree.
 * ===========================================================================
 */
/* Literal 4-octet tags, mesh/crypto.c:423, :373, :385, :435. */
static const uint8_t bt_extref_mesh_prov_prck_tag[] = {
	0x70, 0x72, 0x63, 0x6b			/* "prck" */
};
static const uint8_t bt_extref_mesh_prov_prsk_tag[] = {
	0x70, 0x72, 0x73, 0x6b			/* "prsk" */
};
static const uint8_t bt_extref_mesh_prov_prsn_tag[] = {
	0x70, 0x72, 0x73, 0x6e			/* "prsn" */
};
static const uint8_t bt_extref_mesh_prov_prdk_tag[] = {
	0x70, 0x72, 0x64, 0x6b			/* "prdk" */
};
#define BT_EXTREF_MESH_PROV_ECDH_SECRET_LEN 32
#define BT_EXTREF_MESH_PROV_SALT_INPUT_LEN 48	/* 3 x 16, mesh/crypto.c:410 */
#define BT_EXTREF_MESH_PROV_SESSION_NONCE_OFFSET 3	/* mesh/crypto.c:395 */
#define BT_EXTREF_MESH_PROV_SESSION_NONCE_LEN 13
/* No expected provisioning values are defined here; see the GAP above. */

#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_MESH_VECTORS_H */
