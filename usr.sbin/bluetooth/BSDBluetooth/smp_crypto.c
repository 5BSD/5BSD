/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * SMP cryptographic primitives.
 *
 * Core Spec Vol 3 Part H Section 2.2:
 *   - AES-128 encryption (E function)
 *   - AES-CMAC (RFC 4493)
 *   - c1 confirm generation (legacy)
 *   - s1 key generation (legacy)
 *   - f4, f5, f6, g2 (Secure Connections)
 *   - h6, h7 (Cross-Transport Key Derivation)
 *   - smp_swap_buf (byte order conversion)
 *   - P-256 public key validation
 *   - SC OOB confirm generation
 *   - ATT Signed Write verification
 */

#include <sys/types.h>

#include <sys/endian.h>

#include <err.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "ble_util.h"
#include "smp.h"
#include "smp_internal.h"

/*
 * AES-128 encrypt: E(key, plaintext) -> ciphertext.
 * Used by c1() and s1() functions.
 * Core Spec Vol 3 Part H Section 2.2.1
 */
int
smp_aes128(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
	EVP_CIPHER_CTX *ctx;
	uint8_t k[16], p[16], tmp;
	int outl, i;

	/*
	 * SMP uses big-endian key/data ordering internally,
	 * but protocol PDUs are little-endian.  Reverse for AES.
	 */
	for (i = 0; i < 16; i++) {
		k[i] = key[15 - i];
		p[i] = in[15 - i];
	}

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		warnx("EVP_CIPHER_CTX_new failed");
		memset(out, 0, 16);
		explicit_bzero(k, sizeof(k));
		explicit_bzero(p, sizeof(p));
		return (-1);
	}
	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, k, NULL) <= 0) {
		warnx("EVP_EncryptInit_ex failed");
		EVP_CIPHER_CTX_free(ctx);
		memset(out, 0, 16);
		explicit_bzero(k, sizeof(k));
		explicit_bzero(p, sizeof(p));
		return (-1);
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	if (EVP_EncryptUpdate(ctx, out, &outl, p, 16) <= 0) {
		warnx("EVP_EncryptUpdate failed");
		EVP_CIPHER_CTX_free(ctx);
		memset(out, 0, 16);
		explicit_bzero(k, sizeof(k));
		explicit_bzero(p, sizeof(p));
		return (-1);
	}
	EVP_CIPHER_CTX_free(ctx);

	/* Reverse output back to little-endian */
	for (i = 0; i < 8; i++) {
		tmp = out[i];
		out[i] = out[15 - i];
		out[15 - i] = tmp;
	}

	explicit_bzero(k, sizeof(k));
	explicit_bzero(p, sizeof(p));
	return (0);
}

/*
 * c1 confirm value generation function.
 * Core Spec Vol 3 Part H Section 2.2.3
 *
 * c1(k, r, preq, pres, iat, ia, rat, ra) = E(k, E(k, r XOR p1) XOR p2)
 *   p1 = pres || preq || rat || iat
 *   p2 = padding || ia || ra
 */
int
smp_c1(const uint8_t k[16], const uint8_t r[16],
    const uint8_t preq[7], const uint8_t pres[7],
    uint8_t iat, const uint8_t ia[6],
    uint8_t rat, const uint8_t ra[6],
    uint8_t confirm[16])
{
	uint8_t p1[16], p2[16], tmp[16];
	int i;

	/* p1 = pres || preq || rat || iat (little-endian) */
	p1[0] = iat;
	p1[1] = rat;
	memcpy(p1 + 2, preq, 7);
	memcpy(p1 + 9, pres, 7);

	/* p2 = padding(4) || ia(6) || ra(6) (little-endian: ra at LSB) */
	memcpy(p2, ra, 6);
	memcpy(p2 + 6, ia, 6);
	memset(p2 + 12, 0, 4);

	/* tmp = r XOR p1 */
	for (i = 0; i < 16; i++)
		tmp[i] = r[i] ^ p1[i];

	/* tmp = E(k, tmp) */
	if (smp_aes128(k, tmp, tmp) < 0)
		return (-1);

	/* tmp = tmp XOR p2 */
	for (i = 0; i < 16; i++)
		tmp[i] = tmp[i] ^ p2[i];

	/* confirm = E(k, tmp) */
	if (smp_aes128(k, tmp, confirm) < 0)
		return (-1);

	return (0);
}

/*
 * s1 key generation function.
 * Core Spec Vol 3 Part H Section 2.2.4
 *
 * s1(k, r1, r2) = E(k, r2' || r1')
 *   r1' = lower 8 bytes of r1
 *   r2' = lower 8 bytes of r2
 */
int
smp_s1(const uint8_t k[16], const uint8_t r1[16], const uint8_t r2[16],
    uint8_t stk[16])
{
	uint8_t r[16];

	memcpy(r, r2, 8);	/* r2' in lower half */
	memcpy(r + 8, r1, 8);	/* r1' in upper half */

	return (smp_aes128(k, r, stk));
}

/*
 * Reduce an encryption key to the negotiated key size.
 *
 * Core Spec Vol 3 Part H §2.3.4: "If a key has an encryption key size that
 * is shorter than 16 octets (128 bits), it shall be created by masking the
 * appropriate number of most significant octets of the generated key ...
 * The key shall be masked before the key is distributed, used for
 * encryption, or stored."  Keys are held here in wire (little-endian)
 * order, so the most significant octets are the highest array indices;
 * zeroing indices [key_size..15] keeps the least significant key_size
 * octets, matching the §2.3.4 worked example (7-octet mask ->
 * 0x00000000_00000000_00345678_9ABCDEF0).
 *
 * key_size == 0 (field not yet negotiated) and key_size >= 16 are no-ops.
 */
void
smp_mask_key(uint8_t key[16], uint8_t key_size)
{
	if (key_size == 0 || key_size >= 16)
		return;
	memset(key + key_size, 0, (size_t)(16 - key_size));
}

/* ================================================================
 * LE Secure Connections crypto (Core Spec Vol 3 Part H Section 2.2)
 *
 * The SC crypto functions (f4, f5, f6, g2) operate on values in
 * big-endian (MSB-first) byte order per the spec.  SMP PDUs carry
 * values in little-endian (wire order).  Callers must convert
 * between wire order and crypto order using smp_swap_buf().
 *
 * Unlike the legacy E() function, AES-CMAC is standard RFC 4493
 * and does NOT need the double byte-reversal that smp_aes128 does.
 * ================================================================ */

/*
 * Reverse a byte buffer in-place or into a destination.
 *
 * S-m10: safe when dst == src.  Swapping from both ends means each pair of
 * bytes is exchanged exactly once, so an in-place reversal is not corrupted
 * by reads of already-overwritten source bytes.  For distinct buffers this
 * produces the same result as a straight forward copy-reverse.
 */
void
smp_swap_buf(uint8_t *dst, const uint8_t *src, size_t len)
{
	for (size_t i = 0; i < (len + 1) / 2; i++) {
		uint8_t lo = src[i];
		uint8_t hi = src[len - 1 - i];

		dst[i] = hi;
		dst[len - 1 - i] = lo;
	}
}

/*
 * Validate that a peer's public key point lies on the P-256 curve.
 * Per Core Spec Vol 3 Part H Section 2.3.5.6.1: "A device shall
 * validate that any public key received from any BD_ADDR is on
 * the correct curve (P-256)."
 *
 * pk_x and pk_y are 32-byte big-endian coordinates.
 * Returns 0 on success, -1 if the key is invalid.
 */
int
smp_validate_public_key(const uint8_t *pk_x, const uint8_t *pk_y,
    const uint8_t *local_pk_x)
{
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	BIGNUM *x = NULL, *y = NULL;
	int ret = -1;

	/*
	 * Reject the well-known SC Debug Public Key from Core Spec
	 * Vol 3 Part H Section 2.3.5.6.1.  If a peer sends this key,
	 * the resulting DHKey is publicly known, enabling passive
	 * eavesdropping.  The coordinates are in big-endian order.
	 */
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

	if (memcmp(pk_x, sc_debug_pk_x, 32) == 0 &&
	    memcmp(pk_y, sc_debug_pk_y, 32) == 0) {
		warnx("SMP: peer sent SC Debug Public Key, rejecting");
		BLUED_LOG_SECURITY("peer sent SC Debug Public Key, "
		    "rejecting pairing");
		return (-1);
	}

	group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (group == NULL)
		goto out;

	point = EC_POINT_new(group);
	if (point == NULL)
		goto out;

	x = BN_bin2bn(pk_x, 32, NULL);
	y = BN_bin2bn(pk_y, 32, NULL);
	if (x == NULL || y == NULL)
		goto out;

	if (!EC_POINT_set_affine_coordinates(group, point, x, y, NULL))
		goto out;

	if (!EC_POINT_is_on_curve(group, point, NULL))
		goto out;

	/* Also reject the point at infinity */
	if (EC_POINT_is_at_infinity(group, point))
		goto out;

	/*
	 * Reflection-attack countermeasure (Core Spec Vol 3 Part H
	 * Section 2.3.5.6.1, CVE-2020-26558).  "If the two public keys have
	 * the same X coordinate and neither is the debug key, then each device
	 * shall fail pairing" with DHKey Check Failed.  The debug key is already
	 * rejected above, so a match here means the peer reflected our own
	 * public key -- in SC Passkey Entry that lets an MITM recover the
	 * passkey bit-by-bit across the commitment rounds.  local_pk_x may be
	 * NULL to skip (e.g. before our ephemeral is known).  X is public, so a
	 * plain compare is sufficient.
	 */
	if (local_pk_x != NULL && memcmp(pk_x, local_pk_x, 32) == 0) {
		warnx("SMP: peer public key reflects local key, rejecting");
		BLUED_LOG_SECURITY("peer public key X == local X "
		    "(reflection), rejecting pairing");
		goto out;
	}

	ret = 0;

out:
	BN_free(y);
	BN_free(x);
	EC_POINT_free(point);
	EC_GROUP_free(group);
	return (ret);
}

/*
 * AES-CMAC per RFC 4493.
 * Core Spec Vol 3 Part H Section 2.2.5
 */
int
smp_aes_cmac(const uint8_t key[16], const uint8_t *msg, size_t len,
    uint8_t mac[16])
{
	EVP_MAC *cmac_type;
	EVP_MAC_CTX *ctx;
	OSSL_PARAM params[2];
	size_t outlen;

	static char cipher_name[] = "AES-128-CBC";

	cmac_type = EVP_MAC_fetch(NULL, "CMAC", NULL);
	if (cmac_type == NULL) {
		warnx("EVP_MAC_fetch failed");
		memset(mac, 0, 16);
		return (-1);
	}
	ctx = EVP_MAC_CTX_new(cmac_type);
	if (ctx == NULL) {
		warnx("EVP_MAC_CTX_new failed");
		memset(mac, 0, 16);
		EVP_MAC_free(cmac_type);
		return (-1);
	}
	params[0] = OSSL_PARAM_construct_utf8_string("cipher", cipher_name,
	    0);
	params[1] = OSSL_PARAM_construct_end();
	if (EVP_MAC_init(ctx, key, 16, params) <= 0) {
		warnx("EVP_MAC_init failed");
		goto cmac_fail;
	}
	if (EVP_MAC_update(ctx, msg, len) <= 0) {
		warnx("EVP_MAC_update failed");
		goto cmac_fail;
	}
	outlen = 16;
	if (EVP_MAC_final(ctx, mac, &outlen, 16) <= 0) {
		warnx("EVP_MAC_final failed");
		goto cmac_fail;
	}
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(cmac_type);
	return (0);

cmac_fail:
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(cmac_type);
	memset(mac, 0, 16);
	return (-1);
}

/*
 * f4: LE SC confirm value generation.
 * Core Spec Vol 3 Part H Section 2.2.6
 *
 * f4(U, V, X, Z) = AES-CMAC_X(U || V || Z)
 *
 * All multi-byte inputs are in little-endian (wire) order.
 * Internally converted to big-endian for AES-CMAC per spec.
 * Output is returned in little-endian (wire) order.
 */
int
smp_f4(const uint8_t u[32], const uint8_t v[32], const uint8_t x[16],
    uint8_t z, uint8_t out[16])
{
	uint8_t m[65], x_be[16], mac[16];
	int rc;

	smp_swap_buf(m, u, 32);
	smp_swap_buf(m + 32, v, 32);
	m[64] = z;
	smp_swap_buf(x_be, x, 16);
	rc = smp_aes_cmac(x_be, m, sizeof(m), mac);
	if (rc == 0)
		smp_swap_buf(out, mac, 16);
	explicit_bzero(x_be, sizeof(x_be));
	explicit_bzero(mac, sizeof(mac));
	return (rc);
}

/*
 * The A1/A2 argument shape used by f5 and f6, stated once.
 *
 * Core Spec Vol 3 Part H Sections 2.2.7 and 2.2.8 define A1 and A2 as
 * 56-bit fields, "the address type concatenated with the device address",
 * with the type in the MOST significant octet.  Printed the way the
 * specification prints it (Appendix D.3) A1 is therefore
 *
 *	00 56 12 37 37 bf ce	<- type, then address most significant first
 *
 * blued -- like BlueZ -- passes that whole field to f5/f6 in little-endian
 * (wire) order, i.e. BYTE-REVERSED relative to the line above:
 *
 *	ce bf 37 37 12 56 00	<- address least significant first, TYPE LAST
 *
 * so the address occupies indices [0..5] exactly as it appears on air and
 * in struct smp_conn, and the type octet is at index [6].  BlueZ composes
 * the identical seven octets (emulator/smp.c: memcpy(a, conn->ia, 6);
 * a[6] = conn->ia_type).  Zephyr and NimBLE never compose a seven-octet
 * field at all -- they take the type as a separate argument, ahead of a
 * six-octet on-air address (Zephyr's bt_addr_le_t, NimBLE's (a1t, a1)) --
 * so there is no reference whose seven-octet blob is ordered the other way.
 *
 * Use smp_pack_addr() to build these fields; do not hand-roll them.  A
 * caller who assembles the specification's printed order instead gets a
 * silently wrong LTK or a DHKey check that fails with no diagnostic, which
 * is what smp_a_field_check() below exists to shout about.
 */

/*
 * Misuse canary for the A1/A2 argument order documented above.
 *
 * Per Vol 3 Part H Section 2.3.5.6.1 the address type octet of an A field
 * is 0x00 (public) or 0x01 (random) and nothing else.  If index [6] is not
 * a valid type but index [0] is, the caller almost certainly composed the
 * specification's printed order (type first) rather than the wire order
 * this API takes.  Warn loudly rather than fail: the check is a heuristic,
 * a public address whose most significant octet happens to be 0x00 or 0x01
 * would slip past it, and returning an error here would turn a warning into
 * a new failure mode in code that is otherwise correct.
 */
static void
smp_a_field_check(const uint8_t a[7], const char *which)
{

	if (a[6] > SMP_ID_ADDR_STATIC_RANDOM &&
	    a[0] <= SMP_ID_ADDR_STATIC_RANDOM)
		warnx("SMP: %s looks byte-reversed: it must be the six "
		    "on-air address octets followed by the address type, "
		    "not the specification's printed type-first order "
		    "(see smp_pack_addr())", which);
}

/*
 * f5: LE SC key generation.
 * Core Spec Vol 3 Part H Section 2.2.7
 *
 * Outputs MacKey (Counter=0) and LTK (Counter=1).
 *
 * All multi-byte inputs are in little-endian (wire) order.
 * Internally converted to big-endian for AES-CMAC per spec.
 * Outputs are returned in little-endian (wire) order.
 *
 * a1_addr_then_type and a2_addr_then_type are the A1 and A2 fields in that
 * same little-endian order: six on-air address octets THEN the one-octet
 * address type.  That is the whole specification field byte-reversed; see
 * the block comment above smp_a_field_check() and use smp_pack_addr().
 */
int
smp_f5(const uint8_t w[32], const uint8_t n1[16], const uint8_t n2[16],
    const uint8_t a1_addr_then_type[7], const uint8_t a2_addr_then_type[7],
    uint8_t mackey[16], uint8_t ltk[16])
{
	static const uint8_t salt[16] = {
		0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38,
		0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x60, 0x83, 0xBE
	};
	static const uint8_t keyid[4] = { 0x62, 0x74, 0x6C, 0x65 };
	uint8_t t[16], w_be[32];
	uint8_t m[53], mac[16];
	int rc = -1;

	smp_a_field_check(a1_addr_then_type, "f5 A1");
	smp_a_field_check(a2_addr_then_type, "f5 A2");

	smp_swap_buf(w_be, w, 32);
	if (smp_aes_cmac(salt, w_be, 32, t) != 0)
		goto out;

	m[0] = 0;
	memcpy(m + 1, keyid, 4);
	smp_swap_buf(m + 5, n1, 16);
	smp_swap_buf(m + 21, n2, 16);
	smp_swap_buf(m + 37, a1_addr_then_type, 7);
	smp_swap_buf(m + 44, a2_addr_then_type, 7);
	m[51] = 0x01;
	m[52] = 0x00;

	if (smp_aes_cmac(t, m, sizeof(m), mac) != 0)
		goto out;
	smp_swap_buf(mackey, mac, 16);
	m[0] = 1;
	if (smp_aes_cmac(t, m, sizeof(m), mac) != 0)
		goto out;
	smp_swap_buf(ltk, mac, 16);
	rc = 0;
out:
	explicit_bzero(t, sizeof(t));
	explicit_bzero(w_be, sizeof(w_be));
	explicit_bzero(m, sizeof(m));
	explicit_bzero(mac, sizeof(mac));
	return (rc);
}

/*
 * f6: LE SC check value generation.
 * Core Spec Vol 3 Part H Section 2.2.8
 *
 * f6(W, N1, N2, R, IOcap, A1, A2) = AES-CMAC_W(N1||N2||R||IOcap||A1||A2)
 *
 * All multi-byte inputs are in little-endian (wire) order.
 * Internally converted to big-endian for AES-CMAC per spec.
 * Output is returned in little-endian (wire) order.
 *
 * IOcap is IOcapA/B || OOB || AuthReq as it appears in the Pairing
 * Request/Response PDU and is reversed on the way into CMAC like every
 * other argument (Zephyr and NimBLE write it { 0x02, 0x01, 0x01 } for the
 * specification's printed "010102").
 *
 * a1_addr_then_type and a2_addr_then_type carry the same address-then-type
 * order as smp_f5(); see the block comment above smp_a_field_check().
 */
int
smp_f6(const uint8_t w[16], const uint8_t n1[16], const uint8_t n2[16],
    const uint8_t r[16], const uint8_t iocap[3],
    const uint8_t a1_addr_then_type[7], const uint8_t a2_addr_then_type[7],
    uint8_t out[16])
{
	uint8_t m[65], w_be[16], mac[16];
	int rc;

	smp_a_field_check(a1_addr_then_type, "f6 A1");
	smp_a_field_check(a2_addr_then_type, "f6 A2");

	smp_swap_buf(w_be, w, 16);
	smp_swap_buf(m, n1, 16);
	smp_swap_buf(m + 16, n2, 16);
	smp_swap_buf(m + 32, r, 16);
	smp_swap_buf(m + 48, iocap, 3);
	smp_swap_buf(m + 51, a1_addr_then_type, 7);
	smp_swap_buf(m + 58, a2_addr_then_type, 7);
	rc = smp_aes_cmac(w_be, m, sizeof(m), mac);
	if (rc == 0)
		smp_swap_buf(out, mac, 16);
	explicit_bzero(w_be, sizeof(w_be));
	explicit_bzero(m, sizeof(m));
	explicit_bzero(mac, sizeof(mac));
	return (rc);
}

/*
 * g2: LE SC numeric comparison value.
 * Core Spec Vol 3 Part H Section 2.2.9
 *
 * g2(U, V, X, Y) = AES-CMAC_X(U || V || Y) mod 2^32
 * Writes the 32-bit value through *out; display as 6 least
 * significant digits.
 *
 * All multi-byte inputs are in little-endian (wire) order.
 * Internally converted to big-endian for AES-CMAC per spec.
 * Returns 0 on success, -1 if the underlying AES-CMAC fails.
 */
int
smp_g2(const uint8_t u[32], const uint8_t v[32],
    const uint8_t x[16], const uint8_t y[16], uint32_t *out)
{
	uint8_t m[80]; /* U(32)+V(32)+Y(16) */
	uint8_t x_be[16], mac[16];
	int rc;

	smp_swap_buf(m, u, 32);
	smp_swap_buf(m + 32, v, 32);
	smp_swap_buf(m + 64, y, 16);
	smp_swap_buf(x_be, x, 16);
	rc = smp_aes_cmac(x_be, m, sizeof(m), mac);
	if (rc == 0) {
		/* Least significant 32 bits of the big-endian 128-bit MAC */
		*out = ((uint32_t)mac[12] << 24 | (uint32_t)mac[13] << 16 |
		    (uint32_t)mac[14] << 8 | (uint32_t)mac[15]);
	}
	explicit_bzero(x_be, sizeof(x_be));
	explicit_bzero(mac, sizeof(mac));
	return (rc);
}

/*
 * h6: Link Key conversion function.
 * Core Spec Vol 3 Part H Section 2.2.10
 *
 * h6(W, keyID) = AES-CMAC_W(keyID)
 *
 * BYTE ORDER: every argument is little-endian (wire) order, index 0 = least
 * significant octet, and so is the output.  keyID is no exception: the
 * specification prints the CTKD identifiers as the ASCII strings "lebr",
 * "tmp1", "tmp2" and "brle" most significant octet first, so a caller
 * passes them here REVERSED, e.g. keyID "lebr" (spec 0x6C656272) is
 * { 0x72, 0x62, 0x65, 0x6C }.
 *
 * This matches BlueZ bt_crypto_h6() (src/shared/crypto.c, whose aes_cmac()
 * swaps both key and message) and Zephyr bt_crypto_h6()
 * (subsys/bluetooth/crypto/bt_crypto.c, which swaps key_id explicitly).
 * BlueZ's own h6 unit vector (unit/test-crypto.c test_h6) passes
 * { 0x72, 0x62, 0x65, 0x6c } for "lebr"; so does Zephyr's smp_h6_test().
 */
int
smp_h6(const uint8_t w[16], const uint8_t keyid[4], uint8_t out[16])
{
	uint8_t w_be[16], keyid_be[4], mac[16];
	int rc;

	smp_swap_buf(w_be, w, 16);
	smp_swap_buf(keyid_be, keyid, 4);
	rc = smp_aes_cmac(w_be, keyid_be, 4, mac);
	if (rc == 0)
		smp_swap_buf(out, mac, 16);
	explicit_bzero(w_be, sizeof(w_be));
	explicit_bzero(keyid_be, sizeof(keyid_be));
	explicit_bzero(mac, sizeof(mac));
	return (rc);
}

/*
 * h7: Link Key conversion function (alternate).
 * Core Spec Vol 3 Part H Section 2.2.11
 *
 * h7(SALT, W) = AES-CMAC_SALT(W)
 *
 * BYTE ORDER: as for h6, both arguments and the output are little-endian
 * (wire) order.  The specification prints the Section 2.4.2.4 SALT as
 * 0x00000000000000000000000074_6D_70_31 ("tmp1" in the four LEAST
 * significant octets), so the caller passes
 * { 0x31, 0x70, 0x6D, 0x74, 0x00 x 12 }.
 *
 * This matches Zephyr bt_crypto_h7(), which swaps salt and w explicitly.
 * BlueZ ships no h7 and NimBLE's host has none, so Zephyr and the Core
 * specification's Appendix D.8 sample are the only two sources for it.
 */
int
smp_h7(const uint8_t salt[16], const uint8_t w[16], uint8_t out[16])
{
	uint8_t w_be[16], salt_be[16], mac[16];
	int rc;

	smp_swap_buf(w_be, w, 16);
	smp_swap_buf(salt_be, salt, 16);
	rc = smp_aes_cmac(salt_be, w_be, 16, mac);
	if (rc == 0)
		smp_swap_buf(out, mac, 16);
	explicit_bzero(w_be, sizeof(w_be));
	explicit_bzero(salt_be, sizeof(salt_be));
	explicit_bzero(mac, sizeof(mac));
	return (rc);
}

/*
 * Generate local SC OOB data: {confirm, random}.
 * Core Spec Vol 3 Part H Section 2.3.5.6.4
 *
 * confirm = f4(PKx, PKx, random, 0)
 *
 * The caller should transmit these values to the peer via the OOB
 * channel before pairing begins.
 *
 * local_pk_x is the 32-byte x-coordinate of the local public key
 * in little-endian (wire) order.
 */
int
smp_generate_sc_oob(uint8_t confirm[16], uint8_t random[16],
    const uint8_t local_pk_x[32])
{

	arc4random_buf(random, 16);
	if (smp_f4(local_pk_x, local_pk_x, random, 0, confirm) != 0) {
		warnx("smp_generate_sc_oob: f4 failed");
		return (-1);
	}
	return (0);
}

/*
 * Verify an ATT Signed Write authentication signature.
 * Core Spec Vol 3 Part H Section 2.4.5:  MAC = AES-CMAC(CSRK, msg || SignCounter)
 *
 * Byte order (S-M3): AES-CMAC (RFC 4493) is defined most-significant-octet
 * first, but on the LE link the CSRK and the signed message
 * (att-data || SignCounter_le32) are exchanged least-significant-octet first.
 * The interoperable convention is therefore to byte-reverse BOTH the key AND
 * the entire message into MSB order before CMAC and to byte-reverse the
 * 128-bit MAC back to LSB order afterwards; the 8-octet wire signature is the
 * MOST significant 8 octets of the CMAC (RFC 4493 MSB truncation) transmitted
 * LSB-first, i.e. the high 8 octets of the LSB-first MAC.
 *
 * Verified against BlueZ src/shared/crypto.c bt_crypto_sign_att(): it does
 * swap_buf() on the key and on (m || put_le32(sign_cnt)), CMACs into out[]
 * (out[0] = most significant octet), then swap_buf(out, tmp, 16) and copies
 * tmp[4..15] as the 12-octet signature -- so the MAC half of the signature is
 * tmp[8..15] == out[7..0], i.e. mac_msb[0..7] byte-reversed, exactly what we
 * emit.  The same key/message swapping convention appears in the Linux kernel
 * at net/bluetooth/smp.c smp_aes_cmac(); note that mainline smp.c itself
 * contains no ATT-signing code (it only distributes and stores the CSRK), so
 * the truncation half of this convention is cited to BlueZ only.
 */
bool
smp_verify_signature(const uint8_t csrk[16], const uint8_t *msg,
    size_t msg_len, const uint8_t mac[8], uint32_t counter)
{
	uint8_t *input, *swapped;
	uint8_t csrk_be[16];
	uint8_t full_mac[16];
	uint8_t mac_lsb[16];
	uint32_t cnt_le;
	int rc;

	if (csrk == NULL || mac == NULL || (msg == NULL && msg_len != 0) ||
	    msg_len > SIZE_MAX - sizeof(cnt_le))
		return (false);

	input = malloc(msg_len + 4);
	if (input == NULL) {
		warn("smp_verify_signature: malloc");
		return (false);
	}
	if (msg_len != 0)
		memcpy(input, msg, msg_len);
	cnt_le = htole32(counter);
	memcpy(input + msg_len, &cnt_le, 4);

	/* Reverse the whole (att-data || SignCounter_le32) message into MSB. */
	swapped = malloc(msg_len + 4);
	if (swapped == NULL) {
		warn("smp_verify_signature: malloc");
		free(input);
		return (false);
	}
	smp_swap_buf(swapped, input, msg_len + 4);
	free(input);

	/* Reverse the CSRK into the MSB order smp_aes_cmac (RFC 4493) uses. */
	smp_swap_buf(csrk_be, csrk, 16);
	rc = smp_aes_cmac(csrk_be, swapped, msg_len + 4, full_mac);
	explicit_bzero(csrk_be, sizeof(csrk_be));
	free(swapped);
	if (rc != 0)
		return (false);

	/*
	 * Reverse the MSB-first CMAC output back to LSB order; the wire
	 * signature is its high 8 octets (the MSB-truncated CMAC, sent
	 * LSB-first).  Constant-time compare.
	 */
	smp_swap_buf(mac_lsb, full_mac, 16);
	return (timingsafe_bcmp(mac_lsb + 8, mac, 8) == 0);
}
