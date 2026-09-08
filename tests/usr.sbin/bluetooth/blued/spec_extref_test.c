/*-
 * Self-check for the EXTERNAL reference-vector corpus (spec_extref_*.h).
 *
 * This program deliberately links NO blued source file and includes NO blued
 * header.  Its only job is to prove that the external corpus is internally
 * consistent and correctly transcribed, so that the corpus can be trusted as
 * an oracle by the tests that DO exercise blued.  Nothing here computes an
 * expected value using blued's code.
 *
 * The one computation performed is AES-CMAC via OpenSSL's EVP_MAC.  OpenSSL is
 * a third-party implementation of RFC 4493; it is used here to confirm that
 * the message m and the hash transcribed out of Core 6.3 Appendix B actually
 * correspond to each other, which is what catches a transcription error in
 * spec_extref_db_hash_gen.awk's output.
 */

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/params.h>

#include "spec_extref_db_hash.h"
#include "spec_extref_smp_keydist.h"
#include "spec_extref_smp_vectors.h"

static void
extref_aes_cmac(const uint8_t *key, size_t keylen, const uint8_t *msg,
    size_t msglen, uint8_t out[16])
{
	EVP_MAC *cmac_type;
	EVP_MAC_CTX *ctx;
	OSSL_PARAM params[2];
	size_t outlen = 0;
	static char cipher_name[] = "AES-128-CBC";

	memset(out, 0, 16);

	cmac_type = EVP_MAC_fetch(NULL, "CMAC", NULL);
	ATF_REQUIRE_MSG(cmac_type != NULL, "EVP_MAC_fetch(CMAC) failed");
	ctx = EVP_MAC_CTX_new(cmac_type);
	ATF_REQUIRE_MSG(ctx != NULL, "EVP_MAC_CTX_new failed");

	params[0] = OSSL_PARAM_construct_utf8_string("cipher", cipher_name, 0);
	params[1] = OSSL_PARAM_construct_end();
	ATF_REQUIRE_MSG(EVP_MAC_init(ctx, key, keylen, params) == 1,
	    "EVP_MAC_init failed");
	ATF_REQUIRE_MSG(EVP_MAC_update(ctx, msg, msglen) == 1,
	    "EVP_MAC_update failed");
	ATF_REQUIRE_MSG(EVP_MAC_final(ctx, out, &outlen, 16) == 1,
	    "EVP_MAC_final failed");
	ATF_REQUIRE_EQ_MSG(16, outlen, "CMAC output is not 128 bits");

	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(cmac_type);
}

/*
 * Core 6.3, Vol 3, Part G, Appendix B.  Confirms that the message blocks
 * M0..M6 and the published Database Hash, both extracted from the spec text by
 * spec_extref_db_hash_gen.awk, are consistent under a third-party AES-CMAC.
 * A transcription slip in either array fails here.
 */
ATF_TC_WITHOUT_HEAD(extref_db_hash_appendix_b_selfconsistent);
ATF_TC_BODY(extref_db_hash_appendix_b_selfconsistent, tc)
{
	uint8_t mac[16];

	extref_aes_cmac(bt_extref_db_hash_key, BT_EXTREF_DB_HASH_KEY_LEN,
	    bt_extref_db_hash_m, BT_EXTREF_DB_HASH_M_LEN, mac);

	ATF_CHECK_EQ_MSG(0,
	    memcmp(mac, bt_extref_db_hash_cmac, BT_EXTREF_DB_HASH_LEN),
	    "Appendix B message does not hash to the Appendix B value; the "
	    "extracted corpus is corrupt");
}

/*
 * The two candidate on-the-wire encodings must be exact reverses of one
 * another and must both derive from the same CMAC value.  This pins the
 * corpus so that a later edit cannot quietly make "BlueZ order" and
 * "Zephyr/PTS order" mean the same thing.
 */
ATF_TC_WITHOUT_HEAD(extref_db_hash_wire_candidates_are_reverses);
ATF_TC_BODY(extref_db_hash_wire_candidates_are_reverses, tc)
{
	int i;

	ATF_CHECK_EQ_MSG(0, memcmp(bt_extref_db_hash_wire_bluez,
	    bt_extref_db_hash_cmac, BT_EXTREF_DB_HASH_LEN),
	    "BlueZ wire order must be the unmodified CMAC output");

	for (i = 0; i < BT_EXTREF_DB_HASH_LEN; i++) {
		ATF_CHECK_EQ_MSG(bt_extref_db_hash_cmac[
		    BT_EXTREF_DB_HASH_LEN - 1 - i],
		    bt_extref_db_hash_wire_zephyr_pts[i],
		    "Zephyr/PTS wire order must be the reversed CMAC output "
		    "(octet %d)", i);
	}

	/* Spot-check the leading octet of each, so a wholesale swap is loud. */
	ATF_CHECK_EQ(0xf1, bt_extref_db_hash_wire_bluez[0]);
	ATF_CHECK_EQ(0x90, bt_extref_db_hash_wire_zephyr_pts[0]);

	ATF_CHECK_EQ(0x2b2a, BT_EXTREF_DB_HASH_UUID16);
}

/*
 * linux/net/bluetooth/smp.c:53 -- SMP_SC_NO_DIST is EncKey|LinkKey, not EncKey
 * alone.  Recorded as an arithmetic identity so that a future edit of
 * spec_extref_smp_keydist.h cannot weaken the claim silently.
 */
ATF_TC_WITHOUT_HEAD(extref_smp_sc_key_distribution);
ATF_TC_BODY(extref_smp_sc_key_distribution, tc)
{
	ATF_CHECK_EQ_MSG(0x09, BT_EXTREF_SMP_SC_NO_DIST,
	    "BlueZ clears EncKey AND LinkKey under Secure Connections");
	ATF_CHECK((BT_EXTREF_SMP_SC_NO_DIST & BT_EXTREF_SMP_DIST_ENC_KEY) != 0);
	ATF_CHECK((BT_EXTREF_SMP_SC_NO_DIST & BT_EXTREF_SMP_DIST_LINK_KEY) != 0);
	ATF_CHECK((BT_EXTREF_SMP_SC_NO_DIST & BT_EXTREF_SMP_DIST_ID_KEY) == 0);
	ATF_CHECK((BT_EXTREF_SMP_SC_NO_DIST & BT_EXTREF_SMP_DIST_SIGN) == 0);

	/* The internal mask is the wire mask with SC_NO_DIST removed. */
	ATF_CHECK_EQ(BT_EXTREF_SMP_BLUEZ_SC_INTERNAL_KEY_DIST,
	    BT_EXTREF_SMP_BLUEZ_SC_RSP_RESP_KEY_DIST &
	    (uint8_t)~BT_EXTREF_SMP_SC_NO_DIST);

	/*
	 * BlueZ does not strip anything from the Pairing Response it emits:
	 * EncKey stays set under SC, and LinkKey is added rather than removed.
	 */
	ATF_CHECK_EQ(1, BT_EXTREF_SMP_BLUEZ_WIRE_MASK_UNSTRIPPED_UNDER_SC);
	ATF_CHECK((BT_EXTREF_SMP_BLUEZ_SC_RSP_RESP_KEY_DIST &
	    BT_EXTREF_SMP_DIST_ENC_KEY) != 0);
	ATF_CHECK((BT_EXTREF_SMP_BLUEZ_SC_RSP_RESP_KEY_DIST &
	    BT_EXTREF_SMP_DIST_LINK_KEY) != 0);

	/* Legacy never offers LinkKey (guarded on SC in build_pairing_cmd). */
	ATF_CHECK((BT_EXTREF_SMP_BLUEZ_LEGACY_RSP_KEY_DIST &
	    BT_EXTREF_SMP_DIST_LINK_KEY) == 0);
}

/*
 * Core 6.3, Vol 3, Part H, Appendix D.1 reproduces the RFC 4493 AES-CMAC test
 * vectors.  Recomputing them with OpenSSL proves the extracted spec constants
 * were transcribed correctly, and anchors the whole SMP corpus: every other
 * spec vector in spec_extref_smp_vectors.h came out of the same parser run.
 */
ATF_TC_WITHOUT_HEAD(extref_rfc4493_vectors_selfconsistent);
ATF_TC_BODY(extref_rfc4493_vectors_selfconsistent, tc)
{
	uint8_t mac[16];

	extref_aes_cmac(bt_extref_rfc4493_k, sizeof(bt_extref_rfc4493_k),
	    bt_extref_rfc4493_ex2_msg, sizeof(bt_extref_rfc4493_ex2_msg), mac);
	ATF_CHECK_EQ_MSG(0, memcmp(mac, bt_extref_rfc4493_ex2_cmac, 16),
	    "RFC 4493 / Core 6.3 App D.1.2 vector mis-transcribed");

	extref_aes_cmac(bt_extref_rfc4493_k, sizeof(bt_extref_rfc4493_k),
	    bt_extref_rfc4493_ex3_msg, sizeof(bt_extref_rfc4493_ex3_msg), mac);
	ATF_CHECK_EQ_MSG(0, memcmp(mac, bt_extref_rfc4493_ex3_cmac, 16),
	    "RFC 4493 / Core 6.3 App D.1.3 vector mis-transcribed");

	extref_aes_cmac(bt_extref_rfc4493_k, sizeof(bt_extref_rfc4493_k),
	    bt_extref_rfc4493_ex4_msg, sizeof(bt_extref_rfc4493_ex4_msg), mac);
	ATF_CHECK_EQ_MSG(0, memcmp(mac, bt_extref_rfc4493_ex4_cmac, 16),
	    "RFC 4493 / Core 6.3 App D.1.4 vector mis-transcribed");

	/* Empty message (App D.1.1). */
	extref_aes_cmac(bt_extref_rfc4493_k, sizeof(bt_extref_rfc4493_k),
	    NULL, 0, mac);
	ATF_CHECK_EQ_MSG(0, memcmp(mac, bt_extref_rfc4493_ex1_cmac, 16),
	    "RFC 4493 / Core 6.3 App D.1.1 vector mis-transcribed");
}

/*
 * The ATT signed-write truncation convention, as implemented by BlueZ
 * src/shared/crypto.c bt_crypto_sign_att() and bt_crypto_verify_att_sign().
 *
 * The 12-octet signature is sign_counter (little-endian, 4 octets) followed by
 * the reversed MOST significant 8 octets of the CMAC output; the least
 * significant 4 CMAC octets are discarded.  This case pins that relationship
 * against the published RFC 4493 constant so the corpus cannot drift.
 *
 * NB: LE data signing is current in Core 5.2, this stack's target, but was
 * removed in Core 6.3 (Vol 1 Part C §17.2), so the in-tree 6.3 text prints
 * ATT opcode 0xD2 and SMP code 0x0A as "Previously used" and cannot supply
 * the convention.  BlueZ is therefore the citable source here; see the
 * header comment in spec_extref_smp_vectors.h.
 */
ATF_TC_WITHOUT_HEAD(extref_signed_write_truncation_convention);
ATF_TC_BODY(extref_signed_write_truncation_convention, tc)
{
	int i;

	ATF_CHECK_EQ(4, BT_EXTREF_SIGN_TRUNC_DEMO_MAC_OFFSET);
	ATF_CHECK_EQ(8, BT_EXTREF_SIGN_TRUNC_DEMO_MAC_LEN);

	/*
	 * MAC field == reverse(CMAC[0..7]): signature[4 + i] must equal
	 * cmac[7 - i].
	 */
	for (i = 0; i < BT_EXTREF_SIGN_TRUNC_DEMO_MAC_LEN; i++) {
		ATF_CHECK_EQ_MSG(bt_extref_rfc4493_ex2_cmac[7 - i],
		    bt_extref_sign_trunc_demo_sig[
		    BT_EXTREF_SIGN_TRUNC_DEMO_MAC_OFFSET + i],
		    "signature MAC octet %d is not the reversed most "
		    "significant CMAC octet", i);
	}

	/* Sign counter 1, little-endian, in the leading 4 octets. */
	ATF_CHECK_EQ(0x01, bt_extref_sign_trunc_demo_sig[0]);
	ATF_CHECK_EQ(0x00, bt_extref_sign_trunc_demo_sig[1]);
	ATF_CHECK_EQ(0x00, bt_extref_sign_trunc_demo_sig[2]);
	ATF_CHECK_EQ(0x00, bt_extref_sign_trunc_demo_sig[3]);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, extref_db_hash_appendix_b_selfconsistent);
	ATF_TP_ADD_TC(tp, extref_db_hash_wire_candidates_are_reverses);
	ATF_TP_ADD_TC(tp, extref_smp_sc_key_distribution);
	ATF_TP_ADD_TC(tp, extref_rfc4493_vectors_selfconsistent);
	ATF_TP_ADD_TC(tp, extref_signed_write_truncation_convention);

	return (atf_no_error());
}
