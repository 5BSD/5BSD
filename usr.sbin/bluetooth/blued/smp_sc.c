/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * LE Secure Connections pairing flows.
 *
 * Initiator and responder paths for Just Works, Numeric Comparison,
 * Passkey Entry, and OOB association models using P-256 ECDH.
 *
 * Core Spec Vol 3 Part H Section 2.3.5.6
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/endian.h>
#include <time.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "blued_probes.h"
#include "hci_log.h"
#include "hci_util.h"
#include "smp.h"
#include "smp_internal.h"

/*
 * Core 6.3 Vol 3 Part H §2.3 and §3.5.5: SMP commands have exact
 * lengths.  A received instance of the expected command with any other
 * length is an Invalid Parameters failure, not a prefix-compatible PDU.
 */
static int
smp_sc_fixed_pdu_valid(struct smp_conn *sc, uint8_t *pdu, ssize_t n,
    uint8_t expected_opcode, size_t expected_len)
{
	uint8_t fail[2];

	if (n == (ssize_t)expected_len && pdu[0] == expected_opcode)
		return (1);
	if (n > 0 && pdu[0] == expected_opcode) {
		fail[0] = SMP_PAIRING_FAILED;
		fail[1] = SMP_ERR_INVALID_PARAMETERS;
		(void)smp_log_send(sc, fail, sizeof(fail));
	}
	return (0);
}

/*
 * Build SMP 7-byte address in little-endian order.
 *
 * The spec defines A as a 56-bit value with the address type bit
 * in the most significant octet.  In LE byte order (byte[0]=LSB):
 *   [addr(6), type_bit(1)]
 *
 * The crypto functions (f5/f6) internally reverse this to big-endian:
 *   [type_bit, addr_reversed(6)]
 * which matches the spec's convention.
 */
void
smp_pack_addr(uint8_t out[7], const uint8_t addr[6], uint8_t addr_type)
{
	memcpy(out, addr, 6);
	out[6] = (addr_type == BDADDR_LE_RANDOM) ?
	    SMP_ID_ADDR_STATIC_RANDOM : SMP_ID_ADDR_PUBLIC;
}

/*
 * Test-only LE Secure Connections ephemeral-key seam.  See smp_internal.h.
 * In production this pointer is NULL, so smp_sc_gen_ephemeral() always
 * generates a fresh random P-256 key pair (per-pairing ECDH ephemeral,
 * Core Spec Vol 3 Part H §2.3.5.6.1) — identical to the original inline
 * keygen.  A test installs a hook to inject a known ephemeral for a
 * deterministic flow or to tie a precomputed SC-OOB payload to the key
 * the pairing actually uses.
 */
smp_sc_ephemeral_hook_t smp_sc_ephemeral_hook = NULL;

/*
 * Generate the local SC ephemeral P-256 key pair.  Returns a new EVP_PKEY
 * owned by the caller (freed with EVP_PKEY_free), or NULL on failure.
 */
static EVP_PKEY *
smp_sc_gen_ephemeral(void)
{
	EVP_PKEY *key = NULL;
	EVP_PKEY_CTX *pctx;

	if (smp_sc_ephemeral_hook != NULL)
		return (smp_sc_ephemeral_hook());	/* test-only injection */

	/* Production path: fresh random ephemeral. */
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pctx == NULL)
		return (NULL);
	if (EVP_PKEY_keygen_init(pctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
	    NID_X9_62_prime256v1) <= 0 ||
	    EVP_PKEY_keygen(pctx, &key) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return (NULL);
	}
	EVP_PKEY_CTX_free(pctx);
	return (key);
}

/* Reconstruct and validate the peer P-256 point, then derive a 32-byte DHKey.
 * Every OpenSSL allocation and state transition is fallible; keeping those
 * checks here prevents memory-pressure or provider failures from becoming a
 * NULL dereference in any of the four SC association-model paths. */
static int
smp_sc_compute_dhkey(EVP_PKEY *our_key, uint8_t peer_pk_raw[65],
    uint8_t dhkey_le[32])
{
	OSSL_PARAM params[3];
	EVP_PKEY_CTX *fctx = NULL, *dctx = NULL;
	EVP_PKEY *peer_key = NULL;
	static char curve[] = "prime256v1";
	uint8_t dhkey_be[32] = { 0 };
	size_t dh_len = sizeof(dhkey_be);
	int rc = -1;

	if (our_key == NULL)
		return (-1);
	params[0] = OSSL_PARAM_construct_utf8_string(
	    OSSL_PKEY_PARAM_GROUP_NAME, curve, 0);
	params[1] = OSSL_PARAM_construct_octet_string(
	    OSSL_PKEY_PARAM_PUB_KEY, peer_pk_raw, 65);
	params[2] = OSSL_PARAM_construct_end();
	fctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (fctx == NULL || EVP_PKEY_fromdata_init(fctx) <= 0 ||
	    EVP_PKEY_fromdata(fctx, &peer_key, EVP_PKEY_PUBLIC_KEY,
	    params) <= 0 || peer_key == NULL)
		goto out;
	dctx = EVP_PKEY_CTX_new(our_key, NULL);
	if (dctx == NULL || EVP_PKEY_derive_init(dctx) <= 0 ||
	    EVP_PKEY_derive_set_peer(dctx, peer_key) <= 0 ||
	    EVP_PKEY_derive(dctx, dhkey_be, &dh_len) <= 0 || dh_len != 32)
		goto out;
	smp_swap_buf(dhkey_le, dhkey_be, 32);
	rc = 0;
out:
	explicit_bzero(dhkey_be, sizeof(dhkey_be));
	EVP_PKEY_CTX_free(dctx);
	EVP_PKEY_free(peer_key);
	EVP_PKEY_CTX_free(fctx);
	return (rc);
}

static int
smp_sc_extract_public(EVP_PKEY *key, uint8_t raw[65])
{
	size_t len = 65;

	if (key == NULL || EVP_PKEY_get_octet_string_param(key,
	    OSSL_PKEY_PARAM_PUB_KEY, raw, 65, &len) <= 0 || len != 65 ||
	    raw[0] != POINT_CONVERSION_UNCOMPRESSED)
		return (-1);
	return (0);
}

/*
 * Local SC-OOB ephemeral, generated by smp_sc_oob_generate_local() and used by
 * the next SC pairing(s) so the OOB confirm we published matches the public key
 * the pairing actually presents (Core Spec Vol 3 Part H §2.3.5.6.4).  NULL when
 * no OOB generation is pending.
 */
static EVP_PKEY *smp_sc_oob_key = NULL;

static EVP_PKEY *
smp_sc_oob_key_hook(void)
{

	if (smp_sc_oob_key == NULL)
		return (NULL);
	return (EVP_PKEY_dup(smp_sc_oob_key));
}

/*
 * Generate local LE Secure Connections OOB data (deliverable: OOB engine was
 * wired but had zero exposure; NimBLE sc_oob_generate analogue).  Produces a
 * fresh P-256 ephemeral, returns its public-key x-coordinate (wire/LE order)
 * plus {confirm, random} = f4(PKx,PKx,random,0) for the operator to hand to the
 * peer out of band, and installs the keypair as the ephemeral the next SC
 * pairing will use so the published confirm is verifiable.  Returns 0 on
 * success, -1 on failure.
 */
int
smp_sc_oob_generate_local(uint8_t confirm[16], uint8_t random[16],
    uint8_t pkx_le[32])
{
	EVP_PKEY *key = NULL;
	EVP_PKEY_CTX *pctx;
	uint8_t pk_raw[65];

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pctx == NULL)
		return (-1);
	if (EVP_PKEY_keygen_init(pctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
	    NID_X9_62_prime256v1) <= 0 ||
	    EVP_PKEY_keygen(pctx, &key) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return (-1);
	}
	EVP_PKEY_CTX_free(pctx);

	if (smp_sc_extract_public(key, pk_raw) != 0) {
		EVP_PKEY_free(key);
		return (-1);
	}
	/* OpenSSL big-endian public key -> wire little-endian x-coordinate. */
	smp_swap_buf(pkx_le, pk_raw + 1, 32);
	if (smp_generate_sc_oob(confirm, random, pkx_le) != 0) {
		EVP_PKEY_free(key);
		return (-1);
	}

	if (smp_sc_oob_key != NULL)
		EVP_PKEY_free(smp_sc_oob_key);
	smp_sc_oob_key = key;
	smp_sc_ephemeral_hook = smp_sc_oob_key_hook;
	return (0);
}

/*
 * Drop any pending local SC-OOB ephemeral and detach the hook, restoring
 * per-pairing forward secrecy.  Called once the generated OOB has been consumed
 * by a pairing (or explicitly cleared by the operator).
 */
void
smp_sc_oob_clear_local(void)
{

	if (smp_sc_oob_key != NULL) {
		EVP_PKEY_free(smp_sc_oob_key);
		smp_sc_oob_key = NULL;
	}
	if (smp_sc_ephemeral_hook == smp_sc_oob_key_hook)
		smp_sc_ephemeral_hook = NULL;
}

/*
 * LE Secure Connections pairing — Passkey Entry.
 *
 * The passkey is a 6-digit number (20 bits).  Authentication stage 1
 * runs 20 rounds, one per bit.  Each round exchanges a confirm/nonce
 * pair using f4 with Z = 0x80|bit_value.
 *
 * Core Spec Vol 3 Part H Section 2.3.5.6.3, Figure 2.4
 */
int
smp_pair_sc_passkey(struct smp_conn *sc, const uint8_t preq[7],
    const uint8_t pres[7])
{
	EVP_PKEY *our_key = NULL;
	uint8_t our_pk_raw[65], peer_pk_raw[65];
	uint8_t pka_le[32], pkb_le[32];	/* LE x-coords for crypto */
	uint8_t dhkey_le[32];
	uint8_t na[16], nb[16];
	uint8_t mackey[16], ltk[16];
	uint8_t ea[16], eb[16];
	uint8_t a1[7], a2[7];
	uint8_t iocap_a[3], iocap_b[3];
	uint8_t pdu[66];
	ssize_t n;
	uint32_t passkey;
	uint8_t ra[16]; /* passkey as 128-bit for f6 */
	int ret = -1;
	int i;

	/*
	 * Arm the single cumulative §3.4 deadline if not already armed by the
	 * smp_pair() caller — do NOT reset an inherited deadline, so the timer
	 * spans the whole procedure from the Pairing Request.
	 */
	smp_pairing_arm(sc);

	if (sc->passkey_cb == NULL) {
		/*
		 * No local UI to enter/display the passkey: we cannot fulfil
		 * the negotiated method.  Send Pairing Failed so the peer is
		 * not left waiting (Vol 3 Part H §3.5.5).  Use the same reason
		 * (Pairing Not Supported) as the responder path
		 * (smp_respond_sc_passkey) for cross-role consistency.
		 */
		uint8_t f[2] = { SMP_PAIRING_FAILED,
		    SMP_ERR_PAIRING_NOT_SUPPORTED };
		smp_log_send(sc, f, 2);
		errno = ENOTSUP;
		return (-1);
	}

	/*
	 * Determine passkey display/input role per Core Spec Vol 3 Part H
	 * Table 2.8, initiator side: our IO capability is preq[1], the
	 * peer/responder's is pres[1].
	 */
	{
		bool we_display = smp_passkey_we_display(preq[1], pres[1],
		    true);

		passkey = 0;
		if (we_display)
			passkey = arc4random_uniform(1000000);
		if (sc->passkey_cb(&passkey, we_display,
		    sc->passkey_cb_arg) < 0) {
			uint8_t fail[2] = { SMP_PAIRING_FAILED,
			    SMP_ERR_PASSKEY_ENTRY_FAILED };
			smp_log_send(sc, fail, 2);
			errno = ECANCELED;
			return (-1);
		}
	}

	/* passkey as 128-bit LE integer for f6 */
	memset(ra, 0, sizeof(ra));
	ra[0] = passkey & 0xFF;
	ra[1] = (passkey >> 8) & 0xFF;
	ra[2] = (passkey >> 16) & 0xFF;

	smp_pack_addr(a1, sc->local_addr, sc->local_addr_type);
	smp_pack_addr(a2, sc->remote_addr, sc->remote_addr_type);

	/* IOcap in LE byte order: [IO_cap, OOB, AuthReq] */
	iocap_a[0] = preq[1];
	iocap_a[1] = preq[2];
	iocap_a[2] = preq[3];
	iocap_b[0] = pres[1];
	iocap_b[1] = pres[2];
	iocap_b[2] = pres[3];

	/* Generate P-256 key pair */
	our_key = smp_sc_gen_ephemeral();
	if (our_key == NULL)
		return (-1);

	if (smp_sc_extract_public(our_key, our_pk_raw) != 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}

	/* Send our PK (OpenSSL BE -> wire LE) */
	pdu[0] = SMP_PAIRING_PUBLIC_KEY;
	smp_swap_buf(pdu + 1, our_pk_raw + 1, 32);
	smp_swap_buf(pdu + 33, our_pk_raw + 33, 32);
	/* Store x-coord in LE for crypto functions */
	memcpy(pka_le, pdu + 1, 32);
	if (smp_log_send(sc, pdu, 65) < 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}

	/* Receive peer PK (wire = LE) */
	n = smp_recv_timed(sc, pdu, sizeof(pdu));
	if (n == SMP_RECV_TIMED_OUT) {
		EVP_PKEY_free(our_key);	/* link dropped, no PDU sent */
		return (-1);
	}
	if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_PUBLIC_KEY, 65)) {
		EVP_PKEY_free(our_key);
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	/* Convert peer PK to OpenSSL BE for ECDH */
	peer_pk_raw[0] = 0x04;
	smp_swap_buf(peer_pk_raw + 1, pdu + 1, 32);
	smp_swap_buf(peer_pk_raw + 33, pdu + 33, 32);
	/* Store x-coord in LE for crypto functions */
	memcpy(pkb_le, pdu + 1, 32);

	/* Validate peer public key is on P-256 curve (Core Spec 2.3.5.6.1) */
	if (smp_validate_public_key(peer_pk_raw + 1, peer_pk_raw + 33) != 0) {
		LOG_SMP(1, "SMP: peer public key not on P-256 curve, "
		    "failing pairing");
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		smp_log_send(sc, pdu, 2);
		EVP_PKEY_free(our_key);
		return (-1);
	}
	LOG_SMP(2, "SC: public keys exchanged");
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "pubkey");

	if (smp_sc_compute_dhkey(our_key, peer_pk_raw, dhkey_le) != 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}
	EVP_PKEY_free(our_key);
	LOG_SMP(2, "SC: DHKey computed");
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "dhkey");
	/* P-256 ECDH boundary: shared secret derived (no key material emitted). */
	BLUED_PROBE_SMP_DHKEY(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL));
	BLUED_PROBE_SMP_CRYPTO("dhkey", sc->con_handle);

	/*
	 * Authentication Stage 1: 20 rounds of Passkey Entry.
	 *
	 * For each bit i (0..19) of the passkey:
	 *   rai = 0x80 | ((passkey >> i) & 1)
	 *   Cai = f4(PKax, PKbx, Nai, rai) — initiator confirm
	 *   Cbi = f4(PKbx, PKax, Nbi, rbi) — responder confirm
	 *   Exchange: send Cai, recv Cbi, send Nai, recv Nbi, verify Cbi
	 */
	for (i = 0; i < 20; i++) {
		uint8_t nai[16], nbi[16];
		uint8_t cai[16], cbi_recv[16], cbi_verify[16];
		uint8_t ri;

		if (i == 0 || i == 19)
			LOG_SMP(2, "SC passkey: round %d/20", i + 1);

		ri = SMP_F4_PASSKEY_Z(passkey >> i);

		smp_random(nai, sizeof(nai));
		if (smp_f4(pka_le, pkb_le, nai, ri, cai) != 0) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
			smp_log_send(sc, pdu, 2);
			errno = EIO;
			goto sc_passkey_cleanup;
		}

		/* Send our confirm Cai */
		pdu[0] = SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, cai, 16);
		if (smp_log_send(sc, pdu, 17) < 0)
			goto sc_passkey_cleanup;

		/*
		 * Receive responder confirm Cbi.
		 * The displaying side sends Keypress Notifications (Vol 3
		 * Part H §3.5.8) during passkey entry; consume and log them
		 * transparently rather than rejecting them as out-of-sequence,
		 * for parity with the legacy passkey path (smp_pair()).
		 */
		n = smp_recv_timed_kp(sc, pdu, sizeof(pdu));
		if (n == SMP_RECV_TIMED_OUT)
			goto sc_passkey_cleanup;
		if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_CONFIRM, 17)) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			goto sc_passkey_cleanup;
		}
		memcpy(cbi_recv, pdu + 1, 16);

		/* Send our nonce Nai */
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, nai, 16);
		if (smp_log_send(sc, pdu, 17) < 0)
			goto sc_passkey_cleanup;

		/* Receive responder nonce Nbi (skip any Keypress Notifications) */
		n = smp_recv_timed_kp(sc, pdu, sizeof(pdu));
		if (n == SMP_RECV_TIMED_OUT)
			goto sc_passkey_cleanup;
		if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_RANDOM, 17)) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			goto sc_passkey_cleanup;
		}
		memcpy(nbi, pdu + 1, 16);

		/* Verify Cbi = f4(PKbx, PKax, Nbi, rbi) */
		if (smp_f4(pkb_le, pka_le, nbi, ri, cbi_verify) != 0) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
			smp_log_send(sc, pdu, 2);
			errno = EIO;
			goto sc_passkey_cleanup;
		}
		if (timingsafe_bcmp(cbi_recv, cbi_verify, 16) != 0) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
			smp_log_send(sc, pdu, 2);
			errno = EACCES;
			goto sc_passkey_cleanup;
		}

		/* Keep last round's nonces for f5/f6 */
		memcpy(na, nai, 16);
		memcpy(nb, nbi, 16);
	}
	LOG_SMP(1, "SC passkey: 20 rounds complete");
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "confirm");

	/*
	 * Authentication Stage 2: same as Just Works SC.
	 * MacKey || LTK = f5(DHKey, Na, Nb, A1, A2)
	 * Ea = f6(MacKey, Na, Nb, ra, IOcapA, A1, A2)
	 * Eb = f6(MacKey, Nb, Na, ra, IOcapB, A2, A1)
	 * (ra = rb = passkey for Passkey Entry per Table 2.2)
	 */
	if (smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
		smp_log_send(sc, pdu, 2);
		errno = EIO;
		goto sc_passkey_cleanup;
	}
#ifdef BLUED_DEBUG_KEYS
	if (blued_verbose >= 3)
		blued_hexdump("SMP", "f5 output (LTK)", ltk, 16);
#endif

	if (smp_f6(mackey, na, nb, ra, iocap_a, a1, a2, ea) != 0 ||
	    smp_f6(mackey, nb, na, ra, iocap_b, a2, a1, eb) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
		smp_log_send(sc, pdu, 2);
		errno = EIO;
		goto sc_passkey_cleanup;
	}
#ifdef BLUED_DEBUG_KEYS
	if (blued_verbose >= 3) {
		blued_hexdump("SMP", "f6 output (Ea)", ea, 16);
		blued_hexdump("SMP", "f6 output (Eb)", eb, 16);
	}
#endif

	/* Send Ea, receive and verify Eb */
	pdu[0] = SMP_PAIRING_DHKEY_CHECK;
	memcpy(pdu + 1, ea, 16);
	if (smp_log_send(sc, pdu, 17) < 0)
		goto sc_passkey_cleanup;

	n = smp_recv_timed(sc, pdu, sizeof(pdu));
	if (n == SMP_RECV_TIMED_OUT)
		goto sc_passkey_cleanup;
	if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_DHKEY_CHECK, 17)) {
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		goto sc_passkey_cleanup;
	}
	if (timingsafe_bcmp(pdu + 1, eb, 16) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		smp_log_send(sc, pdu, 2);
		errno = EACCES;
		goto sc_passkey_cleanup;
	}

	/* Start encryption */
	{
		uint8_t params[28];
		params[0] = sc->con_handle & 0xFF;
		params[1] = (sc->con_handle >> 8) & 0xFF;
		memset(params + 2, 0, 10);
		memcpy(params + 12, ltk, 16);
		if (hci_send_raw_cmd(sc->hci_fd, HCI_OP_LE_START_ENCRYPTION, params,
		    sizeof(params)) < 0) {
			explicit_bzero(params, sizeof(params));
			goto sc_passkey_cleanup;
		}
		/* Scrub the LTK copy from the HCI command buffer. */
		explicit_bzero(params, sizeof(params));
	}

	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 5) < 0)
		goto sc_passkey_cleanup;

	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "encrypt");
	BLUED_PROBE_ENCRYPT_START(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL));
	BLUED_LOG_SECURITY("encryption active "
	    "addr=%02x:%02x:%02x:%02x:%02x:%02x handle=%d",
	    sc->remote_addr[5], sc->remote_addr[4],
	    sc->remote_addr[3], sc->remote_addr[2],
	    sc->remote_addr[1], sc->remote_addr[0],
	    sc->con_handle);

	/* Store bond */
	{
		struct smp_bond bond;
		memset(&bond, 0, sizeof(bond));
		memcpy(bond.addr, sc->remote_addr, 6);
		bond.addr_type = sc->remote_addr_type;
		/* Persist the negotiated key size (Vol 3 Part H §2.3.4). */
		bond.key_size = sc->neg_key_size;
		memcpy(bond.ltk, ltk, 16);
		bond.has_ltk = true;
		bond.is_sc = true;
		bond.is_mitm = true; /* Passkey Entry provides MITM */

		BLUED_PROBE_SMP_PHASE(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL), "key-dist");
		/* Receive key distribution from responder (SC: IdKey + SignKey) */
		if (smp_receive_peer_keys(sc, &bond, pres[6], true) != 0) {
			explicit_bzero(&bond, sizeof(bond));
			ret = -1;
			goto sc_passkey_cleanup;
		}

		/* Distribute initiator keys to responder */
		if (smp_distribute_init_keys(sc, preq, pres, true) != 0) {
			explicit_bzero(&bond, sizeof(bond));
			ret = -1;
			goto sc_passkey_cleanup;
		}

		/* Core 6.3 Vol 3 Part H §3.6.1: both directions negotiate LinkKey. */
		if ((preq[5] & preq[6] & pres[5] & pres[6] &
		    SMP_KEY_DIST_LINK_KEY) != 0)
			smp_ctkd_derive_link_key(&bond,
			    (preq[3] & SMP_AUTH_CT2) &&
			    (pres[3] & SMP_AUTH_CT2));

		/*
		 * Persist only if BOTH sides requested Bonding (Core Spec Vol 3
		 * Part H §3.5.1 / §2.3.5.1); a No-Bonding peer's SC keys stay
		 * session-only.
		 */
		if (preq[3] & pres[3] & SMP_AUTH_BONDING) {
			if (smp_bond_db_store(sc->bond_db, &bond) != 0) {
				explicit_bzero(&bond, sizeof(bond));
				ret = -1;
				goto sc_passkey_cleanup;
			}
			BLUED_LOG_SECURITY("bond stored "
			    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
			    "ltk=%d irk=%d lk=%d",
			    bond.addr[5], bond.addr[4],
			    bond.addr[3], bond.addr[2],
			    bond.addr[1], bond.addr[0],
			    bond.has_ltk, bond.has_irk, bond.has_link_key);
		} else {
			LOG_SMP(1, "no-bonding peer: keys kept session-only");
		}
		BLUED_LOG_SECURITY("pairing complete "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "sc=%d bonded=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    1, (preq[3] & pres[3] & SMP_AUTH_BONDING) ? bond.has_ltk : 0);
		explicit_bzero(&bond, sizeof(bond));
	}

	ret = 0;

sc_passkey_cleanup:
	BLUED_PROBE_SMP_PAIR_DONE(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL), ret);
	if (ret != 0)
		BLUED_LOG_SECURITY("pairing failed "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x reason=%02x",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    (unsigned)errno);
	explicit_bzero(dhkey_le, sizeof(dhkey_le));
	explicit_bzero(mackey, sizeof(mackey));
	explicit_bzero(ltk, sizeof(ltk));
	explicit_bzero(na, sizeof(na));
	explicit_bzero(nb, sizeof(nb));
	explicit_bzero(ra, sizeof(ra));
	return (ret);
}

/*
 * LE Secure Connections pairing — Just Works.
 * Called after Pairing Request/Response exchange when both sides
 * set SMP_AUTH_SC.
 *
 * Core Spec Vol 3 Part H Section 2.3.5.6
 */
int
smp_pair_sc(struct smp_conn *sc, const uint8_t preq[7], const uint8_t pres[7],
    int model)
{
	EVP_PKEY *our_key = NULL;
	uint8_t our_pk_raw[65], peer_pk_raw[65];
	uint8_t dhkey_le[32];
	uint8_t na[16], nb[16];
	uint8_t mackey[16], ltk[16];
	uint8_t ea[16], eb[16];
	uint8_t a1[7], a2[7];
	uint8_t iocap_a[3], iocap_b[3];
	uint8_t pdu[66];
	ssize_t n;
	int ret = -1;

	/*
	 * Arm the single cumulative §3.4 deadline if not already armed by the
	 * smp_pair() caller — do NOT reset an inherited deadline, so the timer
	 * spans the whole procedure from the Pairing Request.
	 */
	smp_pairing_arm(sc);

	smp_pack_addr(a1, sc->local_addr, sc->local_addr_type);
	smp_pack_addr(a2, sc->remote_addr, sc->remote_addr_type);

	/*
	 * IOcap in LE byte order: [IO_cap, OOB, AuthReq].
	 * Crypto functions internally reverse to BE [AuthReq, OOB, IO_cap]
	 * per spec Section 2.2.8.
	 */
	iocap_a[0] = preq[1];	/* IO_cap (LSB) */
	iocap_a[1] = preq[2];	/* OOB */
	iocap_a[2] = preq[3];	/* AuthReq (MSB) */
	iocap_b[0] = pres[1];
	iocap_b[1] = pres[2];
	iocap_b[2] = pres[3];

	/* Generate P-256 key pair */
	our_key = smp_sc_gen_ephemeral();
	if (our_key == NULL)
		return (-1);

	/* Extract uncompressed public key */
	if (smp_sc_extract_public(our_key, our_pk_raw) != 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}

	/*
	 * Public key byte order:
	 * OpenSSL uses big-endian [0x04, X(32), Y(32)].
	 * SMP wire format uses little-endian [x(32), y(32)].
	 * We must reverse each 32-byte coordinate.
	 *
	 * We keep two representations:
	 * - our_pk_raw/peer_pk_raw: OpenSSL format (big-endian, for ECDH)
	 * - pka_be/pkb_be: big-endian x-coordinates for f4/f5/f6
	 *   (spec crypto functions operate in big-endian per Appendix D)
	 */
	uint8_t pka_le[32], pkb_le[32]; /* LE x-coords for crypto */

	/* Send our Public Key: [0x0C, x_le(32), y_le(32)] */
	pdu[0] = SMP_PAIRING_PUBLIC_KEY;
	smp_swap_buf(pdu + 1, our_pk_raw + 1, 32);      /* x: BE -> LE */
	smp_swap_buf(pdu + 33, our_pk_raw + 33, 32);     /* y: BE -> LE */
	memcpy(pka_le, pdu + 1, 32);                /* save LE x-coord */
	if (smp_log_send(sc, pdu, 65) < 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}

	/* Receive peer's Public Key (wire = little-endian) */
	n = smp_recv_timed(sc, pdu, sizeof(pdu));
	if (n == SMP_RECV_TIMED_OUT) {
		EVP_PKEY_free(our_key);	/* link dropped, no PDU sent */
		return (-1);
	}
	if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_PUBLIC_KEY, 65)) {
		EVP_PKEY_free(our_key);
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	/* Convert peer PK to OpenSSL big-endian for ECDH */
	peer_pk_raw[0] = 0x04;
	smp_swap_buf(peer_pk_raw + 1, pdu + 1, 32);      /* x: LE -> BE */
	smp_swap_buf(peer_pk_raw + 33, pdu + 33, 32);    /* y: LE -> BE */
	memcpy(pkb_le, pdu + 1, 32);                /* save LE x-coord */

	/* Validate peer public key is on P-256 curve (Core Spec 2.3.5.6.1) */
	if (smp_validate_public_key(peer_pk_raw + 1, peer_pk_raw + 33) != 0) {
		LOG_SMP(1, "SMP: peer public key not on P-256 curve, "
		    "failing pairing");
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		smp_log_send(sc, pdu, 2);
		EVP_PKEY_free(our_key);
		return (-1);
	}
	LOG_SMP(2, "SC: public keys exchanged");
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "pubkey");

	if (smp_sc_compute_dhkey(our_key, peer_pk_raw, dhkey_le) != 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}
	EVP_PKEY_free(our_key);
	LOG_SMP(2, "SC: DHKey computed");
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "dhkey");
	/* P-256 ECDH boundary: shared secret derived (no key material emitted). */
	BLUED_PROBE_SMP_DHKEY(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL));
	BLUED_PROBE_SMP_CRYPTO("dhkey", sc->con_handle);

	/*
	 * Authentication Stage 1 dispatch by model.
	 *
	 * OOB (Section 2.3.5.6.4):
	 *   Each side already has the peer's {confirm, random} from OOB.
	 *   Exchange nonces, then verify peer's OOB confirm.
	 *
	 * Just Works / Numeric Comparison (Section 2.3.5.6.2):
	 *   The RESPONDER computes Cb = f4(PKbx, PKax, Nb, 0) and sends
	 *   Pairing Confirm.  The INITIATOR does NOT send a confirm.
	 *   Then nonces are exchanged.
	 *
	 * f4 inputs use the x-coordinate only (first 32 bytes of LE pk).
	 */
	if (model == SMP_MODEL_OOB) {
		/*
		 * SC OOB Authentication Stage 1.
		 * Core Spec Vol 3 Part H Section 2.3.5.6.4
		 *
		 * As initiator:
		 *  1. Generate Na (our OOB random was already computed and
		 *     sent to the peer out of band)
		 *  2. Send Pairing Random (Na)
		 *  3. Receive Pairing Random (Nb) from responder
		 *  4. Verify peer's OOB confirm: Cb = f4(PKbx, PKbx, Nb, 0)
		 *     must match sc->oob->sc->confirm
		 */
		if (sc->oob == NULL || sc->oob->sc == NULL) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_OOB_NOT_AVAILABLE;
			smp_log_send(sc, pdu, 2);
			errno = ENOTSUP;
			goto sc_jw_cleanup;
		}

		smp_random(na, sizeof(na));

		/* Send our Pairing Random (Na) */
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, na, 16);
		if (smp_log_send(sc, pdu, 17) < 0)
			goto sc_jw_cleanup;

		/* Receive peer's Pairing Random (Nb) */
		n = smp_recv_timed(sc, pdu, sizeof(pdu));
		if (n == SMP_RECV_TIMED_OUT)
			goto sc_jw_cleanup;
		if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_RANDOM, 17)) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			goto sc_jw_cleanup;
		}
		memcpy(nb, pdu + 1, 16);

		/* Verify peer's OOB confirm: Cb = f4(PKbx, PKbx, rb, 0) */
		{
			uint8_t cb_verify[16];
			if (smp_f4(pkb_le, pkb_le, sc->oob->sc->random, 0,
			    cb_verify) != 0) {
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
				smp_log_send(sc, pdu, 2);
				errno = EIO;
				goto sc_jw_cleanup;
			}
			if (timingsafe_bcmp(sc->oob->sc->confirm, cb_verify,
			    16) != 0) {
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
				smp_log_send(sc, pdu, 2);
				errno = EACCES;
				goto sc_jw_cleanup;
			}
		}
		LOG_SMP(1, "SC OOB: peer confirm verified");
	} else {
		/*
		 * Just Works / Numeric Comparison Stage 1.
		 *
		 * As initiator:
		 *  1. Receive Cb from responder
		 *  2. Generate Na, send Na
		 *  3. Receive Nb from responder
		 *  4. Verify Cb == f4(PKbx, PKax, Nb, 0)
		 */
		uint8_t cb_recv[16];

		/* Receive responder's Pairing Confirm (Cb) */
		n = smp_recv_timed(sc, pdu, sizeof(pdu));
		if (n == SMP_RECV_TIMED_OUT)
			goto sc_jw_cleanup;
		if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_CONFIRM, 17)) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			goto sc_jw_cleanup;
		}
		memcpy(cb_recv, pdu + 1, 16);

		/* Generate and send our nonce (Na) */
		smp_random(na, sizeof(na));
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, na, 16);
		if (smp_log_send(sc, pdu, 17) < 0)
			goto sc_jw_cleanup;

		/* Receive responder's nonce (Nb) */
		n = smp_recv_timed(sc, pdu, sizeof(pdu));
		if (n == SMP_RECV_TIMED_OUT)
			goto sc_jw_cleanup;
		if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_RANDOM, 17)) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			goto sc_jw_cleanup;
		}
		memcpy(nb, pdu + 1, 16);

		/* Verify Cb = f4(PKbx, PKax, Nb, 0) */
		{
			uint8_t cb_verify[16];
			if (smp_f4(pkb_le, pka_le, nb, 0, cb_verify) != 0) {
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
				smp_log_send(sc, pdu, 2);
				errno = EIO;
				goto sc_jw_cleanup;
			}
			if (timingsafe_bcmp(cb_recv, cb_verify, 16) != 0) {
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
				smp_log_send(sc, pdu, 2);
				errno = EACCES;
				goto sc_jw_cleanup;
			}
		}
		LOG_SMP(1, "SC: confirm verified");
		BLUED_PROBE_SMP_PHASE(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL), "confirm");

		/*
		 * Numeric Comparison (Section 2.3.5.6.2 step 7):
		 * Both sides compute Va/Vb = g2(PKax, PKbx, Na, Nb) mod 10^6
		 * and display the 6-digit value for user confirmation.
		 */
		if (model == SMP_MODEL_NUMERIC_COMPARISON) {
			uint32_t confirm_val;

			if (smp_g2(pka_le, pkb_le, na, nb, &confirm_val) != 0) {
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
				smp_log_send(sc, pdu, 2);
				errno = EIO;
				goto sc_jw_cleanup;
			}
			confirm_val %= 1000000;
			LOG_SMP(1, "SC: numeric comparison %06u", confirm_val);

			if (sc->numcmp_cb == NULL) {
				/*
				 * No local UI to confirm the numeric value: we
				 * cannot complete authentication.  Send Pairing
				 * Failed so the peer is not left waiting for the
				 * DHKey Check (Vol 3 Part H §3.5.5).  Use the
				 * same reason (Numeric Comparison Failed) as the
				 * responder path for cross-role consistency.
				 */
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_NUMERIC_COMP_FAILED;
				smp_log_send(sc, pdu, 2);
				errno = ENOTSUP;
				goto sc_jw_cleanup;
			}
			if (sc->numcmp_cb(confirm_val, sc->numcmp_cb_arg) < 0) {
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_NUMERIC_COMP_FAILED;
				smp_log_send(sc, pdu, 2);
				errno = EACCES;
				goto sc_jw_cleanup;
			}
		}
	} /* model dispatch */

	/* Compute MacKey and LTK */
	if (smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
		smp_log_send(sc, pdu, 2);
		errno = EIO;
		goto sc_jw_cleanup;
	}
	LOG_SMP(1, "SC: MacKey+LTK derived");
#ifdef BLUED_DEBUG_KEYS
	if (blued_verbose >= 3)
		blued_hexdump("SMP", "f5 output (LTK)", ltk, 16);
#endif

	/* Compute DHKey checks */
	{
		uint8_t r_ea[16], r_eb[16];

		/*
		 * Per Core Spec Vol 3 Part H Section 2.3.5.6.5:
		 * OOB: Ea uses rb (peer's OOB random), Eb uses ra (our random).
		 * All other models: r = 0.
		 */
		if (model == SMP_MODEL_OOB && sc->oob != NULL &&
		    sc->oob->sc != NULL) {
			memcpy(r_ea, sc->oob->sc->random, 16);
			memcpy(r_eb, sc->oob->sc->local_random, 16);
		} else {
			memset(r_ea, 0, sizeof(r_ea));
			memset(r_eb, 0, sizeof(r_eb));
		}
		if (smp_f6(mackey, na, nb, r_ea, iocap_a, a1, a2, ea) != 0 ||
		    smp_f6(mackey, nb, na, r_eb, iocap_b, a2, a1, eb) != 0) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
			smp_log_send(sc, pdu, 2);
			errno = EIO;
			goto sc_jw_cleanup;
		}
#ifdef BLUED_DEBUG_KEYS
		if (blued_verbose >= 3) {
			blued_hexdump("SMP", "f6 output (Ea)", ea, 16);
			blued_hexdump("SMP", "f6 output (Eb)", eb, 16);
		}
#endif
	}

	/* Send our DHKey Check (Ea) */
	pdu[0] = SMP_PAIRING_DHKEY_CHECK;
	memcpy(pdu + 1, ea, 16);
	if (smp_log_send(sc, pdu, 17) < 0)
		goto sc_jw_cleanup;

	/* Receive peer's DHKey Check (Eb) */
	n = smp_recv_timed(sc, pdu, sizeof(pdu));
	if (n == SMP_RECV_TIMED_OUT)
		goto sc_jw_cleanup;
	if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_DHKEY_CHECK, 17)) {
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		goto sc_jw_cleanup;
	}

	if (timingsafe_bcmp(pdu + 1, eb, 16) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		smp_log_send(sc, pdu, 2);
		errno = EACCES;
		goto sc_jw_cleanup;
	}
	LOG_SMP(1, "SC: DHKey check passed");
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "dhkey-check");

	/* Start encryption with SC-derived LTK (rand=0, ediv=0) */
	{
		uint8_t params[28];
		params[0] = sc->con_handle & 0xFF;
		params[1] = (sc->con_handle >> 8) & 0xFF;
		memset(params + 2, 0, 10);
		memcpy(params + 12, ltk, 16);
		if (hci_send_raw_cmd(sc->hci_fd, HCI_OP_LE_START_ENCRYPTION, params,
		    sizeof(params)) < 0) {
			explicit_bzero(params, sizeof(params));
			goto sc_jw_cleanup;
		}
		/* Scrub the LTK copy from the HCI command buffer. */
		explicit_bzero(params, sizeof(params));
	}

	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 5) < 0)
		goto sc_jw_cleanup;

	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "encrypt");
	BLUED_PROBE_ENCRYPT_START(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL));
	BLUED_LOG_SECURITY("encryption active "
	    "addr=%02x:%02x:%02x:%02x:%02x:%02x handle=%d",
	    sc->remote_addr[5], sc->remote_addr[4],
	    sc->remote_addr[3], sc->remote_addr[2],
	    sc->remote_addr[1], sc->remote_addr[0],
	    sc->con_handle);

	/* Store SC bond */
	{
		struct smp_bond bond;
		memset(&bond, 0, sizeof(bond));
		memcpy(bond.addr, sc->remote_addr, 6);
		bond.addr_type = sc->remote_addr_type;
		/* Persist the negotiated key size (Vol 3 Part H §2.3.4). */
		bond.key_size = sc->neg_key_size;
		memcpy(bond.ltk, ltk, 16);
		bond.has_ltk = true;
		bond.is_sc = true;
		bond.is_mitm = (model == SMP_MODEL_PASSKEY_ENTRY ||
		    model == SMP_MODEL_NUMERIC_COMPARISON ||
		    model == SMP_MODEL_OOB);

		BLUED_PROBE_SMP_PHASE(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL), "key-dist");
		/* Receive key distribution from responder.
		 * SC ignores EncKey; IdKey and SignKey apply. */
		if (smp_receive_peer_keys(sc, &bond, pres[6], true) != 0) {
			explicit_bzero(&bond, sizeof(bond));
			ret = -1;
			goto sc_jw_cleanup;
		}

		/* Distribute initiator keys to responder */
		if (smp_distribute_init_keys(sc, preq, pres, true) != 0) {
			explicit_bzero(&bond, sizeof(bond));
			ret = -1;
			goto sc_jw_cleanup;
		}

		/* Core 6.3 Vol 3 Part H §3.6.1: both directions negotiate LinkKey. */
		if ((preq[5] & preq[6] & pres[5] & pres[6] &
		    SMP_KEY_DIST_LINK_KEY) != 0)
			smp_ctkd_derive_link_key(&bond,
			    (preq[3] & SMP_AUTH_CT2) &&
			    (pres[3] & SMP_AUTH_CT2));

		/*
		 * Persist only if BOTH sides requested Bonding (Core Spec Vol 3
		 * Part H §3.5.1 / §2.3.5.1); a No-Bonding peer's SC keys stay
		 * session-only.
		 */
		if (preq[3] & pres[3] & SMP_AUTH_BONDING) {
			if (smp_bond_db_store(sc->bond_db, &bond) != 0) {
				explicit_bzero(&bond, sizeof(bond));
				ret = -1;
				goto sc_jw_cleanup;
			}
			BLUED_LOG_SECURITY("bond stored "
			    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
			    "ltk=%d irk=%d lk=%d",
			    bond.addr[5], bond.addr[4],
			    bond.addr[3], bond.addr[2],
			    bond.addr[1], bond.addr[0],
			    bond.has_ltk, bond.has_irk, bond.has_link_key);
		} else {
			LOG_SMP(1, "no-bonding peer: keys kept session-only");
		}
		BLUED_LOG_SECURITY("pairing complete "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "sc=%d bonded=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    1, (preq[3] & pres[3] & SMP_AUTH_BONDING) ? bond.has_ltk : 0);
		explicit_bzero(&bond, sizeof(bond));
	}

	ret = 0;

sc_jw_cleanup:
	BLUED_PROBE_SMP_PAIR_DONE(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL), ret);
	if (ret != 0)
		BLUED_LOG_SECURITY("pairing failed "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x reason=%02x",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    (unsigned)errno);
	explicit_bzero(dhkey_le, sizeof(dhkey_le));
	explicit_bzero(mackey, sizeof(mackey));
	explicit_bzero(ltk, sizeof(ltk));
	explicit_bzero(na, sizeof(na));
	explicit_bzero(nb, sizeof(nb));
	return (ret);
} /* smp_pair_sc */

/*
 * LE Secure Connections — Responder path (Just Works / Numeric Comparison).
 * Core Spec Vol 3 Part H Section 2.3.5.6
 */
int
smp_respond_sc(struct smp_conn *sc, const uint8_t preq[7],
    const uint8_t pres[7], int model)
{
	EVP_PKEY *our_key = NULL;
	uint8_t our_pk_raw[65], peer_pk_raw[65];
	uint8_t dhkey_le[32];
	uint8_t na[16], nb[16];
	uint8_t mackey[16], ltk[16];
	uint8_t ea[16], eb[16];
	uint8_t a1[7], a2[7];
	uint8_t iocap_a[3], iocap_b[3];
	uint8_t pdu[66];
	ssize_t n;
	uint8_t pka_le[32], pkb_le[32];	/* LE x-coords for crypto */
	int ret = -1;

	/*
	 * Arm the single cumulative §3.4 deadline if not already armed by the
	 * smp_respond() caller; direct-call unit tests arm here.
	 */
	smp_pairing_arm(sc);

	/* a1 = initiator (remote), a2 = responder (us) */
	smp_pack_addr(a1, sc->remote_addr, sc->remote_addr_type);
	smp_pack_addr(a2, sc->local_addr, sc->local_addr_type);

	/* IOcap in LE byte order: [IO_cap, OOB, AuthReq] */
	iocap_a[0] = preq[1]; iocap_a[1] = preq[2]; iocap_a[2] = preq[3];
	iocap_b[0] = pres[1]; iocap_b[1] = pres[2]; iocap_b[2] = pres[3];

	/* Generate P-256 key pair */
	our_key = smp_sc_gen_ephemeral();
	if (our_key == NULL)
		return (-1);

	if (smp_sc_extract_public(our_key, our_pk_raw) != 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}

	/* Receive initiator's PK first (responder receives first) */
	n = smp_recv_timed(sc, pdu, sizeof(pdu));
	if (n == SMP_RECV_TIMED_OUT) {
		EVP_PKEY_free(our_key);	/* link dropped, no PDU sent */
		return (-1);
	}
	if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_PUBLIC_KEY, 65)) {
		EVP_PKEY_free(our_key);
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	peer_pk_raw[0] = 0x04;
	smp_swap_buf(peer_pk_raw + 1, pdu + 1, 32);
	smp_swap_buf(peer_pk_raw + 33, pdu + 33, 32);
	memcpy(pka_le, pdu + 1, 32);		/* save LE x-coord */

	/* Validate peer public key is on P-256 curve (Core Spec 2.3.5.6.1) */
	if (smp_validate_public_key(peer_pk_raw + 1, peer_pk_raw + 33) != 0) {
		LOG_SMP(1, "SMP: peer public key not on P-256 curve, "
		    "failing pairing");
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		smp_log_send(sc, pdu, 2);
		EVP_PKEY_free(our_key);
		return (-1);
	}

	/* Send our PK */
	pdu[0] = SMP_PAIRING_PUBLIC_KEY;
	smp_swap_buf(pdu + 1, our_pk_raw + 1, 32);
	smp_swap_buf(pdu + 33, our_pk_raw + 33, 32);
	memcpy(pkb_le, pdu + 1, 32);		/* save LE x-coord */
	if (smp_log_send(sc, pdu, 65) < 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}
	LOG_SMP(2, "resp SC: public keys exchanged");
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "pubkey");

	if (smp_sc_compute_dhkey(our_key, peer_pk_raw, dhkey_le) != 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}
	EVP_PKEY_free(our_key);
	LOG_SMP(2, "resp SC: DHKey computed");
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "dhkey");

	/* Auth Stage 1 dispatch by model */
	if (model == SMP_MODEL_OOB) {
		/*
		 * SC OOB Authentication Stage 1 — Responder path.
		 * Core Spec Vol 3 Part H Section 2.3.5.6.4
		 *
		 * As responder:
		 *  1. Generate Nb
		 *  2. Receive Pairing Random (Na) from initiator
		 *  3. Verify peer's OOB confirm: Ca = f4(PKax, PKax, ra, 0)
		 *     must match sc->oob->sc->confirm
		 *  4. Send Pairing Random (Nb)
		 */
		if (sc->oob == NULL || sc->oob->sc == NULL) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_OOB_NOT_AVAILABLE;
			smp_log_send(sc, pdu, 2);
			errno = ENOTSUP;
			goto resp_sc_cleanup;
		}

		smp_random(nb, sizeof(nb));

		/* Receive Na from initiator */
		n = smp_recv_timed(sc, pdu, sizeof(pdu));
		if (n == SMP_RECV_TIMED_OUT)
			goto resp_sc_cleanup;
		if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_RANDOM, 17)) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			goto resp_sc_cleanup;
		}
		memcpy(na, pdu + 1, 16);

		/* Verify peer's OOB confirm: Ca = f4(PKax, PKax, ra, 0) */
		{
			uint8_t ca_verify[16];
			if (smp_f4(pka_le, pka_le, sc->oob->sc->random, 0,
			    ca_verify) != 0) {
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
				smp_log_send(sc, pdu, 2);
				errno = EIO;
				goto resp_sc_cleanup;
			}
			if (timingsafe_bcmp(sc->oob->sc->confirm, ca_verify,
			    16) != 0) {
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
				smp_log_send(sc, pdu, 2);
				errno = EACCES;
				goto resp_sc_cleanup;
			}
		}
		LOG_SMP(1, "resp SC OOB: peer confirm verified");

		/* Send Nb */
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, nb, 16);
		if (smp_log_send(sc, pdu, 17) < 0)
			goto resp_sc_cleanup;
	} else {
		/*
		 * Just Works / Numeric Comparison Stage 1.
		 * Generate Nb, compute Cb, exchange nonces.
		 */
		smp_random(nb, sizeof(nb));
		{
			uint8_t cb[16];
			if (smp_f4(pkb_le, pka_le, nb, 0, cb) != 0) {
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
				smp_log_send(sc, pdu, 2);
				errno = EIO;
				goto resp_sc_cleanup;
			}
			pdu[0] = SMP_PAIRING_CONFIRM;
			memcpy(pdu + 1, cb, 16);
			if (smp_log_send(sc, pdu, 17) < 0)
				goto resp_sc_cleanup;
		}

		/* Receive Na */
		n = smp_recv_timed(sc, pdu, sizeof(pdu));
		if (n == SMP_RECV_TIMED_OUT)
			goto resp_sc_cleanup;
		if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_RANDOM, 17)) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			goto resp_sc_cleanup;
		}
		memcpy(na, pdu + 1, 16);

		/* Send Nb */
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, nb, 16);
		if (smp_log_send(sc, pdu, 17) < 0)
			goto resp_sc_cleanup;
		LOG_SMP(2, "resp SC: nonce exchange done");
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "random");

		/* Numeric Comparison */
		if (model == SMP_MODEL_NUMERIC_COMPARISON) {
			uint32_t cv;

			if (smp_g2(pka_le, pkb_le, na, nb, &cv) != 0) {
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
				smp_log_send(sc, pdu, 2);
				errno = EIO;
				goto resp_sc_cleanup;
			}
			cv %= 1000000;
			if (sc->numcmp_cb == NULL ||
			    sc->numcmp_cb(cv, sc->numcmp_cb_arg) < 0) {
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_NUMERIC_COMP_FAILED;
				smp_log_send(sc, pdu, 2);
				errno = EACCES;
				goto resp_sc_cleanup;
			}
		}
	} /* model dispatch */

	/* MacKey + LTK */
	if (smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
		smp_log_send(sc, pdu, 2);
		errno = EIO;
		goto resp_sc_cleanup;
	}
#ifdef BLUED_DEBUG_KEYS
	if (blued_verbose >= 3)
		blued_hexdump("SMP", "f5 output (LTK)", ltk, 16);
#endif

	/* DHKey checks */
	{
		uint8_t r_ea[16], r_eb[16];

		/*
		 * Per Core Spec Vol 3 Part H Section 2.3.5.6.5:
		 * OOB: Ea uses rb (responder's random = our random),
		 *       Eb uses ra (initiator's random = peer's random).
		 * All other models: r = 0.
		 */
		if (model == SMP_MODEL_OOB && sc->oob != NULL &&
		    sc->oob->sc != NULL) {
			memcpy(r_ea, sc->oob->sc->local_random, 16);
			memcpy(r_eb, sc->oob->sc->random, 16);
		} else {
			memset(r_ea, 0, sizeof(r_ea));
			memset(r_eb, 0, sizeof(r_eb));
		}
		if (smp_f6(mackey, na, nb, r_ea, iocap_a, a1, a2, ea) != 0 ||
		    smp_f6(mackey, nb, na, r_eb, iocap_b, a2, a1, eb) != 0) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
			smp_log_send(sc, pdu, 2);
			errno = EIO;
			goto resp_sc_cleanup;
		}
#ifdef BLUED_DEBUG_KEYS
		if (blued_verbose >= 3) {
			blued_hexdump("SMP", "f6 output (Ea)", ea, 16);
			blued_hexdump("SMP", "f6 output (Eb)", eb, 16);
		}
#endif
	}

	/* Receive Ea, verify */
	n = smp_recv_timed(sc, pdu, sizeof(pdu));
	if (n == SMP_RECV_TIMED_OUT)
		goto resp_sc_cleanup;
	if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_DHKEY_CHECK, 17)) {
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		goto resp_sc_cleanup;
	}
	if (timingsafe_bcmp(pdu + 1, ea, 16) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		smp_log_send(sc, pdu, 2);
		errno = EACCES;
		goto resp_sc_cleanup;
	}
	LOG_SMP(1, "resp SC: DHKey check passed");
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "dhkey-check");

	/* Send Eb */
	pdu[0] = SMP_PAIRING_DHKEY_CHECK;
	memcpy(pdu + 1, eb, 16);
	if (smp_log_send(sc, pdu, 17) < 0)
		goto resp_sc_cleanup;

	/* LTK reply + wait for encryption */
	if (hci_le_ltk_request_reply(sc->hci_fd, sc->con_handle, ltk) < 0)
		goto resp_sc_cleanup;
	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 10) < 0)
		goto resp_sc_cleanup;
	LOG_SMP(1, "resp SC: encrypted");

	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "encrypt");
	BLUED_PROBE_ENCRYPT_START(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL));
	BLUED_LOG_SECURITY("encryption active "
	    "addr=%02x:%02x:%02x:%02x:%02x:%02x handle=%d",
	    sc->remote_addr[5], sc->remote_addr[4],
	    sc->remote_addr[3], sc->remote_addr[2],
	    sc->remote_addr[1], sc->remote_addr[0],
	    sc->con_handle);

	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "key-dist");
	/* Distribute our IdKey if negotiated (responder distributes first) */
	if (pres[6] & SMP_KEY_DIST_ID_KEY) {
		/*
		 * Guard on bond_db != NULL (K-low ID-key NULL deref): without a
		 * bond DB there is no local IRK and the local_irk deref below
		 * would fault (the sibling SignKey branch already guards NULL).
		 */
		/* Send Identity Information (IRK). */
		if (sc->bond_db == NULL || smp_ensure_local_irk(sc->bond_db) != 0) {
			ret = -1;
			goto resp_sc_cleanup;
		}
		pdu[0] = SMP_IDENTITY_INFORMATION;
		memcpy(pdu + 1, sc->bond_db->local_irk, 16);
		if (smp_log_send(sc, pdu, 17) != 17) {
			ret = -1;
			goto resp_sc_cleanup;
		}

		/* Send Identity Address Information */
		pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = (sc->local_addr_type == BDADDR_LE_RANDOM) ?
		    SMP_ID_ADDR_STATIC_RANDOM : SMP_ID_ADDR_PUBLIC;
		memcpy(pdu + 2, sc->local_addr, 6);
		if (smp_log_send(sc, pdu, 8) != 8) {
			ret = -1;
			goto resp_sc_cleanup;
		}
	}

	/* Distribute SignKey (CSRK) if negotiated */
	if (pres[6] & SMP_KEY_DIST_LEGACY_SIGN_KEY) {
		if (smp_ensure_local_csrk(sc->bond_db) != 0) {
			ret = -1;
			goto resp_sc_cleanup;
		}
		pdu[0] = SMP_LEGACY_SIGNING_INFORMATION;
		memcpy(pdu + 1, sc->bond_db->local_csrk, 16);
		if (smp_log_send(sc, pdu, 17) != 17) {
			ret = -1;
			goto resp_sc_cleanup;
		}
	}

	/* Store bond */
	{
		struct smp_bond bond;
		memset(&bond, 0, sizeof(bond));
		memcpy(bond.addr, sc->remote_addr, 6);
		bond.addr_type = sc->remote_addr_type;
		/* Persist the negotiated key size (Vol 3 Part H §2.3.4). */
		bond.key_size = sc->neg_key_size;
		memcpy(bond.ltk, ltk, 16);
		bond.has_ltk = true;
		bond.is_sc = true;
		bond.is_mitm = (model == SMP_MODEL_PASSKEY_ENTRY ||
		    model == SMP_MODEL_NUMERIC_COMPARISON ||
		    model == SMP_MODEL_OOB);

		/* Receive initiator's keys. SC ignores EncKey;
		 * IdKey and SignKey from pres[5] apply. */
		if (smp_receive_peer_keys(sc, &bond, pres[5], true) != 0) {
			explicit_bzero(&bond, sizeof(bond));
			ret = -1;
			goto resp_sc_cleanup;
		}

		/* Core 6.3 Vol 3 Part H §3.6.1: both directions negotiate LinkKey. */
		if ((preq[5] & preq[6] & pres[5] & pres[6] &
		    SMP_KEY_DIST_LINK_KEY) != 0)
			smp_ctkd_derive_link_key(&bond,
			    (preq[3] & SMP_AUTH_CT2) &&
			    (pres[3] & SMP_AUTH_CT2));

		/*
		 * Persist only if BOTH sides requested Bonding (Core Spec Vol 3
		 * Part H §3.5.1 / §2.3.5.1); a No-Bonding peer's SC keys stay
		 * session-only.
		 */
		if (preq[3] & pres[3] & SMP_AUTH_BONDING) {
			if (smp_bond_db_store(sc->bond_db, &bond) != 0) {
				explicit_bzero(&bond, sizeof(bond));
				ret = -1;
				goto resp_sc_cleanup;
			}
			BLUED_LOG_SECURITY("bond stored "
			    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
			    "ltk=%d irk=%d lk=%d",
			    bond.addr[5], bond.addr[4],
			    bond.addr[3], bond.addr[2],
			    bond.addr[1], bond.addr[0],
			    bond.has_ltk, bond.has_irk, bond.has_link_key);
		} else {
			LOG_SMP(1, "no-bonding peer: keys kept session-only");
		}
		BLUED_LOG_SECURITY("pairing complete "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "sc=%d bonded=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    1, (preq[3] & pres[3] & SMP_AUTH_BONDING) ? bond.has_ltk : 0);
		explicit_bzero(&bond, sizeof(bond));
	}

	ret = 0;

resp_sc_cleanup:
	BLUED_PROBE_SMP_PAIR_DONE(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL), ret);
	if (ret != 0)
		BLUED_LOG_SECURITY("pairing failed "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x reason=%02x",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    (unsigned)errno);
	explicit_bzero(dhkey_le, sizeof(dhkey_le));
	explicit_bzero(mackey, sizeof(mackey));
	explicit_bzero(ltk, sizeof(ltk));
	explicit_bzero(na, sizeof(na));
	explicit_bzero(nb, sizeof(nb));
	return (ret);
}

/*
 * LE Secure Connections — Responder path for Passkey Entry.
 * Core Spec Vol 3 Part H Section 2.3.5.6.3, Figure 2.4
 *
 * Mirrors smp_pair_sc_passkey() but with responder message ordering:
 * For each bit: recv Cai, send Cbi, recv Nai, verify Cai, send Nbi
 */
int
smp_respond_sc_passkey(struct smp_conn *sc, const uint8_t preq[7],
    const uint8_t pres[7])
{
	EVP_PKEY *our_key = NULL;
	uint8_t our_pk_raw[65], peer_pk_raw[65];
	uint8_t pka_le[32], pkb_le[32];
	uint8_t dhkey_le[32];
	uint8_t na[16], nb[16];
	uint8_t mackey[16], ltk[16];
	uint8_t ea[16], eb[16];
	uint8_t a1[7], a2[7];
	uint8_t iocap_a[3], iocap_b[3];
	uint8_t pdu[66];
	ssize_t n;
	uint32_t passkey;
	uint8_t ra[16];
	int ret = -1;
	int i;

	/*
	 * Arm the single cumulative §3.4 deadline if not already armed by the
	 * smp_respond() caller; direct-call unit tests arm here.
	 */
	smp_pairing_arm(sc);

	if (sc->passkey_cb == NULL) {
		uint8_t f[2] = { SMP_PAIRING_FAILED,
		    SMP_ERR_PAIRING_NOT_SUPPORTED };
		smp_log_send(sc, f, 2);
		errno = ENOTSUP;
		return (-1);
	}

	/*
	 * Determine passkey display/input role per Core Spec Vol 3 Part H
	 * Table 2.8, responder side: our IO capability is pres[1], the
	 * peer/initiator's is preq[1].
	 */
	{
		bool we_display = smp_passkey_we_display(pres[1], preq[1],
		    false);

		passkey = 0;
		if (we_display)
			passkey = arc4random_uniform(1000000);
		if (sc->passkey_cb(&passkey, we_display,
		    sc->passkey_cb_arg) < 0) {
			uint8_t f[2] = { SMP_PAIRING_FAILED,
			    SMP_ERR_PASSKEY_ENTRY_FAILED };
			smp_log_send(sc, f, 2);
			errno = ECANCELED;
			return (-1);
		}
	}

	memset(ra, 0, sizeof(ra));
	ra[0] = passkey & 0xFF;
	ra[1] = (passkey >> 8) & 0xFF;
	ra[2] = (passkey >> 16) & 0xFF;

	/* a1 = initiator (remote), a2 = responder (us) */
	smp_pack_addr(a1, sc->remote_addr, sc->remote_addr_type);
	smp_pack_addr(a2, sc->local_addr, sc->local_addr_type);

	/* IOcap in LE byte order */
	iocap_a[0] = preq[1]; iocap_a[1] = preq[2]; iocap_a[2] = preq[3];
	iocap_b[0] = pres[1]; iocap_b[1] = pres[2]; iocap_b[2] = pres[3];

	/* Generate P-256 key pair */
	our_key = smp_sc_gen_ephemeral();
	if (our_key == NULL)
		return (-1);

	if (smp_sc_extract_public(our_key, our_pk_raw) != 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}

	/* Receive initiator's PK first (responder receives first) */
	n = smp_recv_timed(sc, pdu, sizeof(pdu));
	if (n == SMP_RECV_TIMED_OUT) {
		EVP_PKEY_free(our_key);	/* link dropped, no PDU sent */
		return (-1);
	}
	if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_PUBLIC_KEY, 65)) {
		EVP_PKEY_free(our_key);
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	peer_pk_raw[0] = 0x04;
	smp_swap_buf(peer_pk_raw + 1, pdu + 1, 32);
	smp_swap_buf(peer_pk_raw + 33, pdu + 33, 32);
	memcpy(pka_le, pdu + 1, 32);

	/* Validate peer public key is on P-256 curve (Core Spec 2.3.5.6.1) */
	if (smp_validate_public_key(peer_pk_raw + 1, peer_pk_raw + 33) != 0) {
		LOG_SMP(1, "SMP: peer public key not on P-256 curve, "
		    "failing pairing");
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		smp_log_send(sc, pdu, 2);
		EVP_PKEY_free(our_key);
		return (-1);
	}

	/* Send our PK */
	pdu[0] = SMP_PAIRING_PUBLIC_KEY;
	smp_swap_buf(pdu + 1, our_pk_raw + 1, 32);
	smp_swap_buf(pdu + 33, our_pk_raw + 33, 32);
	memcpy(pkb_le, pdu + 1, 32);
	if (smp_log_send(sc, pdu, 65) < 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}
	LOG_SMP(2, "resp SC: public keys exchanged");
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "pubkey");

	if (smp_sc_compute_dhkey(our_key, peer_pk_raw, dhkey_le) != 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}
	EVP_PKEY_free(our_key);
	LOG_SMP(2, "resp SC: DHKey computed");
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "dhkey");

	/*
	 * Authentication Stage 1: 20 rounds of Passkey Entry.
	 * Responder ordering per Figure 2.4:
	 *   recv Cai, send Cbi, recv Nai, verify Cai, send Nbi
	 */
	for (i = 0; i < 20; i++) {
		uint8_t nai[16], nbi[16];
		uint8_t cai_recv[16], cbi[16], cai_verify[16];
		uint8_t ri;

		if (i == 0 || i == 19)
			LOG_SMP(2, "resp SC passkey: round %d/20", i + 1);

		ri = SMP_F4_PASSKEY_Z(passkey >> i);

		smp_random(nbi, sizeof(nbi));

		/*
		 * Receive initiator's confirm Cai.
		 * The inputting side sends Keypress Notifications (Vol 3
		 * Part H §3.5.8) during passkey entry; consume and log them
		 * transparently rather than rejecting them as out-of-sequence,
		 * for parity with the legacy passkey path (smp_pair()).
		 */
		n = smp_recv_timed_kp(sc, pdu, sizeof(pdu));
		if (n == SMP_RECV_TIMED_OUT)
			goto resp_sc_pk_cleanup;
		if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_CONFIRM, 17)) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			goto resp_sc_pk_cleanup;
		}
		memcpy(cai_recv, pdu + 1, 16);

		/* Compute and send our confirm Cbi */
		if (smp_f4(pkb_le, pka_le, nbi, ri, cbi) != 0) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
			smp_log_send(sc, pdu, 2);
			errno = EIO;
			goto resp_sc_pk_cleanup;
		}
		pdu[0] = SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, cbi, 16);
		if (smp_log_send(sc, pdu, 17) < 0)
			goto resp_sc_pk_cleanup;

		/* Receive initiator's nonce Nai (skip any Keypress Notifications) */
		n = smp_recv_timed_kp(sc, pdu, sizeof(pdu));
		if (n == SMP_RECV_TIMED_OUT)
			goto resp_sc_pk_cleanup;
		if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_RANDOM, 17)) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			goto resp_sc_pk_cleanup;
		}
		memcpy(nai, pdu + 1, 16);

		/* Verify Cai = f4(PKax, PKbx, Nai, rai) */
		if (smp_f4(pka_le, pkb_le, nai, ri, cai_verify) != 0) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
			smp_log_send(sc, pdu, 2);
			errno = EIO;
			goto resp_sc_pk_cleanup;
		}
		if (timingsafe_bcmp(cai_recv, cai_verify, 16) != 0) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
			smp_log_send(sc, pdu, 2);
			errno = EACCES;
			goto resp_sc_pk_cleanup;
		}

		/* Send our nonce Nbi */
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, nbi, 16);
		if (smp_log_send(sc, pdu, 17) < 0)
			goto resp_sc_pk_cleanup;

		/* Keep last round's nonces for f5/f6 */
		memcpy(na, nai, 16);
		memcpy(nb, nbi, 16);
	}
	LOG_SMP(1, "resp SC passkey: 20 rounds complete");
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "confirm");

	/* Auth Stage 2: MacKey/LTK derivation and DHKey checks */
	if (smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
		smp_log_send(sc, pdu, 2);
		errno = EIO;
		goto resp_sc_pk_cleanup;
	}
#ifdef BLUED_DEBUG_KEYS
	if (blued_verbose >= 3)
		blued_hexdump("SMP", "f5 output (LTK)", ltk, 16);
#endif

	if (smp_f6(mackey, na, nb, ra, iocap_a, a1, a2, ea) != 0 ||
	    smp_f6(mackey, nb, na, ra, iocap_b, a2, a1, eb) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
		smp_log_send(sc, pdu, 2);
		errno = EIO;
		goto resp_sc_pk_cleanup;
	}
#ifdef BLUED_DEBUG_KEYS
	if (blued_verbose >= 3) {
		blued_hexdump("SMP", "f6 output (Ea)", ea, 16);
		blued_hexdump("SMP", "f6 output (Eb)", eb, 16);
	}
#endif

	/* Receive Ea from initiator, verify */
	n = smp_recv_timed(sc, pdu, sizeof(pdu));
	if (n == SMP_RECV_TIMED_OUT)
		goto resp_sc_pk_cleanup;
	if (!smp_sc_fixed_pdu_valid(sc, pdu, n, SMP_PAIRING_DHKEY_CHECK, 17)) {
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		goto resp_sc_pk_cleanup;
	}
	if (timingsafe_bcmp(pdu + 1, ea, 16) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		smp_log_send(sc, pdu, 2);
		errno = EACCES;
		goto resp_sc_pk_cleanup;
	}

	/* Send our DHKey Check (Eb) */
	pdu[0] = SMP_PAIRING_DHKEY_CHECK;
	memcpy(pdu + 1, eb, 16);
	if (smp_log_send(sc, pdu, 17) < 0)
		goto resp_sc_pk_cleanup;

	/* LTK reply + wait for encryption */
	if (hci_le_ltk_request_reply(sc->hci_fd, sc->con_handle, ltk) < 0)
		goto resp_sc_pk_cleanup;
	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 10) < 0)
		goto resp_sc_pk_cleanup;

	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "encrypt");
	BLUED_PROBE_ENCRYPT_START(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL));
	BLUED_LOG_SECURITY("encryption active "
	    "addr=%02x:%02x:%02x:%02x:%02x:%02x handle=%d",
	    sc->remote_addr[5], sc->remote_addr[4],
	    sc->remote_addr[3], sc->remote_addr[2],
	    sc->remote_addr[1], sc->remote_addr[0],
	    sc->con_handle);

	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "key-dist");
	/* Distribute our IdKey if negotiated (responder distributes first) */
	if (pres[6] & SMP_KEY_DIST_ID_KEY) {
		/*
		 * Guard on bond_db != NULL (K-low ID-key NULL deref): without a
		 * bond DB there is no local IRK and the local_irk deref below
		 * would fault (the sibling SignKey branch already guards NULL).
		 */
		/* Send Identity Information (IRK). */
		if (sc->bond_db == NULL || smp_ensure_local_irk(sc->bond_db) != 0) {
			ret = -1;
			goto resp_sc_pk_cleanup;
		}
		pdu[0] = SMP_IDENTITY_INFORMATION;
		memcpy(pdu + 1, sc->bond_db->local_irk, 16);
		if (smp_log_send(sc, pdu, 17) != 17) {
			ret = -1;
			goto resp_sc_pk_cleanup;
		}

		/* Send Identity Address Information */
		pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = (sc->local_addr_type == BDADDR_LE_RANDOM) ?
		    SMP_ID_ADDR_STATIC_RANDOM : SMP_ID_ADDR_PUBLIC;
		memcpy(pdu + 2, sc->local_addr, 6);
		if (smp_log_send(sc, pdu, 8) != 8) {
			ret = -1;
			goto resp_sc_pk_cleanup;
		}
	}

	/* Distribute SignKey (CSRK) if negotiated */
	if (pres[6] & SMP_KEY_DIST_LEGACY_SIGN_KEY) {
		if (smp_ensure_local_csrk(sc->bond_db) != 0) {
			ret = -1;
			goto resp_sc_pk_cleanup;
		}
		pdu[0] = SMP_LEGACY_SIGNING_INFORMATION;
		memcpy(pdu + 1, sc->bond_db->local_csrk, 16);
		if (smp_log_send(sc, pdu, 17) != 17) {
			ret = -1;
			goto resp_sc_pk_cleanup;
		}
	}

	/* Store bond */
	{
		struct smp_bond bond;
		memset(&bond, 0, sizeof(bond));
		memcpy(bond.addr, sc->remote_addr, 6);
		bond.addr_type = sc->remote_addr_type;
		/* Persist the negotiated key size (Vol 3 Part H §2.3.4). */
		bond.key_size = sc->neg_key_size;
		memcpy(bond.ltk, ltk, 16);
		bond.has_ltk = true;
		bond.is_sc = true;
		bond.is_mitm = true; /* Passkey Entry provides MITM */

		/* Receive initiator's keys. SC ignores EncKey;
		 * IdKey and SignKey from pres[5] apply. */
		if (smp_receive_peer_keys(sc, &bond, pres[5], true) != 0) {
			explicit_bzero(&bond, sizeof(bond));
			ret = -1;
			goto resp_sc_pk_cleanup;
		}

		/* Core 6.3 Vol 3 Part H §3.6.1: both directions negotiate LinkKey. */
		if ((preq[5] & preq[6] & pres[5] & pres[6] &
		    SMP_KEY_DIST_LINK_KEY) != 0)
			smp_ctkd_derive_link_key(&bond,
			    (preq[3] & SMP_AUTH_CT2) &&
			    (pres[3] & SMP_AUTH_CT2));

		/*
		 * Persist only if BOTH sides requested Bonding (Core Spec Vol 3
		 * Part H §3.5.1 / §2.3.5.1); a No-Bonding peer's SC keys stay
		 * session-only.
		 */
		if (preq[3] & pres[3] & SMP_AUTH_BONDING) {
			if (smp_bond_db_store(sc->bond_db, &bond) != 0) {
				explicit_bzero(&bond, sizeof(bond));
				ret = -1;
				goto resp_sc_pk_cleanup;
			}
			BLUED_LOG_SECURITY("bond stored "
			    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
			    "ltk=%d irk=%d lk=%d",
			    bond.addr[5], bond.addr[4],
			    bond.addr[3], bond.addr[2],
			    bond.addr[1], bond.addr[0],
			    bond.has_ltk, bond.has_irk, bond.has_link_key);
		} else {
			LOG_SMP(1, "no-bonding peer: keys kept session-only");
		}
		BLUED_LOG_SECURITY("pairing complete "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "sc=%d bonded=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    1, (preq[3] & pres[3] & SMP_AUTH_BONDING) ? bond.has_ltk : 0);
		explicit_bzero(&bond, sizeof(bond));
	}

	ret = 0;

resp_sc_pk_cleanup:
	BLUED_PROBE_SMP_PAIR_DONE(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL), ret);
	if (ret != 0)
		BLUED_LOG_SECURITY("pairing failed "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x reason=%02x",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    (unsigned)errno);
	explicit_bzero(dhkey_le, sizeof(dhkey_le));
	explicit_bzero(mackey, sizeof(mackey));
	explicit_bzero(ltk, sizeof(ltk));
	explicit_bzero(na, sizeof(na));
	explicit_bzero(nb, sizeof(nb));
	explicit_bzero(ra, sizeof(ra));
	return (ret);
}
