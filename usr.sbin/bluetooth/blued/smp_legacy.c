/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * LE Legacy Pairing — Responder path.
 * Core Spec Vol 3 Part H Section 2.3.5.5
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/endian.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

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

/* See smp_internal.h.  This is NULL in production. */
smp_legacy_crypto_hook_t smp_legacy_crypto_hook = NULL;

/* Keep the test-only fault seam at the crypto boundary.  In production the
 * hook is NULL, so these wrappers are direct calls to the Core Spec c1/s1
 * primitives; keeping the seam here lets tests exercise the same error
 * handling used for a provider failure without fabricating an SMP PDU. */
static int
smp_legacy_c1(const uint8_t tk[16], const uint8_t rand[16],
    const uint8_t preq[7], const uint8_t pres[7], uint8_t iat,
    const uint8_t ia[6], uint8_t rat, const uint8_t ra[6], uint8_t out[16],
    const char *operation)
{

	if (smp_legacy_crypto_hook != NULL &&
	    smp_legacy_crypto_hook(operation) != 0)
		return (-1);
	return (smp_c1(tk, rand, preq, pres, iat, ia, rat, ra, out));
}

static int
smp_legacy_s1(const uint8_t tk[16], const uint8_t r1[16],
    const uint8_t r2[16], uint8_t out[16])
{

	if (smp_legacy_crypto_hook != NULL &&
	    smp_legacy_crypto_hook("s1") != 0)
		return (-1);
	return (smp_s1(tk, r1, r2, out));
}

/*
 * LE Legacy Pairing — Responder path.
 * Core Spec Vol 3 Part H Section 2.3.5.5
 */
int
smp_respond_legacy(struct smp_conn *sc, const uint8_t preq[7],
    const uint8_t pres[7], const uint8_t tk[16])
{
	uint8_t sr[16], mr[16];
	uint8_t sc_val[16], mc[16], verify[16];
	uint8_t stk[16];
	uint8_t pdu[65];
	ssize_t n;
	uint8_t iat, rat;
	int ret = -1;

	/*
	 * Arm the single cumulative §3.4 deadline if not already armed by the
	 * smp_respond() caller; direct-call unit tests arm here.  This
	 * cumulative bound covers the whole legacy responder exchange:
	 * without it a peer answering just inside each per-message
	 * SO_RCVTIMEO could hold the session far past 30 s.
	 */
	smp_pairing_arm(sc);

	/* iat = initiator (remote), rat = responder (us) */
	iat = (sc->remote_addr_type == BDADDR_LE_RANDOM) ?
	    SMP_ID_ADDR_STATIC_RANDOM : SMP_ID_ADDR_PUBLIC;
	rat = (sc->local_addr_type == BDADDR_LE_RANDOM) ?
	    SMP_ID_ADDR_STATIC_RANDOM : SMP_ID_ADDR_PUBLIC;
	/*
	 * Direct unit tests call this sub-flow with hand-built feature PDUs,
	 * bypassing smp_respond()'s Phase 1 negotiation.  The negotiated key
	 * size is fully determined by those PDUs (Vol 3 Part H §2.3.4), so keep
	 * the legacy responder path self-contained and use the same value for
	 * STK/LTK masking and bond persistence.
	 */
	sc->neg_key_size = (preq[4] < pres[4]) ? preq[4] : pres[4];

	/* Receive initiator's Pairing Confirm */
	n = smp_recv_timed(sc, pdu, 17);
	if (n == SMP_RECV_TIMED_OUT)
		goto resp_legacy_cleanup;
	if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM) {
		/*
		 * §3.5.5 response policy for an unexpected receive:
		 *  - Pairing Failed from the peer: propagate as EACCES; the
		 *    exchange is already being torn down, do not answer it.
		 *  - A well-formed but out-of-sequence PDU (full 17-octet
		 *    length, some other known opcode): reply with Pairing
		 *    Failed (Unspecified Reason) so the peer learns the
		 *    exchange is dead instead of waiting out the 30 s SMP
		 *    timeout (§3.4).  This is the interoperable choice.
		 *  - A truncated PDU (n < 17): dropped SILENTLY.  Its contents
		 *    cannot be trusted, and §3.5.5 does not mandate a response
		 *    to malformed input; answering garbage risks amplifying a
		 *    confused or hostile peer.
		 */
		if (n > 0 && pdu[0] == SMP_PAIRING_FAILED) {
			errno = EACCES;
		} else {
			if (n >= 17) {
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
				smp_log_send(sc, pdu, 2);
			}
			errno = EPROTO;
		}
		goto resp_legacy_cleanup;
	}
	memcpy(mc, pdu + 1, 16);

	/* Generate our random and compute our confirm */
	smp_random(sr, sizeof(sr));
	if (smp_legacy_c1(tk, sr, preq, pres, iat, sc->remote_addr,
	    rat, sc->local_addr, sc_val, "c1-generate") < 0) {
		errno = EIO;
		goto resp_legacy_cleanup;
	}

	/* Send our Pairing Confirm */
	pdu[0] = SMP_PAIRING_CONFIRM;
	memcpy(pdu + 1, sc_val, 16);
	if (smp_log_send(sc, pdu, 17) < 0)
		goto resp_legacy_cleanup;
	LOG_SMP(2, "resp: legacy confirm exchange done");

	/* Receive initiator's Pairing Random */
	n = smp_recv_timed(sc, pdu, 17);
	if (n == SMP_RECV_TIMED_OUT)
		goto resp_legacy_cleanup;
	if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
		/* Same out-of-sequence policy as the Confirm receive above. */
		if (n > 0 && pdu[0] == SMP_PAIRING_FAILED) {
			errno = EACCES;
		} else {
			if (n >= 17) {
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_UNSPECIFIED_REASON;
				smp_log_send(sc, pdu, 2);
			}
			errno = EPROTO;
		}
		goto resp_legacy_cleanup;
	}
	memcpy(mr, pdu + 1, 16);

	/* Verify initiator's confirm */
	if (smp_legacy_c1(tk, mr, preq, pres, iat, sc->remote_addr,
	    rat, sc->local_addr, verify, "c1-verify") < 0) {
		errno = EIO;
		goto resp_legacy_cleanup;
	}
	if (timingsafe_bcmp(verify, mc, 16) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
		smp_log_send(sc, pdu, 2);
		errno = EACCES;
		goto resp_legacy_cleanup;
	}
	LOG_SMP(1, "resp: confirm verified");
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "confirm");

	/* Send our Pairing Random */
	pdu[0] = SMP_PAIRING_RANDOM;
	memcpy(pdu + 1, sr, 16);
	if (smp_log_send(sc, pdu, 17) < 0)
		goto resp_legacy_cleanup;

	/* Derive STK */
	if (smp_legacy_s1(tk, sr, mr, stk) < 0) {
		errno = EIO;
		goto resp_legacy_cleanup;
	}
	/*
	 * Mask the STK to the negotiated key size before it is used for
	 * encryption (Vol 3 Part H §2.3.4).
	 */
	smp_mask_key(stk, sc->neg_key_size);

	/* Respond to LTK Request with STK, then wait for encryption */
	if (hci_le_ltk_request_reply(sc->hci_fd, sc->con_handle, stk) < 0)
		goto resp_legacy_cleanup;
	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 10) < 0)
		goto resp_legacy_cleanup;
	LOG_SMP(1, "resp: encrypted, distributing keys");

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

	/* Distribute our keys (responder distributes first) */
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "key-dist");
	{
		struct smp_bond bond;
		uint8_t our_ltk[16];

		memset(&bond, 0, sizeof(bond));
		memcpy(bond.addr, sc->remote_addr, 6);
		bond.addr_type = sc->remote_addr_type;
		/* Persist the negotiated key size (Vol 3 Part H §2.3.4). */
		bond.key_size = sc->neg_key_size;
		/*
		 * Record the authentication level of this legacy bond.
		 * Legacy Passkey Entry and OOB are MITM-protected association
		 * models, yielding "Authenticated pairing with encryption"
		 * (LE security mode 1 level 3, Core Spec Vol 3 Part C §10.2.1;
		 * model mapping Vol 3 Part H Table 2.8/§2.3.5.1).  Just Works
		 * gives no MITM protection (level 2).  Recompute the negotiated
		 * model from preq/pres, matching smp_respond()'s selection: OOB
		 * (both sides advertised OOB) always reaches here authenticated,
		 * otherwise any non-Just-Works model requires MITM.
		 */
		bond.is_mitm = (preq[2] != 0 && pres[2] != 0) ||
		    (((preq[3] & SMP_AUTH_MITM) || (pres[3] & SMP_AUTH_MITM)) &&
		    smp_select_model(preq[1], pres[1], false) !=
		    SMP_MODEL_JUST_WORKS);

		smp_random(our_ltk, sizeof(our_ltk));
		/*
		 * Mask the LTK to the negotiated key size before it is
		 * distributed or stored (Vol 3 Part H §2.3.4).
		 */
		smp_mask_key(our_ltk, sc->neg_key_size);
		smp_random((uint8_t *)&bond.rand, 8);
		bond.ediv = arc4random() & 0xFFFF;
		memcpy(bond.ltk, our_ltk, 16);
		bond.has_ltk = true;

		if (pres[6] & SMP_KEY_DIST_ENC_KEY) {
			pdu[0] = SMP_ENCRYPTION_INFORMATION;
			memcpy(pdu + 1, our_ltk, 16);
			if (smp_log_send(sc, pdu, 17) != 17) {
				ret = -1;
				goto resp_legacy_cleanup;
			}

			pdu[0] = SMP_CENTRAL_IDENTIFICATION;
			put_le16(pdu + 1, bond.ediv);
			memcpy(pdu + 3, &bond.rand, 8);
			if (smp_log_send(sc, pdu, 11) != 11) {
				ret = -1;
				goto resp_legacy_cleanup;
			}
		}

		/* Distribute IdKey (IRK + Identity Address) if negotiated */
		if (pres[6] & SMP_KEY_DIST_ID_KEY) {
			/*
			 * Guard on bond_db != NULL (K-low ID-key NULL deref):
			 * without a bond DB there is no local IRK and the
			 * local_irk deref below would fault.
			 */
			/* Send Identity Information (IRK). */
			if (sc->bond_db == NULL ||
			    smp_ensure_local_irk(sc->bond_db) != 0) {
				ret = -1;
				goto resp_legacy_cleanup;
			}
			pdu[0] = SMP_IDENTITY_INFORMATION;
			memcpy(pdu + 1, sc->bond_db->local_irk, 16);
			if (smp_log_send(sc, pdu, 17) != 17) {
				ret = -1;
				goto resp_legacy_cleanup;
			}

			/* Send Identity Address Information */
			pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
			pdu[1] = (sc->local_addr_type == BDADDR_LE_RANDOM) ?
			    SMP_ID_ADDR_STATIC_RANDOM : SMP_ID_ADDR_PUBLIC;
			memcpy(pdu + 2, sc->local_addr, 6);
			if (smp_log_send(sc, pdu, 8) != 8) {
				ret = -1;
				goto resp_legacy_cleanup;
			}
		}

		/* Distribute SignKey (CSRK) if negotiated */
		if (pres[6] & SMP_KEY_DIST_LEGACY_SIGN_KEY) {
			if (smp_ensure_local_csrk(sc->bond_db) != 0) {
				ret = -1;
				goto resp_legacy_cleanup;
			}
			pdu[0] = SMP_LEGACY_SIGNING_INFORMATION;
			memcpy(pdu + 1, sc->bond_db->local_csrk, 16);
			if (smp_log_send(sc, pdu, 17) != 17) {
				ret = -1;
				goto resp_legacy_cleanup;
			}
		}

		/* Receive initiator's keys based on negotiated
		 * Initiator Key Distribution (pres[5]) */
		if (smp_receive_peer_keys(sc, &bond, pres[5], false) != 0) {
			explicit_bzero(our_ltk, sizeof(our_ltk));
			explicit_bzero(&bond, sizeof(bond));
			ret = -1;
			goto resp_legacy_cleanup;
		}

		/* Legacy pairing cannot negotiate the Core 6.3 LinkKey bit. */

		/*
		 * Persist only if BOTH sides requested Bonding (Core Spec Vol 3
		 * Part H §3.5.1 / §2.3.5.1); a No-Bonding peer's keys stay
		 * session-only.
		 */
		if (preq[3] & pres[3] & SMP_AUTH_BONDING) {
			if (smp_bond_db_store(sc->bond_db, &bond) != 0) {
				explicit_bzero(our_ltk, sizeof(our_ltk));
				explicit_bzero(&bond, sizeof(bond));
				ret = -1;
				goto resp_legacy_cleanup;
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
		    0, (preq[3] & pres[3] & SMP_AUTH_BONDING) ? bond.has_ltk : 0);
		explicit_bzero(our_ltk, sizeof(our_ltk));
		explicit_bzero(&bond, sizeof(bond));
	}

	ret = 0;

resp_legacy_cleanup:
	BLUED_PROBE_SMP_PAIR_DONE(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL), ret);
	if (ret != 0)
		BLUED_LOG_SECURITY("pairing failed "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x reason=%02x",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    (unsigned)errno);
	explicit_bzero(sr, sizeof(sr));
	explicit_bzero(mr, sizeof(mr));
	explicit_bzero(stk, sizeof(stk));
	return (ret);
}
