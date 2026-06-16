/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * SMP (Security Manager Protocol) for LE pairing.
 *
 * Implements LE Legacy Pairing with "Just Works" and passkey entry methods.
 * Runs over L2CAP CID 0x0006.  Key distribution stores LTK and IRK.
 *
 * Crypto uses the c1 confirm generation function and s1 key generation
 * function per Core Spec Vol 3 Part H Section 2.2.3-2.2.4.
 *
 * Encryption is triggered via HCI LE_Start_Encryption on the raw HCI socket.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/endian.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <err.h>
#include <errno.h>
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

#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>

#include "ble_util.h"
#include "hci_util.h"
#include "smp.h"

/* HCI LE_Start_Encryption opcode */
#define HCI_OP_LE_START_ENCRYPTION \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_START_ENCRYPTION)

/* Association model */
#define SMP_MODEL_JUST_WORKS		0
#define SMP_MODEL_PASSKEY_ENTRY		1
#define SMP_MODEL_NUMERIC_COMPARISON	2

/* Forward declarations */
static int smp_pair_sc(struct smp_conn *, const uint8_t[7], const uint8_t[7],
    int model);
static int smp_pair_sc_passkey(struct smp_conn *, const uint8_t[7],
    const uint8_t[7]);
static void smp_pack_addr(uint8_t[7], const uint8_t[6], uint8_t);
static void smp_f4(const uint8_t[32], const uint8_t[32], const uint8_t[16],
    uint8_t, uint8_t[16]);
static void smp_f5(const uint8_t[32], const uint8_t[16], const uint8_t[16],
    const uint8_t[7], const uint8_t[7], uint8_t[16], uint8_t[16]);
static void smp_f6(const uint8_t[16], const uint8_t[16], const uint8_t[16],
    const uint8_t[16], const uint8_t[3], const uint8_t[7], const uint8_t[7],
    uint8_t[16]);
static void swap_buf(uint8_t *, const uint8_t *, size_t);
static int smp_validate_public_key(const uint8_t *, const uint8_t *);

/*
 * Determine association model from IO capabilities.
 * Core Spec Vol 3 Part H Table 2.8
 */
static int
smp_select_model(uint8_t init_io, uint8_t resp_io, bool sc)
{
	/* Table 2.8 mapping (initiator rows, responder columns) */
	static const uint8_t legacy_table[5][5] = {
		/* Resp: DispOnly  DispYN    KbdOnly   NoIO      KbdDisp */
	/* I:DispOnly */ { 0,      0,        1,        0,        1       },
	/* I:DispYN   */ { 0,      0,        1,        0,        1       },
	/* I:KbdOnly  */ { 1,      1,        1,        0,        1       },
	/* I:NoIO     */ { 0,      0,        0,        0,        0       },
	/* I:KbdDisp  */ { 1,      1,        1,        0,        1       },
	};
	static const uint8_t sc_table[5][5] = {
		/* Resp: DispOnly  DispYN    KbdOnly   NoIO      KbdDisp */
	/* I:DispOnly */ { 0,      0,        1,        0,        1       },
	/* I:DispYN   */ { 0,      2,        1,        0,        2       },
	/* I:KbdOnly  */ { 1,      1,        1,        0,        1       },
	/* I:NoIO     */ { 0,      0,        0,        0,        0       },
	/* I:KbdDisp  */ { 1,      2,        1,        0,        2       },
	};

	if (init_io > 4 || resp_io > 4)
		return (SMP_MODEL_JUST_WORKS);

	return (sc ? sc_table[init_io][resp_io] :
	    legacy_table[init_io][resp_io]);
}

/*
 * AES-128 encrypt: E(key, plaintext) -> ciphertext.
 * Used by c1() and s1() functions.
 * Core Spec Vol 3 Part H Section 2.2.1
 */
static void
smp_aes128(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
	EVP_CIPHER_CTX *ctx;
	uint8_t k[16], p[16];
	int outl;

	/*
	 * SMP uses big-endian key/data ordering internally,
	 * but protocol PDUs are little-endian.  Reverse for AES.
	 */
	for (int i = 0; i < 16; i++) {
		k[i] = key[15 - i];
		p[i] = in[15 - i];
	}

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		warnx("EVP_CIPHER_CTX_new failed");
		memset(out, 0, 16);
		return;
	}
	EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, k, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_EncryptUpdate(ctx, out, &outl, p, 16);
	EVP_CIPHER_CTX_free(ctx);

	/* Reverse output back to little-endian */
	for (int i = 0; i < 8; i++) {
		uint8_t tmp = out[i];
		out[i] = out[15 - i];
		out[15 - i] = tmp;
	}
}

/*
 * c1 confirm value generation function.
 * Core Spec Vol 3 Part H Section 2.2.3
 *
 * c1(k, r, preq, pres, iat, ia, rat, ra) = E(k, E(k, r XOR p1) XOR p2)
 *   p1 = pres || preq || rat || iat
 *   p2 = padding || ia || ra
 */
static void
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
	smp_aes128(k, tmp, tmp);

	/* tmp = tmp XOR p2 */
	for (i = 0; i < 16; i++)
		tmp[i] = tmp[i] ^ p2[i];

	/* confirm = E(k, tmp) */
	smp_aes128(k, tmp, confirm);
}

/*
 * s1 key generation function.
 * Core Spec Vol 3 Part H Section 2.2.4
 *
 * s1(k, r1, r2) = E(k, r2' || r1')
 *   r1' = lower 8 bytes of r1
 *   r2' = lower 8 bytes of r2
 */
static void
smp_s1(const uint8_t k[16], const uint8_t r1[16], const uint8_t r2[16],
    uint8_t stk[16])
{
	uint8_t r[16];

	memcpy(r, r2, 8);	/* r2' in lower half */
	memcpy(r + 8, r1, 8);	/* r1' in upper half */

	smp_aes128(k, r, stk);
}

/*
 * Generate 16 random bytes using /dev/urandom.
 */
static int
smp_random(uint8_t *buf, size_t len)
{
	/* arc4random_buf is always available on FreeBSD */
	arc4random_buf(buf, len);
	return (0);
}

/*
 * Open SMP connection to a BLE device.
 */
/*
 * Send an HCI command via the raw HCI socket.
 *
 * Raw HCI socket expects: [type(1), opcode(2), param_len(1), params...]
 * where type = 0x01 for HCI command packets.
 */
static int
hci_send_cmd(int hci_fd, uint16_t opcode, const void *params, uint8_t plen)
{
	uint8_t pkt[260];	/* max HCI command: 4 + 255 */

	if (plen > 255)
		return (-1);

	pkt[0] = 0x01;			/* HCI command packet type */
	pkt[1] = opcode & 0xFF;
	pkt[2] = (opcode >> 8) & 0xFF;
	pkt[3] = plen;
	if (plen > 0)
		memcpy(pkt + 4, params, plen);

	if (send(hci_fd, pkt, 4 + plen, 0) < 0)
		return (-1);

	return (0);
}

int
smp_open(struct smp_conn *sc, const uint8_t *addr, uint8_t addr_type,
    const uint8_t *local_addr, uint8_t local_addr_type,
    int hci_fd, uint16_t con_handle, struct smp_bond_db *db)
{
	struct sockaddr_l2cap sa;

	memset(sc, 0, sizeof(*sc));
	sc->fd = -1;
	sc->hci_fd = hci_fd;
	sc->con_handle = con_handle;
	sc->remote_addr_type = addr_type;
	sc->bond_db = db;
	memcpy(sc->remote_addr, addr, 6);
	memcpy(sc->local_addr, local_addr, 6);
	sc->local_addr_type = local_addr_type;

	sc->fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BLUETOOTH_PROTO_L2CAP);
	if (sc->fd < 0)
		return (-1);

	memset(&sa, 0, sizeof(sa));
	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;

	if (bind(sc->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(sc->fd);
		sc->fd = -1;
		return (-1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;
	memcpy(&sa.l2cap_bdaddr, addr, sizeof(sa.l2cap_bdaddr));
	sa.l2cap_cid = NG_L2CAP_SMP_CID;
	sa.l2cap_bdaddr_type = addr_type;

	if (connect(sc->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(sc->fd);
		sc->fd = -1;
		return (-1);
	}

	/* SMP timeout: 30 seconds per spec (Vol 3 Part H Section 3.4) */
	{
		struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
		setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}

	return (0);
}

void
smp_close(struct smp_conn *sc)
{
	if (sc->fd >= 0) {
		close(sc->fd);
		sc->fd = -1;
	}
}

/*
 * LE Legacy Pairing — "Just Works" method.
 *
 * Sequence:
 *  1. Send Pairing Request
 *  2. Receive Pairing Response
 *  3. Generate random, compute confirm using TK=0
 *  4. Exchange Pairing Confirm
 *  5. Exchange Pairing Random
 *  6. Verify confirm values
 *  7. Derive STK = s1(TK, Srand, Mrand)
 *  8. Start encryption via HCI LE_Start_Encryption
 *  9. Receive key distribution (LTK, IRK)
 */
/*
 * Store or update a bond in the database.
 * If a bond for this device already exists, update it in place.
 * Otherwise append a new entry.
 */
static void
smp_bond_db_store(struct smp_bond_db *db, const struct smp_bond *bond)
{

	if (db == NULL)
		return;

	/* Update existing bond for this device if present */
	for (int i = 0; i < db->count; i++) {
		if (db->bonds[i].addr_type == bond->addr_type &&
		    memcmp(db->bonds[i].addr, bond->addr, 6) == 0) {
			db->bonds[i] = *bond;
			smp_bond_db_save(db);
			return;
		}
	}

	/* Append new bond */
	if (db->count < SMP_MAX_BONDS) {
		db->bonds[db->count++] = *bond;
		smp_bond_db_save(db);
	}
}

int
smp_pair(struct smp_conn *sc)
{
	uint8_t preq[7], pres[7];
	uint8_t tk[16];		/* Temporary Key — 0 for Just Works */
	uint8_t mrand[16];	/* Our random */
	uint8_t srand[16];	/* Peer random */
	uint8_t mconfirm[16], sconfirm[16], verify[16];
	uint8_t stk[16];
	uint8_t pdu[65];
	ssize_t n;
	uint8_t iat, rat;

	memset(tk, 0, sizeof(tk));

	/* SMP address types: 0=public, 1=random */
	iat = (sc->local_addr_type == BDADDR_LE_RANDOM) ? 1 : 0;
	rat = (sc->remote_addr_type == BDADDR_LE_RANDOM) ? 1 : 0;

	/*
	 * Step 1: Send Pairing Request
	 * Format: [opcode, IO cap, OOB, AuthReq, max_key_size,
	 *          init_key_dist, resp_key_dist]
	 */
	preq[0] = SMP_PAIRING_REQUEST;
	preq[1] = SMP_IO_KEYBOARD_DISPLAY;	/* Can input and display */
	preq[2] = 0x00;			/* No OOB */
	preq[3] = SMP_AUTH_BONDING | SMP_AUTH_MITM | SMP_AUTH_SC;
	preq[4] = 16;				/* Max encryption key size */
	preq[5] = 0;				/* We don't distribute keys */
	preq[6] = SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY;

	if (send(sc->fd, preq, sizeof(preq), 0) < 0)
		return (-1);
	LOG_SMP(1, "pairing request sent IO=%d auth=%02x", preq[1], preq[3]);

	/*
	 * Step 2: Receive Pairing Response
	 */
	n = recv(sc->fd, pres, sizeof(pres), 0);
	if (n < 7) {
		errno = EPROTO;
		return (-1);
	}

	if (pres[0] == SMP_PAIRING_FAILED) {
		warnx("SMP: peer sent pairing failed reason=%02x", pres[1]);
		errno = EACCES;
		return (-1);
	}

	if (pres[0] != SMP_PAIRING_RESPONSE) {
		errno = EPROTO;
		return (-1);
	}
	LOG_SMP(1, "pairing response IO=%d auth=%02x", pres[1], pres[3]);

	/*
	 * Validate encryption key size (Core Spec Vol 3 Part H 3.6.1).
	 * Max_Encryption_Key_Size must be in range [7,16].
	 * Negotiated size = min(ours, theirs); reject if < 7.
	 */
	{
		uint8_t peer_key_sz = pres[4];
		uint8_t neg_key_sz;

		if (peer_key_sz < 7 || peer_key_sz > 16) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_INVALID_PARAMETERS;
			send(sc->fd, pdu, 2, 0);
			errno = EPROTO;
			return (-1);
		}
		neg_key_sz = (preq[4] < peer_key_sz) ? preq[4] : peer_key_sz;
		if (neg_key_sz < 7) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_ENCRYPTION_KEY_SIZE;
			send(sc->fd, pdu, 2, 0);
			errno = EACCES;
			return (-1);
		}
	}

	/*
	 * Determine association model and dispatch.
	 */
	{
		bool use_sc = (preq[3] & SMP_AUTH_SC) &&
		    (pres[3] & SMP_AUTH_SC);
		bool use_mitm = (preq[3] & SMP_AUTH_MITM) ||
		    (pres[3] & SMP_AUTH_MITM);
		int model;

		if (!use_mitm)
			model = SMP_MODEL_JUST_WORKS;
		else
			model = smp_select_model(preq[1], pres[1], use_sc);
		LOG_SMP(1, "model=%d sc=%d", model, use_sc);

		if (use_sc) {
			if (model == SMP_MODEL_PASSKEY_ENTRY)
				return (smp_pair_sc_passkey(sc, preq, pres));
			return (smp_pair_sc(sc, preq, pres, model));
		}

		/* Legacy Passkey Entry: TK = passkey value */
		if (model == SMP_MODEL_PASSKEY_ENTRY) {
			uint32_t passkey = 0;

			if (sc->passkey_cb == NULL) {
				errno = ENOTSUP;
				return (-1);
			}
			/* Display passkey and ask user to confirm on device */
			passkey = arc4random_uniform(1000000);
			if (sc->passkey_cb(&passkey, true,
			    sc->passkey_cb_arg) < 0) {
				uint8_t fail[2] = { SMP_PAIRING_FAILED,
				    SMP_ERR_PASSKEY_ENTRY_FAILED };
				send(sc->fd, fail, 2, 0);
				errno = ECANCELED;
				return (-1);
			}
			/* TK = passkey as 128-bit LE integer */
			memset(tk, 0, sizeof(tk));
			tk[0] = passkey & 0xFF;
			tk[1] = (passkey >> 8) & 0xFF;
			tk[2] = (passkey >> 16) & 0xFF;
			/* Fall through to legacy c1/s1 with this TK */
		}
	}

	/*
	 * LE Legacy Pairing (Just Works or Passkey Entry).
	 * TK is already set: 0 for Just Works, passkey for Passkey Entry.
	 * Step 3: Generate our random and compute confirm value
	 */
	smp_random(mrand, sizeof(mrand));
	smp_c1(tk, mrand, preq, pres, iat, sc->local_addr,
	    rat, sc->remote_addr, mconfirm);

	/*
	 * Step 4: Send Pairing Confirm
	 */
	pdu[0] = SMP_PAIRING_CONFIRM;
	memcpy(pdu + 1, mconfirm, 16);
	if (send(sc->fd, pdu, 17, 0) < 0)
		return (-1);
	LOG_SMP(2, "legacy confirm sent");

	/*
	 * Receive Pairing Confirm from responder
	 */
	n = recv(sc->fd, pdu, 17, 0);
	if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM) {
		if (n > 0 && pdu[0] == SMP_PAIRING_FAILED) {
			errno = EACCES;
			return (-1);
		}
		errno = EPROTO;
		return (-1);
	}
	memcpy(sconfirm, pdu + 1, 16);

	/*
	 * Step 5: Send Pairing Random
	 */
	pdu[0] = SMP_PAIRING_RANDOM;
	memcpy(pdu + 1, mrand, 16);
	if (send(sc->fd, pdu, 17, 0) < 0)
		return (-1);

	/*
	 * Receive Pairing Random from responder
	 */
	n = recv(sc->fd, pdu, 17, 0);
	if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
		if (n > 0 && pdu[0] == SMP_PAIRING_FAILED) {
			errno = EACCES;
			return (-1);
		}
		errno = EPROTO;
		return (-1);
	}
	memcpy(srand, pdu + 1, 16);

	/*
	 * Step 6: Verify responder's confirm value
	 */
	smp_c1(tk, srand, preq, pres, iat, sc->local_addr,
	    rat, sc->remote_addr, verify);
	if (memcmp(verify, sconfirm, 16) != 0) {
		/* Send Pairing Failed */
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
		send(sc->fd, pdu, 2, 0);
		errno = EACCES;
		return (-1);
	}
	LOG_SMP(1, "legacy confirm verified");

	/*
	 * Step 7: Derive STK
	 */
	smp_s1(tk, srand, mrand, stk);
	LOG_SMP(1, "STK derived, starting encryption");
	btled_hexdump("SMP", "s1 output (STK)", stk, 16);

	/*
	 * Step 8: Start encryption via HCI LE_Start_Encryption
	 *
	 * HCI command format:
	 *   [opcode_lo, opcode_hi, param_len,
	 *    handle_lo, handle_hi,
	 *    random(8), ediv(2), ltk(16)]
	 *
	 * For STK: random=0, ediv=0
	 */
	{
		uint8_t params[28];

		params[0] = sc->con_handle & 0xFF;
		params[1] = (sc->con_handle >> 8) & 0xFF;
		memset(params + 2, 0, 8);	/* random = 0 */
		memset(params + 10, 0, 2);	/* EDIV = 0 */
		memcpy(params + 12, stk, 16);	/* STK as LTK */

		if (hci_send_cmd(sc->hci_fd, HCI_OP_LE_START_ENCRYPTION, params,
		    sizeof(params)) < 0)
			return (-1);
	}

	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 5) < 0)
		return (-1);

	/*
	 * Step 9: Receive key distribution from responder
	 *
	 * Expected: Encryption Information (LTK) + Master Identification
	 *           Identity Information (IRK) + Identity Address
	 */
	{
		struct smp_bond bond;
		memset(&bond, 0, sizeof(bond));
		memcpy(bond.addr, sc->remote_addr, 6);
		bond.addr_type = sc->remote_addr_type;

		/* Set receive timeout for key distribution */
		{
			struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
			setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
		}

		/*
		 * Count expected key distribution PDUs from the
		 * negotiated Responder Key Distribution field (pres[6]).
		 * EncKey = 2 PDUs (Encryption Info + Master ID),
		 * IdKey = 2 PDUs (Identity Info + Identity Addr).
		 * This avoids blocking for the full timeout when the
		 * responder has no keys to distribute.
		 */
		int expected_pdus = 0;
		if (pres[6] & SMP_KEY_DIST_ENC_KEY)
			expected_pdus += 2;
		if (pres[6] & SMP_KEY_DIST_ID_KEY)
			expected_pdus += 2;

		for (int i = 0; i < expected_pdus; i++) {
			n = recv(sc->fd, pdu, sizeof(pdu), 0);
			if (n < 1)
				break;

			switch (pdu[0]) {
			case SMP_ENCRYPTION_INFORMATION:
				if (n >= 17) {
					memcpy(bond.ltk, pdu + 1, 16);
					bond.has_ltk = true;
				}
				break;
			case SMP_MASTER_IDENTIFICATION:
				if (n >= 11) {
					memcpy(&bond.ediv, pdu + 1, 2);
					memcpy(&bond.rand, pdu + 3, 8);
				}
				break;
			case SMP_IDENTITY_INFORMATION:
				if (n >= 17) {
					memcpy(bond.irk, pdu + 1, 16);
					bond.has_irk = true;
				}
				break;
			case SMP_IDENTITY_ADDRESS_INFO:
				if (n >= 8) {
					bond.addr_type = pdu[1];
					memcpy(bond.addr, pdu + 2, 6);
				}
				break;
			default:
				break;
			}
		}

		/* Store bond */
		if (bond.has_ltk) {
			smp_bond_db_store(sc->bond_db, &bond);
			LOG_SMP(1, "bond stored");
		}
	}

	return (0);
}

/*
 * Encrypt a connection using a previously bonded LTK.
 */
int
smp_encrypt_with_ltk(struct smp_conn *sc, const struct smp_bond *bond)
{
	uint8_t params[28];

	LOG_SMP(1, "encrypting with stored LTK");

	if (!bond->has_ltk) {
		errno = ENOENT;
		return (-1);
	}

	params[0] = sc->con_handle & 0xFF;
	params[1] = (sc->con_handle >> 8) & 0xFF;
	memcpy(params + 2, &bond->rand, 8);
	memcpy(params + 10, &bond->ediv, 2);
	memcpy(params + 12, bond->ltk, 16);

	if (hci_send_cmd(sc->hci_fd, HCI_OP_LE_START_ENCRYPTION, params, sizeof(params)) < 0)
		return (-1);

	return (0);
}

/*
 * Resolve a Resolvable Private Address (RPA) against an IRK.
 *
 * An RPA is a random address where the upper 2 bits of the MSB are 01.
 * Format: [prand(3) || hash(3)], total 6 bytes.
 * hash = ah(IRK, prand) = E(IRK, padding(13) || prand(3))[0..2]
 *
 * Core Spec Vol 3 Part H Section 2.2.2
 */
static bool
smp_rpa_matches(const uint8_t irk[16], const uint8_t addr[6])
{
	uint8_t prand[3], hash_expected[3];
	uint8_t plaintext[16], cipher[16];

	/* RPA: addr[5] has upper 2 bits = 01 */
	if ((addr[5] & 0xC0) != 0x40)
		return (false);

	/* prand is the upper 3 bytes (addr[3..5]) */
	prand[0] = addr[3];
	prand[1] = addr[4];
	prand[2] = addr[5];

	/* hash is the lower 3 bytes (addr[0..2]) */
	hash_expected[0] = addr[0];
	hash_expected[1] = addr[1];
	hash_expected[2] = addr[2];

	/*
	 * ah(k, r) = E(k, r') mod 2^24, where r' = padding || prand.
	 * "The least significant octet of r becomes the least significant
	 * octet of r'."  smp_aes128 expects LE input (byte[0]=LSB), so
	 * prand goes at bytes [0..2] and padding at bytes [3..15].
	 */
	memset(plaintext, 0, sizeof(plaintext));
	plaintext[0] = prand[0];
	plaintext[1] = prand[1];
	plaintext[2] = prand[2];

	smp_aes128(irk, plaintext, cipher);

	return (memcmp(cipher, hash_expected, 3) == 0);
}

/*
 * Find a bond by device address.
 *
 * First tries exact address match.  If the address is a Resolvable
 * Private Address (RPA) and no exact match is found, resolves against
 * each stored IRK per Core Spec Vol 3 Part H Section 2.2.2.
 */
struct smp_bond *
smp_find_bond(struct smp_bond_db *db, const uint8_t *addr, uint8_t addr_type)
{
	/* Exact match first */
	for (int i = 0; i < db->count; i++) {
		if (db->bonds[i].addr_type == addr_type &&
		    memcmp(db->bonds[i].addr, addr, 6) == 0) {
			LOG_SMP(1, "bond found (exact match)");
			return (&db->bonds[i]);
		}
	}

	/* Try IRK-based RPA resolution for random addresses */
	if (addr_type == BDADDR_LE_RANDOM) {
		for (int i = 0; i < db->count; i++) {
			if (db->bonds[i].has_irk &&
			    smp_rpa_matches(db->bonds[i].irk, addr)) {
				LOG_SMP(1, "bond found (IRK resolved)");
				return (&db->bonds[i]);
			}
		}
	}

	return (NULL);
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
static int
smp_pair_sc_passkey(struct smp_conn *sc, const uint8_t preq[7],
    const uint8_t pres[7])
{
	EVP_PKEY *our_key = NULL, *peer_key = NULL;
	EVP_PKEY_CTX *pctx;
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
	size_t dh_len;
	uint32_t passkey;
	uint8_t ra[16]; /* passkey as 128-bit for f6 */

	if (sc->passkey_cb == NULL) {
		errno = ENOTSUP;
		return (-1);
	}

	/* Generate passkey and display to user */
	passkey = arc4random_uniform(1000000);
	if (sc->passkey_cb(&passkey, true, sc->passkey_cb_arg) < 0) {
		uint8_t fail[2] = { SMP_PAIRING_FAILED,
		    SMP_ERR_PASSKEY_ENTRY_FAILED };
		send(sc->fd, fail, 2, 0);
		errno = ECANCELED;
		return (-1);
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
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pctx == NULL)
		return (-1);
	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
	if (EVP_PKEY_keygen(pctx, &our_key) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return (-1);
	}
	EVP_PKEY_CTX_free(pctx);

	{
		size_t pklen = sizeof(our_pk_raw);
		if (EVP_PKEY_get_octet_string_param(our_key,
		    OSSL_PKEY_PARAM_PUB_KEY, our_pk_raw,
		    sizeof(our_pk_raw), &pklen) <= 0) {
			EVP_PKEY_free(our_key);
			return (-1);
		}
	}

	/* Send our PK (OpenSSL BE -> wire LE) */
	pdu[0] = SMP_PAIRING_PUBLIC_KEY;
	swap_buf(pdu + 1, our_pk_raw + 1, 32);
	swap_buf(pdu + 33, our_pk_raw + 33, 32);
	/* Store x-coord in LE for crypto functions */
	memcpy(pka_le, pdu + 1, 32);
	if (send(sc->fd, pdu, 65, 0) < 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}

	/* Receive peer PK (wire = LE) */
	n = recv(sc->fd, pdu, 65, 0);
	if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY) {
		EVP_PKEY_free(our_key);
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	/* Convert peer PK to OpenSSL BE for ECDH */
	peer_pk_raw[0] = 0x04;
	swap_buf(peer_pk_raw + 1, pdu + 1, 32);
	swap_buf(peer_pk_raw + 33, pdu + 33, 32);
	/* Store x-coord in LE for crypto functions */
	memcpy(pkb_le, pdu + 1, 32);

	/* Validate peer public key is on P-256 curve (Core Spec 2.3.5.6.1) */
	if (smp_validate_public_key(peer_pk_raw + 1, peer_pk_raw + 33) != 0) {
		LOG_SMP(1, "SMP: peer public key not on P-256 curve, "
		    "failing pairing");
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		send(sc->fd, pdu, 2, 0);
		EVP_PKEY_free(our_key);
		return (-1);
	}
	LOG_SMP(2, "SC: public keys exchanged");

	/* Build peer EVP_PKEY and compute DHKey */
	{
		OSSL_PARAM params[3];
		EVP_PKEY_CTX *fctx;
		static char curve[] = "prime256v1";

		params[0] = OSSL_PARAM_construct_utf8_string(
		    OSSL_PKEY_PARAM_GROUP_NAME, curve, 0);
		params[1] = OSSL_PARAM_construct_octet_string(
		    OSSL_PKEY_PARAM_PUB_KEY, peer_pk_raw, 65);
		params[2] = OSSL_PARAM_construct_end();

		peer_key = NULL;
		fctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		EVP_PKEY_fromdata_init(fctx);
		EVP_PKEY_fromdata(fctx, &peer_key, EVP_PKEY_PUBLIC_KEY,
		    params);
		EVP_PKEY_CTX_free(fctx);
		if (peer_key == NULL) {
			EVP_PKEY_free(our_key);
			return (-1);
		}

		EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(our_key, NULL);
		EVP_PKEY_derive_init(dctx);
		EVP_PKEY_derive_set_peer(dctx, peer_key);
		{
			uint8_t dhkey_be[32];
			dh_len = sizeof(dhkey_be);
			if (EVP_PKEY_derive(dctx, dhkey_be, &dh_len) <= 0) {
				EVP_PKEY_CTX_free(dctx);
				EVP_PKEY_free(peer_key);
				EVP_PKEY_free(our_key);
				return (-1);
			}
			swap_buf(dhkey_le, dhkey_be, 32);
		}
		EVP_PKEY_CTX_free(dctx);
	}
	EVP_PKEY_free(peer_key);
	EVP_PKEY_free(our_key);
	LOG_SMP(2, "SC: DHKey computed");

	/*
	 * Authentication Stage 1: 20 rounds of Passkey Entry.
	 *
	 * For each bit i (0..19) of the passkey:
	 *   rai = 0x80 | ((passkey >> i) & 1)
	 *   Cai = f4(PKax, PKbx, Nai, rai) — initiator confirm
	 *   Cbi = f4(PKbx, PKax, Nbi, rbi) — responder confirm
	 *   Exchange: send Cai, recv Cbi, send Nai, recv Nbi, verify Cbi
	 */
	for (int i = 0; i < 20; i++) {
		uint8_t nai[16], nbi[16];
		uint8_t cai[16], cbi_recv[16], cbi_verify[16];
		uint8_t ri;

		if (i == 0 || i == 19)
			LOG_SMP(2, "SC passkey: round %d/20", i + 1);

		ri = 0x80 | ((passkey >> i) & 1);

		smp_random(nai, sizeof(nai));
		smp_f4(pka_le, pkb_le, nai, ri, cai);

		/* Send our confirm Cai */
		pdu[0] = SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, cai, 16);
		if (send(sc->fd, pdu, 17, 0) < 0)
			return (-1);

		/* Receive responder confirm Cbi */
		n = recv(sc->fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			return (-1);
		}
		memcpy(cbi_recv, pdu + 1, 16);

		/* Send our nonce Nai */
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, nai, 16);
		if (send(sc->fd, pdu, 17, 0) < 0)
			return (-1);

		/* Receive responder nonce Nbi */
		n = recv(sc->fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			return (-1);
		}
		memcpy(nbi, pdu + 1, 16);

		/* Verify Cbi = f4(PKbx, PKax, Nbi, rbi) */
		smp_f4(pkb_le, pka_le, nbi, ri, cbi_verify);
		if (memcmp(cbi_recv, cbi_verify, 16) != 0) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
			send(sc->fd, pdu, 2, 0);
			errno = EACCES;
			return (-1);
		}

		/* Keep last round's nonces for f5/f6 */
		memcpy(na, nai, 16);
		memcpy(nb, nbi, 16);
	}
	LOG_SMP(1, "SC passkey: 20 rounds complete");

	/*
	 * Authentication Stage 2: same as Just Works SC.
	 * MacKey || LTK = f5(DHKey, Na, Nb, A1, A2)
	 * Ea = f6(MacKey, Na, Nb, ra, IOcapA, A1, A2)
	 * Eb = f6(MacKey, Nb, Na, ra, IOcapB, A2, A1)
	 * (ra = rb = passkey for Passkey Entry per Table 2.2)
	 */
	smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
	btled_hexdump("SMP", "f5 output (LTK)", ltk, 16);

	smp_f6(mackey, na, nb, ra, iocap_a, a1, a2, ea);
	btled_hexdump("SMP", "f6 output (Ea)", ea, 16);
	smp_f6(mackey, nb, na, ra, iocap_b, a2, a1, eb);
	btled_hexdump("SMP", "f6 output (Eb)", eb, 16);

	/* Send Ea, receive and verify Eb */
	pdu[0] = SMP_PAIRING_DHKEY_CHECK;
	memcpy(pdu + 1, ea, 16);
	if (send(sc->fd, pdu, 17, 0) < 0)
		return (-1);

	n = recv(sc->fd, pdu, 17, 0);
	if (n < 17 || pdu[0] != SMP_PAIRING_DHKEY_CHECK) {
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	if (memcmp(pdu + 1, eb, 16) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		send(sc->fd, pdu, 2, 0);
		errno = EACCES;
		return (-1);
	}

	/* Start encryption */
	{
		uint8_t params[28];
		params[0] = sc->con_handle & 0xFF;
		params[1] = (sc->con_handle >> 8) & 0xFF;
		memset(params + 2, 0, 10);
		memcpy(params + 12, ltk, 16);
		if (hci_send_cmd(sc->hci_fd, HCI_OP_LE_START_ENCRYPTION, params,
		    sizeof(params)) < 0)
			return (-1);
	}

	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 5) < 0)
		return (-1);

	/* Store bond */
	{
		struct smp_bond bond;
		memset(&bond, 0, sizeof(bond));
		memcpy(bond.addr, sc->remote_addr, 6);
		bond.addr_type = sc->remote_addr_type;
		memcpy(bond.ltk, ltk, 16);
		bond.has_ltk = true;
		bond.is_sc = true;

		/* Receive key distribution from responder.
		 * SC ignores EncKey; only IdKey applies. */
		{
			int exp = 0;
			if (pres[6] & SMP_KEY_DIST_ID_KEY) exp += 2;
			for (int i = 0; i < exp; i++) {
				struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
				setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
				    &tv, sizeof(tv));
				n = recv(sc->fd, pdu, sizeof(pdu), 0);
				if (n < 1)
					break;
				if (pdu[0] == SMP_IDENTITY_INFORMATION && n >= 17) {
					memcpy(bond.irk, pdu + 1, 16);
					bond.has_irk = true;
				} else if (pdu[0] == SMP_IDENTITY_ADDRESS_INFO &&
				    n >= 8) {
					bond.addr_type = (pdu[1] == 0x01) ?
					    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
					memcpy(bond.addr, pdu + 2, 6);
				}
			}
		}

		smp_bond_db_store(sc->bond_db, &bond);
	}

	return (0);
}

/*
 * Load bond database from file descriptor.
 * Format: raw array of struct smp_bond.
 */
int
smp_bond_db_load(struct smp_bond_db *db, int fd)
{
	ssize_t n;

	db->fd = fd;
	db->count = 0;

	flock(fd, LOCK_EX);
	n = pread(fd, db->bonds, sizeof(db->bonds), 0);
	flock(fd, LOCK_UN);
	if (n < 0)
		return (-1);

	if ((n % sizeof(struct smp_bond)) != 0) {
		db->count = 0;
		return (0);
	}
	db->count = n / sizeof(struct smp_bond);
	if (db->count > SMP_MAX_BONDS)
		db->count = SMP_MAX_BONDS;

	return (0);
}

/*
 * Save bond database to file descriptor.
 */
int
smp_bond_db_save(struct smp_bond_db *db)
{
	ssize_t n;
	size_t len;

	if (db->fd < 0)
		return (-1);

	flock(db->fd, LOCK_EX);
	len = db->count * sizeof(struct smp_bond);
	n = pwrite(db->fd, db->bonds, len, 0);
	ftruncate(db->fd, len);
	flock(db->fd, LOCK_UN);
	if (n < 0 || (size_t)n != len)
		return (-1);

	return (0);
}

/* ================================================================
 * LE Secure Connections crypto (Core Spec Vol 3 Part H Section 2.2)
 *
 * The SC crypto functions (f4, f5, f6, g2) operate on values in
 * big-endian (MSB-first) byte order per the spec.  SMP PDUs carry
 * values in little-endian (wire order).  Callers must convert
 * between wire order and crypto order using swap_buf().
 *
 * Unlike the legacy E() function, AES-CMAC is standard RFC 4493
 * and does NOT need the double byte-reversal that smp_aes128 does.
 * ================================================================ */

/*
 * Reverse a byte buffer in-place or into a destination.
 */
static void
swap_buf(uint8_t *dst, const uint8_t *src, size_t len)
{
	for (size_t i = 0; i < len; i++)
		dst[i] = src[len - 1 - i];
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
static int
smp_validate_public_key(const uint8_t *pk_x, const uint8_t *pk_y)
{
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	BIGNUM *x = NULL, *y = NULL;
	int ret = -1;

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
static void
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
		return;
	}
	ctx = EVP_MAC_CTX_new(cmac_type);
	if (ctx == NULL) {
		warnx("EVP_MAC_CTX_new failed");
		memset(mac, 0, 16);
		EVP_MAC_free(cmac_type);
		return;
	}
	params[0] = OSSL_PARAM_construct_utf8_string("cipher", cipher_name,
	    0);
	params[1] = OSSL_PARAM_construct_end();
	EVP_MAC_init(ctx, key, 16, params);
	EVP_MAC_update(ctx, msg, len);
	outlen = 16;
	EVP_MAC_final(ctx, mac, &outlen, 16);
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(cmac_type);
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
static void
smp_f4(const uint8_t u[32], const uint8_t v[32], const uint8_t x[16],
    uint8_t z, uint8_t out[16])
{
	uint8_t m[65], x_be[16], mac[16];

	swap_buf(m, u, 32);
	swap_buf(m + 32, v, 32);
	m[64] = z;
	swap_buf(x_be, x, 16);
	smp_aes_cmac(x_be, m, sizeof(m), mac);
	swap_buf(out, mac, 16);
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
 */
static void
smp_f5(const uint8_t w[32], const uint8_t n1[16], const uint8_t n2[16],
    const uint8_t a1[7], const uint8_t a2[7],
    uint8_t mackey[16], uint8_t ltk[16])
{
	static const uint8_t salt[16] = {
		0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38,
		0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x60, 0x83, 0xBE
	};
	static const uint8_t keyid[4] = { 0x62, 0x74, 0x6C, 0x65 };
	uint8_t t[16], w_be[32];
	uint8_t m[53], mac[16];

	swap_buf(w_be, w, 32);
	smp_aes_cmac(salt, w_be, 32, t);

	m[0] = 0;
	memcpy(m + 1, keyid, 4);
	swap_buf(m + 5, n1, 16);
	swap_buf(m + 21, n2, 16);
	swap_buf(m + 37, a1, 7);
	swap_buf(m + 44, a2, 7);
	m[51] = 0x01;
	m[52] = 0x00;

	smp_aes_cmac(t, m, sizeof(m), mac);
	swap_buf(mackey, mac, 16);
	m[0] = 1;
	smp_aes_cmac(t, m, sizeof(m), mac);
	swap_buf(ltk, mac, 16);
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
 */
static void
smp_f6(const uint8_t w[16], const uint8_t n1[16], const uint8_t n2[16],
    const uint8_t r[16], const uint8_t iocap[3],
    const uint8_t a1[7], const uint8_t a2[7],
    uint8_t out[16])
{
	uint8_t m[65], w_be[16], mac[16];

	swap_buf(w_be, w, 16);
	swap_buf(m, n1, 16);
	swap_buf(m + 16, n2, 16);
	swap_buf(m + 32, r, 16);
	swap_buf(m + 48, iocap, 3);
	swap_buf(m + 51, a1, 7);
	swap_buf(m + 58, a2, 7);
	smp_aes_cmac(w_be, m, sizeof(m), mac);
	swap_buf(out, mac, 16);
}

/*
 * g2: LE SC numeric comparison value.
 * Core Spec Vol 3 Part H Section 2.2.9
 *
 * g2(U, V, X, Y) = AES-CMAC_X(U || V || Y) mod 2^32
 * Returns 32-bit value; display as 6 least significant digits.
 *
 * All multi-byte inputs are in little-endian (wire) order.
 * Internally converted to big-endian for AES-CMAC per spec.
 */
static uint32_t
smp_g2(const uint8_t u[32], const uint8_t v[32],
    const uint8_t x[16], const uint8_t y[16])
{
	uint8_t m[80]; /* U(32)+V(32)+Y(16) */
	uint8_t x_be[16], mac[16];

	swap_buf(m, u, 32);
	swap_buf(m + 32, v, 32);
	swap_buf(m + 64, y, 16);
	swap_buf(x_be, x, 16);
	smp_aes_cmac(x_be, m, sizeof(m), mac);

	/* Least significant 32 bits of the big-endian 128-bit MAC */
	return ((uint32_t)mac[12] << 24 | (uint32_t)mac[13] << 16 |
	    (uint32_t)mac[14] << 8 | (uint32_t)mac[15]);
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
static void
smp_pack_addr(uint8_t out[7], const uint8_t addr[6], uint8_t addr_type)
{
	memcpy(out, addr, 6);
	out[6] = (addr_type == BDADDR_LE_RANDOM) ? 0x01 : 0x00;
}

/*
 * LE Secure Connections pairing — Just Works.
 * Called after Pairing Request/Response exchange when both sides
 * set SMP_AUTH_SC.
 *
 * Core Spec Vol 3 Part H Section 2.3.5.6
 */
static int
smp_pair_sc(struct smp_conn *sc, const uint8_t preq[7], const uint8_t pres[7],
    int model)
{
	EVP_PKEY *our_key = NULL, *peer_key = NULL;
	EVP_PKEY_CTX *pctx;
	uint8_t our_pk_raw[65], peer_pk_raw[65];
	uint8_t dhkey_le[32];
	uint8_t na[16], nb[16];
	uint8_t mackey[16], ltk[16];
	uint8_t ea[16], eb[16];
	uint8_t a1[7], a2[7];
	uint8_t iocap_a[3], iocap_b[3];
	uint8_t pdu[66];
	ssize_t n;
	size_t dh_len;

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
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pctx == NULL)
		return (-1);
	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
	if (EVP_PKEY_keygen(pctx, &our_key) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return (-1);
	}
	EVP_PKEY_CTX_free(pctx);

	/* Extract uncompressed public key */
	{
		size_t pklen = sizeof(our_pk_raw);
		if (EVP_PKEY_get_octet_string_param(our_key,
		    OSSL_PKEY_PARAM_PUB_KEY, our_pk_raw,
		    sizeof(our_pk_raw), &pklen) <= 0) {
			EVP_PKEY_free(our_key);
			return (-1);
		}
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
	swap_buf(pdu + 1, our_pk_raw + 1, 32);      /* x: BE -> LE */
	swap_buf(pdu + 33, our_pk_raw + 33, 32);     /* y: BE -> LE */
	memcpy(pka_le, pdu + 1, 32);                /* save LE x-coord */
	if (send(sc->fd, pdu, 65, 0) < 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}

	/* Receive peer's Public Key (wire = little-endian) */
	n = recv(sc->fd, pdu, 65, 0);
	if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY) {
		EVP_PKEY_free(our_key);
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	/* Convert peer PK to OpenSSL big-endian for ECDH */
	peer_pk_raw[0] = 0x04;
	swap_buf(peer_pk_raw + 1, pdu + 1, 32);      /* x: LE -> BE */
	swap_buf(peer_pk_raw + 33, pdu + 33, 32);    /* y: LE -> BE */
	memcpy(pkb_le, pdu + 1, 32);                /* save LE x-coord */

	/* Validate peer public key is on P-256 curve (Core Spec 2.3.5.6.1) */
	if (smp_validate_public_key(peer_pk_raw + 1, peer_pk_raw + 33) != 0) {
		LOG_SMP(1, "SMP: peer public key not on P-256 curve, "
		    "failing pairing");
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		send(sc->fd, pdu, 2, 0);
		EVP_PKEY_free(our_key);
		return (-1);
	}
	LOG_SMP(2, "SC: public keys exchanged");

	/* Reconstruct peer EVP_PKEY */
	{
		OSSL_PARAM params[3];
		EVP_PKEY_CTX *fctx;

		static char curve[] = "prime256v1";
		params[0] = OSSL_PARAM_construct_utf8_string(
		    OSSL_PKEY_PARAM_GROUP_NAME, curve, 0);
		params[1] = OSSL_PARAM_construct_octet_string(
		    OSSL_PKEY_PARAM_PUB_KEY, peer_pk_raw, 65);
		params[2] = OSSL_PARAM_construct_end();

		peer_key = NULL;
		fctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		EVP_PKEY_fromdata_init(fctx);
		EVP_PKEY_fromdata(fctx, &peer_key, EVP_PKEY_PUBLIC_KEY,
		    params);
		EVP_PKEY_CTX_free(fctx);

		if (peer_key == NULL) {
			EVP_PKEY_free(our_key);
			return (-1);
		}
	}

	/* Compute ECDH shared secret (DHKey) — convert BE to LE */
	{
		EVP_PKEY_CTX *dctx;
		uint8_t dhkey_be[32];

		dctx = EVP_PKEY_CTX_new(our_key, NULL);
		EVP_PKEY_derive_init(dctx);
		EVP_PKEY_derive_set_peer(dctx, peer_key);
		dh_len = sizeof(dhkey_be);
		if (EVP_PKEY_derive(dctx, dhkey_be, &dh_len) <= 0) {
			EVP_PKEY_CTX_free(dctx);
			EVP_PKEY_free(peer_key);
			EVP_PKEY_free(our_key);
			return (-1);
		}
		swap_buf(dhkey_le, dhkey_be, 32);
		EVP_PKEY_CTX_free(dctx);
	}

	EVP_PKEY_free(peer_key);
	EVP_PKEY_free(our_key);
	LOG_SMP(2, "SC: DHKey computed");

	/*
	 * Just Works SC Authentication Stage 1 (Section 2.3.5.6.2):
	 *
	 * The RESPONDER computes Cb = f4(PKbx, PKax, Nb, 0) and sends
	 * Pairing Confirm.  The INITIATOR does NOT send a confirm.
	 * Then nonces are exchanged.
	 *
	 * As initiator:
	 *  1. Receive Cb from responder
	 *  2. Generate Na, send Na
	 *  3. Receive Nb from responder
	 *  4. Verify Cb == f4(PKbx, PKax, Nb, 0)
	 *
	 * f4 inputs use the x-coordinate only (first 32 bytes of LE pk).
	 * f4 is defined with big-endian inputs, but since AES-CMAC is
	 * standard and the spec defines the concatenation order with
	 * MSB of U as MSB of message, we pass coordinates as-is in the
	 * byte order the spec expects.  The spec's test vectors confirm
	 * the inputs are NOT reversed per-byte — they're used as-is
	 * in the order written.
	 */
	uint8_t cb_recv[16]; /* responder's confirm */

	/* Receive responder's Pairing Confirm (Cb) */
	n = recv(sc->fd, pdu, 17, 0);
	if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM) {
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	memcpy(cb_recv, pdu + 1, 16);

	/* Generate and send our nonce (Na) */
	smp_random(na, sizeof(na));
	pdu[0] = SMP_PAIRING_RANDOM;
	memcpy(pdu + 1, na, 16);
	if (send(sc->fd, pdu, 17, 0) < 0)
		return (-1);

	/* Receive responder's nonce (Nb) */
	n = recv(sc->fd, pdu, 17, 0);
	if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	memcpy(nb, pdu + 1, 16);

	/* Verify Cb = f4(PKbx, PKax, Nb, 0) */
	{
		uint8_t cb_verify[16];
		smp_f4(pkb_le, pka_le, nb, 0, cb_verify);
		if (memcmp(cb_recv, cb_verify, 16) != 0) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
			send(sc->fd, pdu, 2, 0);
			errno = EACCES;
			return (-1);
		}
	}
	LOG_SMP(1, "SC: confirm verified");

	/*
	 * Numeric Comparison (Section 2.3.5.6.2 step 7):
	 * Both sides compute Va/Vb = g2(PKax, PKbx, Na, Nb) mod 10^6
	 * and display the 6-digit value for user confirmation.
	 */
	if (model == SMP_MODEL_NUMERIC_COMPARISON) {
		uint32_t confirm_val;

		confirm_val = smp_g2(pka_le, pkb_le, na, nb) % 1000000;
		LOG_SMP(1, "SC: numeric comparison %06u", confirm_val);

		if (sc->numcmp_cb == NULL) {
			errno = ENOTSUP;
			return (-1);
		}
		if (sc->numcmp_cb(confirm_val, sc->numcmp_cb_arg) < 0) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_NUMERIC_COMP_FAILED;
			send(sc->fd, pdu, 2, 0);
			errno = EACCES;
			return (-1);
		}
	}

	/* Compute MacKey and LTK */
	smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
	LOG_SMP(1, "SC: MacKey+LTK derived");
	btled_hexdump("SMP", "f5 output (LTK)", ltk, 16);

	/* Compute DHKey checks */
	{
		uint8_t r[16];
		memset(r, 0, sizeof(r));
		smp_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
		btled_hexdump("SMP", "f6 output (Ea)", ea, 16);
		smp_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);
		btled_hexdump("SMP", "f6 output (Eb)", eb, 16);
	}

	/* Send our DHKey Check (Ea) */
	pdu[0] = SMP_PAIRING_DHKEY_CHECK;
	memcpy(pdu + 1, ea, 16);
	if (send(sc->fd, pdu, 17, 0) < 0)
		return (-1);

	/* Receive peer's DHKey Check (Eb) */
	n = recv(sc->fd, pdu, 17, 0);
	if (n < 17 || pdu[0] != SMP_PAIRING_DHKEY_CHECK) {
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}

	if (memcmp(pdu + 1, eb, 16) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		send(sc->fd, pdu, 2, 0);
		errno = EACCES;
		return (-1);
	}
	LOG_SMP(1, "SC: DHKey check passed");

	/* Start encryption with SC-derived LTK (rand=0, ediv=0) */
	{
		uint8_t params[28];
		params[0] = sc->con_handle & 0xFF;
		params[1] = (sc->con_handle >> 8) & 0xFF;
		memset(params + 2, 0, 10);
		memcpy(params + 12, ltk, 16);
		if (hci_send_cmd(sc->hci_fd, HCI_OP_LE_START_ENCRYPTION, params,
		    sizeof(params)) < 0)
			return (-1);
	}

	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 5) < 0)
		return (-1);

	/* Store SC bond */
	{
		struct smp_bond bond;
		memset(&bond, 0, sizeof(bond));
		memcpy(bond.addr, sc->remote_addr, 6);
		bond.addr_type = sc->remote_addr_type;
		memcpy(bond.ltk, ltk, 16);
		bond.has_ltk = true;
		bond.is_sc = true;

		/* Receive key distribution from responder.
		 * SC ignores EncKey; only IdKey applies. */
		{
			int exp = 0;
			if (pres[6] & SMP_KEY_DIST_ID_KEY) exp += 2;
			for (int i = 0; i < exp; i++) {
				struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
				setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
				    &tv, sizeof(tv));
				n = recv(sc->fd, pdu, sizeof(pdu), 0);
				if (n < 1)
					break;
				if (pdu[0] == SMP_IDENTITY_INFORMATION && n >= 17) {
					memcpy(bond.irk, pdu + 1, 16);
					bond.has_irk = true;
				} else if (pdu[0] == SMP_IDENTITY_ADDRESS_INFO &&
				    n >= 8) {
					bond.addr_type = (pdu[1] == 0x01) ?
					    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
					memcpy(bond.addr, pdu + 2, 6);
				}
			}
		}

		smp_bond_db_store(sc->bond_db, &bond);
	}

	return (0);
} /* smp_pair_sc */

/* ----------------------------------------------------------------
 *  SMP Responder (Peripheral) Mode
 * ---------------------------------------------------------------- */

/*
 * Initialize an SMP connection from an already-accepted socket fd.
 */
int
smp_open_accepted(struct smp_conn *sc, int fd,
    const uint8_t *local_addr, uint8_t local_addr_type,
    const uint8_t *remote_addr, uint8_t remote_addr_type,
    int hci_fd, uint16_t con_handle, struct smp_bond_db *db)
{

	memset(sc, 0, sizeof(*sc));
	sc->fd = fd;
	sc->hci_fd = hci_fd;
	sc->con_handle = con_handle;
	sc->remote_addr_type = remote_addr_type;
	memcpy(sc->remote_addr, remote_addr, 6);
	memcpy(sc->local_addr, local_addr, 6);
	sc->local_addr_type = local_addr_type;
	sc->bond_db = db;

	/* SMP timeout: 30 seconds per spec (Vol 3 Part H Section 3.4) */
	{
		struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
		setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}

	return (0);
}

/*
 * LE Legacy Pairing — Responder path.
 * Core Spec Vol 3 Part H Section 2.3.5.5
 */
static int
smp_respond_legacy(struct smp_conn *sc, const uint8_t preq[7],
    const uint8_t pres[7], const uint8_t tk[16])
{
	uint8_t sr[16], mr[16];
	uint8_t sc_val[16], mc[16], verify[16];
	uint8_t stk[16];
	uint8_t pdu[65];
	ssize_t n;
	uint8_t iat, rat;

	/* iat = initiator (remote), rat = responder (us) */
	iat = (sc->remote_addr_type == BDADDR_LE_RANDOM) ? 1 : 0;
	rat = (sc->local_addr_type == BDADDR_LE_RANDOM) ? 1 : 0;

	/* Receive initiator's Pairing Confirm */
	n = recv(sc->fd, pdu, 17, 0);
	if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM) {
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	memcpy(mc, pdu + 1, 16);

	/* Generate our random and compute our confirm */
	smp_random(sr, sizeof(sr));
	smp_c1(tk, sr, preq, pres, iat, sc->remote_addr,
	    rat, sc->local_addr, sc_val);

	/* Send our Pairing Confirm */
	pdu[0] = SMP_PAIRING_CONFIRM;
	memcpy(pdu + 1, sc_val, 16);
	if (send(sc->fd, pdu, 17, 0) < 0)
		return (-1);
	LOG_SMP(2, "resp: legacy confirm exchange done");

	/* Receive initiator's Pairing Random */
	n = recv(sc->fd, pdu, 17, 0);
	if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	memcpy(mr, pdu + 1, 16);

	/* Verify initiator's confirm */
	smp_c1(tk, mr, preq, pres, iat, sc->remote_addr,
	    rat, sc->local_addr, verify);
	if (memcmp(verify, mc, 16) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
		send(sc->fd, pdu, 2, 0);
		errno = EACCES;
		return (-1);
	}
	LOG_SMP(1, "resp: confirm verified");

	/* Send our Pairing Random */
	pdu[0] = SMP_PAIRING_RANDOM;
	memcpy(pdu + 1, sr, 16);
	if (send(sc->fd, pdu, 17, 0) < 0)
		return (-1);

	/* Derive STK */
	smp_s1(tk, sr, mr, stk);

	/* Respond to LTK Request with STK, then wait for encryption */
	if (hci_le_ltk_request_reply(sc->hci_fd, sc->con_handle, stk) < 0)
		return (-1);
	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 10) < 0)
		return (-1);
	LOG_SMP(1, "resp: encrypted, distributing keys");

	/* Distribute our keys (responder distributes first) */
	{
		struct smp_bond bond;
		uint8_t our_ltk[16];

		memset(&bond, 0, sizeof(bond));
		memcpy(bond.addr, sc->remote_addr, 6);
		bond.addr_type = sc->remote_addr_type;

		smp_random(our_ltk, sizeof(our_ltk));
		smp_random((uint8_t *)&bond.rand, 8);
		bond.ediv = (uint16_t)arc4random();
		memcpy(bond.ltk, our_ltk, 16);
		bond.has_ltk = true;

		if (pres[6] & SMP_KEY_DIST_ENC_KEY) {
			pdu[0] = SMP_ENCRYPTION_INFORMATION;
			memcpy(pdu + 1, our_ltk, 16);
			send(sc->fd, pdu, 17, 0);

			pdu[0] = SMP_MASTER_IDENTIFICATION;
			memcpy(pdu + 1, &bond.ediv, 2);
			memcpy(pdu + 3, &bond.rand, 8);
			send(sc->fd, pdu, 11, 0);
		}

		/* Distribute IdKey (IRK + Identity Address) if negotiated */
		if (pres[6] & SMP_KEY_DIST_ID_KEY) {
			/* Send Identity Information (IRK).
			 * Use zero IRK = no privacy, public address. */
			pdu[0] = SMP_IDENTITY_INFORMATION;
			memset(pdu + 1, 0, 16);
			send(sc->fd, pdu, 17, 0);

			/* Send Identity Address Information */
			pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
			pdu[1] = (sc->local_addr_type == BDADDR_LE_RANDOM) ?
			    0x01 : 0x00;
			memcpy(pdu + 2, sc->local_addr, 6);
			send(sc->fd, pdu, 8, 0);
		}

		/* Receive initiator's keys based on negotiated
		 * Initiator Key Distribution (pres[5]) */
		{
			struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
			setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
		}
		{
		int exp = 0;
		if (pres[5] & SMP_KEY_DIST_ENC_KEY) exp += 2;
		if (pres[5] & SMP_KEY_DIST_ID_KEY) exp += 2;
		for (int i = 0; i < exp; i++) {
			n = recv(sc->fd, pdu, sizeof(pdu), 0);
			if (n < 1)
				break;
			if (pdu[0] == SMP_IDENTITY_INFORMATION && n >= 17) {
				memcpy(bond.irk, pdu + 1, 16);
				bond.has_irk = true;
			} else if (pdu[0] == SMP_IDENTITY_ADDRESS_INFO &&
			    n >= 8) {
				bond.addr_type = (pdu[1] == 0x01) ?
				    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
				memcpy(bond.addr, pdu + 2, 6);
			}
		}
		}

		smp_bond_db_store(sc->bond_db, &bond);
	}

	return (0);
}

/*
 * LE Secure Connections — Responder path (Just Works / Numeric Comparison).
 * Core Spec Vol 3 Part H Section 2.3.5.6
 */
static int
smp_respond_sc(struct smp_conn *sc, const uint8_t preq[7],
    const uint8_t pres[7], int model)
{
	EVP_PKEY *our_key = NULL, *peer_key = NULL;
	EVP_PKEY_CTX *pctx;
	uint8_t our_pk_raw[65], peer_pk_raw[65];
	uint8_t dhkey_le[32];
	uint8_t na[16], nb[16];
	uint8_t mackey[16], ltk[16];
	uint8_t ea[16], eb[16];
	uint8_t a1[7], a2[7];
	uint8_t iocap_a[3], iocap_b[3];
	uint8_t pdu[66];
	ssize_t n;
	size_t dh_len;
	uint8_t pka_le[32], pkb_le[32];	/* LE x-coords for crypto */

	/* a1 = initiator (remote), a2 = responder (us) */
	smp_pack_addr(a1, sc->remote_addr, sc->remote_addr_type);
	smp_pack_addr(a2, sc->local_addr, sc->local_addr_type);

	/* IOcap in LE byte order: [IO_cap, OOB, AuthReq] */
	iocap_a[0] = preq[1]; iocap_a[1] = preq[2]; iocap_a[2] = preq[3];
	iocap_b[0] = pres[1]; iocap_b[1] = pres[2]; iocap_b[2] = pres[3];

	/* Generate P-256 key pair */
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pctx == NULL)
		return (-1);
	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
	if (EVP_PKEY_keygen(pctx, &our_key) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return (-1);
	}
	EVP_PKEY_CTX_free(pctx);

	{
		size_t pklen = sizeof(our_pk_raw);
		if (EVP_PKEY_get_octet_string_param(our_key,
		    OSSL_PKEY_PARAM_PUB_KEY, our_pk_raw,
		    sizeof(our_pk_raw), &pklen) <= 0) {
			EVP_PKEY_free(our_key);
			return (-1);
		}
	}

	/* Receive initiator's PK first (responder receives first) */
	n = recv(sc->fd, pdu, 65, 0);
	if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY) {
		EVP_PKEY_free(our_key);
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	peer_pk_raw[0] = 0x04;
	swap_buf(peer_pk_raw + 1, pdu + 1, 32);
	swap_buf(peer_pk_raw + 33, pdu + 33, 32);
	memcpy(pka_le, pdu + 1, 32);		/* save LE x-coord */

	/* Validate peer public key is on P-256 curve (Core Spec 2.3.5.6.1) */
	if (smp_validate_public_key(peer_pk_raw + 1, peer_pk_raw + 33) != 0) {
		LOG_SMP(1, "SMP: peer public key not on P-256 curve, "
		    "failing pairing");
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		send(sc->fd, pdu, 2, 0);
		EVP_PKEY_free(our_key);
		return (-1);
	}

	/* Send our PK */
	pdu[0] = SMP_PAIRING_PUBLIC_KEY;
	swap_buf(pdu + 1, our_pk_raw + 1, 32);
	swap_buf(pdu + 33, our_pk_raw + 33, 32);
	memcpy(pkb_le, pdu + 1, 32);		/* save LE x-coord */
	if (send(sc->fd, pdu, 65, 0) < 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}
	LOG_SMP(2, "resp SC: public keys exchanged");

	/* Reconstruct peer EVP_PKEY */
	{
		OSSL_PARAM params[3];
		EVP_PKEY_CTX *fctx;
		static char curve[] = "prime256v1";

		params[0] = OSSL_PARAM_construct_utf8_string(
		    OSSL_PKEY_PARAM_GROUP_NAME, curve, 0);
		params[1] = OSSL_PARAM_construct_octet_string(
		    OSSL_PKEY_PARAM_PUB_KEY, peer_pk_raw, 65);
		params[2] = OSSL_PARAM_construct_end();

		peer_key = NULL;
		fctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		EVP_PKEY_fromdata_init(fctx);
		EVP_PKEY_fromdata(fctx, &peer_key, EVP_PKEY_PUBLIC_KEY,
		    params);
		EVP_PKEY_CTX_free(fctx);
		if (peer_key == NULL) {
			EVP_PKEY_free(our_key);
			return (-1);
		}
	}

	/* ECDH shared secret — convert BE to LE */
	{
		EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(our_key, NULL);
		uint8_t dhkey_be[32];
		EVP_PKEY_derive_init(dctx);
		EVP_PKEY_derive_set_peer(dctx, peer_key);
		dh_len = sizeof(dhkey_be);
		if (EVP_PKEY_derive(dctx, dhkey_be, &dh_len) <= 0) {
			EVP_PKEY_CTX_free(dctx);
			EVP_PKEY_free(peer_key);
			EVP_PKEY_free(our_key);
			return (-1);
		}
		swap_buf(dhkey_le, dhkey_be, 32);
		EVP_PKEY_CTX_free(dctx);
	}
	EVP_PKEY_free(peer_key);
	EVP_PKEY_free(our_key);
	LOG_SMP(2, "resp SC: DHKey computed");

	/* Auth Stage 1: generate Nb, compute Cb, exchange nonces */
	smp_random(nb, sizeof(nb));
	{
		uint8_t cb[16];
		smp_f4(pkb_le, pka_le, nb, 0, cb);
		pdu[0] = SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, cb, 16);
		if (send(sc->fd, pdu, 17, 0) < 0)
			return (-1);
	}

	/* Receive Na */
	n = recv(sc->fd, pdu, 17, 0);
	if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	memcpy(na, pdu + 1, 16);

	/* Send Nb */
	pdu[0] = SMP_PAIRING_RANDOM;
	memcpy(pdu + 1, nb, 16);
	if (send(sc->fd, pdu, 17, 0) < 0)
		return (-1);
	LOG_SMP(2, "resp SC: nonce exchange done");

	/* Numeric Comparison */
	if (model == SMP_MODEL_NUMERIC_COMPARISON) {
		uint32_t cv = smp_g2(pka_le, pkb_le, na, nb) % 1000000;
		if (sc->numcmp_cb == NULL ||
		    sc->numcmp_cb(cv, sc->numcmp_cb_arg) < 0) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_NUMERIC_COMP_FAILED;
			send(sc->fd, pdu, 2, 0);
			errno = EACCES;
			return (-1);
		}
	}

	/* MacKey + LTK */
	smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
	btled_hexdump("SMP", "f5 output (LTK)", ltk, 16);

	/* DHKey checks */
	{
		uint8_t r[16];
		memset(r, 0, sizeof(r));
		smp_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
		btled_hexdump("SMP", "f6 output (Ea)", ea, 16);
		smp_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);
		btled_hexdump("SMP", "f6 output (Eb)", eb, 16);
	}

	/* Receive Ea, verify */
	n = recv(sc->fd, pdu, 17, 0);
	if (n < 17 || pdu[0] != SMP_PAIRING_DHKEY_CHECK) {
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	if (memcmp(pdu + 1, ea, 16) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		send(sc->fd, pdu, 2, 0);
		errno = EACCES;
		return (-1);
	}
	LOG_SMP(1, "resp SC: DHKey check passed");

	/* Send Eb */
	pdu[0] = SMP_PAIRING_DHKEY_CHECK;
	memcpy(pdu + 1, eb, 16);
	if (send(sc->fd, pdu, 17, 0) < 0)
		return (-1);

	/* LTK reply + wait for encryption */
	if (hci_le_ltk_request_reply(sc->hci_fd, sc->con_handle, ltk) < 0)
		return (-1);
	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 10) < 0)
		return (-1);
	LOG_SMP(1, "resp SC: encrypted");

	/* Distribute our IdKey if negotiated (responder distributes first) */
	if (pres[6] & SMP_KEY_DIST_ID_KEY) {
		/* Send Identity Information (IRK).
		 * Use zero IRK = no privacy, public address. */
		pdu[0] = SMP_IDENTITY_INFORMATION;
		memset(pdu + 1, 0, 16);
		send(sc->fd, pdu, 17, 0);

		/* Send Identity Address Information */
		pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = (sc->local_addr_type == BDADDR_LE_RANDOM) ?
		    0x01 : 0x00;
		memcpy(pdu + 2, sc->local_addr, 6);
		send(sc->fd, pdu, 8, 0);
	}

	/* Store bond */
	{
		struct smp_bond bond;
		memset(&bond, 0, sizeof(bond));
		memcpy(bond.addr, sc->remote_addr, 6);
		bond.addr_type = sc->remote_addr_type;
		memcpy(bond.ltk, ltk, 16);
		bond.has_ltk = true;
		bond.is_sc = true;

		/* Receive initiator's keys. SC ignores EncKey;
		 * only IdKey from pres[5] applies. */
		{
			int exp = 0;
			if (pres[5] & SMP_KEY_DIST_ID_KEY) exp += 2;
			for (int i = 0; i < exp; i++) {
				struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
				setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
				    &tv, sizeof(tv));
				n = recv(sc->fd, pdu, sizeof(pdu), 0);
				if (n < 1) break;
				if (pdu[0] == SMP_IDENTITY_INFORMATION && n >= 17) {
					memcpy(bond.irk, pdu + 1, 16);
					bond.has_irk = true;
				} else if (pdu[0] == SMP_IDENTITY_ADDRESS_INFO &&
				    n >= 8) {
					bond.addr_type = (pdu[1] == 0x01) ?
					    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
					memcpy(bond.addr, pdu + 2, 6);
				}
			}
		}

		smp_bond_db_store(sc->bond_db, &bond);
	}

	return (0);
}

/*
 * LE Secure Connections — Responder path for Passkey Entry.
 * Core Spec Vol 3 Part H Section 2.3.5.6.3, Figure 2.4
 *
 * Mirrors smp_pair_sc_passkey() but with responder message ordering:
 * For each bit: recv Cai, send Cbi, recv Nai, verify Cai, send Nbi
 */
static int
smp_respond_sc_passkey(struct smp_conn *sc, const uint8_t preq[7],
    const uint8_t pres[7])
{
	EVP_PKEY *our_key = NULL, *peer_key = NULL;
	EVP_PKEY_CTX *pctx;
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
	size_t dh_len;
	uint32_t passkey;
	uint8_t ra[16];

	if (sc->passkey_cb == NULL) {
		uint8_t f[2] = { SMP_PAIRING_FAILED,
		    SMP_ERR_PAIRING_NOT_SUPPORTED };
		send(sc->fd, f, 2, 0);
		errno = ENOTSUP;
		return (-1);
	}

	/* Get passkey from user (responder receives, not displays) */
	passkey = 0;
	if (sc->passkey_cb(&passkey, false, sc->passkey_cb_arg) < 0) {
		uint8_t f[2] = { SMP_PAIRING_FAILED,
		    SMP_ERR_PASSKEY_ENTRY_FAILED };
		send(sc->fd, f, 2, 0);
		errno = ECANCELED;
		return (-1);
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
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pctx == NULL)
		return (-1);
	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
	if (EVP_PKEY_keygen(pctx, &our_key) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return (-1);
	}
	EVP_PKEY_CTX_free(pctx);

	{
		size_t pklen = sizeof(our_pk_raw);
		if (EVP_PKEY_get_octet_string_param(our_key,
		    OSSL_PKEY_PARAM_PUB_KEY, our_pk_raw,
		    sizeof(our_pk_raw), &pklen) <= 0) {
			EVP_PKEY_free(our_key);
			return (-1);
		}
	}

	/* Receive initiator's PK first (responder receives first) */
	n = recv(sc->fd, pdu, 65, 0);
	if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY) {
		EVP_PKEY_free(our_key);
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	peer_pk_raw[0] = 0x04;
	swap_buf(peer_pk_raw + 1, pdu + 1, 32);
	swap_buf(peer_pk_raw + 33, pdu + 33, 32);
	memcpy(pka_le, pdu + 1, 32);

	/* Validate peer public key is on P-256 curve (Core Spec 2.3.5.6.1) */
	if (smp_validate_public_key(peer_pk_raw + 1, peer_pk_raw + 33) != 0) {
		LOG_SMP(1, "SMP: peer public key not on P-256 curve, "
		    "failing pairing");
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		send(sc->fd, pdu, 2, 0);
		EVP_PKEY_free(our_key);
		return (-1);
	}

	/* Send our PK */
	pdu[0] = SMP_PAIRING_PUBLIC_KEY;
	swap_buf(pdu + 1, our_pk_raw + 1, 32);
	swap_buf(pdu + 33, our_pk_raw + 33, 32);
	memcpy(pkb_le, pdu + 1, 32);
	if (send(sc->fd, pdu, 65, 0) < 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}
	LOG_SMP(2, "resp SC: public keys exchanged");

	/* Build peer EVP_PKEY and compute DHKey */
	{
		OSSL_PARAM params[3];
		EVP_PKEY_CTX *fctx;
		static char curve[] = "prime256v1";

		params[0] = OSSL_PARAM_construct_utf8_string(
		    OSSL_PKEY_PARAM_GROUP_NAME, curve, 0);
		params[1] = OSSL_PARAM_construct_octet_string(
		    OSSL_PKEY_PARAM_PUB_KEY, peer_pk_raw, 65);
		params[2] = OSSL_PARAM_construct_end();

		peer_key = NULL;
		fctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		EVP_PKEY_fromdata_init(fctx);
		EVP_PKEY_fromdata(fctx, &peer_key, EVP_PKEY_PUBLIC_KEY,
		    params);
		EVP_PKEY_CTX_free(fctx);
		if (peer_key == NULL) {
			EVP_PKEY_free(our_key);
			return (-1);
		}

		EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(our_key, NULL);
		uint8_t dhkey_be[32];
		EVP_PKEY_derive_init(dctx);
		EVP_PKEY_derive_set_peer(dctx, peer_key);
		dh_len = sizeof(dhkey_be);
		if (EVP_PKEY_derive(dctx, dhkey_be, &dh_len) <= 0) {
			EVP_PKEY_CTX_free(dctx);
			EVP_PKEY_free(peer_key);
			EVP_PKEY_free(our_key);
			return (-1);
		}
		swap_buf(dhkey_le, dhkey_be, 32);
		EVP_PKEY_CTX_free(dctx);
	}
	EVP_PKEY_free(peer_key);
	EVP_PKEY_free(our_key);
	LOG_SMP(2, "resp SC: DHKey computed");

	/*
	 * Authentication Stage 1: 20 rounds of Passkey Entry.
	 * Responder ordering per Figure 2.4:
	 *   recv Cai, send Cbi, recv Nai, verify Cai, send Nbi
	 */
	for (int i = 0; i < 20; i++) {
		uint8_t nai[16], nbi[16];
		uint8_t cai_recv[16], cbi[16], cai_verify[16];
		uint8_t ri;

		if (i == 0 || i == 19)
			LOG_SMP(2, "resp SC passkey: round %d/20", i + 1);

		ri = 0x80 | ((passkey >> i) & 1);

		smp_random(nbi, sizeof(nbi));

		/* Receive initiator's confirm Cai */
		n = recv(sc->fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			return (-1);
		}
		memcpy(cai_recv, pdu + 1, 16);

		/* Compute and send our confirm Cbi */
		smp_f4(pkb_le, pka_le, nbi, ri, cbi);
		pdu[0] = SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, cbi, 16);
		if (send(sc->fd, pdu, 17, 0) < 0)
			return (-1);

		/* Receive initiator's nonce Nai */
		n = recv(sc->fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			return (-1);
		}
		memcpy(nai, pdu + 1, 16);

		/* Verify Cai = f4(PKax, PKbx, Nai, rai) */
		smp_f4(pka_le, pkb_le, nai, ri, cai_verify);
		if (memcmp(cai_recv, cai_verify, 16) != 0) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
			send(sc->fd, pdu, 2, 0);
			errno = EACCES;
			return (-1);
		}

		/* Send our nonce Nbi */
		pdu[0] = SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, nbi, 16);
		if (send(sc->fd, pdu, 17, 0) < 0)
			return (-1);

		/* Keep last round's nonces for f5/f6 */
		memcpy(na, nai, 16);
		memcpy(nb, nbi, 16);
	}
	LOG_SMP(1, "resp SC passkey: 20 rounds complete");

	/* Auth Stage 2: MacKey/LTK derivation and DHKey checks */
	smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
	btled_hexdump("SMP", "f5 output (LTK)", ltk, 16);

	smp_f6(mackey, na, nb, ra, iocap_a, a1, a2, ea);
	btled_hexdump("SMP", "f6 output (Ea)", ea, 16);
	smp_f6(mackey, nb, na, ra, iocap_b, a2, a1, eb);
	btled_hexdump("SMP", "f6 output (Eb)", eb, 16);

	/* Receive Ea from initiator, verify */
	n = recv(sc->fd, pdu, 17, 0);
	if (n < 17 || pdu[0] != SMP_PAIRING_DHKEY_CHECK) {
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	if (memcmp(pdu + 1, ea, 16) != 0) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_DHKEY_CHECK_FAILED;
		send(sc->fd, pdu, 2, 0);
		errno = EACCES;
		return (-1);
	}

	/* Send our DHKey Check (Eb) */
	pdu[0] = SMP_PAIRING_DHKEY_CHECK;
	memcpy(pdu + 1, eb, 16);
	if (send(sc->fd, pdu, 17, 0) < 0)
		return (-1);

	/* LTK reply + wait for encryption */
	if (hci_le_ltk_request_reply(sc->hci_fd, sc->con_handle, ltk) < 0)
		return (-1);
	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 10) < 0)
		return (-1);

	/* Distribute our IdKey if negotiated (responder distributes first) */
	if (pres[6] & SMP_KEY_DIST_ID_KEY) {
		/* Send Identity Information (IRK).
		 * Use zero IRK = no privacy, public address. */
		pdu[0] = SMP_IDENTITY_INFORMATION;
		memset(pdu + 1, 0, 16);
		send(sc->fd, pdu, 17, 0);

		/* Send Identity Address Information */
		pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = (sc->local_addr_type == BDADDR_LE_RANDOM) ?
		    0x01 : 0x00;
		memcpy(pdu + 2, sc->local_addr, 6);
		send(sc->fd, pdu, 8, 0);
	}

	/* Store bond */
	{
		struct smp_bond bond;
		memset(&bond, 0, sizeof(bond));
		memcpy(bond.addr, sc->remote_addr, 6);
		bond.addr_type = sc->remote_addr_type;
		memcpy(bond.ltk, ltk, 16);
		bond.has_ltk = true;
		bond.is_sc = true;

		/* Receive initiator's keys. SC ignores EncKey;
		 * only IdKey from pres[5] applies. */
		{
			int exp = 0;
			if (pres[5] & SMP_KEY_DIST_ID_KEY) exp += 2;
			for (int i = 0; i < exp; i++) {
				struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
				setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
				    &tv, sizeof(tv));
				n = recv(sc->fd, pdu, sizeof(pdu), 0);
				if (n < 1)
					break;
				if (pdu[0] == SMP_IDENTITY_INFORMATION && n >= 17) {
					memcpy(bond.irk, pdu + 1, 16);
					bond.has_irk = true;
				} else if (pdu[0] == SMP_IDENTITY_ADDRESS_INFO &&
				    n >= 8) {
					bond.addr_type = (pdu[1] == 0x01) ?
					    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
					memcpy(bond.addr, pdu + 2, 6);
				}
			}
		}

		smp_bond_db_store(sc->bond_db, &bond);
	}

	return (0);
}

/*
 * SMP Responder entry point.
 * Receives Pairing Request, sends Response, dispatches to legacy or SC.
 */
int
smp_respond(struct smp_conn *sc)
{
	uint8_t preq[7], pres[7];
	uint8_t tk[16];
	ssize_t n;

	memset(tk, 0, sizeof(tk));

	/* Receive Pairing Request */
	n = recv(sc->fd, preq, sizeof(preq), 0);
	if (n < 7) {
		errno = EPROTO;
		return (-1);
	}
	if (preq[0] != SMP_PAIRING_REQUEST) {
		errno = (preq[0] == SMP_SECURITY_REQUEST) ? EAGAIN : EPROTO;
		return (-1);
	}
	LOG_SMP(1, "resp: request received IO=%d auth=%02x", preq[1], preq[3]);

	/*
	 * Send Pairing Response.
	 *
	 * Key distribution fields must be a subset of what the initiator
	 * offered (Core Spec Vol 3 Part H Section 3.6.1): "The Peripheral
	 * shall not set to one any flag ... that the Central has set to zero."
	 *
	 * For SC, EncKey is ignored and EDIV/Rand shall not be distributed.
	 */
	{
		bool peer_sc = (preq[3] & SMP_AUTH_SC) != 0;

		pres[0] = SMP_PAIRING_RESPONSE;
		pres[1] = SMP_IO_DISPLAY_YESNO;
		pres[2] = 0x00;
		pres[3] = SMP_AUTH_BONDING | SMP_AUTH_SC;
		pres[4] = 16;
		pres[5] = preq[5] & SMP_KEY_DIST_ID_KEY;
		if (peer_sc)
			pres[6] = preq[6] & SMP_KEY_DIST_ID_KEY;
		else
			pres[6] = preq[6] & (SMP_KEY_DIST_ENC_KEY |
			    SMP_KEY_DIST_ID_KEY);
	}

	if (send(sc->fd, pres, sizeof(pres), 0) < 0)
		return (-1);
	LOG_SMP(1, "resp: response sent IO=%d auth=%02x sc=%d",
	    pres[1], pres[3], (pres[3] & 0x08) != 0);

	/*
	 * Validate encryption key size (Core Spec Vol 3 Part H 3.6.1).
	 * Max_Encryption_Key_Size must be in range [7,16].
	 * Negotiated size = min(ours, theirs); reject if < 7.
	 */
	{
		uint8_t peer_key_sz = preq[4];
		uint8_t neg_key_sz;
		uint8_t fail[2];

		if (peer_key_sz < 7 || peer_key_sz > 16) {
			fail[0] = SMP_PAIRING_FAILED;
			fail[1] = SMP_ERR_INVALID_PARAMETERS;
			send(sc->fd, fail, 2, 0);
			errno = EPROTO;
			return (-1);
		}
		neg_key_sz = (pres[4] < peer_key_sz) ? pres[4] : peer_key_sz;
		if (neg_key_sz < 7) {
			fail[0] = SMP_PAIRING_FAILED;
			fail[1] = SMP_ERR_ENCRYPTION_KEY_SIZE;
			send(sc->fd, fail, 2, 0);
			errno = EACCES;
			return (-1);
		}
	}

	{
		bool use_sc = (preq[3] & SMP_AUTH_SC) &&
		    (pres[3] & SMP_AUTH_SC);
		bool use_mitm = (preq[3] & SMP_AUTH_MITM) ||
		    (pres[3] & SMP_AUTH_MITM);
		int model;

		if (!use_mitm)
			model = SMP_MODEL_JUST_WORKS;
		else
			model = smp_select_model(preq[1], pres[1], use_sc);

		if (use_sc) {
			if (model == SMP_MODEL_PASSKEY_ENTRY)
				return (smp_respond_sc_passkey(sc, preq, pres));
			return (smp_respond_sc(sc, preq, pres, model));
		}

		if (model == SMP_MODEL_PASSKEY_ENTRY) {
			uint32_t passkey = 0;
			if (sc->passkey_cb == NULL) {
				uint8_t f[2] = { SMP_PAIRING_FAILED,
				    SMP_ERR_PAIRING_NOT_SUPPORTED };
				send(sc->fd, f, 2, 0);
				errno = ENOTSUP;
				return (-1);
			}
			if (sc->passkey_cb(&passkey, false,
			    sc->passkey_cb_arg) < 0) {
				uint8_t f[2] = { SMP_PAIRING_FAILED,
				    SMP_ERR_PASSKEY_ENTRY_FAILED };
				send(sc->fd, f, 2, 0);
				errno = ECANCELED;
				return (-1);
			}
			memset(tk, 0, sizeof(tk));
			tk[0] = passkey & 0xFF;
			tk[1] = (passkey >> 8) & 0xFF;
			tk[2] = (passkey >> 16) & 0xFF;
		}

		return (smp_respond_legacy(sc, preq, pres, tk));
	}
}
