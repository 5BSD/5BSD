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
#include <sys/socket.h>
#include <sys/endian.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include "smp.h"

/* Association model */
#define SMP_MODEL_JUST_WORKS		0
#define SMP_MODEL_PASSKEY_ENTRY		1
#define SMP_MODEL_NUMERIC_COMPARISON	2

/* Forward declarations */
static int smp_pair_sc(struct smp_conn *, const uint8_t[7], const uint8_t[7]);
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
	/* I:DispOnly */ { 0,      2,        1,        0,        1       },
	/* I:DispYN   */ { 2,      2,        1,        0,        2       },
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

	/* p2 = padding(4) || ia(6) || ra(6) */
	memset(p2, 0, 4);
	memcpy(p2 + 4, ia, 6);
	memcpy(p2 + 10, ra, 6);

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
		return (-1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;
	memcpy(&sa.l2cap_bdaddr, addr, sizeof(sa.l2cap_bdaddr));
	sa.l2cap_cid = 0x0006;	/* NG_L2CAP_SMP_CID */
	sa.l2cap_bdaddr_type = addr_type;

	if (connect(sc->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(sc->fd);
		return (-1);
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
	preq[5] = SMP_KEY_DIST_ID_KEY;		/* We can send IRK */
	preq[6] = SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY;

	if (send(sc->fd, preq, sizeof(preq), 0) < 0)
		return (-1);

	/*
	 * Step 2: Receive Pairing Response
	 */
	n = recv(sc->fd, pres, sizeof(pres), 0);
	if (n < 7) {
		errno = EPROTO;
		return (-1);
	}

	if (pres[0] == SMP_PAIRING_FAILED) {
		errno = EACCES;
		return (-1);
	}

	if (pres[0] != SMP_PAIRING_RESPONSE) {
		errno = EPROTO;
		return (-1);
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

		if (use_sc) {
			if (model == SMP_MODEL_PASSKEY_ENTRY)
				return (smp_pair_sc_passkey(sc, preq, pres));
			return (smp_pair_sc(sc, preq, pres));
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

	/*
	 * Step 7: Derive STK
	 */
	smp_s1(tk, mrand, srand, stk);

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

		if (hci_send_cmd(sc->hci_fd, 0x2019, params,
		    sizeof(params)) < 0)
			return (-1);
	}

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

		/* Receive up to 4 PDUs for key distribution */
		for (int i = 0; i < 4; i++) {
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
		if (bond.has_ltk && sc->bond_db != NULL &&
		    sc->bond_db->count < SMP_MAX_BONDS) {
			sc->bond_db->bonds[sc->bond_db->count++] = bond;
			smp_bond_db_save(sc->bond_db);
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

	if (!bond->has_ltk)
		return (ENOENT);

	params[0] = sc->con_handle & 0xFF;
	params[1] = (sc->con_handle >> 8) & 0xFF;
	memcpy(params + 2, &bond->rand, 8);
	memcpy(params + 10, &bond->ediv, 2);
	memcpy(params + 12, bond->ltk, 16);

	if (hci_send_cmd(sc->hci_fd, 0x2019, params, sizeof(params)) < 0)
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

	/* ah(k, r) = E(k, r') mod 2^24, where r' = padding || prand */
	memset(plaintext, 0, 13);
	plaintext[13] = prand[0];
	plaintext[14] = prand[1];
	plaintext[15] = prand[2];

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
		    memcmp(db->bonds[i].addr, addr, 6) == 0)
			return (&db->bonds[i]);
	}

	/* Try IRK-based RPA resolution for random addresses */
	if (addr_type == BDADDR_LE_RANDOM) {
		for (int i = 0; i < db->count; i++) {
			if (db->bonds[i].has_irk &&
			    smp_rpa_matches(db->bonds[i].irk, addr))
				return (&db->bonds[i]);
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
	uint8_t pka_le[64], pkb_le[64];
	uint8_t dhkey[32];
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

	iocap_a[0] = preq[3];
	iocap_a[1] = preq[2];
	iocap_a[2] = preq[1];
	iocap_b[0] = pres[3];
	iocap_b[1] = pres[2];
	iocap_b[2] = pres[1];

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
		EVP_PKEY_get_octet_string_param(our_key,
		    OSSL_PKEY_PARAM_PUB_KEY, our_pk_raw,
		    sizeof(our_pk_raw), &pklen);
	}

	/* Send our PK (big-endian -> little-endian) */
	pdu[0] = SMP_PAIRING_PUBLIC_KEY;
	swap_buf(pdu + 1, our_pk_raw + 1, 32);
	swap_buf(pdu + 33, our_pk_raw + 33, 32);
	memcpy(pka_le, pdu + 1, 64);
	if (send(sc->fd, pdu, 65, 0) < 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}

	/* Receive peer PK */
	n = recv(sc->fd, pdu, 65, 0);
	if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY) {
		EVP_PKEY_free(our_key);
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		return (-1);
	}
	memcpy(pkb_le, pdu + 1, 64);
	peer_pk_raw[0] = 0x04;
	swap_buf(peer_pk_raw + 1, pdu + 1, 32);
	swap_buf(peer_pk_raw + 33, pdu + 33, 32);

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
		dh_len = sizeof(dhkey);
		EVP_PKEY_derive(dctx, dhkey, &dh_len);
		EVP_PKEY_CTX_free(dctx);
	}
	EVP_PKEY_free(peer_key);
	EVP_PKEY_free(our_key);

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

	/*
	 * Authentication Stage 2: same as Just Works SC.
	 * MacKey || LTK = f5(DHKey, Na, Nb, A1, A2)
	 * Ea = f6(MacKey, Na, Nb, ra, IOcapA, A1, A2)
	 * Eb = f6(MacKey, Nb, Na, ra, IOcapB, A2, A1)
	 * (ra = rb = passkey for Passkey Entry per Table 2.2)
	 */
	smp_f5(dhkey, na, nb, a1, a2, mackey, ltk);

	smp_f6(mackey, na, nb, ra, iocap_a, a1, a2, ea);
	smp_f6(mackey, nb, na, ra, iocap_b, a2, a1, eb);

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
		pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
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
		if (hci_send_cmd(sc->hci_fd, 0x2019, params,
		    sizeof(params)) < 0)
			return (-1);
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

		if (sc->bond_db != NULL &&
		    sc->bond_db->count < SMP_MAX_BONDS) {
			sc->bond_db->bonds[sc->bond_db->count++] = bond;
			smp_bond_db_save(sc->bond_db);
		}
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

	n = pread(fd, db->bonds, sizeof(db->bonds), 0);
	if (n < 0)
		return (-1);

	if (n < 0 || (n % sizeof(struct smp_bond)) != 0) {
		db->count = 0;
		return (n < 0 ? -1 : 0);
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

	len = db->count * sizeof(struct smp_bond);
	n = pwrite(db->fd, db->bonds, len, 0);
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
	ctx = EVP_MAC_CTX_new(cmac_type);
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
 */
static void
smp_f4(const uint8_t u[32], const uint8_t v[32], const uint8_t x[16],
    uint8_t z, uint8_t out[16])
{
	uint8_t m[65];

	memcpy(m, u, 32);
	memcpy(m + 32, v, 32);
	m[64] = z;
	smp_aes_cmac(x, m, sizeof(m), out);
}

/*
 * f5: LE SC key generation.
 * Core Spec Vol 3 Part H Section 2.2.7
 *
 * Outputs MacKey (Counter=0) and LTK (Counter=1).
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
	uint8_t t[16];
	uint8_t m[53];

	smp_aes_cmac(salt, w, 32, t);

	m[0] = 0;
	memcpy(m + 1, keyid, 4);
	memcpy(m + 5, n1, 16);
	memcpy(m + 21, n2, 16);
	memcpy(m + 37, a1, 7);
	memcpy(m + 44, a2, 7);
	m[51] = 0x01;
	m[52] = 0x00;

	smp_aes_cmac(t, m, sizeof(m), mackey);
	m[0] = 1;
	smp_aes_cmac(t, m, sizeof(m), ltk);
}

/*
 * f6: LE SC check value generation.
 * Core Spec Vol 3 Part H Section 2.2.8
 *
 * f6(W, N1, N2, R, IOcap, A1, A2) = AES-CMAC_W(N1||N2||R||IOcap||A1||A2)
 */
static void
smp_f6(const uint8_t w[16], const uint8_t n1[16], const uint8_t n2[16],
    const uint8_t r[16], const uint8_t iocap[3],
    const uint8_t a1[7], const uint8_t a2[7],
    uint8_t out[16])
{
	uint8_t m[65];

	memcpy(m, n1, 16);
	memcpy(m + 16, n2, 16);
	memcpy(m + 32, r, 16);
	memcpy(m + 48, iocap, 3);
	memcpy(m + 51, a1, 7);
	memcpy(m + 58, a2, 7);
	smp_aes_cmac(w, m, sizeof(m), out);
}

/*
 * Build SMP 7-byte address: [type_bit, bdaddr(6)]
 */
static void
smp_pack_addr(uint8_t out[7], const uint8_t addr[6], uint8_t addr_type)
{
	out[0] = (addr_type == BDADDR_LE_RANDOM) ? 0x01 : 0x00;
	memcpy(out + 1, addr, 6);
}

/*
 * LE Secure Connections pairing — Just Works.
 * Called after Pairing Request/Response exchange when both sides
 * set SMP_AUTH_SC.
 *
 * Core Spec Vol 3 Part H Section 2.3.5.6
 */
static int
smp_pair_sc(struct smp_conn *sc, const uint8_t preq[7], const uint8_t pres[7])
{
	EVP_PKEY *our_key = NULL, *peer_key = NULL;
	EVP_PKEY_CTX *pctx;
	uint8_t our_pk_raw[65], peer_pk_raw[65];
	uint8_t dhkey[32];
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

	/* IOcap: [AuthReq, OOB, IO_cap] per spec */
	iocap_a[0] = preq[3];
	iocap_a[1] = preq[2];
	iocap_a[2] = preq[1];
	iocap_b[0] = pres[3];
	iocap_b[1] = pres[2];
	iocap_b[2] = pres[1];

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
	 * - pka_le/pkb_le: SMP wire format (little-endian, for f4/f5/f6)
	 */
	uint8_t pka_le[64], pkb_le[64]; /* wire-order public keys */

	/* Send our Public Key: [0x0C, x_le(32), y_le(32)] */
	pdu[0] = SMP_PAIRING_PUBLIC_KEY;
	swap_buf(pdu + 1, our_pk_raw + 1, 32);      /* x: BE -> LE */
	swap_buf(pdu + 33, our_pk_raw + 33, 32);     /* y: BE -> LE */
	memcpy(pka_le, pdu + 1, 64);                 /* save LE copy */
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
	memcpy(pkb_le, pdu + 1, 64);                 /* save LE copy */

	/* Convert peer PK to OpenSSL big-endian for ECDH */
	peer_pk_raw[0] = 0x04;
	swap_buf(peer_pk_raw + 1, pdu + 1, 32);      /* x: LE -> BE */
	swap_buf(peer_pk_raw + 33, pdu + 33, 32);    /* y: LE -> BE */

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

	/* Compute ECDH shared secret (DHKey) — big-endian from OpenSSL */
	{
		EVP_PKEY_CTX *dctx;

		dctx = EVP_PKEY_CTX_new(our_key, NULL);
		EVP_PKEY_derive_init(dctx);
		EVP_PKEY_derive_set_peer(dctx, peer_key);
		dh_len = sizeof(dhkey);
		if (EVP_PKEY_derive(dctx, dhkey, &dh_len) <= 0) {
			EVP_PKEY_CTX_free(dctx);
			EVP_PKEY_free(peer_key);
			EVP_PKEY_free(our_key);
			return (-1);
		}
		EVP_PKEY_CTX_free(dctx);
	}

	EVP_PKEY_free(peer_key);
	EVP_PKEY_free(our_key);

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

	/* Compute MacKey and LTK */
	smp_f5(dhkey, na, nb, a1, a2, mackey, ltk);

	/* Compute DHKey checks */
	{
		uint8_t r[16];
		memset(r, 0, sizeof(r));
		smp_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
		smp_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);
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
		pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
		send(sc->fd, pdu, 2, 0);
		errno = EACCES;
		return (-1);
	}

	/* Start encryption with SC-derived LTK (rand=0, ediv=0) */
	{
		uint8_t params[28];
		params[0] = sc->con_handle & 0xFF;
		params[1] = (sc->con_handle >> 8) & 0xFF;
		memset(params + 2, 0, 10);
		memcpy(params + 12, ltk, 16);
		if (hci_send_cmd(sc->hci_fd, 0x2019, params,
		    sizeof(params)) < 0)
			return (-1);
	}

	/* Store SC bond */
	{
		struct smp_bond bond;
		memset(&bond, 0, sizeof(bond));
		memcpy(bond.addr, sc->remote_addr, 6);
		bond.addr_type = sc->remote_addr_type;
		memcpy(bond.ltk, ltk, 16);
		bond.has_ltk = true;
		bond.is_sc = true;

		/* Receive optional IRK distribution */
		for (int i = 0; i < 2; i++) {
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
				bond.addr_type = pdu[1];
				memcpy(bond.addr, pdu + 2, 6);
			}
		}

		if (sc->bond_db != NULL &&
		    sc->bond_db->count < SMP_MAX_BONDS) {
			sc->bond_db->bonds[sc->bond_db->count++] = bond;
			smp_bond_db_save(sc->bond_db);
		}
	}

	return (0);
}
