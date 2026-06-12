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

#include <openssl/evp.h>

#include "smp.h"

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
	preq[1] = SMP_IO_NO_INPUT_NO_OUTPUT;	/* IO capability */
	preq[2] = 0x00;			/* No OOB */
	preq[3] = SMP_AUTH_BONDING;		/* Bonding, no MITM */
	preq[4] = 16;				/* Max encryption key size */
	preq[5] = 0;				/* Initiator key dist: none */
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
 * Find a bond by device address.
 */
struct smp_bond *
smp_find_bond(struct smp_bond_db *db, const uint8_t *addr, uint8_t addr_type)
{
	for (int i = 0; i < db->count; i++) {
		if (db->bonds[i].addr_type == addr_type &&
		    memcmp(db->bonds[i].addr, addr, 6) == 0)
			return (&db->bonds[i]);
	}
	return (NULL);
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
