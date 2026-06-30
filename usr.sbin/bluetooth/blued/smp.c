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
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/endian.h>
#include <time.h>

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
#include <openssl/rand.h>

#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "blued_probes.h"
#include "hci_log.h"
#include "hci_util.h"
#include "smp.h"

/* HCI LE_Start_Encryption opcode */
#define HCI_OP_LE_START_ENCRYPTION \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_START_ENCRYPTION)

/* Association model */
#define SMP_MODEL_JUST_WORKS		0
#define SMP_MODEL_PASSKEY_ENTRY		1
#define SMP_MODEL_NUMERIC_COMPARISON	2
#define SMP_MODEL_OOB			3
#define SMP_MODEL_INVALID		(-1)

/* Forward declarations */
static int smp_pair_sc(struct smp_conn *, const uint8_t[7], const uint8_t[7],
    int model);
static int smp_pair_sc_passkey(struct smp_conn *, const uint8_t[7],
    const uint8_t[7]);
static void smp_pack_addr(uint8_t[7], const uint8_t[6], uint8_t);
void smp_f4(const uint8_t[32], const uint8_t[32], const uint8_t[16],
    uint8_t, uint8_t[16]);
void smp_f5(const uint8_t[32], const uint8_t[16], const uint8_t[16],
    const uint8_t[7], const uint8_t[7], uint8_t[16], uint8_t[16]);
void smp_f6(const uint8_t[16], const uint8_t[16], const uint8_t[16],
    const uint8_t[16], const uint8_t[3], const uint8_t[7], const uint8_t[7],
    uint8_t[16]);
void smp_swap_buf(uint8_t *, const uint8_t *, size_t);
static int smp_validate_public_key(const uint8_t *, const uint8_t *);
static bool smp_pairing_expired(const struct timespec *);

/*
 * Ensure the bond database has a local IRK for identity distribution.
 * If one was previously persisted, it is already loaded; otherwise
 * generate a fresh 128-bit IRK via arc4random_buf and save immediately.
 *
 * All callers reference db->local_irk directly -- there is no file-scope
 * static copy, so the IRK cannot diverge from the bond database.
 */
static void
smp_ensure_local_irk(struct smp_bond_db *db)
{

	if (db == NULL)
		return;

	if (!db->has_local_irk) {
		arc4random_buf(db->local_irk, 16);
		db->has_local_irk = true;
		smp_bond_db_save(db);
		LOG_SMP(1, "generated local IRK for identity distribution");
	}
}

/*
 * Logged send/recv helpers for SMP — log PDUs as L2CAP on CID 0x0006
 * to BTSnoop when capture is active.
 */
static ssize_t
smp_log_send(struct smp_conn *sc, const void *buf, size_t len)
{
	ssize_t n;

	do {
		n = send(sc->fd, buf, len, MSG_EOR);
	} while (n < 0 && errno == EINTR);
	if (n > 0 && hci_log_enabled())
		hci_log_l2cap(sc->con_handle, 0x0006,
		    buf, (uint16_t)n, false);
	return (n);
}

static ssize_t
smp_log_recv(struct smp_conn *sc, void *buf, size_t len)
{
	ssize_t n;

	do {
		n = recv(sc->fd, buf, len, 0);
	} while (n < 0 && errno == EINTR);
	if (n > 0 && hci_log_enabled())
		hci_log_l2cap(sc->con_handle, 0x0006,
		    buf, (uint16_t)n, true);

	/*
	 * SMP timeout: Core Spec Vol 3 Part H Section 3.4 requires the
	 * link to be disconnected when the SMP timeout expires.
	 */
	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		ng_hci_discon_cp dp;

		LOG_SMP(1, "SMP timeout, disconnecting handle=%u",
		    sc->con_handle);
		BLUED_LOG_SECURITY("SMP timeout "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x handle=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    sc->con_handle);
		memset(&dp, 0, sizeof(dp));
		dp.con_handle = htole16(sc->con_handle);
		dp.reason = 0x13;	/* Remote User Terminated Connection */
		hci_send_raw_cmd(sc->hci_fd,
		    NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL,
		    NG_HCI_OCF_DISCON), &dp, sizeof(dp));
	}
	return (n);
}

/*
 * Send a Keypress Notification PDU.
 * Core Spec Vol 3 Part H Section 3.5.8
 *
 * Only sent when both sides indicated Keypress Notification support
 * (SMP_AUTH_KEYPRESS bit) in their AuthReq fields.
 */
static int
smp_send_keypress(struct smp_conn *sc, uint8_t type)
{
	uint8_t pdu[2];

	pdu[0] = SMP_PAIRING_KEYPRESS_NOTIFY;
	pdu[1] = type;
	return (smp_log_send(sc, pdu, sizeof(pdu)) < 0 ? -1 : 0);
}

static const char *
smp_keypress_type_str(uint8_t type)
{
	switch (type) {
	case SMP_KEYPRESS_STARTED:		return ("started");
	case SMP_KEYPRESS_DIGIT_ENTERED:	return ("digit entered");
	case SMP_KEYPRESS_DIGIT_ERASED:		return ("digit erased");
	case SMP_KEYPRESS_CLEARED:		return ("cleared");
	case SMP_KEYPRESS_COMPLETED:		return ("completed");
	default:				return ("unknown");
	}
}

/*
 * Receive a PDU from the SMP socket, transparently consuming and
 * logging any Keypress Notification PDUs that arrive first.
 *
 * Per Core Spec Vol 3 Part H Section 3.5.8, the device performing
 * passkey entry sends Keypress Notifications to the displaying side
 * before or during the confirm exchange.  These are informational
 * and do not alter protocol state.
 *
 * Returns the number of bytes read into buf, or -1 on error.
 */
static ssize_t
smp_recv_skip_keypress(struct smp_conn *sc, uint8_t *buf, size_t len)
{
	ssize_t n;
	int loops = 0;

	for (;;) {
		if (++loops > 100) {
			warnx("too many keypress notifications");
			return (-1);
		}
		n = smp_log_recv(sc, buf, len);
		if (n < 1)
			return (n);
		if (buf[0] != SMP_PAIRING_KEYPRESS_NOTIFY)
			return (n);
		/* Log and discard keypress notification */
		if (n >= 2)
			LOG_SMP(1, "recv keypress notification: %s (0x%02x)",
			    smp_keypress_type_str(buf[1]), buf[1]);
		else
			LOG_SMP(1, "recv keypress notification (malformed)");
	}
}

/*
 * Determine association model from IO capabilities.
 * Core Spec Vol 3 Part H Table 2.8
 */
int
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
		return (SMP_MODEL_INVALID);

	return (sc ? sc_table[init_io][resp_io] :
	    legacy_table[init_io][resp_io]);
}

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
	sc->io_capability = SMP_IO_KEYBOARD_DISPLAY;  /* default */
	sc->min_key_size = 16;  /* KNOB-safe default */

	sc->fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_CLOFORK,
	    BLUETOOTH_PROTO_L2CAP);
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
	sa.l2cap_cid = htole16(NG_L2CAP_SMP_CID);
	sa.l2cap_bdaddr_type = addr_type;

	if (connect(sc->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(sc->fd);
		sc->fd = -1;
		return (-1);
	}

	/* SMP timeout: 30 seconds per spec (Vol 3 Part H Section 3.4) */
	{
		struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
		if (setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
		    &tv, sizeof(tv)) < 0)
			warn("setsockopt SO_RCVTIMEO");
	}

	return (0);
}

void
smp_close(struct smp_conn *sc)
{
	if (sc->fd >= 0) {
		close(sc->fd);
	}
	/* Zero entire struct to scrub all residual pairing data */
	explicit_bzero(sc, sizeof(*sc));
	sc->fd = -1;
	sc->hci_fd = -1;
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
 * Distribute initiator keys to the responder.
 * For SC, only IdKey applies (EncKey is ignored per spec).
 * For Legacy, both EncKey and IdKey may be distributed.
 */
static void
smp_distribute_init_keys(struct smp_conn *sc, const uint8_t *preq,
    const uint8_t *pres, bool is_sc)
{
	uint8_t init_dist = preq[5] & pres[5];
	uint8_t kpdu[19];

	/* SC ignores EncKey distribution (LTK derived from DH key) */
	if (!is_sc && (init_dist & SMP_KEY_DIST_ENC_KEY)) {
		uint8_t our_ltk[16];
		uint64_t our_rand;
		uint16_t our_ediv;

		arc4random_buf(our_ltk, 16);
		arc4random_buf(&our_rand, sizeof(our_rand));
		arc4random_buf(&our_ediv, sizeof(our_ediv));

		kpdu[0] = SMP_ENCRYPTION_INFORMATION;
		memcpy(kpdu + 1, our_ltk, 16);
		smp_log_send(sc, kpdu, 17);

		kpdu[0] = SMP_CENTRAL_IDENTIFICATION;
		put_le16(kpdu + 1, our_ediv);
		memcpy(kpdu + 3, &our_rand, 8);
		smp_log_send(sc, kpdu, 11);

		explicit_bzero(our_ltk, sizeof(our_ltk));
	}

	if (init_dist & SMP_KEY_DIST_ID_KEY) {
		smp_ensure_local_irk(sc->bond_db);

		kpdu[0] = SMP_IDENTITY_INFORMATION;
		memcpy(kpdu + 1, sc->bond_db->local_irk, 16);
		smp_log_send(sc, kpdu, 17);

		kpdu[0] = SMP_IDENTITY_ADDRESS_INFO;
		kpdu[1] = sc->local_addr_type;
		memcpy(kpdu + 2, sc->local_addr, 6);
		smp_log_send(sc, kpdu, 8);
	}

	if (init_dist & SMP_KEY_DIST_SIGN_KEY) {
		uint8_t local_csrk[16];

		arc4random_buf(local_csrk, 16);
		kpdu[0] = SMP_SIGNING_INFORMATION;
		memcpy(kpdu + 1, local_csrk, 16);
		smp_log_send(sc, kpdu, 17);
		LOG_SMP(1, "distributed local CSRK");

		/* Persist local CSRK before zeroing */
		if (sc->bond_db != NULL) {
			memcpy(sc->bond_db->local_csrk, local_csrk, 16);
			sc->bond_db->has_local_csrk = true;
		}
		explicit_bzero(local_csrk, sizeof(local_csrk));
	}

	explicit_bzero(kpdu, sizeof(kpdu));
}

/*
 * Store or update a bond in the database.
 * If a bond for this device already exists, update it in place.
 * Otherwise append a new entry.
 */
void
smp_bond_db_store(struct smp_bond_db *db, const struct smp_bond *bond)
{
	int i;

	if (db == NULL)
		return;

	/* Update existing bond for this device if present */
	for (i = 0; i < db->count; i++) {
		if (db->bonds[i].addr_type == bond->addr_type &&
		    memcmp(db->bonds[i].addr, bond->addr, 6) == 0) {
			db->bonds[i] = *bond;
			smp_bond_db_save(db);
			return;
		}
	}

	/* Append new bond, evicting the oldest if full */
	if (db->count < SMP_MAX_BONDS) {
		db->bonds[db->count++] = *bond;
	} else {
		/*
		 * Database full — evict the first (oldest) entry by
		 * shifting the array down, then store the new bond at
		 * the end.  This provides simple LRU/FIFO eviction.
		 */
		LOG_SMP(1, "bond database full (%d), evicting oldest bond",
		    SMP_MAX_BONDS);
		BLUED_LOG_SECURITY("bond eviction: db full (%d), "
		    "evicting addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "for new addr=%02x:%02x:%02x:%02x:%02x:%02x",
		    SMP_MAX_BONDS,
		    db->bonds[0].addr[5], db->bonds[0].addr[4],
		    db->bonds[0].addr[3], db->bonds[0].addr[2],
		    db->bonds[0].addr[1], db->bonds[0].addr[0],
		    bond->addr[5], bond->addr[4],
		    bond->addr[3], bond->addr[2],
		    bond->addr[1], bond->addr[0]);
		memmove(&db->bonds[0], &db->bonds[1],
		    (SMP_MAX_BONDS - 1) * sizeof(db->bonds[0]));
		/* Zero the last slot before writing new bond —
		 * scrubs the stale copy left by memmove */
		explicit_bzero(&db->bonds[SMP_MAX_BONDS - 1],
		    sizeof(db->bonds[0]));
		db->bonds[SMP_MAX_BONDS - 1] = *bond;
	}
	smp_bond_db_save(db);

	/* Probe fires after the bond is committed */
	{
		char a[18];
		bdaddr_t tmp;
		memcpy(&tmp, bond->addr, sizeof(tmp));
		bt_ntoa(&tmp, a);
		BLUED_PROBE_BOND_ADD(a, bond->is_sc);
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
	int ret = -1;
	int expected_pdus, i;
	struct timespec pair_start;

	clock_gettime(CLOCK_MONOTONIC, &pair_start);

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
	preq[1] = sc->io_capability;
	preq[2] = (sc->oob != NULL &&
	    (sc->oob->legacy != NULL || sc->oob->sc != NULL)) ?
	    0x01 : 0x00;
	preq[3] = SMP_AUTH_BONDING | SMP_AUTH_MITM | SMP_AUTH_SC |
	    SMP_AUTH_KEYPRESS | SMP_AUTH_CT2;
	preq[4] = 16;				/* Max encryption key size */
	preq[5] = SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY |
	    SMP_KEY_DIST_SIGN_KEY; /* Distribute our keys too */
	preq[6] = SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY |
	    SMP_KEY_DIST_SIGN_KEY;

	if (smp_log_send(sc, preq, sizeof(preq)) < 0)
		return (-1);
	LOG_SMP(1, "pairing request sent IO=%d auth=%02x", preq[1], preq[3]);

	/*
	 * Step 2: Receive Pairing Response
	 */
	n = smp_log_recv(sc, pres, sizeof(pres));
	if (smp_pairing_expired(&pair_start)) {
		uint8_t fail[2] = { SMP_PAIRING_FAILED, SMP_ERR_UNSPECIFIED_REASON };
		smp_log_send(sc, fail, 2);
		return (-1);
	}
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
		uint8_t fail[2] = { SMP_PAIRING_FAILED, SMP_ERR_CMD_NOT_SUPPORTED };
		smp_log_send(sc, fail, sizeof(fail));
		errno = EPROTO;
		return (-1);
	}
	LOG_SMP(1, "pairing response IO=%d auth=%02x", pres[1], pres[3]);

	{
		bool use_sc_log = (preq[3] & SMP_AUTH_SC) &&
		    (pres[3] & SMP_AUTH_SC);
		BLUED_LOG_SECURITY("pairing initiated "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "type=%d sc=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    sc->remote_addr_type, use_sc_log);
	}

	/*
	 * Validate encryption key size (Core Spec Vol 3 Part H 3.6.1).
	 * Max_Encryption_Key_Size must be in range [7,16].
	 * Negotiated size = min(ours, theirs).
	 *
	 * Post-KNOB Erratum 11838: SC pairing requires a minimum
	 * negotiated key size of 16 bytes.  Legacy pairing retains
	 * the original minimum of 7 bytes.
	 */
	{
		uint8_t peer_key_sz = pres[4];
		uint8_t neg_key_sz;
		bool is_sc = (preq[3] & SMP_AUTH_SC) &&
		    (pres[3] & SMP_AUTH_SC);

		if (peer_key_sz < 7 || peer_key_sz > 16) {
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_INVALID_PARAMETERS;
			smp_log_send(sc, pdu, 2);
			errno = EPROTO;
			return (-1);
		}
		neg_key_sz = (preq[4] < peer_key_sz) ? preq[4] : peer_key_sz;
		if (is_sc && neg_key_sz < 16) {
			LOG_SMP(1, "SC key size %d < 16, rejecting (KNOB)",
			    neg_key_sz);
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_ENCRYPTION_KEY_SIZE;
			smp_log_send(sc, pdu, 2);
			errno = EACCES;
			return (-1);
		} else if (!is_sc && neg_key_sz < sc->min_key_size) {
			LOG_SMP(1, "legacy key size %d < %d, rejecting",
			    neg_key_sz, sc->min_key_size);
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_ENCRYPTION_KEY_SIZE;
			smp_log_send(sc, pdu, 2);
			errno = EACCES;
			return (-1);
		}
	}

	/*
	 * sc_only: reject if peer does not support Secure Connections.
	 * Core Spec Vol 3 Part H Section 2.3.5.1: a device in SC Only
	 * mode shall reject pairing with a peer that does not support SC.
	 */
	if (sc->sc_only && !(pres[3] & SMP_AUTH_SC)) {
		LOG_SMP(1, "sc_only: peer does not support SC, rejecting");
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_AUTH_REQUIREMENTS;
		smp_log_send(sc, pdu, 2);
		errno = EACCES;
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
		/*
		 * Core Spec Vol 3 Part H Table 2.6 (legacy): OOB used
		 * when BOTH sides have OOB data.
		 * Table 2.7 (SC): OOB used when EITHER side has OOB data.
		 */
		bool have_oob = use_sc ?
		    (preq[2] != 0 || pres[2] != 0) :
		    (preq[2] != 0 && pres[2] != 0);
		int model;

		/*
		 * OOB takes priority over IO capabilities.
		 */
		if (have_oob)
			model = SMP_MODEL_OOB;
		else if (!use_mitm)
			model = SMP_MODEL_JUST_WORKS;
		else
			model = smp_select_model(preq[1], pres[1], use_sc);
		LOG_SMP(1, "model=%d sc=%d", model, use_sc);

		/*
		 * Reject pairing if peer's IO capability is out of
		 * range [0..4].  Core Spec Vol 3 Part H Table 3.4:
		 * values 0x05-0xFF are reserved.
		 */
		if (model == SMP_MODEL_INVALID) {
			LOG_SMP(1, "invalid peer IO capability %d, "
			    "rejecting", pres[1]);
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_INVALID_PARAMETERS;
			smp_log_send(sc, pdu, 2);
			errno = EPROTO;
			return (-1);
		}

		BLUED_PROBE_SMP_PAIR_START(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL), model);

		if (model == SMP_MODEL_OOB)
			BLUED_LOG_SECURITY("OOB pairing "
			    "addr=%02x:%02x:%02x:%02x:%02x:%02x sc=%d",
			    sc->remote_addr[5], sc->remote_addr[4],
			    sc->remote_addr[3], sc->remote_addr[2],
			    sc->remote_addr[1], sc->remote_addr[0],
			    use_sc);

		if (use_sc) {
			int rc;

			explicit_bzero(tk, sizeof(tk));
			if (model == SMP_MODEL_PASSKEY_ENTRY)
				rc = smp_pair_sc_passkey(sc, preq, pres);
			else
				rc = smp_pair_sc(sc, preq, pres, model);
			return (rc);
		}

		/*
		 * Legacy OOB: use peer's TK received out-of-band.
		 * Core Spec Vol 3 Part H Section 2.3.5.5
		 */
		if (model == SMP_MODEL_OOB) {
			if (sc->oob == NULL || sc->oob->legacy == NULL) {
				uint8_t fail[2] = { SMP_PAIRING_FAILED,
				    SMP_ERR_OOB_NOT_AVAILABLE };
				smp_log_send(sc, fail, 2);
				errno = ENOTSUP;
				return (-1);
			}
			memcpy(tk, sc->oob->legacy->tk, 16);
			LOG_SMP(1, "legacy OOB: TK set from OOB data");
			/* Fall through to legacy c1/s1 with this TK */
		}

		/* Legacy Passkey Entry: TK = passkey value */
		if (model == SMP_MODEL_PASSKEY_ENTRY) {
			uint32_t passkey = 0;
			bool kp_notify;
			bool we_display;

			if (sc->passkey_cb == NULL) {
				errno = ENOTSUP;
				return (-1);
			}
			/*
			 * Keypress Notification: both sides must have set the
			 * SMP_AUTH_KEYPRESS bit in their AuthReq fields.
			 * Core Spec Vol 3 Part H Section 3.5.8
			 */
			kp_notify = (preq[3] & SMP_AUTH_KEYPRESS) &&
			    (pres[3] & SMP_AUTH_KEYPRESS);

			/*
			 * Per Core Spec Vol 3 Part H Table 2.8, the
			 * passkey display/input role depends on both
			 * sides' IO capabilities.  When the responder
			 * has DisplayOnly or DisplayYesNo and the
			 * initiator has KeyboardOnly or KeyboardDisplay,
			 * the responder displays and we (initiator) input.
			 */
			we_display = true;
			if ((pres[1] == SMP_IO_DISPLAY_ONLY ||
			    pres[1] == SMP_IO_DISPLAY_YESNO) &&
			    (preq[1] == SMP_IO_KEYBOARD_ONLY ||
			    preq[1] == SMP_IO_KEYBOARD_DISPLAY))
				we_display = false;

			if (we_display)
				passkey = arc4random_uniform(1000000);
			if (kp_notify && !we_display)
				smp_send_keypress(sc,
				    SMP_KEYPRESS_STARTED);
			if (sc->passkey_cb(&passkey, we_display,
			    sc->passkey_cb_arg) < 0) {
				uint8_t fail[2] = { SMP_PAIRING_FAILED,
				    SMP_ERR_PASSKEY_ENTRY_FAILED };
				smp_log_send(sc, fail, 2);
				errno = ECANCELED;
				return (-1);
			}
			if (kp_notify && !we_display)
				smp_send_keypress(sc,
				    SMP_KEYPRESS_COMPLETED);
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
	if (smp_c1(tk, mrand, preq, pres, iat, sc->local_addr,
	    rat, sc->remote_addr, mconfirm) < 0) {
		errno = EIO;
		goto legacy_cleanup;
	}

	/*
	 * Step 4: Send Pairing Confirm
	 */
	pdu[0] = SMP_PAIRING_CONFIRM;
	memcpy(pdu + 1, mconfirm, 16);
	if (smp_log_send(sc, pdu, 17) < 0)
		goto legacy_cleanup;
	LOG_SMP(2, "legacy confirm sent");

	/*
	 * Receive Pairing Confirm from responder.
	 * The responder may send Keypress Notifications (opcode 0x0E) before
	 * the confirm when the responder is performing passkey entry.
	 * Consume and log them transparently.
	 */
	n = smp_recv_skip_keypress(sc, pdu, 17);
	if (smp_pairing_expired(&pair_start)) {
		uint8_t fail[2] = { SMP_PAIRING_FAILED, SMP_ERR_UNSPECIFIED_REASON };
		smp_log_send(sc, fail, 2);
		goto legacy_cleanup;
	}
	if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM) {
		if (n > 0 && pdu[0] == SMP_PAIRING_FAILED)
			errno = EACCES;
		else
			errno = EPROTO;
		goto legacy_cleanup;
	}
	memcpy(sconfirm, pdu + 1, 16);

	/*
	 * Step 5: Send Pairing Random
	 */
	pdu[0] = SMP_PAIRING_RANDOM;
	memcpy(pdu + 1, mrand, 16);
	if (smp_log_send(sc, pdu, 17) < 0)
		goto legacy_cleanup;

	/*
	 * Receive Pairing Random from responder
	 */
	n = smp_log_recv(sc, pdu, 17);
	if (smp_pairing_expired(&pair_start)) {
		uint8_t fail[2] = { SMP_PAIRING_FAILED, SMP_ERR_UNSPECIFIED_REASON };
		smp_log_send(sc, fail, 2);
		goto legacy_cleanup;
	}
	if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
		if (n > 0 && pdu[0] == SMP_PAIRING_FAILED)
			errno = EACCES;
		else
			errno = EPROTO;
		goto legacy_cleanup;
	}
	memcpy(srand, pdu + 1, 16);

	/*
	 * Step 6: Verify responder's confirm value
	 */
	if (smp_c1(tk, srand, preq, pres, iat, sc->local_addr,
	    rat, sc->remote_addr, verify) < 0) {
		errno = EIO;
		goto legacy_cleanup;
	}
	if (timingsafe_bcmp(verify, sconfirm, 16) != 0) {
		/* Send Pairing Failed */
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
		smp_log_send(sc, pdu, 2);
		errno = EACCES;
		goto legacy_cleanup;
	}
	LOG_SMP(1, "legacy confirm verified");

	/*
	 * Step 7: Derive STK
	 */
	if (smp_s1(tk, srand, mrand, stk) < 0) {
		errno = EIO;
		goto legacy_cleanup;
	}
	LOG_SMP(1, "STK derived, starting encryption");
#ifdef BLUED_DEBUG_KEYS
	if (blued_verbose >= 3)
		blued_hexdump("SMP", "s1 output (STK)", stk, 16);
#endif

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

		if (hci_send_raw_cmd(sc->hci_fd, HCI_OP_LE_START_ENCRYPTION, params,
		    sizeof(params)) < 0)
			goto legacy_cleanup;
	}

	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 5) < 0)
		goto legacy_cleanup;

	BLUED_PROBE_ENCRYPT_START(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL));
	BLUED_LOG_SECURITY("encryption active "
	    "addr=%02x:%02x:%02x:%02x:%02x:%02x handle=%d",
	    sc->remote_addr[5], sc->remote_addr[4],
	    sc->remote_addr[3], sc->remote_addr[2],
	    sc->remote_addr[1], sc->remote_addr[0],
	    sc->con_handle);

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
			if (setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv)) < 0)
				warn("setsockopt SO_RCVTIMEO");
		}

		/*
		 * Count expected key distribution PDUs from the
		 * negotiated Responder Key Distribution field (pres[6]).
		 * EncKey = 2 PDUs (Encryption Info + Master ID),
		 * IdKey = 2 PDUs (Identity Info + Identity Addr),
		 * SignKey = 1 PDU (Signing Info / CSRK).
		 * This avoids blocking for the full timeout when the
		 * responder has no keys to distribute.
		 */
		expected_pdus = 0;
		if (pres[6] & SMP_KEY_DIST_ENC_KEY)
			expected_pdus += 2;
		if (pres[6] & SMP_KEY_DIST_ID_KEY)
			expected_pdus += 2;
		if (pres[6] & SMP_KEY_DIST_SIGN_KEY)
			expected_pdus += 1;

		for (i = 0; i < expected_pdus; i++) {
			n = smp_log_recv(sc, pdu, sizeof(pdu));
			if (n < 1)
				break;

			switch (pdu[0]) {
			case SMP_ENCRYPTION_INFORMATION:
				if (n >= 17) {
					memcpy(bond.ltk, pdu + 1, 16);
					bond.has_ltk = true;
				}
				break;
			case SMP_CENTRAL_IDENTIFICATION:
				if (n >= 11) {
					bond.ediv = get_le16(pdu + 1);
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
			case SMP_SIGNING_INFORMATION:
				if (n >= 17) {
					memcpy(bond.csrk, pdu + 1, 16);
					bond.has_csrk = true;
					LOG_SMP(1, "stored peer CSRK");
				}
				break;
			default:
				break;
			}
		}

		/* Distribute initiator keys to responder */
		smp_distribute_init_keys(sc, preq, pres, false);

		/* Store bond */
		if (bond.has_ltk) {
			smp_bond_db_store(sc->bond_db, &bond);
			LOG_SMP(1, "bond stored");
			BLUED_LOG_SECURITY("bond stored "
			    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
			    "ltk=%d irk=%d lk=%d",
			    bond.addr[5], bond.addr[4],
			    bond.addr[3], bond.addr[2],
			    bond.addr[1], bond.addr[0],
			    bond.has_ltk, bond.has_irk,
			    bond.has_link_key);
		}

		BLUED_LOG_SECURITY("pairing complete "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "sc=%d bonded=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    0, bond.has_ltk);
		explicit_bzero(&bond, sizeof(bond));
	}

	ret = 0;

legacy_cleanup:
	BLUED_PROBE_SMP_PAIR_DONE(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL), ret);
	if (ret != 0)
		BLUED_LOG_SECURITY("pairing failed "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x reason=%02x",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    (unsigned)errno);
	explicit_bzero(tk, sizeof(tk));
	explicit_bzero(mrand, sizeof(mrand));
	explicit_bzero(srand, sizeof(srand));
	explicit_bzero(stk, sizeof(stk));
	return (ret);
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

	put_le16(params, sc->con_handle);
	memcpy(params + 2, &bond->rand, 8);
	put_le16(params + 10, bond->ediv);
	memcpy(params + 12, bond->ltk, 16);

	if (hci_send_raw_cmd(sc->hci_fd, HCI_OP_LE_START_ENCRYPTION, params, sizeof(params)) < 0)
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
bool
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

	if (smp_aes128(irk, plaintext, cipher) < 0)
		return (false);

	return (timingsafe_bcmp(cipher, hash_expected, 3) == 0);
}

/*
 * Generate a Resolvable Private Address (RPA) from an IRK.
 *
 * Core Spec Vol 3 Part H Section 2.2.2:
 *   prand = random 24-bit value with upper 2 bits = 01
 *   hash = ah(IRK, prand) = E(IRK, padding || prand)[0..2]
 *   RPA = hash(3) || prand(3)
 */
void
smp_generate_rpa(const uint8_t irk[16], uint8_t rpa[6])
{
	uint8_t prand[3], plaintext[16], cipher[16];

	/* Generate random prand with upper 2 bits = 01 (RPA marker) */
	arc4random_buf(prand, sizeof(prand));
	prand[2] = (prand[2] & 0x3F) | 0x40;

	/* ah(IRK, prand) */
	memset(plaintext, 0, sizeof(plaintext));
	plaintext[0] = prand[0];
	plaintext[1] = prand[1];
	plaintext[2] = prand[2];

	if (smp_aes128(irk, plaintext, cipher) < 0) {
		/* Fallback: all-zero hash (will fail resolution but not crash) */
		memset(rpa, 0, 6);
		return;
	}

	/* RPA = hash[0..2] || prand[0..2] */
	rpa[0] = cipher[0];
	rpa[1] = cipher[1];
	rpa[2] = cipher[2];
	rpa[3] = prand[0];
	rpa[4] = prand[1];
	rpa[5] = prand[2];
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
	int i;

	/* Exact match first */
	for (i = 0; i < db->count; i++) {
		if (db->bonds[i].addr_type == addr_type &&
		    memcmp(db->bonds[i].addr, addr, 6) == 0) {
			LOG_SMP(1, "bond found (exact match)");
			return (&db->bonds[i]);
		}
	}

	/* Try IRK-based RPA resolution for random addresses */
	if (addr_type == BDADDR_LE_RANDOM) {
		for (i = 0; i < db->count; i++) {
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
	int ret = -1;
	int i;
	struct timespec pair_start;

	clock_gettime(CLOCK_MONOTONIC, &pair_start);

	if (sc->passkey_cb == NULL) {
		errno = ENOTSUP;
		return (-1);
	}

	/*
	 * Determine passkey display/input role per Core Spec
	 * Vol 3 Part H Table 2.8.  When the responder has
	 * DisplayOnly or DisplayYesNo and we (initiator) have
	 * KeyboardOnly or KeyboardDisplay, the responder displays
	 * and we input.
	 */
	{
		bool we_display = true;

		if ((pres[1] == SMP_IO_DISPLAY_ONLY ||
		    pres[1] == SMP_IO_DISPLAY_YESNO) &&
		    (preq[1] == SMP_IO_KEYBOARD_ONLY ||
		    preq[1] == SMP_IO_KEYBOARD_DISPLAY))
			we_display = false;

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
	smp_swap_buf(pdu + 1, our_pk_raw + 1, 32);
	smp_swap_buf(pdu + 33, our_pk_raw + 33, 32);
	/* Store x-coord in LE for crypto functions */
	memcpy(pka_le, pdu + 1, 32);
	if (smp_log_send(sc, pdu, 65) < 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}

	/* Receive peer PK (wire = LE) */
	n = smp_log_recv(sc, pdu, 65);
	if (smp_pairing_expired(&pair_start)) {
		uint8_t f[2] = { SMP_PAIRING_FAILED, SMP_ERR_UNSPECIFIED_REASON };
		smp_log_send(sc, f, 2);
		EVP_PKEY_free(our_key);
		return (-1);
	}
	if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY) {
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
			smp_swap_buf(dhkey_le, dhkey_be, 32);
			explicit_bzero(dhkey_be, sizeof(dhkey_be));
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
	for (i = 0; i < 20; i++) {
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
		if (smp_log_send(sc, pdu, 17) < 0)
			goto sc_passkey_cleanup;

		/* Receive responder confirm Cbi */
		n = smp_log_recv(sc, pdu, 17);
		if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM) {
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

		/* Receive responder nonce Nbi */
		n = smp_log_recv(sc, pdu, 17);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			goto sc_passkey_cleanup;
		}
		memcpy(nbi, pdu + 1, 16);

		/* Verify Cbi = f4(PKbx, PKax, Nbi, rbi) */
		smp_f4(pkb_le, pka_le, nbi, ri, cbi_verify);
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

	/*
	 * Authentication Stage 2: same as Just Works SC.
	 * MacKey || LTK = f5(DHKey, Na, Nb, A1, A2)
	 * Ea = f6(MacKey, Na, Nb, ra, IOcapA, A1, A2)
	 * Eb = f6(MacKey, Nb, Na, ra, IOcapB, A2, A1)
	 * (ra = rb = passkey for Passkey Entry per Table 2.2)
	 */
	smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
#ifdef BLUED_DEBUG_KEYS
	if (blued_verbose >= 3)
		blued_hexdump("SMP", "f5 output (LTK)", ltk, 16);
#endif

	smp_f6(mackey, na, nb, ra, iocap_a, a1, a2, ea);
#ifdef BLUED_DEBUG_KEYS
	if (blued_verbose >= 3)
		blued_hexdump("SMP", "f6 output (Ea)", ea, 16);
#endif
	smp_f6(mackey, nb, na, ra, iocap_b, a2, a1, eb);
#ifdef BLUED_DEBUG_KEYS
	if (blued_verbose >= 3)
		blued_hexdump("SMP", "f6 output (Eb)", eb, 16);
#endif

	/* Send Ea, receive and verify Eb */
	pdu[0] = SMP_PAIRING_DHKEY_CHECK;
	memcpy(pdu + 1, ea, 16);
	if (smp_log_send(sc, pdu, 17) < 0)
		goto sc_passkey_cleanup;

	n = smp_log_recv(sc, pdu, 17);
	if (smp_pairing_expired(&pair_start)) {
		uint8_t f[2] = { SMP_PAIRING_FAILED, SMP_ERR_UNSPECIFIED_REASON };
		smp_log_send(sc, f, 2);
		goto sc_passkey_cleanup;
	}
	if (n < 17 || pdu[0] != SMP_PAIRING_DHKEY_CHECK) {
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
		    sizeof(params)) < 0)
			goto sc_passkey_cleanup;
	}

	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 5) < 0)
		goto sc_passkey_cleanup;

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
		memcpy(bond.ltk, ltk, 16);
		bond.has_ltk = true;
		bond.is_sc = true;
		bond.is_mitm = true; /* Passkey Entry provides MITM */

		/* Receive key distribution from responder (SC: IdKey + SignKey) */
		{
			int exp = 0;
			if (pres[6] & SMP_KEY_DIST_ID_KEY)
				exp += 2;
			if (pres[6] & SMP_KEY_DIST_SIGN_KEY)
				exp += 1;
			for (i = 0; i < exp; i++) {
				struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
				if (setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
				    &tv, sizeof(tv)) < 0)
					warn("setsockopt SO_RCVTIMEO");
				n = smp_log_recv(sc, pdu, sizeof(pdu));
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
				} else if (pdu[0] == SMP_SIGNING_INFORMATION &&
				    n >= 17) {
					memcpy(bond.csrk, pdu + 1, 16);
					bond.has_csrk = true;
					LOG_SMP(1, "stored peer CSRK");
				}
			}
		}

		/* Distribute initiator keys to responder */
		smp_distribute_init_keys(sc, preq, pres, true);

		/* Derive BR/EDR Link Key via CTKD (BT 4.2+) */
		smp_ctkd_derive_link_key(&bond,
		    (preq[3] & SMP_AUTH_CT2) && (pres[3] & SMP_AUTH_CT2));

		smp_bond_db_store(sc->bond_db, &bond);
		BLUED_LOG_SECURITY("bond stored "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "ltk=%d irk=%d lk=%d",
		    bond.addr[5], bond.addr[4],
		    bond.addr[3], bond.addr[2],
		    bond.addr[1], bond.addr[0],
		    bond.has_ltk, bond.has_irk, bond.has_link_key);
		BLUED_LOG_SECURITY("pairing complete "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "sc=%d bonded=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    1, bond.has_ltk);
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
 * Bond database at-rest encryption.
 *
 * v1 format ("BOND"): plaintext header + bond array + local IRK trailer.
 * v2 format ("BONDE", version 2): AES-256-CBC encrypted payload (legacy).
 * v3 format ("BONDE", version 3): AES-256-GCM with static PBKDF2 salt
 *     (legacy -- accepted on load, never written).
 * v4 format ("BONDE", version 4): AES-256-GCM authenticated encryption,
 *     key derived from kern.hostuuid via PBKDF2 with a random 128-bit
 *     per-file salt.  A random 96-bit nonce (IV) and 128-bit authentication
 *     tag are also stored in the file header so each save produces different
 *     ciphertext with tamper detection.
 *
 * On load, v1, v2, and v3 files are accepted for backward compatibility.
 * On save, v4 (AES-256-GCM + random salt) is always written.  If hostuuid
 * is unavailable, the save is refused to prevent plaintext key exposure.
 */
#define BOND_MAGIC_PLAIN	"BOND"		/* 4 bytes, v1 plaintext */
#define BOND_MAGIC_ENC		"BONDE"		/* 5 bytes, v2/v3/v4 encrypted */
#define BOND_MAGIC_PLAIN_LEN	4
#define BOND_MAGIC_ENC_LEN	5
#define BOND_ENC_VERSION	4		/* AES-256-GCM + random salt */
#define BOND_ENC_VERSION_GCM	3		/* legacy AES-256-GCM, static salt */
#define BOND_ENC_VERSION_CBC	2		/* legacy AES-256-CBC */
#define BOND_ENC_PBKDF2_ITER	100000
#define BOND_ENC_PBKDF2_SALT	"blued-bond-db"		/* v3 static salt */
#define BOND_ENC_PBKDF2_SALTLEN	13			/* v3 static salt len */
#define BOND_ENC_KEYLEN		32		/* AES-256 key */
#define BOND_ENC_IVLEN		12		/* AES-256-GCM IV (96-bit nonce) */
#define BOND_ENC_TAGLEN		16		/* AES-256-GCM authentication tag */
#define BOND_ENC_SALTLEN	16		/* random per-file PBKDF2 salt */
#define BOND_ENC_CBC_IVLEN	16		/* legacy AES-256-CBC IV */

/*
 * Derive an AES-256 encryption key from the machine's kern.hostuuid.
 * The caller provides a salt and its length; v4 uses a random per-file
 * salt, while v3 (legacy) passes the static BOND_ENC_PBKDF2_SALT.
 * Returns 0 on success, -1 if hostuuid is unavailable.
 */
static int
bond_db_derive_key(uint8_t key[BOND_ENC_KEYLEN],
    const uint8_t *salt, size_t salt_len)
{
	char hostuuid[64];
	size_t len = sizeof(hostuuid);

	if (sysctlbyname("kern.hostuuid", hostuuid, &len, NULL, 0) != 0) {
		warn("sysctlbyname kern.hostuuid");
		return (-1);
	}

	/* Strip trailing newline if present */
	while (len > 0 && (hostuuid[len - 1] == '\n' ||
	    hostuuid[len - 1] == '\0'))
		len--;

	if (len == 0) {
		warnx("kern.hostuuid is empty");
		return (-1);
	}

	if (PKCS5_PBKDF2_HMAC(hostuuid, (int)len,
	    salt, (int)salt_len,
	    BOND_ENC_PBKDF2_ITER, EVP_sha256(),
	    BOND_ENC_KEYLEN, key) != 1) {
		warnx("PKCS5_PBKDF2_HMAC failed");
		explicit_bzero(hostuuid, sizeof(hostuuid));
		return (-1);
	}

	explicit_bzero(hostuuid, sizeof(hostuuid));
	return (0);
}

/*
 * Encrypt a plaintext buffer with AES-256-GCM (authenticated encryption).
 * Caller provides key and iv.  On success, *out is malloc'd ciphertext,
 * *out_len is set, and the authentication tag is written to tag[].
 * Returns 0 on success, -1 on failure.
 */
static int
bond_db_encrypt(const uint8_t *plaintext, size_t pt_len,
    const uint8_t key[BOND_ENC_KEYLEN], const uint8_t iv[BOND_ENC_IVLEN],
    uint8_t **out, size_t *out_len, uint8_t tag[BOND_ENC_TAGLEN])
{
	EVP_CIPHER_CTX *ctx;
	int outl, final_outl;
	uint8_t *ct;

	ct = malloc(pt_len);
	if (ct == NULL)
		return (-1);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		free(ct);
		return (-1);
	}

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
		warnx("EVP_EncryptInit_ex failed (bond encrypt)");
		goto fail;
	}
	if (EVP_EncryptUpdate(ctx, ct, &outl, plaintext, (int)pt_len) != 1) {
		warnx("EVP_EncryptUpdate failed (bond encrypt)");
		goto fail;
	}
	if (EVP_EncryptFinal_ex(ctx, ct + outl, &final_outl) != 1) {
		warnx("EVP_EncryptFinal_ex failed (bond encrypt)");
		goto fail;
	}
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
	    BOND_ENC_TAGLEN, tag) != 1) {
		warnx("EVP_CTRL_GCM_GET_TAG failed (bond encrypt)");
		goto fail;
	}

	*out = ct;
	*out_len = (size_t)(outl + final_outl);
	EVP_CIPHER_CTX_free(ctx);
	return (0);

fail:
	EVP_CIPHER_CTX_free(ctx);
	explicit_bzero(ct, pt_len);
	free(ct);
	return (-1);
}

/*
 * Decrypt a ciphertext buffer with AES-256-GCM (authenticated decryption).
 * The authentication tag must be provided; DecryptFinal will fail if the
 * tag does not match (tampered or wrong key).
 * On success, *out is malloc'd plaintext and *out_len is set.
 * Returns 0 on success, -1 on failure (wrong key, tampered, corrupt).
 */
static int
bond_db_decrypt(const uint8_t *ciphertext, size_t ct_len,
    const uint8_t key[BOND_ENC_KEYLEN], const uint8_t iv[BOND_ENC_IVLEN],
    const uint8_t tag[BOND_ENC_TAGLEN],
    uint8_t **out, size_t *out_len)
{
	EVP_CIPHER_CTX *ctx;
	int outl, final_outl;
	uint8_t *pt;

	if (ct_len == 0)
		return (-1);

	pt = malloc(ct_len);
	if (pt == NULL)
		return (-1);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		free(pt);
		return (-1);
	}

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
		warnx("EVP_DecryptInit_ex failed (bond decrypt)");
		goto fail;
	}
	if (EVP_DecryptUpdate(ctx, pt, &outl, ciphertext, (int)ct_len) != 1) {
		warnx("EVP_DecryptUpdate failed (bond decrypt)");
		goto fail;
	}
	/* Set the expected authentication tag before Finalize */
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
	    BOND_ENC_TAGLEN, (void *)(uintptr_t)tag) != 1) {
		warnx("EVP_CTRL_GCM_SET_TAG failed (bond decrypt)");
		goto fail;
	}
	if (EVP_DecryptFinal_ex(ctx, pt + outl, &final_outl) != 1) {
		warnx("bond db: authentication failed (wrong key or tampered file)");
		goto fail;
	}

	*out = pt;
	*out_len = (size_t)(outl + final_outl);
	EVP_CIPHER_CTX_free(ctx);
	return (0);

fail:
	EVP_CIPHER_CTX_free(ctx);
	explicit_bzero(pt, ct_len);
	free(pt);
	return (-1);
}

/*
 * Decrypt a ciphertext buffer with AES-256-CBC (legacy v2 format).
 * Kept for backward compatibility with v2 bond database files.
 * On success, *out is malloc'd plaintext and *out_len is set.
 * Returns 0 on success, -1 on failure (wrong key, corrupt data).
 */
static int
bond_db_decrypt_cbc(const uint8_t *ciphertext, size_t ct_len,
    const uint8_t key[BOND_ENC_KEYLEN],
    const uint8_t iv[BOND_ENC_CBC_IVLEN],
    uint8_t **out, size_t *out_len)
{
	EVP_CIPHER_CTX *ctx;
	int outl, final_outl;
	uint8_t *pt;

	if (ct_len == 0)
		return (-1);

	pt = malloc(ct_len);
	if (pt == NULL)
		return (-1);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		free(pt);
		return (-1);
	}

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
		warnx("EVP_DecryptInit_ex failed (bond decrypt cbc)");
		goto fail;
	}
	if (EVP_DecryptUpdate(ctx, pt, &outl, ciphertext, (int)ct_len) != 1) {
		warnx("EVP_DecryptUpdate failed (bond decrypt cbc)");
		goto fail;
	}
	if (EVP_DecryptFinal_ex(ctx, pt + outl, &final_outl) != 1) {
		warnx("EVP_DecryptFinal_ex failed (bond decrypt cbc)");
		goto fail;
	}

	*out = pt;
	*out_len = (size_t)(outl + final_outl);
	EVP_CIPHER_CTX_free(ctx);
	return (0);

fail:
	EVP_CIPHER_CTX_free(ctx);
	explicit_bzero(pt, ct_len);
	free(pt);
	return (-1);
}

/*
 * Load bond database from file descriptor.
 *
 * Supports four on-disk formats:
 *   v1 ("BOND"):           plaintext header (8 bytes) + bond array + local IRK
 *   v2 ("BONDE", ver 2):   AES-256-CBC encrypted (legacy)
 *   v3 ("BONDE", ver 3):   AES-256-GCM, static PBKDF2 salt (legacy)
 *   v4 ("BONDE", ver 4):   AES-256-GCM, random per-file PBKDF2 salt
 *
 * v1, v2, and v3 files are loaded for backward compatibility; the next
 * save will automatically upgrade to v4 (AES-256-GCM + random salt).
 */
int
smp_bond_db_load(struct smp_bond_db *db, int fd)
{
	ssize_t n;

	db->fd = fd;
	db->count = 0;
	db->has_local_irk = false;
	memset(db->local_irk, 0, sizeof(db->local_irk));

	/* Ensure owner-only permissions on bond file (contains LTK/IRK) */
	fchmod(fd, 0600);

	/*
	 * Read the first 5 bytes to distinguish:
	 *   "BONDE" — v2/v3/v4 encrypted format
	 *   "BOND"  — v1 plaintext format (first 4 bytes match)
	 *   other   — empty/legacy/corrupt, start fresh
	 */
	{
		uint8_t magic[BOND_MAGIC_ENC_LEN];

		flock(fd, LOCK_EX);

		n = pread(fd, magic, sizeof(magic), 0);
		if (n >= (ssize_t)BOND_MAGIC_ENC_LEN &&
		    memcmp(magic, BOND_MAGIC_ENC, BOND_MAGIC_ENC_LEN) == 0) {
			/*
			 * v2/v3/v4 encrypted format:
			 *   "BONDE" (5)  magic
			 *   uint32_t     version (LE) — 2=CBC, 3=GCM, 4=GCM+salt
			 *
			 * v2 (AES-256-CBC, legacy):
			 *   uint8_t[16]  iv
			 *   uint32_t     ciphertext_len (LE)
			 *   uint8_t[]    ciphertext
			 *
			 * v3 (AES-256-GCM, static salt):
			 *   uint8_t[12]  iv (96-bit nonce)
			 *   uint8_t[16]  tag (authentication tag)
			 *   uint32_t     ciphertext_len (LE)
			 *   uint8_t[]    ciphertext
			 *
			 * v4 (AES-256-GCM, random per-file salt):
			 *   uint8_t[16]  salt (PBKDF2 salt)
			 *   uint8_t[12]  iv (96-bit nonce)
			 *   uint8_t[16]  tag (authentication tag)
			 *   uint32_t     ciphertext_len (LE)
			 *   uint8_t[]    ciphertext
			 */
			uint32_t version, ct_len;
			uint8_t key[BOND_ENC_KEYLEN];
			uint8_t *ct = NULL, *pt = NULL;
			size_t pt_len;
			uint8_t ver_buf[4];
			off_t data_off;

			/* Read the version field first */
			n = pread(fd, ver_buf, 4, BOND_MAGIC_ENC_LEN);
			if (n < 4) {
				warnx("bond db: truncated encrypted header");
				flock(fd, LOCK_UN);
				db->count = 0;
				return (0);
			}

			memcpy(&version, ver_buf, 4);
			version = le32toh(version);

			if (version == BOND_ENC_VERSION) {
				/*
				 * v4 (AES-256-GCM + random salt):
				 * read 16-byte salt, 12-byte IV,
				 * 16-byte tag, 4-byte ct_len
				 */
				uint8_t v4_hdr[BOND_ENC_SALTLEN +
				    BOND_ENC_IVLEN + BOND_ENC_TAGLEN + 4];
				uint8_t file_salt[BOND_ENC_SALTLEN];
				uint8_t iv[BOND_ENC_IVLEN];
				uint8_t tag[BOND_ENC_TAGLEN];

				n = pread(fd, v4_hdr, sizeof(v4_hdr),
				    BOND_MAGIC_ENC_LEN + 4);
				if (n < (ssize_t)sizeof(v4_hdr)) {
					warnx("bond db: truncated v4 header");
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				memcpy(file_salt, v4_hdr, BOND_ENC_SALTLEN);
				memcpy(iv, v4_hdr + BOND_ENC_SALTLEN,
				    BOND_ENC_IVLEN);
				memcpy(tag,
				    v4_hdr + BOND_ENC_SALTLEN + BOND_ENC_IVLEN,
				    BOND_ENC_TAGLEN);
				memcpy(&ct_len,
				    v4_hdr + BOND_ENC_SALTLEN +
				    BOND_ENC_IVLEN + BOND_ENC_TAGLEN, 4);
				ct_len = le32toh(ct_len);

				if (ct_len == 0 || ct_len > 1024 * 1024) {
					warnx("bond db: invalid ciphertext "
					    "length %u", ct_len);
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				ct = malloc(ct_len);
				if (ct == NULL) {
					flock(fd, LOCK_UN);
					return (-1);
				}

				data_off = BOND_MAGIC_ENC_LEN + 4 +
				    (off_t)sizeof(v4_hdr);
				n = pread(fd, ct, ct_len, data_off);
				if (n < (ssize_t)ct_len) {
					warnx("bond db: truncated ciphertext");
					free(ct);
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				if (bond_db_derive_key(key, file_salt,
				    BOND_ENC_SALTLEN) != 0) {
					warnx("bond db: cannot derive key, "
					    "encrypted bonds inaccessible");
					free(ct);
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				if (bond_db_decrypt(ct, ct_len, key, iv,
				    tag, &pt, &pt_len) != 0) {
					warnx("bond db: decryption failed "
					    "(wrong machine or tampered file)");
					BLUED_LOG_SECURITY("bond db decryption "
					    "failed - file may have been copied "
					    "from another machine or is tampered");
					explicit_bzero(key, sizeof(key));
					free(ct);
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}
			} else if (version == BOND_ENC_VERSION_GCM) {
				/*
				 * v3 (AES-256-GCM, static salt):
				 * read 12-byte IV, 16-byte tag,
				 * 4-byte ct_len
				 */
				uint8_t v3_hdr[BOND_ENC_IVLEN +
				    BOND_ENC_TAGLEN + 4];
				uint8_t iv[BOND_ENC_IVLEN];
				uint8_t tag[BOND_ENC_TAGLEN];

				n = pread(fd, v3_hdr, sizeof(v3_hdr),
				    BOND_MAGIC_ENC_LEN + 4);
				if (n < (ssize_t)sizeof(v3_hdr)) {
					warnx("bond db: truncated v3 header");
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				memcpy(iv, v3_hdr, BOND_ENC_IVLEN);
				memcpy(tag, v3_hdr + BOND_ENC_IVLEN,
				    BOND_ENC_TAGLEN);
				memcpy(&ct_len,
				    v3_hdr + BOND_ENC_IVLEN + BOND_ENC_TAGLEN,
				    4);
				ct_len = le32toh(ct_len);

				if (ct_len == 0 || ct_len > 1024 * 1024) {
					warnx("bond db: invalid ciphertext "
					    "length %u", ct_len);
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				ct = malloc(ct_len);
				if (ct == NULL) {
					flock(fd, LOCK_UN);
					return (-1);
				}

				data_off = BOND_MAGIC_ENC_LEN + 4 +
				    (off_t)sizeof(v3_hdr);
				n = pread(fd, ct, ct_len, data_off);
				if (n < (ssize_t)ct_len) {
					warnx("bond db: truncated ciphertext");
					free(ct);
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				if (bond_db_derive_key(key,
				    (const uint8_t *)BOND_ENC_PBKDF2_SALT,
				    BOND_ENC_PBKDF2_SALTLEN) != 0) {
					warnx("bond db: cannot derive key, "
					    "encrypted bonds inaccessible");
					free(ct);
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				if (bond_db_decrypt(ct, ct_len, key, iv,
				    tag, &pt, &pt_len) != 0) {
					warnx("bond db: decryption failed "
					    "(wrong machine or tampered file)");
					BLUED_LOG_SECURITY("bond db decryption "
					    "failed - file may have been copied "
					    "from another machine or is tampered");
					explicit_bzero(key, sizeof(key));
					free(ct);
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				LOG_SMP(1, "loaded v3 (GCM, static salt) "
				    "bond db, will upgrade to v4 on next save");
			} else if (version == BOND_ENC_VERSION_CBC) {
				/*
				 * v2 (AES-256-CBC, legacy): read 16-byte IV,
				 * 4-byte ct_len
				 */
				uint8_t v2_hdr[BOND_ENC_CBC_IVLEN + 4];
				uint8_t iv_cbc[BOND_ENC_CBC_IVLEN];

				n = pread(fd, v2_hdr, sizeof(v2_hdr),
				    BOND_MAGIC_ENC_LEN + 4);
				if (n < (ssize_t)sizeof(v2_hdr)) {
					warnx("bond db: truncated v2 header");
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				memcpy(iv_cbc, v2_hdr, BOND_ENC_CBC_IVLEN);
				memcpy(&ct_len,
				    v2_hdr + BOND_ENC_CBC_IVLEN, 4);
				ct_len = le32toh(ct_len);

				if (ct_len == 0 || ct_len > 1024 * 1024) {
					warnx("bond db: invalid ciphertext "
					    "length %u", ct_len);
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				ct = malloc(ct_len);
				if (ct == NULL) {
					flock(fd, LOCK_UN);
					return (-1);
				}

				data_off = BOND_MAGIC_ENC_LEN + 4 +
				    (off_t)sizeof(v2_hdr);
				n = pread(fd, ct, ct_len, data_off);
				if (n < (ssize_t)ct_len) {
					warnx("bond db: truncated ciphertext");
					free(ct);
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				if (bond_db_derive_key(key,
				    (const uint8_t *)BOND_ENC_PBKDF2_SALT,
				    BOND_ENC_PBKDF2_SALTLEN) != 0) {
					warnx("bond db: cannot derive key, "
					    "encrypted bonds inaccessible");
					free(ct);
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				if (bond_db_decrypt_cbc(ct, ct_len, key,
				    iv_cbc, &pt, &pt_len) != 0) {
					warnx("bond db: decryption failed "
					    "(wrong machine or corrupt file)");
					BLUED_LOG_SECURITY("bond db decryption "
					    "failed - file may have been copied "
					    "from another machine or is corrupt");
					explicit_bzero(key, sizeof(key));
					free(ct);
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				LOG_SMP(1, "loaded v2 (CBC) bond db, "
				    "will upgrade to v4 (GCM+salt) on next save");
			} else {
				warnx("bond db: unknown encrypted version %u",
				    version);
				flock(fd, LOCK_UN);
				db->count = 0;
				return (0);
			}

			explicit_bzero(key, sizeof(key));
			free(ct);

			/*
			 * Parse decrypted plaintext payload:
			 *   uint32_t     count (LE)
			 *   uint32_t     bond_struct_size (LE) [v5+, absent in old files]
			 *   smp_bond[]   bonds[count]
			 *   uint8_t      has_local_irk
			 *   uint8_t[16]  local_irk (if has_local_irk)
			 */
			{
				uint32_t count;
				uint32_t stored_bond_size;
				size_t bond_data_len, offset;
				size_t hdr_size;
				bool has_stored_size;

				if (pt_len < sizeof(uint32_t)) {
					explicit_bzero(pt, pt_len);
					free(pt);
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				memcpy(&count, pt, sizeof(uint32_t));
				count = le32toh(count);
				if (count > SMP_MAX_BONDS)
					count = SMP_MAX_BONDS;

				/*
				 * Detect whether the bond_struct_size field
				 * is present.  Old files have only count + bonds.
				 * New files have count + bond_struct_size + bonds.
				 * Heuristic: if the second uint32_t is a
				 * plausible struct size (64..4096), treat it as
				 * the size field.  Otherwise assume old format
				 * with stored_bond_size == current size.
				 */
				has_stored_size = false;
				stored_bond_size = (uint32_t)sizeof(struct smp_bond);
				if (pt_len >= 2 * sizeof(uint32_t)) {
					uint32_t candidate;
					memcpy(&candidate, pt + sizeof(uint32_t),
					    sizeof(uint32_t));
					candidate = le32toh(candidate);
					if (candidate >= 64 && candidate <= 4096) {
						stored_bond_size = candidate;
						has_stored_size = true;
					}
				}

				hdr_size = sizeof(uint32_t) +
				    (has_stored_size ? sizeof(uint32_t) : 0);
				bond_data_len = (size_t)count * stored_bond_size;
				if (pt_len < hdr_size + bond_data_len) {
					warnx("bond db: decrypted payload "
					    "too small for %u bonds", count);
					explicit_bzero(pt, pt_len);
					free(pt);
					flock(fd, LOCK_UN);
					db->count = 0;
					return (0);
				}

				if (stored_bond_size != sizeof(struct smp_bond)) {
					warnx("bond db: struct size migration "
					    "(stored=%u, current=%zu) — "
					    "migrating %u bonds",
					    stored_bond_size,
					    sizeof(struct smp_bond), count);
				}

				/*
				 * Copy each bond, handling size differences:
				 *  - stored < current: zero-fill new fields
				 *  - stored > current: read only current size
				 */
				memset(db->bonds, 0, sizeof(db->bonds));
				{
					size_t copy_size;
					uint32_t bi;
					const uint8_t *src;

					copy_size = stored_bond_size <
					    sizeof(struct smp_bond) ?
					    stored_bond_size :
					    sizeof(struct smp_bond);
					src = pt + hdr_size;
					for (bi = 0; bi < count; bi++) {
						memcpy(&db->bonds[bi], src,
						    copy_size);
						src += stored_bond_size;
					}
				}
				db->count = (int)count;

				/* Parse local IRK trailer if present */
				offset = hdr_size + bond_data_len;
				if (offset < pt_len && pt[offset] != 0) {
					if (offset + 1 + 16 <= pt_len) {
						memcpy(db->local_irk,
						    pt + offset + 1, 16);
						db->has_local_irk = true;
					}
				}
			}

			explicit_bzero(pt, pt_len);
			free(pt);
			flock(fd, LOCK_UN);

			BLUED_PROBE_BOND_LOAD(db->count);
			LOG_SMP(1, "loaded %d bonds from encrypted database",
			    db->count);
			return (0);
		}

		if (n >= (ssize_t)BOND_MAGIC_PLAIN_LEN &&
		    memcmp(magic, BOND_MAGIC_PLAIN, BOND_MAGIC_PLAIN_LEN) == 0) {
			/*
			 * v1 plaintext format:
			 *   "BOND" (4)   magic
			 *   uint32_t     record_size (LE)
			 *   smp_bond[]   bonds
			 *   uint8_t[17]  local IRK trailer (optional)
			 *
			 * On next save, this will be auto-upgraded to v4.
			 */
			uint8_t hdr[8];
			uint32_t rec_size;

			/* Re-read the full 8-byte v1 header */
			n = pread(fd, hdr, sizeof(hdr), 0);
			if (n < (ssize_t)sizeof(hdr)) {
				flock(fd, LOCK_UN);
				db->count = 0;
				return (0);
			}

			memcpy(&rec_size, hdr + 4, 4);
			rec_size = le32toh(rec_size);

			if (rec_size != sizeof(struct smp_bond)) {
				/* Struct size mismatch — incompatible */
				flock(fd, LOCK_UN);
				db->count = 0;
				return (0);
			}

			n = pread(fd, db->bonds, sizeof(db->bonds),
			    sizeof(hdr));
			if (n < 0) {
				flock(fd, LOCK_UN);
				return (-1);
			}
			if ((n % sizeof(struct smp_bond)) != 0) {
				flock(fd, LOCK_UN);
				db->count = 0;
				return (0);
			}
			db->count = n / sizeof(struct smp_bond);
			if (db->count > SMP_MAX_BONDS)
				db->count = SMP_MAX_BONDS;

			/* Local IRK trailer */
			{
				off_t irk_off;
				uint8_t irk_rec[17];

				irk_off = (off_t)(sizeof(hdr) +
				    db->count * sizeof(struct smp_bond));
				n = pread(fd, irk_rec, sizeof(irk_rec),
				    irk_off);
				if (n == (ssize_t)sizeof(irk_rec) &&
				    irk_rec[0] != 0) {
					memcpy(db->local_irk, irk_rec + 1, 16);
					db->has_local_irk = true;
				}
			}

			flock(fd, LOCK_UN);

			BLUED_PROBE_BOND_LOAD(db->count);
			LOG_SMP(1, "loaded %d bonds from plaintext database "
			    "(will auto-upgrade to encrypted on next save)",
			    db->count);
			BLUED_LOG_SECURITY("bond db loaded in plaintext v1 "
			    "format - will encrypt on next save");
			return (0);
		}

		/*
		 * No valid header — empty, legacy, or corrupt.
		 * Start fresh; bonds will be re-created on next pairing.
		 */
		flock(fd, LOCK_UN);
		db->count = 0;
		return (0);
	}
}

/*
 * Save bond database to file descriptor.
 *
 * Always writes encrypted v4 format ("BONDE", AES-256-GCM with a random
 * per-file PBKDF2 salt).  Refuses to save if key derivation fails --
 * plaintext storage of bond keys is a security risk.
 */
int
smp_bond_db_save(struct smp_bond_db *db)
{
	uint8_t key[BOND_ENC_KEYLEN];
	uint8_t file_salt[BOND_ENC_SALTLEN];
	size_t bond_len, irk_len, pt_len;
	uint8_t *pt, *p;
	uint32_t count_le;
	uint8_t iv[BOND_ENC_IVLEN];
	uint8_t tag[BOND_ENC_TAGLEN];
	uint8_t *ct = NULL;
	size_t ct_len;

	if (db->fd < 0)
		return (-1);

	/* Ensure owner-only permissions on bond file (contains LTK/IRK) */
	fchmod(db->fd, 0600);

	if (flock(db->fd, LOCK_EX) < 0 && errno != EINTR)
		warn("flock LOCK_EX");

	/* Generate a random per-file salt for PBKDF2 key derivation */
	if (RAND_bytes(file_salt, sizeof(file_salt)) != 1) {
		warnx("RAND_bytes failed for bond db salt");
		flock(db->fd, LOCK_UN);
		return (-1);
	}

	/* Derive encryption key using the random salt */
	if (bond_db_derive_key(key, file_salt, BOND_ENC_SALTLEN) != 0) {
		/*
		 * Key derivation failed (kern.hostuuid unavailable).
		 * Refuse to save -- writing bonds in plaintext would
		 * expose LTK/IRK material on disk.  Existing encrypted
		 * data on disk is preserved.
		 */
		BLUED_LOG_SECURITY("bond db: cannot derive encryption "
		    "key, REFUSING to save bonds (kern.hostuuid "
		    "unavailable) -- existing bond file preserved");
		warnx("bond db: cannot derive key, refusing to save "
		    "(no hostuuid)");
		explicit_bzero(key, sizeof(key));
		flock(db->fd, LOCK_UN);
		return (-1);
	}

	/*
	 * Build plaintext payload:
	 *   uint32_t        count (LE)
	 *   uint32_t        bond_struct_size (LE) — sizeof(struct smp_bond)
	 *   smp_bond[]      bonds[count]
	 *   uint8_t         has_local_irk
	 *   uint8_t[16]     local_irk (if has_local_irk)
	 */
	bond_len = (size_t)db->count * sizeof(struct smp_bond);
	irk_len = 1 + (db->has_local_irk ? 16 : 0);
	pt_len = sizeof(uint32_t) + sizeof(uint32_t) + bond_len + irk_len;

	pt = malloc(pt_len);
	if (pt == NULL) {
		explicit_bzero(key, sizeof(key));
		flock(db->fd, LOCK_UN);
		return (-1);
	}

	p = pt;
	count_le = htole32((uint32_t)db->count);
	memcpy(p, &count_le, sizeof(uint32_t));
	p += sizeof(uint32_t);

	{
		uint32_t struct_size_le;
		struct_size_le = htole32((uint32_t)sizeof(struct smp_bond));
		memcpy(p, &struct_size_le, sizeof(uint32_t));
		p += sizeof(uint32_t);
	}

	memcpy(p, db->bonds, bond_len);
	p += bond_len;

	*p++ = db->has_local_irk ? 1 : 0;
	if (db->has_local_irk)
		memcpy(p, db->local_irk, 16);

	/* Generate random IV for this save */
	if (RAND_bytes(iv, sizeof(iv)) != 1) {
		warnx("RAND_bytes failed for bond db IV");
		explicit_bzero(pt, pt_len);
		free(pt);
		explicit_bzero(key, sizeof(key));
		flock(db->fd, LOCK_UN);
		return (-1);
	}

	/* Encrypt */
	if (bond_db_encrypt(pt, pt_len, key, iv, &ct, &ct_len, tag) != 0) {
		warnx("bond db encryption failed");
		explicit_bzero(pt, pt_len);
		free(pt);
		explicit_bzero(key, sizeof(key));
		flock(db->fd, LOCK_UN);
		return (-1);
	}

	explicit_bzero(pt, pt_len);
	free(pt);
	explicit_bzero(key, sizeof(key));

	/*
	 * Write encrypted file (v4, AES-256-GCM + random salt):
	 *   "BONDE"     (5 bytes)
	 *   uint32_t    version = 4 (LE)
	 *   uint8_t[16] salt (PBKDF2 salt)
	 *   uint8_t[12] iv (96-bit nonce)
	 *   uint8_t[16] tag (authentication tag)
	 *   uint32_t    ciphertext_len (LE)
	 *   uint8_t[]   ciphertext
	 */
	{
		uint8_t file_hdr[BOND_MAGIC_ENC_LEN + 4 +
		    BOND_ENC_SALTLEN + BOND_ENC_IVLEN +
		    BOND_ENC_TAGLEN + 4];
		uint32_t version_le, ct_len_le;
		off_t total;
		ssize_t n;
		uint8_t *hp = file_hdr;

		memcpy(hp, BOND_MAGIC_ENC, BOND_MAGIC_ENC_LEN);
		hp += BOND_MAGIC_ENC_LEN;

		version_le = htole32(BOND_ENC_VERSION);
		memcpy(hp, &version_le, 4);
		hp += 4;

		memcpy(hp, file_salt, BOND_ENC_SALTLEN);
		hp += BOND_ENC_SALTLEN;

		memcpy(hp, iv, BOND_ENC_IVLEN);
		hp += BOND_ENC_IVLEN;

		memcpy(hp, tag, BOND_ENC_TAGLEN);
		hp += BOND_ENC_TAGLEN;

		ct_len_le = htole32((uint32_t)ct_len);
		memcpy(hp, &ct_len_le, 4);

		if (pwrite(db->fd, file_hdr, sizeof(file_hdr), 0) !=
		    (ssize_t)sizeof(file_hdr)) {
			warn("pwrite encrypted bond header");
			explicit_bzero(ct, ct_len);
			free(ct);
			flock(db->fd, LOCK_UN);
			return (-1);
		}

		n = pwrite(db->fd, ct, ct_len,
		    (off_t)sizeof(file_hdr));
		if (n < 0 || (size_t)n != ct_len) {
			warn("pwrite encrypted bond ciphertext");
			explicit_bzero(ct, ct_len);
			free(ct);
			flock(db->fd, LOCK_UN);
			return (-1);
		}

		total = (off_t)(sizeof(file_hdr) + ct_len);
		ftruncate(db->fd, total);
	}

	explicit_bzero(ct, ct_len);
	free(ct);

	/* Flush to disk before releasing lock to prevent data loss on crash */
	fsync(db->fd);
	flock(db->fd, LOCK_UN);

	BLUED_PROBE_BOND_SAVE(db->count);
	return (0);
}

/*
 * Save current per-connection CCCD values into a bond.
 * Core Spec Vol 3 Part G Section 2.4.5.1 requires the server to
 * persistently record CCCD values for bonded devices.
 *
 * CCCD values are per-connection state stored in ac->cccds[], not in
 * the shared att_db.  Only non-zero entries are saved.
 */
void
smp_bond_save_cccds(struct smp_bond *bond, const struct att_conn *ac)
{
	int i, n = 0;

	if (bond == NULL || ac == NULL)
		return;

	for (i = 0; i < ac->cccd_count && n < SMP_MAX_CCCDS; i++) {
		if (ac->cccds[i].value != 0) {
			bond->cccds[n].handle = ac->cccds[i].handle;
			bond->cccds[n].value = ac->cccds[i].value;
			n++;
		}
	}
	bond->num_cccds = (uint8_t)n;

	if (ac->cccd_count > SMP_MAX_CCCDS)
		warnx("CCCD persistence: %d/%d stored (cap=%d)",
		    n, ac->cccd_count, SMP_MAX_CCCDS);
}

/*
 * Restore saved CCCD values from a bond into the per-connection state.
 * Populates ac->cccds[] so the ATT server sees the restored values
 * on subsequent reads and can send notifications/indications.
 */
void
smp_bond_restore_cccds(const struct smp_bond *bond, struct att_conn *ac)
{
	int j, n;

	if (bond == NULL || ac == NULL)
		return;

	n = ac->cccd_count;
	for (j = 0; j < bond->num_cccds && n < ATT_MAX_CCCDS_PER_CONN; j++) {
		ac->cccds[n].handle = bond->cccds[j].handle;
		ac->cccds[n].value = bond->cccds[j].value;
		n++;
	}
	ac->cccd_count = n;
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
 */
void
smp_swap_buf(uint8_t *dst, const uint8_t *src, size_t len)
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
		0xdc, 0x80, 0x96, 0x42, 0xf7, 0x6e, 0x7e, 0x77,
		0x64, 0x65, 0xdf, 0xf2, 0x31, 0x95, 0xf1, 0xa1,
		0x38, 0x79, 0xa3, 0xc1, 0xe6, 0x0e, 0xfb, 0x7a,
		0xa8, 0xfc, 0xe4, 0x1b, 0x64, 0xff, 0x3d, 0x07
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
void
smp_f4(const uint8_t u[32], const uint8_t v[32], const uint8_t x[16],
    uint8_t z, uint8_t out[16])
{
	uint8_t m[65], x_be[16], mac[16];

	smp_swap_buf(m, u, 32);
	smp_swap_buf(m + 32, v, 32);
	m[64] = z;
	smp_swap_buf(x_be, x, 16);
	smp_aes_cmac(x_be, m, sizeof(m), mac);
	smp_swap_buf(out, mac, 16);
	explicit_bzero(x_be, sizeof(x_be));
	explicit_bzero(mac, sizeof(mac));
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
void
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

	smp_swap_buf(w_be, w, 32);
	smp_aes_cmac(salt, w_be, 32, t);

	m[0] = 0;
	memcpy(m + 1, keyid, 4);
	smp_swap_buf(m + 5, n1, 16);
	smp_swap_buf(m + 21, n2, 16);
	smp_swap_buf(m + 37, a1, 7);
	smp_swap_buf(m + 44, a2, 7);
	m[51] = 0x01;
	m[52] = 0x00;

	smp_aes_cmac(t, m, sizeof(m), mac);
	smp_swap_buf(mackey, mac, 16);
	m[0] = 1;
	smp_aes_cmac(t, m, sizeof(m), mac);
	smp_swap_buf(ltk, mac, 16);
	explicit_bzero(t, sizeof(t));
	explicit_bzero(w_be, sizeof(w_be));
	explicit_bzero(m, sizeof(m));
	explicit_bzero(mac, sizeof(mac));
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
void
smp_f6(const uint8_t w[16], const uint8_t n1[16], const uint8_t n2[16],
    const uint8_t r[16], const uint8_t iocap[3],
    const uint8_t a1[7], const uint8_t a2[7],
    uint8_t out[16])
{
	uint8_t m[65], w_be[16], mac[16];

	smp_swap_buf(w_be, w, 16);
	smp_swap_buf(m, n1, 16);
	smp_swap_buf(m + 16, n2, 16);
	smp_swap_buf(m + 32, r, 16);
	smp_swap_buf(m + 48, iocap, 3);
	smp_swap_buf(m + 51, a1, 7);
	smp_swap_buf(m + 58, a2, 7);
	smp_aes_cmac(w_be, m, sizeof(m), mac);
	smp_swap_buf(out, mac, 16);
	explicit_bzero(w_be, sizeof(w_be));
	explicit_bzero(m, sizeof(m));
	explicit_bzero(mac, sizeof(mac));
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
uint32_t
smp_g2(const uint8_t u[32], const uint8_t v[32],
    const uint8_t x[16], const uint8_t y[16])
{
	uint8_t m[80]; /* U(32)+V(32)+Y(16) */
	uint8_t x_be[16], mac[16];

	smp_swap_buf(m, u, 32);
	smp_swap_buf(m + 32, v, 32);
	smp_swap_buf(m + 64, y, 16);
	smp_swap_buf(x_be, x, 16);
	smp_aes_cmac(x_be, m, sizeof(m), mac);

	/* Least significant 32 bits of the big-endian 128-bit MAC */
	return ((uint32_t)mac[12] << 24 | (uint32_t)mac[13] << 16 |
	    (uint32_t)mac[14] << 8 | (uint32_t)mac[15]);
}

/*
 * h6: Link Key conversion function.
 * Core Spec Vol 3 Part H Section 2.2.10
 *
 * h6(W, keyID) = AES-CMAC_W(keyID)
 *
 * W is a 128-bit key in little-endian (wire) order; internally converted.
 * keyID is a 32-bit identifier in big-endian order.
 * Output is returned in little-endian (wire) order.
 */
void
smp_h6(const uint8_t w[16], const uint8_t keyid[4], uint8_t out[16])
{
	uint8_t w_be[16], mac[16];

	smp_swap_buf(w_be, w, 16);
	smp_aes_cmac(w_be, keyid, 4, mac);
	smp_swap_buf(out, mac, 16);
}

/*
 * h7: Link Key conversion function (alternate).
 * Core Spec Vol 3 Part H Section 2.2.11
 *
 * h7(SALT, W) = AES-CMAC_SALT(W)
 *
 * SALT is a 128-bit value in big-endian order.
 * W is a 128-bit key in little-endian (wire) order.
 * Output is returned in little-endian (wire) order.
 */
void
smp_h7(const uint8_t salt[16], const uint8_t w[16], uint8_t out[16])
{
	uint8_t w_be[16], mac[16];

	smp_swap_buf(w_be, w, 16);
	smp_aes_cmac(salt, w_be, 16, mac);
	smp_swap_buf(out, mac, 16);
}

/*
 * Cross-Transport Key Derivation: LE LTK -> BR/EDR Link Key.
 * Core Spec Vol 3 Part H Section 2.4.2.4
 *
 * Only valid for LE Secure Connections LTKs (not legacy).
 *
 * CT2 = 1 path (uses h7):
 *   ILK = h7(SALT_CT2, LTK)
 *   Link Key = h6(ILK, "lebr")
 *
 * Returns 0 on success, -1 if bond is not SC.
 */
int
smp_ctkd_derive_link_key(struct smp_bond *bond, bool ct2)
{
	/* SALT for CT2 = 1 path (Core Spec Vol 3 Part H Section 2.4.2.4) */
	static const uint8_t salt_ct2[16] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x74, 0x6D, 0x70, 0x31
	};
	/* keyID "lebr" in big-endian: 0x6C656272 */
	static const uint8_t keyid_lebr[4] = { 0x6C, 0x65, 0x62, 0x72 };
	/* keyID "tmp1" in big-endian: 0x746D7031 (CT2=0 path) */
	static const uint8_t keyid_tmp1[4] = { 0x74, 0x6D, 0x70, 0x31 };
	uint8_t ilk[16];

	if (!bond->is_sc || !bond->has_ltk)
		return (-1);

	/*
	 * Per Core Spec Vol 3 Part H Section 2.4.2.4, CTKD shall only
	 * derive a BR/EDR Link Key when the LE link was authenticated
	 * using an association model providing MITM protection (Passkey
	 * Entry, Numeric Comparison, or OOB).  Just Works does not
	 * provide MITM protection and must not produce a cross-transport
	 * key, as the unauthenticated key would be silently trusted on
	 * BR/EDR.
	 */
	if (!bond->is_mitm) {
		LOG_SMP(1, "CTKD: skipping — pairing was not MITM-protected");
		return (0);
	}

	if (ct2) {
		/* Both sides support CT2: use h7(SALT, LTK) */
		smp_h7(salt_ct2, bond->ltk, ilk);
	} else {
		/* At least one side lacks CT2: use h6(LTK, "tmp1") */
		smp_h6(bond->ltk, keyid_tmp1, ilk);
	}
	smp_h6(ilk, keyid_lebr, bond->link_key);
	bond->has_link_key = true;

	LOG_SMP(1, "CTKD: ct2=%d, BR/EDR link key derived", ct2);

	return (0);
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
	smp_f4(local_pk_x, local_pk_x, random, 0, confirm);
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
static void
smp_pack_addr(uint8_t out[7], const uint8_t addr[6], uint8_t addr_type)
{
	memcpy(out, addr, 6);
	out[6] = (addr_type == BDADDR_LE_RANDOM) ? 0x01 : 0x00;
}

/*
 * Verify an ATT Signed Write authentication signature.
 * Core Spec Vol 3 Part H Section 2.4.5:
 *   MAC = AES-CMAC(CSRK, msg || counter_le32)
 * The signature is the first 8 bytes of the 16-byte CMAC output.
 */
bool
smp_verify_signature(const uint8_t csrk[16], const uint8_t *msg,
    size_t msg_len, const uint8_t mac[8], uint32_t counter)
{
	uint8_t *input;
	uint8_t full_mac[16];
	uint32_t cnt_le;
	int rc;

	input = malloc(msg_len + 4);
	if (input == NULL) {
		warn("smp_verify_signature: malloc");
		return (false);
	}

	memcpy(input, msg, msg_len);
	cnt_le = htole32(counter);
	memcpy(input + msg_len, &cnt_le, 4);

	rc = smp_aes_cmac(csrk, input, msg_len + 4, full_mac);
	free(input);
	if (rc != 0)
		return (false);

	return (timingsafe_bcmp(full_mac, mac, 8) == 0);
}

/*
 * Check if more than 30 seconds have elapsed since the given start time.
 * Used as a cumulative pairing timer to detect stalled sessions.
 */
static bool
smp_pairing_expired(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return ((now.tv_sec - start->tv_sec) > 30 ||
	    ((now.tv_sec - start->tv_sec) == 30 &&
	     now.tv_nsec >= start->tv_nsec));
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
	int ret = -1;
	int i;
	struct timespec pair_start;

	clock_gettime(CLOCK_MONOTONIC, &pair_start);

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
	smp_swap_buf(pdu + 1, our_pk_raw + 1, 32);      /* x: BE -> LE */
	smp_swap_buf(pdu + 33, our_pk_raw + 33, 32);     /* y: BE -> LE */
	memcpy(pka_le, pdu + 1, 32);                /* save LE x-coord */
	if (smp_log_send(sc, pdu, 65) < 0) {
		EVP_PKEY_free(our_key);
		return (-1);
	}

	/* Receive peer's Public Key (wire = little-endian) */
	n = smp_log_recv(sc, pdu, 65);
	if (smp_pairing_expired(&pair_start)) {
		uint8_t f[2] = { SMP_PAIRING_FAILED, SMP_ERR_UNSPECIFIED_REASON };
		smp_log_send(sc, f, 2);
		EVP_PKEY_free(our_key);
		return (-1);
	}
	if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY) {
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
		smp_swap_buf(dhkey_le, dhkey_be, 32);
		explicit_bzero(dhkey_be, sizeof(dhkey_be));
		EVP_PKEY_CTX_free(dctx);
	}

	EVP_PKEY_free(peer_key);
	EVP_PKEY_free(our_key);
	LOG_SMP(2, "SC: DHKey computed");

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
		n = smp_log_recv(sc, pdu, 17);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			goto sc_jw_cleanup;
		}
		memcpy(nb, pdu + 1, 16);

		/* Verify peer's OOB confirm: Cb = f4(PKbx, PKbx, rb, 0) */
		{
			uint8_t cb_verify[16];
			smp_f4(pkb_le, pkb_le, sc->oob->sc->random, 0,
			    cb_verify);
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
		n = smp_log_recv(sc, pdu, 17);
		if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM) {
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
		n = smp_log_recv(sc, pdu, 17);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			goto sc_jw_cleanup;
		}
		memcpy(nb, pdu + 1, 16);

		/* Verify Cb = f4(PKbx, PKax, Nb, 0) */
		{
			uint8_t cb_verify[16];
			smp_f4(pkb_le, pka_le, nb, 0, cb_verify);
			if (timingsafe_bcmp(cb_recv, cb_verify, 16) != 0) {
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
				smp_log_send(sc, pdu, 2);
				errno = EACCES;
				goto sc_jw_cleanup;
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
	smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
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
		smp_f6(mackey, na, nb, r_ea, iocap_a, a1, a2, ea);
#ifdef BLUED_DEBUG_KEYS
		if (blued_verbose >= 3)
			blued_hexdump("SMP", "f6 output (Ea)", ea, 16);
#endif
		smp_f6(mackey, nb, na, r_eb, iocap_b, a2, a1, eb);
#ifdef BLUED_DEBUG_KEYS
		if (blued_verbose >= 3)
			blued_hexdump("SMP", "f6 output (Eb)", eb, 16);
#endif
	}

	/* Send our DHKey Check (Ea) */
	pdu[0] = SMP_PAIRING_DHKEY_CHECK;
	memcpy(pdu + 1, ea, 16);
	if (smp_log_send(sc, pdu, 17) < 0)
		goto sc_jw_cleanup;

	/* Receive peer's DHKey Check (Eb) */
	n = smp_log_recv(sc, pdu, 17);
	if (smp_pairing_expired(&pair_start)) {
		uint8_t f[2] = { SMP_PAIRING_FAILED, SMP_ERR_UNSPECIFIED_REASON };
		smp_log_send(sc, f, 2);
		goto sc_jw_cleanup;
	}
	if (n < 17 || pdu[0] != SMP_PAIRING_DHKEY_CHECK) {
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

	/* Start encryption with SC-derived LTK (rand=0, ediv=0) */
	{
		uint8_t params[28];
		params[0] = sc->con_handle & 0xFF;
		params[1] = (sc->con_handle >> 8) & 0xFF;
		memset(params + 2, 0, 10);
		memcpy(params + 12, ltk, 16);
		if (hci_send_raw_cmd(sc->hci_fd, HCI_OP_LE_START_ENCRYPTION, params,
		    sizeof(params)) < 0)
			goto sc_jw_cleanup;
	}

	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 5) < 0)
		goto sc_jw_cleanup;

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
		memcpy(bond.ltk, ltk, 16);
		bond.has_ltk = true;
		bond.is_sc = true;
		bond.is_mitm = (model == SMP_MODEL_PASSKEY_ENTRY ||
		    model == SMP_MODEL_NUMERIC_COMPARISON ||
		    model == SMP_MODEL_OOB);

		/* Receive key distribution from responder.
		 * SC ignores EncKey; IdKey and SignKey apply. */
		{
			int exp = 0;
			if (pres[6] & SMP_KEY_DIST_ID_KEY)
				exp += 2;
			if (pres[6] & SMP_KEY_DIST_SIGN_KEY)
				exp += 1;
			for (i = 0; i < exp; i++) {
				struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
				if (setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
				    &tv, sizeof(tv)) < 0)
					warn("setsockopt SO_RCVTIMEO");
				n = smp_log_recv(sc, pdu, sizeof(pdu));
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
				} else if (pdu[0] == SMP_SIGNING_INFORMATION &&
				    n >= 17) {
					memcpy(bond.csrk, pdu + 1, 16);
					bond.has_csrk = true;
					LOG_SMP(1, "stored peer CSRK");
				}
			}
		}

		/* Distribute initiator keys to responder */
		smp_distribute_init_keys(sc, preq, pres, true);

		/* Derive BR/EDR Link Key via CTKD (BT 4.2+) */
		smp_ctkd_derive_link_key(&bond,
		    (preq[3] & SMP_AUTH_CT2) && (pres[3] & SMP_AUTH_CT2));

		smp_bond_db_store(sc->bond_db, &bond);
		BLUED_LOG_SECURITY("bond stored "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "ltk=%d irk=%d lk=%d",
		    bond.addr[5], bond.addr[4],
		    bond.addr[3], bond.addr[2],
		    bond.addr[1], bond.addr[0],
		    bond.has_ltk, bond.has_irk, bond.has_link_key);
		BLUED_LOG_SECURITY("pairing complete "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "sc=%d bonded=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    1, bond.has_ltk);
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
	return (ret);
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
	sc->io_capability = SMP_IO_KEYBOARD_DISPLAY;  /* default */
	sc->min_key_size = 16;  /* KNOB-safe default */

	/* SMP timeout: 30 seconds per spec (Vol 3 Part H Section 3.4) */
	{
		struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
		if (setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
		    &tv, sizeof(tv)) < 0)
			warn("setsockopt SO_RCVTIMEO");
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
	int ret = -1;
	int i;

	/* iat = initiator (remote), rat = responder (us) */
	iat = (sc->remote_addr_type == BDADDR_LE_RANDOM) ? 1 : 0;
	rat = (sc->local_addr_type == BDADDR_LE_RANDOM) ? 1 : 0;

	/* Receive initiator's Pairing Confirm */
	n = smp_log_recv(sc, pdu, 17);
	if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM) {
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		goto resp_legacy_cleanup;
	}
	memcpy(mc, pdu + 1, 16);

	/* Generate our random and compute our confirm */
	smp_random(sr, sizeof(sr));
	if (smp_c1(tk, sr, preq, pres, iat, sc->remote_addr,
	    rat, sc->local_addr, sc_val) < 0) {
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
	n = smp_log_recv(sc, pdu, 17);
	if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
		errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
		    EACCES : EPROTO;
		goto resp_legacy_cleanup;
	}
	memcpy(mr, pdu + 1, 16);

	/* Verify initiator's confirm */
	if (smp_c1(tk, mr, preq, pres, iat, sc->remote_addr,
	    rat, sc->local_addr, verify) < 0) {
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

	/* Send our Pairing Random */
	pdu[0] = SMP_PAIRING_RANDOM;
	memcpy(pdu + 1, sr, 16);
	if (smp_log_send(sc, pdu, 17) < 0)
		goto resp_legacy_cleanup;

	/* Derive STK */
	if (smp_s1(tk, sr, mr, stk) < 0) {
		errno = EIO;
		goto resp_legacy_cleanup;
	}

	/* Respond to LTK Request with STK, then wait for encryption */
	if (hci_le_ltk_request_reply(sc->hci_fd, sc->con_handle, stk) < 0)
		goto resp_legacy_cleanup;
	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 10) < 0)
		goto resp_legacy_cleanup;
	LOG_SMP(1, "resp: encrypted, distributing keys");

	BLUED_PROBE_ENCRYPT_START(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL));
	BLUED_LOG_SECURITY("encryption active "
	    "addr=%02x:%02x:%02x:%02x:%02x:%02x handle=%d",
	    sc->remote_addr[5], sc->remote_addr[4],
	    sc->remote_addr[3], sc->remote_addr[2],
	    sc->remote_addr[1], sc->remote_addr[0],
	    sc->con_handle);

	/* Distribute our keys (responder distributes first) */
	{
		struct smp_bond bond;
		uint8_t our_ltk[16];

		memset(&bond, 0, sizeof(bond));
		memcpy(bond.addr, sc->remote_addr, 6);
		bond.addr_type = sc->remote_addr_type;

		smp_random(our_ltk, sizeof(our_ltk));
		smp_random((uint8_t *)&bond.rand, 8);
		bond.ediv = arc4random() & 0xFFFF;
		memcpy(bond.ltk, our_ltk, 16);
		bond.has_ltk = true;

		if (pres[6] & SMP_KEY_DIST_ENC_KEY) {
			pdu[0] = SMP_ENCRYPTION_INFORMATION;
			memcpy(pdu + 1, our_ltk, 16);
			smp_log_send(sc, pdu, 17);

			pdu[0] = SMP_CENTRAL_IDENTIFICATION;
			put_le16(pdu + 1, bond.ediv);
			memcpy(pdu + 3, &bond.rand, 8);
			smp_log_send(sc, pdu, 11);
		}

		/* Distribute IdKey (IRK + Identity Address) if negotiated */
		if (pres[6] & SMP_KEY_DIST_ID_KEY) {
			/* Send Identity Information (IRK). */
			smp_ensure_local_irk(sc->bond_db);
			pdu[0] = SMP_IDENTITY_INFORMATION;
			memcpy(pdu + 1, sc->bond_db->local_irk, 16);
			smp_log_send(sc, pdu, 17);

			/* Send Identity Address Information */
			pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
			pdu[1] = (sc->local_addr_type == BDADDR_LE_RANDOM) ?
			    0x01 : 0x00;
			memcpy(pdu + 2, sc->local_addr, 6);
			smp_log_send(sc, pdu, 8);
		}

		/* Receive initiator's keys based on negotiated
		 * Initiator Key Distribution (pres[5]) */
		{
			struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
			if (setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv)) < 0)
				warn("setsockopt SO_RCVTIMEO");
		}
		{
			int exp = 0;
			if (pres[5] & SMP_KEY_DIST_ENC_KEY)
				exp += 2;
			if (pres[5] & SMP_KEY_DIST_ID_KEY)
				exp += 2;
			if (pres[5] & SMP_KEY_DIST_SIGN_KEY)
				exp += 1;
			for (i = 0; i < exp; i++) {
				n = smp_log_recv(sc, pdu, sizeof(pdu));
				if (n < 1)
					break;
				if (pdu[0] == SMP_IDENTITY_INFORMATION &&
				    n >= 17) {
					memcpy(bond.irk, pdu + 1, 16);
					bond.has_irk = true;
				} else if (pdu[0] ==
				    SMP_IDENTITY_ADDRESS_INFO && n >= 8) {
					bond.addr_type = (pdu[1] == 0x01) ?
					    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
					memcpy(bond.addr, pdu + 2, 6);
				} else if (pdu[0] ==
				    SMP_SIGNING_INFORMATION &&
				    n >= 17) {
					memcpy(bond.csrk, pdu + 1, 16);
					bond.has_csrk = true;
					LOG_SMP(1, "stored peer CSRK");
				}
			}
		}

		/* Derive BR/EDR Link Key via CTKD (BT 4.2+) */
		smp_ctkd_derive_link_key(&bond,
		    (preq[3] & SMP_AUTH_CT2) && (pres[3] & SMP_AUTH_CT2));

		smp_bond_db_store(sc->bond_db, &bond);
		BLUED_LOG_SECURITY("bond stored "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "ltk=%d irk=%d lk=%d",
		    bond.addr[5], bond.addr[4],
		    bond.addr[3], bond.addr[2],
		    bond.addr[1], bond.addr[0],
		    bond.has_ltk, bond.has_irk, bond.has_link_key);
		BLUED_LOG_SECURITY("pairing complete "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "sc=%d bonded=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    0, bond.has_ltk);
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
	int ret = -1;
	int i;

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
	n = smp_log_recv(sc, pdu, 65);
	if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY) {
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
		smp_swap_buf(dhkey_le, dhkey_be, 32);
		explicit_bzero(dhkey_be, sizeof(dhkey_be));
		EVP_PKEY_CTX_free(dctx);
	}
	EVP_PKEY_free(peer_key);
	EVP_PKEY_free(our_key);
	LOG_SMP(2, "resp SC: DHKey computed");

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
		n = smp_log_recv(sc, pdu, 17);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			goto resp_sc_cleanup;
		}
		memcpy(na, pdu + 1, 16);

		/* Verify peer's OOB confirm: Ca = f4(PKax, PKax, ra, 0) */
		{
			uint8_t ca_verify[16];
			smp_f4(pka_le, pka_le, sc->oob->sc->random, 0,
			    ca_verify);
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
			smp_f4(pkb_le, pka_le, nb, 0, cb);
			pdu[0] = SMP_PAIRING_CONFIRM;
			memcpy(pdu + 1, cb, 16);
			if (smp_log_send(sc, pdu, 17) < 0)
				goto resp_sc_cleanup;
		}

		/* Receive Na */
		n = smp_log_recv(sc, pdu, 17);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
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

		/* Numeric Comparison */
		if (model == SMP_MODEL_NUMERIC_COMPARISON) {
			uint32_t cv = smp_g2(pka_le, pkb_le, na, nb) % 1000000;
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
	smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
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
		smp_f6(mackey, na, nb, r_ea, iocap_a, a1, a2, ea);
#ifdef BLUED_DEBUG_KEYS
		if (blued_verbose >= 3)
			blued_hexdump("SMP", "f6 output (Ea)", ea, 16);
#endif
		smp_f6(mackey, nb, na, r_eb, iocap_b, a2, a1, eb);
#ifdef BLUED_DEBUG_KEYS
		if (blued_verbose >= 3)
			blued_hexdump("SMP", "f6 output (Eb)", eb, 16);
#endif
	}

	/* Receive Ea, verify */
	n = smp_log_recv(sc, pdu, 17);
	if (n < 17 || pdu[0] != SMP_PAIRING_DHKEY_CHECK) {
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

	BLUED_PROBE_ENCRYPT_START(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL));
	BLUED_LOG_SECURITY("encryption active "
	    "addr=%02x:%02x:%02x:%02x:%02x:%02x handle=%d",
	    sc->remote_addr[5], sc->remote_addr[4],
	    sc->remote_addr[3], sc->remote_addr[2],
	    sc->remote_addr[1], sc->remote_addr[0],
	    sc->con_handle);

	/* Distribute our IdKey if negotiated (responder distributes first) */
	if (pres[6] & SMP_KEY_DIST_ID_KEY) {
		/* Send Identity Information (IRK). */
		smp_ensure_local_irk(sc->bond_db);
		pdu[0] = SMP_IDENTITY_INFORMATION;
		memcpy(pdu + 1, sc->bond_db->local_irk, 16);
		smp_log_send(sc, pdu, 17);

		/* Send Identity Address Information */
		pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = (sc->local_addr_type == BDADDR_LE_RANDOM) ?
		    0x01 : 0x00;
		memcpy(pdu + 2, sc->local_addr, 6);
		smp_log_send(sc, pdu, 8);
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
		bond.is_mitm = (model == SMP_MODEL_PASSKEY_ENTRY ||
		    model == SMP_MODEL_NUMERIC_COMPARISON ||
		    model == SMP_MODEL_OOB);

		/* Receive initiator's keys. SC ignores EncKey;
		 * IdKey and SignKey from pres[5] apply. */
		{
			int exp = 0;
			if (pres[5] & SMP_KEY_DIST_ID_KEY) exp += 2;
			if (pres[5] & SMP_KEY_DIST_SIGN_KEY) exp += 1;
			for (i = 0; i < exp; i++) {
				struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
				if (setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
				    &tv, sizeof(tv)) < 0)
					warn("setsockopt SO_RCVTIMEO");
				n = smp_log_recv(sc, pdu, sizeof(pdu));
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
				} else if (pdu[0] == SMP_SIGNING_INFORMATION &&
				    n >= 17) {
					memcpy(bond.csrk, pdu + 1, 16);
					bond.has_csrk = true;
					LOG_SMP(1, "stored peer CSRK");
				}
			}
		}

		/* Derive BR/EDR Link Key via CTKD (BT 4.2+) */
		smp_ctkd_derive_link_key(&bond,
		    (preq[3] & SMP_AUTH_CT2) && (pres[3] & SMP_AUTH_CT2));

		smp_bond_db_store(sc->bond_db, &bond);
		BLUED_LOG_SECURITY("bond stored "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "ltk=%d irk=%d lk=%d",
		    bond.addr[5], bond.addr[4],
		    bond.addr[3], bond.addr[2],
		    bond.addr[1], bond.addr[0],
		    bond.has_ltk, bond.has_irk, bond.has_link_key);
		BLUED_LOG_SECURITY("pairing complete "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "sc=%d bonded=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    1, bond.has_ltk);
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
	return (ret);
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
	int ret = -1;
	int i;

	if (sc->passkey_cb == NULL) {
		uint8_t f[2] = { SMP_PAIRING_FAILED,
		    SMP_ERR_PAIRING_NOT_SUPPORTED };
		smp_log_send(sc, f, 2);
		errno = ENOTSUP;
		return (-1);
	}

	/*
	 * Determine passkey display/input role per Core Spec
	 * Vol 3 Part H Table 2.8.  When we (responder) have
	 * DisplayOnly or DisplayYesNo and the initiator has
	 * KeyboardOnly or KeyboardDisplay, we display.
	 */
	{
		bool we_display = false;

		if ((pres[1] == SMP_IO_DISPLAY_ONLY ||
		    pres[1] == SMP_IO_DISPLAY_YESNO) &&
		    (preq[1] == SMP_IO_KEYBOARD_ONLY ||
		    preq[1] == SMP_IO_KEYBOARD_DISPLAY))
			we_display = true;

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
	n = smp_log_recv(sc, pdu, 65);
	if (n < 65 || pdu[0] != SMP_PAIRING_PUBLIC_KEY) {
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
		smp_swap_buf(dhkey_le, dhkey_be, 32);
		explicit_bzero(dhkey_be, sizeof(dhkey_be));
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
	for (i = 0; i < 20; i++) {
		uint8_t nai[16], nbi[16];
		uint8_t cai_recv[16], cbi[16], cai_verify[16];
		uint8_t ri;

		if (i == 0 || i == 19)
			LOG_SMP(2, "resp SC passkey: round %d/20", i + 1);

		ri = 0x80 | ((passkey >> i) & 1);

		smp_random(nbi, sizeof(nbi));

		/* Receive initiator's confirm Cai */
		n = smp_log_recv(sc, pdu, 17);
		if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			goto resp_sc_pk_cleanup;
		}
		memcpy(cai_recv, pdu + 1, 16);

		/* Compute and send our confirm Cbi */
		smp_f4(pkb_le, pka_le, nbi, ri, cbi);
		pdu[0] = SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, cbi, 16);
		if (smp_log_send(sc, pdu, 17) < 0)
			goto resp_sc_pk_cleanup;

		/* Receive initiator's nonce Nai */
		n = smp_log_recv(sc, pdu, 17);
		if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
			errno = (n > 0 && pdu[0] == SMP_PAIRING_FAILED) ?
			    EACCES : EPROTO;
			goto resp_sc_pk_cleanup;
		}
		memcpy(nai, pdu + 1, 16);

		/* Verify Cai = f4(PKax, PKbx, Nai, rai) */
		smp_f4(pka_le, pkb_le, nai, ri, cai_verify);
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

	/* Auth Stage 2: MacKey/LTK derivation and DHKey checks */
	smp_f5(dhkey_le, na, nb, a1, a2, mackey, ltk);
#ifdef BLUED_DEBUG_KEYS
	if (blued_verbose >= 3)
		blued_hexdump("SMP", "f5 output (LTK)", ltk, 16);
#endif

	smp_f6(mackey, na, nb, ra, iocap_a, a1, a2, ea);
#ifdef BLUED_DEBUG_KEYS
	if (blued_verbose >= 3)
		blued_hexdump("SMP", "f6 output (Ea)", ea, 16);
#endif
	smp_f6(mackey, nb, na, ra, iocap_b, a2, a1, eb);
#ifdef BLUED_DEBUG_KEYS
	if (blued_verbose >= 3)
		blued_hexdump("SMP", "f6 output (Eb)", eb, 16);
#endif

	/* Receive Ea from initiator, verify */
	n = smp_log_recv(sc, pdu, 17);
	if (n < 17 || pdu[0] != SMP_PAIRING_DHKEY_CHECK) {
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

	BLUED_PROBE_ENCRYPT_START(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL));
	BLUED_LOG_SECURITY("encryption active "
	    "addr=%02x:%02x:%02x:%02x:%02x:%02x handle=%d",
	    sc->remote_addr[5], sc->remote_addr[4],
	    sc->remote_addr[3], sc->remote_addr[2],
	    sc->remote_addr[1], sc->remote_addr[0],
	    sc->con_handle);

	/* Distribute our IdKey if negotiated (responder distributes first) */
	if (pres[6] & SMP_KEY_DIST_ID_KEY) {
		/* Send Identity Information (IRK). */
		smp_ensure_local_irk(sc->bond_db);
		pdu[0] = SMP_IDENTITY_INFORMATION;
		memcpy(pdu + 1, sc->bond_db->local_irk, 16);
		smp_log_send(sc, pdu, 17);

		/* Send Identity Address Information */
		pdu[0] = SMP_IDENTITY_ADDRESS_INFO;
		pdu[1] = (sc->local_addr_type == BDADDR_LE_RANDOM) ?
		    0x01 : 0x00;
		memcpy(pdu + 2, sc->local_addr, 6);
		smp_log_send(sc, pdu, 8);
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
		bond.is_mitm = true; /* Passkey Entry provides MITM */

		/* Receive initiator's keys. SC ignores EncKey;
		 * IdKey and SignKey from pres[5] apply. */
		{
			int exp = 0;
			if (pres[5] & SMP_KEY_DIST_ID_KEY) exp += 2;
			if (pres[5] & SMP_KEY_DIST_SIGN_KEY) exp += 1;
			for (i = 0; i < exp; i++) {
				struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
				if (setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
				    &tv, sizeof(tv)) < 0)
					warn("setsockopt SO_RCVTIMEO");
				n = smp_log_recv(sc, pdu, sizeof(pdu));
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
				} else if (pdu[0] == SMP_SIGNING_INFORMATION &&
				    n >= 17) {
					memcpy(bond.csrk, pdu + 1, 16);
					bond.has_csrk = true;
					LOG_SMP(1, "stored peer CSRK");
				}
			}
		}

		/* Derive BR/EDR Link Key via CTKD (BT 4.2+) */
		smp_ctkd_derive_link_key(&bond,
		    (preq[3] & SMP_AUTH_CT2) && (pres[3] & SMP_AUTH_CT2));

		smp_bond_db_store(sc->bond_db, &bond);
		BLUED_LOG_SECURITY("bond stored "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "ltk=%d irk=%d lk=%d",
		    bond.addr[5], bond.addr[4],
		    bond.addr[3], bond.addr[2],
		    bond.addr[1], bond.addr[0],
		    bond.has_ltk, bond.has_irk, bond.has_link_key);
		BLUED_LOG_SECURITY("pairing complete "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "sc=%d bonded=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    1, bond.has_ltk);
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

/*
 * Rate-limit pairing attempts per address to mitigate brute-force attacks.
 * Core Spec Vol 3 Part H Section 3.4: "A device in a Pairing mode shall
 * not allow ... multiple pairing attempts without appropriate delays."
 *
 * Track the most recent SMP_RATE_LIMIT_SLOTS addresses that have attempted
 * pairing.  If the same address attempts more than SMP_RATE_LIMIT_MAX times
 * within SMP_RATE_LIMIT_WINDOW seconds, reject with Repeated Attempts.
 *
 * Additionally, enforce a global rate limit across all addresses to prevent
 * bypass via address rotation: reject if total pairing attempts across all
 * addresses exceed SMP_RATE_LIMIT_GLOBAL_MAX within the window.
 */
#define SMP_RATE_LIMIT_SLOTS		32
#define SMP_RATE_LIMIT_MAX		3
#define SMP_RATE_LIMIT_WINDOW		60
#define SMP_RATE_LIMIT_MAX_WINDOW	900
#define SMP_RATE_LIMIT_GLOBAL_MAX	30

struct smp_rate_entry {
	uint8_t		addr[6];
	uint8_t		addr_type;
	int		count;
	uint8_t		failures;	/* consecutive failures for backoff */
	time_t		first;
};

static struct smp_rate_entry smp_rate_table[SMP_RATE_LIMIT_SLOTS];

/* Global rate limiter: total pairing attempts across all addresses */
static int	smp_rate_global_count;
static time_t	smp_rate_global_first;

/*
 * Compute the effective lockout window for a given failure count.
 * After SMP_RATE_LIMIT_MAX attempts, the window doubles for each
 * subsequent failure: 60s, 120s, 240s, ... capped at 900s.
 */
static time_t
smp_rate_window(uint8_t failures)
{
	time_t window;
	int doublings;

	if (failures <= SMP_RATE_LIMIT_MAX)
		return (SMP_RATE_LIMIT_WINDOW);

	doublings = failures - SMP_RATE_LIMIT_MAX;
	if (doublings > 4)
		doublings = 4;	/* cap shift to avoid overflow */
	window = SMP_RATE_LIMIT_WINDOW << doublings;
	if (window > SMP_RATE_LIMIT_MAX_WINDOW)
		window = SMP_RATE_LIMIT_MAX_WINDOW;
	return (window);
}

/*
 * Check and update the pairing rate limiter.
 * Returns 0 if the attempt is allowed, -1 if rate-limited.
 */
static int
smp_rate_check(const uint8_t *addr, uint8_t addr_type)
{
	time_t now;
	int i, oldest;
	time_t oldest_time;
	struct timespec ts;

	/* Use monotonic clock — immune to NTP/settimeofday jumps */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec;

	/*
	 * Global rate limit: reject if total attempts across all
	 * addresses exceed the threshold within the window.  This
	 * prevents an attacker from rotating addresses to bypass
	 * the per-address limit.
	 */
	if (smp_rate_global_count > 0 &&
	    now - smp_rate_global_first <= SMP_RATE_LIMIT_WINDOW) {
		smp_rate_global_count++;
		if (smp_rate_global_count > SMP_RATE_LIMIT_GLOBAL_MAX) {
			BLUED_LOG_SECURITY("pairing global rate limit "
			    "exceeded (%d attempts in %d sec)",
			    smp_rate_global_count,
			    (int)(now - smp_rate_global_first));
			return (-1);
		}
	} else {
		/* Window expired or first attempt — reset */
		smp_rate_global_count = 1;
		smp_rate_global_first = now;
	}

	/* Look for existing entry */
	for (i = 0; i < SMP_RATE_LIMIT_SLOTS; i++) {
		if (smp_rate_table[i].count == 0)
			continue;
		if (smp_rate_table[i].addr_type != addr_type ||
		    memcmp(smp_rate_table[i].addr, addr, 6) != 0)
			continue;

		/* Found matching entry — check window with backoff */
		{
			time_t window = smp_rate_window(
			    smp_rate_table[i].failures);
			if (now - smp_rate_table[i].first > window) {
				/* Window expired, reset count but keep
				 * failure history for backoff */
				smp_rate_table[i].count = 1;
				smp_rate_table[i].first = now;
				return (0);
			}
		}
		smp_rate_table[i].count++;
		if (smp_rate_table[i].count > SMP_RATE_LIMIT_MAX) {
			smp_rate_table[i].failures++;
			if (smp_rate_table[i].failures > 255)
				smp_rate_table[i].failures = 255;
			return (-1);
		}
		return (0);
	}

	/* No existing entry — find a free or oldest slot */
	oldest = 0;
	oldest_time = smp_rate_table[0].first;
	for (i = 0; i < SMP_RATE_LIMIT_SLOTS; i++) {
		if (smp_rate_table[i].count == 0) {
			oldest = i;
			break;
		}
		if (smp_rate_table[i].first < oldest_time) {
			oldest_time = smp_rate_table[i].first;
			oldest = i;
		}
	}

	memcpy(smp_rate_table[oldest].addr, addr, 6);
	smp_rate_table[oldest].addr_type = addr_type;
	smp_rate_table[oldest].count = 1;
	smp_rate_table[oldest].failures = 0;
	smp_rate_table[oldest].first = now;
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
	n = smp_log_recv(sc, preq, sizeof(preq));
	if (n < 7) {
		errno = EPROTO;
		explicit_bzero(tk, sizeof(tk));
		return (-1);
	}
	if (preq[0] != SMP_PAIRING_REQUEST) {
		if (preq[0] == SMP_SECURITY_REQUEST) {
			errno = EAGAIN;
		} else {
			uint8_t fail[2] = { SMP_PAIRING_FAILED, SMP_ERR_CMD_NOT_SUPPORTED };
			smp_log_send(sc, fail, sizeof(fail));
			errno = EPROTO;
		}
		explicit_bzero(tk, sizeof(tk));
		return (-1);
	}
	LOG_SMP(1, "resp: request received IO=%d auth=%02x", preq[1], preq[3]);

	/*
	 * Rate-limit pairing attempts per Core Spec Vol 3 Part H §3.4.
	 * Reject with SMP_ERR_REPEATED_ATTEMPTS if too many attempts
	 * from the same address within the rate-limit window.
	 */
	if (smp_rate_check(sc->remote_addr, sc->remote_addr_type) < 0) {
		uint8_t fail[2] = { SMP_PAIRING_FAILED,
		    SMP_ERR_REPEATED_ATTEMPTS };
		BLUED_LOG_SECURITY("pairing rate-limited "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0]);
		smp_log_send(sc, fail, 2);
		errno = EACCES;
		explicit_bzero(tk, sizeof(tk));
		return (-1);
	}

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
		pres[1] = sc->io_capability;
		pres[2] = (sc->oob != NULL &&
		    (sc->oob->legacy != NULL || sc->oob->sc != NULL)) ?
		    0x01 : 0x00;
		pres[3] = SMP_AUTH_BONDING | SMP_AUTH_MITM | SMP_AUTH_SC |
		    SMP_AUTH_KEYPRESS | SMP_AUTH_CT2;
		pres[4] = 16;
		pres[5] = preq[5] & (SMP_KEY_DIST_ID_KEY |
		    SMP_KEY_DIST_SIGN_KEY);
		if (peer_sc)
			pres[6] = preq[6] & (SMP_KEY_DIST_ID_KEY |
			    SMP_KEY_DIST_SIGN_KEY);
		else
			pres[6] = preq[6] & (SMP_KEY_DIST_ENC_KEY |
			    SMP_KEY_DIST_ID_KEY | SMP_KEY_DIST_SIGN_KEY);
	}

	if (smp_log_send(sc, pres, sizeof(pres)) < 0) {
		explicit_bzero(tk, sizeof(tk));
		return (-1);
	}
	LOG_SMP(1, "resp: response sent IO=%d auth=%02x sc=%d",
	    pres[1], pres[3], (pres[3] & 0x08) != 0);

	{
		bool use_sc_log = (preq[3] & SMP_AUTH_SC) &&
		    (pres[3] & SMP_AUTH_SC);
		BLUED_LOG_SECURITY("pairing initiated "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "type=%d sc=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    sc->remote_addr_type, use_sc_log);
	}

	/*
	 * Validate encryption key size (Core Spec Vol 3 Part H 3.6.1).
	 * Max_Encryption_Key_Size must be in range [7,16].
	 * Negotiated size = min(ours, theirs).
	 *
	 * Post-KNOB Erratum 11838: SC pairing requires a minimum
	 * negotiated key size of 16 bytes.  Legacy pairing retains
	 * the original minimum of 7 bytes.
	 */
	{
		uint8_t peer_key_sz = preq[4];
		uint8_t neg_key_sz;
		uint8_t fail[2];
		bool is_sc = (preq[3] & SMP_AUTH_SC) &&
		    (pres[3] & SMP_AUTH_SC);

		if (peer_key_sz < 7 || peer_key_sz > 16) {
			fail[0] = SMP_PAIRING_FAILED;
			fail[1] = SMP_ERR_INVALID_PARAMETERS;
			smp_log_send(sc, fail, 2);
			errno = EPROTO;
			explicit_bzero(tk, sizeof(tk));
			return (-1);
		}
		neg_key_sz = (pres[4] < peer_key_sz) ? pres[4] : peer_key_sz;
		if (is_sc && neg_key_sz < 16) {
			LOG_SMP(1, "SC key size %d < 16, rejecting (KNOB)",
			    neg_key_sz);
			fail[0] = SMP_PAIRING_FAILED;
			fail[1] = SMP_ERR_ENCRYPTION_KEY_SIZE;
			smp_log_send(sc, fail, 2);
			errno = EACCES;
			explicit_bzero(tk, sizeof(tk));
			return (-1);
		} else if (!is_sc && neg_key_sz < sc->min_key_size) {
			LOG_SMP(1, "legacy key size %d < %d, rejecting",
			    neg_key_sz, sc->min_key_size);
			fail[0] = SMP_PAIRING_FAILED;
			fail[1] = SMP_ERR_ENCRYPTION_KEY_SIZE;
			smp_log_send(sc, fail, 2);
			errno = EACCES;
			explicit_bzero(tk, sizeof(tk));
			return (-1);
		}
	}

	if (sc->sc_only && !(preq[3] & SMP_AUTH_SC)) {
		uint8_t fail[2] = { SMP_PAIRING_FAILED,
		    SMP_ERR_AUTH_REQUIREMENTS };
		LOG_SMP(1, "sc_only: peer does not support SC, rejecting");
		smp_log_send(sc, fail, 2);
		errno = EACCES;
		explicit_bzero(tk, sizeof(tk));
		return (-1);
	}

	{
		bool use_sc = (preq[3] & SMP_AUTH_SC) &&
		    (pres[3] & SMP_AUTH_SC);
		bool use_mitm = (preq[3] & SMP_AUTH_MITM) ||
		    (pres[3] & SMP_AUTH_MITM);
		/*
		 * Core Spec Vol 3 Part H Table 2.6 (legacy): OOB used
		 * when BOTH sides have OOB data.
		 * Table 2.7 (SC): OOB used when EITHER side has OOB data.
		 */
		bool have_oob = use_sc ?
		    (preq[2] != 0 || pres[2] != 0) :
		    (preq[2] != 0 && pres[2] != 0);
		int model;

		/*
		 * OOB takes priority over IO capabilities.
		 */
		if (have_oob)
			model = SMP_MODEL_OOB;
		else if (!use_mitm)
			model = SMP_MODEL_JUST_WORKS;
		else
			model = smp_select_model(preq[1], pres[1], use_sc);

		/*
		 * Reject pairing if peer's IO capability is out of
		 * range [0..4].  Core Spec Vol 3 Part H Table 3.4:
		 * values 0x05-0xFF are reserved.
		 */
		if (model == SMP_MODEL_INVALID) {
			uint8_t fail[2] = { SMP_PAIRING_FAILED,
			    SMP_ERR_INVALID_PARAMETERS };
			LOG_SMP(1, "invalid peer IO capability %d, "
			    "rejecting", preq[1]);
			smp_log_send(sc, fail, sizeof(fail));
			errno = EPROTO;
			return (-1);
		}

		BLUED_PROBE_SMP_PAIR_START(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL), model);

		if (model == SMP_MODEL_OOB)
			BLUED_LOG_SECURITY("OOB pairing "
			    "addr=%02x:%02x:%02x:%02x:%02x:%02x sc=%d",
			    sc->remote_addr[5], sc->remote_addr[4],
			    sc->remote_addr[3], sc->remote_addr[2],
			    sc->remote_addr[1], sc->remote_addr[0],
			    use_sc);

		if (use_sc) {
			int rc;

			explicit_bzero(tk, sizeof(tk));
			if (model == SMP_MODEL_PASSKEY_ENTRY)
				rc = smp_respond_sc_passkey(sc, preq, pres);
			else
				rc = smp_respond_sc(sc, preq, pres, model);
			return (rc);
		}

		/*
		 * Legacy OOB: use peer's TK received out-of-band.
		 * Core Spec Vol 3 Part H Section 2.3.5.5
		 */
		if (model == SMP_MODEL_OOB) {
			if (sc->oob == NULL || sc->oob->legacy == NULL) {
				uint8_t f[2] = { SMP_PAIRING_FAILED,
				    SMP_ERR_OOB_NOT_AVAILABLE };
				smp_log_send(sc, f, 2);
				errno = ENOTSUP;
				explicit_bzero(tk, sizeof(tk));
				return (-1);
			}
			memcpy(tk, sc->oob->legacy->tk, 16);
			LOG_SMP(1, "resp: legacy OOB: TK set from OOB data");
			/* Fall through to legacy c1/s1 with this TK */
		}

		if (model == SMP_MODEL_PASSKEY_ENTRY) {
			uint32_t passkey = 0;
			bool kp_notify;
			bool we_display;

			if (sc->passkey_cb == NULL) {
				uint8_t f[2] = { SMP_PAIRING_FAILED,
				    SMP_ERR_PAIRING_NOT_SUPPORTED };
				smp_log_send(sc, f, 2);
				errno = ENOTSUP;
				explicit_bzero(tk, sizeof(tk));
				return (-1);
			}
			/*
			 * Keypress Notification: both sides must have set the
			 * SMP_AUTH_KEYPRESS bit in their AuthReq fields.
			 * Core Spec Vol 3 Part H Section 3.5.8
			 */
			kp_notify = (preq[3] & SMP_AUTH_KEYPRESS) &&
			    (pres[3] & SMP_AUTH_KEYPRESS);

			/*
			 * Per Core Spec Vol 3 Part H Table 2.8, the
			 * passkey display/input role depends on both
			 * sides' IO capabilities.  When we (responder)
			 * have DisplayOnly or DisplayYesNo and the
			 * initiator has KeyboardOnly or KeyboardDisplay,
			 * we display and the initiator inputs.
			 */
			we_display = false;
			if ((pres[1] == SMP_IO_DISPLAY_ONLY ||
			    pres[1] == SMP_IO_DISPLAY_YESNO) &&
			    (preq[1] == SMP_IO_KEYBOARD_ONLY ||
			    preq[1] == SMP_IO_KEYBOARD_DISPLAY))
				we_display = true;

			if (we_display)
				passkey = arc4random_uniform(1000000);
			if (kp_notify && !we_display)
				smp_send_keypress(sc,
				    SMP_KEYPRESS_STARTED);
			if (sc->passkey_cb(&passkey, we_display,
			    sc->passkey_cb_arg) < 0) {
				uint8_t f[2] = { SMP_PAIRING_FAILED,
				    SMP_ERR_PASSKEY_ENTRY_FAILED };
				smp_log_send(sc, f, 2);
				errno = ECANCELED;
				explicit_bzero(tk, sizeof(tk));
				return (-1);
			}
			if (kp_notify && !we_display)
				smp_send_keypress(sc,
				    SMP_KEYPRESS_COMPLETED);
			memset(tk, 0, sizeof(tk));
			tk[0] = passkey & 0xFF;
			tk[1] = (passkey >> 8) & 0xFF;
			tk[2] = (passkey >> 16) & 0xFF;
		}

		{
			int rc = smp_respond_legacy(sc, preq, pres, tk);
			explicit_bzero(tk, sizeof(tk));
			return (rc);
		}
	}
}
