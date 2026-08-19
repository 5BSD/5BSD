/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * btpeer.c - a hardware-free virtual remote BLE peer riding an hci_emu link.
 *
 * See btpeer.h.  The peer is a protocol-driving test harness for Bluetooth
 * Core 6.3-shaped traffic.  It is not, by itself, an independent oracle: its
 * SMP path links blued command macros and crypto primitives.  Tests using it
 * must supply independent wire/expected values or pair it with the dedicated
 * OpenSSL and published-vector oracle suites.
 *
 * References:
 *   Vol 3 Part A (L2CAP), Section 3.1 (B-frame).
 *   Vol 3 Part F (ATT), Section 3.4 (PDUs), 3.4.1.1 (error codes).
 *   Vol 3 Part G (GATT), Section 3 (attribute types), 4 (procedures).
 *   Vol 3 Part H (SMP), Section 2.2 (c1/s1), 3.5/3.6 (pairing PDUs).
 *   Vol 4 Part E (HCI), Section 5.4.2 (ACL data packet).
 */

#include <sys/types.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include "hci_emulator.h"
#include "smp.h"		/* smp_c1/s1/f4/f5/f6/g2 - Vol 3 Part H 2.2 */
#include "btpeer.h"

#ifndef BDADDR_LE_RANDOM
#define BDADDR_LE_RANDOM	2
#endif

/* ----------------------------------------------------------------
 * Local little-endian helpers (keep btpeer self-contained).
 * ---------------------------------------------------------------- */
static inline void
pk16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v & 0xFF);
	p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static inline uint16_t
gt16(const uint8_t *p)
{
	return ((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* ----------------------------------------------------------------
 * L2CAP fixed channel IDs (Vol 3 Part A Section 2.1, Table 2.1).
 * ---------------------------------------------------------------- */
#define L2CAP_CID_ATT		0x0004
#define L2CAP_CID_SMP		0x0006

/* ----------------------------------------------------------------
 * ATT opcodes (Vol 3 Part F Section 3.4.8, Table 3.37).
 * ---------------------------------------------------------------- */
#define ATT_ERROR_RSP		0x01
#define ATT_MTU_REQ		0x02
#define ATT_MTU_RSP		0x03
#define ATT_FIND_INFO_REQ	0x04
#define ATT_FIND_INFO_RSP	0x05
#define ATT_FIND_BY_TYPE_REQ	0x06
#define ATT_FIND_BY_TYPE_RSP	0x07
#define ATT_READ_BY_TYPE_REQ	0x08
#define ATT_READ_BY_TYPE_RSP	0x09
#define ATT_READ_REQ		0x0A
#define ATT_READ_RSP		0x0B
#define ATT_READ_BLOB_REQ	0x0C
#define ATT_READ_BLOB_RSP	0x0D
#define ATT_READ_MULTIPLE_REQ	0x0E
#define ATT_READ_MULTIPLE_RSP	0x0F
#define ATT_READ_BY_GROUP_REQ	0x10
#define ATT_READ_BY_GROUP_RSP	0x11
#define ATT_WRITE_REQ		0x12
#define ATT_WRITE_RSP		0x13
#define ATT_PREPARE_WRITE_REQ	0x16
#define ATT_PREPARE_WRITE_RSP	0x17
#define ATT_EXECUTE_WRITE_REQ	0x18
#define ATT_EXECUTE_WRITE_RSP	0x19
#define ATT_HANDLE_NOTIFY	0x1B
#define ATT_HANDLE_IND		0x1D
#define ATT_HANDLE_CFM		0x1E
#define ATT_READ_MULT_VAR_REQ	0x20	/* Vol 3 Part F 3.4.4.9 (EATT) */
#define ATT_READ_MULT_VAR_RSP	0x21
#define ATT_MULTI_HANDLE_NOTIFY	0x23	/* Vol 3 Part F 3.4.7.4 */
#define ATT_WRITE_CMD		0x52
#define ATT_SIGNED_WRITE_CMD	0xD2	/* Vol 3 Part F 3.4.5.4 */

/* ATT error codes (Vol 3 Part F Section 3.4.1.1, Table 3.4). */
#define ATT_ERR_INVALID_HANDLE		0x01
#define ATT_ERR_READ_NOT_PERMITTED	0x02
#define ATT_ERR_WRITE_NOT_PERMITTED	0x03
#define ATT_ERR_INVALID_PDU		0x04
#define ATT_ERR_INSUFF_ENCRYPTION	0x0F
#define ATT_ERR_UNSUPPORTED_GROUP_TYPE	0x10
#define ATT_ERR_ATTR_NOT_FOUND		0x0A
#define ATT_ERR_REQ_NOT_SUPPORTED	0x06
#define ATT_ERR_INVALID_OFFSET		0x07
#define ATT_ERR_INVALID_ATTR_VAL_LEN	0x0D
#define ATT_ERR_PREPARE_QUEUE_FULL	0x09

/* GATT attribute type UUIDs (Vol 3 Part G Section 3.4, Table 3.7). */
#define GATT_PRIMARY_SERVICE	0x2800
#define GATT_SECONDARY_SERVICE	0x2801
#define GATT_CHARACTERISTIC	0x2803
#define GATT_CCCD		0x2902

/* SMP opcodes (Vol 3 Part H Section 3.3). */
#define SMP_PAIR_REQ		0x01
#define SMP_PAIR_RSP		0x02
#define SMP_PAIR_CONFIRM	0x03
#define SMP_PAIR_RANDOM		0x04
#define SMP_PAIR_FAILED		0x05

/* ----------------------------------------------------------------
 * Peer object
 * ---------------------------------------------------------------- */
struct btpeer_attr {
	uint16_t	handle;
	uint16_t	uuid16;
	uint8_t		perms;
	uint16_t	len;		/* current value length */
	uint16_t	cap;		/* reserved capacity in val_store */
	uint16_t	off;		/* offset into val_store */
};

struct btpeer {
	struct hci_emu	*emu;
	uint16_t	handle;		/* our LE-ACL connection handle */
	bool		have_handle;
	uint16_t	mtu;		/* peer's advertised MTU */

	/* Peer server attribute database (accessory role). */
	struct btpeer_attr attrs[BTPEER_MAX_ATTRS];
	int		nattrs;
	uint16_t	next_handle;
	uint8_t		val_store[BTPEER_VAL_STORE];
	size_t		val_used;

	/* Client-role response capture (synchronous round trip). */
	bool		rsp_ready;
	uint8_t		rsp[512];
	uint16_t	rsp_len;

	/* Captured ATT error (Vol 3 Part F 3.4.1.1). */
	bool		have_err;
	uint8_t		err_req_op;
	uint16_t	err_handle;
	uint8_t		err_code;

	btpeer_notify_cb notify_cb;
	void		*notify_arg;

	/* Arm-on-subscribe (HID keystroke on subscribe). */
	bool		armed;
	uint16_t	arm_cccd;
	uint16_t	arm_val_handle;
	uint8_t		arm_val[64];
	uint16_t	arm_val_len;

	/* Server-side prepared-write queue (Vol 3 Part F 3.4.6). */
	struct {
		uint16_t	handle;
		uint16_t	offset;
		uint8_t		val[64];
		uint16_t	len;
	}		prepq[16];
	int		nprep;

	/* Client-side capture of the last Prepare Write Response echo. */
	bool		prep_echo_valid;
	uint16_t	prep_echo_handle;
	uint16_t	prep_echo_offset;
	uint8_t		prep_echo_val[64];
	uint16_t	prep_echo_len;

	/* SMP peer state (Vol 3 Part H). */
	uint8_t		peer_addr[6];	/* responder-side address */
	uint8_t		peer_addr_type;	/* internal BDADDR_LE_* */
	uint8_t		init_addr[6];	/* initiator-side (DUT when peer=responder) */
	uint8_t		init_addr_type;
	uint8_t		preq[7];	/* Pairing Request (from initiator) */
	uint8_t		pres[7];	/* Pairing Response (from responder) */
	uint8_t		srand[16];	/* our Pairing Random (legacy) */
	uint8_t		mconfirm[16];	/* stashed peer confirm (legacy) */
	uint8_t		stk[16];
	bool		smp_have_stk;

	/* Full-matrix SMP configuration + results. */
	struct btpeer_smp_cfg smp_cfg;
	bool		smp_configured;
	int		smp_phase;	/* BSMP_PH_* */
	bool		smp_bonded;
	bool		smp_is_sc;
	bool		smp_is_mitm;
	uint8_t		smp_ltk[16];
	uint8_t		smp_fail;	/* Pairing Failed reason sent/received */
	bool		inject_fired;	/* mid-flow fault already injected once */

	/* SC ECDH working state. */
	EVP_PKEY	*sc_key;	/* our P-256 key pair */
	uint8_t		sc_pk_le[64];	/* our public key, wire LE (x||y) */
	uint8_t		sc_pka_le[32];	/* initiator PK x-coord, LE */
	uint8_t		sc_pkb_le[32];	/* responder PK x-coord, LE */
	uint8_t		sc_dhkey_le[32];
	uint8_t		sc_na[16], sc_nb[16];	/* nonces */
	uint8_t		sc_cb[16];	/* our JW/NC confirm (responder) */
	uint8_t		sc_cx[16];	/* stashed peer confirm */
	int		sc_pk_round;	/* SC passkey round index (0..19) */
	uint8_t		sc_ea[16], sc_eb[16];

	/* OOB material (Vol 3 Part H 2.3.5.4 / 2.3.5.6.4). */
	uint8_t		oob_tk[16];	/* legacy shared TK */
	bool		have_oob_tk;
	uint8_t		oob_local_rand[16];	/* SC: our rb */
	uint8_t		oob_peer_confirm[16];	/* SC: DUT's Ca */
	uint8_t		oob_peer_rand[16];	/* SC: DUT's ra */
	bool		have_oob_sc;

	/* Peer-received key distribution (from OUR side). */
	bool		got_irk;
	uint8_t		peer_irk[16];
	bool		got_identity;
	uint8_t		peer_id_type;	/* 0x00 public / 0x01 random (wire) */
	uint8_t		peer_id_addr[6];
	bool		got_csrk;
	uint8_t		peer_csrk[16];
	int		keydist_recv;	/* count of init keys still expected */
};

/* SMP peer phases (reactive state machine). */
enum {
	BSMP_PH_IDLE = 0,
	BSMP_PH_FEATURE,	/* initiator: sent PReq, waiting PRes */
	BSMP_PH_LEG_CONFIRM,	/* legacy: waiting peer confirm */
	BSMP_PH_LEG_RANDOM,	/* legacy: waiting peer random */
	BSMP_PH_SC_PK,		/* SC: waiting peer public key */
	BSMP_PH_SC_CONFIRM,	/* SC JW/NC initiator: waiting Cb */
	BSMP_PH_SC_RANDOM,	/* SC JW/NC: waiting peer nonce */
	BSMP_PH_SC_PK_ROUND,	/* SC passkey: per-round confirm/nonce */
	BSMP_PH_SC_DHCHECK,	/* SC: waiting DHKey check */
	BSMP_PH_KEYDIST,	/* receiving OUR key distribution */
	BSMP_PH_DONE,
	BSMP_PH_FAILED,
};

/* ----------------------------------------------------------------
 * Transmit: wrap a single L2CAP B-frame in one LE ACL start fragment and
 * feed it into our emu, which the link delivers to the DUT side.
 *
 * ACL data packet (Vol 4 Part E Section 5.4.2):
 *   0x02 | Handle+Flags(2,LE) | Data_Total_Length(2,LE) | Data
 * L2CAP B-frame (Vol 3 Part A Section 3.1):
 *   PDU_Length(2,LE) | Channel_ID(2,LE) | Information_Payload
 * ---------------------------------------------------------------- */
static void
btpeer_tx_l2cap(struct btpeer *bp, uint16_t cid, const uint8_t *payload,
    uint16_t plen)
{
	uint8_t pkt[280];
	uint16_t acl_len;

	if (!bp->have_handle)
		(void)btpeer_bind_conn(bp);
	if (!bp->have_handle)
		return;
	if ((size_t)plen + 9 > sizeof(pkt))
		return;

	acl_len = (uint16_t)(4 + plen);		/* L2CAP header + payload */
	pkt[0] = NG_HCI_ACL_DATA_PKT;
	pk16(&pkt[1], NG_HCI_MK_CON_HANDLE(bp->handle,
	    NG_HCI_LE_PACKET_START, NG_HCI_POINT2POINT));
	pk16(&pkt[3], acl_len);
	pk16(&pkt[5], plen);			/* L2CAP PDU length */
	pk16(&pkt[7], cid);			/* L2CAP CID */
	if (plen != 0)
		memcpy(&pkt[9], payload, plen);

	hci_emu_input(bp->emu, pkt, (size_t)9 + plen);
}

/* ----------------------------------------------------------------
 * Peer server: attribute database
 * ---------------------------------------------------------------- */
static struct btpeer_attr *
srv_alloc(struct btpeer *bp, uint16_t uuid16, uint8_t perms,
    const void *value, uint16_t len)
{
	struct btpeer_attr *a;
	uint16_t cap;

	/* Writable attributes reserve headroom so a later Write can change the
	 * value length (Vol 3 Part F 3.4.5): capacity >= 32 or initial length. */
	cap = len;
	if ((perms & (BTPEER_PERM_WRITE | BTPEER_PERM_WRITE_ENC)) && cap < 32)
		cap = 32;
	if (bp->nattrs >= BTPEER_MAX_ATTRS)
		return (NULL);
	if (bp->val_used + cap > sizeof(bp->val_store))
		return (NULL);
	a = &bp->attrs[bp->nattrs++];
	a->handle = bp->next_handle++;
	a->uuid16 = uuid16;
	a->perms = perms;
	a->off = (uint16_t)bp->val_used;
	a->len = len;
	a->cap = cap;
	if (len != 0)
		memcpy(&bp->val_store[bp->val_used], value, len);
	bp->val_used += cap;
	return (a);
}

static struct btpeer_attr *
srv_find(struct btpeer *bp, uint16_t handle)
{
	int i;

	for (i = 0; i < bp->nattrs; i++)
		if (bp->attrs[i].handle == handle)
			return (&bp->attrs[i]);
	return (NULL);
}

uint16_t
btpeer_add_attr(struct btpeer *bp, uint16_t uuid16, uint8_t perms,
    const void *value, uint16_t len)
{
	struct btpeer_attr *a;

	a = srv_alloc(bp, uuid16, perms, value, len);
	return (a == NULL ? 0 : a->handle);
}

uint16_t
btpeer_add_service(struct btpeer *bp, uint16_t svc_uuid)
{
	uint8_t v[2];

	pk16(v, svc_uuid);
	/* Primary Service declaration value = service UUID (Vol 3 Part G 3.1). */
	return (btpeer_add_attr(bp, GATT_PRIMARY_SERVICE, BTPEER_PERM_READ,
	    v, 2));
}

uint16_t
btpeer_add_characteristic(struct btpeer *bp, uint16_t char_uuid, uint8_t props,
    uint8_t perms, const void *value, uint16_t len)
{
	struct btpeer_attr *decl;
	uint8_t dv[5];
	uint16_t val_handle;

	/*
	 * Characteristic declaration (Vol 3 Part G Section 3.3.1):
	 * Properties(1) | Value Handle(2) | Characteristic UUID(2).
	 * The value attribute immediately follows the declaration.
	 */
	val_handle = (uint16_t)(bp->next_handle + 1);
	dv[0] = props;
	pk16(&dv[1], val_handle);
	pk16(&dv[3], char_uuid);
	decl = srv_alloc(bp, GATT_CHARACTERISTIC, BTPEER_PERM_READ, dv, 5);
	if (decl == NULL)
		return (0);
	if (srv_alloc(bp, char_uuid, perms, value, len) == NULL)
		return (0);
	return (val_handle);
}

uint16_t
btpeer_add_cccd(struct btpeer *bp)
{
	uint8_t v[2] = { 0x00, 0x00 };

	/* CCCD (Vol 3 Part G Section 3.3.3.3): read/write, 2 octets. */
	return (btpeer_add_attr(bp, GATT_CCCD,
	    BTPEER_PERM_READ | BTPEER_PERM_WRITE, v, 2));
}

int
btpeer_set_value(struct btpeer *bp, uint16_t handle, const void *value,
    uint16_t len)
{
	struct btpeer_attr *a = srv_find(bp, handle);

	if (a == NULL || len > a->cap)
		return (-1);
	memcpy(&bp->val_store[a->off], value, len);
	a->len = len;
	return (0);
}

int
btpeer_get_value(const struct btpeer *bp, uint16_t handle, uint8_t *buf,
    size_t buflen, size_t *outlen)
{
	const struct btpeer_attr *a;
	int i;

	for (i = 0; i < bp->nattrs; i++) {
		if (bp->attrs[i].handle != handle)
			continue;
		a = &bp->attrs[i];
		if (a->len > buflen)
			return (-1);
		memcpy(buf, &bp->val_store[a->off], a->len);
		if (outlen != NULL)
			*outlen = a->len;
		return (0);
	}
	return (-1);
}

int
btpeer_get_cccd(const struct btpeer *bp, uint16_t handle, uint16_t *value)
{
	const struct btpeer_attr *a;
	int i;

	for (i = 0; i < bp->nattrs; i++) {
		if (bp->attrs[i].handle == handle &&
		    bp->attrs[i].uuid16 == GATT_CCCD) {
			a = &bp->attrs[i];
			if (value != NULL)
				*value = (a->len >= 2) ?
				    gt16(&bp->val_store[a->off]) : 0;
			return (0);
		}
	}
	return (-1);
}

/* End Group Handle of the service group starting at index si (Vol 3 Part G
 * Section 3.1): the last handle before the next service declaration. */
static uint16_t
srv_group_end(struct btpeer *bp, int si)
{
	int i;
	uint16_t end;

	end = bp->attrs[si].handle;
	for (i = si + 1; i < bp->nattrs; i++) {
		if (bp->attrs[i].uuid16 == GATT_PRIMARY_SERVICE ||
		    bp->attrs[i].uuid16 == GATT_SECONDARY_SERVICE)
			break;
		end = bp->attrs[i].handle;
	}
	return (end);
}

/* ----------------------------------------------------------------
 * Peer server: request handling (Vol 3 Part F Section 3.4)
 * ---------------------------------------------------------------- */
static void
srv_error(struct btpeer *bp, uint8_t req_op, uint16_t handle, uint8_t code)
{
	uint8_t pdu[5];

	/* Error Response (Vol 3 Part F 3.4.1.1). */
	pdu[0] = ATT_ERROR_RSP;
	pdu[1] = req_op;
	pk16(&pdu[2], handle);
	pdu[4] = code;
	btpeer_tx_l2cap(bp, L2CAP_CID_ATT, pdu, 5);
}

static void
srv_read(struct btpeer *bp, const uint8_t *pdu, uint16_t len, bool blob)
{
	struct btpeer_attr *a;
	uint16_t handle, offset;
	uint8_t rsp[512];
	uint16_t rlen, avail, mtu;

	if ((!blob && len < 3) || (blob && len < 5)) {
		srv_error(bp, pdu[0], 0, ATT_ERR_INVALID_PDU);
		return;
	}
	handle = gt16(&pdu[1]);
	offset = blob ? gt16(&pdu[3]) : 0;
	a = srv_find(bp, handle);
	if (a == NULL) {
		srv_error(bp, pdu[0], handle, ATT_ERR_INVALID_HANDLE);
		return;
	}
	if (!(a->perms & (BTPEER_PERM_READ | BTPEER_PERM_READ_ENC))) {
		srv_error(bp, pdu[0], handle, ATT_ERR_READ_NOT_PERMITTED);
		return;
	}
	if (offset > a->len) {
		srv_error(bp, pdu[0], handle, 0x07 /* Invalid Offset */);
		return;
	}
	mtu = bp->mtu;
	rsp[0] = blob ? ATT_READ_BLOB_RSP : ATT_READ_RSP;
	avail = (uint16_t)(a->len - offset);
	if (avail > (uint16_t)(mtu - 1))
		avail = (uint16_t)(mtu - 1);
	memcpy(&rsp[1], &bp->val_store[a->off + offset], avail);
	rlen = (uint16_t)(1 + avail);
	btpeer_tx_l2cap(bp, L2CAP_CID_ATT, rsp, rlen);
}

static void
srv_read_by_group(struct btpeer *bp, const uint8_t *pdu, uint16_t len)
{
	uint16_t start, end, type;
	uint8_t rsp[512];
	uint16_t rlen;
	int i;
	bool any;

	/* Read By Group Type Request (Vol 3 Part F 3.4.4.9). */
	if (len < 7) {
		srv_error(bp, pdu[0], 0, ATT_ERR_INVALID_PDU);
		return;
	}
	start = gt16(&pdu[1]);
	end = gt16(&pdu[3]);
	type = gt16(&pdu[5]);
	if (type != GATT_PRIMARY_SERVICE && type != GATT_SECONDARY_SERVICE) {
		srv_error(bp, pdu[0], start, ATT_ERR_UNSUPPORTED_GROUP_TYPE);
		return;
	}
	/* Response (3.4.4.10): opcode | Length | { start | end | value }*.
	 * Each service with a 16-bit UUID: Length = 2+2+2 = 6. */
	rsp[0] = ATT_READ_BY_GROUP_RSP;
	rsp[1] = 6;
	rlen = 2;
	any = false;
	for (i = 0; i < bp->nattrs; i++) {
		struct btpeer_attr *a = &bp->attrs[i];
		uint16_t gend;

		if (a->uuid16 != type)
			continue;
		if (a->handle < start || a->handle > end)
			continue;
		if (a->len != 2)	/* only 16-bit service UUIDs here */
			continue;
		if (rlen + 6 > (uint16_t)bp->mtu)
			break;
		gend = srv_group_end(bp, i);
		pk16(&rsp[rlen], a->handle);
		pk16(&rsp[rlen + 2], gend);
		memcpy(&rsp[rlen + 4], &bp->val_store[a->off], 2);
		rlen = (uint16_t)(rlen + 6);
		any = true;
	}
	if (!any) {
		srv_error(bp, pdu[0], start, ATT_ERR_ATTR_NOT_FOUND);
		return;
	}
	btpeer_tx_l2cap(bp, L2CAP_CID_ATT, rsp, rlen);
}

static void
srv_read_by_type(struct btpeer *bp, const uint8_t *pdu, uint16_t len)
{
	uint16_t start, end, type;
	uint8_t rsp[512];
	uint16_t rlen, elen;
	int i;
	bool any;

	/* Read By Type Request (Vol 3 Part F 3.4.4.1). */
	if (len < 7) {		/* 16-bit type only */
		srv_error(bp, pdu[0], 0, ATT_ERR_INVALID_PDU);
		return;
	}
	start = gt16(&pdu[1]);
	end = gt16(&pdu[3]);
	type = gt16(&pdu[5]);

	rsp[0] = ATT_READ_BY_TYPE_RSP;
	rlen = 2;
	elen = 0;
	any = false;
	for (i = 0; i < bp->nattrs; i++) {
		struct btpeer_attr *a = &bp->attrs[i];
		uint16_t thislen;

		if (a->uuid16 != type)
			continue;
		if (a->handle < start || a->handle > end)
			continue;
		/* Response record (3.4.4.2): Handle(2) | Value. */
		thislen = (uint16_t)(2 + a->len);
		if (thislen > (uint16_t)(bp->mtu - 2))
			thislen = (uint16_t)(bp->mtu - 2);
		if (!any) {
			elen = thislen;
			rsp[1] = (uint8_t)elen;	/* Length field */
		} else if (thislen != elen) {
			break;		/* only equal-length records per rsp */
		}
		if (rlen + elen > (uint16_t)bp->mtu)
			break;
		pk16(&rsp[rlen], a->handle);
		memcpy(&rsp[rlen + 2], &bp->val_store[a->off],
		    (size_t)elen - 2);
		rlen = (uint16_t)(rlen + elen);
		any = true;
	}
	if (!any) {
		srv_error(bp, pdu[0], start, ATT_ERR_ATTR_NOT_FOUND);
		return;
	}
	btpeer_tx_l2cap(bp, L2CAP_CID_ATT, rsp, rlen);
}

static void
srv_find_info(struct btpeer *bp, const uint8_t *pdu, uint16_t len)
{
	uint16_t start, end;
	uint8_t rsp[512];
	uint16_t rlen;
	int i;
	bool any;

	/* Find Information Request (Vol 3 Part F 3.4.3.1). */
	if (len < 5) {
		srv_error(bp, pdu[0], 0, ATT_ERR_INVALID_PDU);
		return;
	}
	start = gt16(&pdu[1]);
	end = gt16(&pdu[3]);
	/* Response (3.4.3.2): opcode | Format(0x01=16-bit) | {Handle|UUID}*. */
	rsp[0] = ATT_FIND_INFO_RSP;
	rsp[1] = 0x01;
	rlen = 2;
	any = false;
	for (i = 0; i < bp->nattrs; i++) {
		struct btpeer_attr *a = &bp->attrs[i];

		if (a->handle < start || a->handle > end)
			continue;
		if (rlen + 4 > (uint16_t)bp->mtu)
			break;
		pk16(&rsp[rlen], a->handle);
		pk16(&rsp[rlen + 2], a->uuid16);
		rlen = (uint16_t)(rlen + 4);
		any = true;
	}
	if (!any) {
		srv_error(bp, pdu[0], start, ATT_ERR_ATTR_NOT_FOUND);
		return;
	}
	btpeer_tx_l2cap(bp, L2CAP_CID_ATT, rsp, rlen);
}

static void
srv_write(struct btpeer *bp, const uint8_t *pdu, uint16_t len, bool cmd)
{
	struct btpeer_attr *a;
	uint16_t handle, vlen;

	/* Write Request/Command (Vol 3 Part F 3.4.5.1 / 3.4.5.3). */
	if (len < 3) {
		if (!cmd)
			srv_error(bp, pdu[0], 0, ATT_ERR_INVALID_PDU);
		return;
	}
	handle = gt16(&pdu[1]);
	vlen = (uint16_t)(len - 3);
	a = srv_find(bp, handle);
	if (a == NULL) {
		if (!cmd)
			srv_error(bp, pdu[0], handle, ATT_ERR_INVALID_HANDLE);
		return;
	}
	if (!(a->perms & (BTPEER_PERM_WRITE | BTPEER_PERM_WRITE_ENC))) {
		if (!cmd)
			srv_error(bp, pdu[0], handle,
			    ATT_ERR_WRITE_NOT_PERMITTED);
		return;
	}
	if (vlen > a->cap) {
		if (!cmd)
			srv_error(bp, pdu[0], handle,
			    0x0D /* Invalid Attribute Value Length */);
		return;
	}
	memcpy(&bp->val_store[a->off], &pdu[3], vlen);
	a->len = vlen;

	if (!cmd) {
		uint8_t rsp = ATT_WRITE_RSP;	/* 3.4.5.2 */
		btpeer_tx_l2cap(bp, L2CAP_CID_ATT, &rsp, 1);
	}

	/*
	 * Arm-on-subscribe: once OUR client enables notifications on the
	 * armed CCCD, push the staged notification (models a HID keystroke).
	 */
	if (bp->armed && a->uuid16 == GATT_CCCD && handle == bp->arm_cccd &&
	    vlen >= 2 && (gt16(&pdu[3]) & 0x0001) != 0) {
		btpeer_server_notify(bp, bp->arm_val_handle, bp->arm_val,
		    bp->arm_val_len);
	}
}

static void
srv_read_multiple(struct btpeer *bp, const uint8_t *pdu, uint16_t len)
{
	uint8_t rsp[512];
	uint16_t rlen;
	int i;

	/* Read Multiple Request (Vol 3 Part F 3.4.4.7): >= 2 handles. */
	if (len < 5 || ((len - 1) % 2) != 0) {
		srv_error(bp, pdu[0], 0, ATT_ERR_INVALID_PDU);
		return;
	}
	rsp[0] = ATT_READ_MULTIPLE_RSP;
	rlen = 1;
	/* Response (3.4.4.8): opcode | Set Of Values (each value untruncated
	 * except the last may be clamped to MTU). */
	for (i = 1; i + 1 < (int)len; i += 2) {
		uint16_t h = gt16(&pdu[i]);
		struct btpeer_attr *a = srv_find(bp, h);
		uint16_t take;

		if (a == NULL) {
			srv_error(bp, pdu[0], h, ATT_ERR_INVALID_HANDLE);
			return;
		}
		if (!(a->perms & (BTPEER_PERM_READ | BTPEER_PERM_READ_ENC))) {
			srv_error(bp, pdu[0], h, ATT_ERR_READ_NOT_PERMITTED);
			return;
		}
		take = a->len;
		if (rlen + take > bp->mtu)
			take = (uint16_t)(bp->mtu - rlen);
		memcpy(&rsp[rlen], &bp->val_store[a->off], take);
		rlen = (uint16_t)(rlen + take);
		if (rlen >= bp->mtu)
			break;
	}
	btpeer_tx_l2cap(bp, L2CAP_CID_ATT, rsp, rlen);
}

static void
srv_find_by_type(struct btpeer *bp, const uint8_t *pdu, uint16_t len)
{
	uint16_t start, end, type;
	uint8_t rsp[512];
	uint16_t rlen;
	int i;
	bool any;

	/* Find By Type Value Request (Vol 3 Part F 3.4.3.3):
	 * opcode | Start | End | Attribute Type(2) | Attribute Value. */
	if (len < 7) {
		srv_error(bp, pdu[0], 0, ATT_ERR_INVALID_PDU);
		return;
	}
	start = gt16(&pdu[1]);
	end = gt16(&pdu[3]);
	type = gt16(&pdu[5]);
	/* Response (3.4.3.4): opcode | { Found Handle | Group End Handle }*. */
	rsp[0] = ATT_FIND_BY_TYPE_RSP;
	rlen = 1;
	any = false;
	for (i = 0; i < bp->nattrs; i++) {
		struct btpeer_attr *a = &bp->attrs[i];
		uint16_t gend;

		if (a->uuid16 != type)
			continue;
		if (a->handle < start || a->handle > end)
			continue;
		/* Compare the attribute value with the searched value. */
		if (a->len != (uint16_t)(len - 7) ||
		    memcmp(&bp->val_store[a->off], &pdu[7], a->len) != 0)
			continue;
		if (rlen + 4 > bp->mtu)
			break;
		gend = srv_group_end(bp, i);
		pk16(&rsp[rlen], a->handle);
		pk16(&rsp[rlen + 2], gend);
		rlen = (uint16_t)(rlen + 4);
		any = true;
	}
	if (!any) {
		srv_error(bp, pdu[0], start, ATT_ERR_ATTR_NOT_FOUND);
		return;
	}
	btpeer_tx_l2cap(bp, L2CAP_CID_ATT, rsp, rlen);
}

static void
srv_prepare_write(struct btpeer *bp, const uint8_t *pdu, uint16_t len)
{
	struct btpeer_attr *a;
	uint16_t handle, offset, vlen;
	uint8_t rsp[512];

	/* Prepare Write Request (Vol 3 Part F 3.4.6.1):
	 * opcode | Handle | Value Offset | Part Attribute Value. */
	if (len < 5) {
		srv_error(bp, pdu[0], 0, ATT_ERR_INVALID_PDU);
		return;
	}
	handle = gt16(&pdu[1]);
	offset = gt16(&pdu[3]);
	vlen = (uint16_t)(len - 5);
	a = srv_find(bp, handle);
	if (a == NULL) {
		srv_error(bp, pdu[0], handle, ATT_ERR_INVALID_HANDLE);
		return;
	}
	if (!(a->perms & (BTPEER_PERM_WRITE | BTPEER_PERM_WRITE_ENC))) {
		srv_error(bp, pdu[0], handle, ATT_ERR_WRITE_NOT_PERMITTED);
		return;
	}
	if (bp->nprep >= (int)(sizeof(bp->prepq) / sizeof(bp->prepq[0]))) {
		srv_error(bp, pdu[0], handle, ATT_ERR_PREPARE_QUEUE_FULL);
		return;
	}
	if (vlen > sizeof(bp->prepq[0].val)) {
		srv_error(bp, pdu[0], handle, ATT_ERR_INVALID_ATTR_VAL_LEN);
		return;
	}
	bp->prepq[bp->nprep].handle = handle;
	bp->prepq[bp->nprep].offset = offset;
	memcpy(bp->prepq[bp->nprep].val, &pdu[5], vlen);
	bp->prepq[bp->nprep].len = vlen;
	bp->nprep++;
	/* Response (3.4.6.2): echo the whole request verbatim. */
	rsp[0] = ATT_PREPARE_WRITE_RSP;
	memcpy(&rsp[1], &pdu[1], (size_t)len - 1);
	btpeer_tx_l2cap(bp, L2CAP_CID_ATT, rsp, len);
}

static void
srv_execute_write(struct btpeer *bp, const uint8_t *pdu, uint16_t len)
{
	uint8_t rsp;
	int i;

	/* Execute Write Request (Vol 3 Part F 3.4.6.3): opcode | Flags. */
	if (len < 2) {
		srv_error(bp, pdu[0], 0, ATT_ERR_INVALID_PDU);
		return;
	}
	if (pdu[1] == 0x01) {			/* write the queued values */
		for (i = 0; i < bp->nprep; i++) {
			struct btpeer_attr *a = srv_find(bp, bp->prepq[i].handle);
			uint16_t end;

			if (a == NULL)
				continue;
			end = (uint16_t)(bp->prepq[i].offset + bp->prepq[i].len);
			if (end > a->cap) {
				bp->nprep = 0;
				srv_error(bp, pdu[0], bp->prepq[i].handle,
				    ATT_ERR_INVALID_OFFSET);
				return;
			}
			memcpy(&bp->val_store[a->off + bp->prepq[i].offset],
			    bp->prepq[i].val, bp->prepq[i].len);
			if (end > a->len)
				a->len = end;
		}
	}
	bp->nprep = 0;				/* 0x00 cancels the queue */
	rsp = ATT_EXECUTE_WRITE_RSP;		/* 3.4.6.4 */
	btpeer_tx_l2cap(bp, L2CAP_CID_ATT, &rsp, 1);
}

static void
btpeer_srv_handle(struct btpeer *bp, const uint8_t *pdu, uint16_t len)
{

	switch (pdu[0]) {
	case ATT_READ_MULTIPLE_REQ:
		srv_read_multiple(bp, pdu, len);
		break;
	case ATT_FIND_BY_TYPE_REQ:
		srv_find_by_type(bp, pdu, len);
		break;
	case ATT_PREPARE_WRITE_REQ:
		srv_prepare_write(bp, pdu, len);
		break;
	case ATT_EXECUTE_WRITE_REQ:
		srv_execute_write(bp, pdu, len);
		break;
	case ATT_MTU_REQ:
		/* Exchange MTU Response (Vol 3 Part F 3.4.2.2). */
		if (len >= 3) {
			uint8_t rsp[3];
			uint16_t cmtu = gt16(&pdu[1]);

			if (cmtu >= 23 && cmtu < bp->mtu)
				bp->mtu = cmtu;
			rsp[0] = ATT_MTU_RSP;
			pk16(&rsp[1], bp->mtu);
			btpeer_tx_l2cap(bp, L2CAP_CID_ATT, rsp, 3);
		}
		break;
	case ATT_READ_REQ:
		srv_read(bp, pdu, len, false);
		break;
	case ATT_READ_BLOB_REQ:
		srv_read(bp, pdu, len, true);
		break;
	case ATT_READ_BY_GROUP_REQ:
		srv_read_by_group(bp, pdu, len);
		break;
	case ATT_READ_BY_TYPE_REQ:
		srv_read_by_type(bp, pdu, len);
		break;
	case ATT_FIND_INFO_REQ:
		srv_find_info(bp, pdu, len);
		break;
	case ATT_WRITE_REQ:
		srv_write(bp, pdu, len, false);
		break;
	case ATT_WRITE_CMD:
		srv_write(bp, pdu, len, true);
		break;
	case ATT_HANDLE_CFM:
		/* Confirmation for our Indication (Vol 3 Part F 3.4.7.3). */
		break;
	default:
		/* Request Not Supported (Vol 3 Part F 3.4.1.1). */
		srv_error(bp, pdu[0], 0, ATT_ERR_REQ_NOT_SUPPORTED);
		break;
	}
}

int
btpeer_server_notify(struct btpeer *bp, uint16_t handle, const void *value,
    uint16_t len)
{
	uint8_t pdu[512];

	/* Handle Value Notification (Vol 3 Part F 3.4.7.1). */
	if ((size_t)len + 3 > bp->mtu || (size_t)len + 3 > sizeof(pdu))
		return (-1);
	pdu[0] = ATT_HANDLE_NOTIFY;
	pk16(&pdu[1], handle);
	memcpy(&pdu[3], value, len);
	btpeer_tx_l2cap(bp, L2CAP_CID_ATT, pdu, (uint16_t)(3 + len));
	return (0);
}

int
btpeer_server_indicate(struct btpeer *bp, uint16_t handle, const void *value,
    uint16_t len)
{
	uint8_t pdu[512];

	/* Handle Value Indication (Vol 3 Part F 3.4.7.2). */
	if ((size_t)len + 3 > bp->mtu || (size_t)len + 3 > sizeof(pdu))
		return (-1);
	pdu[0] = ATT_HANDLE_IND;
	pk16(&pdu[1], handle);
	memcpy(&pdu[3], value, len);
	btpeer_tx_l2cap(bp, L2CAP_CID_ATT, pdu, (uint16_t)(3 + len));
	return (0);
}

int
btpeer_arm_notify_on_subscribe(struct btpeer *bp, uint16_t cccd_handle,
    uint16_t value_handle, const void *value, uint16_t len)
{

	if (len > sizeof(bp->arm_val))
		return (-1);
	bp->armed = true;
	bp->arm_cccd = cccd_handle;
	bp->arm_val_handle = value_handle;
	memcpy(bp->arm_val, value, len);
	bp->arm_val_len = len;
	return (0);
}

/* ----------------------------------------------------------------
 * Peer client: receive responses / notifications
 * ---------------------------------------------------------------- */
static void
btpeer_client_rx(struct btpeer *bp, const uint8_t *pdu, uint16_t len)
{

	if (pdu[0] == ATT_HANDLE_NOTIFY || pdu[0] == ATT_HANDLE_IND) {
		uint16_t h = (len >= 3) ? gt16(&pdu[1]) : 0;
		bool ind = (pdu[0] == ATT_HANDLE_IND);

		if (ind) {
			uint8_t cfm = ATT_HANDLE_CFM;	/* 3.4.7.3 */
			btpeer_tx_l2cap(bp, L2CAP_CID_ATT, &cfm, 1);
		}
		if (bp->notify_cb != NULL)
			bp->notify_cb(bp->notify_arg, h,
			    (len > 3) ? &pdu[3] : NULL,
			    (uint16_t)((len > 3) ? len - 3 : 0), ind);
		return;
	}

	/*
	 * Multiple Handle Value Notification (0x23, Vol 3 Part F 3.4.7.4):
	 * a concatenation of {Handle(2), Value Length(2), Value} tuples with no
	 * confirmation.  Deliver one callback per tuple (indication == false).
	 */
	if (pdu[0] == ATT_MULTI_HANDLE_NOTIFY) {
		uint16_t off = 1;

		while ((uint16_t)(off + 4) <= len) {
			uint16_t h = gt16(&pdu[off]);
			uint16_t vl = gt16(&pdu[off + 2]);

			if ((uint16_t)(off + 4 + vl) > len)
				break;		/* malformed tuple */
			if (bp->notify_cb != NULL)
				bp->notify_cb(bp->notify_arg, h,
				    (vl > 0) ? &pdu[off + 4] : NULL, vl, false);
			off = (uint16_t)(off + 4 + vl);
		}
		return;
	}

	if (pdu[0] == ATT_ERROR_RSP && len >= 5) {
		bp->have_err = true;
		bp->err_req_op = pdu[1];
		bp->err_handle = gt16(&pdu[2]);
		bp->err_code = pdu[4];
	}
	if (pdu[0] == ATT_PREPARE_WRITE_RSP && len >= 5) {
		uint16_t vl = (uint16_t)(len - 5);

		bp->prep_echo_valid = true;
		bp->prep_echo_handle = gt16(&pdu[1]);
		bp->prep_echo_offset = gt16(&pdu[3]);
		if (vl > sizeof(bp->prep_echo_val))
			vl = sizeof(bp->prep_echo_val);
		memcpy(bp->prep_echo_val, &pdu[5], vl);
		bp->prep_echo_len = vl;
	}
	if (len > sizeof(bp->rsp))
		len = sizeof(bp->rsp);
	memcpy(bp->rsp, pdu, len);
	bp->rsp_len = len;
	bp->rsp_ready = true;
}

/* Is this opcode a request the peer's server must answer? */
static bool
is_server_request(uint8_t op)
{

	switch (op) {
	case ATT_MTU_REQ:
	case ATT_FIND_INFO_REQ:
	case ATT_FIND_BY_TYPE_REQ:
	case ATT_READ_BY_TYPE_REQ:
	case ATT_READ_REQ:
	case ATT_READ_BLOB_REQ:
	case ATT_READ_MULTIPLE_REQ:
	case ATT_READ_BY_GROUP_REQ:
	case ATT_WRITE_REQ:
	case ATT_WRITE_CMD:
	case ATT_PREPARE_WRITE_REQ:
	case ATT_EXECUTE_WRITE_REQ:
	case ATT_HANDLE_CFM:
		return (true);
	default:
		return (false);
	}
}

/* ----------------------------------------------------------------
 * SMP peer (Vol 3 Part H): full pairing-method matrix, both roles.
 * ---------------------------------------------------------------- */

/* SMP wire address-type octet (Vol 3 Part H 2.3): 0x00 public, 0x01 random. */
static uint8_t
bsmp_wtype(uint8_t t)
{

	return ((t == 1 || t == BDADDR_LE_RANDOM) ? 1 : 0);
}

/* Packed address for f5/f6 (Vol 3 Part H 2.2.7): addr(6) | type(1). */
static void
bsmp_pack(uint8_t out[7], const uint8_t addr[6], uint8_t t)
{

	memcpy(out, addr, 6);
	out[6] = bsmp_wtype(t);
}

static uint8_t
bsmp_authreq(const struct btpeer *bp)
{
	uint8_t a = 0;

	if (bp->smp_cfg.bonding)
		a |= SMP_AUTH_BONDING;
	if (bp->smp_cfg.mitm)
		a |= SMP_AUTH_MITM;
	if (bp->smp_cfg.sc)
		a |= SMP_AUTH_SC;
	return (a);
}

static void
bsmp_fail(struct btpeer *bp, uint8_t reason)
{
	uint8_t p[2];

	p[0] = SMP_PAIRING_FAILED;
	p[1] = reason;
	btpeer_tx_l2cap(bp, L2CAP_CID_SMP, p, 2);
	bp->smp_fail = reason;
	bp->smp_phase = BSMP_PH_FAILED;
}

/* Wire opcode + full length of the PDU a given handshake stage carries. */
static uint8_t
bsmp_stage_opcode(uint8_t stage)
{

	switch (stage) {
	case BTPEER_SMP_STAGE_PUBKEY:	return (SMP_PAIRING_PUBLIC_KEY);
	case BTPEER_SMP_STAGE_CONFIRM:	return (SMP_PAIRING_CONFIRM);
	case BTPEER_SMP_STAGE_RANDOM:	return (SMP_PAIRING_RANDOM);
	case BTPEER_SMP_STAGE_DHCHECK:	return (SMP_PAIRING_DHKEY_CHECK);
	default:			return (0);
	}
}

/*
 * Mid-flow fault injection (Vol 3 Part H 3.5.5).  Called at every point the
 * peer is about to emit a stage PDU (public key / confirm / random / DHKey
 * check).  If a fault is armed for `stage` and has not fired yet, emit the
 * spec-defined fault instead of the normal PDU, mark the exchange failed, and
 * return true so the caller aborts its normal send.  Fires at most once.
 */
static bool
bsmp_inject(struct btpeer *bp, uint8_t stage)
{
	uint8_t p[65];
	uint16_t len;

	if (bp->smp_cfg.inject_stage != stage ||
	    bp->smp_cfg.inject_action == BTPEER_SMP_INJECT_NONE ||
	    bp->inject_fired)
		return (false);
	bp->inject_fired = true;
	len = (stage == BTPEER_SMP_STAGE_PUBKEY) ? 65 : 17;

	switch (bp->smp_cfg.inject_action) {
	case BTPEER_SMP_INJECT_FAIL:
		/*
		 * A spec-legal peer rejection at this stage (Table 3.7 reason).
		 * OUR side must surface it as EACCES and tear down.
		 */
		bsmp_fail(bp, bp->smp_cfg.inject_reason);
		return (true);
	case BTPEER_SMP_INJECT_WRONG_OPCODE:
		/*
		 * Correct length, but a wrong (valid, non-Failed) opcode so OUR
		 * side takes the opcode-mismatch (EPROTO) arm rather than the
		 * Pairing-Failed (EACCES) arm.  Use Confirm unless Confirm is
		 * what was expected, in which case use Random.
		 */
		memset(p, 0xAB, sizeof(p));
		p[0] = (stage == BTPEER_SMP_STAGE_CONFIRM) ?
		    SMP_PAIRING_RANDOM : SMP_PAIRING_CONFIRM;
		btpeer_tx_l2cap(bp, L2CAP_CID_SMP, p, len);
		bp->smp_phase = BSMP_PH_FAILED;
		return (true);
	case BTPEER_SMP_INJECT_TRUNCATED:
		/*
		 * Correct opcode, but a single octet so OUR receive-side length
		 * guard (n < 17 / n < 65) drops it as EPROTO.
		 */
		p[0] = bsmp_stage_opcode(stage);
		btpeer_tx_l2cap(bp, L2CAP_CID_SMP, p, 1);
		bp->smp_phase = BSMP_PH_FAILED;
		return (true);
	case BTPEER_SMP_INJECT_OFF_CURVE:
		/*
		 * A full 65-octet Public Key whose coordinates are not on the
		 * P-256 curve (Vol 3 Part H 2.3.5.6.1): OUR side must fail
		 * public-key validation and reply Pairing Failed (DHKey Check
		 * Failed).  Only meaningful at the PUBKEY stage.
		 */
		memset(p, 0xEE, sizeof(p));
		p[0] = SMP_PAIRING_PUBLIC_KEY;
		btpeer_tx_l2cap(bp, L2CAP_CID_SMP, p, 65);
		bp->smp_phase = BSMP_PH_FAILED;
		return (true);
	default:
		return (false);
	}
}

/* Count of key-distribution PDUs implied by a distribution mask. */
static int
bsmp_key_count(uint8_t dist, bool is_sc)
{
	int n = 0;

	if (!is_sc && (dist & SMP_KEY_DIST_ENC_KEY))
		n += 2;			/* Encryption Info + Central ID */
	if (dist & SMP_KEY_DIST_ID_KEY)
		n += 2;			/* Identity Info + Identity Addr */
	if (dist & SMP_KEY_DIST_LEGACY_SIGN_KEY)
		n += 1;			/* Signing Info */
	return (n);
}

/* Our own identity address by role (initiator uses init_addr, else peer_addr). */
static void
bsmp_own_addr(const struct btpeer *bp, uint8_t addr[6], uint8_t *wtype)
{

	if (bp->smp_cfg.role == BTPEER_SMP_INITIATOR) {
		memcpy(addr, bp->init_addr, 6);
		*wtype = bsmp_wtype(bp->init_addr_type);
	} else {
		memcpy(addr, bp->peer_addr, 6);
		*wtype = bsmp_wtype(bp->peer_addr_type);
	}
}

/*
 * Transmit one distributed key PDU (Vol 3 Part H 3.6).  If a key-distribution
 * fault is armed for this opcode, send it TRUNCATED (a lone opcode octet) so
 * OUR receive-side length guard (n >= 17 / n >= 8) drops it.
 */
static void
bsmp_kd_tx(struct btpeer *bp, const uint8_t *p, uint16_t len)
{

	if (p[0] == bp->smp_cfg.inject_kd_trunc_opcode)
		len = 1;
	btpeer_tx_l2cap(bp, L2CAP_CID_SMP, p, len);
}

/* Emit our key distribution PDUs (Vol 3 Part H 3.6.2-3.6.6). */
static void
bsmp_send_keys(struct btpeer *bp, uint8_t dist, bool is_sc)
{
	uint8_t p[17], addr[6], wt;

	if (!is_sc && (dist & SMP_KEY_DIST_ENC_KEY)) {
		/* Encryption Information: our LTK (deterministic for the test). */
		p[0] = SMP_ENCRYPTION_INFORMATION;
		if (bp->smp_cfg.have_local_ltk)
			memcpy(p + 1, bp->smp_cfg.local_ltk, 16);
		else
			memset(p + 1, 0x40, 16);
		memcpy(bp->smp_ltk, p + 1, 16);
		bsmp_kd_tx(bp, p, 17);
		/* Central Identification: EDIV=0, Rand=0 (STK-style). */
		p[0] = SMP_CENTRAL_IDENTIFICATION;
		memset(p + 1, 0, 10);
		bsmp_kd_tx(bp, p, 11);
	}
	if (dist & SMP_KEY_DIST_ID_KEY) {
		p[0] = SMP_IDENTITY_INFORMATION;	/* our IRK */
		if (bp->smp_cfg.have_local_irk)
			memcpy(p + 1, bp->smp_cfg.local_irk, 16);
		else
			memset(p + 1, 0x55, 16);
		bsmp_kd_tx(bp, p, 17);
		p[0] = SMP_IDENTITY_ADDRESS_INFO;
		bsmp_own_addr(bp, addr, &wt);
		p[1] = wt;
		memcpy(p + 2, addr, 6);
		bsmp_kd_tx(bp, p, 8);
	}
	if (dist & SMP_KEY_DIST_LEGACY_SIGN_KEY) {
		p[0] = SMP_LEGACY_SIGNING_INFORMATION;		/* our CSRK */
		if (bp->smp_cfg.have_local_csrk)
			memcpy(p + 1, bp->smp_cfg.local_csrk, 16);
		else
			memset(p + 1, 0x66, 16);
		bsmp_kd_tx(bp, p, 17);
	}
}

/* Store a key-distribution PDU received from OUR side (Vol 3 Part H 3.6). */
static void
bsmp_store_peer_key(struct btpeer *bp, const uint8_t *pdu, uint16_t len)
{

	switch (pdu[0]) {
	case SMP_IDENTITY_INFORMATION:
		if (len >= 17) {
			memcpy(bp->peer_irk, &pdu[1], 16);
			bp->got_irk = true;
		}
		break;
	case SMP_IDENTITY_ADDRESS_INFO:
		if (len >= 8) {
			bp->peer_id_type = pdu[1];
			memcpy(bp->peer_id_addr, &pdu[2], 6);
			bp->got_identity = true;
		}
		break;
	case SMP_LEGACY_SIGNING_INFORMATION:
		if (len >= 17) {
			memcpy(bp->peer_csrk, &pdu[1], 16);
			bp->got_csrk = true;
		}
		break;
	default:
		break;			/* Encryption Info / Central ID: ignore */
	}
}

/* Once handshake + (mock) encryption is done, distribute/collect keys. */
static void
bsmp_enter_keydist(struct btpeer *bp)
{
	uint8_t init_dist, resp_dist;

	bp->smp_bonded = true;
	bp->smp_phase = BSMP_PH_KEYDIST;
	init_dist = (uint8_t)(bp->preq[5] & bp->pres[5]);
	resp_dist = bp->pres[6];

	if (bp->smp_cfg.role == BTPEER_SMP_RESPONDER) {
		/* Responder distributes first, then receives initiator keys. */
		bsmp_send_keys(bp, resp_dist, bp->smp_is_sc);
		bp->keydist_recv = bsmp_key_count(init_dist, bp->smp_is_sc);
	} else {
		/* Initiator receives responder keys first, then distributes. */
		bp->keydist_recv = bsmp_key_count(resp_dist, bp->smp_is_sc);
		if (bp->keydist_recv == 0)
			bsmp_send_keys(bp, init_dist, bp->smp_is_sc);
	}
	if (bp->keydist_recv == 0)
		bp->smp_phase = BSMP_PH_DONE;
}

static void
bsmp_keydist_rx(struct btpeer *bp, const uint8_t *pdu, uint16_t len)
{

	bsmp_store_peer_key(bp, pdu, len);
	if (bp->keydist_recv > 0)
		bp->keydist_recv--;
	if (bp->keydist_recv == 0) {
		if (bp->smp_cfg.role == BTPEER_SMP_INITIATOR)
			bsmp_send_keys(bp, (uint8_t)(bp->preq[5] & bp->pres[5]),
			    bp->smp_is_sc);
		bp->smp_phase = BSMP_PH_DONE;
	}
}

/* ---- Legacy pairing (c1/s1, Vol 3 Part H 2.2.3/2.2.4) ---- */
static void
bsmp_legacy_tk(const struct btpeer *bp, uint8_t tk[16])
{

	memset(tk, 0, 16);		/* Just Works TK = 0 (2.3.5.2) */
	if (bp->smp_cfg.method == BTPEER_SMP_PASSKEY) {
		tk[0] = (uint8_t)(bp->smp_cfg.passkey & 0xFF);
		tk[1] = (uint8_t)((bp->smp_cfg.passkey >> 8) & 0xFF);
		tk[2] = (uint8_t)((bp->smp_cfg.passkey >> 16) & 0xFF);
	} else if (bp->smp_cfg.method == BTPEER_SMP_OOB && bp->have_oob_tk) {
		memcpy(tk, bp->oob_tk, 16);
	}
}

static void
bsmp_legacy_rx(struct btpeer *bp, const uint8_t *pdu, uint16_t len)
{
	uint8_t tk[16], out[17], iat, rat;

	bsmp_legacy_tk(bp, tk);
	iat = bsmp_wtype(bp->init_addr_type);
	rat = bsmp_wtype(bp->peer_addr_type);

	if (bp->smp_cfg.role == BTPEER_SMP_RESPONDER) {
		switch (pdu[0]) {
		case SMP_PAIRING_CONFIRM:
			if (len < 17)
				return;
			if (bsmp_inject(bp, BTPEER_SMP_STAGE_CONFIRM))
				return;
			memcpy(bp->mconfirm, &pdu[1], 16);
			out[0] = SMP_PAIRING_CONFIRM;
			if (smp_c1(tk, bp->srand, bp->preq, bp->pres, iat,
			    bp->init_addr, rat, bp->peer_addr, &out[1]) < 0)
				return;
			if (bp->smp_cfg.force_confirm_mismatch)
				out[1] ^= 0xFF;
			btpeer_tx_l2cap(bp, L2CAP_CID_SMP, out, 17);
			bp->smp_phase = BSMP_PH_LEG_RANDOM;
			break;
		case SMP_PAIRING_RANDOM: {
			uint8_t verify[16];

			if (len < 17)
				return;
			if (bsmp_inject(bp, BTPEER_SMP_STAGE_RANDOM))
				return;
			/* Verify initiator confirm (Vol 3 Part H 2.3.5.5). */
			if (smp_c1(tk, &pdu[1], bp->preq, bp->pres, iat,
			    bp->init_addr, rat, bp->peer_addr, verify) < 0)
				return;
			if (memcmp(verify, bp->mconfirm, 16) != 0) {
				bsmp_fail(bp, SMP_ERR_CONFIRM_VALUE_FAILED);
				return;
			}
			out[0] = SMP_PAIRING_RANDOM;
			memcpy(&out[1], bp->srand, 16);
			btpeer_tx_l2cap(bp, L2CAP_CID_SMP, out, 17);
			if (smp_s1(tk, bp->srand, &pdu[1], bp->stk) == 0) {
				bp->smp_have_stk = true;
				memcpy(bp->smp_ltk, bp->stk, 16);
			}
			bp->smp_is_sc = false;
			bp->smp_is_mitm = (bp->smp_cfg.method != BTPEER_SMP_JUST_WORKS);
			bsmp_enter_keydist(bp);
			break;
		}
		default:
			break;
		}
	} else {			/* INITIATOR */
		switch (pdu[0]) {
		case SMP_PAIRING_CONFIRM:
			if (len < 17)
				return;
			memcpy(bp->mconfirm, &pdu[1], 16);	/* peer confirm */
			if (bsmp_inject(bp, BTPEER_SMP_STAGE_RANDOM))
				return;
			out[0] = SMP_PAIRING_RANDOM;
			memcpy(&out[1], bp->srand, 16);		/* our mrand */
			btpeer_tx_l2cap(bp, L2CAP_CID_SMP, out, 17);
			bp->smp_phase = BSMP_PH_LEG_RANDOM;
			break;
		case SMP_PAIRING_RANDOM: {
			uint8_t verify[16];

			if (len < 17)
				return;
			if (smp_c1(tk, &pdu[1], bp->preq, bp->pres, iat,
			    bp->init_addr, rat, bp->peer_addr, verify) < 0)
				return;
			if (memcmp(verify, bp->mconfirm, 16) != 0) {
				bsmp_fail(bp, SMP_ERR_CONFIRM_VALUE_FAILED);
				return;
			}
			if (smp_s1(tk, &pdu[1], bp->srand, bp->stk) == 0) {
				bp->smp_have_stk = true;
				memcpy(bp->smp_ltk, bp->stk, 16);
			}
			bp->smp_is_sc = false;
			bp->smp_is_mitm = (bp->smp_cfg.method != BTPEER_SMP_JUST_WORKS);
			bsmp_enter_keydist(bp);
			break;
		}
		default:
			break;
		}
	}
}

/* ---- Secure Connections crypto scaffold ---- */
static int
bsmp_sc_keygen(struct btpeer *bp)
{
	EVP_PKEY_CTX *pctx;
	uint8_t raw[65];
	size_t rawlen = sizeof(raw);

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pctx == NULL)
		return (-1);
	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
	if (EVP_PKEY_keygen(pctx, &bp->sc_key) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return (-1);
	}
	EVP_PKEY_CTX_free(pctx);
	if (EVP_PKEY_get_octet_string_param(bp->sc_key, OSSL_PKEY_PARAM_PUB_KEY,
	    raw, sizeof(raw), &rawlen) <= 0)
		return (-1);
	/* Wire LE: reverse each 32-byte BE coordinate (Vol 3 Part H 2.3.5.6.1). */
	smp_swap_buf(bp->sc_pk_le, raw + 1, 32);
	smp_swap_buf(bp->sc_pk_le + 32, raw + 33, 32);
	return (0);
}

static int
bsmp_sc_dhkey(struct btpeer *bp, const uint8_t peer_pk_le[64])
{
	uint8_t peer_be[65], dh_be[32];
	EVP_PKEY *peer = NULL;
	EVP_PKEY_CTX *fctx, *dctx;
	OSSL_PARAM params[3];
	static char curve[] = "prime256v1";
	size_t dl = sizeof(dh_be);

	peer_be[0] = 0x04;
	smp_swap_buf(peer_be + 1, peer_pk_le, 32);
	smp_swap_buf(peer_be + 33, peer_pk_le + 32, 32);
	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
	    curve, 0);
	params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
	    peer_be, 65);
	params[2] = OSSL_PARAM_construct_end();
	fctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	EVP_PKEY_fromdata_init(fctx);
	EVP_PKEY_fromdata(fctx, &peer, EVP_PKEY_PUBLIC_KEY, params);
	EVP_PKEY_CTX_free(fctx);
	if (peer == NULL)
		return (-1);
	dctx = EVP_PKEY_CTX_new(bp->sc_key, NULL);
	EVP_PKEY_derive_init(dctx);
	EVP_PKEY_derive_set_peer(dctx, peer);
	if (EVP_PKEY_derive(dctx, dh_be, &dl) <= 0) {
		EVP_PKEY_CTX_free(dctx);
		EVP_PKEY_free(peer);
		return (-1);
	}
	EVP_PKEY_CTX_free(dctx);
	EVP_PKEY_free(peer);
	smp_swap_buf(bp->sc_dhkey_le, dh_be, 32);
	return (0);
}

/* Send our SC public key (Vol 3 Part H 3.5.6). */
static void
bsmp_sc_send_pk(struct btpeer *bp)
{
	uint8_t pk[65];

	pk[0] = SMP_PAIRING_PUBLIC_KEY;
	memcpy(&pk[1], bp->sc_pk_le, 64);
	btpeer_tx_l2cap(bp, L2CAP_CID_SMP, pk, 65);
}

/* SC Stage 2: derive LTK, exchange DHKey checks (Vol 3 Part H 2.3.5.6.5). */
static void
bsmp_sc_stage2(struct btpeer *bp, bool we_send_first)
{
	uint8_t a1[7], a2[7], iocap_a[3], iocap_b[3];
	uint8_t mackey[16], r_ea[16], r_eb[16];

	bsmp_pack(a1, bp->init_addr, bp->init_addr_type);
	bsmp_pack(a2, bp->peer_addr, bp->peer_addr_type);
	iocap_a[0] = bp->preq[1]; iocap_a[1] = bp->preq[2]; iocap_a[2] = bp->preq[3];
	iocap_b[0] = bp->pres[1]; iocap_b[1] = bp->pres[2]; iocap_b[2] = bp->pres[3];

	memset(r_ea, 0, 16);
	memset(r_eb, 0, 16);
	if (bp->smp_cfg.method == BTPEER_SMP_PASSKEY) {
		/* ra = rb = passkey (Vol 3 Part H 2.3.5.6.5 Table). */
		r_ea[0] = (uint8_t)(bp->smp_cfg.passkey & 0xFF);
		r_ea[1] = (uint8_t)((bp->smp_cfg.passkey >> 8) & 0xFF);
		r_ea[2] = (uint8_t)((bp->smp_cfg.passkey >> 16) & 0xFF);
		memcpy(r_eb, r_ea, 16);
	} else if (bp->smp_cfg.method == BTPEER_SMP_OOB) {
		/* Ea uses initiator's ra, Eb uses responder's rb (2.3.5.6.5). */
		memcpy(r_ea, bp->oob_peer_rand, 16);	/* DUT initiator ra */
		memcpy(r_eb, bp->oob_local_rand, 16);	/* our rb */
	}

	if (smp_f5(bp->sc_dhkey_le, bp->sc_na, bp->sc_nb, a1, a2, mackey,
	    bp->smp_ltk) != 0 ||
	    smp_f6(mackey, bp->sc_na, bp->sc_nb, r_ea, iocap_a, a1, a2,
	    bp->sc_ea) != 0 ||
	    smp_f6(mackey, bp->sc_nb, bp->sc_na, r_eb, iocap_b, a2, a1,
	    bp->sc_eb) != 0) {
		bsmp_fail(bp, SMP_ERR_UNSPECIFIED_REASON);
		return;
	}
	bp->smp_is_sc = true;
	bp->smp_is_mitm = (bp->smp_cfg.method != BTPEER_SMP_JUST_WORKS);

	if (we_send_first) {		/* initiator: send Ea, wait Eb */
		uint8_t out[17];
		if (bsmp_inject(bp, BTPEER_SMP_STAGE_DHCHECK)) {
			bp->smp_phase = BSMP_PH_SC_DHCHECK;
			return;			/* fault in place of Ea */
		}
		out[0] = SMP_PAIRING_DHKEY_CHECK;
		memcpy(&out[1], bp->sc_ea, 16);
		if (bp->smp_cfg.force_dhkey_mismatch)
			out[1] ^= 0xFF;
		btpeer_tx_l2cap(bp, L2CAP_CID_SMP, out, 17);
		bp->smp_phase = BSMP_PH_SC_DHCHECK;
	}
	/* responder waits for Ea in SC_DHCHECK phase (set by caller). */
}

/* SC round setup for Passkey Entry (Vol 3 Part H 2.3.5.6.3). */
static uint8_t
bsmp_passkey_ri(const struct btpeer *bp)
{

	return (uint8_t)(0x80 | ((bp->smp_cfg.passkey >> bp->sc_pk_round) & 1));
}

static void
bsmp_sc_rx(struct btpeer *bp, const uint8_t *pdu, uint16_t len)
{
	bool resp = (bp->smp_cfg.role == BTPEER_SMP_RESPONDER);
	uint8_t out[65];

	switch (bp->smp_phase) {
	case BSMP_PH_SC_PK:
		if (pdu[0] != SMP_PAIRING_PUBLIC_KEY || len < 65)
			return;
		if (resp) {
			memcpy(bp->sc_pka_le, &pdu[1], 32);	/* initiator PK x */
			/* Responder's Public Key is what OUR initiator receives
			 * next (Vol 3 Part H 2.3.5.6.1); inject a PK-stage fault
			 * here instead. */
			if (bsmp_inject(bp, BTPEER_SMP_STAGE_PUBKEY))
				return;
			if (bsmp_sc_keygen(bp) != 0) {
				bsmp_fail(bp, SMP_ERR_UNSPECIFIED_REASON);
				return;
			}
			memcpy(bp->sc_pkb_le, bp->sc_pk_le, 32);
			bsmp_sc_send_pk(bp);
			if (bsmp_sc_dhkey(bp, &pdu[1]) != 0) {
				bsmp_fail(bp, SMP_ERR_DHKEY_CHECK_FAILED);
				return;
			}
			if (bp->smp_cfg.method == BTPEER_SMP_PASSKEY) {
				bp->sc_pk_round = 0;
				bp->smp_phase = BSMP_PH_SC_PK_ROUND;
			} else if (bp->smp_cfg.method == BTPEER_SMP_OOB) {
				bp->smp_phase = BSMP_PH_SC_RANDOM;
			} else if (bsmp_inject(bp, BTPEER_SMP_STAGE_CONFIRM)) {
				return;			/* fault in place of Cb */
			} else {
				/* JW/NC: send Cb = f4(PKbx, PKax, Nb, 0). */
				arc4random_buf(bp->sc_nb, 16);
				if (smp_f4(bp->sc_pkb_le, bp->sc_pka_le,
				    bp->sc_nb, 0, bp->sc_cb) != 0) {
					bsmp_fail(bp, SMP_ERR_UNSPECIFIED_REASON);
					return;
				}
				out[0] = SMP_PAIRING_CONFIRM;
				memcpy(&out[1], bp->sc_cb, 16);
				if (bp->smp_cfg.force_confirm_mismatch)
					out[1] ^= 0xFF;
				btpeer_tx_l2cap(bp, L2CAP_CID_SMP, out, 17);
				bp->smp_phase = BSMP_PH_SC_RANDOM;
			}
		} else {			/* initiator got responder PK */
			memcpy(bp->sc_pkb_le, &pdu[1], 32);
			if (bsmp_sc_dhkey(bp, &pdu[1]) != 0) {
				bsmp_fail(bp, SMP_ERR_DHKEY_CHECK_FAILED);
				return;
			}
			if (bp->smp_cfg.method == BTPEER_SMP_PASSKEY) {
				/* Send Cai for round 0. */
				bp->sc_pk_round = 0;
				if (bsmp_inject(bp, BTPEER_SMP_STAGE_CONFIRM)) {
					bp->smp_phase = BSMP_PH_SC_PK_ROUND;
					return;		/* fault for Cai */
				}
				arc4random_buf(bp->sc_na, 16);
				if (smp_f4(bp->sc_pka_le, bp->sc_pkb_le,
				    bp->sc_na, bsmp_passkey_ri(bp),
				    bp->sc_cb) != 0) {
					bsmp_fail(bp, SMP_ERR_UNSPECIFIED_REASON);
					return;
				}
				out[0] = SMP_PAIRING_CONFIRM;
				memcpy(&out[1], bp->sc_cb, 16);
				btpeer_tx_l2cap(bp, L2CAP_CID_SMP, out, 17);
				bp->smp_phase = BSMP_PH_SC_PK_ROUND;
			} else if (bp->smp_cfg.method == BTPEER_SMP_OOB) {
				/* Send Na (our nonce). */
				if (bsmp_inject(bp, BTPEER_SMP_STAGE_RANDOM)) {
					bp->smp_phase = BSMP_PH_SC_RANDOM;
					return;		/* fault for Na */
				}
				arc4random_buf(bp->sc_na, 16);
				out[0] = SMP_PAIRING_RANDOM;
				memcpy(&out[1], bp->sc_na, 16);
				btpeer_tx_l2cap(bp, L2CAP_CID_SMP, out, 17);
				bp->smp_phase = BSMP_PH_SC_RANDOM;
			} else {
				/* JW/NC: wait for responder confirm Cb. */
				bp->smp_phase = BSMP_PH_SC_CONFIRM;
			}
		}
		break;

	case BSMP_PH_SC_CONFIRM:		/* initiator JW/NC: got Cb */
		if (pdu[0] != SMP_PAIRING_CONFIRM || len < 17)
			return;
		memcpy(bp->sc_cx, &pdu[1], 16);
		if (bsmp_inject(bp, BTPEER_SMP_STAGE_RANDOM))
			return;			/* fault in place of Na */
		arc4random_buf(bp->sc_na, 16);
		out[0] = SMP_PAIRING_RANDOM;
		memcpy(&out[1], bp->sc_na, 16);
		btpeer_tx_l2cap(bp, L2CAP_CID_SMP, out, 17);
		bp->smp_phase = BSMP_PH_SC_RANDOM;
		break;

	case BSMP_PH_SC_RANDOM:
		if (pdu[0] != SMP_PAIRING_RANDOM || len < 17)
			return;
		if (resp) {
			memcpy(bp->sc_na, &pdu[1], 16);		/* got Na */
			if (bp->smp_cfg.method == BTPEER_SMP_OOB) {
				/* Verify Ca = f4(PKax, PKax, ra, 0). */
				uint8_t ca[16];
				if (smp_f4(bp->sc_pka_le, bp->sc_pka_le,
				    bp->oob_peer_rand, 0, ca) != 0 ||
				    memcmp(ca, bp->oob_peer_confirm, 16) != 0) {
					bsmp_fail(bp, SMP_ERR_CONFIRM_VALUE_FAILED);
					return;
				}
			}
			if (bsmp_inject(bp, BTPEER_SMP_STAGE_RANDOM))
				return;			/* fault in place of Nb */
			out[0] = SMP_PAIRING_RANDOM;
			memcpy(&out[1], bp->sc_nb, 16);		/* send Nb */
			btpeer_tx_l2cap(bp, L2CAP_CID_SMP, out, 17);
			if (bp->smp_cfg.method == BTPEER_SMP_NUMERIC &&
			    bp->smp_cfg.force_numeric_reject) {
				bsmp_fail(bp, SMP_ERR_NUMERIC_COMP_FAILED);
				return;
			}
			bp->smp_phase = BSMP_PH_SC_DHCHECK;
			bsmp_sc_stage2(bp, false);	/* compute; wait Ea */
		} else {			/* initiator JW/NC/OOB: got Nb */
			memcpy(bp->sc_nb, &pdu[1], 16);
			if (bp->smp_cfg.method != BTPEER_SMP_OOB) {
				/* Verify Cb = f4(PKbx, PKax, Nb, 0). */
				uint8_t cb[16];
				if (smp_f4(bp->sc_pkb_le, bp->sc_pka_le,
				    bp->sc_nb, 0, cb) != 0 ||
				    memcmp(cb, bp->sc_cx, 16) != 0) {
					bsmp_fail(bp, SMP_ERR_CONFIRM_VALUE_FAILED);
					return;
				}
			}
			if (bp->smp_cfg.method == BTPEER_SMP_NUMERIC &&
			    bp->smp_cfg.force_numeric_reject) {
				bsmp_fail(bp, SMP_ERR_NUMERIC_COMP_FAILED);
				return;
			}
			bsmp_sc_stage2(bp, true);	/* send Ea */
		}
		break;

	case BSMP_PH_SC_PK_ROUND: {
		uint8_t ri = bsmp_passkey_ri(bp);

		if (resp) {
			if (pdu[0] == SMP_PAIRING_CONFIRM && len >= 17) {
				/* Got Cai; reply Cbi = f4(PKbx,PKax,Nbi,ri). */
				memcpy(bp->sc_cx, &pdu[1], 16);
				if (bsmp_inject(bp, BTPEER_SMP_STAGE_CONFIRM))
					return;		/* fault for Cbi */
				arc4random_buf(bp->sc_nb, 16);
				if (smp_f4(bp->sc_pkb_le, bp->sc_pka_le,
				    bp->sc_nb, ri, bp->sc_cb) != 0) {
					bsmp_fail(bp, SMP_ERR_UNSPECIFIED_REASON);
					return;
				}
				out[0] = SMP_PAIRING_CONFIRM;
				memcpy(&out[1], bp->sc_cb, 16);
				btpeer_tx_l2cap(bp, L2CAP_CID_SMP, out, 17);
			} else if (pdu[0] == SMP_PAIRING_RANDOM && len >= 17) {
				/* Got Nai; verify Cai = f4(PKax,PKbx,Nai,ri). */
				uint8_t v[16];
				memcpy(bp->sc_na, &pdu[1], 16);
				if (bsmp_inject(bp, BTPEER_SMP_STAGE_RANDOM))
					return;		/* fault for Nbi */
				if (smp_f4(bp->sc_pka_le, bp->sc_pkb_le,
				    bp->sc_na, ri, v) != 0 ||
				    memcmp(v, bp->sc_cx, 16) != 0) {
					bsmp_fail(bp, SMP_ERR_CONFIRM_VALUE_FAILED);
					return;
				}
				out[0] = SMP_PAIRING_RANDOM;
				memcpy(&out[1], bp->sc_nb, 16);
				btpeer_tx_l2cap(bp, L2CAP_CID_SMP, out, 17);
				if (++bp->sc_pk_round >= 20) {
					bp->smp_phase = BSMP_PH_SC_DHCHECK;
					bsmp_sc_stage2(bp, false);
				}
			}
		} else {		/* initiator */
			if (pdu[0] == SMP_PAIRING_CONFIRM && len >= 17) {
				/* Got Cbi; send Nai. */
				memcpy(bp->sc_cx, &pdu[1], 16);
				if (bsmp_inject(bp, BTPEER_SMP_STAGE_RANDOM))
					return;		/* fault for Nai */
				out[0] = SMP_PAIRING_RANDOM;
				memcpy(&out[1], bp->sc_na, 16);
				btpeer_tx_l2cap(bp, L2CAP_CID_SMP, out, 17);
			} else if (pdu[0] == SMP_PAIRING_RANDOM && len >= 17) {
				/* Got Nbi; verify Cbi = f4(PKbx,PKax,Nbi,ri). */
				uint8_t v[16];
				memcpy(bp->sc_nb, &pdu[1], 16);
				if (smp_f4(bp->sc_pkb_le, bp->sc_pka_le,
				    bp->sc_nb, ri, v) != 0 ||
				    memcmp(v, bp->sc_cx, 16) != 0) {
					bsmp_fail(bp, SMP_ERR_CONFIRM_VALUE_FAILED);
					return;
				}
				if (++bp->sc_pk_round >= 20) {
					bsmp_sc_stage2(bp, true);
				} else {
					/* Send next Cai. */
					arc4random_buf(bp->sc_na, 16);
					if (smp_f4(bp->sc_pka_le, bp->sc_pkb_le,
					    bp->sc_na, bsmp_passkey_ri(bp),
					    bp->sc_cb) != 0) {
						bsmp_fail(bp,
						    SMP_ERR_UNSPECIFIED_REASON);
						return;
					}
					out[0] = SMP_PAIRING_CONFIRM;
					memcpy(&out[1], bp->sc_cb, 16);
					btpeer_tx_l2cap(bp, L2CAP_CID_SMP,
					    out, 17);
				}
			}
		}
		break;
	}

	case BSMP_PH_SC_DHCHECK:
		if (pdu[0] != SMP_PAIRING_DHKEY_CHECK || len < 17)
			return;
		if (resp) {
			/* Verify Ea, then send Eb. */
			if (memcmp(&pdu[1], bp->sc_ea, 16) != 0) {
				bsmp_fail(bp, SMP_ERR_DHKEY_CHECK_FAILED);
				return;
			}
			if (bsmp_inject(bp, BTPEER_SMP_STAGE_DHCHECK))
				return;			/* fault in place of Eb */
			out[0] = SMP_PAIRING_DHKEY_CHECK;
			memcpy(&out[1], bp->sc_eb, 16);
			if (bp->smp_cfg.force_dhkey_mismatch)
				out[1] ^= 0xFF;
			btpeer_tx_l2cap(bp, L2CAP_CID_SMP, out, 17);
			bsmp_enter_keydist(bp);
		} else {
			/* Verify Eb (initiator). */
			if (memcmp(&pdu[1], bp->sc_eb, 16) != 0) {
				bsmp_fail(bp, SMP_ERR_DHKEY_CHECK_FAILED);
				return;
			}
			bsmp_enter_keydist(bp);
		}
		break;

	default:
		break;
	}
}

/* Build our Pairing Request/Response feature exchange PDU. */
static void
bsmp_build_feature(struct btpeer *bp, uint8_t *p, bool is_req)
{

	p[0] = is_req ? SMP_PAIRING_REQUEST : SMP_PAIRING_RESPONSE;
	p[1] = bp->smp_cfg.io_cap;
	p[2] = (bp->smp_cfg.method == BTPEER_SMP_OOB) ? 0x01 : 0x00;
	p[3] = bsmp_authreq(bp);
	p[4] = bp->smp_cfg.max_key_size ? bp->smp_cfg.max_key_size : 16;
	if (is_req) {
		p[5] = bp->smp_cfg.local_key_dist;	/* initiator distributes */
		p[6] = bp->smp_cfg.remote_key_dist;	/* responder distributes */
	} else {
		p[5] = bp->smp_cfg.remote_key_dist;	/* initiator distributes */
		p[6] = bp->smp_cfg.local_key_dist;	/* responder distributes */
	}
}

static void
btpeer_smp_rx(struct btpeer *bp, const uint8_t *pdu, uint16_t len)
{

	if (len < 1)
		return;
	if (pdu[0] == SMP_PAIRING_FAILED) {
		if (len >= 2)
			bp->smp_fail = pdu[1];
		bp->smp_phase = BSMP_PH_FAILED;
		return;
	}

	/* RESPONDER: the first inbound PDU is the initiator's Pairing Request. */
	if (bp->smp_cfg.role == BTPEER_SMP_RESPONDER &&
	    pdu[0] == SMP_PAIRING_REQUEST) {
		memset(bp->preq, 0, 7);
		memcpy(bp->preq, pdu, (len < 7) ? len : 7);
		bsmp_build_feature(bp, bp->pres, false);
		if (bp->smp_cfg.force_fail_reason != 0) {
			bsmp_fail(bp, bp->smp_cfg.force_fail_reason);
			return;
		}
		btpeer_tx_l2cap(bp, L2CAP_CID_SMP, bp->pres, 7);
		bp->smp_phase = bp->smp_cfg.sc ? BSMP_PH_SC_PK :
		    BSMP_PH_LEG_CONFIRM;
		return;
	}

	/* INITIATOR: consume the responder's Pairing Response. */
	if (bp->smp_cfg.role == BTPEER_SMP_INITIATOR &&
	    pdu[0] == SMP_PAIRING_RESPONSE && bp->smp_phase == BSMP_PH_FEATURE) {
		uint8_t tk[16], out[17], iat, rat;

		memset(bp->pres, 0, 7);
		memcpy(bp->pres, pdu, (len < 7) ? len : 7);
		if (bp->smp_cfg.sc) {
			/* Our Public Key is the first SC PDU OUR responder
			 * receives (Vol 3 Part H 2.3.5.6.1). */
			if (bsmp_inject(bp, BTPEER_SMP_STAGE_PUBKEY)) {
				bp->smp_phase = BSMP_PH_SC_PK;
				return;
			}
			if (bsmp_sc_keygen(bp) != 0) {
				bsmp_fail(bp, SMP_ERR_UNSPECIFIED_REASON);
				return;
			}
			memcpy(bp->sc_pka_le, bp->sc_pk_le, 32);
			bsmp_sc_send_pk(bp);
			bp->smp_phase = BSMP_PH_SC_PK;
		} else {
			/* Legacy: send our Pairing Confirm first. */
			bsmp_legacy_tk(bp, tk);
			iat = bsmp_wtype(bp->init_addr_type);
			rat = bsmp_wtype(bp->peer_addr_type);
			if (bsmp_inject(bp, BTPEER_SMP_STAGE_CONFIRM)) {
				bp->smp_phase = BSMP_PH_LEG_CONFIRM;
				return;
			}
			out[0] = SMP_PAIRING_CONFIRM;
			if (smp_c1(tk, bp->srand, bp->preq, bp->pres, iat,
			    bp->init_addr, rat, bp->peer_addr, &out[1]) < 0) {
				bsmp_fail(bp, SMP_ERR_UNSPECIFIED_REASON);
				return;
			}
			if (bp->smp_cfg.force_confirm_mismatch)
				out[1] ^= 0xFF;
			btpeer_tx_l2cap(bp, L2CAP_CID_SMP, out, 17);
			bp->smp_phase = BSMP_PH_LEG_CONFIRM;
		}
		return;
	}

	/* Dispatch by phase. */
	switch (bp->smp_phase) {
	case BSMP_PH_KEYDIST:
		bsmp_keydist_rx(bp, pdu, len);
		break;
	case BSMP_PH_LEG_CONFIRM:
	case BSMP_PH_LEG_RANDOM:
		bsmp_legacy_rx(bp, pdu, len);
		break;
	case BSMP_PH_SC_PK:
	case BSMP_PH_SC_CONFIRM:
	case BSMP_PH_SC_RANDOM:
	case BSMP_PH_SC_PK_ROUND:
	case BSMP_PH_SC_DHCHECK:
		bsmp_sc_rx(bp, pdu, len);
		break;
	default:
		break;
	}
}

/* ----------------------------------------------------------------
 * emu output callback: data arriving from the DUT side
 * ---------------------------------------------------------------- */
static void
btpeer_emu_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct btpeer *bp = ctx;
	const uint8_t *acl, *payload;
	uint16_t acl_len, l2_len, cid;

	if (len < 1 || pkt[0] != NG_HCI_ACL_DATA_PKT)
		return;			/* HCI event, not L2CAP data */
	if (len < 9)
		return;
	acl = &pkt[1];
	acl_len = gt16(&acl[2]);
	if ((size_t)acl_len + 5 > len || acl_len < 4)
		return;
	l2_len = gt16(&pkt[5]);
	cid = gt16(&pkt[7]);
	payload = &pkt[9];
	if ((size_t)l2_len + 9 > len)
		return;

	if (cid == L2CAP_CID_ATT) {
		if (l2_len < 1)
			return;
		if (is_server_request(payload[0]))
			btpeer_srv_handle(bp, payload, l2_len);
		else
			btpeer_client_rx(bp, payload, l2_len);
	} else if (cid == L2CAP_CID_SMP) {
		btpeer_smp_rx(bp, payload, l2_len);
	}
}

/* ----------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------- */
struct btpeer *
btpeer_new(struct hci_emu *emu)
{
	struct btpeer *bp;
	static const uint8_t default_srand[16] = {
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
	};

	bp = calloc(1, sizeof(*bp));
	if (bp == NULL)
		return (NULL);
	bp->emu = emu;
	bp->mtu = 23;			/* ATT default MTU (Vol 3 Part F 3.2.8) */
	bp->next_handle = 0x0001;
	memcpy(bp->srand, default_srand, 16);
	/*
	 * Default SMP configuration reproduces the original minimal responder:
	 * LE Legacy Just Works, IO=NoInputNoOutput, Bonding only, no key
	 * distribution.  Tests that call btpeer_smp_configure() override it.
	 */
	bp->smp_cfg.role = BTPEER_SMP_RESPONDER;
	bp->smp_cfg.method = BTPEER_SMP_JUST_WORKS;
	bp->smp_cfg.io_cap = 0x03;		/* NoInputNoOutput */
	bp->smp_cfg.bonding = true;
	bp->smp_cfg.max_key_size = 16;
	bp->smp_configured = true;
	hci_emu_set_output(emu, btpeer_emu_out, bp);
	return (bp);
}

void
btpeer_free(struct btpeer *bp)
{

	if (bp == NULL)
		return;
	if (bp->sc_key != NULL)
		EVP_PKEY_free(bp->sc_key);
	free(bp);
}

int
btpeer_bind_conn(struct btpeer *bp)
{
	uint16_t h;

	if (bp->have_handle)
		return (0);
	if (hci_emu_get_conn_count(bp->emu) < 1)
		return (-1);
	if (!hci_emu_get_conn_handle(bp->emu, 0, &h))
		return (-1);
	bp->handle = h;
	bp->have_handle = true;
	return (0);
}

/*
 * Reset the peer's per-connection ATT bearer state (Vol 3 Part F 3.2.8 /
 * 3.4.2): a reconnection is a NEW L2CAP bearer, so the cached connection
 * handle is dropped (so btpeer_bind_conn re-learns the freshly-allocated
 * handle), the MTU returns to the ATT default (23), and any in-flight
 * transaction / prepared-write echo state is cleared.  Client-side only; it
 * does not touch the peer's own attribute database or SMP state.
 */
void
btpeer_reset_bearer(struct btpeer *bp)
{

	bp->have_handle = false;
	bp->mtu = 23;
	bp->rsp_ready = false;
	bp->have_err = false;
	bp->prep_echo_valid = false;
}

void
btpeer_set_mtu(struct btpeer *bp, uint16_t mtu)
{

	bp->mtu = mtu;
}

void
btpeer_on_notify(struct btpeer *bp, btpeer_notify_cb cb, void *arg)
{

	bp->notify_cb = cb;
	bp->notify_arg = arg;
}

int
btpeer_last_att_error(const struct btpeer *bp, uint8_t *req_op,
    uint16_t *handle, uint8_t *code)
{

	if (!bp->have_err)
		return (0);
	if (req_op != NULL)
		*req_op = bp->err_req_op;
	if (handle != NULL)
		*handle = bp->err_handle;
	if (code != NULL)
		*code = bp->err_code;
	return (1);
}

/* ----------------------------------------------------------------
 * Peer client: synchronous ATT transactions
 * ---------------------------------------------------------------- */
static int
btpeer_att_txn(struct btpeer *bp, const uint8_t *req, uint16_t reqlen,
    uint8_t expect_op)
{

	bp->rsp_ready = false;
	bp->have_err = false;
	btpeer_tx_l2cap(bp, L2CAP_CID_ATT, req, reqlen);
	/* The emu link delivers the response inline. */
	if (!bp->rsp_ready || bp->rsp_len < 1)
		return (-1);
	if (bp->rsp[0] == ATT_ERROR_RSP)
		return (1);		/* error response captured */
	if (bp->rsp[0] != expect_op)
		return (-1);
	return (0);
}

int
btpeer_gatt_exchange_mtu(struct btpeer *bp, uint16_t client_mtu,
    uint16_t *server_mtu)
{
	uint8_t req[3];
	int rc;

	/* Exchange MTU Request (Vol 3 Part F 3.4.2.1). */
	req[0] = ATT_MTU_REQ;
	pk16(&req[1], client_mtu);
	rc = btpeer_att_txn(bp, req, 3, ATT_MTU_RSP);
	if (rc != 0)
		return (rc);
	if (bp->rsp_len < 3)
		return (-1);
	if (server_mtu != NULL)
		*server_mtu = gt16(&bp->rsp[1]);
	/* Effective MTU = min(client, server) (Vol 3 Part F 3.4.2.2). */
	{
		uint16_t s = gt16(&bp->rsp[1]);
		bp->mtu = (client_mtu < s) ? client_mtu : s;
		if (bp->mtu < 23)
			bp->mtu = 23;
	}
	return (0);
}

int
btpeer_gatt_discover_services(struct btpeer *bp, struct btpeer_service *out,
    int max, int *count)
{
	uint16_t start = 0x0001;
	int n = 0;

	/* Read By Group Type over 0x2800 (Vol 3 Part G 4.4.1). */
	for (;;) {
		uint8_t req[7];
		uint16_t rl;
		int rc, i;
		uint8_t rec;

		req[0] = ATT_READ_BY_GROUP_REQ;
		pk16(&req[1], start);
		pk16(&req[3], 0xFFFF);
		pk16(&req[5], GATT_PRIMARY_SERVICE);
		rc = btpeer_att_txn(bp, req, 7, ATT_READ_BY_GROUP_RSP);
		if (rc == 1)		/* Attr Not Found => done */
			break;
		if (rc != 0)
			return (-1);
		rl = bp->rsp_len;
		rec = bp->rsp[1];	/* record length */
		if (rec < 6 || rl < 2u + rec)
			return (-1);
		for (i = 2; i + rec <= (int)rl; i += rec) {
			uint16_t s = gt16(&bp->rsp[i]);
			uint16_t e = gt16(&bp->rsp[i + 2]);

			if (n < max) {
				out[n].start = s;
				out[n].end = e;
				out[n].uuid16 = (rec >= 6) ?
				    gt16(&bp->rsp[i + 4]) : 0;
				n++;
			}
			if (e == 0xFFFF) {
				start = 0xFFFF;
				goto done;
			}
			start = (uint16_t)(e + 1);
		}
	}
done:
	if (count != NULL)
		*count = n;
	return (0);
}

int
btpeer_gatt_discover_chars(struct btpeer *bp, uint16_t start, uint16_t end,
    struct btpeer_char *out, int max, int *count)
{
	int n = 0;
	uint16_t cur = start;

	/* Read By Type over 0x2803 (Vol 3 Part G 4.6.1). */
	for (;;) {
		uint8_t req[7];
		uint16_t rl;
		int rc, i;
		uint8_t rec;

		if (cur > end)
			break;
		req[0] = ATT_READ_BY_TYPE_REQ;
		pk16(&req[1], cur);
		pk16(&req[3], end);
		pk16(&req[5], GATT_CHARACTERISTIC);
		rc = btpeer_att_txn(bp, req, 7, ATT_READ_BY_TYPE_RSP);
		if (rc == 1)
			break;
		if (rc != 0)
			return (-1);
		rl = bp->rsp_len;
		rec = bp->rsp[1];
		if (rec < 7 || rl < 2u + rec)
			return (-1);
		for (i = 2; i + rec <= (int)rl; i += rec) {
			uint16_t decl = gt16(&bp->rsp[i]);

			if (n < max) {
				out[n].decl = decl;
				out[n].props = bp->rsp[i + 2];
				out[n].value = gt16(&bp->rsp[i + 3]);
				out[n].uuid16 = gt16(&bp->rsp[i + 5]);
				n++;
			}
			if (decl >= end)
				goto done;
			cur = (uint16_t)(decl + 1);
		}
	}
done:
	if (count != NULL)
		*count = n;
	return (0);
}

int
btpeer_gatt_discover_descs(struct btpeer *bp, uint16_t start, uint16_t end,
    struct btpeer_desc *out, int max, int *count)
{
	int n = 0;
	uint16_t cur = start;

	/* Find Information (Vol 3 Part G 4.7.1). */
	for (;;) {
		uint8_t req[5];
		uint16_t rl;
		int rc, i;

		if (cur > end)
			break;
		req[0] = ATT_FIND_INFO_REQ;
		pk16(&req[1], cur);
		pk16(&req[3], end);
		rc = btpeer_att_txn(bp, req, 5, ATT_FIND_INFO_RSP);
		if (rc == 1)
			break;
		if (rc != 0)
			return (-1);
		rl = bp->rsp_len;
		if (rl < 2 || bp->rsp[1] != 0x01)	/* 16-bit format */
			return (-1);
		for (i = 2; i + 4 <= (int)rl; i += 4) {
			uint16_t h = gt16(&bp->rsp[i]);

			if (n < max) {
				out[n].handle = h;
				out[n].uuid16 = gt16(&bp->rsp[i + 2]);
				n++;
			}
			if (h >= end)
				goto done;
			cur = (uint16_t)(h + 1);
		}
	}
done:
	if (count != NULL)
		*count = n;
	return (0);
}

int
btpeer_gatt_read(struct btpeer *bp, uint16_t handle, uint8_t *buf,
    size_t buflen, size_t *outlen)
{
	uint8_t req[3];
	int rc;
	size_t dl;

	/* Read Request (Vol 3 Part F 3.4.4.3). */
	req[0] = ATT_READ_REQ;
	pk16(&req[1], handle);
	rc = btpeer_att_txn(bp, req, 3, ATT_READ_RSP);
	if (rc != 0)
		return (rc);
	dl = (size_t)bp->rsp_len - 1;
	if (dl > buflen)
		dl = buflen;
	memcpy(buf, &bp->rsp[1], dl);
	if (outlen != NULL)
		*outlen = dl;
	return (0);
}

int
btpeer_gatt_read_blob(struct btpeer *bp, uint16_t handle, uint16_t offset,
    uint8_t *buf, size_t buflen, size_t *outlen)
{
	uint8_t req[5];
	int rc;
	size_t dl;

	/* Read Blob Request (Vol 3 Part F 3.4.4.5). */
	req[0] = ATT_READ_BLOB_REQ;
	pk16(&req[1], handle);
	pk16(&req[3], offset);
	rc = btpeer_att_txn(bp, req, 5, ATT_READ_BLOB_RSP);
	if (rc != 0)
		return (rc);
	dl = (size_t)bp->rsp_len - 1;
	if (dl > buflen)
		dl = buflen;
	memcpy(buf, &bp->rsp[1], dl);
	if (outlen != NULL)
		*outlen = dl;
	return (0);
}

int
btpeer_gatt_write(struct btpeer *bp, uint16_t handle, const void *data,
    uint16_t len)
{
	uint8_t req[512];
	int rc;

	/* Write Request (Vol 3 Part F 3.4.5.1). */
	if ((size_t)len + 3 > sizeof(req) || (size_t)len + 3 > bp->mtu)
		return (-1);
	req[0] = ATT_WRITE_REQ;
	pk16(&req[1], handle);
	memcpy(&req[3], data, len);
	rc = btpeer_att_txn(bp, req, (uint16_t)(3 + len), ATT_WRITE_RSP);
	return (rc);
}

int
btpeer_gatt_write_cmd(struct btpeer *bp, uint16_t handle, const void *data,
    uint16_t len)
{
	uint8_t req[512];

	/* Write Command (Vol 3 Part F 3.4.5.3): no response. */
	if ((size_t)len + 3 > sizeof(req) || (size_t)len + 3 > bp->mtu)
		return (-1);
	req[0] = ATT_WRITE_CMD;
	pk16(&req[1], handle);
	memcpy(&req[3], data, len);
	btpeer_tx_l2cap(bp, L2CAP_CID_ATT, req, (uint16_t)(3 + len));
	return (0);
}

int
btpeer_gatt_subscribe(struct btpeer *bp, uint16_t cccd_handle,
    uint16_t cccd_value)
{
	uint8_t v[2];

	/* CCCD write (Vol 3 Part G 3.3.3.3). */
	pk16(v, cccd_value);
	return (btpeer_gatt_write(bp, cccd_handle, v, 2));
}

int
btpeer_gatt_find_by_type_value(struct btpeer *bp, uint16_t start, uint16_t end,
    uint16_t type_uuid, const void *value, uint16_t vlen,
    struct btpeer_service *out, int max, int *count)
{
	int n = 0;
	uint16_t cur = start;

	/* Find By Type Value (Vol 3 Part F 3.4.3.3), paged over the range. */
	for (;;) {
		uint8_t req[64];
		uint16_t rl;
		int rc, i;

		if (cur > end)
			break;
		if ((size_t)vlen + 7 > sizeof(req))
			return (-1);
		req[0] = ATT_FIND_BY_TYPE_REQ;
		pk16(&req[1], cur);
		pk16(&req[3], end);
		pk16(&req[5], type_uuid);
		if (vlen != 0)
			memcpy(&req[7], value, vlen);
		rc = btpeer_att_txn(bp, req, (uint16_t)(7 + vlen),
		    ATT_FIND_BY_TYPE_RSP);
		if (rc == 1)			/* Attr Not Found => done */
			break;
		if (rc != 0)
			return (-1);
		rl = bp->rsp_len;
		/* Response (3.4.3.4): opcode | { Found | Group End }*. */
		for (i = 1; i + 4 <= (int)rl; i += 4) {
			uint16_t s = gt16(&bp->rsp[i]);
			uint16_t e = gt16(&bp->rsp[i + 2]);

			if (n < max) {
				out[n].start = s;
				out[n].end = e;
				out[n].uuid16 = type_uuid;
				n++;
			}
			if (e == 0xFFFF)
				goto done;
			cur = (uint16_t)(e + 1);
		}
	}
done:
	if (count != NULL)
		*count = n;
	return (0);
}

int
btpeer_gatt_read_by_type(struct btpeer *bp, uint16_t start, uint16_t end,
    uint16_t type_uuid, struct btpeer_rbt_rec *out, int max, int *count)
{
	int n = 0;
	uint16_t cur = start;

	/* Read By Type (Vol 3 Part F 3.4.4.1), paged over the range. */
	for (;;) {
		uint8_t req[7];
		uint16_t rl;
		int rc, i;
		uint8_t rec;

		if (cur > end)
			break;
		req[0] = ATT_READ_BY_TYPE_REQ;
		pk16(&req[1], cur);
		pk16(&req[3], end);
		pk16(&req[5], type_uuid);
		rc = btpeer_att_txn(bp, req, 7, ATT_READ_BY_TYPE_RSP);
		if (rc == 1)
			break;
		if (rc != 0)
			return (-1);
		rl = bp->rsp_len;
		rec = bp->rsp[1];		/* Length: handle(2)+value */
		if (rec < 3 || rl < 2u + rec)
			return (-1);
		for (i = 2; i + rec <= (int)rl; i += rec) {
			uint16_t h = gt16(&bp->rsp[i]);
			uint16_t vl = (uint16_t)(rec - 2);

			if (n < max) {
				out[n].handle = h;
				if (vl > sizeof(out[n].val))
					vl = sizeof(out[n].val);
				memcpy(out[n].val, &bp->rsp[i + 2], vl);
				out[n].vlen = vl;
				n++;
			}
			if (h >= end)
				goto done;
			cur = (uint16_t)(h + 1);
		}
	}
done:
	if (count != NULL)
		*count = n;
	return (0);
}

int
btpeer_gatt_read_multiple(struct btpeer *bp, const uint16_t *handles,
    int nhandles, uint8_t *buf, size_t buflen, size_t *outlen)
{
	uint8_t req[64];
	int rc, i;
	size_t dl;

	/* Read Multiple Request (Vol 3 Part F 3.4.4.7). */
	if (nhandles < 2 || (size_t)(1 + 2 * nhandles) > sizeof(req))
		return (-1);
	req[0] = ATT_READ_MULTIPLE_REQ;
	for (i = 0; i < nhandles; i++)
		pk16(&req[1 + 2 * i], handles[i]);
	rc = btpeer_att_txn(bp, req, (uint16_t)(1 + 2 * nhandles),
	    ATT_READ_MULTIPLE_RSP);
	if (rc != 0)
		return (rc);
	dl = (size_t)bp->rsp_len - 1;
	if (dl > buflen)
		dl = buflen;
	memcpy(buf, &bp->rsp[1], dl);
	if (outlen != NULL)
		*outlen = dl;
	return (0);
}

int
btpeer_gatt_read_multiple_variable(struct btpeer *bp, const uint16_t *handles,
    int nhandles, uint8_t *buf, size_t buflen, size_t *outlen)
{
	uint8_t req[64];
	int rc, i;
	size_t dl;

	/* Read Multiple Variable Request (Vol 3 Part F 3.4.4.9): >= 2 handles. */
	if (nhandles < 2 || (size_t)(1 + 2 * nhandles) > sizeof(req))
		return (-1);
	req[0] = ATT_READ_MULT_VAR_REQ;
	for (i = 0; i < nhandles; i++)
		pk16(&req[1 + 2 * i], handles[i]);
	rc = btpeer_att_txn(bp, req, (uint16_t)(1 + 2 * nhandles),
	    ATT_READ_MULT_VAR_RSP);
	if (rc != 0)
		return (rc);
	/* Copy the Length-Value tuple list verbatim (payload after opcode). */
	dl = (size_t)bp->rsp_len - 1;
	if (dl > buflen)
		dl = buflen;
	memcpy(buf, &bp->rsp[1], dl);
	if (outlen != NULL)
		*outlen = dl;
	return (0);
}

int
btpeer_gatt_signed_write(struct btpeer *bp, uint16_t handle, const void *data,
    uint16_t len, const uint8_t csrk[16], uint32_t counter)
{
	uint8_t pdu[512];
	uint8_t msg_swp[512];
	uint8_t csrk_be[16], full_mac[16];
	uint16_t mlen;		/* signed message length: opcode|handle|value */
	size_t n;
	int i;

	/* opcode(1) | handle(2) | value | SignCounter(4) | MAC(8) */
	if ((size_t)len + 1 + 2 + 4 + 8 > sizeof(pdu))
		return (-1);
	pdu[0] = ATT_SIGNED_WRITE_CMD;
	pk16(&pdu[1], handle);
	if (len != 0)
		memcpy(&pdu[3], data, len);
	mlen = (uint16_t)(3 + len);
	/* Append the sign counter (Vol 3 Part H 2.4.5), little-endian. */
	pdu[mlen + 0] = (uint8_t)(counter & 0xFF);
	pdu[mlen + 1] = (uint8_t)((counter >> 8) & 0xFF);
	pdu[mlen + 2] = (uint8_t)((counter >> 16) & 0xFF);
	pdu[mlen + 3] = (uint8_t)((counter >> 24) & 0xFF);

	/*
	 * MAC byte order (S-M3): the interoperable stacks (Linux
	 * net/bluetooth/smp.c, BlueZ bt_crypto_sign_att) byte-reverse BOTH the
	 * CSRK and the whole (opcode||handle||value||SignCounter_le32) message
	 * into the MSB order RFC 4493 AES-CMAC uses, then byte-reverse the MAC
	 * back; the 8-octet wire signature is the low 8 octets of that LSB-first
	 * MAC.  Generate it exactly as smp_verify_signature now checks it.
	 */
	n = (size_t)mlen + 4;
	for (i = 0; i < 16; i++)
		csrk_be[i] = csrk[15 - i];
	for (i = 0; (size_t)i < n; i++)
		msg_swp[i] = pdu[n - 1 - (size_t)i];
	if (smp_aes_cmac(csrk_be, msg_swp, n, full_mac) != 0)
		return (-1);
	for (i = 0; i < 8; i++)
		pdu[mlen + 4 + i] = full_mac[15 - i];

	btpeer_tx_l2cap(bp, L2CAP_CID_ATT, pdu, (uint16_t)(mlen + 4 + 8));
	return (0);
}

int
btpeer_gatt_prepare_write(struct btpeer *bp, uint16_t handle, uint16_t offset,
    const void *data, uint16_t len)
{
	uint8_t req[512];

	/* Prepare Write Request (Vol 3 Part F 3.4.6.1). */
	if ((size_t)len + 5 > sizeof(req) || (size_t)len + 5 > bp->mtu)
		return (-1);
	bp->prep_echo_valid = false;
	req[0] = ATT_PREPARE_WRITE_REQ;
	pk16(&req[1], handle);
	pk16(&req[3], offset);
	if (len != 0)
		memcpy(&req[5], data, len);
	return (btpeer_att_txn(bp, req, (uint16_t)(5 + len),
	    ATT_PREPARE_WRITE_RSP));
}

int
btpeer_gatt_execute_write(struct btpeer *bp, uint8_t flags)
{
	uint8_t req[2];

	/* Execute Write Request (Vol 3 Part F 3.4.6.3). */
	req[0] = ATT_EXECUTE_WRITE_REQ;
	req[1] = flags;
	return (btpeer_att_txn(bp, req, 2, ATT_EXECUTE_WRITE_RSP));
}

int
btpeer_gatt_write_long(struct btpeer *bp, uint16_t handle, const void *data,
    uint16_t len)
{
	const uint8_t *p = data;
	uint16_t off = 0, chunk;
	int rc;

	/* Reliable long write (Vol 3 Part G 4.9.4): Prepare each part with an
	 * echo check, then Execute.  Part size = ATT_MTU - 5 (3.4.6.1). */
	chunk = (uint16_t)(bp->mtu - 5);
	if (chunk == 0)
		return (-1);
	while (off < len) {
		uint16_t this = (uint16_t)(len - off);

		if (this > chunk)
			this = chunk;
		rc = btpeer_gatt_prepare_write(bp, handle, off, p + off, this);
		if (rc != 0)
			return (rc);
		/* Verify the server echoed our part exactly (reliable write). */
		if (!bp->prep_echo_valid ||
		    bp->prep_echo_handle != handle ||
		    bp->prep_echo_offset != off ||
		    bp->prep_echo_len != this ||
		    memcmp(bp->prep_echo_val, p + off, this) != 0)
			return (-1);
		off = (uint16_t)(off + this);
	}
	return (btpeer_gatt_execute_write(bp, 0x01));
}

int
btpeer_last_prepare_echo(const struct btpeer *bp, uint16_t *handle,
    uint16_t *offset, uint8_t *buf, size_t buflen, size_t *outlen)
{
	size_t dl;

	if (!bp->prep_echo_valid)
		return (0);
	if (handle != NULL)
		*handle = bp->prep_echo_handle;
	if (offset != NULL)
		*offset = bp->prep_echo_offset;
	dl = bp->prep_echo_len;
	if (dl > buflen)
		dl = buflen;
	if (buf != NULL)
		memcpy(buf, bp->prep_echo_val, dl);
	if (outlen != NULL)
		*outlen = dl;
	return (1);
}

/* ----------------------------------------------------------------
 * SMP configuration / results
 * ---------------------------------------------------------------- */
void
btpeer_smp_set_addrs(struct btpeer *bp, const uint8_t peer_addr[6],
    uint8_t peer_addr_type, const uint8_t init_addr[6],
    uint8_t init_addr_type)
{

	memcpy(bp->peer_addr, peer_addr, 6);
	bp->peer_addr_type = peer_addr_type;
	memcpy(bp->init_addr, init_addr, 6);
	bp->init_addr_type = init_addr_type;
}

void
btpeer_smp_set_srand(struct btpeer *bp, const uint8_t srand[16])
{

	memcpy(bp->srand, srand, 16);
}

bool
btpeer_smp_done(const struct btpeer *bp)
{

	return (bp->smp_have_stk);
}

int
btpeer_smp_get_stk(const struct btpeer *bp, uint8_t stk[16])
{

	if (!bp->smp_have_stk)
		return (-1);
	memcpy(stk, bp->stk, 16);
	return (0);
}

/* ----------------------------------------------------------------
 * Full SMP pairing-method matrix: configuration + results
 * ---------------------------------------------------------------- */
void
btpeer_smp_configure(struct btpeer *bp, const struct btpeer_smp_cfg *cfg)
{

	bp->smp_cfg = *cfg;
	if (bp->smp_cfg.max_key_size == 0)
		bp->smp_cfg.max_key_size = 16;
	bp->smp_configured = true;
	bp->smp_phase = BSMP_PH_IDLE;
	bp->smp_bonded = false;
	bp->smp_is_sc = false;
	bp->smp_is_mitm = false;
	bp->smp_fail = 0;
	bp->smp_have_stk = false;
	bp->got_irk = bp->got_identity = bp->got_csrk = false;
	bp->sc_pk_round = 0;
	bp->keydist_recv = 0;
	bp->inject_fired = false;
}

void
btpeer_smp_set_oob_legacy_tk(struct btpeer *bp, const uint8_t tk[16])
{

	memcpy(bp->oob_tk, tk, 16);
	bp->have_oob_tk = true;
}

void
btpeer_smp_set_oob_sc(struct btpeer *bp, const uint8_t local_random[16],
    const uint8_t peer_confirm[16], const uint8_t peer_random[16])
{

	memcpy(bp->oob_local_rand, local_random, 16);
	memcpy(bp->oob_peer_confirm, peer_confirm, 16);
	memcpy(bp->oob_peer_rand, peer_random, 16);
	bp->have_oob_sc = true;
}

int
btpeer_smp_get_oob_pubkey_x(struct btpeer *bp, uint8_t pkx_le[32])
{

	/* Ensure our SC key pair exists so the test can precompute our Cb. */
	if (bp->sc_key == NULL && bsmp_sc_keygen(bp) != 0)
		return (-1);
	memcpy(pkx_le, bp->sc_pk_le, 32);
	return (0);
}

int
btpeer_smp_start(struct btpeer *bp)
{
	uint8_t req[7];

	if (bp->smp_cfg.role != BTPEER_SMP_INITIATOR)
		return (-1);
	bsmp_build_feature(bp, bp->preq, true);
	memcpy(req, bp->preq, 7);
	bp->smp_phase = BSMP_PH_FEATURE;
	btpeer_tx_l2cap(bp, L2CAP_CID_SMP, req, 7);
	return (0);
}

bool
btpeer_smp_bonded(const struct btpeer *bp)
{

	return (bp->smp_bonded);
}

bool
btpeer_smp_is_sc(const struct btpeer *bp)
{

	return (bp->smp_is_sc);
}

bool
btpeer_smp_is_mitm(const struct btpeer *bp)
{

	return (bp->smp_is_mitm);
}

int
btpeer_smp_get_ltk(const struct btpeer *bp, uint8_t ltk[16])
{

	if (!bp->smp_bonded)
		return (-1);
	memcpy(ltk, bp->smp_ltk, 16);
	return (0);
}

uint8_t
btpeer_smp_fail_reason(const struct btpeer *bp)
{

	return (bp->smp_fail);
}

bool
btpeer_smp_got_peer_irk(const struct btpeer *bp, uint8_t irk[16])
{

	if (bp->got_irk && irk != NULL)
		memcpy(irk, bp->peer_irk, 16);
	return (bp->got_irk);
}

bool
btpeer_smp_got_peer_identity(const struct btpeer *bp, uint8_t *addr_type,
    uint8_t addr[6])
{

	if (bp->got_identity) {
		if (addr_type != NULL)
			*addr_type = bp->peer_id_type;
		if (addr != NULL)
			memcpy(addr, bp->peer_id_addr, 6);
	}
	return (bp->got_identity);
}

bool
btpeer_smp_got_peer_csrk(const struct btpeer *bp, uint8_t csrk[16])
{

	if (bp->got_csrk && csrk != NULL)
		memcpy(csrk, bp->peer_csrk, 16);
	return (bp->got_csrk);
}
