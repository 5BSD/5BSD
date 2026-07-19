/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * blued control-socket protocol, shared by blued, libble, and meshd.
 *
 * Every message has an 8-byte little-endian header followed by ih_len bytes:
 *
 *   offset  size  field
 *   0       4     payload length, excluding the header
 *   4       2     IPC_T_* frame type
 *   6       2     protocol version, error code, or operation domain
 *
 * Operation requests, replies, and events use IPC_T_OP_* and an 8-byte
 * prefix.  Requests carry a nonzero request ID and zero status/flags.  Replies
 * repeat the request ID and domain and carry an IPC_ERR_* status.  Unsolicited
 * events use request ID zero; events produced by a pending operation repeat
 * its request ID.  Domain payloads are binary and length-delimited.
 *
 * IPC_T_HELLO must be the first frame.  ih_arg is IPC_PROTO_VERSION and the
 * payload is a little-endian IPC_FEATURE_* bitmask.  The reply carries the
 * accepted feature mask.  A version mismatch receives IPC_T_ERROR and the
 * session is not activated.  The current protocol exposes only typed binary
 * operations, replies, and events.
 *
 * Event delivery requires IPC_FEATURE_EVENTS.  Mesh additionally requires
 * IPC_FEATURE_MESH and uid 0; the daemon validates mesh AD types and treats
 * payload bytes as opaque.  IPC_FEATURE_FDPASS enables SCM_RIGHTS handoff for
 * L2CAP, GATT acquire, and ISO data paths.
 */

#ifndef _BLUED_IPC_PROTO_H_
#define _BLUED_IPC_PROTO_H_

#include <stddef.h>
#include <stdint.h>

/* Current protocol version.  Bump on an incompatible wire change. */
#define	IPC_PROTO_VERSION	6u

/* Fixed header size and maximum payload carried in a single frame. */
#define	IPC_HDR_SIZE		8u
#define	IPC_MAX_PAYLOAD		4096u

/* Frame types (ih_type). */
#define	IPC_T_HELLO		1	/* handshake (both directions) */
#define	IPC_T_ERROR		4	/* server -> client: structured error */
#define	IPC_T_OP_REQ		12	/* client -> server: correlated operation */
#define	IPC_T_OP_REPLY		13	/* server -> client: correlated result */
#define	IPC_T_OP_EVENT		14	/* server -> client: typed async event */

#define	IPC_OP_PREFIX_SIZE	8
#define	IPC_OP_DOMAIN_CTL	1
#define	IPC_OP_DOMAIN_GAP	2
#define	IPC_OP_DOMAIN_GATT	3
#define	IPC_OP_DOMAIN_SECURITY	4
#define	IPC_OP_DOMAIN_ADV	5
#define	IPC_OP_DOMAIN_PERIODIC	6
#define	IPC_OP_DOMAIN_L2CAP	7
#define	IPC_OP_DOMAIN_ISO	8
#define	IPC_OP_DOMAIN_MESH	9

/* Controller-scoped operation requests carry the adapter in flags[15:8]. */
#define	IPC_OP_FLAGS_RESERVED_MASK	0x00ffu
#define	IPC_OP_ADAPTER_SHIFT		8
#define	IPC_OP_ADAPTER_MASK		0xff00u

#define	IPC_MESH_SUBSCRIBE	1
#define	IPC_MESH_UNSUBSCRIBE	2
#define	IPC_MESH_ADV_SEND	3
#define	IPC_MESH_EV_ADV		1
#define	IPC_MESH_REQ_SIZE	2
#define	IPC_MESH_ADV_REQ_HDR_SIZE 6
#define	IPC_MESH_ADV_EVENT_HDR_SIZE 4
#define	IPC_MESH_ADAPTER_DEFAULT	0xff

#define	IPC_GAP_REQ_SIZE	12
#define	IPC_GAP_DISCONNECT	1
#define	IPC_GAP_SET_PHY		2
#define	IPC_GAP_SET_DATA_LEN	3
#define	IPC_GAP_CONN_UPDATE	4
#define	IPC_GAP_CONNECT		5
#define	IPC_GAP_SCAN		6
#define	IPC_GAP_CONNECT_NAME	7
#define	IPC_GAP_PATH_LOSS	8
#define	IPC_GAP_GET_CONNECTIONS	9
#define	IPC_GAP_F_CONN_PARAMS	0x0001u
#define	IPC_GAP_F_PHY		0x0002u
#define	IPC_GAP_PHY_REQ_SIZE	14
#define	IPC_GAP_DATA_LEN_REQ_SIZE 16
#define	IPC_GAP_CONN_UPDATE_REQ_SIZE 20
#define	IPC_GAP_CONNECT_REQ_SIZE	22
#define	IPC_GAP_SCAN_REQ_SIZE	44
#define	IPC_GAP_CONNECT_NAME_REQ_SIZE 36
#define	IPC_GAP_PATH_LOSS_REQ_SIZE 20
#define	IPC_GAP_CONNECTION_REQ_SIZE 12
#define	IPC_GAP_CONNECTION_REPLY_HDR_SIZE 4
#define	IPC_GAP_CONNECTION_RECORD_SIZE 88
#define	IPC_GAP_CONNECTION_MAX 32
#define	IPC_GAP_CONN_F_ENCRYPTED 0x01u
#define	IPC_GAP_CONN_F_AUTHENTICATED 0x02u
#define	IPC_GAP_CONN_F_PHY_VALID 0x04u
#define	IPC_GAP_CONNECT_NAME_REPLY_SIZE 7
#define	IPC_GAP_SCAN_F_PASSIVE	0x0001u
#define	IPC_GAP_SCAN_F_ACCEPT_LIST 0x0002u
#define	IPC_GAP_SCAN_F_NO_DEDUP	0x0004u
#define	IPC_GAP_EV_CONNECTED	1
#define	IPC_GAP_EV_DISCONNECTED	2
#define	IPC_GAP_EV_SCAN_RESULT	3
#define	IPC_GAP_CONNECTED_EVENT_SIZE 15
#define	IPC_GAP_DISCONNECTED_EVENT_SIZE 12
#define	IPC_GAP_SCAN_RESULT_EVENT_SIZE 64

#define	IPC_GATT_READ		1
#define	IPC_GATT_WRITE		2
#define	IPC_GATT_WRITE_CMD	3
#define	IPC_GATT_SUBSCRIBE	4
#define	IPC_GATT_UNSUBSCRIBE	5
#define	IPC_GATT_DISCOVER	6
#define	IPC_GATT_READ_REPLY	7
#define	IPC_GATT_READ_REJECT	8
#define	IPC_GATT_AUTHORIZE_REPLY 9
#define	IPC_GATT_SET_VALUE	10
#define	IPC_GATT_NOTIFY		11
#define	IPC_GATT_INDICATE	12
#define	IPC_GATT_REMOVE_SERVICE	13
#define	IPC_GATT_ADD_SERVICE	14
#define	IPC_GATT_ADD_CHARACTERISTIC 15
#define	IPC_GATT_ADD_INCLUDE	16
#define	IPC_GATT_ADD_DESCRIPTOR	17
#define	IPC_GATT_ACQUIRE_NOTIFY	18
#define	IPC_GATT_ACQUIRE_WRITE	19
#define	IPC_GATT_REQ_SIZE	14
#define	IPC_GATT_VALUE_REQ_SIZE	16
#define	IPC_GATT_DECISION_REQ_SIZE 15
#define	IPC_GATT_ADD_SERVICE_REQ_SIZE 32
#define	IPC_GATT_ADD_CHAR_REQ_SIZE 38
#define	IPC_GATT_ADD_INCLUDE_REQ_SIZE 20
#define	IPC_GATT_ADD_DESC_REQ_SIZE 36
#define	IPC_GATT_HANDLE_REPLY_SIZE 4
#define	IPC_GATT_ACQUIRE_REPLY_SIZE 4
#define	IPC_GATT_READ_REPLY_SIZE	6
#define	IPC_GATT_DISCOVER_REPLY_SIZE 6
#define	IPC_GATT_EV_NOTIFY	1
#define	IPC_GATT_EV_SERVICE	2
#define	IPC_GATT_EV_CHARACTERISTIC 3
#define	IPC_GATT_EV_WRITE	4
#define	IPC_GATT_EV_READ	5
#define	IPC_GATT_EV_AUTHORIZE	6
/* Notify event ends with adapter_index:u8 and bearer_att_mtu:le16. */
#define	IPC_GATT_NOTIFY_EVENT_SIZE 16
#define	IPC_GATT_DISCOVERY_EVENT_SIZE 24
#define	IPC_GATT_VALUE_EVENT_SIZE 6
#define	IPC_GATT_READ_EVENT_SIZE 6
#define	IPC_GATT_AUTHORIZE_EVENT_SIZE 12

#define	IPC_SECURITY_PAIR	1
#define	IPC_SECURITY_PASSKEY_REPLY 2
#define	IPC_SECURITY_NUMCMP_REPLY 3
#define	IPC_SECURITY_REGISTER_AGENT 4
#define	IPC_SECURITY_UNREGISTER_AGENT 5
#define	IPC_SECURITY_UNBOND	6
#define	IPC_SECURITY_REKEY	7
#define	IPC_SECURITY_SET_POLICY	8
#define	IPC_SECURITY_GET_POLICY	9
#define	IPC_SECURITY_GET_INFO	10
#define	IPC_SECURITY_OOB_GENERATE 11
#define	IPC_SECURITY_OOB_INJECT_SC 12
#define	IPC_SECURITY_OOB_INJECT_LEGACY 13
#define	IPC_SECURITY_OOB_CLEAR	14
#define	IPC_SECURITY_RESOLV_ADD 15
#define	IPC_SECURITY_RESOLV_REMOVE 16
#define	IPC_SECURITY_RESOLV_CLEAR 17
#define	IPC_SECURITY_BOND_LIST	18
#define	IPC_SECURITY_RESOLV_LIST 19
#define	IPC_SECURITY_BOND_EXPORT 20
#define	IPC_SECURITY_BOND_IMPORT 21
#define	IPC_SECURITY_REQ_SIZE	12
#define	IPC_SECURITY_PASSKEY_REQ_SIZE 16
#define	IPC_SECURITY_DECISION_REQ_SIZE 13
#define	IPC_SECURITY_AGENT_REQ_SIZE 13
#define	IPC_SECURITY_POLICY_REQ_SIZE 24
#define	IPC_SECURITY_POLICY_REPLY_SIZE 12
#define	IPC_SECURITY_INFO_REPLY_SIZE 12
#define	IPC_SECURITY_OOB_REPLY_SIZE 66
#define	IPC_SECURITY_OOB_SC_REQ_SIZE 44
#define	IPC_SECURITY_OOB_LEGACY_REQ_SIZE 28
#define	IPC_SECURITY_OOB_CLEAR_REQ_SIZE 13
#define	IPC_SECURITY_RESOLV_REQ_SIZE 32
#define	IPC_SECURITY_OOB_CLEAR_F_ALL 0x01u
#define	IPC_SECURITY_RESOLV_F_IRK 0x01u
#define	IPC_SECURITY_BOND_REPLY_HDR_SIZE 4
#define	IPC_SECURITY_BOND_RECORD_SIZE 72
#define	IPC_SECURITY_BOND_F_LTK 0x01u
#define	IPC_SECURITY_BOND_F_IRK 0x02u
#define	IPC_SECURITY_BOND_F_CSRK 0x04u
#define	IPC_SECURITY_BOND_F_SC 0x08u
#define	IPC_SECURITY_BOND_F_LINK_KEY 0x10u
#define	IPC_SECURITY_BOND_F_MITM 0x20u
#define	IPC_SECURITY_RESOLV_REPLY_HDR_SIZE 4
#define	IPC_SECURITY_RESOLV_RECORD_SIZE 8
#define	IPC_SECURITY_RESOLV_F_IN_LIST 0x01u
#define	IPC_SECURITY_BOND_EXPORT_REPLY_HDR_SIZE 4
#define	IPC_SECURITY_BOND_IMPORT_REQ_HDR_SIZE 16
#define	IPC_SECURITY_POLICY_F_MITM 0x0001u
#define	IPC_SECURITY_POLICY_F_BONDING 0x0002u
#define	IPC_SECURITY_POLICY_F_SC 0x0004u
#define	IPC_SECURITY_POLICY_F_KEYPRESS 0x0008u
#define	IPC_SECURITY_POLICY_F_IO_CAP 0x0010u
#define	IPC_SECURITY_POLICY_F_MIN_SEC 0x0020u
#define	IPC_SECURITY_POLICY_F_KEY_SIZE 0x0040u
#define	IPC_SECURITY_POLICY_F_KEY_DIST 0x0080u
#define	IPC_SECURITY_POLICY_F_ALL 0x00ffu
#define	IPC_SECURITY_INFO_F_ENCRYPTED 0x01u
#define	IPC_SECURITY_INFO_F_AUTHENTICATED 0x02u
#define	IPC_SECURITY_INFO_F_SC 0x04u
#define	IPC_SECURITY_INFO_F_BONDED 0x08u
#define	IPC_SECURITY_EV_PASSKEY_DISPLAY 1
#define	IPC_SECURITY_EV_PASSKEY_INPUT 2
#define	IPC_SECURITY_EV_NUMCMP	3
#define	IPC_SECURITY_EV_KEYPRESS 4
#define	IPC_SECURITY_PASSKEY_EVENT_SIZE 13
#define	IPC_SECURITY_INPUT_EVENT_SIZE 9
#define	IPC_SECURITY_KEYPRESS_EVENT_SIZE 10

#define	IPC_ADV_SET_PARAMS	1
#define	IPC_ADV_SET_NAME	2
#define	IPC_ADV_SET_DATA	3
#define	IPC_ADV_SET_SCAN_RESPONSE 4
#define	IPC_ADV_SET_CREATE	5
#define	IPC_ADV_SET_HANDLE_PARAMS 6
#define	IPC_ADV_SET_HANDLE_DATA 7
#define	IPC_ADV_SET_HANDLE_ENABLE 8
#define	IPC_ADV_SET_HANDLE_REMOVE 9
#define	IPC_ADV_PARAMS_REQ_SIZE	28
#define	IPC_ADV_NAME_REQ_HDR_SIZE 4
#define	IPC_ADV_NAME_MAX_SIZE	26
#define	IPC_ADV_DATA_REQ_HDR_SIZE 8
#define	IPC_ADV_SET_CREATE_REQ_SIZE 4
#define	IPC_ADV_SET_CREATE_REPLY_SIZE 4
#define	IPC_ADV_SET_PARAMS_REQ_SIZE 20
#define	IPC_ADV_SET_DATA_REQ_HDR_SIZE 8
#define	IPC_ADV_SET_STATE_REQ_SIZE 8

#define	IPC_PERIODIC_ADV_PARAMS	1
#define	IPC_PERIODIC_ADV_DATA	2
#define	IPC_PERIODIC_ADV_ENABLE	3
#define	IPC_PERIODIC_SYNC_CREATE 4
#define	IPC_PERIODIC_SYNC_CANCEL 5
#define	IPC_PERIODIC_SYNC_TERMINATE 6
#define	IPC_PERIODIC_LIST_ADD	7
#define	IPC_PERIODIC_LIST_REMOVE 8
#define	IPC_PERIODIC_LIST_CLEAR 9
#define	IPC_PERIODIC_LIST_SIZE	10
#define	IPC_PERIODIC_PAST_TRANSFER 11
#define	IPC_PERIODIC_PAST_RECEIVE 12
#define	IPC_PERIODIC_PAST_SET_INFO 13
#define	IPC_PERIODIC_PAST_PARAMS 14
#define	IPC_PERIODIC_PAST_DEFAULT_PARAMS 15
#define	IPC_PERIODIC_PARAMS_REQ_SIZE 12
#define	IPC_PERIODIC_DATA_REQ_HDR_SIZE 8
#define	IPC_PERIODIC_STATE_REQ_SIZE 8
#define	IPC_PERIODIC_SYNC_CREATE_REQ_SIZE 16
#define	IPC_PERIODIC_PEER_REQ_SIZE 12
#define	IPC_PERIODIC_SIMPLE_REQ_SIZE 4
#define	IPC_PERIODIC_SIZE_REPLY_SIZE 4
#define	IPC_PERIODIC_PAST_TRANSFER_REQ_SIZE 16
#define	IPC_PERIODIC_PAST_PARAMS_REQ_SIZE 20
#define	IPC_PERIODIC_PAST_DEFAULT_REQ_SIZE 12

#define	IPC_L2CAP_ACQUIRE_COC	1
#define	IPC_L2CAP_EATT_OPEN	2
#define	IPC_L2CAP_EATT_CLOSE	3
#define	IPC_L2CAP_REQ_SIZE	17
#define	IPC_L2CAP_ACQUIRE_REPLY_SIZE 14

#define	IPC_ISO_CIG_CREATE	1
#define	IPC_ISO_CIS_CREATE	2
#define	IPC_ISO_CIS_TEARDOWN	3
#define	IPC_ISO_CIG_REMOVE	4
#define	IPC_ISO_CIS_ACCEPT	5
#define	IPC_ISO_CIS_REJECT	6
#define	IPC_ISO_BIG_CREATE	7
#define	IPC_ISO_BIG_TERMINATE	8
#define	IPC_ISO_BIG_SYNC_CREATE 9
#define	IPC_ISO_BIG_SYNC_TERMINATE 10
#define	IPC_ISO_ACQUIRE	11
#define	IPC_ISO_BIS_ACQUIRE	12
#define	IPC_ISO_CONNECT_ACQUIRE 13
#define	IPC_ISO_CIG_REQ_HDR_SIZE 24
#define	IPC_ISO_CIS_PARAM_SIZE	10
#define	IPC_ISO_CIG_REPLY_SIZE	20
#define	IPC_ISO_CIS_CREATE_REQ_SIZE 16
#define	IPC_ISO_SIMPLE_REQ_SIZE 8
#define	IPC_ISO_BIG_REQ_SIZE	38
#define	IPC_ISO_BIG_SYNC_REQ_SIZE 36
#define	IPC_ISO_CONNECT_ACQUIRE_REQ_SIZE 16
#define	IPC_ISO_ACQUIRE_REPLY_SIZE 4
#define	IPC_ISO_EV_CIS_REQUEST	1
#define	IPC_ISO_EV_ESTABLISHED	2
#define	IPC_ISO_EVENT_SIZE	14

#define	IPC_STATUS_REPLY_SIZE	8
#define	IPC_STATUS_F_PERIPH_ACTIVE	0x0001u

#define	IPC_ADAPTER_CAPS_REPLY_SIZE	34
#define	IPC_ADAPTER_NAME_SIZE		16

#define	IPC_CTL_REQ_SIZE	12
#define	IPC_CTL_REPLY_SIZE	8

#define	IPC_CTL_F_BOOL		0x0001u	/* arg0 carries boolean state */
#define	IPC_CTL_F_ADAPTER	0x0002u	/* arg1 carries adapter index */
#define	IPC_CTL_F_LIMITED	0x0004u	/* limited discoverable mode */

#define	IPC_CTL_POWER		1
#define	IPC_CTL_PRIVACY		2
#define	IPC_CTL_SET_MTU		3
#define	IPC_CTL_GATT_BEGIN	4
#define	IPC_CTL_GATT_COMMIT	5
#define	IPC_CTL_GATT_ROLLBACK	6
#define	IPC_CTL_ADVERTISE	7
#define	IPC_CTL_DISCOVERABLE	8
#define	IPC_CTL_PAIRABLE	9
#define	IPC_CTL_RPA_TIMEOUT	10
#define	IPC_CTL_STATUS		11
#define	IPC_CTL_ADAPTER_CAPS	12

/*
 * Structured error codes (ih_arg on an IPC_T_ERROR frame).  The optional
 * payload carries a human-readable message.  libble maps these onto its
 * BLE_ERR_* space for ble_errno()/ble_strerror().
 */
#define	IPC_ERR_NONE		0
#define	IPC_ERR_GENERIC		1	/* unclassified daemon error */
#define	IPC_ERR_UNKNOWN_CMD	2	/* unrecognised command */
#define	IPC_ERR_INVAL		3	/* invalid argument/address/handle/hex */
#define	IPC_ERR_NOT_FOUND	4	/* device/handle/service not found */
#define	IPC_ERR_NOT_CONN	5	/* device not connected / no ATT channel */
#define	IPC_ERR_BUSY		6	/* rate limited / already in progress */
#define	IPC_ERR_PERM		7	/* permission denied (privilege tier) */
#define	IPC_ERR_TOOBIG		8	/* value/line too long */
#define	IPC_ERR_NOMEM		9	/* out of memory */
#define	IPC_ERR_PROTO		10	/* malformed frame / version mismatch */
#define	IPC_ERR_IO		11	/* ATT/HCI read/write failed */

/* Feature bits negotiated in the fixed-width HELLO payload. */
#define	IPC_HELLO_FEATURES_SIZE	4u
#define	IPC_FEATURE_EVENTS	0x00000001u	/* async event frames */
#define	IPC_FEATURE_FDPASS	0x00000002u	/* SCM_RIGHTS fd transfer */
#define	IPC_FEATURE_MESH	0x00000004u	/* mesh bearer; implies events */
#define	IPC_FEATURE_ALL		(IPC_FEATURE_EVENTS | IPC_FEATURE_FDPASS | \
				 IPC_FEATURE_MESH)

/* ---- little-endian header encode/decode (host-endian independent) ---- */

static inline void
ipc_put_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
	p[2] = (uint8_t)((v >> 16) & 0xff);
	p[3] = (uint8_t)((v >> 24) & 0xff);
}

static inline void
ipc_put_le16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
}

static inline uint32_t
ipc_get_le32(const uint8_t *p)
{
	return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
	    ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint16_t
ipc_get_le16(const uint8_t *p)
{
	return (uint16_t)(((uint16_t)p[0]) | ((uint16_t)p[1] << 8));
}

static inline void
ipc_hdr_encode(uint8_t hdr[IPC_HDR_SIZE], uint32_t len, uint16_t type,
    uint16_t arg)
{
	ipc_put_le32(hdr, len);
	ipc_put_le16(hdr + 4, type);
	ipc_put_le16(hdr + 6, arg);
}

static inline void
ipc_hdr_decode(const uint8_t hdr[IPC_HDR_SIZE], uint32_t *len, uint16_t *type,
    uint16_t *arg)
{
	*len = ipc_get_le32(hdr);
	*type = ipc_get_le16(hdr + 4);
	*arg = ipc_get_le16(hdr + 6);
}

static inline void
ipc_op_prefix_encode(uint8_t payload[IPC_OP_PREFIX_SIZE], uint32_t request_id,
    uint16_t status, uint16_t flags)
{
	ipc_put_le32(payload + 0, request_id);
	ipc_put_le16(payload + 4, status);
	ipc_put_le16(payload + 6, flags);
}

static inline void
ipc_op_prefix_decode(const uint8_t payload[IPC_OP_PREFIX_SIZE],
    uint32_t *request_id, uint16_t *status, uint16_t *flags)
{
	*request_id = ipc_get_le32(payload + 0);
	*status = ipc_get_le16(payload + 4);
	*flags = ipc_get_le16(payload + 6);
}

static inline void
ipc_gap_req_encode(uint8_t payload[IPC_GAP_REQ_SIZE], uint16_t opcode,
    uint16_t flags, uint8_t addr_type, const uint8_t addr[6],
    uint8_t adapter_index)
{
	ipc_put_le16(payload + 0, opcode);
	ipc_put_le16(payload + 2, flags);
	payload[4] = addr_type;
	memcpy(payload + 5, addr, 6);
	payload[11] = adapter_index;
}

static inline void
ipc_gap_req_decode(const uint8_t payload[IPC_GAP_REQ_SIZE], uint16_t *opcode,
    uint16_t *flags, uint8_t *addr_type, uint8_t addr[6],
    uint8_t *adapter_index)
{
	*opcode = ipc_get_le16(payload + 0);
	*flags = ipc_get_le16(payload + 2);
	*addr_type = payload[4];
	memcpy(addr, payload + 5, 6);
	*adapter_index = payload[11];
}

static inline void
ipc_status_reply_encode(uint8_t payload[IPC_STATUS_REPLY_SIZE],
    uint16_t adapters, uint16_t connections, uint16_t clients, uint16_t flags)
{
	ipc_put_le16(payload + 0, adapters);
	ipc_put_le16(payload + 2, connections);
	ipc_put_le16(payload + 4, clients);
	ipc_put_le16(payload + 6, flags);
}

static inline void
ipc_status_reply_decode(const uint8_t payload[IPC_STATUS_REPLY_SIZE],
    uint16_t *adapters, uint16_t *connections, uint16_t *clients,
    uint16_t *flags)
{
	*adapters = ipc_get_le16(payload + 0);
	*connections = ipc_get_le16(payload + 2);
	*clients = ipc_get_le16(payload + 4);
	*flags = ipc_get_le16(payload + 6);
}

static inline void
ipc_adapter_caps_reply_encode(
    uint8_t payload[IPC_ADAPTER_CAPS_REPLY_SIZE], uint16_t index,
    const char name[IPC_ADAPTER_NAME_SIZE], const uint8_t addr[6],
    uint8_t addr_type, uint8_t powered, uint64_t le_features)
{
	size_t i;

	ipc_put_le16(payload + 0, index);
	for (i = 0; i < IPC_ADAPTER_NAME_SIZE; i++)
		payload[2 + i] = (uint8_t)name[i];
	for (i = 0; i < 6; i++)
		payload[18 + i] = addr[i];
	payload[24] = addr_type;
	payload[25] = powered;
	ipc_put_le32(payload + 26, (uint32_t)(le_features & 0xffffffffu));
	ipc_put_le32(payload + 30, (uint32_t)(le_features >> 32));
}

static inline void
ipc_adapter_caps_reply_decode(
    const uint8_t payload[IPC_ADAPTER_CAPS_REPLY_SIZE], uint16_t *index,
    char name[IPC_ADAPTER_NAME_SIZE], uint8_t addr[6], uint8_t *addr_type,
    uint8_t *powered, uint64_t *le_features)
{
	size_t i;
	uint64_t lo, hi;

	*index = ipc_get_le16(payload + 0);
	for (i = 0; i < IPC_ADAPTER_NAME_SIZE; i++)
		name[i] = (char)payload[2 + i];
	for (i = 0; i < 6; i++)
		addr[i] = payload[18 + i];
	*addr_type = payload[24];
	*powered = payload[25];
	lo = ipc_get_le32(payload + 26);
	hi = ipc_get_le32(payload + 30);
	*le_features = lo | (hi << 32);
}

static inline void
ipc_ctl_req_encode(uint8_t payload[IPC_CTL_REQ_SIZE], uint16_t opcode,
    uint16_t flags, uint32_t arg0, uint32_t arg1)
{
	ipc_put_le16(payload + 0, opcode);
	ipc_put_le16(payload + 2, flags);
	ipc_put_le32(payload + 4, arg0);
	ipc_put_le32(payload + 8, arg1);
}

static inline void
ipc_ctl_req_decode(const uint8_t payload[IPC_CTL_REQ_SIZE],
    uint16_t *opcode, uint16_t *flags, uint32_t *arg0, uint32_t *arg1)
{
	*opcode = ipc_get_le16(payload + 0);
	*flags = ipc_get_le16(payload + 2);
	*arg0 = ipc_get_le32(payload + 4);
	*arg1 = ipc_get_le32(payload + 8);
}

static inline void
ipc_ctl_reply_encode(uint8_t payload[IPC_CTL_REPLY_SIZE], uint16_t opcode,
    uint16_t flags, uint32_t value)
{
	ipc_put_le16(payload + 0, opcode);
	ipc_put_le16(payload + 2, flags);
	ipc_put_le32(payload + 4, value);
}

static inline void
ipc_ctl_reply_decode(const uint8_t payload[IPC_CTL_REPLY_SIZE],
    uint16_t *opcode, uint16_t *flags, uint32_t *value)
{
	*opcode = ipc_get_le16(payload + 0);
	*flags = ipc_get_le16(payload + 2);
	*value = ipc_get_le32(payload + 4);
}

#endif /* _BLUED_IPC_PROTO_H_ */
