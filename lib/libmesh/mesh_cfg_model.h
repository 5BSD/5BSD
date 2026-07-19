/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Configuration model (MshMDL_v1.1 Section 4.4.1), the
 * mandatory foundation model present on the primary element of every node.
 * This module provides the message codecs (build + parse of the access-PDU
 * parameters) and a small server-side state block for the core set of
 * Configuration messages.
 *
 * Every codec here operates on the *Access PDU* (opcode + parameters) as
 * produced/consumed by mesh_access.[ch]: a _build() emits the full access
 * payload (the plaintext that mesh_upper_encrypt() carries), and a _parse()
 * consumes it.  All addresses, key indexes and model identifiers are
 * little-endian on the wire (MshMDL Sections 4.3.1, 4.3.2); the 12-bit key
 * index packing follows Section 4.3.1.1.
 *
 * Opcodes are cited from the MshMDL Section 4.3.4 message summary table.
 * The module is pure and hardware-free: no I/O, no globals; secrets (the
 * 128-bit keys carried by AppKey/NetKey Add/Update) are the caller's to
 * clear, but the codecs keep no copies beyond the caller-supplied structs.
 * Every function returns 0 on success and -1 on failure, output zeroed on
 * failure.
 */

#ifndef _MESH_CFG_MODEL_H_
#define _MESH_CFG_MODEL_H_

#include <stddef.h>
#include <stdint.h>

/* ----------------------------------------------------------------
 * Configuration model opcodes.  MshMDL Section 4.3.4 (summary of
 * messages).  1-octet opcodes are 0x00..0x06; the remainder are the
 * 2-octet 0x80xx family.
 * ---------------------------------------------------------------- */
#define	MESH_CFG_OP_APPKEY_ADD			0x0000
#define	MESH_CFG_OP_APPKEY_UPDATE		0x0001
#define	MESH_CFG_OP_COMP_DATA_STATUS		0x0002
#define	MESH_CFG_OP_MODEL_PUB_SET		0x0003
#define	MESH_CFG_OP_APPKEY_DELETE		0x8000
#define	MESH_CFG_OP_APPKEY_GET			0x8001
#define	MESH_CFG_OP_APPKEY_LIST			0x8002
#define	MESH_CFG_OP_APPKEY_STATUS		0x8003
#define	MESH_CFG_OP_COMP_DATA_GET		0x8008
#define	MESH_CFG_OP_BEACON_GET			0x8009
#define	MESH_CFG_OP_BEACON_SET			0x800A
#define	MESH_CFG_OP_BEACON_STATUS		0x800B
#define	MESH_CFG_OP_DEFAULT_TTL_GET		0x800C
#define	MESH_CFG_OP_DEFAULT_TTL_SET		0x800D
#define	MESH_CFG_OP_DEFAULT_TTL_STATUS		0x800E
#define	MESH_CFG_OP_FRIEND_GET			0x800F
#define	MESH_CFG_OP_FRIEND_SET			0x8010
#define	MESH_CFG_OP_FRIEND_STATUS		0x8011
#define	MESH_CFG_OP_GATT_PROXY_GET		0x8012
#define	MESH_CFG_OP_GATT_PROXY_SET		0x8013
#define	MESH_CFG_OP_GATT_PROXY_STATUS		0x8014
#define	MESH_CFG_OP_MODEL_PUB_GET		0x8018
#define	MESH_CFG_OP_MODEL_PUB_STATUS		0x8019
#define	MESH_CFG_OP_MODEL_PUB_VA_SET		0x801A
#define	MESH_CFG_OP_MODEL_SUB_ADD		0x801B
#define	MESH_CFG_OP_MODEL_SUB_DELETE		0x801C
#define	MESH_CFG_OP_MODEL_SUB_DELETE_ALL	0x801D
#define	MESH_CFG_OP_MODEL_SUB_OVERWRITE		0x801E
#define	MESH_CFG_OP_MODEL_SUB_STATUS		0x801F
#define	MESH_CFG_OP_MODEL_SUB_VA_ADD		0x8020
#define	MESH_CFG_OP_RELAY_GET			0x8026
#define	MESH_CFG_OP_RELAY_SET			0x8027
#define	MESH_CFG_OP_RELAY_STATUS		0x8028
#define	MESH_CFG_OP_MODEL_APP_BIND		0x803D
#define	MESH_CFG_OP_MODEL_APP_STATUS		0x803E
#define	MESH_CFG_OP_MODEL_APP_UNBIND		0x803F
#define	MESH_CFG_OP_NETKEY_ADD			0x8040
#define	MESH_CFG_OP_NETKEY_DELETE		0x8041
#define	MESH_CFG_OP_NETKEY_GET			0x8042
#define	MESH_CFG_OP_NETKEY_LIST			0x8043
#define	MESH_CFG_OP_NETKEY_STATUS		0x8044
#define	MESH_CFG_OP_NETKEY_UPDATE		0x8045
#define	MESH_CFG_OP_NODE_RESET			0x8049
#define	MESH_CFG_OP_NODE_RESET_STATUS		0x804A

/* Additional mandatory Configuration Server opcodes (MshMDL Section 4.3.4). */
#define	MESH_CFG_OP_KEY_REFRESH_PHASE_GET	0x8015
#define	MESH_CFG_OP_KEY_REFRESH_PHASE_SET	0x8016
#define	MESH_CFG_OP_KEY_REFRESH_PHASE_STATUS	0x8017
#define	MESH_CFG_OP_MODEL_SUB_VA_DELETE		0x8021
#define	MESH_CFG_OP_MODEL_SUB_VA_OVERWRITE	0x8022
#define	MESH_CFG_OP_NET_TRANSMIT_GET		0x8023
#define	MESH_CFG_OP_NET_TRANSMIT_SET		0x8024
#define	MESH_CFG_OP_NET_TRANSMIT_STATUS		0x8025
#define	MESH_CFG_OP_SIG_MODEL_SUB_GET		0x8029
#define	MESH_CFG_OP_SIG_MODEL_SUB_LIST		0x802A
#define	MESH_CFG_OP_VND_MODEL_SUB_GET		0x802B
#define	MESH_CFG_OP_VND_MODEL_SUB_LIST		0x802C
#define	MESH_CFG_OP_LPN_POLLTIMEOUT_GET		0x802D
#define	MESH_CFG_OP_LPN_POLLTIMEOUT_STATUS	0x802E
#define	MESH_CFG_OP_NODE_IDENTITY_GET		0x8046
#define	MESH_CFG_OP_NODE_IDENTITY_SET		0x8047
#define	MESH_CFG_OP_NODE_IDENTITY_STATUS	0x8048
#define	MESH_CFG_OP_SIG_MODEL_APP_GET		0x804B
#define	MESH_CFG_OP_SIG_MODEL_APP_LIST		0x804C
#define	MESH_CFG_OP_VND_MODEL_APP_GET		0x804D
#define	MESH_CFG_OP_VND_MODEL_APP_LIST		0x804E

/*
 * Node Identity states (MshMDL Section 4.2.13.2) and Key Refresh Phase
 * transition/state values (Section 4.2.14).
 */
#define	MESH_CFG_NODE_IDENTITY_STOPPED		0x00
#define	MESH_CFG_NODE_IDENTITY_RUNNING		0x01
#define	MESH_CFG_NODE_IDENTITY_NOT_SUPPORTED	0x02
#define	MESH_CFG_KR_PHASE_0			0x00	/* Normal operation */
#define	MESH_CFG_KR_PHASE_1			0x01	/* both keys, tx old */
#define	MESH_CFG_KR_PHASE_2			0x02	/* both keys, tx new */
#define	MESH_CFG_KR_TRANSITION_2		0x02	/* -> Phase 2 */
#define	MESH_CFG_KR_TRANSITION_3		0x03	/* -> Phase 0 (finish) */

#define	MESH_CFG_MAX_ADDRESSES			32

/*
 * Configuration status codes.  MshMDL Section 4.3.4, Table "Summary of
 * status codes".
 */
enum mesh_cfg_status {
	MESH_CFG_SUCCESS			= 0x00,
	MESH_CFG_INVALID_ADDRESS		= 0x01,
	MESH_CFG_INVALID_MODEL			= 0x02,
	MESH_CFG_INVALID_APPKEY_INDEX		= 0x03,
	MESH_CFG_INVALID_NETKEY_INDEX		= 0x04,
	MESH_CFG_INSUFFICIENT_RESOURCES		= 0x05,
	MESH_CFG_KEY_INDEX_ALREADY_STORED	= 0x06,
	MESH_CFG_INVALID_PUBLISH_PARAMS		= 0x07,
	MESH_CFG_NOT_A_SUBSCRIBE_MODEL		= 0x08,
	MESH_CFG_STORAGE_FAILURE		= 0x09,
	MESH_CFG_FEATURE_NOT_SUPPORTED		= 0x0A,
	MESH_CFG_CANNOT_UPDATE			= 0x0B,
	MESH_CFG_CANNOT_REMOVE			= 0x0C,
	MESH_CFG_CANNOT_BIND			= 0x0D,
	MESH_CFG_TEMP_UNABLE_TO_CHANGE		= 0x0E,
	MESH_CFG_CANNOT_SET			= 0x0F,
	MESH_CFG_UNSPECIFIED_ERROR		= 0x10,
	MESH_CFG_INVALID_BINDING		= 0x11
};

/* ----------------------------------------------------------------
 * Key-index packing (MshMDL Section 4.3.1.1).
 * A single 12-bit key index occupies 2 octets little-endian (4 RFU bits).
 * Two key indexes pack into 3 octets: idx0 in the least significant 12
 * bits, idx1 in the most significant 12 bits.
 * ---------------------------------------------------------------- */
void	mesh_cfg_keyidx_pack1(uint8_t out[2], uint16_t idx);
uint16_t	mesh_cfg_keyidx_unpack1(const uint8_t in[2]);
void	mesh_cfg_keyidx_pack2(uint8_t out[3], uint16_t idx0, uint16_t idx1);
void	mesh_cfg_keyidx_unpack2(const uint8_t in[3], uint16_t *idx0,
	    uint16_t *idx1);

/* ----------------------------------------------------------------
 * Model identifier (MshMDL Section 4.3.2).  A SIG model is a 2-octet
 * model id (little-endian); a vendor model is a 4-octet identifier:
 * Company Identifier (2, LE) followed by vendor model id (2, LE).
 * ---------------------------------------------------------------- */
struct mesh_cfg_model_id {
	uint16_t	model_id;
	uint16_t	company_id;	/* used only when vendor != 0 */
	int		vendor;		/* 0 => SIG (2 octets), 1 => vendor (4) */
};
int	mesh_cfg_model_id_encode(const struct mesh_cfg_model_id *m, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_model_id_decode(const uint8_t *in, size_t inlen,
	    struct mesh_cfg_model_id *out);

/* ================================================================
 * Composition Data (MshMDL Section 4.4.1.2).
 * ================================================================ */

/* Feature bits for the Composition Data Page 0 Features field (LE). */
#define	MESH_CFG_FEATURE_RELAY		0x0001
#define	MESH_CFG_FEATURE_PROXY		0x0002
#define	MESH_CFG_FEATURE_FRIEND		0x0004
#define	MESH_CFG_FEATURE_LOW_POWER	0x0008

#define	MESH_CFG_COMP_MAX_MODELS	48
#define	MESH_CFG_COMP_MAX_ELEMENTS	8

struct mesh_cfg_comp_element {
	uint16_t	loc;		/* location descriptor */
	uint16_t	sig_models[MESH_CFG_COMP_MAX_MODELS];
	size_t		n_sig;
	struct {
		uint16_t company_id;
		uint16_t model_id;
	}		vnd_models[MESH_CFG_COMP_MAX_MODELS];
	size_t		n_vnd;
};

struct mesh_cfg_comp_page0 {
	uint16_t	cid;		/* Company Identifier */
	uint16_t	pid;		/* Product Identifier */
	uint16_t	vid;		/* Version Identifier */
	uint16_t	crpl;		/* replay protection list size */
	uint16_t	features;	/* MESH_CFG_FEATURE_* */
	struct mesh_cfg_comp_element elements[MESH_CFG_COMP_MAX_ELEMENTS];
	size_t		n_elements;
};

/*
 * Encode/decode Composition Data Page 0 (Section 4.4.1.2.1): the fixed
 * CID/PID/VID/CRPL/Features header followed by, per element, Loc, NumS,
 * NumV, the SIG model ids and the vendor model ids.  Everything little-
 * endian.  These operate on the raw page-0 octet blob (no opcode/page byte).
 */
int	mesh_cfg_comp_page0_encode(const struct mesh_cfg_comp_page0 *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_comp_page0_decode(const uint8_t *in, size_t inlen,
	    struct mesh_cfg_comp_page0 *out);

/* Config Composition Data Get: opcode 0x8008 + Page (1 octet). */
int	mesh_cfg_comp_get_build(uint8_t page, uint8_t *out, size_t *outlen);
int	mesh_cfg_comp_get_parse(const uint8_t *in, size_t inlen, uint8_t *page);

/* Config Composition Data Status: opcode 0x02 + Page (1) + page data. */
#define	MESH_CFG_COMP_DATA_MAX	(378)	/* access params less opcode+page */
struct mesh_cfg_comp_status {
	uint8_t		page;
	uint8_t		data[MESH_CFG_COMP_DATA_MAX];
	size_t		data_len;
};
int	mesh_cfg_comp_status_build(const struct mesh_cfg_comp_status *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_comp_status_parse(const uint8_t *in, size_t inlen,
	    struct mesh_cfg_comp_status *out);

/* ================================================================
 * AppKey / NetKey management (MshMDL Sections 4.4.1.2.x, 4.3.1.1).
 * ================================================================ */

/*
 * AppKey Add (0x00) / AppKey Update (0x01): NetKeyIndexAndAppKeyIndex (the
 * two-index 3-octet packing) + AppKey (16).  build() takes the opcode
 * (MESH_CFG_OP_APPKEY_ADD or _UPDATE); parse() reports it back.
 */
struct mesh_cfg_appkey {
	uint16_t	net_idx;
	uint16_t	app_idx;
	uint8_t		key[16];
};
int	mesh_cfg_appkey_add_build(uint32_t opcode, const struct mesh_cfg_appkey *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_appkey_add_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, struct mesh_cfg_appkey *out);

/* AppKey Delete (0x8000): NetKeyIndexAndAppKeyIndex (3). */
int	mesh_cfg_appkey_delete_build(uint16_t net_idx, uint16_t app_idx,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_appkey_delete_parse(const uint8_t *in, size_t inlen,
	    uint16_t *net_idx, uint16_t *app_idx);

/* AppKey Get (0x8001): NetKeyIndex (2). */
int	mesh_cfg_appkey_get_build(uint16_t net_idx, uint8_t *out, size_t *outlen);
int	mesh_cfg_appkey_get_parse(const uint8_t *in, size_t inlen,
	    uint16_t *net_idx);

/* AppKey Status (0x8003): Status (1) + NetKeyIndexAndAppKeyIndex (3). */
int	mesh_cfg_appkey_status_build(uint8_t status, uint16_t net_idx,
	    uint16_t app_idx, uint8_t *out, size_t *outlen);
int	mesh_cfg_appkey_status_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, uint16_t *net_idx, uint16_t *app_idx);

/*
 * AppKey List (0x8002): Status (1) + NetKeyIndex (2) + a list of AppKey
 * indexes packed two-per-3-octets (a trailing odd index takes 2 octets).
 * NetKey List (0x8043): a list of NetKey indexes, same packing, no header.
 */
#define	MESH_CFG_MAX_KEY_INDEXES	32
int	mesh_cfg_appkey_list_build(uint8_t status, uint16_t net_idx,
	    const uint16_t *app_idx, size_t n, uint8_t *out, size_t *outlen);
int	mesh_cfg_appkey_list_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, uint16_t *net_idx, uint16_t *app_idx, size_t max,
	    size_t *n);

/*
 * NetKey Add (0x8040) / NetKey Update (0x8045): NetKeyIndex (2) + NetKey (16).
 */
struct mesh_cfg_netkey {
	uint16_t	net_idx;
	uint8_t		key[16];
};
int	mesh_cfg_netkey_add_build(uint32_t opcode, const struct mesh_cfg_netkey *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_netkey_add_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, struct mesh_cfg_netkey *out);

/* NetKey Delete (0x8041) / Get (0x8042). */
int	mesh_cfg_netkey_delete_build(uint16_t net_idx, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_netkey_delete_parse(const uint8_t *in, size_t inlen,
	    uint16_t *net_idx);
int	mesh_cfg_netkey_get_build(uint8_t *out, size_t *outlen);

/* NetKey Status (0x8044): Status (1) + NetKeyIndex (2). */
int	mesh_cfg_netkey_status_build(uint8_t status, uint16_t net_idx,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_netkey_status_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, uint16_t *net_idx);

/* NetKey List (0x8043): list of NetKey indexes, two-per-3-octets. */
int	mesh_cfg_netkey_list_build(const uint16_t *net_idx, size_t n,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_netkey_list_parse(const uint8_t *in, size_t inlen,
	    uint16_t *net_idx, size_t max, size_t *n);

/* ================================================================
 * Model App bind / Model publication / Model subscription.
 * ================================================================ */

/*
 * Model App Bind (0x803D) / Unbind (0x803F): ElementAddress (2) +
 * AppKeyIndex (2) + ModelIdentifier (2 or 4).  Model App Status (0x803E)
 * prepends a 1-octet Status.
 */
struct mesh_cfg_model_app {
	uint16_t			elem_addr;
	uint16_t			app_idx;
	struct mesh_cfg_model_id	model;
};
int	mesh_cfg_model_app_build(uint32_t opcode, const struct mesh_cfg_model_app *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_model_app_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, struct mesh_cfg_model_app *out);
int	mesh_cfg_model_app_status_build(uint8_t status,
	    const struct mesh_cfg_model_app *in, uint8_t *out, size_t *outlen);
int	mesh_cfg_model_app_status_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, struct mesh_cfg_model_app *out);

/*
 * Model Publication Set (0x03) / Status (0x8019).  MshMDL Section 4.4.1.2.
 * The AppKeyIndex/CredentialFlag word packs the 12-bit AppKeyIndex in bits
 * 0..11 and the CredentialFlag in bit 12 (bits 13..15 RFU), little-endian.
 * PublishPeriod is (StepResolution<<6)|NumberOfSteps; PublishRetransmit is
 * (IntervalSteps<<3)|Count.
 */
struct mesh_cfg_model_pub {
	uint16_t			elem_addr;
	uint16_t			pub_addr;
	uint16_t			app_idx;
	uint8_t				cred_flag;	/* 0 or 1 */
	uint8_t				ttl;
	uint8_t				period;		/* packed */
	uint8_t				retransmit;	/* packed */
	struct mesh_cfg_model_id	model;
};
int	mesh_cfg_model_pub_set_build(const struct mesh_cfg_model_pub *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_model_pub_set_parse(const uint8_t *in, size_t inlen,
	    struct mesh_cfg_model_pub *out);
int	mesh_cfg_model_pub_status_build(uint8_t status,
	    const struct mesh_cfg_model_pub *in, uint8_t *out, size_t *outlen);
int	mesh_cfg_model_pub_status_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, struct mesh_cfg_model_pub *out);

/* Model Publication Get (0x8018): ElementAddress (2) + ModelIdentifier. */
int	mesh_cfg_model_pub_get_build(uint16_t elem_addr,
	    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen);
int	mesh_cfg_model_pub_get_parse(const uint8_t *in, size_t inlen,
	    uint16_t *elem_addr, struct mesh_cfg_model_id *model);

/*
 * Model Subscription Add (0x801B) / Delete (0x801C) / Overwrite (0x801E):
 * ElementAddress (2) + Address (2) + ModelIdentifier.  Delete All (0x801D)
 * omits Address.  Subscription Status (0x801F) prepends a 1-octet Status.
 */
struct mesh_cfg_model_sub {
	uint16_t			elem_addr;
	uint16_t			address;
	struct mesh_cfg_model_id	model;
};
int	mesh_cfg_model_sub_build(uint32_t opcode, const struct mesh_cfg_model_sub *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_model_sub_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, struct mesh_cfg_model_sub *out);
int	mesh_cfg_model_sub_del_all_build(uint16_t elem_addr,
	    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen);
int	mesh_cfg_model_sub_del_all_parse(const uint8_t *in, size_t inlen,
	    uint16_t *elem_addr, struct mesh_cfg_model_id *model);
int	mesh_cfg_model_sub_status_build(uint8_t status,
	    const struct mesh_cfg_model_sub *in, uint8_t *out, size_t *outlen);
int	mesh_cfg_model_sub_status_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, struct mesh_cfg_model_sub *out);

/*
 * Virtual-address Model Publication Set (0x801A): ElementAddress (2) + Label
 * UUID (16) + AppKeyIndex/CredentialFlag (2) + PublishTTL (1) + PublishPeriod
 * (1) + PublishRetransmit (1) + ModelIdentifier (2 or 4).  Identical to the
 * plain Model Publication Set except the 2-octet PublishAddress is replaced
 * by the 16-octet Label UUID (MshMDL Section 4.4.1.2.7).
 */
struct mesh_cfg_model_pub_va {
	uint16_t			elem_addr;
	uint8_t				label[16];
	uint16_t			app_idx;
	uint8_t				cred_flag;
	uint8_t				ttl;
	uint8_t				period;
	uint8_t				retransmit;
	struct mesh_cfg_model_id	model;
};
int	mesh_cfg_model_pub_va_set_build(const struct mesh_cfg_model_pub_va *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_model_pub_va_set_parse(const uint8_t *in, size_t inlen,
	    struct mesh_cfg_model_pub_va *out);

/*
 * Virtual-address Model Subscription Add (0x8020) / Delete (0x8021) /
 * Overwrite (0x8022): ElementAddress (2) + Label UUID (16) + ModelIdentifier
 * (2 or 4).  MshMDL Section 4.4.1.2.9/10/11.
 */
struct mesh_cfg_model_sub_va {
	uint16_t			elem_addr;
	uint8_t				label[16];
	struct mesh_cfg_model_id	model;
};
int	mesh_cfg_model_sub_va_build(uint32_t opcode,
	    const struct mesh_cfg_model_sub_va *in, uint8_t *out, size_t *outlen);
int	mesh_cfg_model_sub_va_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, struct mesh_cfg_model_sub_va *out);

/*
 * Model Subscription Get / List (MshMDL Section 4.4.1.2.12/13).
 * SIG Get (0x8029) / Vendor Get (0x802B): ElementAddress (2) + ModelId (2/4).
 * SIG List (0x802A) / Vendor List (0x802C): Status (1) + ElementAddress (2) +
 * ModelId (2/4) + Addresses (2 octets each, group addresses).
 */
int	mesh_cfg_model_sub_get_build(uint32_t opcode, uint16_t elem_addr,
	    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen);
int	mesh_cfg_model_sub_get_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, uint16_t *elem_addr, struct mesh_cfg_model_id *model);
int	mesh_cfg_model_sub_list_build(uint32_t opcode, uint8_t status,
	    uint16_t elem_addr, const struct mesh_cfg_model_id *model,
	    const uint16_t *addrs, size_t n, uint8_t *out, size_t *outlen);
int	mesh_cfg_model_sub_list_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, uint8_t *status, uint16_t *elem_addr,
	    struct mesh_cfg_model_id *model, uint16_t *addrs, size_t max,
	    size_t *n);

/*
 * Model App (binding) Get / List (MshMDL Section 4.4.1.2.4/5).
 * SIG Get (0x804B) / Vendor Get (0x804D): ElementAddress (2) + ModelId (2/4).
 * SIG List (0x804C) / Vendor List (0x804E): Status (1) + ElementAddress (2) +
 * ModelId (2/4) + AppKeyIndexes (two-per-3-octets packing).
 */
int	mesh_cfg_model_app_get_build(uint32_t opcode, uint16_t elem_addr,
	    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen);
int	mesh_cfg_model_app_get_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, uint16_t *elem_addr, struct mesh_cfg_model_id *model);
int	mesh_cfg_model_app_list_build(uint32_t opcode, uint8_t status,
	    uint16_t elem_addr, const struct mesh_cfg_model_id *model,
	    const uint16_t *app_idx, size_t n, uint8_t *out, size_t *outlen);
int	mesh_cfg_model_app_list_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, uint8_t *status, uint16_t *elem_addr,
	    struct mesh_cfg_model_id *model, uint16_t *app_idx, size_t max,
	    size_t *n);

/*
 * Config Network Transmit Get (0x8023) / Set (0x8024) / Status (0x8025).
 * MshMDL Section 4.4.1.2.x.  The NetworkTransmit octet packs Count in bits
 * 0..2 and IntervalSteps in bits 3..7 (transmit interval = (steps+1)*10 ms).
 */
struct mesh_cfg_net_transmit {
	uint8_t		count;		/* 3-bit NetworkTransmitCount */
	uint8_t		interval_steps;	/* 5-bit NetworkTransmitIntervalSteps */
};
int	mesh_cfg_net_transmit_get_build(uint8_t *out, size_t *outlen);
int	mesh_cfg_net_transmit_set_build(uint32_t opcode,
	    const struct mesh_cfg_net_transmit *in, uint8_t *out, size_t *outlen);
int	mesh_cfg_net_transmit_set_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, struct mesh_cfg_net_transmit *out);

/*
 * Config Key Refresh Phase Get (0x8015) / Set (0x8016) / Status (0x8017).
 * MshMDL Section 4.4.1.2.x.  Get: NetKeyIndex (2).  Set: NetKeyIndex (2) +
 * Transition (1: 0x02 or 0x03).  Status: Status (1) + NetKeyIndex (2) +
 * Phase (1: 0x00/0x01/0x02).
 */
int	mesh_cfg_kr_phase_get_build(uint16_t net_idx, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_kr_phase_get_parse(const uint8_t *in, size_t inlen,
	    uint16_t *net_idx);
int	mesh_cfg_kr_phase_set_build(uint16_t net_idx, uint8_t transition,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_kr_phase_set_parse(const uint8_t *in, size_t inlen,
	    uint16_t *net_idx, uint8_t *transition);
int	mesh_cfg_kr_phase_status_build(uint8_t status, uint16_t net_idx,
	    uint8_t phase, uint8_t *out, size_t *outlen);
int	mesh_cfg_kr_phase_status_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, uint16_t *net_idx, uint8_t *phase);

/*
 * Config Node Identity Get (0x8046) / Set (0x8047) / Status (0x8048).
 * MshMDL Section 4.4.1.2.x.  Get: NetKeyIndex (2).  Set: NetKeyIndex (2) +
 * Identity (1).  Status: Status (1) + NetKeyIndex (2) + Identity (1).
 */
int	mesh_cfg_node_identity_get_build(uint16_t net_idx, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_node_identity_get_parse(const uint8_t *in, size_t inlen,
	    uint16_t *net_idx);
int	mesh_cfg_node_identity_set_build(uint16_t net_idx, uint8_t identity,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_node_identity_set_parse(const uint8_t *in, size_t inlen,
	    uint16_t *net_idx, uint8_t *identity);
int	mesh_cfg_node_identity_status_build(uint8_t status, uint16_t net_idx,
	    uint8_t identity, uint8_t *out, size_t *outlen);
int	mesh_cfg_node_identity_status_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, uint16_t *net_idx, uint8_t *identity);

/*
 * Config Low Power Node PollTimeout Get (0x802D) / Status (0x802E).
 * MshMDL Section 4.4.1.2.x.  Get: LPNAddress (2).  Status: LPNAddress (2) +
 * PollTimeout (3 octets, little-endian, units of 100 ms).
 */
int	mesh_cfg_lpn_polltimeout_get_build(uint16_t lpn_addr, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_lpn_polltimeout_get_parse(const uint8_t *in, size_t inlen,
	    uint16_t *lpn_addr);
int	mesh_cfg_lpn_polltimeout_status_build(uint16_t lpn_addr,
	    uint32_t poll_timeout, uint8_t *out, size_t *outlen);
int	mesh_cfg_lpn_polltimeout_status_parse(const uint8_t *in, size_t inlen,
	    uint16_t *lpn_addr, uint32_t *poll_timeout);

/* ================================================================
 * Node-wide state: Beacon, Default TTL, GATT Proxy, Friend, Relay,
 * Node Reset.  Each Get carries no parameters.
 * ================================================================ */

/*
 * Single-octet state Set/Status shared by Beacon (0x800A/0x800B), Default
 * TTL (0x800D/0x800E), GATT Proxy (0x8013/0x8014) and Friend (0x8010/0x8011).
 * build() takes the opcode of the Set or Status message; the value is the
 * one state octet.
 */
int	mesh_cfg_u8_state_build(uint32_t opcode, uint8_t value, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_u8_state_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
	    uint8_t *value);

/* An empty-parameter message (any Get with no parameters, Node Reset). */
int	mesh_cfg_empty_build(uint32_t opcode, uint8_t *out, size_t *outlen);

/*
 * Relay Set (0x8027) / Status (0x8028): Relay (1) + RelayRetransmit (1),
 * where RelayRetransmit = (IntervalSteps<<3)|Count.
 */
struct mesh_cfg_relay {
	uint8_t		relay;		/* 0 disabled, 1 enabled, 2 not supported */
	uint8_t		retransmit;	/* packed count/interval */
};
int	mesh_cfg_relay_set_build(uint32_t opcode, const struct mesh_cfg_relay *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_relay_set_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
	    struct mesh_cfg_relay *out);

/* Node Reset (0x8049) / Node Reset Status (0x804A): no parameters. */
int	mesh_cfg_node_reset_build(uint8_t *out, size_t *outlen);
int	mesh_cfg_node_reset_status_build(uint8_t *out, size_t *outlen);

/* ================================================================
 * Minimal Configuration Server state (MshMDL Section 4.4.1.1).
 * A small, testable state block covering the node-wide states; the key /
 * binding / publication / subscription databases are the caller's to hold
 * (their codecs are above).  No persistence, no I/O.
 * ================================================================ */
struct mesh_cfg_server_state {
	uint8_t		default_ttl;	/* 0..127 (except 1) */
	uint8_t		beacon;		/* 0 off, 1 on */
	uint8_t		gatt_proxy;	/* 0 off, 1 on, 2 unsupported */
	uint8_t		friend;		/* 0 off, 1 on, 2 unsupported */
	uint8_t		relay;		/* 0 off, 1 on, 2 unsupported */
	uint8_t		relay_retransmit;
};
void	mesh_cfg_server_init(struct mesh_cfg_server_state *s);
int	mesh_cfg_default_ttl_valid(uint8_t ttl);

#endif /* _MESH_CFG_MODEL_H_ */
