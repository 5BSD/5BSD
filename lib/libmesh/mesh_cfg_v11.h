/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Protocol 1.1 additional Configuration models (MshPRT_v1.1
 * Sections 4.2-4.4).  These are the foundation models added in Mesh 1.1 that a
 * Configuration Client uses to control the new node states:
 *
 *   - SAR Configuration Server (Section 4.4.x): the segmentation-and-
 *     reassembly Transmitter (MshPRT Section 4.2.29) and Receiver (MshPRT
 *     Section 4.2.30) state - Get / Set / Status;
 *   - On-Demand Private Proxy Server: Get / Set / Status of the On-Demand
 *     Private GATT Proxy state;
 *   - Solicitation PDU RPL Configuration Server: Solicitation PDU RPL Items
 *     Clear (+ unacknowledged) / Status over an address range;
 *   - Opcodes Aggregator Server: the Aggregator Sequence / Aggregator Status
 *     container that batches several model messages into one message;
 *   - Large Composition Data Server: Large Composition Data Get / Status and
 *     Models Metadata Get / Status (offset-addressed page reads);
 *   - Private Beacon Server: Private Beacon, Private GATT Proxy and Private
 *     Node Identity - Get / Set / Status.
 *
 * As with mesh_cfg_model.[ch], each _build() emits the full Access PDU (opcode
 * plus parameters, via mesh_access_pdu_build()) and each _parse() consumes it.
 * Opcodes are the 2-octet 0x80xx values assigned for MshPRT Section 4.3
 * message summary; every multi-octet field is little-endian.  Pure and
 * hardware-free: no I/O, no globals.  Every function returns 0 on success and
 * -1 on failure, with outputs zeroed on failure.
 */

#ifndef _MESH_CFG_V11_H_
#define _MESH_CFG_V11_H_

#include <stddef.h>
#include <stdint.h>

/* ----------------------------------------------------------------
 * Opcodes (Bluetooth Assigned Numbers; MshPRT_v1.1 §4.3 messages).
 * ---------------------------------------------------------------- */
#define	MESH_CFG_OP_PRIV_BEACON_GET		0x8060
#define	MESH_CFG_OP_PRIV_BEACON_SET		0x8061
#define	MESH_CFG_OP_PRIV_BEACON_STATUS		0x8062
#define	MESH_CFG_OP_PRIV_GATT_PROXY_GET		0x8063
#define	MESH_CFG_OP_PRIV_GATT_PROXY_SET		0x8064
#define	MESH_CFG_OP_PRIV_GATT_PROXY_STATUS	0x8065
#define	MESH_CFG_OP_PRIV_NODE_IDENTITY_GET	0x8066
#define	MESH_CFG_OP_PRIV_NODE_IDENTITY_SET	0x8067
#define	MESH_CFG_OP_PRIV_NODE_IDENTITY_STATUS	0x8068
#define	MESH_CFG_OP_OD_PRIV_PROXY_GET		0x8069
#define	MESH_CFG_OP_OD_PRIV_PROXY_SET		0x806A
#define	MESH_CFG_OP_OD_PRIV_PROXY_STATUS	0x806B
#define	MESH_CFG_OP_SAR_TRANSMITTER_GET		0x806C
#define	MESH_CFG_OP_SAR_TRANSMITTER_SET		0x806D
#define	MESH_CFG_OP_SAR_TRANSMITTER_STATUS	0x806E
#define	MESH_CFG_OP_SAR_RECEIVER_GET		0x806F
#define	MESH_CFG_OP_SAR_RECEIVER_SET		0x8070
#define	MESH_CFG_OP_SAR_RECEIVER_STATUS		0x8071
#define	MESH_CFG_OP_AGGREGATOR_SEQUENCE		0x8072
#define	MESH_CFG_OP_AGGREGATOR_STATUS		0x8073
#define	MESH_CFG_OP_LARGE_COMP_DATA_GET		0x8074
#define	MESH_CFG_OP_LARGE_COMP_DATA_STATUS	0x8075
#define	MESH_CFG_OP_MODELS_METADATA_GET		0x8076
#define	MESH_CFG_OP_MODELS_METADATA_STATUS	0x8077
#define	MESH_CFG_OP_SOL_PDU_RPL_ITEMS_CLEAR		0x8078
#define	MESH_CFG_OP_SOL_PDU_RPL_ITEMS_CLEAR_UNACK	0x8079
#define	MESH_CFG_OP_SOL_PDU_RPL_ITEMS_STATUS		0x807A

/* Private Node Identity / Private GATT Proxy values (MshPRT §§4.2.44-.47). */
#define	MESH_CFG_PRIV_IDENTITY_STOPPED		0x00
#define	MESH_CFG_PRIV_IDENTITY_RUNNING		0x01
#define	MESH_CFG_PRIV_IDENTITY_NOT_SUPPORTED	0x02

/* ================================================================
 * SAR Transmitter (MshPRT_v1.1 Section 4.2.29).  Seven 4-bit subfields
 * packed into four octets (the top nibble of octet 3 is RFU):
 *   o0 = SegIntStep | (UnicastRetransCount << 4)
 *   o1 = UnicastRetransWithoutProgressCount | (UnicastRetransIntStep << 4)
 *   o2 = UnicastRetransIntInc | (MulticastRetransCount << 4)
 *   o3 = MulticastRetransIntStep
 * ================================================================ */
struct mesh_cfg_sar_transmitter {
	uint8_t	seg_interval_step;			/* 4 bits */
	uint8_t	unicast_retrans_count;			/* 4 bits */
	uint8_t	unicast_retrans_without_progress_count;	/* 4 bits */
	uint8_t	unicast_retrans_interval_step;		/* 4 bits */
	uint8_t	unicast_retrans_interval_increment;	/* 4 bits */
	uint8_t	multicast_retrans_count;		/* 4 bits */
	uint8_t	multicast_retrans_interval_step;	/* 4 bits */
};

/* SAR Transmitter Get (0x806C): no parameters. */
int	mesh_cfg_sar_tx_get_build(uint8_t *out, size_t *outlen);
/* SAR Transmitter Set (0x806D) / Status (0x806E): 4 packed octets. */
int	mesh_cfg_sar_tx_build(uint32_t opcode,
	    const struct mesh_cfg_sar_transmitter *in, uint8_t *out, size_t *outlen);
int	mesh_cfg_sar_tx_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
	    struct mesh_cfg_sar_transmitter *out);

/* ================================================================
 * SAR Receiver (MshPRT_v1.1 Section 4.2.30).  Three octets:
 *   o0 = SegmentsThreshold(5) | (AckDelayIncrement(3) << 5)
 *   o1 = DiscardTimeout(4) | (RxSegmentIntervalStep(4) << 4)
 *   o2 = AckRetransmissionsCount(2)  (bits 2..7 RFU)
 * ================================================================ */
struct mesh_cfg_sar_receiver {
	uint8_t	segments_threshold;		/* 5 bits */
	uint8_t	ack_delay_increment;		/* 3 bits */
	uint8_t	discard_timeout;		/* 4 bits */
	uint8_t	rx_segment_interval_step;	/* 4 bits */
	uint8_t	ack_retrans_count;		/* 2 bits */
};

/* SAR Receiver Get (0x806F): no parameters. */
int	mesh_cfg_sar_rx_get_build(uint8_t *out, size_t *outlen);
/* SAR Receiver Set (0x8070) / Status (0x8071): 3 packed octets. */
int	mesh_cfg_sar_rx_build(uint32_t opcode,
	    const struct mesh_cfg_sar_receiver *in, uint8_t *out, size_t *outlen);
int	mesh_cfg_sar_rx_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
	    struct mesh_cfg_sar_receiver *out);

/* ================================================================
 * On-Demand Private Proxy Server.  Get (0x8069) empty; Set (0x806A) /
 * Status (0x806B) a single On-Demand Private GATT Proxy octet.
 * ================================================================ */
int	mesh_cfg_od_priv_proxy_get_build(uint8_t *out, size_t *outlen);
int	mesh_cfg_od_priv_proxy_build(uint32_t opcode, uint8_t value, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_od_priv_proxy_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, uint8_t *value);

/* ================================================================
 * Solicitation PDU RPL Configuration Server.  Solicitation PDU RPL Items
 * Clear (0x8078) / Clear Unacknowledged (0x8079) / Status (0x807A) carry an
 * Address Range: a 15-bit Range Start with a Length-Present bit in bit 15 of
 * the little-endian word, followed by a 1-octet Range Length only when the
 * range spans more than one address (MshPRT §3.4.2.2.1 address range).
 * ================================================================ */
struct mesh_cfg_addr_range {
	uint16_t	range_start;
	uint8_t		range_length;	/* number of addresses, >= 1 */
};
int	mesh_cfg_sol_pdu_rpl_clear_build(uint32_t opcode,
	    const struct mesh_cfg_addr_range *in, uint8_t *out, size_t *outlen);
int	mesh_cfg_sol_pdu_rpl_clear_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, struct mesh_cfg_addr_range *out);
int	mesh_cfg_sol_pdu_rpl_status_build(const struct mesh_cfg_addr_range *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_sol_pdu_rpl_status_parse(const uint8_t *in, size_t inlen,
	    struct mesh_cfg_addr_range *out);

/* ================================================================
 * Opcodes Aggregator Server (MshPRT §4.3.9).  Aggregator Sequence
 * (0x8072): Element Address (2, LE) followed by a list of items.  Aggregator
 * Status (0x8073): Status (1) + Element Address (2, LE) + a list of items.
 * Each item is a length-prefixed aggregated Access PDU: a 1-octet length when
 * length <= 0x7F (Length_Format bit 0 = 0, length in bits 1..7) or a 2-octet
 * little-endian length otherwise (Length_Format bit 0 = 1, length in bits
 * 1..15), then that many octets of opcode+parameters (length 0 = empty item).
 * ================================================================ */
#define	MESH_CFG_AGG_MAX_ITEMS	16

/* One aggregated item.  For build, data/len are the caller's; for parse the
 * views point into the input buffer. */
struct mesh_cfg_agg_item {
	const uint8_t	*data;
	size_t		len;
};
int	mesh_cfg_agg_seq_build(uint16_t elem_addr,
	    const struct mesh_cfg_agg_item *items, size_t n, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_agg_seq_parse(const uint8_t *in, size_t inlen, uint16_t *elem_addr,
	    struct mesh_cfg_agg_item *items, size_t max, size_t *n);
int	mesh_cfg_agg_status_build(uint8_t status, uint16_t elem_addr,
	    const struct mesh_cfg_agg_item *items, size_t n, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_agg_status_parse(const uint8_t *in, size_t inlen, uint8_t *status,
	    uint16_t *elem_addr, struct mesh_cfg_agg_item *items, size_t max,
	    size_t *n);

/*
 * Encode / decode a single aggregator item length prefix (helper exposed for
 * the Server's item-by-item processing).  _len_encode writes 1 or 2 octets;
 * _len_decode reads them and reports the prefix size.
 */
int	mesh_cfg_agg_len_encode(size_t len, uint8_t *out, size_t *outlen);
int	mesh_cfg_agg_len_decode(const uint8_t *in, size_t inlen, size_t *len,
	    size_t *prefix);

/* ================================================================
 * Large Composition Data Server.  Large Composition Data Get (0x8074) /
 * Models Metadata Get (0x8076): Page (1) + Offset (2, LE).  The matching
 * Status messages (0x8075 / 0x8077): Page (1) + Offset (2, LE) + Total Size
 * (2, LE) + Data (the slice at Offset).
 * ================================================================ */
#define	MESH_CFG_LCD_DATA_MAX	376

struct mesh_cfg_lcd_get {
	uint8_t		page;
	uint16_t	offset;
};
struct mesh_cfg_lcd_status {
	uint8_t		page;
	uint16_t	offset;
	uint16_t	total_size;
	uint8_t		data[MESH_CFG_LCD_DATA_MAX];
	size_t		data_len;
};
int	mesh_cfg_lcd_get_build(uint32_t opcode, const struct mesh_cfg_lcd_get *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_lcd_get_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
	    struct mesh_cfg_lcd_get *out);
int	mesh_cfg_lcd_status_build(uint32_t opcode,
	    const struct mesh_cfg_lcd_status *in, uint8_t *out, size_t *outlen);
int	mesh_cfg_lcd_status_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
	    struct mesh_cfg_lcd_status *out);

/* ================================================================
 * Private Beacon Server.  Private Beacon Get (0x8060) empty; Set (0x8061) a
 * Private Beacon octet plus an optional Random Update Interval Steps octet;
 * Status (0x8062) both octets.  Private GATT Proxy Get/Set/Status
 * (0x8063/0x8064/0x8065) a single octet.  Private Node Identity Get (0x8066)
 * NetKeyIndex (2); Set (0x8067) NetKeyIndex (2) + Private Identity (1);
 * Status (0x8068) Status (1) + NetKeyIndex (2) + Private Identity (1).
 * ================================================================ */
struct mesh_cfg_priv_beacon {
	uint8_t	private_beacon;			/* 0 off, 1 on */
	uint8_t	random_update_interval_steps;
	int	has_random_update;		/* Set: second octet present */
};
int	mesh_cfg_priv_beacon_get_build(uint8_t *out, size_t *outlen);
int	mesh_cfg_priv_beacon_set_build(const struct mesh_cfg_priv_beacon *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_priv_beacon_set_parse(const uint8_t *in, size_t inlen,
	    struct mesh_cfg_priv_beacon *out);
int	mesh_cfg_priv_beacon_status_build(const struct mesh_cfg_priv_beacon *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_priv_beacon_status_parse(const uint8_t *in, size_t inlen,
	    struct mesh_cfg_priv_beacon *out);

int	mesh_cfg_priv_gatt_proxy_get_build(uint8_t *out, size_t *outlen);
int	mesh_cfg_priv_gatt_proxy_build(uint32_t opcode, uint8_t value, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_priv_gatt_proxy_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, uint8_t *value);

struct mesh_cfg_priv_node_identity {
	uint16_t	net_idx;
	uint8_t		identity;		/* MESH_CFG_PRIV_IDENTITY_* */
};
int	mesh_cfg_priv_node_identity_get_build(uint16_t net_idx, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_priv_node_identity_get_parse(const uint8_t *in, size_t inlen,
	    uint16_t *net_idx);
int	mesh_cfg_priv_node_identity_set_build(
	    const struct mesh_cfg_priv_node_identity *in, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_priv_node_identity_set_parse(const uint8_t *in, size_t inlen,
	    struct mesh_cfg_priv_node_identity *out);
int	mesh_cfg_priv_node_identity_status_build(uint8_t status,
	    const struct mesh_cfg_priv_node_identity *in, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_priv_node_identity_status_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, struct mesh_cfg_priv_node_identity *out);

#endif /* _MESH_CFG_V11_H_ */
