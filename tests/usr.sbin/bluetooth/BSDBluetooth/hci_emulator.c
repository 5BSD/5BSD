/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * hci_emulator.c - the "brain" of a userspace HCI controller emulator.
 *
 * ORACLE DISCIPLINE: every command handler's return parameters and every
 * emitted event's byte layout is hand-encoded from the Bluetooth Core
 * Spec Vol 4 Part E (HCI) -- NOT from the daemon and NOT from emulator
 * convenience.  Struct layouts are taken from
 * sys/netgraph/bluetooth/include/ng_hci.h so the emitted bytes are
 * byte-compatible with the in-tree stack.  Each handler cites its spec
 * section.
 *
 * Increment 1 scope: controller init/config command set + LE
 * advertising/scan/resolving-list state + asynchronous event injection +
 * a fault-injection hook.  No kernel, no netgraph, no daemon globals.
 */

#include <sys/types.h>
#include <sys/endian.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include <stdlib.h>
#include <string.h>

#include "hci_emulator.h"

/*
 * The controller replies "1" in Num_HCI_Command_Packets for every
 * Command Complete / Command Status: it is always ready to accept one
 * more command (Vol 4 Part E §7.7.14 / §7.7.15).
 */
#define	EMU_NUM_CMD_PKTS	1

/* Common status codes, Vol 4 Part E §1.3 (Error Code table). */
#define	EMU_STATUS_SUCCESS		0x00
#define	EMU_STATUS_UNKNOWN_CMD		0x01	/* Unknown HCI Command */
#define	EMU_STATUS_INVALID_PARAMS	0x12	/* Invalid HCI Cmd Params */

/* Additional status / reason codes, Vol 4 Part E §1.3 (Error Code table). */
#define	EMU_STATUS_UNKNOWN_CONN_ID	0x02	/* Unknown Connection Identifier */
#define	EMU_STATUS_PIN_OR_KEY_MISSING	0x06	/* PIN or Key Missing */
#define	EMU_STATUS_COMMAND_DISALLOWED	0x0c	/* Command Disallowed */
#define	EMU_REASON_REMOTE_USER_TERM	0x13	/* Remote User Terminated Conn */
#define	EMU_REASON_LOCAL_HOST_TERM	0x16	/* Conn Terminated By Local Host */
#define	EMU_REASON_CONN_TIMEOUT		0x08	/* Connection Timeout (Vol 6 B §4.5.2) */

#define	EMU_RESOLV_MAX		8	/* resolving-list table depth */
#define	EMU_FORCE_MAX		8	/* fault-injection table depth */
#define	EMU_CONN_MAX		4	/* connection table depth */
#define	EMU_LINK_MAX		4	/* simulated-air neighbor depth */
#define	EMU_TIMER_MAX		8	/* deterministic timer-queue depth */
#define	EMU_ISO_MAX		8	/* CIS + BIS stream table depth */

/* Nanoseconds per unit of the LE Supervision_Timeout field (10 ms, §7.8.12). */
#define	EMU_SUP_TIMEOUT_UNIT_NS	(10ULL * 1000000ULL)

/* First dynamically-allocated ACL connection handle (12-bit, §5.4.2). */
#define	EMU_FIRST_HANDLE	0x0040

/*
 * First dynamically-allocated ISO (CIS/BIS) connection handle.  ISO streams
 * share the 12-bit handle space with ACL (§5.4.5); a disjoint base keeps the
 * two ranges from colliding in the emulator's tables.
 */
#define	EMU_FIRST_ISO_HANDLE	0x0e00

/* LE feature bits, Core Vol 6 Part B §4.6. */
#define	EMU_LE_FEAT_ENCRYPTION		(UINT64_C(1) << 0)
#define	EMU_LE_FEAT_CONN_PARAM_REQ	(UINT64_C(1) << 1)
#define	EMU_LE_FEAT_DATA_LENGTH_EXT	(UINT64_C(1) << 5)
#define	EMU_LE_FEAT_LL_PRIVACY		(UINT64_C(1) << 6)
#define	EMU_LE_FEAT_2M_PHY		(UINT64_C(1) << 8)
#define	EMU_LE_FEAT_CODED_PHY		(UINT64_C(1) << 11)
#define	EMU_LE_FEAT_EXT_ADVERTISING	(UINT64_C(1) << 12)
#define	EMU_LE_FEAT_PERIODIC_ADV	(UINT64_C(1) << 13)
#define	EMU_LE_FEAT_PAST_SENDER		(UINT64_C(1) << 24)
#define	EMU_LE_FEAT_PAST_RECIPIENT	(UINT64_C(1) << 25)
#define	EMU_LE_FEAT_CIS_CENTRAL		(UINT64_C(1) << 28)
#define	EMU_LE_FEAT_CIS_PERIPH		(UINT64_C(1) << 29)
#define	EMU_LE_FEAT_ISO_BROADCASTER	(UINT64_C(1) << 30)
#define	EMU_LE_FEAT_SYNC_RECEIVER	(UINT64_C(1) << 31)
#define	EMU_LE_FEAT_POWER_CONTROL	(UINT64_C(1) << 33)
#define	EMU_LE_FEAT_PATH_LOSS_MONITORING (UINT64_C(1) << 35)

#define	EMU_LE_FEAT_BASE \
	(EMU_LE_FEAT_ENCRYPTION | EMU_LE_FEAT_CONN_PARAM_REQ | \
	 EMU_LE_FEAT_DATA_LENGTH_EXT | EMU_LE_FEAT_LL_PRIVACY | \
	 EMU_LE_FEAT_2M_PHY)
#define	EMU_LE_FEAT_EXT_ADV_PROFILE \
	(EMU_LE_FEAT_BASE | EMU_LE_FEAT_EXT_ADVERTISING | \
	 EMU_LE_FEAT_CODED_PHY)
#define	EMU_LE_FEAT_PERIODIC_PROFILE \
	(EMU_LE_FEAT_EXT_ADV_PROFILE | EMU_LE_FEAT_PERIODIC_ADV | \
	 EMU_LE_FEAT_PAST_SENDER | EMU_LE_FEAT_PAST_RECIPIENT)
#define	EMU_LE_FEAT_ISO_PROFILE \
	(EMU_LE_FEAT_PERIODIC_PROFILE | EMU_LE_FEAT_CIS_CENTRAL | \
	 EMU_LE_FEAT_CIS_PERIPH | EMU_LE_FEAT_ISO_BROADCASTER | \
	 EMU_LE_FEAT_SYNC_RECEIVER)
#define	EMU_LE_FEAT_POWER_PROFILE \
	(EMU_LE_FEAT_BASE | EMU_LE_FEAT_POWER_CONTROL | \
	 EMU_LE_FEAT_PATH_LOSS_MONITORING)
#define	EMU_LE_FEAT_FULL_PROFILE \
	(EMU_LE_FEAT_ISO_PROFILE | EMU_LE_FEAT_POWER_CONTROL | \
	 EMU_LE_FEAT_PATH_LOSS_MONITORING)

struct emu_resolv_entry {
	uint8_t	peer_addr_type;
	uint8_t	peer_addr[6];
	uint8_t	peer_irk[16];
	uint8_t	local_irk[16];
};

struct emu_force_entry {
	uint16_t	opcode;
	uint8_t		status;
	int		active;
};

/*
 * One entry in the deterministic timer queue (Increment 3).  When the
 * virtual clock reaches deadline_ns the timer fires fn(e, handle).  There
 * is no wall-clock involvement whatsoever: only hci_emu_advance() moves
 * time forward.
 */
struct emu_timer {
	int		active;
	uint64_t	deadline_ns;
	void	       (*fn)(struct hci_emu *e, uint16_t handle);
	uint16_t	handle;
};

/*
 * One established ACL connection.  handle is this controller's local
 * connection handle; peer/peer_handle identify the same link on the
 * partner controller (so ACL data can be delivered with the con_handle
 * rewritten to the value the peer knows it by).
 */
struct emu_conn {
	int		active;
	uint16_t	handle;		/* local connection handle */
	uint16_t	peer_handle;	/* handle on the partner controller */
	struct hci_emu	*peer;		/* partner controller for this link */
	uint8_t		role;		/* 0x00 central, 0x01 peripheral */
	uint8_t		peer_addr_type;	/* remote device address type */
	uint8_t		peer_addr[6];	/* remote device address */

	/* --- Increment 3: supervision timeout / encryption / power --- */
	uint64_t	sup_timeout_ns;	/* supervision timeout duration (0=off) */
	uint8_t		encrypted;	/* 1 once encryption is enabled */

	int8_t		tx_power_level;	/* modeled local tx power (dBm) */
	uint8_t		path_loss;	/* modeled current path loss (dB) */

	/* LE_Set_Path_Loss_Reporting_Parameters state (§7.8.119). */
	uint8_t		pl_high_threshold;
	uint8_t		pl_high_hysteresis;
	uint8_t		pl_low_threshold;
	uint8_t		pl_low_hysteresis;
	uint16_t	pl_min_time_spent;
	uint8_t		pl_report_enable;

	/* LE_Set_Transmit_Power_Reporting_Enable state (§7.8.121). */
	uint8_t		txp_local_enable;
	uint8_t		txp_remote_enable;
};

/*
 * One Connected (CIS) or Broadcast (BIS) Isochronous Stream.  handle is this
 * controller's local ISO connection handle; peer/peer_handle identify the same
 * stream on the partner controller so an ISO SDU can be delivered with the
 * connection handle rewritten to the value the peer knows it by (Vol 4 Part E
 * §5.4.5).  A stream forwards host ISO data only once its input data path has
 * been set up (LE Setup ISO Data Path, §7.8.109).
 */
struct emu_iso {
	int		active;
	uint16_t	handle;		/* local ISO connection handle */
	uint16_t	acl_handle;	/* associated ACL conn (CIS only) */
	uint8_t		group_id;	/* CIG_ID (CIS) or BIG_Handle (BIS) */
	uint8_t		is_broadcast;	/* 0 = CIS, 1 = BIS */
	uint8_t		established;	/* CIS/BIG (Sync) Established emitted */
	uint8_t		path_in_open;	/* Host->Controller data path (dir 0x00) */
	uint8_t		path_out_open;	/* Controller->Host data path (dir 0x01) */
	struct hci_emu	*peer;		/* partner controller for this stream */
	uint16_t	peer_handle;	/* stream handle on the partner */
};

struct hci_emu {
	hci_emu_out_fn	out;
	void		*out_ctx;

	/* --- controller identity / capabilities --- */
	uint8_t		bd_addr[6];
	uint8_t		hci_version;
	uint16_t	hci_revision;
	uint8_t		lmp_version;
	uint16_t	manufacturer;
	uint16_t	lmp_subversion;
	uint8_t		lmp_features[8];
	uint8_t		le_features[8];
	uint8_t		supported_commands[64];

	uint16_t	acl_size;
	uint8_t		sco_size;
	uint16_t	num_acl;
	uint16_t	num_sco;

	uint16_t	le_acl_len;
	uint8_t		le_acl_num;
	uint16_t	iso_len;
	uint8_t		iso_num;

	uint8_t		num_adv_sets;

	/* --- host-configured masks --- */
	uint8_t		event_mask[8];
	uint8_t		le_event_mask[8];

	/* --- LE advertising / scan state --- */
	uint8_t		random_addr[6];

	uint16_t	adv_interval_min;
	uint16_t	adv_interval_max;
	uint8_t		adv_type;
	uint8_t		adv_own_addr_type;
	uint8_t		adv_channel_map;
	uint8_t		adv_filter_policy;

	uint8_t		adv_data_len;
	uint8_t		adv_data[31];
	uint8_t		scanrsp_data_len;
	uint8_t		scanrsp_data[31];
	uint8_t		adv_enable;

	/* LE periodic advertising (one deterministic set, handle 0). */
	uint16_t	periodic_interval_min;
	uint16_t	periodic_interval_max;
	uint16_t	periodic_properties;
	uint8_t		periodic_data_len;
	uint8_t		periodic_data[NG_HCI_LE_PERIODIC_ADV_DATA_MAX];
	uint8_t		periodic_enable;

	uint8_t		scan_type;
	uint16_t	scan_interval;
	uint16_t	scan_window;
	uint8_t		scan_own_addr_type;
	uint8_t		scan_filter_policy;
	uint8_t		scan_enable;
	uint8_t		scan_filter_dups;

	/* --- resolving list / privacy state --- */
	uint8_t			addr_resolution_enable;
	int			resolv_count;
	struct emu_resolv_entry	resolv[EMU_RESOLV_MAX];

	/* --- fault injection --- */
	struct emu_force_entry	force[EMU_FORCE_MAX];

	/* --- Increment 2: linking + connections + ACL --- */
	struct hci_emu		*links[EMU_LINK_MAX];
	size_t			n_links;
	uint16_t		next_handle;	/* handle allocator */
	struct emu_conn		conns[EMU_CONN_MAX];

	/* Pending LE_Create_Connection state (initiator side). */
	int			connecting;
	uint8_t			conn_peer_addr_type;
	uint8_t			conn_peer_addr[6];
	uint8_t			conn_own_addr_type;

	/* --- Increment 3: virtual clock + timer queue --- */
	uint64_t		clock_ns;	/* virtual "now" (nanoseconds) */
	struct emu_timer	timers[EMU_TIMER_MAX];

	/* --- Increment 3: encryption --- */
	uint8_t			enc_outcome;	/* success-path Encryption_Change status */

	/* --- Increment 4: ISO / CIS / BIG stream table --- */
	struct emu_iso		iso[EMU_ISO_MAX];
	uint16_t		next_iso_handle;	/* ISO handle allocator */
};

/* ------------------------------------------------------------------ */
/* Opcodes (OGF/OCF -> 16-bit opcode via ng_hci.h NG_HCI_OPCODE()).    */
/* ------------------------------------------------------------------ */
#define	OP_RESET \
	NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND, NG_HCI_OCF_RESET)
#define	OP_SET_EVENT_MASK \
	NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND, NG_HCI_OCF_SET_EVENT_MASK)
#define	OP_WRITE_LE_HOST_SUPPORTED \
	NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND, NG_HCI_OCF_WRITE_LE_HOST_SUPPORTED)
#define	OP_READ_LOCAL_VER \
	NG_HCI_OPCODE(NG_HCI_OGF_INFO, NG_HCI_OCF_READ_LOCAL_VER)
#define	OP_READ_LOCAL_COMMANDS \
	NG_HCI_OPCODE(NG_HCI_OGF_INFO, NG_HCI_OCF_READ_LOCAL_COMMANDS)
#define	OP_READ_LOCAL_FEATURES \
	NG_HCI_OPCODE(NG_HCI_OGF_INFO, NG_HCI_OCF_READ_LOCAL_FEATURES)
#define	OP_READ_BUFFER_SIZE \
	NG_HCI_OPCODE(NG_HCI_OGF_INFO, NG_HCI_OCF_READ_BUFFER_SIZE)
#define	OP_READ_BDADDR \
	NG_HCI_OPCODE(NG_HCI_OGF_INFO, NG_HCI_OCF_READ_BDADDR)

#define	OP_LE_SET_EVENT_MASK \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_EVENT_MASK)
#define	OP_LE_READ_BUFFER_SIZE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_READ_BUFFER_SIZE)
#define	OP_LE_READ_BUFFER_SIZE_V2 \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_READ_BUFFER_SIZE_V2)
#define	OP_LE_READ_LOCAL_FEATURES \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_READ_LOCAL_SUPPORTED_FEATURES)
#define	OP_LE_READ_NUM_ADV_SETS \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_READ_NUM_SUPPORTED_ADV_SETS)
#define	OP_LE_SET_RANDOM_ADDRESS \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_RANDOM_ADDRESS)
#define	OP_LE_SET_ADV_PARAMS \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_ADVERTISING_PARAMETERS)
#define	OP_LE_SET_ADV_DATA \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_ADVERTISING_DATA)
#define	OP_LE_SET_SCAN_RSP_DATA \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_SCAN_RESPONSE_DATA)
#define	OP_LE_SET_ADV_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_ADVERTISE_ENABLE)
#define	OP_LE_SET_SCAN_PARAMS \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_SCAN_PARAMETERS)
#define	OP_LE_SET_SCAN_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_SCAN_ENABLE)
#define	OP_LE_ADD_RESOLV \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_ADD_DEV_RESOLVING_LIST)
#define	OP_LE_REMOVE_RESOLV \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_REMOVE_DEV_RESOLVING_LIST)
#define	OP_LE_CLEAR_RESOLV \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_CLEAR_RESOLVING_LIST)
#define	OP_LE_SET_ADDR_RESOLUTION_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_ADDR_RESOLUTION_ENABLE)
#define	OP_LE_SET_PERIODIC_ADV_PARAMS \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_PERIODIC_ADV_PARAMS)
#define	OP_LE_SET_PERIODIC_ADV_DATA \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_PERIODIC_ADV_DATA)
#define	OP_LE_SET_PERIODIC_ADV_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_PERIODIC_ADV_ENABLE)
#define	OP_LE_SET_PERIODIC_ADV_RCV_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_PERIODIC_ADV_RCV_ENABLE)
#define	OP_LE_PERIODIC_ADV_SYNC_TRANSFER \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_PERIODIC_ADV_SYNC_TRANSFER)

#define	OP_DISCONNECT \
	NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL, NG_HCI_OCF_DISCON)
#define	OP_LE_CREATE_CONNECTION \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_CREATE_CONNECTION)
#define	OP_LE_CREATE_CONNECTION_CANCEL \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_CREATE_CONNECTION_CANCEL)

/* Increment 3: LE encryption / LTK (§7.8.24-.26). */
#define	OP_LE_ENABLE_ENCRYPTION \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_START_ENCRYPTION)
#define	OP_LE_LTK_REQ_REPLY \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_LONG_TERM_KEY_REQUEST_REPLY)
#define	OP_LE_LTK_REQ_NEG_REPLY \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, \
	    NG_HCI_OCF_LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY)

/* Increment 3: LE Power Control (§7.8.117-.121). */
#define	OP_LE_READ_REMOTE_TX_POWER \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_READ_REMOTE_TX_POWER_LEVEL)
#define	OP_LE_SET_PATH_LOSS_PARAMS \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_PATH_LOSS_REPORTING_PARAMS)
#define	OP_LE_SET_PATH_LOSS_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_PATH_LOSS_REPORTING_ENABLE)
#define	OP_LE_SET_TX_POWER_REPORTING_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_TX_POWER_REPORTING_ENABLE)

/* Increment 4: LE Isochronous Channels (§7.8.97-.109, §7.7.65.25-.30). */
#define	OP_LE_SET_CIG_PARAMS \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_CIG_PARAMS)
#define	OP_LE_CREATE_CIS \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_CREATE_CIS)
#define	OP_LE_REMOVE_CIG \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_REMOVE_CIG)
#define	OP_LE_SETUP_ISO_DATA_PATH \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SETUP_ISO_DATA_PATH)
#define	OP_LE_CREATE_BIG \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_CREATE_BIG)
#define	OP_LE_BIG_CREATE_SYNC \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_BIG_CREATE_SYNC)

/* ================================================================== */
/* Emit helpers                                                        */
/* ================================================================== */

static void
emu_emit(struct hci_emu *e, const uint8_t *pkt, size_t len)
{

	if (e->out != NULL)
		e->out(e->out_ctx, pkt, len);
}

/*
 * Command Complete (event 0x0E), Vol 4 Part E §7.7.14.
 * Typed layout: 0x04 | 0x0E | param_len | num_cmd_pkts(1) | opcode(2,LE) |
 *               return_params (status first).
 */
static void
emu_cmd_complete(struct hci_emu *e, uint16_t opcode, const void *rp,
    uint8_t rplen)
{
	uint8_t buf[3 + sizeof(ng_hci_command_compl_ep) + 255];
	uint16_t op;

	buf[0] = NG_HCI_EVENT_PKT;		/* 0x04 */
	buf[1] = NG_HCI_EVENT_COMMAND_COMPL;	/* 0x0E */
	buf[2] = (uint8_t)(3 + rplen);		/* num_cmd_pkts + opcode + rp */
	buf[3] = EMU_NUM_CMD_PKTS;
	op = htole16(opcode);
	memcpy(&buf[4], &op, 2);
	if (rplen != 0)
		memcpy(&buf[6], rp, rplen);
	emu_emit(e, buf, (size_t)6 + rplen);
}

/* Command Complete carrying only a status byte. */
static void
emu_cmd_status_rp(struct hci_emu *e, uint16_t opcode, uint8_t status)
{

	emu_cmd_complete(e, opcode, &status, 1);
}

/*
 * Command Status (event 0x0F), Vol 4 Part E §7.7.15.
 * Typed layout: 0x04 | 0x0F | 4 | status(1) | num_cmd_pkts(1) | opcode(2,LE)
 */
static void
emu_command_status(struct hci_emu *e, uint16_t opcode, uint8_t status)
{
	uint8_t buf[3 + sizeof(ng_hci_command_status_ep)];
	uint16_t op;

	buf[0] = NG_HCI_EVENT_PKT;		/* 0x04 */
	buf[1] = NG_HCI_EVENT_COMMAND_STATUS;	/* 0x0F */
	buf[2] = (uint8_t)sizeof(ng_hci_command_status_ep); /* 4 */
	buf[3] = status;
	buf[4] = EMU_NUM_CMD_PKTS;
	op = htole16(opcode);
	memcpy(&buf[5], &op, 2);
	emu_emit(e, buf, sizeof(buf));
}

/*
 * Emit an arbitrary typed event: 0x04 | evt_code | plen | params.
 */
static void
emu_event(struct hci_emu *e, uint8_t evt_code, const uint8_t *params,
    uint8_t plen)
{
	uint8_t buf[3 + 255];

	buf[0] = NG_HCI_EVENT_PKT;	/* 0x04 */
	buf[1] = evt_code;
	buf[2] = plen;
	if (plen != 0)
		memcpy(&buf[3], params, plen);
	emu_emit(e, buf, (size_t)3 + plen);
}

/* Forward decl: emit an LE Advertising Report on scanner for advertiser. */
static void	emu_send_adv_report(struct hci_emu *scanner,
		    struct hci_emu *advertiser);
static int	hci_emu_set_feature_profile(struct hci_emu *e, uint64_t feats);
static void	emu_timer_cancel(struct hci_emu *,
		    void (*)(struct hci_emu *, uint16_t), uint16_t);
static void	emu_supervision_fire(struct hci_emu *, uint16_t);

/* ================================================================== */
/* Lifecycle / config                                                  */
/* ================================================================== */

struct hci_emu *
hci_emu_new(void)
{
	struct hci_emu *e;

	e = calloc(1, sizeof(*e));
	if (e == NULL)
		return (NULL);

	/*
	 * Sane spec-legal defaults so an unconfigured emulator still
	 * answers every init command with success.
	 */
	e->bd_addr[0] = 0x11;
	e->bd_addr[1] = 0x22;
	e->bd_addr[2] = 0x33;
	e->bd_addr[3] = 0x44;
	e->bd_addr[4] = 0x55;
	e->bd_addr[5] = 0x66;

	e->hci_version = 0x0c;		/* Bluetooth 5.3 */
	e->hci_revision = 0x0000;
	e->lmp_version = 0x0c;
	e->manufacturer = 0x000f;	/* Broadcom, arbitrary but legal */
	e->lmp_subversion = 0x0000;

	e->acl_size = 1021;
	e->sco_size = 96;
	e->num_acl = 8;
	e->num_sco = 0;

	e->le_acl_len = 251;
	e->le_acl_num = 8;
	e->iso_len = 0;
	e->iso_num = 0;

	e->num_adv_sets = 1;

	e->next_handle = EMU_FIRST_HANDLE;
	e->next_iso_handle = EMU_FIRST_ISO_HANDLE;
	(void)hci_emu_set_feature_profile(e, EMU_LE_FEAT_FULL_PROFILE);

	return (e);
}

void
hci_emu_free(struct hci_emu *e)
{
	size_t i, j;
	struct hci_emu *peer;

	if (e == NULL)
		return;
	for (i = 0; i < e->n_links; i++) {
		peer = e->links[i];
		if (peer == NULL)
			continue;
		for (j = 0; j < EMU_CONN_MAX; j++)
			if (peer->conns[j].active && peer->conns[j].peer == e) {
				emu_timer_cancel(peer, emu_supervision_fire,
				    peer->conns[j].handle);
				memset(&peer->conns[j], 0,
				    sizeof(peer->conns[j]));
			}
		for (j = 0; j < EMU_ISO_MAX; j++)
			if (peer->iso[j].active && peer->iso[j].peer == e)
				memset(&peer->iso[j], 0, sizeof(peer->iso[j]));
		for (j = 0; j < peer->n_links; j++) {
			if (peer->links[j] != e)
				continue;
			memmove(&peer->links[j], &peer->links[j + 1],
			    (peer->n_links - j - 1) * sizeof(peer->links[0]));
			peer->n_links--;
			peer->links[peer->n_links] = NULL;
			break;
		}
	}

	free(e);
}

void
hci_emu_set_output(struct hci_emu *e, hci_emu_out_fn fn, void *ctx)
{

	e->out = fn;
	e->out_ctx = ctx;
}

void
hci_emu_set_bd_addr(struct hci_emu *e, const uint8_t bd_addr[6])
{

	memcpy(e->bd_addr, bd_addr, 6);
}

void
hci_emu_set_local_version(struct hci_emu *e, uint8_t hci_version,
    uint16_t hci_revision, uint8_t lmp_version, uint16_t manufacturer,
    uint16_t lmp_subversion)
{

	e->hci_version = hci_version;
	e->hci_revision = hci_revision;
	e->lmp_version = lmp_version;
	e->manufacturer = manufacturer;
	e->lmp_subversion = lmp_subversion;
}

void
hci_emu_set_buffer_size(struct hci_emu *e, uint16_t acl_size, uint8_t sco_size,
    uint16_t num_acl, uint16_t num_sco)
{

	e->acl_size = acl_size;
	e->sco_size = sco_size;
	e->num_acl = num_acl;
	e->num_sco = num_sco;
}

void
hci_emu_set_le_buffer_size(struct hci_emu *e, uint16_t le_acl_len,
    uint8_t le_acl_num, uint16_t iso_len, uint8_t iso_num)
{

	e->le_acl_len = le_acl_len;
	e->le_acl_num = le_acl_num;
	e->iso_len = iso_len;
	e->iso_num = iso_num;
}

void
hci_emu_set_lmp_features(struct hci_emu *e, const uint8_t feats[8])
{

	memcpy(e->lmp_features, feats, 8);
}

void
hci_emu_set_le_features(struct hci_emu *e, const uint8_t feats[8])
{

	memcpy(e->le_features, feats, 8);
}

void
hci_emu_set_supported_commands(struct hci_emu *e, const uint8_t cmds[64])
{

	memcpy(e->supported_commands, cmds, 64);
}

void
hci_emu_set_num_adv_sets(struct hci_emu *e, uint8_t n)
{

	e->num_adv_sets = n;
}

static int
hci_emu_set_feature_profile(struct hci_emu *e, uint64_t feats)
{

	le64enc(e->le_features, feats);
	memset(e->supported_commands, 0xff, sizeof(e->supported_commands));
	e->num_adv_sets =
	    (feats & EMU_LE_FEAT_EXT_ADVERTISING) != 0 ? 4 : 1;
	if ((feats & (EMU_LE_FEAT_CIS_CENTRAL | EMU_LE_FEAT_CIS_PERIPH |
	    EMU_LE_FEAT_ISO_BROADCASTER | EMU_LE_FEAT_SYNC_RECEIVER)) != 0) {
		e->iso_len = 512;
		e->iso_num = 8;
	} else {
		e->iso_len = 0;
		e->iso_num = 0;
	}
	return (0);
}

int
hci_emu_apply_profile(struct hci_emu *e, enum hci_emu_profile profile)
{

	switch (profile) {
	case HCI_EMU_PROFILE_LEGACY:
		return (hci_emu_set_feature_profile(e, EMU_LE_FEAT_BASE));
	case HCI_EMU_PROFILE_EXT_ADV:
		return (hci_emu_set_feature_profile(e,
		    EMU_LE_FEAT_EXT_ADV_PROFILE));
	case HCI_EMU_PROFILE_PERIODIC:
		return (hci_emu_set_feature_profile(e,
		    EMU_LE_FEAT_PERIODIC_PROFILE));
	case HCI_EMU_PROFILE_ISO:
		return (hci_emu_set_feature_profile(e,
		    EMU_LE_FEAT_ISO_PROFILE));
	case HCI_EMU_PROFILE_POWER_CONTROL:
		return (hci_emu_set_feature_profile(e,
		    EMU_LE_FEAT_POWER_PROFILE));
	case HCI_EMU_PROFILE_FULL:
		return (hci_emu_set_feature_profile(e,
		    EMU_LE_FEAT_FULL_PROFILE));
	default:
		return (-1);
	}
}

/* ================================================================== */
/* Getters                                                             */
/* ================================================================== */

int
hci_emu_get_adv_enable(const struct hci_emu *e)
{

	return (e->adv_enable);
}

int
hci_emu_get_scan_enable(const struct hci_emu *e)
{

	return (e->scan_enable);
}

int
hci_emu_get_periodic_adv_enable(const struct hci_emu *e)
{

	return (e->periodic_enable);
}

int
hci_emu_get_addr_resolution_enable(const struct hci_emu *e)
{

	return (e->addr_resolution_enable);
}

void
hci_emu_get_random_addr(const struct hci_emu *e, uint8_t out[6])
{

	memcpy(out, e->random_addr, 6);
}

int
hci_emu_get_resolving_list_count(const struct hci_emu *e)
{

	return (e->resolv_count);
}

uint64_t
hci_emu_get_event_mask(const struct hci_emu *e)
{

	return (le64dec(e->event_mask));
}

uint64_t
hci_emu_get_le_event_mask(const struct hci_emu *e)
{

	return (le64dec(e->le_event_mask));
}

int
hci_emu_get_conn_count(const struct hci_emu *e)
{
	int i, n;

	n = 0;
	for (i = 0; i < EMU_CONN_MAX; i++)
		if (e->conns[i].active)
			n++;
	return (n);
}

int
hci_emu_get_conn_handle(const struct hci_emu *e, int idx, uint16_t *handle_out)
{
	int i, n;

	n = 0;
	for (i = 0; i < EMU_CONN_MAX; i++) {
		if (!e->conns[i].active)
			continue;
		if (n == idx) {
			if (handle_out != NULL)
				*handle_out = e->conns[i].handle;
			return (1);
		}
		n++;
	}
	return (0);
}

int
hci_emu_get_iso_count(const struct hci_emu *e)
{
	int i, n;

	n = 0;
	for (i = 0; i < EMU_ISO_MAX; i++)
		if (e->iso[i].active)
			n++;
	return (n);
}

int
hci_emu_get_iso_handle(const struct hci_emu *e, int idx, uint16_t *handle_out)
{
	int i, n;

	n = 0;
	for (i = 0; i < EMU_ISO_MAX; i++) {
		if (!e->iso[i].active)
			continue;
		if (n == idx) {
			if (handle_out != NULL)
				*handle_out = e->iso[i].handle;
			return (1);
		}
		n++;
	}
	return (0);
}

int
hci_emu_get_iso_path_open(const struct hci_emu *e, uint16_t handle)
{
	int i, flags;

	for (i = 0; i < EMU_ISO_MAX; i++) {
		if (!e->iso[i].active || e->iso[i].handle != handle)
			continue;
		flags = 0;
		if (e->iso[i].path_in_open)
			flags |= 0x01;
		if (e->iso[i].path_out_open)
			flags |= 0x02;
		return (flags);
	}
	return (-1);
}

/* ================================================================== */
/* Command handlers                                                    */
/*                                                                     */
/* Each handler cites its Core Spec Vol 4 Part E section.  "p"/"plen"  */
/* are the command parameters (after the 3-byte typed cmd header).     */
/* ================================================================== */

/* Reset (§7.3.2): status only. Clears volatile controller state. */
static void
h_reset(struct hci_emu *e, uint16_t op)
{

	e->adv_enable = 0;
	e->scan_enable = 0;
	e->addr_resolution_enable = 0;
	e->resolv_count = 0;
	memset(e->event_mask, 0, sizeof(e->event_mask));
	memset(e->le_event_mask, 0, sizeof(e->le_event_mask));
	/* Volatile link state: drop connections, keep the physical link. */
	memset(e->conns, 0, sizeof(e->conns));
	memset(e->iso, 0, sizeof(e->iso));
	e->connecting = 0;
	e->next_handle = EMU_FIRST_HANDLE;
	e->next_iso_handle = EMU_FIRST_ISO_HANDLE;
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

/* Read_BD_ADDR (§7.4.6): status + BD_ADDR(6). */
static void
h_read_bdaddr(struct hci_emu *e, uint16_t op)
{
	ng_hci_read_bdaddr_rp rp;

	rp.status = EMU_STATUS_SUCCESS;
	memcpy(rp.bdaddr.b, e->bd_addr, 6);
	emu_cmd_complete(e, op, &rp, sizeof(rp));
}

/* Read_Local_Version_Information (§7.4.1). */
static void
h_read_local_ver(struct hci_emu *e, uint16_t op)
{
	ng_hci_read_local_ver_rp rp;

	rp.status = EMU_STATUS_SUCCESS;
	rp.hci_version = e->hci_version;
	rp.hci_revision = htole16(e->hci_revision);
	rp.lmp_version = e->lmp_version;
	rp.manufacturer = htole16(e->manufacturer);
	rp.lmp_subversion = htole16(e->lmp_subversion);
	emu_cmd_complete(e, op, &rp, sizeof(rp));
}

/* Read_Buffer_Size (§7.4.5). */
static void
h_read_buffer_size(struct hci_emu *e, uint16_t op)
{
	ng_hci_read_buffer_size_rp rp;

	rp.status = EMU_STATUS_SUCCESS;
	rp.max_acl_size = htole16(e->acl_size);
	rp.max_sco_size = e->sco_size;
	rp.num_acl_pkt = htole16(e->num_acl);
	rp.num_sco_pkt = htole16(e->num_sco);
	emu_cmd_complete(e, op, &rp, sizeof(rp));
}

/* Read_Local_Supported_Commands (§7.4.2): status + 64-byte bitmask. */
static void
h_read_local_commands(struct hci_emu *e, uint16_t op)
{
	ng_hci_read_local_commands_rp rp;

	rp.status = EMU_STATUS_SUCCESS;
	memcpy(rp.features, e->supported_commands, 64);
	emu_cmd_complete(e, op, &rp, sizeof(rp));
}

/* Read_Local_Supported_Features (§7.4.3): status + 8-byte LMP features. */
static void
h_read_local_features(struct hci_emu *e, uint16_t op)
{
	ng_hci_read_local_features_rp rp;

	rp.status = EMU_STATUS_SUCCESS;
	memcpy(rp.features, e->lmp_features, 8);
	emu_cmd_complete(e, op, &rp, sizeof(rp));
}

/* Write_LE_Host_Supported (§7.3.79): status only. */
static void
h_write_le_host_supported(struct hci_emu *e, uint16_t op,
    const uint8_t *p, uint8_t plen)
{

	(void)e;
	(void)p;
	if (plen < sizeof(ng_hci_write_le_host_supported_cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

/* Set_Event_Mask (§7.3.1): status only; store the 8-byte mask. */
static void
h_set_event_mask(struct hci_emu *e, uint16_t op, const uint8_t *p, uint8_t plen)
{

	if (plen < sizeof(ng_hci_set_event_mask_cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	memcpy(e->event_mask, p, 8);
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

/* LE_Set_Event_Mask (§7.8.1): status only; store the 8-byte LE mask. */
static void
h_le_set_event_mask(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{

	if (plen < sizeof(ng_hci_le_set_event_mask_cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	memcpy(e->le_event_mask, p, 8);
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

/* LE_Read_Buffer_Size v1 (§7.8.2): status + le_len(2) + le_num(1). */
static void
h_le_read_buffer_size(struct hci_emu *e, uint16_t op)
{
	ng_hci_le_read_buffer_size_rp rp;

	rp.status = EMU_STATUS_SUCCESS;
	rp.hc_le_data_packet_length = htole16(e->le_acl_len);
	rp.hc_total_num_le_data_packets = e->le_acl_num;
	emu_cmd_complete(e, op, &rp, sizeof(rp));
}

/* LE_Read_Buffer_Size v2 (§7.8.2): + iso_len(2) + iso_num(1). */
static void
h_le_read_buffer_size_v2(struct hci_emu *e, uint16_t op)
{
	ng_hci_le_read_buffer_size_rp_v2 rp;

	rp.status = EMU_STATUS_SUCCESS;
	rp.hc_le_data_packet_length = htole16(e->le_acl_len);
	rp.hc_total_num_le_data_packets = e->le_acl_num;
	rp.hc_iso_data_packet_length = htole16(e->iso_len);
	rp.hc_total_num_iso_data_packets = e->iso_num;
	emu_cmd_complete(e, op, &rp, sizeof(rp));
}

/*
 * LE_Read_Local_Supported_Features (§7.8.3): status + LE_Features(8).
 * Hand-encoded (ng_hci uses a u_int64_t; we emit the 8 stored bytes
 * directly so the wire order matches the host's little-endian layout).
 */
static void
h_le_read_local_features(struct hci_emu *e, uint16_t op)
{
	uint8_t rp[1 + 8];

	rp[0] = EMU_STATUS_SUCCESS;
	memcpy(&rp[1], e->le_features, 8);
	emu_cmd_complete(e, op, rp, sizeof(rp));
}

/* LE_Read_Number_of_Supported_Advertising_Sets (§7.8.58). */
static void
h_le_read_num_adv_sets(struct hci_emu *e, uint16_t op)
{
	ng_hci_le_read_num_supported_adv_sets_rp rp;

	rp.status = EMU_STATUS_SUCCESS;
	rp.num_supported_adv_sets = e->num_adv_sets;
	emu_cmd_complete(e, op, &rp, sizeof(rp));
}

/* LE_Set_Random_Address (§7.8.4): status only; store 6-byte address. */
static void
h_le_set_random_address(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{

	if (plen < 6) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	memcpy(e->random_addr, p, 6);
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

/* LE_Set_Advertising_Parameters (§7.8.5): status only. */
static void
h_le_set_adv_params(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	const ng_hci_le_set_advertising_parameters_cp *cp;

	if (plen < sizeof(*cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cp = (const void *)p;
	e->adv_interval_min = le16toh(cp->advertising_interval_min);
	e->adv_interval_max = le16toh(cp->advertising_interval_max);
	e->adv_type = cp->advertising_type;
	e->adv_own_addr_type = cp->own_address_type;
	e->adv_channel_map = cp->advertising_channel_map;
	e->adv_filter_policy = cp->advertising_filter_policy;
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

/* LE_Set_Advertising_Data (§7.8.7): status only; store len + data. */
static void
h_le_set_adv_data(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	uint8_t dlen;

	if (plen < 1) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	dlen = p[0];
	if (dlen > 31 || (uint8_t)(plen - 1) < dlen) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	e->adv_data_len = dlen;
	memcpy(e->adv_data, &p[1], dlen);
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

/* LE_Set_Scan_Response_Data (§7.8.8): status only; store len + data. */
static void
h_le_set_scanrsp_data(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	uint8_t dlen;

	if (plen < 1) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	dlen = p[0];
	if (dlen > 31 || (uint8_t)(plen - 1) < dlen) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	e->scanrsp_data_len = dlen;
	memcpy(e->scanrsp_data, &p[1], dlen);
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

/* LE_Set_Advertising_Enable (§7.8.9): status only; flip adv_enable. */
static void
h_le_set_adv_enable(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	size_t i;

	if (plen < 1) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	e->adv_enable = (p[0] != 0);
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);

	/*
	 * Over the simulated air (Increment 2): if we just started
	 * advertising and the linked peer is scanning, it observes us with
	 * one LE Advertising Report (§7.7.65.2).
	 */
	if (e->adv_enable)
		for (i = 0; i < e->n_links; i++)
			if (e->links[i]->scan_enable)
				emu_send_adv_report(e->links[i], e);
}

/* LE_Set_Scan_Parameters (§7.8.10): status only. */
static void
h_le_set_scan_params(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	const ng_hci_le_set_scan_parameters_cp *cp;

	if (plen < sizeof(*cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cp = (const void *)p;
	e->scan_type = cp->le_scan_type;
	e->scan_interval = le16toh(cp->le_scan_interval);
	e->scan_window = le16toh(cp->le_scan_window);
	e->scan_own_addr_type = cp->own_address_type;
	e->scan_filter_policy = cp->scanning_filter_policy;
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

/* LE periodic advertising controls (Core 5.0, Vol 4 E §7.8.61-.63). */
static void
h_le_set_periodic_adv_params(struct hci_emu *e, uint16_t op,
    const uint8_t *p, uint8_t plen)
{
	const ng_hci_le_set_periodic_adv_params_cp *cp;

	if (plen != sizeof(*cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cp = (const void *)p;
	if (cp->advertising_handle != 0) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	e->periodic_interval_min = le16toh(cp->periodic_adv_interval_min);
	e->periodic_interval_max = le16toh(cp->periodic_adv_interval_max);
	e->periodic_properties = le16toh(cp->periodic_adv_properties);
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

static void
h_le_set_periodic_adv_data(struct hci_emu *e, uint16_t op,
    const uint8_t *p, uint8_t plen)
{
	uint8_t len;

	if (plen < 3 || p[0] != 0 || p[1] != 0x03) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	len = p[2];
	if (len > NG_HCI_LE_PERIODIC_ADV_DATA_MAX || (size_t)plen != 3 + len) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	e->periodic_data_len = len;
	memcpy(e->periodic_data, p + 3, len);
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

static void
h_le_set_periodic_adv_enable(struct hci_emu *e, uint16_t op,
    const uint8_t *p, uint8_t plen)
{

	if (plen != 2 || p[1] != 0 || p[0] > 1) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	e->periodic_enable = p[0];
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

/* PAST receive/transfer (Core 5.1, Vol 4 E §7.8.88-.89).  These commands
 * have no asynchronous completion; validate their wire form and acknowledge
 * them so integration tests can exercise a 5.1 controller boundary. */
static void
h_le_set_periodic_adv_rcv_enable(struct hci_emu *e, uint16_t op,
    const uint8_t *p, uint8_t plen)
{
	const ng_hci_le_set_periodic_adv_rcv_enable_cp *cp;

	if (plen != sizeof(*cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cp = (const void *)p;
	if (le16toh(cp->sync_handle) > 0x0eff || (cp->enable & ~0x03) != 0) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

static void
h_le_periodic_adv_sync_transfer(struct hci_emu *e, uint16_t op,
    const uint8_t *p, uint8_t plen)
{
	const ng_hci_le_periodic_adv_sync_transfer_cp *cp;

	if (plen != sizeof(*cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cp = (const void *)p;
	if (le16toh(cp->sync_handle) > 0x0eff) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

/* LE_Set_Scan_Enable (§7.8.11): status only; flip scan_enable. */
static void
h_le_set_scan_enable(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	size_t i;

	if (plen < sizeof(ng_hci_le_set_scan_enable_cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	e->scan_enable = (p[0] != 0);
	e->scan_filter_dups = p[1];
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);

	/*
	 * Over the simulated air (Increment 2): if we just started scanning
	 * and the linked peer is advertising, we observe it with one LE
	 * Advertising Report (§7.7.65.2).
	 */
	if (e->scan_enable)
		for (i = 0; i < e->n_links; i++)
			if (e->links[i]->adv_enable)
				emu_send_adv_report(e, e->links[i]);
}

/* LE_Add_Device_To_Resolving_List (§7.8.38): status only. */
static void
h_le_add_resolv(struct hci_emu *e, uint16_t op, const uint8_t *p, uint8_t plen)
{
	const ng_hci_le_add_dev_resolving_list_cp *cp;
	struct emu_resolv_entry *ent;

	if (plen < sizeof(*cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	if (e->resolv_count >= EMU_RESOLV_MAX) {
		/* Memory Capacity Exceeded (0x07). */
		emu_cmd_status_rp(e, op, 0x07);
		return;
	}
	cp = (const void *)p;
	ent = &e->resolv[e->resolv_count++];
	ent->peer_addr_type = cp->peer_identity_addr_type;
	memcpy(ent->peer_addr, cp->peer_identity_addr.b, 6);
	memcpy(ent->peer_irk, cp->peer_irk, 16);
	memcpy(ent->local_irk, cp->local_irk, 16);
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

/* LE_Remove_Device_From_Resolving_List (§7.8.39): status only. */
static void
h_le_remove_resolv(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	const ng_hci_le_remove_dev_resolving_list_cp *cp;
	int i;

	if (plen < sizeof(*cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cp = (const void *)p;
	for (i = 0; i < e->resolv_count; i++) {
		if (e->resolv[i].peer_addr_type == cp->peer_identity_addr_type &&
		    memcmp(e->resolv[i].peer_addr, cp->peer_identity_addr.b,
		    6) == 0) {
			/* Shift the tail down over the removed entry. */
			memmove(&e->resolv[i], &e->resolv[i + 1],
			    (size_t)(e->resolv_count - i - 1) *
			    sizeof(e->resolv[0]));
			e->resolv_count--;
			emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
			return;
		}
	}
	/* Unknown Connection Identifier (0x02) per §7.8.39. */
	emu_cmd_status_rp(e, op, 0x02);
}

/* LE_Clear_Resolving_List (§7.8.40): status only. */
static void
h_le_clear_resolv(struct hci_emu *e, uint16_t op)
{

	e->resolv_count = 0;
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

/* LE_Set_Address_Resolution_Enable (§7.8.44): status only. */
static void
h_le_set_addr_resolution_enable(struct hci_emu *e, uint16_t op,
    const uint8_t *p, uint8_t plen)
{

	if (plen < 1) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	e->addr_resolution_enable = (p[0] != 0);
	emu_cmd_status_rp(e, op, EMU_STATUS_SUCCESS);
}

/* ================================================================== */
/* Fault injection                                                     */
/* ================================================================== */

void
hci_emu_force_status(struct hci_emu *e, uint16_t opcode, uint8_t status)
{
	int i, freeslot;

	/* opcode 0x0000 is reserved (NOP) and means "clear all". */
	if (opcode == 0x0000) {
		hci_emu_clear_forced_status(e);
		return;
	}

	freeslot = -1;
	for (i = 0; i < EMU_FORCE_MAX; i++) {
		if (e->force[i].active && e->force[i].opcode == opcode) {
			e->force[i].status = status;
			return;
		}
		if (!e->force[i].active && freeslot < 0)
			freeslot = i;
	}
	if (freeslot >= 0) {
		e->force[freeslot].opcode = opcode;
		e->force[freeslot].status = status;
		e->force[freeslot].active = 1;
	}
}

void
hci_emu_clear_forced_status(struct hci_emu *e)
{

	memset(e->force, 0, sizeof(e->force));
}

/*
 * Return 1 and store the forced status if opcode is overridden.
 */
static int
emu_forced(struct hci_emu *e, uint16_t opcode, uint8_t *status_out)
{
	int i;

	for (i = 0; i < EMU_FORCE_MAX; i++) {
		if (e->force[i].active && e->force[i].opcode == opcode) {
			*status_out = e->force[i].status;
			return (1);
		}
	}
	return (0);
}

/* ================================================================== */
/* Increment 2: controller links, connections, ACL data path           */
/* ================================================================== */

void
hci_emu_link(struct hci_emu *a, struct hci_emu *b)
{
	size_t i;

	if (a == NULL || b == NULL || a == b)
		return;
	for (i = 0; i < a->n_links; i++)
		if (a->links[i] == b)
			return;
	if (a->n_links == EMU_LINK_MAX || b->n_links == EMU_LINK_MAX)
		return;
	a->links[a->n_links++] = b;
	b->links[b->n_links++] = a;
}

/* Allocate the next 12-bit connection handle (§5.4.2 handle range). */
static uint16_t
emu_next_handle(struct hci_emu *e)
{
	uint16_t h;

	h = e->next_handle;
	e->next_handle++;
	if (e->next_handle == 0 || e->next_handle > 0x0eff)
		e->next_handle = EMU_FIRST_HANDLE;
	return (h);
}

static struct emu_conn *
emu_conn_alloc(struct hci_emu *e)
{
	int i;

	for (i = 0; i < EMU_CONN_MAX; i++)
		if (!e->conns[i].active)
			return (&e->conns[i]);
	return (NULL);
}

static struct emu_conn *
emu_conn_by_handle(struct hci_emu *e, uint16_t handle)
{
	int i;

	for (i = 0; i < EMU_CONN_MAX; i++)
		if (e->conns[i].active && e->conns[i].handle == handle)
			return (&e->conns[i]);
	return (NULL);
}

/* ================================================================== */
/* Increment 3: virtual clock + deterministic timer queue              */
/* ================================================================== */

/*
 * Arm a timer to fire fn(e, handle) once the virtual clock has advanced
 * by delay_ns from "now".  Any existing timer with the same fn+handle is
 * replaced first (so re-arming on traffic is idempotent).  If the queue
 * is full the request is silently dropped.
 */
static void
emu_timer_cancel(struct hci_emu *e, void (*fn)(struct hci_emu *, uint16_t),
    uint16_t handle)
{
	int i;

	for (i = 0; i < EMU_TIMER_MAX; i++)
		if (e->timers[i].active && e->timers[i].fn == fn &&
		    e->timers[i].handle == handle)
			e->timers[i].active = 0;
}

static void
emu_timer_arm(struct hci_emu *e, uint64_t delay_ns,
    void (*fn)(struct hci_emu *, uint16_t), uint16_t handle)
{
	int i;

	emu_timer_cancel(e, fn, handle);
	for (i = 0; i < EMU_TIMER_MAX; i++) {
		if (!e->timers[i].active) {
			e->timers[i].active = 1;
			e->timers[i].deadline_ns = e->clock_ns + delay_ns;
			e->timers[i].fn = fn;
			e->timers[i].handle = handle;
			return;
		}
	}
}

/*
 * Supervision timeout expiry (Vol 6 Part B §4.5.2): the link supervision
 * timer elapsed with no traffic.  Tear the connection down on both sides
 * with a Disconnection Complete carrying reason Connection Timeout (0x08).
 */
static void
emu_supervision_fire(struct hci_emu *e, uint16_t handle)
{
	struct hci_emu *peer;
	struct emu_conn *c, *pc;
	uint16_t phandle;

	c = emu_conn_by_handle(e, handle);
	if (c == NULL)
		return;			/* already gone: nothing to do */
	peer = c->peer;
	phandle = c->peer_handle;
	pc = (peer != NULL) ? emu_conn_by_handle(peer, phandle) : NULL;

	hci_emu_inject_disconnection_complete(e, handle, EMU_REASON_CONN_TIMEOUT);
	if (peer != NULL) {
		emu_timer_cancel(peer, emu_supervision_fire, phandle);
		hci_emu_inject_disconnection_complete(peer, phandle,
		    EMU_REASON_CONN_TIMEOUT);
	}

	memset(c, 0, sizeof(*c));
	if (pc != NULL)
		memset(pc, 0, sizeof(*pc));
}

/* (Re)arm the supervision timer for a connection from its stored duration. */
static void
emu_arm_supervision(struct hci_emu *e, struct emu_conn *c)
{

	if (c->sup_timeout_ns == 0)
		return;
	emu_timer_arm(e, c->sup_timeout_ns, emu_supervision_fire, c->handle);
}

void
hci_emu_set_clock(struct hci_emu *e, uint64_t ns)
{

	e->clock_ns = ns;
}

uint64_t
hci_emu_get_clock(const struct hci_emu *e)
{

	return (e->clock_ns);
}

/*
 * Advance the virtual clock by dt nanoseconds, firing every timer whose
 * deadline falls within the interval -- strictly in deadline order, and
 * with the clock set to each timer's deadline as it fires (so a handler
 * that re-arms schedules relative to the correct "now").  Deterministic;
 * no wall-clock is consulted.
 */
void
hci_emu_advance(struct hci_emu *e, uint64_t ns)
{
	uint64_t target;
	int i, best;

	target = e->clock_ns + ns;
	for (;;) {
		best = -1;
		for (i = 0; i < EMU_TIMER_MAX; i++) {
			if (!e->timers[i].active)
				continue;
			if (e->timers[i].deadline_ns > target)
				continue;
			if (best < 0 || e->timers[i].deadline_ns <
			    e->timers[best].deadline_ns)
				best = i;
		}
		if (best < 0)
			break;
		e->clock_ns = e->timers[best].deadline_ns;
		e->timers[best].active = 0;	/* deactivate before firing */
		e->timers[best].fn(e, e->timers[best].handle);
	}
	e->clock_ns = target;
}

/*
 * The device address a controller uses on air for a given Own_Address_Type:
 * 0x00 public -> BD_ADDR; anything else -> the configured random address.
 * (Vol 6 Part B §1.3; Vol 4 Part E §7.8.5/§7.8.12 Own_Address_Type.)
 */
static void
emu_own_addr(const struct hci_emu *e, uint8_t own_type, uint8_t out[6])
{

	if (own_type == 0x00)
		memcpy(out, e->bd_addr, 6);
	else
		memcpy(out, e->random_addr, 6);
}

/*
 * Map an Advertising_Type from LE_Set_Advertising_Parameters (§7.8.5) to the
 * Event_Type reported in an LE Advertising Report (§7.7.65.2).  The two
 * enumerations are NOT identical: Advertising_Type 0x04 (ADV_DIRECT_IND, low
 * duty cycle) must be reported with Event_Type 0x01 (ADV_DIRECT_IND) -- report
 * Event_Type 0x04 is reserved for SCAN_RSP.  Types 0x00-0x03 coincide in both
 * tables and pass through unchanged.
 */
static uint8_t
emu_adv_report_event_type(uint8_t adv_type)
{

	if (adv_type == 0x04)
		return (0x01);
	return (adv_type);
}

/*
 * Emit one LE Advertising Report (§7.7.65.2) on the scanner, built from the
 * advertiser's on-air address and advertising data.  Event_Type is derived
 * from the advertiser's Advertising_Type via emu_adv_report_event_type() (the
 * two enumerations differ for 0x04).  RSSI is a fixed simulated value (there is
 * no real radio); -70 dBm (0xBA) is used.
 */
static void
emu_send_adv_report(struct hci_emu *scanner, struct hci_emu *advertiser)
{
	uint8_t addr[6];

	emu_own_addr(advertiser, advertiser->adv_own_addr_type, addr);
	hci_emu_inject_le_adv_report(scanner,
	    emu_adv_report_event_type(advertiser->adv_type),
	    advertiser->adv_own_addr_type, addr, advertiser->adv_data,
	    advertiser->adv_data_len, (int8_t)-70);
}

/*
 * Is this controller currently advertising in a connectable mode?
 * Connectable advertising PDU types are ADV_IND (0x00), high-duty-cycle
 * ADV_DIRECT_IND (0x01) and low-duty-cycle ADV_DIRECT_IND (0x04).
 * (Vol 4 Part E §7.8.5, Advertising_Type table.)
 */
static int
emu_adv_connectable(const struct hci_emu *e)
{

	if (!e->adv_enable)
		return (0);
	return (e->adv_type == 0x00 || e->adv_type == 0x01 ||
	    e->adv_type == 0x04);
}

/*
 * LE_Create_Connection (§7.8.12).  Returns Command Status (§7.7.15), NOT
 * Command Complete.  If a connectable advertiser matching Peer_Address is
 * reachable over the link, both controllers register the connection and each
 * emits an LE Connection Complete (§7.7.65.1): the initiator as Central
 * (Role 0x00), the advertiser as Peripheral (Role 0x01).  Otherwise the
 * connection stays pending (our model: no event until Cancel or a host
 * timeout) -- see h_le_create_connection_cancel.
 */
static void
h_le_create_connection(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	const ng_hci_le_create_connection_cp *cp;
	struct hci_emu *peer;
	struct emu_conn *ic, *pc;
	uint8_t adv_addr[6], init_addr[6];
	uint16_t interval, latency, sto, ih, ph;
	size_t i;

	if (plen < sizeof(*cp)) {
		emu_command_status(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cp = (const void *)p;

	/* Command Status accepted; the result arrives as a later event. */
	emu_command_status(e, op, EMU_STATUS_SUCCESS);

	/* Record the pending target (so a later Cancel can report it). */
	e->connecting = 1;
	e->conn_peer_addr_type = cp->peer_addr_type;
	memcpy(e->conn_peer_addr, cp->peer_addr.b, 6);
	e->conn_own_addr_type = cp->own_address_type;

	peer = NULL;
	for (i = 0; i < e->n_links; i++) {
		if (!emu_adv_connectable(e->links[i]))
			continue;
		emu_own_addr(e->links[i], e->links[i]->adv_own_addr_type,
		    adv_addr);
		if (memcmp(adv_addr, cp->peer_addr.b, 6) == 0) {
			peer = e->links[i];
			break;
		}
	}
	if (peer == NULL)
		return;				/* no matching advertiser: pending */

	ic = emu_conn_alloc(e);
	pc = emu_conn_alloc(peer);
	if (ic == NULL || pc == NULL)
		return;				/* out of table slots: pending */

	ih = emu_next_handle(e);
	ph = emu_next_handle(peer);
	emu_own_addr(e, cp->own_address_type, init_addr);

	interval = le16toh(cp->conn_interval_max);
	latency = le16toh(cp->conn_latency);
	sto = le16toh(cp->supervision_timeout);

	/* Register on the initiator (Central). */
	ic->active = 1;
	ic->handle = ih;
	ic->peer = peer;
	ic->peer_handle = ph;
	ic->role = 0x00;
	ic->peer_addr_type = peer->adv_own_addr_type;
	memcpy(ic->peer_addr, adv_addr, 6);
	ic->sup_timeout_ns = (uint64_t)sto * EMU_SUP_TIMEOUT_UNIT_NS;

	/* Register on the advertiser (Peripheral). */
	pc->active = 1;
	pc->handle = ph;
	pc->peer = e;
	pc->peer_handle = ih;
	pc->role = 0x01;
	pc->peer_addr_type = cp->own_address_type;
	memcpy(pc->peer_addr, init_addr, 6);
	pc->sup_timeout_ns = (uint64_t)sto * EMU_SUP_TIMEOUT_UNIT_NS;

	e->connecting = 0;
	peer->adv_enable = 0;	/* advertising ends on connection (§7.8.9) */

	/* Arm the link supervision timer on both sides (§4.5.2). */
	emu_arm_supervision(e, ic);
	emu_arm_supervision(peer, pc);

	/* LE Connection Complete on both sides (§7.7.65.1). */
	hci_emu_inject_le_connection_complete(e, EMU_STATUS_SUCCESS, ih,
	    0x00, peer->adv_own_addr_type, adv_addr, interval, latency, sto,
	    0x00);
	hci_emu_inject_le_connection_complete(peer, EMU_STATUS_SUCCESS, ph,
	    0x01, cp->own_address_type, init_addr, interval, latency, sto,
	    0x00);
}

/*
 * LE_Create_Connection_Cancel (§7.8.13).  Returns Command Complete.  If a
 * connection creation was outstanding, the controller additionally emits an
 * LE Connection Complete with status Unknown Connection Identifier (0x02);
 * otherwise the command completes with Command Disallowed (0x0C).
 */
static void
h_le_create_connection_cancel(struct hci_emu *e, uint16_t op)
{
	ng_hci_le_create_connection_cancel_rp rp;

	if (!e->connecting) {
		rp.status = EMU_STATUS_COMMAND_DISALLOWED;
		emu_cmd_complete(e, op, &rp, sizeof(rp));
		return;
	}
	e->connecting = 0;
	rp.status = EMU_STATUS_SUCCESS;
	emu_cmd_complete(e, op, &rp, sizeof(rp));
	hci_emu_inject_le_connection_complete(e, EMU_STATUS_UNKNOWN_CONN_ID,
	    0x0000, 0x00, e->conn_peer_addr_type, e->conn_peer_addr,
	    0, 0, 0, 0x00);
}

/*
 * Disconnect (§7.1.6).  Returns Command Status, then a Disconnection
 * Complete (§7.7.5) on each side of the link.  Per §7.1.6 the initiator's
 * event carries reason Connection Terminated By Local Host (0x16), while the
 * remote's event carries the Reason the initiator supplied.
 */
static void
h_disconnect(struct hci_emu *e, uint16_t op, const uint8_t *p, uint8_t plen)
{
	const ng_hci_discon_cp *cp;
	struct hci_emu *peer;
	struct emu_conn *c, *pc;
	uint16_t handle, phandle;
	uint8_t reason;

	if (plen < sizeof(*cp)) {
		emu_command_status(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cp = (const void *)p;
	handle = NG_HCI_CON_HANDLE(le16toh(cp->con_handle));
	reason = cp->reason;

	c = emu_conn_by_handle(e, handle);
	if (c == NULL) {
		emu_command_status(e, op, EMU_STATUS_UNKNOWN_CONN_ID);
		return;
	}
	emu_command_status(e, op, EMU_STATUS_SUCCESS);

	peer = c->peer;
	phandle = c->peer_handle;
	pc = (peer != NULL) ? emu_conn_by_handle(peer, phandle) : NULL;

	hci_emu_inject_disconnection_complete(e, handle,
	    EMU_REASON_LOCAL_HOST_TERM);
	if (peer != NULL)
		hci_emu_inject_disconnection_complete(peer, phandle, reason);

	/* Drop any armed supervision timers for this link. */
	emu_timer_cancel(e, emu_supervision_fire, handle);
	if (peer != NULL)
		emu_timer_cancel(peer, emu_supervision_fire, phandle);

	memset(c, 0, sizeof(*c));
	if (pc != NULL)
		memset(pc, 0, sizeof(*pc));
}

/*
 * ACL data path.  A host ACL packet on an established connection is
 * delivered out the peer controller's output callback with the connection
 * handle rewritten to the value the peer knows the link by (PB/BC flags
 * preserved, §5.4.2).  The sender then receives a Number Of Completed
 * Packets event (§7.7.19) crediting one packet on that handle.
 */
static void
emu_num_completed(struct hci_emu *e, uint16_t handle, uint16_t count)
{
	uint8_t p[1 + 4];

	p[0] = 1;			/* Num_Handles */
	le16enc(&p[1], handle);
	le16enc(&p[3], count);
	emu_event(e, NG_HCI_EVENT_NUM_COMPL_PKTS, p, sizeof(p));
}

static void
emu_handle_acl(struct hci_emu *e, const uint8_t *pkt, size_t len)
{
	const ng_hci_acldata_pkt_t *hdr;
	struct emu_conn *c;
	uint16_t chf, handle, plen16, newchf;
	uint8_t *buf;
	size_t frame_len;

	if (len < sizeof(ng_hci_acldata_pkt_t))
		return;
	hdr = (const void *)pkt;
	chf = le16toh(hdr->con_handle);
	handle = NG_HCI_CON_HANDLE(chf);
	plen16 = le16toh(hdr->length);
	frame_len = sizeof(ng_hci_acldata_pkt_t) + plen16;
	if (len < frame_len)
		return;			/* truncated payload */

	c = emu_conn_by_handle(e, handle);
	if (c == NULL || c->peer == NULL)
		return;			/* no such connection: drop */

	/*
	 * Traffic resets the link supervision timer on both endpoints
	 * (Vol 6 Part B §4.5.2): the timer only expires after a period with
	 * no received packets.
	 */
	emu_arm_supervision(e, c);
	{
		struct emu_conn *pc = emu_conn_by_handle(c->peer,
		    c->peer_handle);
		if (pc != NULL)
			emu_arm_supervision(c->peer, pc);
	}

	/* Rewrite only the handle bits; keep PB/BC flags (§5.4.2). */
	newchf = NG_HCI_MK_CON_HANDLE(c->peer_handle, NG_HCI_PB_FLAG(chf),
	    NG_HCI_BC_FLAG(chf));

	buf = malloc(frame_len);
	if (buf == NULL)
		return;
	memcpy(buf, pkt, frame_len);
	le16enc(&buf[1], newchf);
	if (c->peer->out != NULL)
		c->peer->out(c->peer->out_ctx, buf, frame_len);
	free(buf);

	emu_num_completed(e, handle, 1);
}

/* ================================================================== */
/* Increment 3: LE encryption / LTK path (§7.8.24-.26)                 */
/* ================================================================== */

/*
 * LE_Enable_Encryption (§7.8.24, OCF 0x0019).  Returns Command Status;
 * the result arrives later as events.  On the peer (peripheral) the
 * controller raises an LE Long Term Key Request meta event (§7.7.65.5)
 * carrying the Random_Number and Encrypted_Diversifier from this command,
 * so the peer host can look up and supply the LTK.
 */
static void
h_le_enable_encryption(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	const ng_hci_le_start_encryption_cp *cp;
	struct hci_emu *peer;
	struct emu_conn *c, *pc;
	uint8_t ep[sizeof(ng_hci_le_long_term_key_request_ep)];
	uint16_t handle;

	if (plen < sizeof(*cp)) {
		emu_command_status(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cp = (const void *)p;
	handle = le16toh(cp->connection_handle);

	c = emu_conn_by_handle(e, handle);
	if (c == NULL) {
		emu_command_status(e, op, EMU_STATUS_UNKNOWN_CONN_ID);
		return;
	}
	emu_command_status(e, op, EMU_STATUS_SUCCESS);

	peer = c->peer;
	pc = (peer != NULL) ? emu_conn_by_handle(peer, c->peer_handle) : NULL;
	if (pc == NULL)
		return;			/* no peer host to request the LTK */

	/*
	 * LE Long Term Key Request (§7.7.65.5): Connection_Handle(2) |
	 * Random_Number(8) | Encrypted_Diversifier(2).  The Random_Number
	 * and EDIV are copied verbatim (little-endian on the wire) from the
	 * initiator's command parameters, which lie at p[2..9] and p[10..11].
	 */
	le16enc(&ep[0], pc->handle);
	memcpy(&ep[2], &p[2], 8);		/* random_number, stays LE */
	memcpy(&ep[10], &p[10], 2);		/* encrypted_diversifier */
	{
		uint8_t params[1 + sizeof(ep)];

		params[0] = NG_HCI_LEEV_LONG_TERM_KEY_REQUEST;	/* 0x05 */
		memcpy(&params[1], ep, sizeof(ep));
		emu_event(peer, NG_HCI_EVENT_LE, params, sizeof(params));
	}
}

/* Enable encryption on a link and emit Encryption_Change on both sides. */
static void
emu_encryption_succeed(struct hci_emu *e, struct emu_conn *c)
{
	struct hci_emu *peer;
	struct emu_conn *pc;
	uint8_t status, enabled;

	status = e->enc_outcome;
	enabled = (status == EMU_STATUS_SUCCESS) ? 0x01 : 0x00;

	peer = c->peer;
	pc = (peer != NULL) ? emu_conn_by_handle(peer, c->peer_handle) : NULL;

	c->encrypted = enabled;
	if (pc != NULL)
		pc->encrypted = enabled;

	hci_emu_inject_encryption_change(e, c->handle, status, enabled);
	if (peer != NULL)
		hci_emu_inject_encryption_change(peer, c->peer_handle, status,
		    enabled);
}

/*
 * LE_Long_Term_Key_Request_Reply (§7.8.25, OCF 0x001a).  The peripheral
 * host supplies the LTK.  Returns Command Complete (status +
 * Connection_Handle), then encryption completes: an Encryption_Change
 * (§7.7.8) on both sides carrying the settable outcome status.
 */
static void
h_le_ltk_reply(struct hci_emu *e, uint16_t op, const uint8_t *p, uint8_t plen)
{
	const ng_hci_le_long_term_key_request_reply_cp *cp;
	ng_hci_le_long_term_key_request_reply_rp rp;
	struct emu_conn *c;
	uint16_t handle;

	if (plen < sizeof(*cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cp = (const void *)p;
	handle = le16toh(cp->connection_handle);

	c = emu_conn_by_handle(e, handle);
	rp.status = (c != NULL) ? EMU_STATUS_SUCCESS : EMU_STATUS_UNKNOWN_CONN_ID;
	rp.connection_handle = htole16(handle);
	emu_cmd_complete(e, op, &rp, sizeof(rp));

	if (c != NULL)
		emu_encryption_succeed(e, c);
}

/*
 * LE_Long_Term_Key_Request_Negative_Reply (§7.8.26, OCF 0x001b).  The
 * peripheral host has no key.  Returns Command Complete (status +
 * Connection_Handle); encryption then fails and the initiating central
 * receives an Encryption_Change (§7.7.8) with status PIN or Key Missing
 * (0x06) and encryption disabled.
 */
static void
h_le_ltk_negative_reply(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	const ng_hci_le_long_term_key_request_negative_reply_cp *cp;
	ng_hci_le_long_term_key_request_negative_reply_rp rp;
	struct emu_conn *c;
	uint16_t handle;

	if (plen < sizeof(*cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cp = (const void *)p;
	handle = le16toh(cp->connection_handle);

	c = emu_conn_by_handle(e, handle);
	rp.status = (c != NULL) ? EMU_STATUS_SUCCESS : EMU_STATUS_UNKNOWN_CONN_ID;
	rp.connection_handle = htole16(handle);
	emu_cmd_complete(e, op, &rp, sizeof(rp));

	if (c != NULL && c->peer != NULL)
		hci_emu_inject_encryption_change(c->peer, c->peer_handle,
		    EMU_STATUS_PIN_OR_KEY_MISSING, 0x00);
}

/* ================================================================== */
/* Increment 3: LE Power Control (Core 5.2, §7.8.117-.121)             */
/* ================================================================== */

/*
 * LE_Read_Remote_Transmit_Power_Level (§7.8.118, OCF 0x0077).  Returns
 * Command Status, then an LE Transmit Power Reporting event (§7.7.65.33)
 * with Reason 0x02 (remote-power read completed).  The reported level is
 * the peer's modeled tx-power level, fetched over the link.
 */
static void
h_le_read_remote_tx_power(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	const ng_hci_le_read_remote_tx_power_cp *cp;
	struct hci_emu *peer;
	struct emu_conn *c, *pc;
	uint16_t handle;
	int8_t level;

	if (plen < sizeof(*cp)) {
		emu_command_status(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cp = (const void *)p;
	handle = le16toh(cp->connection_handle);

	c = emu_conn_by_handle(e, handle);
	if (c == NULL) {
		emu_command_status(e, op, EMU_STATUS_UNKNOWN_CONN_ID);
		return;
	}
	emu_command_status(e, op, EMU_STATUS_SUCCESS);

	peer = c->peer;
	pc = (peer != NULL) ? emu_conn_by_handle(peer, c->peer_handle) : NULL;
	level = (pc != NULL) ? pc->tx_power_level : c->tx_power_level;

	/*
	 * Reason 0x02 (remote tx power read completed); tx_power_level_flag
	 * 0x00 (neither min nor max); Delta 0x00.  Vol 4 Part E §7.7.65.33:
	 * "When this event is generated with Reason set to 0x02, Delta shall
	 * be set to zero."
	 */
	hci_emu_inject_tx_power_report(e, EMU_STATUS_SUCCESS, handle, 0x02,
	    cp->phy, level, 0x00, (int8_t)0x00);
}

/*
 * LE_Set_Path_Loss_Reporting_Parameters (§7.8.119, OCF 0x0078).  Returns
 * Command Complete (status + Connection_Handle); stores the zone
 * thresholds/hysteresis for the connection.
 */
static void
h_le_set_path_loss_params(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	const ng_hci_le_set_path_loss_reporting_params_cp *cp;
	ng_hci_le_set_path_loss_reporting_params_rp rp;
	struct emu_conn *c;
	uint16_t handle;

	if (plen < sizeof(*cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cp = (const void *)p;
	handle = le16toh(cp->connection_handle);
	c = emu_conn_by_handle(e, handle);

	rp.status = (c != NULL) ? EMU_STATUS_SUCCESS : EMU_STATUS_UNKNOWN_CONN_ID;
	rp.connection_handle = htole16(handle);
	if (c != NULL) {
		c->pl_high_threshold = cp->high_threshold;
		c->pl_high_hysteresis = cp->high_hysteresis;
		c->pl_low_threshold = cp->low_threshold;
		c->pl_low_hysteresis = cp->low_hysteresis;
		c->pl_min_time_spent = le16toh(cp->min_time_spent);
	}
	emu_cmd_complete(e, op, &rp, sizeof(rp));
}

/* Map the current path loss to a zone using the connection thresholds. */
static uint8_t
emu_path_loss_zone(const struct emu_conn *c)
{

	if (c->path_loss <= c->pl_low_threshold)
		return (0x00);				/* low zone */
	if (c->path_loss >= c->pl_high_threshold)
		return (0x02);				/* high zone */
	return (0x01);					/* middle zone */
}

/*
 * LE_Set_Path_Loss_Reporting_Enable (§7.8.120, OCF 0x0079).  Returns
 * Command Complete (status + Connection_Handle).  On enable the
 * controller reports the current zone with an initial LE Path Loss
 * Threshold event (§7.7.65.32).
 */
static void
h_le_set_path_loss_enable(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	const ng_hci_le_set_path_loss_reporting_enable_cp *cp;
	ng_hci_le_set_path_loss_reporting_enable_rp rp;
	struct emu_conn *c;
	uint16_t handle;

	if (plen < sizeof(*cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cp = (const void *)p;
	handle = le16toh(cp->connection_handle);
	c = emu_conn_by_handle(e, handle);

	rp.status = (c != NULL) ? EMU_STATUS_SUCCESS : EMU_STATUS_UNKNOWN_CONN_ID;
	rp.connection_handle = htole16(handle);
	emu_cmd_complete(e, op, &rp, sizeof(rp));

	if (c == NULL)
		return;
	c->pl_report_enable = (cp->enable != 0);
	if (c->pl_report_enable)
		hci_emu_inject_path_loss_threshold(e, handle, c->path_loss,
		    emu_path_loss_zone(c));
}

/*
 * LE_Set_Transmit_Power_Reporting_Enable (§7.8.121, OCF 0x007a).  Returns
 * Command Complete (status + Connection_Handle); records whether local
 * and remote tx-power change reports are enabled for the connection.
 */
static void
h_le_set_tx_power_reporting_enable(struct hci_emu *e, uint16_t op,
    const uint8_t *p, uint8_t plen)
{
	const ng_hci_le_set_tx_power_reporting_enable_cp *cp;
	ng_hci_le_set_tx_power_reporting_enable_rp rp;
	struct emu_conn *c;
	uint16_t handle;

	if (plen < sizeof(*cp)) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cp = (const void *)p;
	handle = le16toh(cp->connection_handle);
	c = emu_conn_by_handle(e, handle);

	rp.status = (c != NULL) ? EMU_STATUS_SUCCESS : EMU_STATUS_UNKNOWN_CONN_ID;
	rp.connection_handle = htole16(handle);
	if (c != NULL) {
		c->txp_local_enable = (cp->local_enable != 0);
		c->txp_remote_enable = (cp->remote_enable != 0);
	}
	emu_cmd_complete(e, op, &rp, sizeof(rp));
}

/* ================================================================== */
/* Increment 4: LE Isochronous Channels (CIS / BIG / ISO data path)    */
/* ================================================================== */

static struct emu_iso *
emu_iso_alloc(struct hci_emu *e)
{
	int i;

	for (i = 0; i < EMU_ISO_MAX; i++)
		if (!e->iso[i].active)
			return (&e->iso[i]);
	return (NULL);
}

static struct emu_iso *
emu_iso_by_handle(struct hci_emu *e, uint16_t handle)
{
	int i;

	for (i = 0; i < EMU_ISO_MAX; i++)
		if (e->iso[i].active && e->iso[i].handle == handle)
			return (&e->iso[i]);
	return (NULL);
}

static int
emu_iso_free_slots(const struct hci_emu *e)
{
	int i, n = 0;

	for (i = 0; i < EMU_ISO_MAX; i++)
		if (!e->iso[i].active)
			n++;
	return (n);
}

static uint16_t
emu_next_iso_handle(struct hci_emu *e)
{
	uint16_t h;

	h = e->next_iso_handle;
	e->next_iso_handle++;
	if (e->next_iso_handle == 0 || e->next_iso_handle > 0x0eff)
		e->next_iso_handle = EMU_FIRST_ISO_HANDLE;
	return (h);
}

static uint64_t
emu_le_features(const struct hci_emu *e)
{

	return (le64dec(e->le_features));
}

static int
emu_has_le_feature(const struct hci_emu *e, uint64_t feature)
{

	return ((emu_le_features(e) & feature) != 0);
}

static int
emu_command_supported_by_features(const struct hci_emu *e, uint16_t opcode)
{

	switch (opcode) {
	case OP_LE_SET_PERIODIC_ADV_PARAMS:
	case OP_LE_SET_PERIODIC_ADV_DATA:
	case OP_LE_SET_PERIODIC_ADV_ENABLE:
		return (emu_has_le_feature(e, EMU_LE_FEAT_PERIODIC_ADV));
	case OP_LE_SET_PERIODIC_ADV_RCV_ENABLE:
		return (emu_has_le_feature(e, EMU_LE_FEAT_PAST_RECIPIENT));
	case OP_LE_PERIODIC_ADV_SYNC_TRANSFER:
		return (emu_has_le_feature(e, EMU_LE_FEAT_PAST_SENDER));
	case OP_LE_READ_REMOTE_TX_POWER:
	case OP_LE_SET_TX_POWER_REPORTING_ENABLE:
		return (emu_has_le_feature(e, EMU_LE_FEAT_POWER_CONTROL));
	case OP_LE_SET_PATH_LOSS_PARAMS:
	case OP_LE_SET_PATH_LOSS_ENABLE:
		return (emu_has_le_feature(e, EMU_LE_FEAT_PATH_LOSS_MONITORING));
	case OP_LE_SET_CIG_PARAMS:
	case OP_LE_CREATE_CIS:
	case OP_LE_SETUP_ISO_DATA_PATH:
		return ((emu_le_features(e) &
		    (EMU_LE_FEAT_CIS_CENTRAL | EMU_LE_FEAT_CIS_PERIPH)) != 0);
	case OP_LE_CREATE_BIG:
		return (emu_has_le_feature(e, EMU_LE_FEAT_ISO_BROADCASTER));
	case OP_LE_BIG_CREATE_SYNC:
		return (emu_has_le_feature(e, EMU_LE_FEAT_SYNC_RECEIVER));
	default:
		return (1);
	}
}

/*
 * LE CIS Established (LE Meta 0x3E / subevent 0x19), Vol 4 Part E §7.7.65.25.
 * The emulator reports a single fixed, spec-legal parameter set: what a data
 * flow test asserts is that the event arrives on both endpoints and carries
 * the correct connection handle, not the negotiated timing values.
 */
static void
emu_emit_cis_established(struct hci_emu *e, uint16_t handle)
{
	uint8_t params[1 + sizeof(ng_hci_le_cis_established_ep)];
	ng_hci_le_cis_established_ep ep = { 0 };

	params[0] = NG_HCI_LEEV_CIS_ESTABLISHED;	/* 0x19 */
	ep.status = EMU_STATUS_SUCCESS;
	ep.connection_handle = htole16(handle);
	ep.phy_c_to_p = 0x01;			/* LE 1M */
	ep.phy_p_to_c = 0x01;
	ep.nse = 1;
	ep.bn_c_to_p = 1;
	ep.bn_p_to_c = 1;
	ep.ft_c_to_p = 1;
	ep.ft_p_to_c = 1;
	ep.max_pdu_c_to_p = htole16(251);
	ep.max_pdu_p_to_c = htole16(251);
	ep.iso_interval = htole16(0x0008);	/* 10 ms in 1.25 ms units */
	memcpy(&params[1], &ep, sizeof(ep));
	emu_event(e, NG_HCI_EVENT_LE, params, sizeof(params));
}

/*
 * LE Set CIG Parameters (§7.8.97, OCF 0x0062).  Returns Command Complete
 * with status | CIG_ID | CIS_Count | Connection_Handle[i].  The command body
 * is a 15-octet header (CIG_ID at offset 0, CIS_Count at offset 14) followed
 * by CIS_Count 9-octet CIS records.  A CIS connection handle is allocated for
 * every requested CIS and returned so a later LE Create CIS can reference it.
 */
static void
h_le_set_cig_params(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	uint8_t rp[3 + 2 * 31];
	uint8_t cig_id, cis_count, i;

	if (plen < 15) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	cig_id = p[0];
	cis_count = p[14];
	if (cig_id > 0xEF || cis_count > 31 ||
	    (size_t)15 + (size_t)cis_count * 9 > plen) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}

	rp[0] = EMU_STATUS_SUCCESS;
	rp[1] = cig_id;
	rp[2] = cis_count;
	for (i = 0; i < cis_count; i++) {
		struct emu_iso *s = emu_iso_alloc(e);
		uint16_t h;

		if (s == NULL) {
			emu_cmd_status_rp(e, op, 0x07);	/* Memory Capacity Exceeded */
			return;
		}
		h = emu_next_iso_handle(e);
		memset(s, 0, sizeof(*s));
		s->active = 1;
		s->handle = h;
		s->group_id = cig_id;
		s->is_broadcast = 0;
		le16enc(&rp[3 + i * 2], h);
	}
	emu_cmd_complete(e, op, rp, (uint8_t)(3 + cis_count * 2));
}

/*
 * LE Create CIS (§7.8.99, OCF 0x0064).  Returns Command Status, then an LE
 * CIS Established event (§7.7.65.25) on the central and the peripheral.  The
 * command body is CIS_Count followed by {CIS_Connection_Handle,
 * ACL_Connection_Handle} pairs.  Each CIS is bound to its ACL connection's
 * partner controller so ISO SDUs can later be forwarded across the link.
 */
static void
h_le_create_cis(struct hci_emu *e, uint16_t op, const uint8_t *p, uint8_t plen)
{
	uint8_t cis_count, i;

	if (plen < 1 || (cis_count = p[0]) == 0 || cis_count > 31 ||
	    (size_t)1 + (size_t)cis_count * 4 > plen) {
		emu_command_status(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	emu_command_status(e, op, EMU_STATUS_SUCCESS);

	for (i = 0; i < cis_count; i++) {
		uint16_t cis_h = le16dec(&p[1 + i * 4]);
		uint16_t acl_h = le16dec(&p[1 + i * 4 + 2]);
		struct emu_iso *s, *ps;
		struct emu_conn *ac;
		uint16_t peer_h;

		s = emu_iso_by_handle(e, cis_h);
		ac = emu_conn_by_handle(e, acl_h);
		if (s == NULL || ac == NULL || ac->peer == NULL)
			continue;

		ps = emu_iso_alloc(ac->peer);
		if (ps == NULL)
			continue;
		peer_h = emu_next_iso_handle(ac->peer);

		s->acl_handle = acl_h;
		s->peer = ac->peer;
		s->peer_handle = peer_h;
		s->established = 1;

		memset(ps, 0, sizeof(*ps));
		ps->active = 1;
		ps->handle = peer_h;
		ps->acl_handle = ac->peer_handle;
		ps->group_id = s->group_id;
		ps->is_broadcast = 0;
		ps->established = 1;
		ps->peer = e;
		ps->peer_handle = cis_h;

		emu_emit_cis_established(e, cis_h);
		emu_emit_cis_established(ac->peer, peer_h);
	}
}

/*
 * LE Setup ISO Data Path (§7.8.109, OCF 0x006E).  Returns Command Complete
 * with status | Connection_Handle.  Opens the requested data-path direction
 * (0x00 = Host->Controller input, 0x01 = Controller->Host output) so ISO
 * SDUs on that stream begin to forward.
 */
static void
h_le_setup_iso_data_path(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	ng_hci_le_setup_iso_data_path_rp rp;
	struct emu_iso *s;
	uint16_t handle;
	uint8_t direction;

	if (plen < 13) {
		emu_cmd_status_rp(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	handle = le16dec(&p[0]);
	direction = p[2];

	s = emu_iso_by_handle(e, handle);
	rp.status = (s != NULL) ? EMU_STATUS_SUCCESS : EMU_STATUS_UNKNOWN_CONN_ID;
	rp.connection_handle = htole16(handle);
	if (s != NULL) {
		if (direction == 0x00)
			s->path_in_open = 1;
		else if (direction == 0x01)
			s->path_out_open = 1;
	}
	emu_cmd_complete(e, op, &rp, sizeof(rp));
}

/*
 * LE Create BIG (§7.8.103, OCF 0x0068).  Returns Command Status, then an LE
 * Create BIG Complete event (§7.7.65.27) carrying a BIS connection handle per
 * BIS.  Body: BIG_Handle | Advertising_Handle | Num_BIS | ... .  The
 * broadcaster registers each BIS; a receiver later links to them via BIG
 * Create Sync.
 */
static void
h_le_create_big(struct hci_emu *e, uint16_t op, const uint8_t *p, uint8_t plen)
{
	uint8_t params[1 + sizeof(ng_hci_le_create_big_compl_ep) + 2 * 31];
	ng_hci_le_create_big_compl_ep ep = { 0 };
	uint8_t big_handle, num_bis, i;
	size_t o;

	if (plen < 3) {
		emu_command_status(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	big_handle = p[0];
	num_bis = p[2];
	if (num_bis < 1 || num_bis > 31) {
		emu_command_status(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	/*
	 * The whole group must fit the stream table: reject up front with
	 * Memory Capacity Exceeded rather than allocate a partial group and
	 * emit a Create BIG Complete whose Num_BIS overcounts the handles
	 * actually appended (§7.7.65.27).
	 */
	if (num_bis > emu_iso_free_slots(e)) {
		emu_command_status(e, op, 0x07);	/* Memory Capacity Exceeded */
		return;
	}
	emu_command_status(e, op, EMU_STATUS_SUCCESS);

	params[0] = NG_HCI_LEEV_CREATE_BIG_COMPL;	/* 0x1b */
	ep.status = EMU_STATUS_SUCCESS;
	ep.big_handle = big_handle;
	ep.phy = 0x01;
	ep.nse = 1;
	ep.bn = 1;
	ep.pto = 0;
	ep.irc = 1;
	ep.max_pdu = htole16(251);
	ep.iso_interval = htole16(0x0008);
	ep.num_bis = num_bis;
	memcpy(&params[1], &ep, sizeof(ep));
	o = 1 + sizeof(ep);

	for (i = 0; i < num_bis; i++) {
		struct emu_iso *s = emu_iso_alloc(e);
		uint16_t h;

		if (s == NULL)
			break;
		h = emu_next_iso_handle(e);
		memset(s, 0, sizeof(*s));
		s->active = 1;
		s->handle = h;
		s->group_id = big_handle;
		s->is_broadcast = 1;
		s->established = 1;
		le16enc(&params[o], h);
		o += 2;
	}
	emu_event(e, NG_HCI_EVENT_LE, params, (uint8_t)o);
}

/*
 * LE BIG Create Sync (§7.8.106, OCF 0x006B).  Returns Command Status, then an
 * LE BIG Sync Established event (§7.7.65.29).  The receiver allocates a BIS
 * handle per synchronized stream and pairs it, in order, with the
 * broadcaster's BIS entries over the physical link so broadcast ISO SDUs
 * forward broadcaster->receiver.  Body: BIG_Handle | Sync_Handle(2) |
 * Encryption(1) | Broadcast_Code(16) | MSE(1) | BIG_Sync_Timeout(2) |
 * Num_BIS(1) | BIS[i](1).
 */
static void
h_le_big_create_sync(struct hci_emu *e, uint16_t op, const uint8_t *p,
    uint8_t plen)
{
	uint8_t params[1 + sizeof(ng_hci_le_big_sync_est_ep) + 2 * 31];
	ng_hci_le_big_sync_est_ep ep = { 0 };
	struct hci_emu *bc = NULL;
	struct emu_iso *bc_bis[31];
	uint8_t big_handle, num_bis, i;
	int nbc = 0, k;
	size_t j;
	size_t o;

	if (plen < 24) {
		emu_command_status(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	big_handle = p[0];
	num_bis = p[23];
	if (num_bis < 1 || num_bis > 31) {
		emu_command_status(e, op, EMU_STATUS_INVALID_PARAMS);
		return;
	}
	/*
	 * Reject up front if the receiver's stream table cannot hold every
	 * synchronized BIS, so the BIG Sync Established event never claims a
	 * Num_BIS larger than the handles actually appended (§7.7.65.29).
	 */
	if (num_bis > emu_iso_free_slots(e)) {
		emu_command_status(e, op, 0x07);	/* Memory Capacity Exceeded */
		return;
	}
	emu_command_status(e, op, EMU_STATUS_SUCCESS);

	/* Select a linked broadcaster with unsynchronized BIS entries. */
	for (j = 0; j < e->n_links && bc == NULL; j++)
		for (k = 0; k < EMU_ISO_MAX; k++)
			if (e->links[j]->iso[k].active &&
			    e->links[j]->iso[k].is_broadcast &&
			    e->links[j]->iso[k].peer == NULL) {
				bc = e->links[j];
				break;
			}

	/* Gather the broadcaster's not-yet-synced BIS entries, in order. */
	if (bc != NULL) {
		for (k = 0; k < EMU_ISO_MAX && nbc < 31; k++)
			if (bc->iso[k].active && bc->iso[k].is_broadcast &&
			    bc->iso[k].peer == NULL)
				bc_bis[nbc++] = &bc->iso[k];
	}

	params[0] = NG_HCI_LEEV_BIG_SYNC_EST;		/* 0x1d */
	ep.status = EMU_STATUS_SUCCESS;
	ep.big_handle = big_handle;
	ep.nse = 1;
	ep.bn = 1;
	ep.pto = 0;
	ep.irc = 1;
	ep.max_pdu = htole16(251);
	ep.iso_interval = htole16(0x0008);
	ep.num_bis = num_bis;
	memcpy(&params[1], &ep, sizeof(ep));
	o = 1 + sizeof(ep);

	for (i = 0; i < num_bis; i++) {
		struct emu_iso *s = emu_iso_alloc(e);
		uint16_t h;

		if (s == NULL)
			break;
		h = emu_next_iso_handle(e);
		memset(s, 0, sizeof(*s));
		s->active = 1;
		s->handle = h;
		s->group_id = big_handle;
		s->is_broadcast = 1;
		s->established = 1;
		if (i < nbc) {
			/* Pair receiver BIS[i] with broadcaster BIS[i]. */
			s->peer = bc;
			s->peer_handle = bc_bis[i]->handle;
			bc_bis[i]->peer = e;
			bc_bis[i]->peer_handle = h;
		}
		le16enc(&params[o], h);
		o += 2;
	}
	emu_event(e, NG_HCI_EVENT_LE, params, (uint8_t)o);
}

/*
 * HCI ISO data path (§5.4.5).  A host ISO packet on a stream whose input data
 * path is open is delivered out the partner controller's output callback with
 * the connection handle rewritten to the value the peer knows the stream by
 * (PB/TS flags preserved).  The sender then receives a Number Of Completed
 * Packets event (§7.7.19) crediting one packet on that handle.
 */
static void
emu_handle_iso(struct hci_emu *e, const uint8_t *pkt, size_t len)
{
	const ng_hci_isodata_pkt_t *hdr;
	struct emu_iso *s;
	uint16_t chf, handle, plen16, newchf;
	uint8_t *buf;
	size_t frame_len;

	if (len < sizeof(ng_hci_isodata_pkt_t))
		return;
	hdr = (const void *)pkt;
	chf = le16toh(hdr->con_handle);
	handle = NG_HCI_ISO_CON_HANDLE(chf);
	plen16 = (uint16_t)NG_HCI_ISO_DATA_LENGTH(le16toh(hdr->length));
	frame_len = sizeof(ng_hci_isodata_pkt_t) + plen16;
	if (len < frame_len)
		return;			/* truncated ISO data load */

	s = emu_iso_by_handle(e, handle);
	if (s == NULL || !s->established || s->peer == NULL || !s->path_in_open)
		return;			/* no forwardable stream: drop */

	/* Rewrite only the handle bits; keep PB/TS flags (§5.4.5). */
	newchf = (uint16_t)((s->peer_handle & 0x0fff) | (chf & 0x7000));

	buf = malloc(frame_len);
	if (buf == NULL)
		return;
	memcpy(buf, pkt, frame_len);
	le16enc(&buf[1], newchf);
	if (s->peer->out != NULL)
		s->peer->out(s->peer->out_ctx, buf, frame_len);
	free(buf);

	emu_num_completed(e, handle, 1);
}

/* ================================================================== */
/* Command dispatch                                                    */
/* ================================================================== */

static void
emu_dispatch_command(struct hci_emu *e, uint16_t opcode, const uint8_t *p,
    uint8_t plen)
{
	uint8_t forced;

	/*
	 * Fault-injection hook (btdev analogue): if the test forced a
	 * status for this opcode, complete with that status and skip the
	 * real handler.  Return parameters are omitted on a forced error
	 * (spec-legal: on failure the controller need not return the
	 * command-specific parameters).
	 */
	if (emu_forced(e, opcode, &forced)) {
		emu_cmd_status_rp(e, opcode, forced);
		return;
	}
	if (!emu_command_supported_by_features(e, opcode)) {
		emu_cmd_status_rp(e, opcode, EMU_STATUS_UNKNOWN_CMD);
		return;
	}

	switch (opcode) {
	case OP_RESET:
		h_reset(e, opcode);
		break;
	case OP_SET_EVENT_MASK:
		h_set_event_mask(e, opcode, p, plen);
		break;
	case OP_WRITE_LE_HOST_SUPPORTED:
		h_write_le_host_supported(e, opcode, p, plen);
		break;
	case OP_READ_LOCAL_VER:
		h_read_local_ver(e, opcode);
		break;
	case OP_READ_LOCAL_COMMANDS:
		h_read_local_commands(e, opcode);
		break;
	case OP_READ_LOCAL_FEATURES:
		h_read_local_features(e, opcode);
		break;
	case OP_READ_BUFFER_SIZE:
		h_read_buffer_size(e, opcode);
		break;
	case OP_READ_BDADDR:
		h_read_bdaddr(e, opcode);
		break;

	case OP_LE_SET_EVENT_MASK:
		h_le_set_event_mask(e, opcode, p, plen);
		break;
	case OP_LE_READ_BUFFER_SIZE:
		h_le_read_buffer_size(e, opcode);
		break;
	case OP_LE_READ_BUFFER_SIZE_V2:
		h_le_read_buffer_size_v2(e, opcode);
		break;
	case OP_LE_READ_LOCAL_FEATURES:
		h_le_read_local_features(e, opcode);
		break;
	case OP_LE_READ_NUM_ADV_SETS:
		h_le_read_num_adv_sets(e, opcode);
		break;
	case OP_LE_SET_RANDOM_ADDRESS:
		h_le_set_random_address(e, opcode, p, plen);
		break;
	case OP_LE_SET_ADV_PARAMS:
		h_le_set_adv_params(e, opcode, p, plen);
		break;
	case OP_LE_SET_ADV_DATA:
		h_le_set_adv_data(e, opcode, p, plen);
		break;
	case OP_LE_SET_SCAN_RSP_DATA:
		h_le_set_scanrsp_data(e, opcode, p, plen);
		break;
	case OP_LE_SET_ADV_ENABLE:
		h_le_set_adv_enable(e, opcode, p, plen);
		break;
	case OP_LE_SET_SCAN_PARAMS:
		h_le_set_scan_params(e, opcode, p, plen);
		break;
	case OP_LE_SET_SCAN_ENABLE:
		h_le_set_scan_enable(e, opcode, p, plen);
		break;
	case OP_LE_ADD_RESOLV:
		h_le_add_resolv(e, opcode, p, plen);
		break;
	case OP_LE_REMOVE_RESOLV:
		h_le_remove_resolv(e, opcode, p, plen);
		break;
	case OP_LE_CLEAR_RESOLV:
		h_le_clear_resolv(e, opcode);
		break;
	case OP_LE_SET_ADDR_RESOLUTION_ENABLE:
		h_le_set_addr_resolution_enable(e, opcode, p, plen);
		break;
	case OP_LE_SET_PERIODIC_ADV_PARAMS:
		h_le_set_periodic_adv_params(e, opcode, p, plen);
		break;
	case OP_LE_SET_PERIODIC_ADV_DATA:
		h_le_set_periodic_adv_data(e, opcode, p, plen);
		break;
	case OP_LE_SET_PERIODIC_ADV_ENABLE:
		h_le_set_periodic_adv_enable(e, opcode, p, plen);
		break;
	case OP_LE_SET_PERIODIC_ADV_RCV_ENABLE:
		h_le_set_periodic_adv_rcv_enable(e, opcode, p, plen);
		break;
	case OP_LE_PERIODIC_ADV_SYNC_TRANSFER:
		h_le_periodic_adv_sync_transfer(e, opcode, p, plen);
		break;

	case OP_DISCONNECT:
		h_disconnect(e, opcode, p, plen);
		break;
	case OP_LE_CREATE_CONNECTION:
		h_le_create_connection(e, opcode, p, plen);
		break;
	case OP_LE_CREATE_CONNECTION_CANCEL:
		h_le_create_connection_cancel(e, opcode);
		break;

	case OP_LE_ENABLE_ENCRYPTION:
		h_le_enable_encryption(e, opcode, p, plen);
		break;
	case OP_LE_LTK_REQ_REPLY:
		h_le_ltk_reply(e, opcode, p, plen);
		break;
	case OP_LE_LTK_REQ_NEG_REPLY:
		h_le_ltk_negative_reply(e, opcode, p, plen);
		break;

	case OP_LE_READ_REMOTE_TX_POWER:
		h_le_read_remote_tx_power(e, opcode, p, plen);
		break;
	case OP_LE_SET_PATH_LOSS_PARAMS:
		h_le_set_path_loss_params(e, opcode, p, plen);
		break;
	case OP_LE_SET_PATH_LOSS_ENABLE:
		h_le_set_path_loss_enable(e, opcode, p, plen);
		break;
	case OP_LE_SET_TX_POWER_REPORTING_ENABLE:
		h_le_set_tx_power_reporting_enable(e, opcode, p, plen);
		break;

	case OP_LE_SET_CIG_PARAMS:
		h_le_set_cig_params(e, opcode, p, plen);
		break;
	case OP_LE_CREATE_CIS:
		h_le_create_cis(e, opcode, p, plen);
		break;
	case OP_LE_SETUP_ISO_DATA_PATH:
		h_le_setup_iso_data_path(e, opcode, p, plen);
		break;
	case OP_LE_CREATE_BIG:
		h_le_create_big(e, opcode, p, plen);
		break;
	case OP_LE_BIG_CREATE_SYNC:
		h_le_big_create_sync(e, opcode, p, plen);
		break;

	default:
		/*
		 * Unknown/unhandled opcode: Command Complete carrying
		 * Unknown HCI Command (0x01).  Vol 4 Part E §7.7.14 plus
		 * the §1.3 error-code table.
		 */
		emu_cmd_status_rp(e, opcode, EMU_STATUS_UNKNOWN_CMD);
		break;
	}
}

void
hci_emu_input(struct hci_emu *e, const uint8_t *pkt, size_t len)
{
	uint16_t opcode;
	uint8_t plen;

	if (pkt == NULL || len < 1)
		return;

	switch (pkt[0]) {
	case NG_HCI_CMD_PKT:	/* 0x01 */
		/* type(1) | opcode(2,LE) | param_len(1) | params */
		if (len < sizeof(ng_hci_cmd_pkt_t))
			return;
		opcode = le16dec(&pkt[1]);
		plen = pkt[3];
		if (len < (size_t)sizeof(ng_hci_cmd_pkt_t) + plen)
			return;		/* truncated parameters */
		emu_dispatch_command(e, opcode, &pkt[4], plen);
		break;

	case NG_HCI_ACL_DATA_PKT:	/* 0x02 */
		/*
		 * Increment 2: deliver host ACL data to the linked peer and
		 * credit the sender with a Number Of Completed Packets event.
		 */
		emu_handle_acl(e, pkt, len);
		break;

	case NG_HCI_ISO_DATA_PKT:	/* 0x05 */
		/*
		 * Increment 4: forward an ISO SDU to the linked peer over an
		 * established stream whose input data path is open (§5.4.5).
		 */
		emu_handle_iso(e, pkt, len);
		break;

	default:
		/* Unknown packet type indicator: ignore. */
		break;
	}
}

/* ================================================================== */
/* Asynchronous event injection                                        */
/* ================================================================== */

void
hci_emu_inject_event(struct hci_emu *e, uint8_t evt_code,
    const uint8_t *params, uint8_t plen)
{

	emu_event(e, evt_code, params, plen);
}

/*
 * LE Connection Complete, Vol 4 Part E §7.7.65.1.
 * LE Meta event (0x3E), subevent 0x01.  Params:
 *   Subevent_Code(1)=0x01 | Status(1) | Connection_Handle(2) | Role(1) |
 *   Peer_Address_Type(1) | Peer_Address(6) | Connection_Interval(2) |
 *   Peripheral_Latency(2) | Supervision_Timeout(2) |
 *   Central_Clock_Accuracy(1)  == 19 bytes total.
 */
void
hci_emu_inject_le_connection_complete(struct hci_emu *e, uint8_t status,
    uint16_t handle, uint8_t role, uint8_t peer_addr_type,
    const uint8_t peer_addr[6], uint16_t conn_interval, uint16_t conn_latency,
    uint16_t supervision_timeout, uint8_t central_clock_accuracy)
{
	uint8_t params[1 + sizeof(ng_hci_le_connection_complete_ep)];
	ng_hci_le_connection_complete_ep ep = { 0 };

	params[0] = NG_HCI_LEEV_CON_COMPL;	/* 0x01 */
	ep.status = status;
	ep.handle = htole16(handle);
	ep.role = role;
	ep.address_type = peer_addr_type;
	memcpy(ep.address.b, peer_addr, 6);
	ep.interval = htole16(conn_interval);
	ep.latency = htole16(conn_latency);
	ep.supervision_timeout = htole16(supervision_timeout);
	ep.central_clock_accuracy = central_clock_accuracy;
	memcpy(&params[1], &ep, sizeof(ep));

	emu_event(e, NG_HCI_EVENT_LE, params, sizeof(params));
}

/*
 * LE Advertising Report, Vol 4 Part E §7.7.65.2.
 * LE Meta event (0x3E), subevent 0x02.  Params:
 *   Subevent_Code(1)=0x02 | Num_Reports(1)=1 | then per report:
 *   Event_Type(1) | Address_Type(1) | Address(6) | Data_Length(1) |
 *   Data(Data_Length) | RSSI(1, signed).
 */
void
hci_emu_inject_le_adv_report(struct hci_emu *e, uint8_t evt_type,
    uint8_t addr_type, const uint8_t addr[6], const uint8_t *ad,
    uint8_t adlen, int8_t rssi)
{
	uint8_t params[2 + 1 + 1 + 6 + 1 + 31 + 1];
	size_t o = 0;

	if (adlen > 31)
		adlen = 31;

	params[o++] = NG_HCI_LEEV_ADVREP;	/* 0x02 */
	params[o++] = 1;			/* Num_Reports */
	params[o++] = evt_type;
	params[o++] = addr_type;
	memcpy(&params[o], addr, 6);
	o += 6;
	params[o++] = adlen;
	if (adlen != 0 && ad != NULL) {
		memcpy(&params[o], ad, adlen);
		o += adlen;
	}
	params[o++] = (uint8_t)rssi;

	emu_event(e, NG_HCI_EVENT_LE, params, (uint8_t)o);
}

void
hci_emu_inject_periodic_sync_established(struct hci_emu *e, uint8_t status,
    uint16_t sync_handle, uint8_t sid, uint8_t addr_type,
    const uint8_t addr[6], uint8_t phy, uint16_t interval)
{
	uint8_t p[16] = { NG_HCI_LEEV_PER_ADV_SYNC_EST, status };

	le16enc(p + 2, sync_handle);
	p[4] = sid;
	p[5] = addr_type;
	memcpy(p + 6, addr, 6);
	p[12] = phy;
	le16enc(p + 13, interval);
	p[15] = 0; /* advertiser clock accuracy */
	emu_event(e, NG_HCI_EVENT_LE, p, sizeof(p));
}

void
hci_emu_inject_periodic_adv_report(struct hci_emu *e, uint16_t sync_handle,
    int8_t tx_power, int8_t rssi, uint8_t cte_type, uint8_t data_status,
    const uint8_t *data, uint8_t data_len)
{
	uint8_t p[1 + 7 + NG_HCI_LE_PERIODIC_ADV_DATA_MAX];

	if (data_len > NG_HCI_LE_PERIODIC_ADV_DATA_MAX)
		data_len = NG_HCI_LE_PERIODIC_ADV_DATA_MAX;
	p[0] = NG_HCI_LEEV_PER_ADV_REPORT;
	le16enc(p + 1, sync_handle);
	p[3] = (uint8_t)tx_power;
	p[4] = (uint8_t)rssi;
	p[5] = cte_type;
	p[6] = data_status;
	p[7] = data_len;
	if (data_len != 0 && data != NULL)
		memcpy(p + 8, data, data_len);
	emu_event(e, NG_HCI_EVENT_LE, p, (uint8_t)(8 + data_len));
}

void
hci_emu_inject_periodic_sync_lost(struct hci_emu *e, uint16_t sync_handle)
{
	uint8_t p[3] = { NG_HCI_LEEV_PER_ADV_SYNC_LOST };

	le16enc(p + 1, sync_handle);
	emu_event(e, NG_HCI_EVENT_LE, p, sizeof(p));
}

/*
 * Disconnection Complete, Vol 4 Part E §7.7.5.  Event 0x05:
 *   Status(1) | Connection_Handle(2) | Reason(1).
 */
void
hci_emu_inject_disconnection_complete(struct hci_emu *e, uint16_t handle,
    uint8_t reason)
{
	ng_hci_discon_compl_ep ep = { 0 };

	ep.status = EMU_STATUS_SUCCESS;
	ep.con_handle = htole16(handle);
	ep.reason = reason;
	emu_event(e, NG_HCI_EVENT_DISCON_COMPL, (const uint8_t *)&ep,
	    sizeof(ep));
}

/* ================================================================== */
/* Increment 3: encryption / power-control setters + injectors         */
/* ================================================================== */

void
hci_emu_set_encryption_outcome(struct hci_emu *e, uint8_t status)
{

	e->enc_outcome = status;
}

int
hci_emu_get_conn_encrypted(const struct hci_emu *e, uint16_t handle)
{
	int i;

	for (i = 0; i < EMU_CONN_MAX; i++)
		if (e->conns[i].active && e->conns[i].handle == handle)
			return (e->conns[i].encrypted);
	return (0);
}

void
hci_emu_set_conn_tx_power(struct hci_emu *e, uint16_t handle, int8_t tx_power)
{
	struct emu_conn *c;

	c = emu_conn_by_handle(e, handle);
	if (c != NULL)
		c->tx_power_level = tx_power;
}

void
hci_emu_set_conn_path_loss(struct hci_emu *e, uint16_t handle,
    uint8_t path_loss)
{
	struct emu_conn *c;

	c = emu_conn_by_handle(e, handle);
	if (c != NULL)
		c->path_loss = path_loss;
}

/*
 * Encryption Change, Vol 4 Part E §7.7.8.  Event 0x08:
 *   Status(1) | Connection_Handle(2) | Encryption_Enabled(1).
 */
void
hci_emu_inject_encryption_change(struct hci_emu *e, uint16_t handle,
    uint8_t status, uint8_t enabled)
{
	ng_hci_encryption_change_ep ep = { 0 };

	ep.status = status;
	ep.con_handle = htole16(handle);
	ep.encryption_enable = enabled;
	emu_event(e, NG_HCI_EVENT_ENCRYPTION_CHANGE, (const uint8_t *)&ep,
	    sizeof(ep));
}

/*
 * LE Transmit Power Reporting, Vol 4 Part E §7.7.65.33.
 * LE Meta event (0x3E), subevent 0x21.  Params:
 *   Subevent_Code(1)=0x21 | Status(1) | Connection_Handle(2) | Reason(1) |
 *   PHY(1) | TX_Power_Level(1,signed) | TX_Power_Level_Flag(1) |
 *   Delta(1,signed)  == 9 bytes total.
 */
void
hci_emu_inject_tx_power_report(struct hci_emu *e, uint8_t status,
    uint16_t handle, uint8_t reason, uint8_t phy, int8_t tx_power_level,
    uint8_t tx_power_level_flag, int8_t delta)
{
	uint8_t params[1 + sizeof(ng_hci_le_tx_power_reporting_ep)];
	ng_hci_le_tx_power_reporting_ep ep = { 0 };

	params[0] = NG_HCI_LEEV_TX_POWER_REPORTING;	/* 0x21 */
	ep.status = status;
	ep.connection_handle = htole16(handle);
	ep.reason = reason;
	ep.phy = phy;
	ep.tx_power_level = (uint8_t)tx_power_level;
	ep.tx_power_level_flag = tx_power_level_flag;
	ep.delta = (uint8_t)delta;
	memcpy(&params[1], &ep, sizeof(ep));

	emu_event(e, NG_HCI_EVENT_LE, params, sizeof(params));
}

/*
 * LE Path Loss Threshold, Vol 4 Part E §7.7.65.32.
 * LE Meta event (0x3E), subevent 0x20.  Params:
 *   Subevent_Code(1)=0x20 | Connection_Handle(2) | Current_Path_Loss(1) |
 *   Zone_Entered(1)  == 5 bytes total.
 */
void
hci_emu_inject_path_loss_threshold(struct hci_emu *e, uint16_t handle,
    uint8_t current_path_loss, uint8_t zone_entered)
{
	uint8_t params[1 + sizeof(ng_hci_le_path_loss_threshold_ep)];
	ng_hci_le_path_loss_threshold_ep ep = { 0 };

	params[0] = NG_HCI_LEEV_PATH_LOSS_THRESHOLD;	/* 0x20 */
	ep.connection_handle = htole16(handle);
	ep.current_path_loss = current_path_loss;
	ep.zone_entered = zone_entered;
	memcpy(&params[1], &ep, sizeof(ep));

	emu_event(e, NG_HCI_EVENT_LE, params, sizeof(params));
}
