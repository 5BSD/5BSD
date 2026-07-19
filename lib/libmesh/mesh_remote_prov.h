/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Remote Provisioning (MshPRT_v1.1 Section 4.4) and the Remote
 * Provisioning Client / Server models (MshMDL_v1.1 Section 4.4.4 / 4.4.5).
 *
 * Remote Provisioning lets a Provisioner admit an unprovisioned device that is
 * out of its direct radio range by tunnelling the ordinary provisioning
 * exchange of Section 5 through an already-provisioned proxy node: the Remote
 * Provisioning Server.  The Client (co-located with the Provisioner) drives the
 * Server with model messages; the Server runs a local PB-ADV / PB-GATT bearer
 * to the target device on the Client's behalf.  The provisioning protocol
 * itself (mesh_provisioner.[ch]) is unchanged - it emits and consumes raw
 * Provisioning PDUs, and the PB-Remote bearer here carries those PDUs in place
 * of PB-ADV.
 *
 * This module provides:
 *
 *   1. The Remote Provisioning Client / Server model message codecs (the
 *      0x804F..0x805F two-octet opcode block): Scan Capabilities Get/Status,
 *      Scan Get/Start/Stop/Status/Report, Extended Scan Start/Report, Link
 *      Get/Open/Close/Status/Report, PDU Send, PDU Outbound Report and PDU
 *      Report.  Opcodes are emitted big-endian by the access layer; the message
 *      parameters use the field order and endianness of the model tables (OOB
 *      Information big-endian, matching the unprovisioned device beacon).
 *
 *   2. The Remote Provisioning scan state machine (Section 4.4.2): a Server-side
 *      responder that starts/stops scanning on a mock clock, reports discovered
 *      unprovisioned devices (all devices, or a single targeted UUID) up to the
 *      scanned-items limit, and times out; and a Client-side controller that
 *      issues the scan messages and collects the reported UUIDs.
 *
 *   3. The PB-Remote bearer and link state machine (Section 4.4.3): a Client
 *      link that opens a link to a remote unprovisioned device UUID, tunnels
 *      Provisioning PDUs through PDU Send / PDU Report with the inbound /
 *      outbound PDU numbering, and closes with a reason; and the matching
 *      Server link that relays PDUs to/from the device-side bearer.
 *
 * Pure and hardware-free: every codec operates on caller buffers, every timer
 * is driven by a caller-supplied millisecond clock (uint64_t now), and no
 * function reads a real clock or performs I/O.  Each function returns 0 on
 * success and -1 on failure with outputs zeroed on failure, unless documented
 * as a predicate.
 */

#ifndef _MESH_REMOTE_PROV_H_
#define _MESH_REMOTE_PROV_H_

#include <stddef.h>
#include <stdint.h>

#include "mesh_provision.h"

/* ================================================================
 * Remote Provisioning model opcodes (MshMDL_v1.1 Section 4.4.4/4.4.5).  These
 * are two-octet opcodes; mesh_access_pdu_build() places them big-endian.
 * ================================================================ */
#define	MESH_RP_OP_SCAN_CAPABILITIES_GET	0x804FUL
#define	MESH_RP_OP_SCAN_CAPABILITIES_STATUS	0x8050UL
#define	MESH_RP_OP_SCAN_GET			0x8051UL
#define	MESH_RP_OP_SCAN_START			0x8052UL
#define	MESH_RP_OP_SCAN_STOP			0x8053UL
#define	MESH_RP_OP_SCAN_STATUS			0x8054UL
#define	MESH_RP_OP_SCAN_REPORT			0x8055UL
#define	MESH_RP_OP_EXTENDED_SCAN_START		0x8056UL
#define	MESH_RP_OP_EXTENDED_SCAN_REPORT		0x8057UL
#define	MESH_RP_OP_LINK_GET			0x8058UL
#define	MESH_RP_OP_LINK_OPEN			0x8059UL
#define	MESH_RP_OP_LINK_CLOSE			0x805AUL
#define	MESH_RP_OP_LINK_STATUS			0x805BUL
#define	MESH_RP_OP_LINK_REPORT			0x805CUL
#define	MESH_RP_OP_PDU_SEND			0x805DUL
#define	MESH_RP_OP_PDU_OUTBOUND_REPORT		0x805EUL
#define	MESH_RP_OP_PDU_REPORT			0x805FUL

/* ================================================================
 * Status codes (MshMDL_v1.1 Section 4.4.3, Table 4.x).
 * ================================================================ */
#define	MESH_RP_STATUS_SUCCESS				0x00
#define	MESH_RP_STATUS_SCANNING_CANNOT_START		0x01
#define	MESH_RP_STATUS_INVALID_STATE			0x02
#define	MESH_RP_STATUS_LIMITED_RESOURCES		0x03
#define	MESH_RP_STATUS_LINK_CANNOT_OPEN			0x04
#define	MESH_RP_STATUS_LINK_OPEN_FAILED			0x05
#define	MESH_RP_STATUS_LINK_CLOSED_BY_DEVICE		0x06
#define	MESH_RP_STATUS_LINK_CLOSED_BY_SERVER		0x07
#define	MESH_RP_STATUS_LINK_CLOSED_BY_CLIENT		0x08
#define	MESH_RP_STATUS_LINK_CLOSED_CANNOT_RX_PDU	0x09
#define	MESH_RP_STATUS_LINK_CLOSED_CANNOT_TX_PDU	0x0A
#define	MESH_RP_STATUS_LINK_CLOSED_CANNOT_DELIVER	0x0B

/* Remote Provisioning scanning state (Scan Status / Section 4.4.2). */
#define	MESH_RP_SCAN_IDLE			0x00
#define	MESH_RP_SCAN_ACTIVE			0x01
#define	MESH_RP_SCAN_LIMITED			0x02

/* Remote Provisioning link state (Link Status / Report, Section 4.4.3). */
#define	MESH_RP_LINK_IDLE			0x00
#define	MESH_RP_LINK_OPENING			0x01
#define	MESH_RP_LINK_ACTIVE			0x02
#define	MESH_RP_LINK_OUTBOUND_TRANSFER		0x03
#define	MESH_RP_LINK_CLOSING			0x04

/*
 * Link Close reason (Section 4.4.5.4).  Mirrors the PB-ADV Link Close reason
 * codes (Section 5.3.1.2) that the Server forwards to the device.
 */
#define	MESH_RP_LINK_CLOSE_SUCCESS		0x00
#define	MESH_RP_LINK_CLOSE_PROHIBITED		0x01
#define	MESH_RP_LINK_CLOSE_FAIL			0x02

/* Largest tunnelled Provisioning PDU (one Provisioning PDU, no fragmentation). */
#define	MESH_RP_PROV_PDU_MAX			MESH_PROV_PDU_MAX

/* Extended Scan bounds. */
#define	MESH_RP_AD_FILTER_MAX			16
#define	MESH_RP_ADV_DATA_MAX			64

/* Scanned-item bound the Client records from Scan Reports. */
#define	MESH_RP_SCAN_FOUND_MAX			8

/* Encoded-message buffer any Remote Provisioning message fits in. */
#define	MESH_RP_MSG_MAX				(2 + 1 + MESH_RP_PROV_PDU_MAX)

/* ================================================================
 * Model message codecs.  Each build emits a full Access PDU (opcode ||
 * parameters); each parse validates the opcode and length-gates every field.
 * ================================================================ */

/* Scan Capabilities Get (0x804F): no parameters. */
int	mesh_rp_scan_caps_get_build(uint8_t *out, size_t *outlen);

/* Scan Capabilities Status (0x8050): MaxScannedItems(1) || ActiveScan(1). */
struct mesh_rp_scan_caps {
	uint8_t		max_scanned_items;
	uint8_t		active_scan;		/* 0 = passive only, 1 = active */
};
int	mesh_rp_scan_caps_status_build(const struct mesh_rp_scan_caps *in,
	    uint8_t *out, size_t *outlen);
int	mesh_rp_scan_caps_status_parse(const uint8_t *in, size_t inlen,
	    struct mesh_rp_scan_caps *out);

/* Scan Get (0x8051): no parameters. */
int	mesh_rp_scan_get_build(uint8_t *out, size_t *outlen);

/*
 * Scan Start (0x8052): ScannedItemsLimit(1) || Timeout(1) || [UUID(16)].
 * A present UUID makes this a single-device targeted scan.
 */
struct mesh_rp_scan_start {
	uint8_t		scanned_items_limit;
	uint8_t		timeout;		/* seconds, 0x01..0xFF */
	int		has_uuid;
	uint8_t		uuid[16];
};
int	mesh_rp_scan_start_build(const struct mesh_rp_scan_start *in,
	    uint8_t *out, size_t *outlen);
int	mesh_rp_scan_start_parse(const uint8_t *in, size_t inlen,
	    struct mesh_rp_scan_start *out);

/* Scan Stop (0x8053): no parameters. */
int	mesh_rp_scan_stop_build(uint8_t *out, size_t *outlen);

/*
 * Scan Status (0x8054): Status(1) || RPScanningState(1) ||
 * ScannedItemsLimit(1) || Timeout(1).
 */
struct mesh_rp_scan_status {
	uint8_t		status;
	uint8_t		scanning_state;		/* MESH_RP_SCAN_* */
	uint8_t		scanned_items_limit;
	uint8_t		timeout;
};
int	mesh_rp_scan_status_build(const struct mesh_rp_scan_status *in,
	    uint8_t *out, size_t *outlen);
int	mesh_rp_scan_status_parse(const uint8_t *in, size_t inlen,
	    struct mesh_rp_scan_status *out);

/*
 * Scan Report (0x8055): RSSI(1, signed) || UUID(16) || OOBInformation(2, BE) ||
 * [URIHash(4)].
 */
struct mesh_rp_scan_report {
	int8_t		rssi;
	uint8_t		uuid[16];
	uint16_t	oob;			/* big-endian on the wire */
	int		has_uri_hash;
	uint8_t		uri_hash[4];
};
int	mesh_rp_scan_report_build(const struct mesh_rp_scan_report *in,
	    uint8_t *out, size_t *outlen);
int	mesh_rp_scan_report_parse(const uint8_t *in, size_t inlen,
	    struct mesh_rp_scan_report *out);

/*
 * Extended Scan Start (0x8056): ADTypeFilterCount(1) ||
 * ADTypeFilter(ADTypeFilterCount) || [UUID(16) || Timeout(1)].
 */
struct mesh_rp_ext_scan_start {
	uint8_t		ad_type_filter_count;
	uint8_t		ad_types[MESH_RP_AD_FILTER_MAX];
	int		has_uuid;
	uint8_t		uuid[16];
	uint8_t		timeout;		/* seconds, present iff has_uuid */
};
int	mesh_rp_ext_scan_start_build(const struct mesh_rp_ext_scan_start *in,
	    uint8_t *out, size_t *outlen);
int	mesh_rp_ext_scan_start_parse(const uint8_t *in, size_t inlen,
	    struct mesh_rp_ext_scan_start *out);

/*
 * Extended Scan Report (0x8057): Status(1) || UUID(16) ||
 * [OOBInformation(2, BE) || AdvStructures(variable)].  The OOB and adv fields
 * are present together only when Status == Success and adv data was captured.
 */
struct mesh_rp_ext_scan_report {
	uint8_t		status;
	uint8_t		uuid[16];
	int		has_adv;
	uint16_t	oob;			/* big-endian on the wire */
	uint8_t		adv[MESH_RP_ADV_DATA_MAX];
	size_t		adv_len;
};
int	mesh_rp_ext_scan_report_build(const struct mesh_rp_ext_scan_report *in,
	    uint8_t *out, size_t *outlen);
int	mesh_rp_ext_scan_report_parse(const uint8_t *in, size_t inlen,
	    struct mesh_rp_ext_scan_report *out);

/* Link Get (0x8058): no parameters. */
int	mesh_rp_link_get_build(uint8_t *out, size_t *outlen);

/* NPPI Procedure values used when Link Open omits the UUID. */
#define MESH_RP_NPPI_DEVICE_KEY_REFRESH		0x00
#define MESH_RP_NPPI_NODE_ADDRESS_REFRESH	0x01
#define MESH_RP_NPPI_NODE_COMPOSITION_REFRESH	0x02

/*
 * Link Open (0x8059): either UUID(16) || [Timeout(1)], or NPPI Procedure(1).
 * Existing zero-initialized callers select the UUID form.  Set has_nppi to
 * select the mutually exclusive Node Provisioning Protocol Interface form.
 */
struct mesh_rp_link_open {
	uint8_t		uuid[16];
	int		has_timeout;
	uint8_t		timeout;		/* seconds */
	int		has_nppi;
	uint8_t		nppi_procedure;
};
int	mesh_rp_link_open_build(const struct mesh_rp_link_open *in, uint8_t *out,
	    size_t *outlen);
int	mesh_rp_link_open_parse(const uint8_t *in, size_t inlen,
	    struct mesh_rp_link_open *out);

/* Link Close (0x805A): Reason(1). */
int	mesh_rp_link_close_build(uint8_t reason, uint8_t *out, size_t *outlen);
int	mesh_rp_link_close_parse(const uint8_t *in, size_t inlen,
	    uint8_t *reason);

/* Link Status (0x805B): Status(1) || RPState(1). */
struct mesh_rp_link_status {
	uint8_t		status;
	uint8_t		rp_state;		/* MESH_RP_LINK_* */
};
int	mesh_rp_link_status_build(const struct mesh_rp_link_status *in,
	    uint8_t *out, size_t *outlen);
int	mesh_rp_link_status_parse(const uint8_t *in, size_t inlen,
	    struct mesh_rp_link_status *out);

/* Link Report (0x805C): Status(1) || RPState(1) || [Reason(1)]. */
struct mesh_rp_link_report {
	uint8_t		status;
	uint8_t		rp_state;		/* MESH_RP_LINK_* */
	int		has_reason;
	uint8_t		reason;
};
int	mesh_rp_link_report_build(const struct mesh_rp_link_report *in,
	    uint8_t *out, size_t *outlen);
int	mesh_rp_link_report_parse(const uint8_t *in, size_t inlen,
	    struct mesh_rp_link_report *out);

/* PDU Send (0x805D): OutboundPDUNumber(1) || ProvisioningPDU(variable). */
struct mesh_rp_pdu_send {
	uint8_t		outbound_pdu_number;
	uint8_t		prov_pdu[MESH_RP_PROV_PDU_MAX];
	size_t		prov_len;
};
int	mesh_rp_pdu_send_build(const struct mesh_rp_pdu_send *in, uint8_t *out,
	    size_t *outlen);
int	mesh_rp_pdu_send_parse(const uint8_t *in, size_t inlen,
	    struct mesh_rp_pdu_send *out);

/* PDU Outbound Report (0x805E): OutboundPDUNumber(1). */
int	mesh_rp_pdu_outbound_report_build(uint8_t outbound_pdu_number,
	    uint8_t *out, size_t *outlen);
int	mesh_rp_pdu_outbound_report_parse(const uint8_t *in, size_t inlen,
	    uint8_t *outbound_pdu_number);

/* PDU Report (0x805F): InboundPDUNumber(1) || ProvisioningPDU(variable). */
struct mesh_rp_pdu_report {
	uint8_t		inbound_pdu_number;
	uint8_t		prov_pdu[MESH_RP_PROV_PDU_MAX];
	size_t		prov_len;
};
int	mesh_rp_pdu_report_build(const struct mesh_rp_pdu_report *in,
	    uint8_t *out, size_t *outlen);
int	mesh_rp_pdu_report_parse(const uint8_t *in, size_t inlen,
	    struct mesh_rp_pdu_report *out);

/* ================================================================
 * Remote Provisioning scan state machine (Section 4.4.2).
 * ================================================================ */

/* Server-side scan responder. */
struct mesh_rp_scan_server {
	uint8_t		state;			/* MESH_RP_SCAN_* */
	uint8_t		max_scanned_items;	/* capability */
	int		active_scan_supported;
	uint8_t		items_limit;		/* 0 = unlimited */
	uint8_t		timeout;		/* seconds */
	int		has_target;		/* single-device targeted scan */
	uint8_t		target[16];
	uint8_t		reported;		/* items reported so far */
	uint64_t	start_ms;
	uint64_t	deadline_ms;
};

/*
 * Initialise a Server scan responder with its advertised capabilities
 * (max_scanned_items, active_scan_supported).  State is idle.
 */
void	mesh_rp_scan_server_init(struct mesh_rp_scan_server *s,
	    uint8_t max_scanned_items, int active_scan_supported);

/* Fill the Server's Scan Capabilities. */
void	mesh_rp_scan_server_caps(const struct mesh_rp_scan_server *s,
	    struct mesh_rp_scan_caps *out);

/*
 * Handle a Scan Start: begin scanning at now and fill *st with the Scan Status
 * to return.  Returns 0 on success (scanning started), -1 if the request is
 * rejected (st still filled with the failing status).
 */
int	mesh_rp_scan_server_start(struct mesh_rp_scan_server *s,
	    const struct mesh_rp_scan_start *req, uint64_t now,
	    struct mesh_rp_scan_status *st);

/* Handle a Scan Stop: return to idle and fill *st. */
int	mesh_rp_scan_server_stop(struct mesh_rp_scan_server *s, uint64_t now,
	    struct mesh_rp_scan_status *st);

/* Fill *st with the current Scan Status (a Scan Get response). */
void	mesh_rp_scan_server_status(struct mesh_rp_scan_server *s, uint64_t now,
	    struct mesh_rp_scan_status *st);

/*
 * Offer a discovered unprovisioned device to the scanner.  If scanning is
 * active, the device passes the single-device filter (when set) and the limit
 * is not yet reached, *rep is filled with the Scan Report to emit and *emit is
 * set to 1; the reported count advances and, when it reaches the limit, the
 * scan drops to idle.  Returns 0 on success (whether or not a report is
 * emitted), -1 on error.
 */
int	mesh_rp_scan_server_device_seen(struct mesh_rp_scan_server *s,
	    const uint8_t uuid[16], uint16_t oob, int8_t rssi, uint64_t now,
	    struct mesh_rp_scan_report *rep, int *emit);

/*
 * Advance the scan timeout at now.  When the timeout elapses the scan returns
 * to idle.  Returns 1 if the scan just expired (caller may emit a Scan Status),
 * 0 otherwise.
 */
int	mesh_rp_scan_server_tick(struct mesh_rp_scan_server *s, uint64_t now);

/* True while the Server is scanning (active or limited). */
int	mesh_rp_scan_server_scanning(const struct mesh_rp_scan_server *s);

/* Client-side scan controller. */
struct mesh_rp_scan_client {
	int		scanning;
	uint8_t		found[MESH_RP_SCAN_FOUND_MAX][16];
	size_t		nfound;
};

void	mesh_rp_scan_client_init(struct mesh_rp_scan_client *c);

/*
 * Build a Scan Start message.  uuid may be NULL (general scan) or a 16-octet
 * targeted UUID.  Marks the controller scanning.
 */
int	mesh_rp_scan_client_start(struct mesh_rp_scan_client *c,
	    uint8_t scanned_items_limit, uint8_t timeout, const uint8_t uuid[16],
	    uint8_t *out, size_t *outlen);

/* Record a received Scan Report's UUID.  Returns 0, -1 on overflow/error. */
int	mesh_rp_scan_client_on_report(struct mesh_rp_scan_client *c,
	    const struct mesh_rp_scan_report *rep);

/* True if the Client has recorded the given UUID from a Scan Report. */
int	mesh_rp_scan_client_found(const struct mesh_rp_scan_client *c,
	    const uint8_t uuid[16]);

/* Build a Scan Stop message and clear the scanning flag. */
int	mesh_rp_scan_client_stop(struct mesh_rp_scan_client *c, uint8_t *out,
	    size_t *outlen);

/* ================================================================
 * PB-Remote bearer / link state machine (Section 4.4.3).
 * ================================================================ */

/* Client link: drives a remote provisioning link through a Server. */
struct mesh_rp_client_link {
	uint8_t		state;			/* MESH_RP_LINK_* */
	uint8_t		device_uuid[16];
	int		has_nppi;
	uint8_t		nppi_procedure;
	uint8_t		outbound_pdu_number;	/* next PDU Send number */
	uint8_t		inbound_pdu_number;	/* last PDU Report number seen */
	int		have_inbound;
	int		awaiting_outbound_report;
	uint8_t		last_reason;		/* reason of the last close */
	uint64_t	open_ms;
	uint64_t	open_deadline_ms;
};

void	mesh_rp_client_link_init(struct mesh_rp_client_link *l);

/*
 * Build a Link Open message for device_uuid and move to OPENING.  timeout is
 * the link-open timeout in seconds (0 => omit the field); open_timeout_ms is
 * the mock-clock budget after which the link is declared failed.
 */
int	mesh_rp_client_link_open(struct mesh_rp_client_link *l,
	    const uint8_t device_uuid[16], uint8_t timeout,
	    uint64_t open_timeout_ms, uint64_t now, uint8_t *out, size_t *outlen);

/* Open the Node Provisioning Protocol Interface for an NPPI procedure. */
int	mesh_rp_client_link_open_nppi(struct mesh_rp_client_link *l,
	    uint8_t procedure, uint64_t open_timeout_ms, uint64_t now,
	    uint8_t *out, size_t *outlen);

/* Apply a received Link Status.  Returns 0, -1 on error. */
int	mesh_rp_client_link_on_status(struct mesh_rp_client_link *l,
	    const struct mesh_rp_link_status *st);

/* Apply a received Link Report.  Returns 0, -1 on error. */
int	mesh_rp_client_link_on_report(struct mesh_rp_client_link *l,
	    const struct mesh_rp_link_report *rp);

/*
 * Tunnel one outbound Provisioning PDU: build a PDU Send with the current
 * outbound PDU number, advance the number, and await the PDU Outbound Report.
 * Fails unless the link is active and no send is outstanding.
 */
int	mesh_rp_client_link_send_pdu(struct mesh_rp_client_link *l,
	    const uint8_t *prov_pdu, size_t len, uint8_t *out, size_t *outlen);

/* Apply a received PDU Outbound Report (clears the outstanding send). */
int	mesh_rp_client_link_on_outbound_report(struct mesh_rp_client_link *l,
	    uint8_t outbound_pdu_number);

/*
 * Apply a received PDU Report: deliver the tunnelled Provisioning PDU to
 * prov_pdu/len (buffers of MESH_RP_PROV_PDU_MAX) and record the inbound number.
 * Returns 0, -1 on error.
 */
int	mesh_rp_client_link_on_pdu_report(struct mesh_rp_client_link *l,
	    const struct mesh_rp_pdu_report *rp, uint8_t *prov_pdu, size_t *len);

/* Build a Link Close with reason and move to CLOSING. */
int	mesh_rp_client_link_close(struct mesh_rp_client_link *l, uint8_t reason,
	    uint8_t *out, size_t *outlen);

/*
 * Advance the open timeout at now.  Returns 1 if the link-open budget just
 * elapsed without reaching ACTIVE (link declared idle/failed), 0 otherwise.
 */
int	mesh_rp_client_link_tick(struct mesh_rp_client_link *l, uint64_t now);

/* Predicates. */
int	mesh_rp_client_link_is_active(const struct mesh_rp_client_link *l);
int	mesh_rp_client_link_idle(const struct mesh_rp_client_link *l);

/* Server link: relays PDUs between the Client and the device-side bearer. */
struct mesh_rp_server_link {
	uint8_t		state;			/* MESH_RP_LINK_* */
	uint8_t		device_uuid[16];
	int		has_nppi;
	uint8_t		nppi_procedure;
	uint8_t		inbound_pdu_number;	/* last PDU Report number */
	uint8_t		outbound_pdu_number;	/* last PDU Send number seen */
	int		have_outbound;
	int		outbound_pending;
	uint8_t		pending_outbound_pdu_number;
	uint8_t		link_close_status;
	int		has_link_close_reason;
	uint8_t		link_close_reason;
};

void	mesh_rp_server_link_init(struct mesh_rp_server_link *s);

/*
 * Handle a Link Open: adopt the target UUID, move to OPENING, and fill *st with
 * the Link Status to return.  Returns 0 on success, -1 if rejected (st still
 * filled with the failing status).
 */
int	mesh_rp_server_link_on_open(struct mesh_rp_server_link *s,
	    const struct mesh_rp_link_open *op, struct mesh_rp_link_status *st);

/*
 * The device-side bearer (PB-ADV/PB-GATT) to the target is established: move to
 * ACTIVE and fill *rp with the Link Report (state ACTIVE) to emit.  Returns 0,
 * -1 if not OPENING.
 */
int	mesh_rp_server_link_bearer_open(struct mesh_rp_server_link *s,
	    struct mesh_rp_link_report *rp);

/*
 * Handle a PDU Send from the Client.  A new sequential PDU is copied to
 * prov_pdu/len and returns 0.  A duplicate/out-of-order number is not
 * delivered: *len is zero, *outrep reports the current count, and 1 is
 * returned.  For a new PDU, *outrep is only the prospective number; it shall
 * not be transmitted until mesh_rp_server_link_pdu_delivered() succeeds.
 * Returns -1 on an invalid argument or state.
 */
int	mesh_rp_server_link_on_pdu_send(struct mesh_rp_server_link *s,
	    const struct mesh_rp_pdu_send *snd, uint8_t *prov_pdu, size_t *len,
	    uint8_t *outrep);

/* Commit or fail the pending device/local delivery.  Success advances the
 * count, restores Link Active, and returns the report number.  Failure leaves
 * the count unchanged and moves PB-Remote to Link Closing; for NPPI it closes
 * immediately and fills failure_report with the Link Report to transmit. */
int	mesh_rp_server_link_pdu_delivered(struct mesh_rp_server_link *s,
	    int success, uint8_t *outrep,
	    struct mesh_rp_link_report *failure_report);

/* Complete a server-initiated PB-Remote bearer close and return the deferred
 * Link Report.  reason may be negative when the bearer supplied no reason. */
int	mesh_rp_server_link_bearer_closed(struct mesh_rp_server_link *s,
	    int reason, struct mesh_rp_link_report *rp);

/*
 * The device returned a Provisioning PDU: advance the inbound count and build
 * a PDU Report carrying the new count.  Returns 0, -1 on
 * error.
 */
int	mesh_rp_server_link_report_pdu(struct mesh_rp_server_link *s,
	    const uint8_t *prov_pdu, size_t len, struct mesh_rp_pdu_report *out);

/*
 * Handle a Link Close with reason: move to idle and fill *rp with the Link
 * Report (state IDLE, the close reason mapped to a status).  Returns 0, -1.
 */
int	mesh_rp_server_link_on_close(struct mesh_rp_server_link *s,
	    uint8_t reason, struct mesh_rp_link_report *rp);

/* Fill *st with the Server link's current Link Status. */
void	mesh_rp_server_link_status(const struct mesh_rp_server_link *s,
	    struct mesh_rp_link_status *st);

int	mesh_rp_server_link_is_active(const struct mesh_rp_server_link *s);

#endif /* _MESH_REMOTE_PROV_H_ */
