/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh driven provisioning roles.  MshPRT_v1.1 Section 5.
 *
 * mesh_provision.[ch] provides the provisioning PDU codec, the ECDH P-256 and
 * the security functions; this module drives them as a running protocol.  Two
 * layers:
 *
 *   1. The provisioning protocol session (struct mesh_prov_session): a role
 *      (Provisioner or Device) state machine over the Provisioning PDUs of
 *      Section 5.4.1.  Fed one inbound PDU at a time, it derives the shared
 *      secret and security material and enqueues the outbound PDUs of the
 *      exchange - Invite, Capabilities, Start, Public Key, Confirmation, Random,
 *      Data and Complete - ending with both sides holding the same DevKey and
 *      the device holding the handed-over NetKey / IV Index / unicast address.
 *      The engine implements algorithms 0x00 (CMAC) and 0x01 (HMAC-SHA-256)
 *      with all four authentication methods of Table 5.31: No OOB (0x00),
 *      Static OOB (0x01), Output OOB (0x02) and Input OOB (0x03).  The two
 *      operator-driven methods run over the prompt interface below
 *      (mesh_prov_session_oob_prompt / _oob_input): the session tells the
 *      caller what to display or to collect, and stalls the exchange until it
 *      is answered.  A method the local side cannot satisfy is refused, never
 *      silently downgraded to an unauthenticated one.
 *
 *   2. The PB-ADV link / transaction layer (struct mesh_prov_link): the Section
 *      5.2 / 5.3.1 bearer - Link Open / Ack / Close, per-direction transaction
 *      numbers, Generic Provisioning segmentation and reassembly, Transaction
 *      Acknowledgment and timed retransmission - all on the injected clock.
 *
 * Pure and hardware-free apart from the ECDH key pair (an OpenSSL handle freed
 * by mesh_prov_session_free()); no I/O, no globals, no real clock.
 */

#ifndef _MESH_PROVISIONER_H_
#define _MESH_PROVISIONER_H_

#include <stddef.h>
#include <stdint.h>

#include "mesh_prov_cert.h"
#include "mesh_prov_records.h"
#include "mesh_provision.h"

/* ================================================================
 * Provisioning protocol session.  MshPRT_v1.1 Section 5.4.
 * ================================================================ */

enum mesh_prov_role {
	MESH_PROV_ROLE_PROVISIONER = 0,
	MESH_PROV_ROLE_DEVICE = 1,
};

enum mesh_prov_sess_state {
	/* Provisioner. */
	MPS_P_IDLE = 0,
	/*
	 * Certificate-based provisioning (Section 5.5) retrieves the device's
	 * certificate chain as provisioning records first.  Both retrieval
	 * PDUs are exchanged BEFORE the Provisioning Invite PDU (Sections
	 * 5.4.2.6.1 and 5.4.2.6.2), one at a time: "The Provisioner shall not
	 * send a new PDU until it has received a [response] to the previously
	 * sent request."
	 */
	MPS_P_WAIT_RECORDS_LIST,	/* Records Get sent */
	MPS_P_WAIT_RECORD_RSP,		/* Record Request sent */
	MPS_P_WAIT_CAPS,	/* Invite sent */
	MPS_P_WAIT_PUBKEY,	/* Start + our Public Key sent */
	/*
	 * Output OOB (Section 5.4.2.4.3): the Provisionee is displaying its
	 * value and the exchange is stalled until the operator hands it to
	 * mesh_prov_session_oob_input().
	 */
	MPS_P_WAIT_OOB_INPUT,
	/*
	 * Input OOB (Section 5.4.2.4.4): we displayed the value, the operator
	 * is entering it on the Provisionee, and we hold our Confirmation back
	 * until the Provisioning Input Complete PDU arrives.
	 */
	MPS_P_WAIT_INPUT_COMPLETE,
	MPS_P_WAIT_CONFIRM,	/* our Confirmation sent */
	MPS_P_WAIT_RANDOM,	/* our Random sent */
	MPS_P_WAIT_COMPLETE,	/* Data sent */
	/* Device. */
	MPS_D_WAIT_INVITE,
	MPS_D_WAIT_START,	/* Capabilities sent */
	MPS_D_WAIT_PUBKEY,	/* Start received */
	/*
	 * Input OOB (Section 5.4.2.4.4): our Public Key is sent and the
	 * operator is entering the value the Provisioner displayed; the
	 * Provisioning Input Complete PDU follows the input, not the Public
	 * Key exchange.
	 */
	MPS_D_WAIT_OOB_INPUT,
	MPS_D_WAIT_CONFIRM,	/* our Public Key sent */
	MPS_D_WAIT_RANDOM,	/* our Confirmation sent */
	MPS_D_WAIT_DATA,	/* our Random sent */
	/* Terminal. */
	MPS_DONE,
	MPS_FAILED,
};

/* Outbound Provisioning PDU FIFO depth (Start + Public Key is the max burst). */
#define	MESH_PROV_SESS_TXQ	4

/*
 * Operator-driven OOB authentication (MshPRT_v1.1.1 Sections 5.4.1.3,
 * 5.4.2.4.3 and 5.4.2.4.4).
 *
 * Which side shows the value and which side types it is fixed by the method,
 * not by the role, and the two methods are mirror images:
 *
 *   - Output OOB (0x02): the PROVISIONEE generates the value and outputs it
 *     (blink / beep / vibrate / display), and the user of the PROVISIONER
 *     types what was observed.  So a Provisioner session raises an INPUT
 *     prompt and a Device session raises a DISPLAY prompt.
 *   - Input OOB (0x03): the PROVISIONER generates the value and shows it to
 *     its user, who enters it on the PROVISIONEE; the Provisionee announces
 *     the completed entry with a Provisioning Input Complete PDU.  So a
 *     Provisioner session raises a DISPLAY prompt and a Device session raises
 *     an INPUT prompt.
 *
 * A DISPLAY prompt is informational: the session already holds the AuthValue
 * and only needs the caller to show `value` to a human.  An INPUT prompt
 * stalls the exchange until mesh_prov_session_oob_input() supplies the peer's
 * value.
 */
enum mesh_prov_oob_prompt_kind {
	MESH_PROV_OOB_PROMPT_NONE = 0,
	MESH_PROV_OOB_PROMPT_DISPLAY,	/* show `value` to the operator */
	MESH_PROV_OOB_PROMPT_INPUT,	/* collect the peer's value */
};

/* Methods this side is willing to drive (see _set_oob_methods). */
#define	MESH_PROV_OOB_ALLOW_OUTPUT	0x01
#define	MESH_PROV_OOB_ALLOW_INPUT	0x02

/* Value text: at most MESH_PROV_OOB_SIZE_MAX characters, NUL-terminated. */
#define	MESH_PROV_OOB_VALUE_MAX		(MESH_PROV_OOB_SIZE_MAX + 1)

struct mesh_prov_oob_prompt {
	enum mesh_prov_oob_prompt_kind	kind;
	uint8_t		method;		/* 0x02 Output OOB / 0x03 Input OOB */
	uint8_t		action;		/* Table 5.32 / Table 5.34 */
	uint8_t		size;		/* Table 5.33 / Table 5.35 */
	int		alphanumeric;	/* data type: 1 alnum, 0 numeric */
	char		value[MESH_PROV_OOB_VALUE_MAX];	/* DISPLAY only */
};

struct mesh_prov_session {
	enum mesh_prov_role		role;
	enum mesh_prov_sess_state	state;
	uint8_t				error;		/* Failed ErrorCode */

	struct mesh_prov_keypair	kp;		/* our key pair */
	int				have_kp;
	uint8_t				our_pub[64];
	uint8_t				peer_pub[64];
	uint8_t				ecdh[32];

	uint8_t				attention;	/* Invite Attention Duration */
	struct mesh_prov_caps		caps;		/* device: advertised caps */
	uint8_t				algorithm;	/* negotiated algorithm */

	/* ConfirmationInputs pieces (parameter octets, no Type). */
	uint8_t				invite_val[MESH_PROV_INVITE_VAL_LEN];
	uint8_t				caps_val[MESH_PROV_CAPS_VAL_LEN];
	uint8_t				start_val[MESH_PROV_START_VAL_LEN];

	/*
	 * AuthValue (Section 5.4.2.4.1) for the selected authentication
	 * method, and the Static OOB value it is derived from when the method
	 * is 0x01.  The AuthValue width follows the negotiated algorithm (128
	 * bits for CMAC, 256 for HMAC-SHA-256), so it is (re)computed once the
	 * algorithm is fixed rather than at init time.
	 */
	uint8_t				auth[32];
	uint8_t				static_oob[32];
	size_t				static_oob_len;
	int				have_static_oob;
	/*
	 * Operator-driven OOB authentication state (Sections 5.4.2.4.3 /
	 * 5.4.2.4.4): the methods this side may drive, the method / Action /
	 * Size the Start committed to, the pending operator prompt and the
	 * value shown or collected for it.  oob_wait_* is the Input Complete /
	 * operator timeout clock, started on the first tick spent stalled.
	 */
	unsigned			oob_allow;
	uint8_t				oob_method;	/* 0 when unused */
	uint8_t				oob_action;
	uint8_t				oob_size;
	int				oob_alnum;
	enum mesh_prov_oob_prompt_kind	oob_prompt;
	int				oob_have_value;
	char				oob_value[MESH_PROV_OOB_VALUE_MAX];
	int				oob_wait_started;
	uint64_t			oob_wait_start_ms;
	uint8_t				our_confirm[32];	/* anti-reflection */
	uint8_t				random[32];	/* our Random */
	uint8_t				peer_random[32];
	uint8_t				peer_confirm[32];

	uint8_t				conf_salt[32];
	uint8_t				conf_key[32];

	/*
	 * Certificate-based provisioning (Section 5.5) and the provisioning
	 * record retrieval that feeds it (Section 5.4.2.6).  cert_mode is the
	 * operator's opt-in; cert_policy is the trust anchor and the identity
	 * the certificate must bind; records holds every record retrieved;
	 * plan/plan_cur is the retrieval order (Base URI, Device Certificate,
	 * then the intermediates in the ascending order Section 5.4.2.6.5
	 * requires); cert_result is the verdict, which the operator reads.
	 * have_oob_pubkey marks peer_pub as an OOB Public Key obtained from a
	 * validated Device Certificate rather than from a Public Key PDU.
	 */
	unsigned			cert_mode;
	struct mesh_prov_cert_policy	cert_policy;
	struct mesh_prov_cert_result	cert_result;
	int				have_oob_pubkey;
	struct mesh_prov_record_store	records;
	struct mesh_prov_record_fetch	fetch;
	uint16_t			rec_ids[MESH_PROV_RECORD_SLOTS];
	size_t				rec_nids;
	uint16_t			rec_extensions;
	uint16_t			rec_plan[MESH_PROV_RECORD_SLOTS];
	size_t				rec_nplan;
	size_t				rec_cur;

	/* Provisioner: the data to hand over.  Device: the received data. */
	struct mesh_prov_data		data;
	int				have_data;

	/* Derived results. */
	uint8_t				session_key[16];
	uint8_t				session_nonce[13];
	uint8_t				devkey[16];
	int				provisioned;	/* device: data installed */

	/* Outbound PDU queue. */
	uint8_t				txq[MESH_PROV_SESS_TXQ][MESH_PROV_PDU_MAX];
	size_t				txq_len[MESH_PROV_SESS_TXQ];
	size_t				txq_head;
	size_t				txq_tail;
};

/*
 * Initialise a Provisioner session.  priv (if non-NULL) is a fixed 32-octet
 * private key (else a fresh key pair is generated); random is our 32-octet
 * Provisioning Random (if non-NULL, else generated); attention is the Invite
 * Attention Duration; data is the provisioning data (NetKey / index / flags /
 * IV Index / unicast address) to hand the device.  Returns 0, -1 on error.
 */
int	mesh_prov_provisioner_init(struct mesh_prov_session *s,
	    const uint8_t priv[32], const uint8_t random[32], uint8_t attention,
	    const struct mesh_prov_data *data);

/*
 * Initialise a Device session with the capabilities to advertise.  priv /
 * random as above.  Returns 0, -1 on error.
 */
int	mesh_prov_device_init(struct mesh_prov_session *s, const uint8_t priv[32],
	    const uint8_t random[32], const struct mesh_prov_caps *caps);

/*
 * Install the Static OOB authentication value (Section 5.4.1.3 Authentication
 * Method 0x01), obtained from the device out of band - printed on the label,
 * shipped in the carton, read from an NFC tag.  Call it after the role init
 * and before the exchange starts.  Both roles use it:
 *
 *   - a Provisioner that holds one selects Static OOB in Provisioning Start
 *     whenever the device's Capabilities advertise Static OOB (OOB Type bit 0);
 *   - a Provisionee that holds one accepts a Start selecting Static OOB, and
 *     rejects one when it does not (the AuthValue would not match and the
 *     exchange would fail later, at Confirmation, with a misleading error).
 *
 * value is the authentication value as an octet array of data type Binary; it
 * is copied left-aligned and zero-padded, or trimmed, to the AuthValue width of
 * the negotiated algorithm (Section 5.4.2.4.1).  len must be 1..32.  Passing
 * NULL clears the value and returns the session to No-OOB.  Returns 0, -1 on
 * error.
 */
int	mesh_prov_session_set_static_oob(struct mesh_prov_session *s,
	    const uint8_t *value, size_t len);

/*
 * Declare which operator-driven OOB authentication methods this side is
 * willing to drive: the bitwise OR of MESH_PROV_OOB_ALLOW_OUTPUT and
 * MESH_PROV_OOB_ALLOW_INPUT, or 0 (the default) for neither.  Call it after
 * the role init and before the exchange starts.
 *
 * It gates the PROVISIONER's method selection only: a Provisioner picks Output
 * or Input OOB in Provisioning Start when the Provisionee's Capabilities
 * advertise the matching size / Action AND the operator has opted in here, so
 * an unattended daemon is never stalled waiting for a human that is not there.
 * The DEVICE role needs no opt-in - advertising a non-zero Output/Input OOB
 * Size in its Capabilities is the opt-in, and it accepts a Start selecting
 * only what it advertised.
 *
 * Returns 0, -1 on error (bad bits, or the exchange has already started).
 */
int	mesh_prov_session_set_oob_methods(struct mesh_prov_session *s,
	    unsigned allow);

/*
 * Certificate-based provisioning (MshPRT_v1.1.1 Section 5.5), Provisioner
 * side.  MESH_PROV_CERT_MODE_RETRIEVE makes the session retrieve the device's
 * provisioning records over the bearer before it sends the Provisioning Invite
 * PDU, validate the Device Certificate found there against `pol`, and use the
 * public key it contains as the device's OOB Public Key -- Provisioning Start
 * carries Public Key 0x01 and the device never transmits its key over the
 * bearer (Section 5.4.2.3).
 *
 * MESH_PROV_CERT_MODE_REQUIRE additionally refuses to provision a device that
 * cannot supply a usable certificate: Section 5.4.2.3 lets a Provisioner
 * require OOB Public Key retrieval, and "if the Provisioner has requirements
 * that the Provisionee does not meet ... the provisioning protocol shall
 * fail".
 *
 * Downgrade rule, and it is not conditional on REQUIRE: once a Device
 * Certificate has been retrieved, it is validated and used or the session
 * fails.  A certificate that fails path validation, that names another
 * device, or that a Provisionee will not accept as an OOB Public Key never
 * turns into an unauthenticated exchange -- silently weakening an
 * authenticated method is a security defect, not a fallback.
 *
 * Call it after mesh_prov_provisioner_init() and before
 * mesh_prov_session_start().  Returns 0, -1 on the wrong role or state, an
 * unknown mode bit, or REQUIRE/RETRIEVE without a policy.
 */
#define	MESH_PROV_CERT_MODE_RETRIEVE	0x01
#define	MESH_PROV_CERT_MODE_REQUIRE	0x02
int	mesh_prov_session_set_cert_policy(struct mesh_prov_session *s,
	    unsigned mode, const struct mesh_prov_cert_policy *pol);

/*
 * The certificate verdict of the session, or NULL.  Valid from the moment the
 * retrieval finishes; res->verdict is MESH_PROV_CERT_OK only when the OOB
 * Public Key in it was actually adopted.
 */
const struct mesh_prov_cert_result *mesh_prov_session_cert_result(
	    const struct mesh_prov_session *s);

/*
 * The Record IDs the Provisionee reported in its Provisioning Records List
 * (Section 5.4.1.14), and the Provisioning Extensions bitmask that came with
 * them.  Returns the number of IDs written (<= max), 0 before a list has been
 * received.
 */
size_t	mesh_prov_session_records_list(const struct mesh_prov_session *s,
	    uint16_t *ids, size_t max, uint16_t *extensions);

/*
 * One retrieved record's data, or NULL when that record was not retrieved.
 * The pointer is into the session and lives as long as it does.
 */
const uint8_t *mesh_prov_session_record(const struct mesh_prov_session *s,
	    uint16_t record_id, size_t *len);

/*
 * Read the pending operator prompt.  Returns 1 with *out filled when the
 * session wants something shown to, or collected from, a human; 0 when it
 * does not; -1 on error.  A DISPLAY prompt stays readable until the exchange
 * moves past the authentication step, so a late-connecting operator interface
 * can still render it.
 */
int	mesh_prov_session_oob_prompt(const struct mesh_prov_session *s,
	    struct mesh_prov_oob_prompt *out);

/*
 * Supply the value the peer displayed, answering a MESH_PROV_OOB_PROMPT_INPUT
 * prompt.  `value` is NUL-terminated text: decimal digits for a Numeric data
 * type (shorter than the Authentication Size is accepted and left-padded with
 * zeros, as leading zeros are output but need not be typed), or exactly
 * Authentication Size characters from [0-9A-Z] for an Alphanumeric one.
 *
 * The AuthValue is derived from it (Section 5.4.2.4.1) and the stalled
 * exchange resumes: a Provisioner sends its Provisioning Confirmation, a
 * Provisionee sends the Provisioning Input Complete PDU and then answers the
 * Confirmation.  It may also be called before the stall is reached, in which
 * case the value is simply remembered.  Returns 0, -1 if there is no input
 * prompt or the value does not match the negotiated Action / Size.
 */
int	mesh_prov_session_oob_input(struct mesh_prov_session *s,
	    const char *value);

/*
 * Deadline for a stalled authentication step: the operator supplying the value
 * the peer displayed, and the Provisioner waiting for the Provisioning Input
 * Complete PDU that follows the entry on the Provisionee.  MshPRT_v1.1.1
 * Section 5.4.4 gives the provisioning protocol timer a minimum of 60 s and
 * requires the link to be closed when it expires; the authentication step is
 * the one place where the peer is legitimately silent for that long, so it
 * gets an explicit timer of the same length rather than relying on the bearer
 * to notice.
 */
#define	MESH_PROV_INPUT_COMPLETE_TIMEOUT_MS	60000

/*
 * Advance the operator / Input Complete timeout on a stalled session (see
 * MESH_PROV_INPUT_COMPLETE_TIMEOUT_MS).  `now` is the caller's monotonic
 * millisecond clock; the timer starts on the first tick spent stalled.
 * Returns 0 when the session is not stalled or the deadline has not passed,
 * and -1 when it has: the session moves to FAILED and enqueues a Provisioning
 * Failed PDU, exactly like any other protocol error.
 */
int	mesh_prov_session_tick(struct mesh_prov_session *s, uint64_t now);

/* Release the session's ECDH key pair (safe on a zeroed session). */
void	mesh_prov_session_free(struct mesh_prov_session *s);

/*
 * Provisioner only: begin the exchange by enqueuing the Provisioning Invite.
 * Returns 0, -1 on error or the wrong role/state.
 */
int	mesh_prov_session_start(struct mesh_prov_session *s);

/*
 * Feed one inbound Provisioning PDU (Type octet + parameters).  Advances the
 * state machine and enqueues any outbound PDUs (drain them with
 * mesh_prov_session_poll).  Returns 0 on success, -1 on a protocol error (the
 * session moves to FAILED and a Failed PDU is enqueued).
 */
int	mesh_prov_session_recv(struct mesh_prov_session *s, const uint8_t *pdu,
	    size_t len);

/*
 * Dequeue the next outbound Provisioning PDU.  Returns 1 with out/outlen
 * filled, 0 if the queue is empty, -1 on error.
 */
int	mesh_prov_session_poll(struct mesh_prov_session *s, uint8_t *out,
	    size_t *outlen);

/* Terminal-state predicates and result accessors. */
int	mesh_prov_session_done(const struct mesh_prov_session *s);
int	mesh_prov_session_failed(const struct mesh_prov_session *s);
const uint8_t	*mesh_prov_session_devkey(const struct mesh_prov_session *s);
uint8_t		mesh_prov_session_num_elements(
		    const struct mesh_prov_session *s);
/* Device: copy the installed provisioning data.  Returns 0, -1 if not provisioned. */
int	mesh_prov_session_get_data(const struct mesh_prov_session *s,
	    struct mesh_prov_data *out);

/* ================================================================
 * PB-ADV link / transaction layer.  MshPRT_v1.1 Section 5.2 / 5.3.1.
 * ================================================================ */

enum mesh_prov_link_state {
	MESH_LINK_CLOSED = 0,
	MESH_LINK_OPENING,	/* provisioner: Link Open sent, awaiting Link Ack */
	MESH_LINK_OPEN,		/* link established */
	MESH_LINK_FAILED,	/* retransmission budget exhausted / timed out */
};

/*
 * Mandatory PB-ADV provisioning timers (MshPRT_v1.1 Section 5.3.1.4.1 /
 * 5.4.4).  All three are 60 s: the link-establishment timer (Provisioner:
 * Link Open to Link Ack), the link timer (no bearer PDU received on an open
 * link) and the provisioning protocol timer (no Provisioning PDU delivered).
 * A silent peer trips one of these and the link is declared FAILED.
 */
#define	MESH_PROV_LINK_ESTABLISH_TIMEOUT_MS	60000
#define	MESH_PROV_LINK_TIMEOUT_MS		60000
#define	MESH_PROV_PROTOCOL_TIMEOUT_MS		60000

struct mesh_prov_link {
	enum mesh_prov_role	role;
	enum mesh_prov_link_state state;
	uint32_t		link_id;
	uint8_t			device_uuid[16];

	uint8_t			tx_txn;		/* our next transaction number */
	int			rx_have;	/* a transaction has been delivered */
	uint8_t			rx_txn;		/* last delivered transaction number */

	/* Outbound transaction: the segmented Generic Provisioning PDUs. */
	struct mesh_gp_pdu	segs[MESH_GP_SEG_MAX];
	size_t			nseg;
	size_t			seg_cursor;	/* next segment to emit */
	int			awaiting_ack;	/* full transaction sent, need Ack */
	int			open_pending;	/* provisioner: Link Open to (re)send */
	uint64_t		last_tx_ms;
	uint64_t		last_rx_ms;	/* last bearer PDU received (link timer) */
	uint64_t		link_start_ms;	/* Link Open sent (establishment timer) */
	uint64_t		proto_start_ms;	/* last Provisioning PDU delivered */
	uint32_t		retry_interval_ms;
	unsigned		retries;
	unsigned		max_retries;

	struct mesh_gp_reasm	reasm;		/* inbound reassembly */
};

/*
 * Initialise the link layer.  retry_interval_ms is the retransmission timeout;
 * max_retries bounds the retransmissions before the link is declared FAILED.
 * The provisioner picks link_id and targets device_uuid; the device adopts the
 * Provisioner's link_id from the received Link Open.
 */
void	mesh_prov_link_init_provisioner(struct mesh_prov_link *l,
	    uint32_t link_id, const uint8_t device_uuid[16],
	    uint32_t retry_interval_ms, unsigned max_retries);
void	mesh_prov_link_init_device(struct mesh_prov_link *l,
	    const uint8_t device_uuid[16], uint32_t retry_interval_ms,
	    unsigned max_retries);

/*
 * Provisioner: open the link (build a Link Open PB-ADV packet, state OPENING).
 * Returns 0, -1 on error or the wrong role.
 */
int	mesh_prov_link_open(struct mesh_prov_link *l, uint64_t now, uint8_t *out,
	    size_t *outlen);

/* Build a Link Close PB-ADV packet with the given reason.  Returns 0, -1. */
int	mesh_prov_link_close(struct mesh_prov_link *l, uint8_t reason,
	    uint8_t *out, size_t *outlen);

/*
 * Queue a Provisioning PDU for transmission as one transaction (segments it and
 * assigns the current transaction number).  Fails if a transaction is still
 * awaiting acknowledgment or the link is not open.  Returns 0, -1 on error.
 */
int	mesh_prov_link_send(struct mesh_prov_link *l, const uint8_t *prov_pdu,
	    size_t len, uint64_t now);

/*
 * Emit the next outbound bearer packet: the pending Link Open, the next unsent
 * segment of the current transaction, or - once the retransmission timeout has
 * elapsed with no Ack - a retransmission of the whole transaction.  Returns 1
 * with out/outlen filled, 0 if nothing is due now, -1 if the retransmission
 * budget is exhausted (link FAILED).
 */
int	mesh_prov_link_poll(struct mesh_prov_link *l, uint64_t now, uint8_t *out,
	    size_t *outlen);

/*
 * Feed a received bearer packet (a full PB-ADV packet: LinkID || Transaction ||
 * Generic Provisioning PDU).  Effects, by content:
 *   - Link Open (device): adopt the link_id, open the link, emit a Link Ack;
 *   - Link Ack (provisioner): mark the link open;
 *   - Link Close: close the link;
 *   - Transaction Ack matching our transaction: clear awaiting-ack, advance the
 *     transaction number;
 *   - Transaction segments: reassemble; on completion copy the Provisioning PDU
 *     to pdu/pdu_len (*have_pdu = 1) and emit a Transaction Ack (*have_ack = 1).
 * out arguments may be NULL if the caller does not expect that output.  Returns
 * 0 on success, -1 on error.
 */
int	mesh_prov_link_recv(struct mesh_prov_link *l, const uint8_t *pkt,
	    size_t len, uint64_t now, uint8_t *pdu, size_t *pdu_len, int *have_pdu,
	    uint8_t *ack, size_t *acklen, int *have_ack);

/* True once the link is OPEN. */
int	mesh_prov_link_is_open(const struct mesh_prov_link *l);

/*
 * True when the link is OPEN and no transaction is in flight - i.e. a new
 * mesh_prov_link_send() will be accepted.  Callers gate feeding the next
 * Provisioning PDU on this so a PDU is not dequeued while a transaction is
 * still awaiting its Acknowledgment.
 */
int	mesh_prov_link_idle(const struct mesh_prov_link *l);

#endif /* _MESH_PROVISIONER_H_ */
