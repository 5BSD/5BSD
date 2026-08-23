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
 *      with the No-OOB authentication method.
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
	MPS_P_WAIT_CAPS,	/* Invite sent */
	MPS_P_WAIT_PUBKEY,	/* Start + our Public Key sent */
	MPS_P_WAIT_CONFIRM,	/* our Confirmation sent */
	MPS_P_WAIT_RANDOM,	/* our Random sent */
	MPS_P_WAIT_COMPLETE,	/* Data sent */
	/* Device. */
	MPS_D_WAIT_INVITE,
	MPS_D_WAIT_START,	/* Capabilities sent */
	MPS_D_WAIT_PUBKEY,	/* Start received */
	MPS_D_WAIT_CONFIRM,	/* our Public Key sent */
	MPS_D_WAIT_RANDOM,	/* our Confirmation sent */
	MPS_D_WAIT_DATA,	/* our Random sent */
	/* Terminal. */
	MPS_DONE,
	MPS_FAILED,
};

/* Outbound Provisioning PDU FIFO depth (Start + Public Key is the max burst). */
#define	MESH_PROV_SESS_TXQ	4

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

	uint8_t				auth[32];	/* AuthValue (No-OOB) */
	uint8_t				random[32];	/* our Random */
	uint8_t				peer_random[32];
	uint8_t				peer_confirm[32];

	uint8_t				conf_salt[32];
	uint8_t				conf_key[32];

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
