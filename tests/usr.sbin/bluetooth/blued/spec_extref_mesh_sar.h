/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * EXTERNAL REFERENCE ORACLE: Bluetooth Mesh segmentation and reassembly --
 * the Mesh 1.1 SAR Transmitter and SAR Receiver composite states with their
 * formulas and default values, the Segment Acknowledgment message rules, and
 * the acknowledgment-timer arithmetic.
 *
 * Hand-written.  Every constant and every claim below is traceable to a named
 * external source; nothing here was derived from any file under
 * /usr/src/lib/libmesh or /usr/src/usr.sbin/bluetooth, and no value was
 * produced by running 5BSD code.
 *
 * WHY THIS HEADER EXISTS
 * ======================
 * The SAR timing rules changed shape between Mesh Profile 1.0.1 and Mesh
 * Protocol 1.1.  In 1.0 the acknowledgment delay was a fixed expression of TTL;
 * in 1.1 it is derived from seven transmitter states and five receiver states,
 * all of them settable over the air by the SAR Configuration Server model.
 * The three available reference implementations sit on OPPOSITE SIDES of that
 * change (see "reference split" below), so "what the references do" does not
 * settle the question here and the specification text has to.  That is the
 * situation this header is for.
 *
 * SOURCES
 * =======
 * SPEC: /usr/src/bluetooth-specs/MshPRT_v1.1.1.txt.  Line numbers below are
 *   lines of that .txt file.
 *     Section 3.5.2.3.1 Segment Acknowledgment message .... lines ~4519-4571
 *     Section 3.5.3.3   Segmentation behavior ............. lines ~4765-4965
 *     Section 3.5.3.4   Reassembly behavior ............... lines ~4990-5145
 *     Table 3.24 (valid segment ack conditions) ........... lines  4890-4907
 *     Table 3.25 (segment processing conditions) .......... lines ~5085-5127
 *     Section 4.2.48 SAR Transmitter ...................... lines 14913-15025
 *     Section 4.2.49 SAR Receiver ......................... lines 15026-15098
 *
 * REFERENCE SPLIT -- established by reading the trees, not assumed
 * ===============================================================
 *   ZEPHYR (2665fcca3cced3aefb7202d6289991d8cc1dfcac) implements Mesh 1.1 SAR:
 *     subsys/bluetooth/mesh/sar_cfg.c, sar_cfg_srv.c, sar_cfg_cli.c,
 *     sar_cfg_internal.h, and transport.c.  Zephyr is PTS-qualified.
 *   BLUEZ 5.87 (92305dc06ab8a6d89af2dae1d725cc4d51462ad1) has NO SAR
 *     Configuration model.  Its SAR lives entirely in mesh/net.c + net.h and
 *     is Mesh 1.0-shaped: a flat inter-segment timeout SEG_TO and a message
 *     timeout MSG_TO, with acknowledgment driven by segment arrival rather
 *     than by a timer.
 *   APACHE NIMBLE mesh is Mesh 1.0-era throughout (no sar_cfg anywhere).  Its
 *     nimble/host/mesh/src/transport.c uses the 1.0 expression built from
 *     150 ms + 50 ms per TTL.
 *
 * The load-bearing consequence, and the reason a stack cannot simply decline
 * to implement the states: MshPRT v1.1.1 line 14915 (SAR Transmitter) and
 * line 15029 (SAR Receiver), verbatim:
 *
 *   "A node shall implement the SAR Transmitter state independently of the
 *    presence of the SAR Configuration Server model."
 *   "The node shall implement the SAR Receiver independently of the presence
 *    of the SAR Configuration Server model."
 *
 * The states are mandatory; only the model that lets a provisioner CHANGE
 * them is optional.  Shipping the Configuration Server model without the
 * underlying behaviour is therefore the one combination the specification
 * rules out explicitly -- a provisioner can read and write the states and
 * observe no effect.
 */

#ifndef SPEC_EXTREF_MESH_SAR_H
#define SPEC_EXTREF_MESH_SAR_H

#include <stdint.h>

/*
 * ---------------------------------------------------------------------------
 * SAR Transmitter, MshPRT v1.1.1 Section 4.2.48, .txt lines 14913-15025.
 * Each state's field width, its formula and its default are transcribed from
 * the section named in the comment.  The specification's word for every
 * default here is "should".
 * ---------------------------------------------------------------------------
 */

/* 4.2.48.1 SAR Segment Interval Step -- 4-bit.
 * "segment transmission interval=(SAR Segment Interval Step+1)x10" (ms)
 * "The default value ... should be 0b0101 (60 milliseconds)." */
#define	SPEC_EXTREF_MESH_SAR_TX_SEG_INT_STEP_BITS	4
#define	SPEC_EXTREF_MESH_SAR_TX_SEG_INT_STEP_DEFAULT	0x05u
#define	SPEC_EXTREF_MESH_SAR_TX_SEG_INT_MS(step)	(((step) + 1u) * 10u)
#define	SPEC_EXTREF_MESH_SAR_TX_SEG_INT_MS_DEFAULT	60u

/* 4.2.48.2 SAR Unicast Retransmissions Count -- 4-bit.
 * "The maximum number of transmissions of a segment is
 *  (SAR Unicast Retransmissions Count + 1)."
 * "0b0000 represents a single transmission, and 0b0111 represents 8
 *  transmissions."
 * "The default value ... should be 0b0010 (3 transmissions)." */
#define	SPEC_EXTREF_MESH_SAR_TX_UNICAST_RETRANS_BITS	4
#define	SPEC_EXTREF_MESH_SAR_TX_UNICAST_RETRANS_DEFAULT	0x02u
#define	SPEC_EXTREF_MESH_SAR_TX_MAX_TRANSMISSIONS(c)	((c) + 1u)

/* 4.2.48.3 SAR Unicast Retransmissions Without Progress Count -- 4-bit.
 * A SEPARATE budget from 4.2.48.2, reset whenever a retransmission makes
 * progress.  Default 0b0010 (3 transmissions).  The specification adds the
 * tuning note: "The value of this state should be set to a value greater than
 * the value of the SAR Acknowledgement Retransmissions Count on a peer node.
 * This helps prevent the SAR transmitter from abandoning the SAR
 * prematurely." */
#define	SPEC_EXTREF_MESH_SAR_TX_NO_PROGRESS_BITS	4
#define	SPEC_EXTREF_MESH_SAR_TX_NO_PROGRESS_DEFAULT	0x02u

/* 4.2.48.4 SAR Unicast Retransmissions Interval Step -- 4-bit.
 * "unicast retransmissions interval=
 *   (SAR Unicast Retransmissions Interval Step+1)x25" (ms)
 * "The default ... should be 0b0111 (200 milliseconds) or higher." */
#define	SPEC_EXTREF_MESH_SAR_TX_UNICAST_INT_STEP_BITS	4
#define	SPEC_EXTREF_MESH_SAR_TX_UNICAST_INT_STEP_DEFAULT 0x07u
#define	SPEC_EXTREF_MESH_SAR_TX_UNICAST_INT_MS(step)	(((step) + 1u) * 25u)
#define	SPEC_EXTREF_MESH_SAR_TX_UNICAST_INT_MS_DEFAULT	200u

/* 4.2.48.5 SAR Unicast Retransmissions Interval Increment -- 4-bit.
 * "unicast retransmissions interval increment=
 *   (SAR Unicast Retransmissions Interval Increment+1)x25" (ms)
 * "The default ... should be 0b0001 (50 milliseconds)." */
#define	SPEC_EXTREF_MESH_SAR_TX_UNICAST_INC_BITS	4
#define	SPEC_EXTREF_MESH_SAR_TX_UNICAST_INC_DEFAULT	0x01u
#define	SPEC_EXTREF_MESH_SAR_TX_UNICAST_INC_MS(inc)	(((inc) + 1u) * 25u)
#define	SPEC_EXTREF_MESH_SAR_TX_UNICAST_INC_MS_DEFAULT	50u

/*
 * The combined unicast retransmissions timer, Section 3.5.3.3.1, .txt line
 * 4828, verbatim:
 *   "[unicast retransmissions interval step + unicast retransmissions
 *     interval increment * (TTL - 1)]"
 * TTL is the TTL of the segmented message being retransmitted.  The
 * specification qualifies it: the increment term applies when the TTL is
 * greater than 0; a TTL of 0 uses the interval step alone.
 *
 * This is the term a flat "one interval for everything" retransmit timer
 * loses.  With the defaults above and a 5-hop TTL the correct interval is
 * 200 + 50*4 = 400 ms, twice the flat 200 ms.
 */
#define	SPEC_EXTREF_MESH_SAR_TX_UNICAST_TIMER_MS(step, inc, ttl)	\
	(SPEC_EXTREF_MESH_SAR_TX_UNICAST_INT_MS(step) +			\
	 ((ttl) > 0u ? SPEC_EXTREF_MESH_SAR_TX_UNICAST_INC_MS(inc) *	\
	  ((ttl) - 1u) : 0u))

/* 4.2.48.6 SAR Multicast Retransmissions Count -- 4-bit, default 0b0010.
 * Applies to a group address OR a virtual address destination.  Its existence
 * is the point: a segmented message to a group is retransmitted, not sent
 * once.  There is no acknowledgment for a multicast transaction, so the count
 * is the ONLY reliability mechanism it has. */
#define	SPEC_EXTREF_MESH_SAR_TX_MULTICAST_RETRANS_BITS	4
#define	SPEC_EXTREF_MESH_SAR_TX_MULTICAST_RETRANS_DEFAULT 0x02u

/* 4.2.48.7 SAR Multicast Retransmissions Interval Step -- 4-bit.
 * "multicast retransmissions interval=
 *   (SAR Multicast Retransmissions Interval Step+1)x25" (ms)
 * "The default ... should be 0b1001 (250 milliseconds)." */
#define	SPEC_EXTREF_MESH_SAR_TX_MULTICAST_INT_STEP_BITS	4
#define	SPEC_EXTREF_MESH_SAR_TX_MULTICAST_INT_STEP_DEFAULT 0x09u
#define	SPEC_EXTREF_MESH_SAR_TX_MULTICAST_INT_MS(step)	(((step) + 1u) * 25u)
#define	SPEC_EXTREF_MESH_SAR_TX_MULTICAST_INT_MS_DEFAULT 250u

/*
 * ---------------------------------------------------------------------------
 * SAR Receiver, MshPRT v1.1.1 Section 4.2.49, .txt lines 15026-15098.
 * ---------------------------------------------------------------------------
 */

/* 4.2.49.1 SAR Segments Threshold -- 5-bit, default 0b00011 (3 segments).
 * "the size of a segmented message in number of segments above which
 *  retransmissions of the Segment Acknowledgment messages are enabled." */
#define	SPEC_EXTREF_MESH_SAR_RX_SEG_THRESHOLD_BITS	5
#define	SPEC_EXTREF_MESH_SAR_RX_SEG_THRESHOLD_DEFAULT	0x03u

/* 4.2.49.2 SAR Acknowledgment Delay Increment -- 3-bit.
 * "acknowledgment delay increment=SAR Acknowledgment Delay Increment+1.5"
 * "The default ... should be 0b001 (2.5 segment transmission interval steps)
 *  or higher."
 * Note the +1.5: this is a HALF-INTEGER multiplier.  Integer arithmetic must
 * carry the doubling explicitly (Zephyr does exactly this, keeping an
 * ..._X2 constant), or the ack fires early.  The doubled form is pinned here
 * so a test never has to reintroduce the rounding itself. */
#define	SPEC_EXTREF_MESH_SAR_RX_ACK_DELAY_INC_BITS	3
#define	SPEC_EXTREF_MESH_SAR_RX_ACK_DELAY_INC_DEFAULT	0x01u
#define	SPEC_EXTREF_MESH_SAR_RX_ACK_DELAY_INC_X2(inc)	(2u * (inc) + 3u)
#define	SPEC_EXTREF_MESH_SAR_RX_ACK_DELAY_INC_X2_DEFAULT 5u	/* 2.5 x 2 */

/* 4.2.49.3 SAR Acknowledgment Retransmissions Count -- 2-bit.
 * "The maximum number of transmissions of a Segment Acknowledgment message is
 *  (SAR Acknowledgment Retransmissions Count + 1)."
 * "0b00 represents a limit of 1 transmission, and 0b11 represents a limit of
 *  4 transmissions."
 * "The default ... should be 0b00 (1 transmission)." */
#define	SPEC_EXTREF_MESH_SAR_RX_ACK_RETRANS_BITS	2
#define	SPEC_EXTREF_MESH_SAR_RX_ACK_RETRANS_DEFAULT	0x00u

/* 4.2.49.4 SAR Discard Timeout -- 4-bit.
 * "discard timeout=(SAR Discard Timeout+1)x5" (SECONDS, not milliseconds)
 * "The default ... should be 0b0001 (10 seconds) or higher." */
#define	SPEC_EXTREF_MESH_SAR_RX_DISCARD_TIMEOUT_BITS	4
#define	SPEC_EXTREF_MESH_SAR_RX_DISCARD_TIMEOUT_DEFAULT	0x01u
#define	SPEC_EXTREF_MESH_SAR_RX_DISCARD_SECONDS(t)	(((t) + 1u) * 5u)
#define	SPEC_EXTREF_MESH_SAR_RX_DISCARD_SECONDS_DEFAULT	10u

/* 4.2.49.5 SAR Receiver Segment Interval Step -- 4-bit.
 * "segment reception interval=(SAR Receiver Segment Interval Step+1)x10" (ms)
 * "The default ... should be 0b0101 (60 milliseconds)." */
#define	SPEC_EXTREF_MESH_SAR_RX_SEG_INT_STEP_BITS	4
#define	SPEC_EXTREF_MESH_SAR_RX_SEG_INT_STEP_DEFAULT	0x05u
#define	SPEC_EXTREF_MESH_SAR_RX_SEG_INT_MS(step)	(((step) + 1u) * 10u)
#define	SPEC_EXTREF_MESH_SAR_RX_SEG_INT_MS_DEFAULT	60u

/*
 * The SAR Acknowledgment timer, Section 3.5.3.4, .txt line 5027, verbatim:
 *
 *   "[min(SegN + 0.5, acknowledgment delay increment) * segment reception
 *     interval]"
 *
 * Both operands of the min() carry a half.  Doubling throughout gives exact
 * integer arithmetic:
 *
 *   ms = min(2*SegN + 1, ack_delay_increment_x2) * seg_reception_interval / 2
 *
 * With the defaults (increment 0b001 -> x2 = 5, interval 60 ms):
 *   SegN = 1  ->  min(3,5)  * 60 / 2 =  90 ms
 *   SegN = 2  ->  min(5,5)  * 60 / 2 = 150 ms
 *   SegN = 31 ->  min(63,5) * 60 / 2 = 150 ms   (saturated by the increment)
 *
 * The saturation is the behaviour that matters: past a small SegN the delay
 * stops growing, so a 32-segment transfer produces on the order of one
 * acknowledgment, not thirty-two.
 */
#define	SPEC_EXTREF_MESH_SAR_RX_ACK_TIMER_MS(segn, inc_x2, seg_int_ms)	\
	((((2u * (segn) + 1u) < (inc_x2)) ? (2u * (segn) + 1u) : (inc_x2))\
	 * (seg_int_ms) / 2u)

#define	SPEC_EXTREF_MESH_SAR_RX_ACK_TIMER_MS_DEFAULT(segn)		\
	SPEC_EXTREF_MESH_SAR_RX_ACK_TIMER_MS((segn),			\
	    SPEC_EXTREF_MESH_SAR_RX_ACK_DELAY_INC_X2_DEFAULT,		\
	    SPEC_EXTREF_MESH_SAR_RX_SEG_INT_MS_DEFAULT)

/*
 * Section 3.5.3.4, .txt line 5053, verbatim -- the rate limit on re-acking a
 * SeqAuth that has already been fully delivered ("Most Recent SeqAuth"):
 *   "The lower transport layer shall not send more than one Segment
 *    Acknowledgment message for the same SeqAuth in a period of:
 *    [acknowledgment delay increment * segment reception interval]
 *    milliseconds"
 * Defaults: 2.5 * 60 = 150 ms.
 */
#define	SPEC_EXTREF_MESH_SAR_RX_REACK_MIN_INTERVAL_MS(inc_x2, seg_int_ms) \
	((inc_x2) * (seg_int_ms) / 2u)
#define	SPEC_EXTREF_MESH_SAR_RX_REACK_MIN_INTERVAL_MS_DEFAULT	150u

/*
 * ---------------------------------------------------------------------------
 * Segment Acknowledgment message rules, Section 3.5.2.3.1 and Table 3.24.
 * ---------------------------------------------------------------------------
 */

/* The Segment Acknowledgment message is a Transport Control message with
 * Opcode 0x00.  .txt line 4880: "The Opcode field shall be set to 0x00." */
#define	SPEC_EXTREF_MESH_SEG_ACK_OPCODE			0x00u

/* .txt lines 4882-4884, verbatim:
 *   "The OBO field shall be set to 0 by a node that is directly addressed by
 *    the received message and shall be set to 1 by a Friend node that is
 *    acknowledging this message on behalf of a Low Power node."
 * And .txt line 5154 (reassembly behaviour of a Friend):
 *   "If the device is acting as a Friend node for a Low Power node, then it
 *    shall reassemble segmented messages destined for the Low Power node and
 *    act as described, except that it shall set the OBO field to 1."
 * Pinned as flags because OBO has to be implemented on BOTH sides: set it
 * when acking as a Friend, and honour it when validating an ack. */
#define	SPEC_EXTREF_MESH_OBO_DIRECT			0u
#define	SPEC_EXTREF_MESH_OBO_ON_BEHALF_OF_LPN		1u
#define	SPEC_EXTREF_MESH_FRIEND_MUST_SET_OBO		1
#define	SPEC_EXTREF_MESH_SENDER_MUST_HONOUR_OBO		1

/* .txt lines 4886-4892, verbatim:
 *   "The AckedSegments field shall be set to indicate the segments received.
 *    The least significant bit, bit 0, shall represent segment 0; and the most
 *    significant bit, bit 31, shall represent segment 31. If bit n is set to
 *    1, then segment n is being acknowledged. ... Any bits for segments larger
 *    than the SegN field value of the upper transport layer message being
 *    acknowledged shall be set to 0 and ignored upon receipt." */
#define	SPEC_EXTREF_MESH_SEG_MAX			32u
#define	SPEC_EXTREF_MESH_BLOCKACK_FULL(segn)				\
	((segn) >= 31u ? 0xFFFFFFFFu : ((uint32_t)1u << ((segn) + 1u)) - 1u)

/* .txt lines 4894-4895, verbatim:
 *   "If the received segments were sent with the TTL field set to 0, it is
 *    recommended that the corresponding Segment Acknowledgment message is sent
 *    with the TTL field set to 0."
 * "Recommended", not "shall" -- but a stack that always uses a fixed default
 * TTL floods a strictly single-hop exchange across the whole mesh. */
#define	SPEC_EXTREF_MESH_SEG_ACK_TTL0_MIRRORED_RECOMMENDED	1

/*
 * Table 3.24 "Conditions to validate a segment acknowledgment message",
 * .txt lines 4890-4907.  ALL FOUR must hold.  Transcribed verbatim, in order,
 * as separate flags so a test can assert each is checked rather than assuming
 * one comparison covers them.
 *
 *   1. "SeqAuth derived from the SeqZero field of the Segment Acknowledgment
 *       message matches the value stored by the lower transport layer"
 *   2. "Either the source address of the Segment Acknowledgment message
 *       matches the destination address value stored by the lower transport
 *       layer, or the value of the OBO field of the Segment Acknowledgment
 *       message is 1."
 *   3. "For the SeqAuth derived from the SeqZero field of the message, there
 *       is at least one unacknowledged segment that the AckedSegments field of
 *       the message reports as delivered"
 *   4. "The message was secured using the same NetKey that was used to secure
 *       the segmented message"
 *
 * Condition 2 is the one that decides whether a stack can talk to any Low
 * Power node at all: the ack arrives from the FRIEND's address, not from the
 * address the segments were sent to.  A matcher written as a plain
 * "stored_dst == ack_src" comparison fails every such exchange.
 */
#define	SPEC_EXTREF_MESH_ACK_COND_SEQAUTH_MATCH		1
#define	SPEC_EXTREF_MESH_ACK_COND_SRC_OR_OBO		1
#define	SPEC_EXTREF_MESH_ACK_COND_NEW_SEGMENT_ACKED	1
#define	SPEC_EXTREF_MESH_ACK_COND_SAME_NETKEY		1

/*
 * .txt lines 4771-4773, verbatim:
 *   "When a Segment Acknowledgment message that is a valid acknowledgment for
 *    a segmented message with the AckedSegments field set to 0x00000000 is
 *    received, then the transmission of the Upper Transport PDU shall be
 *    immediately canceled"
 * An all-zero BlockAck means ABANDON, never "resend everything".
 */
#define	SPEC_EXTREF_MESH_BLOCKACK_CANCEL		0x00000000u

/*
 * .txt line 4993, verbatim -- the obligation to EMIT that cancel:
 *   "When the Processing Result is Message Rejected and the message is
 *    destined to a unicast address, the lower transport layer shall respond
 *    with a Segment Acknowledgment message with the AckedSegments field set to
 *    0x00000000."
 * i.e. running out of reassembly resources is an active refusal, not a silent
 * drop.  Both directions are "shall".
 */
#define	SPEC_EXTREF_MESH_MUST_SEND_CANCEL_ON_REJECT	1

/*
 * .txt lines 4819-4821 / 5065-5069: a destination that is a group address or
 * a virtual address is never acknowledged.  Reassembly still happens; only the
 * acknowledgment is suppressed, and the Discard timer alone bounds it.
 */
#define	SPEC_EXTREF_MESH_NO_ACK_TO_NON_UNICAST		1

/*
 * .txt line 4747, verbatim -- the Low Power node exemption:
 *   "When the Low Power node feature is in use, reassembly is performed by a
 *    Friend node and the Low Power node does not send any Segment
 *    Acknowledgment messages."
 */
#define	SPEC_EXTREF_MESH_LPN_SENDS_NO_SEG_ACK		1

/*
 * ---------------------------------------------------------------------------
 * SeqAuth, SeqZero and the 8192 cancellation bound, Section 3.5.3.1.
 * ---------------------------------------------------------------------------
 *
 * .txt lines 4725-4726, the specification's own worked example, reproduced so
 * a test has a vector it did not compute itself:
 *   "If the SEQ field value of a received message was 0x647262, the IV Index
 *    was 0x58437AF2, and the received SeqZero field value was 0x1849, then the
 *    SeqAuth value is 0x58437AF2645849."
 * and the second example, .txt lines 4728-4730:
 *   "If the SEQ field value of a received message was 0x647262 and the
 *    received SeqZero field value was 0x1263, then the SeqAuth value is
 *    0x58437AF2645263."
 */
#define	SPEC_EXTREF_MESH_SEQZERO_BITS			13
#define	SPEC_EXTREF_MESH_SEQZERO_MASK			0x1FFFu
#define	SPEC_EXTREF_MESH_SEQAUTH_EX1_SEQ		0x647262u
#define	SPEC_EXTREF_MESH_SEQAUTH_EX1_IV			0x58437AF2u
#define	SPEC_EXTREF_MESH_SEQAUTH_EX1_SEQZERO		0x1849u
#define	SPEC_EXTREF_MESH_SEQAUTH_EX1_RESULT		0x58437AF2645849ULL
#define	SPEC_EXTREF_MESH_SEQAUTH_EX2_SEQ		0x647262u
#define	SPEC_EXTREF_MESH_SEQAUTH_EX2_SEQZERO		0x1263u
#define	SPEC_EXTREF_MESH_SEQAUTH_EX2_RESULT		0x58437AF2645263ULL

/*
 * .txt lines 4732-4736, verbatim:
 *   "Because of the limited size of the SeqZero field, it is not possible to
 *    send a segmented message when the SEQ field value is 8192 greater than
 *    the SeqAuth value. If a segmented message has not been acknowledged by
 *    the time that the SEQ field value is 8192 greater than the SeqAuth value,
 *    then the transmission of the Upper Transport PDU shall be canceled."
 */
#define	SPEC_EXTREF_MESH_SEQAUTH_CANCEL_DELTA		8192u

/*
 * .txt lines 4767-4768, verbatim:
 *   "The lower transport layer shall not transmit segmented messages for more
 *    than one Upper Transport PDU to the same destination at the same time."
 */
#define	SPEC_EXTREF_MESH_ONE_SEG_TX_PER_DST		1

/*
 * .txt lines 5016-5019, verbatim -- the supersede rule on the receive side:
 *   "If another reassembly is already pending for the same source address and
 *    for the same destination address, the pending reassembly shall be
 *    discarded and the SAR Discard timer and SAR Acknowledgment timer shall be
 *    stopped."
 * combined with Table 3.25's SeqAuth Error row and .txt line 5048:
 *   "When the Processing Status is SeqAuth Error, Repeated Segment, or Late
 *    Segment, the lower transport layer shall ignore the message."
 * A NEWER SeqAuth from a source supersedes; an OLDER one is ignored outright.
 * Neither may open a second concurrent reassembly for the same (src, dst).
 */
#define	SPEC_EXTREF_MESH_ONE_REASM_PER_SRC_DST		1
#define	SPEC_EXTREF_MESH_OLDER_SEQAUTH_IS_IGNORED	1

/*
 * ---------------------------------------------------------------------------
 * Segment payload sizes, Section 3.5.2 and Table 3.62 (Section 3.7.2).
 * ---------------------------------------------------------------------------
 * A segment of a Segmented Access message carries 12 octets; a segment of a
 * Segmented Control message carries 8.  Every segment except the last must be
 * exactly full.
 *
 * Table 3.62, .txt lines ~8808-8826, "Maximum useful Access message size":
 *   1 packet, unsegmented, 32-bit TransMIC ......  11 octets
 *   1 packet, segmented,   32-bit TransMIC ......   8 octets
 *   1 packet, segmented,   64-bit TransMIC ......   4 octets
 *   n packets,             32-bit TransMIC ...... (n*12)-4
 *   n packets,             64-bit TransMIC ...... (n*12)-8
 *   32 packets,            32-bit TransMIC ...... 380 octets
 *   32 packets,            64-bit TransMIC ...... 376 octets
 */
#define	SPEC_EXTREF_MESH_SEG_ACCESS_PAYLOAD		12u
#define	SPEC_EXTREF_MESH_SEG_CONTROL_PAYLOAD		8u
/* .txt line 4633: "To transmit Upper Transport Access PDUs larger than 15
 * octets, or shorter Upper Transport Access PDUs [tagged send-segmented],
 * the lower transport layer shall segment..."  15 is therefore the largest
 * Upper Transport Access PDU an Unsegmented Access message can carry, and
 * .txt line 5340 fixes its TransMIC at 32 bits: "For Unsegmented Access
 * messages, the TransMIC field is a 32-bit field."  Hence 11 octets of
 * access payload, which is Table 3.62 row 1. */
#define	SPEC_EXTREF_MESH_UNSEG_UPPER_ACCESS_PDU_MAX	15u
#define	SPEC_EXTREF_MESH_UNSEG_ACCESS_PAYLOAD		11u
#define	SPEC_EXTREF_MESH_TRANSMIC_SHORT_OCTETS		4u
#define	SPEC_EXTREF_MESH_TRANSMIC_LONG_OCTETS		8u
#define	SPEC_EXTREF_MESH_MAX_ACCESS_PDU			380u
#define	SPEC_EXTREF_MESH_USEFUL_ACCESS_32BIT(n)		(((n) * 12u) - 4u)
#define	SPEC_EXTREF_MESH_USEFUL_ACCESS_64BIT(n)		(((n) * 12u) - 8u)

#endif /* SPEC_EXTREF_MESH_SAR_H */
