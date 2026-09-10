/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh multi-node network simulator.  Composes the Phase 1-8
 * libmesh modules into a running network over a shared virtual advertising
 * medium.  See mesh_sim.h for the architecture and the modelled scope.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "mesh_bridge.h"
#include "mesh_sim.h"
#include "mesh_crypto.h"
#include "mesh_generic.h"
#include "mesh_beacon.h"
#include "mesh_provision.h"

/* Managed-flooding k2 P-input is the single octet 0x00 (MshPRT_v1.1 3.8.2.6). */
static const uint8_t k2_p_managed[1] = { 0x00 };

/*
 * Directed k2 P-input.  MshPRT_v1.1.1 Section 3.9.6.3.1, verbatim: "The
 * directed security material is derived from the directed security credentials
 * using the following formula: NID || EncryptionKey || PrivacyKey=k2(NetKey,
 * 0x02).  For Network PDUs that are transmitted according to directed
 * forwarding functionality, the directed security material is used."
 */
static const uint8_t k2_p_directed[1] = { 0x02 };

/*
 * Derive both network security materials a subnet needs from one NetKey: the
 * managed-flooding one (P=0x00) and the directed one (P=0x02).  They are
 * always derived together because Table 3.14 chooses between them per
 * retransmitted PDU; a node holding only one of the pair cannot honour the
 * table's Outbound Security Material column.
 */
static int
derive_subnet_material(const uint8_t netkey[16], uint8_t *nid, uint8_t *enckey,
    uint8_t *privkey, uint8_t *dir_nid, uint8_t *dir_enckey,
    uint8_t *dir_privkey)
{

	if (mesh_k2(netkey, k2_p_managed, sizeof(k2_p_managed), nid, enckey,
	    privkey) != 0)
		return (-1);
	return (mesh_k2(netkey, k2_p_directed, sizeof(k2_p_directed), dir_nid,
	    dir_enckey, dir_privkey));
}

/* Largest Upper Transport Access PDU we buffer. */
#define	SIM_UPPER_MAX	MESH_UPPER_MAX
#define	SIM_SAR_RETRANS_MS	200
#define	SIM_SAR_DISCARD_MS	10000
#define	SIM_SAR_RETRIES		4

/*
 * SAR Receiver and multicast SAR Transmitter timing, at the specification's
 * own default values.
 *
 * MshPRT_v1.1.1 Section 4.2.49.5: "segment reception interval=(SAR Receiver
 * Segment Interval Step+1)x10", default 0b0101, i.e. 60 ms.  Section 4.2.49.2:
 * "acknowledgment delay increment=SAR Acknowledgment Delay Increment+1.5",
 * default 0b001, i.e. 2.5 - a half-integer, so it is carried here doubled and
 * the division by two is done once, at the end, to keep the arithmetic exact.
 * Section 4.2.49.1: SAR Segments Threshold, default 0b00011 (3 segments), above
 * which acknowledgment retransmissions are enabled; Section 4.2.49.3: SAR
 * Acknowledgment Retransmissions Count, default 0b00, which is "a limit of 1
 * transmission" - so at the defaults there are no acknowledgment
 * retransmissions to emit and the threshold has nothing to gate.
 *
 * Section 4.2.48.6: SAR Multicast Retransmissions Count, default 0b0010, and
 * "the maximum number of transmissions of a segment is (SAR Multicast
 * Retransmissions Count + 1)" - three transmissions, i.e. two retransmissions
 * after the first.  Section 4.2.48.7: "multicast retransmissions
 * interval=(SAR Multicast Retransmissions Interval Step+1)x25", default
 * 0b1001, i.e. 250 ms.
 *
 * These are the specification's defaults expressed as engine constants.
 * Whether the SAR Receiver and SAR Transmitter composite states become
 * writable through the SAR Configuration Server model is a separate question
 * about that model, and is deliberately not decided here.
 */
#define	SIM_SAR_RX_SEG_INT_MS		60
#define	SIM_SAR_ACK_DELAY_INC_X2	5	/* 2.5, doubled */
#define	SIM_SAR_MULTICAST_RETRANS	2	/* count: 3 transmissions */
#define	SIM_SAR_MULTICAST_INT_MS	250

/*
 * The SAR Acknowledgment timer, MshPRT_v1.1.1 Section 3.5.3.4:
 *
 *   [min(SegN + 0.5, acknowledgment delay increment) * segment reception
 *    interval]
 *
 * Both operands of the min() carry a half, so both are doubled and the result
 * halved once.  With the defaults above this saturates quickly: SegN 1 gives
 * 90 ms, SegN 2 gives 150 ms, and SegN 31 also gives 150 ms.  The saturation is
 * the point - past a small SegN the delay stops growing, so an arbitrarily long
 * transfer still produces on the order of one acknowledgment.
 */
static uint32_t
sar_ack_delay_ms(uint8_t segn)
{
	uint32_t a = 2u * (uint32_t)segn + 1u;
	uint32_t b = SIM_SAR_ACK_DELAY_INC_X2;

	return ((a < b ? a : b) * SIM_SAR_RX_SEG_INT_MS / 2u);
}

/*
 * The minimum interval between two Segment Acknowledgment messages for the same
 * SeqAuth, MshPRT_v1.1.1 Section 3.5.3.4: [acknowledgment delay increment *
 * segment reception interval], 150 ms at the defaults.
 */
static uint32_t
sar_reack_min_ms(void)
{

	return (SIM_SAR_ACK_DELAY_INC_X2 * SIM_SAR_RX_SEG_INT_MS / 2u);
}

/*
 * Per-node SAR timing (MshPRT_v1.1.1 4.2.48 / 4.2.49), configured through
 * mesh_sim_set_sar() from the SAR Transmitter / Receiver Configuration Server
 * states.  An unset (zero) value falls back to the library default, so nodes
 * that never configure SAR behave exactly as before.
 */
static uint32_t
sar_retrans_ms(const struct mesh_node *node)
{

	return (node->sar_retrans_ms != 0 ? node->sar_retrans_ms :
	    SIM_SAR_RETRANS_MS);
}

static uint32_t
sar_retries(const struct mesh_node *node)
{

	return (node->sar_retries != 0 ? node->sar_retries : SIM_SAR_RETRIES);
}

static uint32_t
sar_discard_ms(const struct mesh_node *node)
{

	return (node->sar_discard_ms != 0 ? node->sar_discard_ms :
	    SIM_SAR_DISCARD_MS);
}
/* Default TTL used for locally originated Segment Acks (MshPRT_v1.1 3.5.3.4). */
#define	SIM_DEFAULT_TTL		5

static struct mesh_sim_subnet_key *find_subnet(struct mesh_node *, uint16_t);
static void node_recv_net(struct mesh_sim *, struct mesh_node *,
    const uint8_t *, size_t, int);

/* ================================================================
 * Small helpers.
 * ================================================================ */

static int
local_unicast(const struct mesh_node *node, uint16_t addr)
{
	uint8_t i;

	for (i = 0; i < node->n_elements; i++) {
		if (node->elems[i].addr == addr)
			return (1);
	}
	return (0);
}

static int
node_subscribed(const struct mesh_node *node, uint16_t addr)
{
	uint8_t ei;
	size_t i;

	for (ei = 0; ei < node->n_elements; ei++) {
		for (i = 0; i < node->elem_n_subs[ei]; i++) {
			if (node->elem_subs[ei][i] == addr)
				return (1);
		}
		if (mesh_addr_is_virtual(addr)) {
			for (i = 0; i < node->elem_n_labels[ei]; i++) {
				uint16_t va;

				if (mesh_virtual_addr(node->elem_labels[ei][i], &va) == 0 &&
				    va == addr)
					return (1);
			}
		}
	}
	return (0);
}

/*
 * Fixed group destination addresses, MshPRT_v1.1.1 Section 3.6.4.2 Table 3.28
 * (and identically Section 3.7.3.1 Table 3.64 for access messages): a PDU
 * whose DST is a fixed group address is processed "if ... the destination
 * address matches a fixed group destination address specified in Table 3.28
 * and the corresponding condition (if any) is satisfied".  The conditions are
 * per-feature - directed forwarding for all-directed-forwarding-nodes, Proxy
 * for all-proxies, Friend for all-friends, Relay for all-relays - and
 * all-nodes has none.
 *
 * Matching only all-nodes, as this used to, makes a Friend Request (which is
 * addressed to all-friends, Section 3.6.6.2) undeliverable through the normal
 * receive path, and leaves all-relays and all-proxies unreachable entirely.
 */
static int
fixed_group_addressed(const struct mesh_node *node, uint16_t dst)
{

	switch (dst) {
	case MESH_ADDR_ALL_NODES:
		return (1);
	case MESH_ADDR_ALL_RELAYS:
		return (node->is_relay != 0);
	case MESH_ADDR_ALL_PROXIES:
		return (node->is_proxy != 0);
	case MESH_ADDR_ALL_FRIENDS:
		/*
		 * Either face of the Friend feature counts: this engine's own
		 * Friend Queue role, or a consumer that runs its own friendship
		 * engine and reports the feature through
		 * mesh_sim_set_friend_feature().
		 */
		return (node->is_friend != 0 || node->friend_feature != 0);
	case MESH_ADDR_ALL_DF:
		return (node->df_enabled != 0);
	default:
		return (0);
	}
}

static int
addressed_here(const struct mesh_node *node, uint16_t dst)
{

	if (fixed_group_addressed(node, dst))
		return (1);
	if (local_unicast(node, dst))
		return (1);
	if (node_subscribed(node, dst))
		return (1);
	return (0);
}

/*
 * Network message cache: 1 if (src, seq, iv_index) already recorded, else
 * records it and returns 0.  M-N1: the IV Index is part of the key so the same
 * (src, seq) recurring after an IV Index change is not treated as a duplicate.
 */
static int
nmc_seen_record(struct mesh_node *node, uint16_t src, uint32_t seq,
    uint32_t iv_index)
{
	size_t i;

	for (i = 0; i < MESH_SIM_NMC_SIZE; i++) {
		if (node->nmc[i].valid && node->nmc[i].src == src &&
		    node->nmc[i].seq == seq && node->nmc[i].iv_index == iv_index)
			return (1);
	}
	node->nmc[node->nmc_next].valid = 1;
	node->nmc[node->nmc_next].src = src;
	node->nmc[node->nmc_next].seq = seq;
	node->nmc[node->nmc_next].iv_index = iv_index;
	node->nmc_next = (node->nmc_next + 1) % MESH_SIM_NMC_SIZE;
	return (0);
}

/* Select the network security material a node uses to TRANSMIT (Key Refresh). */
static void
node_tx_netsec(const struct mesh_node *node, uint8_t *nid,
    const uint8_t **enc, const uint8_t **priv)
{

	if (node->have_new_key && mesh_kr_tx_key(&node->kr) == MESH_KR_KEY_NEW) {
		*nid = node->new_nid;
		*enc = node->new_enckey;
		*priv = node->new_privkey;
	} else {
		*nid = node->nid;
		*enc = node->enckey;
		*priv = node->privkey;
	}
}

/*
 * Managed-flooding ("network") security material for one subnet of this node,
 * selected by that subnet's own Key Refresh transmit rule.  Returns 0 and
 * fills the credential out-parameters, or -1 when net_idx is not a subnet this
 * node holds.
 *
 * MshPRT_v1.1.1 Section 3.4.6.3 Table 3.14 lists exactly two outbound security
 * materials for a relayed Network PDU, "flooding" and "directed"; no row
 * outputs friendship material.  This is the flooding one, and it is what a
 * Friend must re-secure a PDU with when relaying traffic it received under the
 * friendship credential (Section 3.6.6.2).
 */
static int
net_flooding_txsec(struct mesh_node *node, uint16_t net_idx, uint8_t *nid,
    const uint8_t **enc, const uint8_t **priv)
{
	struct mesh_sim_subnet_key *sn;

	if (net_idx == node->primary_net_idx) {
		node_tx_netsec(node, nid, enc, priv);
		return (0);
	}
	sn = find_subnet(node, net_idx);
	if (sn == NULL)
		return (-1);
	if (sn->have_new_key && mesh_kr_tx_key(&sn->kr) == MESH_KR_KEY_NEW) {
		*nid = sn->new_nid;
		*enc = sn->new_enckey;
		*priv = sn->new_privkey;
	} else {
		*nid = sn->nid;
		*enc = sn->enckey;
		*priv = sn->privkey;
	}
	return (0);
}

/*
 * Directed security material for one subnet of this node, selected by that
 * subnet's own Key Refresh transmit rule.  Returns 0 and fills the credential
 * out-parameters, or -1 when net_idx is not a subnet this node holds.
 *
 * MshPRT_v1.1.1 Section 3.9.6.3.1: "For Network PDUs that are transmitted
 * according to directed forwarding functionality, the directed security
 * material is used."  Section 3.4.6.3's Table 3.14 is where "according to
 * directed forwarding functionality" is made concrete for a RETRANSMITTED
 * PDU, and one invariant runs through every row of that table: the Outbound
 * Security Material is "directed" exactly when the Outbound Bearers are "path
 * bearers", and "flooding" for every other outbound bearer set (ADV, GATT,
 * "all bearers") - whatever the Inbound Security Material was.  That
 * invariant, rather than a row-by-row transcription of a table whose
 * conditions name states this stack does not yet keep (Directed proxy,
 * Directed friend, dependent-node lists), is what the callers below
 * implement; it is an INTERPRETATION of Table 3.14, and is recorded as one.
 */
static int
net_directed_txsec(struct mesh_node *node, uint16_t net_idx, uint8_t *nid,
    const uint8_t **enc, const uint8_t **priv)
{
	struct mesh_sim_subnet_key *sn;

	if (net_idx == node->primary_net_idx) {
		if (node->have_new_key &&
		    mesh_kr_tx_key(&node->kr) == MESH_KR_KEY_NEW) {
			*nid = node->new_directed_nid;
			*enc = node->new_directed_enckey;
			*priv = node->new_directed_privkey;
		} else {
			*nid = node->directed_nid;
			*enc = node->directed_enckey;
			*priv = node->directed_privkey;
		}
		return (0);
	}
	sn = find_subnet(node, net_idx);
	if (sn == NULL)
		return (-1);
	if (sn->have_new_key && mesh_kr_tx_key(&sn->kr) == MESH_KR_KEY_NEW) {
		*nid = sn->new_directed_nid;
		*enc = sn->new_directed_enckey;
		*priv = sn->new_directed_privkey;
	} else {
		*nid = sn->directed_nid;
		*enc = sn->directed_enckey;
		*priv = sn->directed_privkey;
	}
	return (0);
}

/* ================================================================
 * Medium.
 * ================================================================ */

static int
enqueue_net_to(struct mesh_sim *sim, int tx_node, int to_node, uint8_t nid,
    const uint8_t *enc, const uint8_t *priv, uint32_t iv,
    const struct mesh_net_pdu *pdu)
{
	struct mesh_sim_tx *slot;
	uint8_t out[MESH_NET_MAX_PDU];
	size_t outlen;

	if (sim->n_tx >= MESH_SIM_MAX_TX)
		return (-1);
	if (mesh_net_encrypt(enc, priv, nid, iv, pdu, out, &outlen) != 0)
		return (-1);
	slot = &sim->tx[sim->n_tx++];
	memcpy(slot->bytes, out, outlen);
	slot->len = outlen;
	slot->tx_node = tx_node;
	slot->to_node = to_node;
	slot->valid = 1;
	return (0);
}

static int
enqueue_net(struct mesh_sim *sim, int tx_node, uint8_t nid,
    const uint8_t *enc, const uint8_t *priv, uint32_t iv,
    const struct mesh_net_pdu *pdu)
{

	int error;
	struct mesh_sim_relay_tx *job;
	size_t i;

	error = enqueue_net_to(sim, tx_node, -1, nid, enc, priv, iv, pdu);
	if (error != 0 || tx_node < 0 || tx_node >= sim->n_nodes ||
	    sim->nodes[tx_node].relay.net_tx_count == 0)
		return (error);
	job = NULL;
	for (i = 0; i < MESH_SIM_RELAY_TX; i++)
		if (!mesh_relay_tx_active(&sim->retransmit[i].timer)) {
			job = &sim->retransmit[i];
			break;
		}
	if (job == NULL)
		return (0);
	job->pdu = sim->tx[sim->n_tx - 1];
	mesh_relay_tx_schedule(&job->timer,
	    sim->nodes[tx_node].relay.net_tx_count,
	    sim->nodes[tx_node].relay.net_tx_steps, sim->now_ms);
	return (0);
}

static int
enqueue_relay(struct mesh_sim *sim, struct mesh_node *node, uint8_t nid,
    const uint8_t *enc, const uint8_t *priv, uint32_t iv,
    const struct mesh_net_pdu *pdu)
{
	struct mesh_sim_relay_tx *job;
	int error;
	size_t i;

	error = enqueue_net_to(sim, node->index, -1, nid, enc, priv, iv, pdu);
	if (error != 0 || node->relay.relay_rx_count == 0)
		return (error);
	job = NULL;
	for (i = 0; i < MESH_SIM_RELAY_TX; i++)
		if (!mesh_relay_tx_active(&sim->retransmit[i].timer)) {
			job = &sim->retransmit[i];
			break;
		}
	if (job == NULL)
		return (0);
	job->pdu = sim->tx[sim->n_tx - 1];
	mesh_relay_tx_schedule(&job->timer, node->relay.relay_rx_count,
	    node->relay.relay_rx_steps, sim->now_ms);
	return (0);
}

/*
 * Record an outstanding segmented transmission.  segs[] are the CLEARTEXT
 * Network PDUs just enqueued, kept so a retransmission can be re-secured with
 * a fresh sequence number (see struct mesh_sim_sar_tx).
 */
static void
sar_tx_record(struct mesh_sim *sim, struct mesh_node *node,
    const struct mesh_net_pdu *segs, size_t nseg, uint16_t dst,
    uint16_t seqzero, uint32_t iv)
{
	struct mesh_sim_sar_tx *s = NULL;
	int multicast;
	size_t i;

	/*
	 * A group or virtual destination is tracked too.  MshPRT_v1.1.1 Section
	 * 3.5.3.3: "For each transmission to a group address or a virtual
	 * address, the lower transport layer stores the destination address,
	 * the derived SeqAuth of the segmented message, and the remaining
	 * number of retransmissions value."  There is no acknowledgment for a
	 * multicast transaction, so that count is the only reliability it has;
	 * declining to track it sent every multicast segmented message exactly
	 * once.  MESH_ADDR_UNASSIGNED is not a destination at all.
	 */
	multicast = !mesh_addr_is_unicast(dst);
	if (dst == MESH_ADDR_UNASSIGNED || nseg == 0 || nseg > MESH_SEG_MAX)
		return;
	for (i = 0; i < MESH_SIM_SAR_TX; i++) {
		if (!node->sar_tx[i].used) {
			s = &node->sar_tx[i];
			break;
		}
		if (s == NULL || node->sar_tx[i].deadline_ms < s->deadline_ms)
			s = &node->sar_tx[i];
	}
	memset(s, 0, sizeof(*s));
	for (i = 0; i < nseg; i++)
		s->seg[i] = segs[i];
	s->dst = dst;
	s->seqzero = seqzero;
	s->iv_index = iv;
	s->segn = (uint8_t)(nseg - 1);
	s->multicast = multicast;
	if (multicast) {
		/*
		 * Section 3.5.3.3: "when the last segment is transmitted and
		 * the destination is a group or a virtual address, the lower
		 * transport layer shall start a SAR Multicast Retransmissions
		 * timer with the initial value set to the multicast
		 * retransmissions interval."
		 */
		s->retrans_left = SIM_SAR_MULTICAST_RETRANS;
		s->deadline_ms = sim->now_ms + SIM_SAR_MULTICAST_INT_MS;
	} else
		s->deadline_ms = sim->now_ms + sar_retrans_ms(node);
	s->used = 1;
}

/*
 * Repeat every segment of a multicast segmented transaction.
 *
 * MshPRT_v1.1.1 Section 3.5.3.3: "When the SAR Multicast Retransmissions timer
 * expires and the remaining number of retransmissions value is greater than 0,
 * then the lower transport layer shall repeat the transmission of all the
 * segments of the Upper Transport PDU.  The lower transport layer shall
 * decrement the remaining number of retransmissions value by 1" - and when it
 * reaches 0 the transmission is cancelled.  ALL segments are repeated, not the
 * unacknowledged ones, because a multicast transaction is never acknowledged
 * and there is no AckedSegments value for it.
 *
 * Each repeated segment takes a fresh network sequence number for the same
 * reason a unicast retransmission does: Section 3.4.6.5's network message cache
 * lets every relay drop a (SRC, SEQ, IVI) it has already processed, so
 * re-sending the original SEQ would be discarded at the first relay.
 */
static void
sar_tx_multicast_repeat(struct mesh_sim *sim, struct mesh_node *node,
    struct mesh_sim_sar_tx *s)
{
	struct mesh_net_pdu np;
	const uint8_t *enc, *priv;
	uint8_t nid;
	size_t i;

	if (s->retrans_left == 0) {
		s->used = 0;
		return;
	}
	node_tx_netsec(node, &nid, &enc, &priv);
	for (i = 0; i <= s->segn && sim->n_tx < MESH_SIM_MAX_TX; i++) {
		if (node->seq > MESH_IV_SEQ_MAX)
			break;
		np = s->seg[i];
		np.nid = nid;
		np.seq = node->seq;
		if (enqueue_net(sim, node->index, nid, enc, priv, s->iv_index,
		    &np) != 0)
			break;
		node->seq++;
	}
	s->retrans_left--;
	s->deadline_ms = sim->now_ms + SIM_SAR_MULTICAST_INT_MS;
	if (s->retrans_left == 0)
		s->used = 0;
}

/*
 * Re-send the segments the peer has not acknowledged.
 *
 * MshPRT_v1.1.1 Section 3.5.3.3 retransmits the unacknowledged segments of the
 * transaction; the transaction is identified by SeqZero, which is invariant.
 * Each retransmitted segment is a NEW Network PDU and therefore takes the next
 * sequence number: Section 3.4.5's network message cache lets every relay drop
 * a (SRC, SEQ, IVI) it has already processed, so re-sending the original SEQ
 * is silently discarded at the first relay and the retransmission never reaches
 * a multi-hop peer.  The IV Index stays pinned to the one the transaction's
 * SeqAuth was computed under.
 */
static void
sar_tx_requeue_missing(struct mesh_sim *sim, struct mesh_node *node,
    struct mesh_sim_sar_tx *s)
{
	struct mesh_net_pdu np;
	const uint8_t *enc, *priv;
	uint32_t full;
	uint8_t nid;
	size_t i;

	full = mesh_blockack_full(s->segn);
	if ((s->blockack & full) == full) {
		s->used = 0;
		return;
	}
	node_tx_netsec(node, &nid, &enc, &priv);
	for (i = 0; i <= s->segn && sim->n_tx < MESH_SIM_MAX_TX; i++) {
		if ((s->blockack & ((uint32_t)1 << i)) != 0)
			continue;
		if (node->seq > MESH_IV_SEQ_MAX)
			break;
		np = s->seg[i];
		np.nid = nid;
		np.seq = node->seq;
		if (enqueue_net(sim, node->index, nid, enc, priv, s->iv_index,
		    &np) != 0)
			break;
		node->seq++;
	}
	s->retries++;
	s->deadline_ms = sim->now_ms + sar_retrans_ms(node);
	if (s->retries >= sar_retries(node))
		s->used = 0;
}

/*
 * Does this node have a segmented transmission out that has not been
 * acknowledged?  MshPRT_v1.1.1 Section 3.11.5, verbatim:
 *
 *   "A node shall defer state change from IV Update in Progress to Normal
 *    Operation, as defined by this procedure, when the node has transmitted a
 *    Segmented Access message or a Segmented Control message without receiving
 *    the corresponding Segment Acknowledgment messages.  The deferred change
 *    of the state shall be executed when the appropriate Segment
 *    Acknowledgment message is received or the timeout for the delivery of
 *    this message is reached."
 *
 * and the reason, in the specification's own note:
 *
 *   "Note: This requirement is necessary because upon completing the IV Update
 *    procedure the sequence number is reset to 0x000000 and the SeqAuth value
 *    would not be valid."
 *
 * An occupied SAR transmit slot IS "transmitted ... without receiving the
 * corresponding Segment Acknowledgment": the slot is released when the
 * acknowledgment arrives, when a zero BlockAck cancels the transaction, or
 * when the retransmission budget / discard deadline runs out - which is the
 * "timeout for the delivery of this message" the same sentence names as the
 * other release condition.
 *
 * INTERPRETATION, recorded as one: a MULTICAST segmented transaction is held
 * here too, although Section 3.5.3.4 acknowledges only unicast destinations so
 * no "corresponding Segment Acknowledgment message" can ever arrive for it.
 * Its SeqAuth is invalidated by the sequence reset exactly as a unicast one's
 * is, and its slot is released by its own retransmission timeout, so the
 * deferral is bounded either way.
 *
 * The deferral is not a separate timer: every caller that can complete an IV
 * Update is retried (the node tick runs mesh_sim_complete_iv_update() on every
 * tick while the state is In Progress), so the completion happens on the first
 * attempt after the last slot is released.
 */
static int
node_sar_tx_unacked(const struct mesh_node *node)
{
	size_t i;

	for (i = 0; i < MESH_SIM_SAR_TX; i++)
		if (node->sar_tx[i].used)
			return (1);
	return (0);
}

/* The current virtual clock expressed in milliseconds (DF / provisioning). */
static uint64_t
sim_now_ms(const struct mesh_sim *sim)
{

	return (sim->now_ms);
}

/*
 * Wall-clock seconds for the IV Update dwell anchor.  Uses wall_now (set by
 * the host from CLOCK_REALTIME) so time-in-state survives a restart; falls
 * back to the monotonic `now` when the host has not provided a wall clock.
 */
static uint64_t
sim_iv_now(const struct mesh_sim *sim)
{

	return (sim->wall_now != 0 ? sim->wall_now : sim->now);
}

/* ================================================================
 * Setup.
 * ================================================================ */

int
mesh_sim_init(struct mesh_sim *sim, const uint8_t netkey[16],
    const uint8_t appkey[16], uint32_t iv_index)
{

	if (sim == NULL || netkey == NULL || appkey == NULL)
		return (-1);
	memset(sim, 0, sizeof(*sim));
	memcpy(sim->netkey, netkey, 16);
	memcpy(sim->appkey, appkey, 16);
	sim->iv_index = iv_index;
	sim->now = 0;
	sim->now_ms = 0;
	return (0);
}

struct mesh_node *
mesh_sim_add_node(struct mesh_sim *sim, uint16_t addr, uint8_t n_elements)
{
	struct mesh_node *node;
	size_t i;

	if (sim == NULL || n_elements == 0 || n_elements > MESH_SIM_MAX_ELEMS)
		return (NULL);
	if (sim->n_nodes >= MESH_SIM_MAX_NODES)
		return (NULL);
	node = &sim->nodes[sim->n_nodes];
	memset(node, 0, sizeof(*node));
	node->addr = addr;
	node->n_elements = n_elements;
	for (i = 0; i < n_elements; i++) {
		node->elems[i].addr = (uint16_t)(addr + i);
		node->elems[i].models = node->models[i];
		node->elems[i].n_models = 0;
	}
	memcpy(node->netkey, sim->netkey, 16);
	if (derive_subnet_material(node->netkey, &node->nid, node->enckey,
	    node->privkey, &node->directed_nid, node->directed_enckey,
	    node->directed_privkey) != 0)
		return (NULL);
	node->primary_net_idx = 0;
	if (mesh_sim_add_appkey(node, 0, 0, sim->appkey) != 0)
		return (NULL);
	mesh_iv_init(&node->iv, sim->iv_index, sim_iv_now(sim));
	node->seq = 0;
	mesh_rpl_init(&node->rpl, node->rpl_store, MESH_SIM_RPL_SIZE);
	/*
	 * The Subnet Bridge replay list (MshPRT_v1.1.1 Section 3.9.8) is bound
	 * unconditionally: a node can be made a bridge at any time by a
	 * SUBNET_BRIDGE_SET, and an unbound list would fail closed on every
	 * bridged PDU.
	 */
	mesh_rpl_init(&node->bridge_rpl, node->bridge_rpl_store,
	    MESH_SIM_RPL_SIZE);
	mesh_kr_init(&node->kr);
	node->sim = sim;
	node->index = sim->n_nodes;
	sim->n_nodes++;
	return (node);
}

/*
 * Refresh the default model binding list (mesh_node::model_app_idx) from the
 * node's AppKeys, and the per-model count of every model still pointing at it.
 * Models whose binding list came from somewhere else - a Configuration Server's
 * Config Model App Bind database, say - are left alone.
 */
static void
sim_sync_default_bindings(struct mesh_node *node)
{
	size_t i, e, m;

	for (i = 0; i < node->n_appkeys && i < MESH_SIM_MAX_APPKEYS; i++)
		node->model_app_idx[i] = node->appkeys[i].app_idx;
	for (e = 0; e < node->n_elements; e++)
		for (m = 0; m < node->elems[e].n_models; m++)
			if (node->models[e][m].app_idx == node->model_app_idx)
				node->models[e][m].n_app = node->n_appkeys;
}

int
mesh_sim_add_model(struct mesh_node *node, uint8_t elem_index,
    struct mesh_model model)
{
	struct mesh_element *el;

	if (node == NULL || elem_index >= node->n_elements)
		return (-1);
	el = &node->elems[elem_index];
	/* Sized for complete SIG application-model compositions. */
	if (el->n_models >= MESH_SIM_MAX_MODELS)
		return (-1);
	node->models[elem_index][el->n_models] = model;
	/*
	 * Bind the node's own AppKeys to the model unless the caller supplied a
	 * binding list of its own (see mesh_node::model_app_idx).  A
	 * Configuration Server overwrites this from its Config Model App Bind
	 * database; the binding CHECK in the access layer is unconditional
	 * regardless, so a model bound to nothing processes nothing.
	 */
	if (model.app_idx == NULL) {
		node->models[elem_index][el->n_models].app_idx =
		    node->model_app_idx;
		node->models[elem_index][el->n_models].n_app = node->n_appkeys;
	}
	el->n_models++;
	sim_sync_default_bindings(node);
	return (0);
}

int
mesh_sim_set_devkey(struct mesh_node *node, const uint8_t devkey[16],
    mesh_sim_devkey_rx_fn rx, void *arg)
{

	if (node == NULL || devkey == NULL)
		return (-1);
	memcpy(node->devkey, devkey, sizeof(node->devkey));
	node->have_devkey = 1;
	node->devkey_rx = rx;
	node->devkey_rx_arg = arg;
	return (0);
}

int
mesh_sim_set_devkey_client(struct mesh_node *node,
    mesh_sim_devkey_lookup_fn lookup, mesh_sim_devkey_upper_rx_fn rx, void *arg)
{

	if (node == NULL || lookup == NULL || rx == NULL)
		return (-1);
	node->devkey_lookup = lookup;
	node->devkey_upper_rx = rx;
	node->devkey_client_arg = arg;
	return (0);
}

int
mesh_sim_subscribe(struct mesh_node *node, uint16_t group)
{
	uint8_t i;

	if (node == NULL)
		return (-1);
	for (i = 0; i < node->n_elements; i++)
		if (node->elem_n_subs[i] >= MESH_SIM_MAX_SUBS)
			return (-1);
	for (i = 0; i < node->n_elements; i++)
		(void)mesh_sim_subscribe_element(node, i, group);
	return (0);
}

int
mesh_sim_subscribe_element(struct mesh_node *node, uint8_t elem_index,
    uint16_t group)
{
	size_t i;

	if (node == NULL || elem_index >= node->n_elements)
		return (-1);
	for (i = 0; i < node->elem_n_subs[elem_index]; i++)
		if (node->elem_subs[elem_index][i] == group)
			return (0);
	if (node->elem_n_subs[elem_index] >= MESH_SIM_MAX_SUBS)
		return (-1);
	node->elem_subs[elem_index][node->elem_n_subs[elem_index]++] = group;
	node->elems[elem_index].subs = node->elem_subs[elem_index];
	node->elems[elem_index].n_subs = node->elem_n_subs[elem_index];
	return (0);
}

int
mesh_sim_subscribe_virtual_element(struct mesh_node *node, uint8_t elem_index,
    const uint8_t label[MESH_LABEL_UUID_LEN])
{
	size_t i;

	if (node == NULL || label == NULL || elem_index >= node->n_elements)
		return (-1);
	for (i = 0; i < node->elem_n_labels[elem_index]; i++)
		if (memcmp(node->elem_labels[elem_index][i], label,
		    MESH_LABEL_UUID_LEN) == 0)
			return (0);
	if (node->elem_n_labels[elem_index] >= MESH_SIM_MAX_SUBS)
		return (-1);
	memcpy(node->elem_labels[elem_index][node->elem_n_labels[elem_index]++],
	    label, MESH_LABEL_UUID_LEN);
	node->elems[elem_index].labels = node->elem_labels[elem_index];
	node->elems[elem_index].n_labels = node->elem_n_labels[elem_index];
	return (0);
}

void
mesh_sim_clear_subscriptions(struct mesh_node *node, uint8_t elem_index)
{

	if (node == NULL || elem_index >= node->n_elements)
		return;
	node->elem_n_subs[elem_index] = 0;
	node->elem_n_labels[elem_index] = 0;
	node->elems[elem_index].subs = node->elem_subs[elem_index];
	node->elems[elem_index].n_subs = 0;
	node->elems[elem_index].labels = node->elem_labels[elem_index];
	node->elems[elem_index].n_labels = 0;
}

int
mesh_sim_link(struct mesh_sim *sim, struct mesh_node *a, struct mesh_node *b)
{

	if (sim == NULL || a == NULL || b == NULL || a == b)
		return (-1);
	sim->use_topology = 1;
	sim->linked[a->index][b->index] = 1;
	sim->linked[b->index][a->index] = 1;
	return (0);
}

/*
 * Subnet Bridge state (MshPRT_v1.1.1 Section 4.2.41) and Bridging Table state
 * (Section 4.2.42).  See mesh_sim.h for why both clear the bridge replay list.
 */
void
mesh_sim_set_bridge(struct mesh_node *node, int enabled)
{

	if (node == NULL)
		return;
	node->bridge_enabled = enabled ? 1 : 0;
	mesh_rpl_reset(&node->bridge_rpl);
}

void
mesh_sim_set_bridging_table(struct mesh_node *node,
    const struct mesh_bridging_table *t)
{

	if (node == NULL)
		return;
	if (t == NULL)
		memset(&node->bridge_table, 0, sizeof(node->bridge_table));
	else
		node->bridge_table = *t;
	mesh_rpl_reset(&node->bridge_rpl);
}

void
mesh_sim_set_relay(struct mesh_node *node, int enabled)
{

	if (node == NULL)
		return;
	node->is_relay = enabled ? 1 : 0;
	node->relay.enabled = enabled ? 1 : 0;
	/*
	 * The Directed Forwarding managed-flooding fallback IS the Relay
	 * feature: node_recv_net always takes the DF branch (df_enabled is set
	 * once at init) and mesh_df_forward_decide falls back to FLOOD purely on
	 * managed_flood_relay.  Track the Relay state here too, or Config Relay
	 * Set = 0 has no effect and the node keeps re-flooding (NB-3).
	 */
	node->df_feat.managed_flood_relay = enabled ? 1 : 0;
}

void
mesh_sim_set_friend_feature(struct mesh_node *node, int enabled)
{

	if (node != NULL)
		node->friend_feature = enabled ? 1 : 0;
}

int
mesh_sim_set_friend(struct mesh_node *node, uint16_t lpn_addr,
    uint8_t lpn_elements, size_t qcap)
{

	if (node == NULL || lpn_elements == 0)
		return (-1);
	node->is_friend = 1;
	node->friend_lpn = lpn_addr;
	mesh_fq_init(&node->fq, lpn_addr, lpn_elements, qcap);
	return (0);
}

int
mesh_sim_set_lpn(struct mesh_node *node, uint16_t friend_addr,
    uint32_t poll_timeout)
{

	if (node == NULL)
		return (-1);
	if (mesh_lpn_init(&node->lpn, poll_timeout, 0) != 0)
		return (-1);
	node->is_lpn = 1;
	node->awake = 0;
	node->lpn_friend = friend_addr;
	return (0);
}

int
mesh_sim_establish_friendship(struct mesh_sim *sim, struct mesh_node *friend,
    struct mesh_node *lpn, uint16_t net_idx, uint16_t lpn_counter,
    uint16_t friend_counter)
{
	struct mesh_sim_subnet_key *friend_subnet, *lpn_subnet;
	const uint8_t *friend_key, *lpn_key;

	if (sim == NULL || friend == NULL || lpn == NULL)
		return (-1);
	if (!friend->is_friend || !lpn->is_lpn)
		return (-1);
	if (net_idx == friend->primary_net_idx)
		friend_key = friend->netkey;
	else {
		friend_subnet = find_subnet(friend, net_idx);
		if (friend_subnet == NULL)
			return (-1);
		friend_key = friend_subnet->netkey;
	}
	if (net_idx == lpn->primary_net_idx)
		lpn_key = lpn->netkey;
	else {
		lpn_subnet = find_subnet(lpn, net_idx);
		if (lpn_subnet == NULL)
			return (-1);
		lpn_key = lpn_subnet->netkey;
	}
	if (timingsafe_bcmp(friend_key, lpn_key, 16) != 0)
		return (-1);
	/*
	 * Both endpoints derive the SAME friendship credential from the subnet
	 * NetKey and the exchanged addresses/counters (Section 3.6.6.2).
	 */
	if (mesh_sim_friend_cred_derive(friend, net_idx, lpn->addr,
	    friend->addr, lpn_counter, friend_counter) != 0)
		return (-1);
	if (mesh_sim_friend_cred_derive(lpn, net_idx, lpn->addr, friend->addr,
	    lpn_counter, friend_counter) != 0)
		return (-1);
	mesh_lpn_established(&lpn->lpn);
	return (0);
}

int
mesh_sim_add_subnet(struct mesh_node *node, uint16_t net_idx,
    const uint8_t netkey[16])
{
	struct mesh_sim_subnet_key *subnet;
	size_t i;

	if (node == NULL || netkey == NULL || net_idx > 0x0fff)
		return (-1);
	if (net_idx == node->primary_net_idx)
		return (timingsafe_bcmp(node->netkey, netkey, 16) == 0 ? 0 : -1);
	for (i = 0; i < node->n_subnets; i++) {
		if (node->subnets[i].valid && node->subnets[i].net_idx == net_idx)
			return (timingsafe_bcmp(node->subnets[i].netkey, netkey, 16) == 0 ?
			    0 : -1);
	}
	if (node->n_subnets >= MESH_SIM_MAX_SUBNETS - 1)
		return (-1);
	subnet = &node->subnets[node->n_subnets];
	memset(subnet, 0, sizeof(*subnet));
	subnet->valid = 1;
	subnet->net_idx = net_idx;
	mesh_kr_init(&subnet->kr);
	memcpy(subnet->netkey, netkey, 16);
	if (derive_subnet_material(subnet->netkey, &subnet->nid, subnet->enckey,
	    subnet->privkey, &subnet->directed_nid, subnet->directed_enckey,
	    subnet->directed_privkey) != 0) {
		memset(subnet, 0, sizeof(*subnet));
		return (-1);
	}
	node->n_subnets++;
	return (0);
}

int
mesh_sim_add_appkey(struct mesh_node *node, uint16_t net_idx,
    uint16_t app_idx, const uint8_t appkey[16])
{
	struct mesh_sim_app_key *entry;
	size_t i;
	int have_subnet;

	if (node == NULL || appkey == NULL || net_idx > 0x0fff ||
	    app_idx > 0x0fff)
		return (-1);
	have_subnet = net_idx == node->primary_net_idx;
	for (i = 0; i < node->n_subnets; i++)
		if (node->subnets[i].valid && node->subnets[i].net_idx == net_idx)
			have_subnet = 1;
	if (!have_subnet)
		return (-1);
	for (i = 0; i < node->n_appkeys; i++) {
		entry = &node->appkeys[i];
		if (entry->valid && entry->app_idx == app_idx) {
			if (entry->net_idx != net_idx)
				return (-1);
			/*
			 * A Config AppKey Add replaces the key outright, so any
			 * key staged by a Config AppKey Update is discarded
			 * with it (Section 4.4.1.2.13).
			 */
			memcpy(entry->key, appkey, 16);
			entry->have_new_key = 0;
			explicit_bzero(entry->new_key, sizeof(entry->new_key));
			entry->new_aid = 0;
			return (mesh_k4(entry->key, &entry->aid));
		}
	}
	if (node->n_appkeys >= MESH_SIM_MAX_APPKEYS)
		return (-1);
	entry = &node->appkeys[node->n_appkeys];
	memset(entry, 0, sizeof(*entry));
	entry->valid = 1;
	entry->net_idx = net_idx;
	entry->app_idx = app_idx;
	memcpy(entry->key, appkey, 16);
	if (mesh_k4(entry->key, &entry->aid) != 0) {
		memset(entry, 0, sizeof(*entry));
		return (-1);
	}
	node->n_appkeys++;
	sim_sync_default_bindings(node);
	return (0);
}

int
mesh_sim_remove_appkey(struct mesh_node *node, uint16_t app_idx)
{
	size_t i;

	if (node == NULL)
		return (-1);
	for (i = 0; i < node->n_appkeys; i++) {
		if (!node->appkeys[i].valid || node->appkeys[i].app_idx != app_idx)
			continue;
		memmove(&node->appkeys[i], &node->appkeys[i + 1],
		    (node->n_appkeys - i - 1) * sizeof(node->appkeys[0]));
		node->n_appkeys--;
		memset(&node->appkeys[node->n_appkeys], 0,
		    sizeof(node->appkeys[0]));
		sim_sync_default_bindings(node);
		return (0);
	}
	return (-1);
}

/* Find one application key index on this node. */
static struct mesh_sim_app_key *
find_appkey(struct mesh_node *node, uint16_t app_idx)
{
	size_t i;

	for (i = 0; i < node->n_appkeys; i++)
		if (node->appkeys[i].valid &&
		    node->appkeys[i].app_idx == app_idx)
			return (&node->appkeys[i]);
	return (NULL);
}

int
mesh_sim_appkey_update(struct mesh_node *node, uint16_t net_idx,
    uint16_t app_idx, const uint8_t new_key[16])
{
	struct mesh_sim_app_key *e;

	if (node == NULL || new_key == NULL)
		return (-1);
	e = find_appkey(node, app_idx);
	if (e == NULL || e->net_idx != net_idx)
		return (-1);
	if (mesh_k4(new_key, &e->new_aid) != 0)
		return (-1);
	memcpy(e->new_key, new_key, 16);
	e->have_new_key = 1;
	return (0);
}

int
mesh_sim_appkey_finalize(struct mesh_node *node, uint16_t app_idx)
{
	struct mesh_sim_app_key *e;

	if (node == NULL)
		return (-1);
	e = find_appkey(node, app_idx);
	if (e == NULL || !e->have_new_key)
		return (-1);
	memcpy(e->key, e->new_key, 16);
	e->aid = e->new_aid;
	e->have_new_key = 0;
	explicit_bzero(e->new_key, sizeof(e->new_key));
	e->new_aid = 0;
	return (0);
}

/*
 * The Key Refresh state of the subnet an AppKey is bound to, or NULL when the
 * subnet is unknown.  MshPRT_v1.1.1 Section 3.11.4: application keys follow the
 * phase of their bound NetKey.
 */
static const struct mesh_key_refresh *
appkey_subnet_kr(const struct mesh_node *node, uint16_t net_idx)
{
	size_t i;

	if (net_idx == node->primary_net_idx)
		return (node->have_new_key ? &node->kr : NULL);
	for (i = 0; i < node->n_subnets; i++)
		if (node->subnets[i].valid &&
		    node->subnets[i].net_idx == net_idx)
			return (node->subnets[i].have_new_key ?
			    &node->subnets[i].kr : NULL);
	return (NULL);
}

/*
 * Select the application key used to TRANSMIT under this index.  Section
 * 3.11.4: Phase 1 transmits with the old key, Phase 2 with the new one.
 */
static void
appkey_tx(const struct mesh_node *node, const struct mesh_sim_app_key *ak,
    const uint8_t **key, uint8_t *aid)
{
	const struct mesh_key_refresh *kr;

	if (ak->have_new_key) {
		kr = appkey_subnet_kr(node, ak->net_idx);
		if (kr != NULL && mesh_kr_tx_key(kr) == MESH_KR_KEY_NEW) {
			*key = ak->new_key;
			*aid = ak->new_aid;
			return;
		}
	}
	*key = ak->key;
	*aid = ak->aid;
}

int
mesh_sim_remove_subnet(struct mesh_node *node, uint16_t net_idx)
{
	size_t i;

	if (node == NULL || net_idx == node->primary_net_idx)
		return (-1);
	for (i = node->n_appkeys; i > 0; i--)
		if (node->appkeys[i - 1].valid &&
		    node->appkeys[i - 1].net_idx == net_idx)
			(void)mesh_sim_remove_appkey(node,
			    node->appkeys[i - 1].app_idx);
	for (i = 0; i < node->n_subnets; i++) {
		if (!node->subnets[i].valid || node->subnets[i].net_idx != net_idx)
			continue;
		memmove(&node->subnets[i], &node->subnets[i + 1],
		    (node->n_subnets - i - 1) * sizeof(node->subnets[0]));
		node->n_subnets--;
		memset(&node->subnets[node->n_subnets], 0,
		    sizeof(node->subnets[0]));
		return (0);
	}
	return (-1);
}

void
mesh_sim_set_proxy(struct mesh_node *node)
{

	if (node == NULL)
		return;
	node->is_proxy = 1;
	mesh_proxy_filter_init(&node->pfilter);
}

int
mesh_sim_proxy_apply_config(struct mesh_node *node, const uint8_t *secured_pdu,
    size_t len)
{
	struct mesh_proxy_cfg cfg;
	uint8_t msg[MESH_PROXY_MAX_MSG];
	size_t msglen;
	uint32_t iv;

	if (node == NULL || secured_pdu == NULL || !node->is_proxy)
		return (-1);
	iv = mesh_iv_tx_index(&node->iv);
	if (mesh_proxy_cfg_decrypt(node->enckey, node->privkey, node->nid, iv,
	    secured_pdu, len, NULL, NULL, msg, sizeof(msg), &msglen) != 0)
		return (-1);
	if (mesh_proxy_cfg_parse(msg, msglen, &cfg) != 0)
		return (-1);
	switch (cfg.opcode) {
	case MESH_PROXY_OP_SET_FILTER_TYPE:
		return (mesh_proxy_filter_set_type(&node->pfilter,
		    cfg.filter_type));
	case MESH_PROXY_OP_ADD_ADDR:
		return (mesh_proxy_filter_add(&node->pfilter, cfg.addrs,
		    cfg.naddr));
	case MESH_PROXY_OP_REMOVE_ADDR:
		return (mesh_proxy_filter_remove(&node->pfilter, cfg.addrs,
		    cfg.naddr));
	default:
		return (-1);
	}
}

int
mesh_sim_proxy_gatt_in(struct mesh_sim *sim, struct mesh_node *proxy,
    const uint8_t *net_pdu, size_t len)
{

	if (sim == NULL || proxy == NULL || net_pdu == NULL || !proxy->is_proxy ||
	    len == 0 || len > MESH_NET_MAX_PDU)
		return (-1);
	/*
	 * MshPRT_v1.1 Section 6.7: the Proxy Server both relays the PDU onto the
	 * advertising bearer (reinject) and hands it to its own network layer.
	 * mesh_sim_step() skips delivery back to the transmitting node, so a PDU
	 * addressed to the proxy (or a group it subscribes to) would never be
	 * delivered locally; deliver it here.
	 */
	node_recv_net(sim, proxy, net_pdu, len, -1);
	return (mesh_sim_reinject(sim, proxy->index, net_pdu, len));
}

/* ================================================================
 * Transmit path.
 * ================================================================ */

/*
 * Originate an access message secured with explicit network (nid/enc/priv) and
 * application (appkey/aid) material.  node_originate() below wraps this with the
 * node's primary-subnet (Key-Refresh-aware) credential; the secondary-subnet
 * originator supplies the netkey2/appkey2 credential instead.
 */
static int
node_originate_ex(struct mesh_sim *sim, struct mesh_node *node,
    uint16_t src_addr, uint16_t dst, uint32_t opcode, const uint8_t *params,
    size_t plen, uint8_t ttl, uint8_t nid, const uint8_t *enc,
    const uint8_t *priv, const uint8_t *appkey, uint8_t aid,
    const uint8_t *label)
{
	uint8_t apdu[MESH_ACCESS_PAYLOAD_MAX];
	uint8_t upper[SIM_UPPER_MAX];
	struct mesh_net_pdu np;
	uint32_t iv, seq0;
	size_t apdu_len, upper_len;
	uint16_t va;

	if (mesh_addr_is_virtual(dst)) {
		if (label == NULL || mesh_virtual_addr(label, &va) != 0 || va != dst)
			return (-1);
	} else if (label != NULL)
		return (-1);
	if (mesh_access_pdu_build(opcode, params, plen, apdu, &apdu_len) != 0)
		return (-1);
	seq0 = node->seq;
	iv = mesh_iv_tx_index(&node->iv);
	if (seq0 > MESH_IV_SEQ_MAX)
		return (-1);
	if (mesh_upper_encrypt(appkey, 1, 0, seq0, src_addr, dst, iv,
	    label, apdu, apdu_len, upper, &upper_len) != 0)
		return (-1);

	if (upper_len <= MESH_NET_MAX_TRANSPORT_PDU - 1) {
		/* Unsegmented access Lower Transport PDU. */
		struct mesh_lower lt;
		uint8_t lt_bytes[MESH_LOWER_DATA_MAX];
		size_t lt_len;

		memset(&lt, 0, sizeof(lt));
		lt.seg = 0;
		lt.ctl = 0;
		lt.akf = 1;
		lt.aid = aid;
		memcpy(lt.data, upper, upper_len);
		lt.data_len = upper_len;
		if (mesh_lower_build(&lt, lt_bytes, &lt_len) != 0)
			return (-1);
		memset(&np, 0, sizeof(np));
		np.nid = nid;
		np.ctl = 0;
		np.ttl = ttl;
		np.seq = seq0;
		np.src = src_addr;
		np.dst = dst;
		memcpy(np.transport, lt_bytes, lt_len);
		np.transport_len = lt_len;
		if (enqueue_net(sim, node->index, nid, enc, priv, iv, &np) != 0)
			return (-1);
		node->seq++;
		return (0);
	} else {
		/* Segmented access. */
		struct mesh_seg segs[MESH_SEG_MAX];
		struct mesh_net_pdu snp[MESH_SEG_MAX];
		size_t nseg, i;
		uint16_t seqzero = (uint16_t)(seq0 & 0x1fff);

		if (mesh_sar_segment(1, aid, 0, seqzero, upper, upper_len,
		    segs, MESH_SEG_MAX, &nseg) != 0)
			return (-1);
		if (nseg - 1 > MESH_IV_SEQ_MAX - seq0 ||
		    nseg > MESH_SIM_MAX_TX - sim->n_tx)
			return (-1);
		for (i = 0; i < nseg; i++) {
			memset(&np, 0, sizeof(np));
			np.nid = nid;
			np.ctl = 0;
			np.ttl = ttl;
			np.seq = seq0 + (uint32_t)i;
			np.src = src_addr;
			np.dst = dst;
			memcpy(np.transport, segs[i].bytes, segs[i].len);
			np.transport_len = segs[i].len;
			if (enqueue_net(sim, node->index, nid, enc, priv, iv,
			    &np) != 0)
				return (-1);
			snp[i] = np;
		}
		sar_tx_record(sim, node, snp, nseg, dst, seqzero, iv);
		node->seq += (uint32_t)nseg;
		return (0);
	}
}

static int
node_originate(struct mesh_sim *sim, struct mesh_node *node, uint16_t src_addr,
    uint16_t dst, uint32_t opcode, const uint8_t *params, size_t plen,
    uint8_t ttl)
{
	const uint8_t *enc, *priv, *akey;
	uint8_t nid, aid;

	node_tx_netsec(node, &nid, &enc, &priv);
	if (node->n_appkeys == 0)
		return (-1);
	appkey_tx(node, &node->appkeys[0], &akey, &aid);
	return (node_originate_ex(sim, node, src_addr, dst, opcode, params, plen,
	    ttl, nid, enc, priv, akey, aid, NULL));
}

static int
node_tx_control(struct mesh_sim *sim, struct mesh_node *node, uint16_t dst,
    const uint8_t *lt, size_t lt_len, uint8_t ttl, int friend_cred)
{
	struct mesh_net_pdu np;
	uint8_t nid;
	const uint8_t *enc, *priv;
	uint32_t iv;

	/*
	 * The friendship credential is reserved for actual Friend<->LPN traffic
	 * (e.g. the LPN's Friend Poll): only such PDUs (friend_cred) may use it
	 * (Section 3.6.6.2).  Every other control PDU (e.g. a Segment Ack to a
	 * third party) uses the managed-flooding subnet credential.
	 */
	if (!friend_cred ||
	    mesh_sim_friend_txsec(node, &nid, &enc, &priv) != 0)
		node_tx_netsec(node, &nid, &enc, &priv);
	iv = mesh_iv_tx_index(&node->iv);
	if (node->seq > MESH_IV_SEQ_MAX)
		return (-1);
	memset(&np, 0, sizeof(np));
	np.nid = nid;
	np.ctl = 1;
	np.ttl = ttl;
	np.seq = node->seq;
	np.src = node->addr;
	np.dst = dst;
	memcpy(np.transport, lt, lt_len);
	np.transport_len = lt_len;
	if (enqueue_net(sim, node->index, nid, enc, priv, iv, &np) != 0)
		return (-1);
	node->seq++;
	return (0);
}

static struct mesh_sim_reasm *
reasm_session(struct mesh_sim *sim, struct mesh_node *node, uint16_t src,
    uint32_t seqauth, uint32_t iv, int ctl)
{
	struct mesh_sim_reasm *free_slot = NULL;
	size_t i;

	for (i = 0; i < MESH_SIM_REASM; i++) {
		struct mesh_sim_reasm *s = &node->reasm[i];

		if (s->used && sim->now_ms >= s->deadline_ms) {
			/*
			 * MshPRT_v1.1.1 Section 3.5.3.4: when the SAR Discard
			 * timer expires the reassembly has failed, and the
			 * layer "shall stop the SAR Acknowledgment timer, stop
			 * the SAR Discard timer, remove the AckedSegments value
			 * and discard all stored segments" - so no
			 * acknowledgment is emitted for the abandoned SeqAuth.
			 */
			s->ack_armed = 0;
			s->used = 0;
		}
		if (s->used && s->r.src == src && s->seqauth == seqauth &&
		    s->iv_index == iv && s->ctl == ctl)
			return (s);
		if (!s->used && free_slot == NULL)
			free_slot = s;
	}
	return (free_slot);
}

/*
 * Emit a Segment Acknowledgment message to dst.
 *
 * MshPRT_v1.1.1 Section 3.5.2.3.1 defines the message; Section 3.5.3.4 defines
 * the OBO field: "The OBO field shall be set to 0 by a node that is directly
 * addressed by the received message and shall be set to 1 by a Friend node
 * that is acknowledging this message on behalf of a Low Power node."  It always
 * uses the managed-flooding credential: the acknowledgment goes back to the
 * originator on the network, not to the Low Power node.
 */
static void
send_seg_ack(struct mesh_sim *sim, struct mesh_node *node, uint16_t dst,
    uint16_t seqzero, uint32_t blockack, uint8_t ttl, int obo)
{
	struct mesh_seg_ack ack;
	uint8_t lt[MESH_SEG_ACK_LEN];
	size_t len;

	if (!mesh_addr_is_unicast(dst))
		return;
	memset(&ack, 0, sizeof(ack));
	ack.seqzero = seqzero;
	ack.blockack = blockack;
	ack.obo = obo ? 1 : 0;
	if (mesh_seg_ack_build(&ack, lt, &len) == 0)
		(void)node_tx_control(sim, node, dst, lt, len, ttl, 0);
}

/*
 * Arm (or re-arm) the SAR Acknowledgment timer for one reassembly session.
 *
 * MshPRT_v1.1.1 Section 3.5.3.4 starts the timer "from the initial value" on a
 * First Segment and again on every Next Segment to a unicast destination, and
 * the acknowledgment is emitted only when that timer expires.  Because every
 * arriving segment pushes the deadline out, a burst of segments arriving faster
 * than the delay produces ONE acknowledgment rather than one per segment.
 * ack_src / ack_seqzero / ack_ttl are captured so the expiry can address the
 * acknowledgment without the segment in hand: Section 3.5.3.4 requires "the
 * DST field shall have the same value as the SRC field of the first received
 * segment of the segmented message".
 */
static void
sar_ack_arm(struct mesh_sim *sim, struct mesh_sim_reasm *sess, uint16_t src,
    uint16_t seqzero, uint8_t rx_ttl)
{

	sess->ack_src = src;
	sess->ack_seqzero = seqzero;
	sess->ack_ttl = rx_ttl;
	sess->ack_due_ms = sim->now_ms + sar_ack_delay_ms(sess->r.segn);
	sess->ack_armed = 1;
}

/*
 * TTL for a Segment Acknowledgment message.  MshPRT_v1.1.1 Section 3.5.2.3.1:
 * "If the received segments were sent with the TTL field set to 0, it is
 * recommended that the corresponding Segment Acknowledgment message is sent
 * with the TTL field set to 0."  A PDU is only relayed with TTL >= 2 and is
 * decremented by one, so a received TTL of 0 is exactly a segment that was
 * originated with TTL 0; every other ack goes out with the default TTL rather
 * than the residual received value.
 */
static uint8_t
seg_ack_ttl(uint8_t rx_ttl)
{

	return (rx_ttl == 0 ? 0 : SIM_DEFAULT_TTL);
}

/*
 * Is this node an established Low Power node?
 *
 * MshPRT_v1.1.1 Section 3.5.3.5 / .txt line 4747: "When the Low Power node
 * feature is in use, reassembly is performed by a Friend node and the Low Power
 * node does not send any Segment Acknowledgment messages."
 */
static int
lpn_in_use(const struct mesh_node *node)
{

	return (node->is_lpn && node->have_friend_cred);
}

int
mesh_sim_send_access(struct mesh_sim *sim, struct mesh_node *node, uint16_t dst,
    uint32_t opcode, const uint8_t *params, size_t plen, uint8_t ttl)
{

	if (sim == NULL || node == NULL)
		return (-1);
	return (node_originate(sim, node, node->addr, dst, opcode, params,
	    plen, ttl));
}

int
mesh_sim_send_upper(struct mesh_sim *sim, struct mesh_node *node, uint16_t dst,
    uint32_t seq0, const uint8_t *upper, size_t upper_len, int akf, uint8_t aid,
    uint8_t ttl)
{
	struct mesh_net_pdu np;
	uint8_t nid;
	const uint8_t *enc, *priv;
	uint32_t iv;

	if (sim == NULL || node == NULL || upper == NULL || upper_len == 0 ||
	    upper_len > SIM_UPPER_MAX)
		return (-1);
	node_tx_netsec(node, &nid, &enc, &priv);
	iv = mesh_iv_tx_index(&node->iv);
	if (seq0 > MESH_IV_SEQ_MAX)
		return (-1);

	if (upper_len <= MESH_NET_MAX_TRANSPORT_PDU - 1) {
		/* Unsegmented Lower Transport PDU. */
		struct mesh_lower lt;
		uint8_t lt_bytes[MESH_LOWER_DATA_MAX];
		size_t lt_len;

		memset(&lt, 0, sizeof(lt));
		lt.seg = 0;
		lt.ctl = 0;
		lt.akf = akf ? 1 : 0;
		lt.aid = aid;
		memcpy(lt.data, upper, upper_len);
		lt.data_len = upper_len;
		if (mesh_lower_build(&lt, lt_bytes, &lt_len) != 0)
			return (-1);
		memset(&np, 0, sizeof(np));
		np.nid = nid;
		np.ctl = 0;
		np.ttl = ttl;
		np.seq = seq0;
		np.src = node->addr;
		np.dst = dst;
		memcpy(np.transport, lt_bytes, lt_len);
		np.transport_len = lt_len;
		if (enqueue_net(sim, node->index, nid, enc, priv, iv, &np) != 0)
			return (-1);
		return (1);
	} else {
		/* Segmented access. */
		struct mesh_seg segs[MESH_SEG_MAX];
		struct mesh_net_pdu snp[MESH_SEG_MAX];
		size_t nseg, i;
		uint16_t seqzero = (uint16_t)(seq0 & 0x1fff);

		if (mesh_sar_segment(akf ? 1 : 0, aid, 0, seqzero, upper,
		    upper_len, segs, MESH_SEG_MAX, &nseg) != 0)
			return (-1);
		if (nseg - 1 > MESH_IV_SEQ_MAX - seq0 ||
		    nseg > MESH_SIM_MAX_TX - sim->n_tx)
			return (-1);
		for (i = 0; i < nseg; i++) {
			memset(&np, 0, sizeof(np));
			np.nid = nid;
			np.ctl = 0;
			np.ttl = ttl;
			np.seq = seq0 + (uint32_t)i;
			np.src = node->addr;
			np.dst = dst;
			memcpy(np.transport, segs[i].bytes, segs[i].len);
			np.transport_len = segs[i].len;
			if (enqueue_net(sim, node->index, nid, enc, priv, iv,
			    &np) != 0)
				return (-1);
			snp[i] = np;
		}
		sar_tx_record(sim, node, snp, nseg, dst, seqzero, iv);
		return ((int)nseg);
	}
}

int
mesh_sim_send_access_key(struct mesh_sim *sim, struct mesh_node *node,
    uint16_t net_idx, uint16_t app_idx, uint16_t dst, uint32_t opcode,
    const uint8_t *params, size_t plen, uint8_t ttl)
{

	if (node == NULL)
		return (-1);
	return (mesh_sim_send_access_key_from(sim, node, node->addr, net_idx,
	    app_idx, dst, opcode, params, plen, ttl));
}

int
mesh_sim_send_access_key_from(struct mesh_sim *sim, struct mesh_node *node,
    uint16_t src, uint16_t net_idx, uint16_t app_idx, uint16_t dst,
    uint32_t opcode, const uint8_t *params, size_t plen, uint8_t ttl)
{
	const struct mesh_sim_subnet_key *subnet = NULL;
	const struct mesh_sim_app_key *appkey = NULL;
	const uint8_t *akey;
	uint8_t aid;
	size_t i;

	if (sim == NULL || node == NULL || src < node->addr ||
	    (uint32_t)src >= (uint32_t)node->addr + node->n_elements)
		return (-1);
	for (i = 0; i < node->n_appkeys; i++)
		if (node->appkeys[i].valid && node->appkeys[i].app_idx == app_idx &&
		    node->appkeys[i].net_idx == net_idx)
			appkey = &node->appkeys[i];
	if (appkey == NULL)
		return (-1);
	/* Section 3.11.4: the AppKey follows its bound subnet's phase. */
	appkey_tx(node, appkey, &akey, &aid);
	if (net_idx == node->primary_net_idx && node->have_new_key &&
	    mesh_kr_tx_key(&node->kr) == MESH_KR_KEY_NEW)
		return (node_originate_ex(sim, node, src, dst, opcode,
		    params, plen, ttl, node->new_nid, node->new_enckey,
		    node->new_privkey, akey, aid, NULL));
	if (net_idx == node->primary_net_idx)
		return (node_originate_ex(sim, node, src, dst, opcode,
		    params, plen, ttl, node->nid, node->enckey, node->privkey,
		    akey, aid, NULL));
	for (i = 0; i < node->n_subnets; i++)
		if (node->subnets[i].valid && node->subnets[i].net_idx == net_idx)
			subnet = &node->subnets[i];
	if (subnet == NULL)
		return (-1);
	if (subnet->have_new_key &&
	    mesh_kr_tx_key(&subnet->kr) == MESH_KR_KEY_NEW)
		return (node_originate_ex(sim, node, src, dst, opcode,
		    params, plen, ttl, subnet->new_nid, subnet->new_enckey,
		    subnet->new_privkey, akey, aid, NULL));
	return (node_originate_ex(sim, node, src, dst, opcode, params,
	    plen, ttl, subnet->nid, subnet->enckey, subnet->privkey,
	    akey, aid, NULL));
}

int
mesh_sim_send_access_key_from_virtual(struct mesh_sim *sim,
    struct mesh_node *node, uint16_t src, uint16_t net_idx, uint16_t app_idx,
    const uint8_t label[MESH_LABEL_UUID_LEN], uint32_t opcode,
    const uint8_t *params, size_t plen, uint8_t ttl)
{
	const struct mesh_sim_subnet_key *subnet = NULL;
	const struct mesh_sim_app_key *appkey = NULL;
	const uint8_t *nidp, *enc, *priv;
	uint16_t dst;
	size_t i;
	uint8_t nid;

	if (sim == NULL || node == NULL || label == NULL ||
	    src < node->addr ||
	    (uint32_t)src >= (uint32_t)node->addr + node->n_elements ||
	    mesh_virtual_addr(label, &dst) != 0)
		return (-1);
	for (i = 0; i < node->n_appkeys; i++)
		if (node->appkeys[i].valid && node->appkeys[i].app_idx == app_idx &&
		    node->appkeys[i].net_idx == net_idx)
			appkey = &node->appkeys[i];
	if (appkey == NULL)
		return (-1);
	if (net_idx == node->primary_net_idx) {
		if (node->have_new_key &&
		    mesh_kr_tx_key(&node->kr) == MESH_KR_KEY_NEW) {
			nid = node->new_nid; enc = node->new_enckey;
			priv = node->new_privkey;
		} else {
			nid = node->nid; enc = node->enckey; priv = node->privkey;
		}
	} else {
		for (i = 0; i < node->n_subnets; i++)
			if (node->subnets[i].valid &&
			    node->subnets[i].net_idx == net_idx)
				subnet = &node->subnets[i];
		if (subnet == NULL)
			return (-1);
		if (subnet->have_new_key &&
		    mesh_kr_tx_key(&subnet->kr) == MESH_KR_KEY_NEW) {
			nid = subnet->new_nid; enc = subnet->new_enckey;
			priv = subnet->new_privkey;
		} else {
			nid = subnet->nid; enc = subnet->enckey;
			priv = subnet->privkey;
		}
	}
	nidp = &nid;
	return (node_originate_ex(sim, node, src, dst, opcode, params, plen,
	    ttl, *nidp, enc, priv, appkey->key, appkey->aid, label));
}

/* ================================================================
 * Receive path.
 * ================================================================ */

/*
 * Attempt to decrypt a received PDU under the node's key/IV candidates.
 * On success fills *out, records the IV used and, via the enc/priv/nid out-
 * pointers, the key material that verified (so a relay can re-secure with the
 * same subnet credential), and reports through *friend_cred_used /
 * *directed_cred_used which of the three families of Section 3.9.6.3.1
 * authenticated.  Returns 0 on success, -1 if no candidate authenticated.
 *
 * The inbound family matters to the caller because it is the Inbound Security
 * Material column of Table 3.14, and because neither friendship nor directed
 * material may simply be re-used on an outbound copy: friendship material is
 * held only by this node and its LPN, and directed material belongs to the
 * path bearers alone.
 */
static int
try_decrypt(struct mesh_node *node, const uint8_t *bytes, size_t len,
    struct mesh_net_pdu *out, uint32_t *iv_used, uint8_t *nid_used,
    const uint8_t **enc_used, const uint8_t **priv_used,
    uint16_t *net_idx_used, int *friend_cred_used, int *directed_cred_used)
{
	struct {
		uint8_t		nid;
		const uint8_t	*enc;
		const uint8_t	*priv;
		uint16_t	net_idx;
		int		friend_cred;
		int		directed_cred;
	/*
	 * Capacity, stated so it is checkable rather than incidental.  Each
	 * subnet contributes up to FOUR candidates - flooding and directed,
	 * each in old-key and new-key form - and the primary subnet is held
	 * outside the subnets[] array, so the worst case is
	 * (1 + n_subnets) * 4 plus the two friendship credentials.
	 * mesh_sim_add_subnet() caps n_subnets at MESH_SIM_MAX_SUBNETS - 1,
	 * which leaves this bound with slack rather than with none.
	 */
	} cand[(MESH_SIM_MAX_SUBNETS + 1) * 4 + 2];
	uint32_t ivs[2];
	int n_iv, i, c, ncand;
	size_t si;

	ivs[0] = node->iv.iv_index;
	n_iv = 1;
	if (node->iv.iv_index > 0) {
		ivs[1] = node->iv.iv_index - 1;
		n_iv = 2;
	}

	/*
	 * Assemble the network-credential candidates this node will try, in the
	 * MshPRT_v1.1 Section 3.4.6.3 NID-candidate sense: the primary subnet
	 * (Key-Refresh old/new), the friendship credential, and any secondary
	 * subnet.  AppKey/AID selection is intentionally deferred until after
	 * network authentication because a subnet can bind multiple AppKeys.
	 */
	ncand = 0;
	memset(cand, 0, sizeof(cand));
	if (mesh_kr_rx_accept_old(&node->kr)) {
		cand[ncand].nid = node->nid;
		cand[ncand].enc = node->enckey;
		cand[ncand].priv = node->privkey;
		cand[ncand].net_idx = node->primary_net_idx;
		ncand++;
	}
	if (node->have_new_key && mesh_kr_rx_accept_new(&node->kr)) {
		cand[ncand].nid = node->new_nid;
		cand[ncand].enc = node->new_enckey;
		cand[ncand].priv = node->new_privkey;
		cand[ncand].net_idx = node->primary_net_idx;
		ncand++;
	}
	if (node->have_friend_cred) {
		cand[ncand].nid = node->friend_nid;
		cand[ncand].enc = node->friend_enckey;
		cand[ncand].priv = node->friend_privkey;
		cand[ncand].net_idx = node->friend_net_idx;
		cand[ncand].friend_cred = 1;
		ncand++;
	}
	/*
	 * Section 3.11.4.2: through Phases 1 and 2 the node "shall receive
	 * messages using the old keys and the new keys", and the friendship
	 * material is one of the three families derived from the NetKey
	 * (Section 3.9.6.3.1), so BOTH friendship credentials are receive
	 * candidates for as long as the refresh is in flight.
	 */
	if (node->have_new_friend_cred) {
		cand[ncand].nid = node->new_friend_nid;
		cand[ncand].enc = node->new_friend_enckey;
		cand[ncand].priv = node->new_friend_privkey;
		cand[ncand].net_idx = node->friend_net_idx;
		cand[ncand].friend_cred = 1;
		ncand++;
	}
	/*
	 * Directed security material (Section 3.9.6.3.1), offered only by a
	 * node with directed forwarding enabled: Section 2.3.13 makes the
	 * directed credentials a property of the directed forwarding
	 * functionality, and a node without it neither sends nor expects them.
	 */
	if (node->df_enabled) {
		if (mesh_kr_rx_accept_old(&node->kr)) {
			cand[ncand].nid = node->directed_nid;
			cand[ncand].enc = node->directed_enckey;
			cand[ncand].priv = node->directed_privkey;
			cand[ncand].net_idx = node->primary_net_idx;
			cand[ncand].directed_cred = 1;
			ncand++;
		}
		if (node->have_new_key && mesh_kr_rx_accept_new(&node->kr)) {
			cand[ncand].nid = node->new_directed_nid;
			cand[ncand].enc = node->new_directed_enckey;
			cand[ncand].priv = node->new_directed_privkey;
			cand[ncand].net_idx = node->primary_net_idx;
			cand[ncand].directed_cred = 1;
			ncand++;
		}
	}
	for (si = 0; si < node->n_subnets; si++) {
		if (!node->subnets[si].valid)
			continue;
		if (mesh_kr_rx_accept_old(&node->subnets[si].kr)) {
			cand[ncand].nid = node->subnets[si].nid;
			cand[ncand].enc = node->subnets[si].enckey;
			cand[ncand].priv = node->subnets[si].privkey;
			cand[ncand].net_idx = node->subnets[si].net_idx;
			ncand++;
		}
		if (node->subnets[si].have_new_key &&
		    mesh_kr_rx_accept_new(&node->subnets[si].kr)) {
			cand[ncand].nid = node->subnets[si].new_nid;
			cand[ncand].enc = node->subnets[si].new_enckey;
			cand[ncand].priv = node->subnets[si].new_privkey;
			cand[ncand].net_idx = node->subnets[si].net_idx;
			ncand++;
		}
		if (!node->df_enabled)
			continue;
		if (mesh_kr_rx_accept_old(&node->subnets[si].kr)) {
			cand[ncand].nid = node->subnets[si].directed_nid;
			cand[ncand].enc = node->subnets[si].directed_enckey;
			cand[ncand].priv = node->subnets[si].directed_privkey;
			cand[ncand].net_idx = node->subnets[si].net_idx;
			cand[ncand].directed_cred = 1;
			ncand++;
		}
		if (node->subnets[si].have_new_key &&
		    mesh_kr_rx_accept_new(&node->subnets[si].kr)) {
			cand[ncand].nid = node->subnets[si].new_directed_nid;
			cand[ncand].enc = node->subnets[si].new_directed_enckey;
			cand[ncand].priv =
			    node->subnets[si].new_directed_privkey;
			cand[ncand].net_idx = node->subnets[si].net_idx;
			cand[ncand].directed_cred = 1;
			ncand++;
		}
	}

	for (c = 0; c < ncand; c++) {
		if (!mesh_net_nid_match(cand[c].nid, bytes[0]))
			continue;
		for (i = 0; i < n_iv; i++) {
			if (mesh_net_decrypt(cand[c].enc, cand[c].priv,
			    cand[c].nid, ivs[i], bytes, len, out) == 0) {
				*iv_used = ivs[i];
				*nid_used = cand[c].nid;
				*enc_used = cand[c].enc;
				*priv_used = cand[c].priv;
				*net_idx_used = cand[c].net_idx;
				*friend_cred_used = cand[c].friend_cred;
				*directed_cred_used = cand[c].directed_cred;
				return (0);
			}
		}
	}
	return (-1);
}

/*
 * Deliver one reassembled upper transport PDU.  Returns 1 once the PDU has
 * been AUTHENTICATED - the DevKey or AppKey TransMIC verified - and 0 when it
 * has not.  MshPRT_v1.1.1 Section 3.9.8 records a PDU in the replay protection
 * list only after it has been accepted, so the caller commits the RPL on 1 and
 * leaves the list untouched on 0; anything that fails after authentication (a
 * malformed access PDU, an unbound model) still returns 1, because the message
 * was genuine and its sequence number is spent.
 */
static int
node_deliver_access(struct mesh_sim *sim, struct mesh_node *node, uint16_t src,
    uint16_t dst, uint32_t seqauth, int szmic, int akf, uint8_t aid,
    const uint8_t *upper, size_t upper_len, uint32_t iv, uint16_t net_idx)
{
	uint8_t access[MESH_ACCESS_PAYLOAD_MAX];
	struct mesh_access_pdu ap;
	struct mesh_model_reply reply;
	size_t access_len, ei, i, li;
	uint16_t rx_app_idx = UINT16_MAX;
	const uint8_t *rx_label = NULL;
	int opened = 0;

	if (akf == 0) {
		uint8_t reply_access[MESH_ACCESS_PAYLOAD_MAX];
		uint8_t reply_upper[SIM_UPPER_MAX];
		uint8_t remote_key[16];
		size_t reply_len = 0, reply_upper_len;
		uint32_t reply_seq;
		int local_open, n, rc;

		if (dst != node->addr)
			return (0);
		local_open = node->have_devkey && node->devkey_rx != NULL &&
		    mesh_upper_decrypt(node->devkey, 0, szmic, seqauth, src, dst, iv,
		    NULL, upper, upper_len, access, &access_len) == 0;
		if (!local_open) {
			if (node->devkey_lookup == NULL || node->devkey_upper_rx == NULL ||
			    node->devkey_lookup(node->devkey_client_arg, src,
			    remote_key) != 0 ||
			    mesh_upper_decrypt(remote_key, 0, szmic, seqauth, src, dst,
			    iv, NULL, upper, upper_len, access, &access_len) != 0)
				return (0);
		}
		/* Authenticated from here on: the TransMIC verified. */
		if (mesh_access_pdu_parse(access, access_len, &ap) != 0)
			return (1);
		node->rx.valid = 1;
		node->rx.src = src;
		node->rx.dst = dst;
		node->rx.app_idx = UINT16_MAX;
		node->rx.have_label = 0;
		memset(node->rx.label, 0, MESH_LABEL_UUID_LEN);
		node->rx.opcode = ap.opcode;
		node->rx.params_len = ap.params_len;
		memcpy(node->rx.params, ap.params, ap.params_len);
		node->rx.count++;
		if (!local_open) {
			(void)node->devkey_upper_rx(node->devkey_client_arg, seqauth,
			    src, dst, upper, upper_len);
			explicit_bzero(remote_key, sizeof(remote_key));
			return (1);
		}
		rc = node->devkey_rx(node->devkey_rx_arg, src, dst, net_idx,
		    access, access_len, reply_access, &reply_len);
		if (rc <= 0 || reply_len == 0 || reply_len > sizeof(reply_access))
			return (1);
		reply_seq = node->seq;
		/*
		 * The device-key nonce IV MUST match the IV the network layer
		 * secures this reply with (mesh_iv_tx_index), not the inbound
		 * request's decrypt IV: during an IV Update they differ, so a
		 * reply encrypted at the request's IV is undecryptable by the
		 * peer, and reusing the inbound IV with a fresh reply_seq risks
		 * device-nonce reuse (NB-5).
		 */
		if (mesh_upper_encrypt(node->devkey, 0, 0, reply_seq, node->addr,
		    src, mesh_iv_tx_index(&node->iv), NULL, reply_access,
		    reply_len, reply_upper, &reply_upper_len) != 0)
			return (1);
		n = mesh_sim_send_upper(sim, node, src, reply_seq, reply_upper,
		    reply_upper_len, 0, 0,
		    node->default_ttl ? node->default_ttl : 5);
		if (n > 0)
			node->seq += (uint32_t)n;
		return (1);
	}
	if (akf != 1)
		return (0);
	/*
	 * MshPRT_v1.1.1 Section 3.11.4: throughout Key Refresh Phases 1 and 2 a
	 * node "shall receive messages using the old keys and the new keys", so
	 * every AppKey index bound to this subnet contributes BOTH its current
	 * key and any key staged by a Config AppKey Update as a candidate.  The
	 * two have independent AIDs, so each is matched on its own.
	 */
	for (i = 0; i < node->n_appkeys && !opened; i++) {
		const struct mesh_sim_app_key *ak = &node->appkeys[i];
		const uint8_t *cand[2];
		size_t nc = 0, c;

		if (!ak->valid || ak->net_idx != net_idx)
			continue;
		if (ak->aid == aid)
			cand[nc++] = ak->key;
		if (ak->have_new_key && ak->new_aid == aid)
			cand[nc++] = ak->new_key;
		for (c = 0; c < nc && !opened; c++) {
			if (!mesh_addr_is_virtual(dst)) {
				opened = mesh_upper_decrypt(cand[c], 1, szmic,
				    seqauth, src, dst, iv, NULL, upper,
				    upper_len, access, &access_len) == 0;
				if (opened)
					rx_app_idx = ak->app_idx;
				continue;
			}
			/*
			 * A virtual DST alone is insufficient: hash collisions
			 * are resolved by authenticating with each subscribed
			 * Label UUID as CCM AAD.
			 */
			for (ei = 0; ei < node->n_elements && !opened; ei++) {
				for (li = 0; li < node->elem_n_labels[ei]; li++) {
					uint16_t va;

					if (mesh_virtual_addr(
					    node->elem_labels[ei][li], &va) != 0 ||
					    va != dst)
						continue;
					if (mesh_upper_decrypt(cand[c], 1, szmic,
					    seqauth, src, dst, iv,
					    node->elem_labels[ei][li], upper,
					    upper_len, access, &access_len) == 0) {
						opened = 1;
						rx_app_idx = ak->app_idx;
						/*
						 * MshPRT_v1.1.1 Section
						 * 3.4.2.3: this is the label
						 * that authenticated the
						 * message, and the 14-bit hash
						 * in the address cannot
						 * distinguish it from any
						 * other label that collides
						 * with it.  Carry it into
						 * dispatch; routing on the
						 * hash instead delivers a
						 * colliding label's traffic to
						 * the wrong model.
						 */
						rx_label =
						    node->elem_labels[ei][li];
						break;
					}
				}
			}
		}
	}
	if (!opened)
		return (0);
	/* Authenticated from here on: the AppKey TransMIC verified. */
	if (mesh_access_pdu_parse(access, access_len, &ap) != 0)
		return (1);

	/* Capture the delivered access message (test hook). */
	node->rx.valid = 1;
	node->rx.src = src;
	node->rx.dst = dst;
	node->rx.app_idx = rx_app_idx;
	node->rx.have_label = rx_label != NULL;
	if (rx_label != NULL)
		memcpy(node->rx.label, rx_label, MESH_LABEL_UUID_LEN);
	else
		memset(node->rx.label, 0, MESH_LABEL_UUID_LEN);
	node->rx.opcode = ap.opcode;
	node->rx.params_len = ap.params_len;
	memcpy(node->rx.params, ap.params, ap.params_len);
	node->rx.count++;

	memset(&reply, 0, sizeof(reply));
	(void)mesh_access_dispatch_key_at(node->elems, node->n_elements, src, dst,
	    rx_app_idx, rx_label, access, access_len, &reply, sim_now_ms(sim));
	if (reply.have_reply)
		(void)node_originate(sim, node, reply.src, reply.dst, reply.opcode,
		    reply.params, reply.params_len,
		    node->default_ttl ? node->default_ttl : 5);
	return (1);
}

/* ================================================================
 * Directed Forwarding and Heartbeat receive-side helpers.
 * ================================================================ */

/*
 * Send a locally originated Transport Control PDU (opcode || params).
 * `directed` selects the directed security material of Section 3.9.6.3.1 for
 * the path-discovery messages; every other control message (Heartbeat, and
 * anything added later) leaves it clear and goes out under managed flooding.
 */
static int
node_tx_ctl(struct mesh_sim *sim, struct mesh_node *node, int to_node,
    uint16_t dst, uint8_t opcode, const uint8_t *params, size_t plen,
    uint8_t ttl, int directed)
{
	struct mesh_net_pdu np;
	uint8_t nid;
	const uint8_t *enc, *priv;
	uint32_t iv;

	if (plen + 1 > sizeof(np.transport))
		return (-1);
	if (node->seq > MESH_IV_SEQ_MAX)
		return (-1);
	/*
	 * Credential selection, MshPRT_v1.1.1 Section 3.9.6.3.1.  The
	 * path-discovery control messages are the directed ones: Sections
	 * 3.6.8.2.1, 3.6.8.2.3, 3.6.8.2.4 and 3.6.8.2.7 each say of the
	 * PATH_REQUEST, PATH_REPLY, PATH_CONFIRMATION and
	 * PATH_REQUEST_SOLICITATION Network PDU that the node "shall send the
	 * message using the directed security credentials of the subnet over
	 * which the message is sent and shall tag the message with the
	 * immutable-credentials tag."  Every other Transport Control message
	 * this helper carries - the Heartbeat above all - falls under "For all
	 * other Network PDUs, the managed flooding security material is used."
	 */
	if (directed) {
		if (net_directed_txsec(node, node->primary_net_idx, &nid, &enc,
		    &priv) != 0)
			return (-1);
	} else
		node_tx_netsec(node, &nid, &enc, &priv);
	iv = mesh_iv_tx_index(&node->iv);
	memset(&np, 0, sizeof(np));
	np.nid = nid;
	np.ctl = 1;
	np.ttl = ttl;
	np.seq = node->seq;
	np.src = node->addr;
	np.dst = dst;
	np.transport[0] = (uint8_t)(opcode & 0x7f);
	memcpy(np.transport + 1, params, plen);
	np.transport_len = plen + 1;
	if (enqueue_net_to(sim, node->index, to_node, nid, enc, priv, iv,
	    &np) != 0)
		return (-1);
	node->seq++;
	return (0);
}

/* Find a forwarding-table entry by its (Path Origin, Path Target) key. */
static struct mesh_df_fwd_entry *
df_find(struct mesh_df_fwd_table *t, uint16_t origin, uint16_t target)
{
	size_t i;

	for (i = 0; i < MESH_DF_MAX_ENTRIES; i++) {
		if (t->entries[i].valid &&
		    t->entries[i].path_origin == origin &&
		    t->entries[i].path_target == target)
			return (&t->entries[i]);
	}
	return (NULL);
}

static int
df_dep_has(const uint16_t *deps, size_t n, uint16_t addr)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (deps[i] == addr)
			return (1);
	}
	return (0);
}

/*
 * Handle a Directed Forwarding path-discovery control PDU (Path Request /
 * Reply / Confirmation, MshPRT_v1.1 Section 3.6.6.5).  Returns 1 if the PDU was
 * a path-discovery opcode consumed here, 0 if it is some other control PDU that
 * the caller should keep processing.  prev_hop is the adjacent node the PDU was
 * heard from - the bearer recorded in the Forwarding Table.
 */
static int
df_handle_control(struct mesh_sim *sim, struct mesh_node *node,
    const struct mesh_net_pdu *pdu, int prev_hop, int seen, uint32_t iv,
    uint8_t nid, const uint8_t *enc, const uint8_t *priv)
{
	uint8_t op = (uint8_t)(pdu->transport[0] & 0x7f);
	const uint8_t *params = pdu->transport + 1;
	size_t plen = (pdu->transport_len > 0) ? pdu->transport_len - 1 : 0;
	uint64_t now = sim_now_ms(sim);

	switch (op) {
	case MESH_DF_OP_PATH_REQUEST: {
		struct mesh_df_path_request req;
		uint64_t lifetime;

		if (seen)
			return (1);	/* already processed and re-flooded */
		if (mesh_df_path_request_parse(params, plen, &req) != 0)
			return (1);
		lifetime = mesh_df_lifetime_ms[req.lifetime & 0x03];
		if (local_unicast(node, req.destination)) {
			/* Path Target: install the reverse entry and reply. */
			struct mesh_df_path_reply rep;
			uint8_t rp[MESH_ACCESS_PAYLOAD_MAX];
			size_t rl;

			(void)mesh_df_table_add(&node->df_table,
			    req.origin.range_start, req.destination,
			    req.forwarding_number, (uint8_t)prev_hop, 0, lifetime,
			    now);
			memset(&rep, 0, sizeof(rep));
			rep.confirmation_request = 1;
			/*
			 * P-C1b (Table 3.52): mesh_df_path_reply_build() serializes
			 * the Path Target unicast range only when Unicast_Destination
			 * is set.  This arm is reached only when req.destination
			 * matched a local element (always a unicast address), so set
			 * it -- otherwise the built reply omits the target range and
			 * the origin's range_covers() check rejects the reply.
			 */
			rep.unicast_destination = 1;
			rep.forwarding_number = req.forwarding_number;
			rep.path_origin = req.origin.range_start;
			rep.target.range_start = node->addr;
			rep.target.range_length = node->n_elements;
			if (mesh_df_path_reply_build(&rep, rp, &rl) == 0)
				(void)node_tx_ctl(sim, node, prev_hop,
				    req.origin.range_start, MESH_DF_OP_PATH_REPLY,
				    rp, rl, pdu->ttl, 1);
			return (1);
		}
		/* Intermediate: install the reverse entry and re-flood. */
		(void)mesh_df_table_add(&node->df_table, req.origin.range_start,
		    req.destination, req.forwarding_number, (uint8_t)prev_hop, 0,
		    lifetime, now);
		if (pdu->ttl >= 2) {
			struct mesh_net_pdu rp = *pdu;

			rp.ttl = (uint8_t)(pdu->ttl - 1);
			if (enqueue_net_to(sim, node->index, -1, nid, enc, priv,
			    iv, &rp) == 0)
				node->relay_count++;
		}
		return (1);
	}
	case MESH_DF_OP_PATH_REPLY: {
		struct mesh_df_path_reply rep;
		struct mesh_df_fwd_entry *e;

		if (mesh_df_path_reply_parse(params, plen, &rep) != 0)
			return (1);
		if (local_unicast(node, rep.path_origin)) {
			/* Path Origin: accept the reply, confirm the path. */
			int need_confirm = 0;

			if (mesh_df_discovery_on_reply(&node->df_disc, &rep,
			    &need_confirm) != 1)
				return (1);
			(void)mesh_df_table_add(&node->df_table, node->addr,
			    rep.target.range_start, rep.forwarding_number, 0,
			    (uint8_t)prev_hop,
			    mesh_df_lifetime_ms[node->df_disc.lifetime & 0x03],
			    now);
			if (need_confirm) {
				struct mesh_df_path_confirmation cf;
				uint8_t cb[8];
				size_t cl;

				if (mesh_df_discovery_confirm(&node->df_disc,
				    &cf) == 0 &&
				    mesh_df_path_confirmation_build(&cf, cb,
				    &cl) == 0)
					(void)node_tx_ctl(sim, node, prev_hop,
					    rep.target.range_start,
					    MESH_DF_OP_PATH_CONFIRMATION, cb, cl,
					    pdu->ttl, 1);
			}
			return (1);
		}
		if (seen)
			return (1);
		/* Intermediate: complete the entry and forward toward origin. */
		e = df_find(&node->df_table, rep.path_origin,
		    rep.target.range_start);
		if (e != NULL) {
			e->bearer_toward_target = (uint8_t)prev_hop;
			if (pdu->ttl >= 2) {
				struct mesh_net_pdu fp = *pdu;

				fp.ttl = (uint8_t)(pdu->ttl - 1);
				(void)enqueue_net_to(sim, node->index,
				    e->bearer_toward_origin, nid, enc, priv, iv,
				    &fp);
			}
		}
		return (1);
	}
	case MESH_DF_OP_PATH_CONFIRMATION: {
		struct mesh_df_path_confirmation cf;
		struct mesh_df_fwd_entry *e;

		if (mesh_df_path_confirmation_parse(params, plen, &cf) != 0)
			return (1);
		e = df_find(&node->df_table, cf.path_origin, cf.path_target);
		if (e != NULL)
			e->backward_validated = 1;
		if (local_unicast(node, cf.path_target))
			return (1);	/* reached the Path Target */
		if (seen)
			return (1);
		if (e != NULL && pdu->ttl >= 2) {
			struct mesh_net_pdu fp = *pdu;

			fp.ttl = (uint8_t)(pdu->ttl - 1);
			(void)enqueue_net_to(sim, node->index,
			    e->bearer_toward_target, nid, enc, priv, iv, &fp);
		}
		return (1);
	}
	default:
		return (0);
	}
}

/*
 * Resolve the managed-flooding TRANSMIT credential of one subnet by NetKey
 * Index (MshPRT_v1.1.1 Section 3.9.6.3.1), honouring Key Refresh key
 * selection exactly as the origination paths do.  Returns 0 and the NID plus
 * the encryption / privacy keys, or -1 when this node does not hold that
 * subnet's NetKey - in which case a bridge simply cannot re-secure onto it.
 */
static int
node_subnet_tx_cred(struct mesh_node *node, uint16_t net_idx, uint8_t *nid,
    const uint8_t **enc, const uint8_t **priv)
{
	const struct mesh_sim_subnet_key *subnet;
	size_t i;

	if (node == NULL || nid == NULL || enc == NULL || priv == NULL)
		return (-1);
	if (net_idx == node->primary_net_idx) {
		if (node->have_new_key &&
		    mesh_kr_tx_key(&node->kr) == MESH_KR_KEY_NEW) {
			*nid = node->new_nid;
			*enc = node->new_enckey;
			*priv = node->new_privkey;
		} else {
			*nid = node->nid;
			*enc = node->enckey;
			*priv = node->privkey;
		}
		return (0);
	}
	subnet = NULL;
	for (i = 0; i < node->n_subnets; i++)
		if (node->subnets[i].valid &&
		    node->subnets[i].net_idx == net_idx)
			subnet = &node->subnets[i];
	if (subnet == NULL)
		return (-1);
	if (subnet->have_new_key &&
	    mesh_kr_tx_key(&subnet->kr) == MESH_KR_KEY_NEW) {
		*nid = subnet->new_nid;
		*enc = subnet->new_enckey;
		*priv = subnet->new_privkey;
	} else {
		*nid = subnet->nid;
		*enc = subnet->enckey;
		*priv = subnet->privkey;
	}
	return (0);
}

/*
 * Subnet bridging (MshPRT_v1.1.1 Section 3.4.6.3, Table 3.14 "Traffic is to be
 * bridged").  Called on the receive path for an authenticated, non-duplicate
 * Network PDU that this node is not the final destination of.
 *
 * Section 3.4.6.3 states the key selection directly: "If the node is a Subnet
 * Bridge node, the node shall check all the Bridging Table state entries to
 * determine whether the Network PDU is to be bridged to different subnets",
 * then retransmits under NetKeyIndex2 (or NetKeyIndex1, for the reverse
 * direction of a Directions == 0x02 entry).  Everything else is inherited from
 * the surrounding retransmission rules of that section: "The IV Index used
 * when retransmitting the Network PDU shall be the same IV Index as in the
 * received Network PDU.  The TTL field value of the retransmitted Network PDU
 * shall be equal to the TTL field value of the received Network PDU
 * decremented by 1."
 *
 * SEQ AND SRC ARE CARRIED ACROSS UNCHANGED.  A bridge re-secures a PDU; it
 * does not originate one.  Section 3.4.6.3 lists exactly two fields that
 * change on retransmission (the network key and the TTL) and the Network nonce
 * is built from the PDU's own CTL/TTL/SEQ/SRC and IV Index, so the bridge must
 * not substitute its own sequence number - doing so would make the message
 * unauthenticatable at the far end against the originator's SeqAuth and would
 * break segmented-message reassembly across the bridge.
 *
 * Replay (Section 3.9.8).  Bridged traffic is checked against, and committed
 * to, the bridge's OWN replay list, which is keyed by source address across
 * both subnets: "A Subnet Bridge node shall maintain the most recent IVISeq
 * value for each source address authorized to send messages to bridged
 * subnets.  Messages received by the Subnet Bridge node with the IVISeq value
 * less than or equal to the last stored value from that source address shall
 * be discarded immediately upon reception.  When a message is retransmitted to
 * a bridged subnet, the stored IVISeq value shall be updated."  Peek first and
 * commit only once the re-secured PDU is actually queued, so a PDU that could
 * not be re-secured does not burn its source's sequence number.  A full list
 * discards ("If a node does not have enough resources to perform replay
 * protection for a given source address, then the node shall discard the
 * message immediately upon reception").
 *
 * Table 3.14 pairs every "Traffic is to be bridged" row with "Directed
 * forwarding is enabled", but Section 3.4.6.3's own prose imposes no such
 * condition, and the Bridge Configuration Server has no dependency on the
 * Directed Forwarding feature.  This implements the flooding-outbound row
 * without the directed-forwarding conjunct, which is the only reading under
 * which a Subnet Bridge in a flooding-only network works at all; the directed
 * outbound rows (path bearers, directed credentials) are not implemented.
 */
static void
node_bridge_forward(struct mesh_sim *sim, struct mesh_node *node,
    const struct mesh_net_pdu *pdu, uint32_t iv, uint16_t rx_net_idx)
{
	struct mesh_net_pdu bp;
	const uint8_t *enc, *priv;
	uint16_t tx_net_idx;
	uint8_t nid;

	if (!node->bridge_enabled)
		return;
	/* Section 3.4.6.3 gates all retransmission on TTL >= 2. */
	if (pdu->ttl < 2)
		return;
	if (!mesh_bridge_forward_net_idx(&node->bridge_table, pdu->src,
	    pdu->dst, rx_net_idx, &tx_net_idx))
		return;
	if (mesh_rpl_peek(&node->bridge_rpl, pdu->src, iv, pdu->seq) != 1) {
		node->bridge_replay_drops++;
		return;
	}
	if (node_subnet_tx_cred(node, tx_net_idx, &nid, &enc, &priv) != 0)
		return;
	bp = *pdu;
	bp.ttl = (uint8_t)(pdu->ttl - 1);
	if (enqueue_net_to(sim, node->index, -1, nid, enc, priv, iv, &bp) != 0)
		return;
	(void)mesh_rpl_commit(&node->bridge_rpl, pdu->src, iv, pdu->seq);
	node->bridge_fwd_count++;
}

static void
node_recv_net(struct mesh_sim *sim, struct mesh_node *node,
    const uint8_t *bytes, size_t len, int prev_hop)
{
	struct mesh_net_pdu pdu;
	uint32_t iv;
	uint16_t net_idx;
	uint8_t nid;
	const uint8_t *enc, *priv;
	int friend_cred = 0, directed_cred = 0, may_forward = 1, seen;

	sim->delivered++;
	if (try_decrypt(node, bytes, len, &pdu, &iv, &nid, &enc, &priv,
	    &net_idx, &friend_cred, &directed_cred) != 0)
		return;
	if (local_unicast(node, pdu.src))	/* our own message looped back */
		return;

	/*
	 * MshPRT_v1.1.1 Section 3.6.6.2: "OutMsg1 is sent secured using the
	 * friend security material and therefore only the Friend node will
	 * receive and relay this message.  When the Friend node relays OutMsg1,
	 * the message will be retransmitted using the managed flooding security
	 * credentials."  Only the Friend and its Low Power node hold the
	 * friendship material, so relaying under the credential that
	 * authenticated the PDU - as every other inbound credential is relayed -
	 * would make everything the LPN sends undecryptable by the rest of the
	 * network.  Swap in the subnet's managed-flooding material (this also
	 * rewrites the NID, exactly as the outbound copy must carry it); if the
	 * subnet is somehow gone, deliver locally but do not forward.
	 */
	/*
	 * The same rewrite is required for a PDU that arrived under the
	 * DIRECTED security material and is about to leave over a bearer that
	 * is not a path bearer.  Every row of Table 3.14 whose Outbound Bearers
	 * are ADV, GATT or "all bearers" names "flooding" in its Outbound
	 * Security Material column, including the rows whose Inbound Security
	 * Material is "directed"; only the "path bearers" rows name "directed".
	 * So the default outbound credential here is the subnet's managed
	 * flooding material, and the directed-forwarding branch below swaps in
	 * the directed material for the one case that earns it.
	 */
	if ((friend_cred || directed_cred) &&
	    net_flooding_txsec(node, net_idx, &nid, &enc, &priv) != 0)
		may_forward = 0;

	seen = nmc_seen_record(node, pdu.src, pdu.seq, iv);	/* M-N1 */

	/*
	 * Proxy (GATT bearer) forward, MshPRT_v1.1 Section 6.4/6.7: a proxy
	 * forwards a Network PDU to its GATT client only when the destination
	 * passes the proxy filter.  Count it once per distinct PDU (not per
	 * relay copy).
	 */
	if (node->is_proxy && !seen &&
	    mesh_proxy_filter_accepts(&node->pfilter, pdu.dst)) {
		node->proxy_fwd_count++;
		node->proxy_last_fwd_dst = pdu.dst;
	}

	/*
	 * Directed Forwarding path-discovery control PDUs (Path Request / Reply
	 * / Confirmation) are consumed by the DF machinery; they establish the
	 * Forwarding Table and are not delivered to models (Section 3.6.6.5).
	 */
	if (node->df_enabled && pdu.ctl == 1) {
		uint8_t dnid = nid;
		const uint8_t *denc = enc, *dpriv = priv;

		/*
		 * The path-discovery control messages are sent "using the
		 * directed security credentials of the subnet over which the
		 * message is sent" and "tagged with the immutable-credentials
		 * tag" (Sections 3.6.8.2.1, 3.6.8.2.3, 3.6.8.2.4, 3.6.8.2.7),
		 * so a node that passes one on re-secures it with the directed
		 * material, not with whatever authenticated it.
		 */
		if (net_directed_txsec(node, net_idx, &dnid, &denc,
		    &dpriv) == 0 &&
		    df_handle_control(sim, node, &pdu, prev_hop, seen, iv, dnid,
		    denc, dpriv))
			return;
	}

	/*
	 * Subnet bridging (Section 3.4.6.3).  Table 3.14 lists the bridging
	 * rows separately from the Relay row, so a node that is both a relay
	 * and a bridge performs both actions on the same PDU: it retransmits on
	 * the inbound subnet AND re-secures a copy onto the bridged subnet.
	 * Skipped for a duplicate (already bridged on its first sighting) and
	 * for a PDU addressed to one of this node's own elements, which is
	 * delivered rather than retransmitted.
	 */
	if (node->bridge_enabled && may_forward && !seen &&
	    !local_unicast(node, pdu.dst))
		node_bridge_forward(sim, node, &pdu, iv, net_idx);

	/*
	 * Forwarding.  A DF node routes along an established path when one
	 * matches (delivered only to the next-hop bearer), otherwise falls back
	 * to managed flooding (Section 3.6.6).  A plain node uses the Relay
	 * feature.  Duplicates (seen) are never re-forwarded.
	 */
	if (node->df_enabled && may_forward && !seen &&
	    !local_unicast(node, pdu.dst)) {
		enum mesh_df_forward v;
		struct mesh_df_fwd_entry *m = NULL;
		uint8_t new_ttl;

		v = mesh_df_forward_decide(&node->df_table, &node->df_feat,
		    pdu.src, pdu.dst, pdu.ttl, &new_ttl, sim_now_ms(sim), &m);
		if (v == MESH_DF_FORWARD_DIRECTED && m != NULL) {
			struct mesh_net_pdu rp = pdu;
			int bearer;

			rp.ttl = new_ttl;
			if (pdu.dst == m->path_target ||
			    df_dep_has(m->dep_target, m->dep_target_n, pdu.dst))
				bearer = m->bearer_toward_target;
			else
				bearer = m->bearer_toward_origin;
			/*
			 * A half-installed entry may carry MESH_DF_BEARER_NONE
			 * (0) for the selected direction.  Bearer 0 also aliases
			 * node index 0, so unicasting there would blackhole the
			 * PDU; fall back to managed flooding instead (consistent
			 * with mesh_df_forward_decide()).
			 */
			if (bearer == MESH_DF_BEARER_NONE) {
				if (enqueue_relay(sim, node, nid, enc, priv, iv,
				    &rp) == 0)
					node->relay_count++;
			} else {
				uint8_t dnid = nid;
				const uint8_t *denc = enc, *dpriv = priv;

				/*
				 * Table 3.14: this is the "path bearers"
				 * outbound row, and every such row secures the
				 * retransmitted PDU with the DIRECTED security
				 * material of the subnet (Section 3.9.6.3.1:
				 * "For Network PDUs that are transmitted
				 * according to directed forwarding
				 * functionality, the directed security material
				 * is used").  Re-securing here also rewrites
				 * the NID octet, which is how the next hop
				 * knows to reach for the directed credential.
				 */
				if (net_directed_txsec(node, net_idx, &dnid,
				    &denc, &dpriv) == 0 &&
				    enqueue_net_to(sim, node->index, bearer,
				    dnid, denc, dpriv, iv, &rp) == 0) {
					node->relay_count++;
					node->df_directed_fwd++;
				}
			}
		} else if (v == MESH_DF_FORWARD_FLOOD) {
			struct mesh_net_pdu rp = pdu;

			rp.ttl = new_ttl;
			if (enqueue_relay(sim, node, nid, enc, priv, iv,
			    &rp) == 0)
				node->relay_count++;
		} else if (friend_cred && mesh_net_relay(pdu.ttl, &new_ttl)) {
			/*
			 * MESH_DF_FORWARD_DROP, but the PDU came from our own
			 * Low Power node.  mesh_df_forward_decide() declines
			 * because no forwarding-table entry matched and the
			 * managed-flooding Relay feature is off - neither of
			 * which the Friend feature depends on.  Section 3.6.6.2
			 * has the Friend relay what its Low Power node sends,
			 * and Friend, Relay and Directed Forwarding are
			 * independent features (Section 3.6.6.1), so a Friend
			 * that has DF enabled and Relay disabled must not
			 * black-hole its LPN's uplink any more than one without
			 * DF does.  Forward by managed flooding: Table 3.14
			 * offers no directed row for a PDU with no path, and
			 * the credentials were already rewritten to the
			 * subnet's flooding material above.
			 */
			struct mesh_net_pdu rp = pdu;

			rp.ttl = new_ttl;
			if (enqueue_relay(sim, node, nid, enc, priv, iv,
			    &rp) == 0)
				node->relay_count++;
		}
	} else if (!node->df_enabled && may_forward &&
	    (node->is_relay || friend_cred)) {
		uint8_t new_ttl;
		int dst_local = local_unicast(node, pdu.dst);
		int forward;

		forward = mesh_relay_decide(&node->relay, pdu.ttl, seen,
		    dst_local, &new_ttl);
		/*
		 * A PDU received under friendship credentials is forwarded even
		 * when the Relay feature is disabled.  Friend and Relay are
		 * independent features (MshPRT_v1.1.1 Section 3.6.6.1), and
		 * Section 3.6.6.2 states unconditionally that the Friend node
		 * relays what its Low Power node sends; a Friend with Relay off
		 * is a legal configuration that would otherwise black-hole its
		 * LPN's entire uplink.  The exemption sits AFTER the TTL gate,
		 * which mesh_net_relay() re-applies here: a friendship PDU with
		 * TTL 0 or 1 is still not forwarded, and TTL is still
		 * decremented by one.
		 */
		if (!forward && friend_cred && !seen && !dst_local)
			forward = mesh_net_relay(pdu.ttl, &new_ttl);
		if (forward) {
			struct mesh_net_pdu rp = pdu;

			rp.ttl = new_ttl;
			if (enqueue_relay(sim, node, nid, enc, priv, iv,
			    &rp) == 0)
				node->relay_count++;
		}
	}

	/*
	 * Friend feature: store a message destined for our LPN.
	 *
	 * MshPRT_v1.1.1 Section 3.5.5: "The Friend Queue stores Lower Transport
	 * PDUs for a Low Power node ... The CTL, TTL, SEQ, SRC, and DST fields
	 * shall be stored with the associated Lower Transport PDU."  CTL is a
	 * stored field, not a filter, so a Transport Control PDU addressed to
	 * the Low Power node is queued like any other - which matters most for
	 * a Segment Acknowledgment, since Section 3.5.3.5 has the Low Power
	 * node send none of its own and rely on the queue for the ones
	 * answering its outbound transfers.
	 */
	if (node->is_friend) {
		uint16_t base = node->fq.lpn_addr;
		uint16_t top = (uint16_t)(base + node->fq.num_elements - 1);
		int for_lpn = (pdu.dst >= base && pdu.dst <= top) ||
		    mesh_friend_sub_contains(&node->fq.sub, pdu.dst);

		if (for_lpn) {
			struct mesh_fq_entry e;

			memset(&e, 0, sizeof(e));
			e.ctl = pdu.ctl;
			e.ttl = pdu.ttl;
			e.seq = pdu.seq;
			/*
			 * Capture the IV Index the PDU was secured with (the
			 * decrypt IV), per the mesh_fq_entry contract:
			 * delivery re-secures at this index so the original
			 * (IV,SRC,SEQ) is not remapped across an IV Update.
			 */
			e.iv_index = iv;
			e.src = pdu.src;
			e.dst = pdu.dst;
			if (pdu.transport_len <= MESH_FQ_PDU_MAX) {
				memcpy(e.pdu, pdu.transport, pdu.transport_len);
				e.pdu_len = pdu.transport_len;
				/*
				 * Section 3.5.5: a Segmented Access or
				 * Segmented Control message "shall only be
				 * stored into the Friend Queue after the
				 * complete Upper Transport PDU has been
				 * successfully reassembled and the Friend node
				 * has acknowledged the reception of all
				 * segments".  This engine's Friend role does no
				 * Friend-side reassembly, so flag an individual
				 * segment (SEG, bit 7 of the first Lower
				 * Transport octet) and let mesh_fq_enqueue
				 * apply that gate: storing raw segments would
				 * ship each one to the Low Power node as though
				 * it were a whole message.  meshd runs its own
				 * Friend engine, which does reassemble
				 * (meshd_friend_sar_rx) before queueing.
				 */
				e.segmented = (pdu.transport[0] & 0x80u) ?
				    1 : 0;
				(void)mesh_fq_enqueue(&node->fq, &e);
			}
		}
	}

	/* A sleeping Low Power node's radio is off. */
	if (node->is_lpn && !node->awake)
		return;
	if (!addressed_here(node, pdu.dst))
		return;

	/* Capture the TTL of the PDU as delivered (per-hop decrement proof). */
	node->rx.ttl = pdu.ttl;

	if (pdu.ctl == 0) {
		struct mesh_lower lower;

		if (mesh_lower_parse(0, pdu.transport, pdu.transport_len,
		    &lower) != 0)
			return;
		if (lower.seg == 0) {
			/*
			 * Unsegmented messages use their Network SEQ directly.
			 * MshPRT_v1.1.1 Section 3.9.8 records an ACCEPTED PDU,
			 * so peek here and commit only once the upper transport
			 * layer has verified the TransMIC: a PDU that fails
			 * application authentication must not advance the
			 * stored sequence number.
			 */
			if (mesh_rpl_peek(&node->rpl, pdu.src, iv,
			    pdu.seq) != 1)
				return;
			if (node_deliver_access(sim, node, pdu.src, pdu.dst,
			    pdu.seq, 0, lower.akf, lower.aid, lower.data,
			    lower.data_len, iv, net_idx) == 1)
				(void)mesh_rpl_commit(&node->rpl, pdu.src, iv,
				    pdu.seq);
		} else {
			struct mesh_sim_reasm *sess;
			uint8_t up[SIM_UPPER_MAX];
			size_t up_len;
			uint32_t seqauth, maxseq;
			int r;

			/*
			 * SeqAuth is the sequence number of segment zero.  Every
			 * segment in a transaction must encode the same SeqAuth via
			 * (Network SEQ - SegO) and SeqZero.  Check underflow as well as
			 * the 13-bit relationship before touching SAR/RPL state.
			 */
			/*
			 * MshPRT_v1.1 Section 3.5.3.1: SeqAuth is derived from
			 * SeqZero, not from (SEQ - SegO).  A compliant peer may
			 * (re)transmit any segment with any SEQ in the window
			 * [SeqAuth, SeqAuth + 8191], so reconstruct the upper
			 * SEQ bits and borrow one 0x2000 block if SeqZero maps
			 * above this segment's SEQ.
			 */
			seqauth = (pdu.seq & ~(uint32_t)0x1fff) | lower.seqzero;
			if (seqauth > pdu.seq)
				seqauth -= 0x2000;
			if (seqauth > 0xffffff - lower.segn)
				return;

			sess = reasm_session(sim, node, pdu.src, seqauth, iv, 0);
			if (sess == NULL)
				return;
			if (!sess->used) {
				/*
				 * Replay protection is evaluated once for the segmented
				 * transaction, at its SeqAuth.  Subsequent unseen segments
				 * in the active transaction may arrive in any order and must
				 * not be rejected merely because their individual Network
				 * SEQ is below a segment already received.
				 *
				 * PEEK only.  MshPRT_v1.1.1 Section 3.9.8
				 * records an accepted PDU, and a segmented
				 * message is not accepted until every segment
				 * has arrived and the TransMIC has verified.
				 * Committing here (on segment zero) makes a
				 * transaction that never completes poison its
				 * own SeqAuth: the peer's retransmission - which
				 * carries the same SeqZero, and therefore the
				 * same SeqAuth, by Section 3.5.3.1 - would then
				 * be scored a replay and the message would be
				 * undeliverable forever.
				 */
				if (mesh_rpl_peek(&node->rpl, pdu.src, iv,
				    seqauth) != 1)
					return;
				mesh_reasm_init(&sess->r);
				sess->seqauth = seqauth;
				sess->iv_index = iv;
				sess->dst = pdu.dst;
				sess->szmic = lower.szmic;
				sess->ctl = 0;
				sess->complete = 0;
				sess->ack_armed = 0;
				sess->acked_once = 0;
				sess->last_ack_ms = 0;
				sess->deadline_ms = sim->now_ms +
				    sar_discard_ms(node);
				sess->used = 1;
			} else if (sess->complete) {
				/*
				 * C4-L4: a retransmitted segment for an
				 * already-completed SeqAuth.  MshPRT 3.5.3.4
				 * requires re-sending the (complete) block ack
				 * rather than silently dropping it; do not
				 * re-run RPL/reassembly or re-deliver.
				 */
				sess->deadline_ms = sim->now_ms +
				    sar_discard_ms(node);
				/*
				 * Most Recent SeqAuth, MshPRT_v1.1.1 Section
				 * 3.5.3.4: re-send the complete block ack, but
				 * "not more than one Segment Acknowledgment
				 * message for the same SeqAuth in a period of
				 * [acknowledgment delay increment * segment
				 * reception interval] milliseconds", so a peer
				 * that floods retransmissions of an already
				 * delivered transaction cannot make us answer
				 * every one of them.
				 */
				if (local_unicast(node, pdu.dst) &&
				    !lpn_in_use(node) &&
				    (!sess->acked_once || sim->now_ms -
				    sess->last_ack_ms >= sar_reack_min_ms())) {
					send_seg_ack(sim, node, pdu.src,
					    lower.seqzero, sess->r.blockack,
					    seg_ack_ttl(pdu.ttl), 0);
					sess->acked_once = 1;
					sess->last_ack_ms = sim->now_ms;
				}
				return;
			} else if (sess->dst != pdu.dst ||
			    sess->szmic != lower.szmic ||
			    sess->r.akf != lower.akf || sess->r.aid != lower.aid) {
				/* Header fields are invariant across one segmented PDU. */
				return;
			}
			r = mesh_reasm_input(&sess->r, pdu.src, pdu.transport,
			    pdu.transport_len);
			if (r < 0)
				return;
			sess->deadline_ms = sim->now_ms +
			    sar_discard_ms(node);
			/*
			 * MshPRT_v1.1.1 Section 3.5.3.4: acknowledge only a
			 * segmented message addressed to a unicast address of
			 * this node - never a group/virtual DST - and, Section
			 * 3.5.3.5, never as an established Low Power node,
			 * whose Friend acknowledges on its behalf.
			 *
			 * A First or Next Segment starts the SAR
			 * Acknowledgment timer rather than acknowledging;
			 * only a Last Segment (r == 1, below) acknowledges at
			 * once, with every segment reported delivered.
			 */
			if (local_unicast(node, pdu.dst) && !lpn_in_use(node) &&
			    r != 1)
				sar_ack_arm(sim, sess, pdu.src, lower.seqzero,
				    pdu.ttl);
			if (r == 1) {
				if (local_unicast(node, pdu.dst) &&
				    !lpn_in_use(node)) {
					send_seg_ack(sim, node, pdu.src,
					    lower.seqzero, sess->r.blockack,
					    seg_ack_ttl(pdu.ttl), 0);
					sess->acked_once = 1;
					sess->last_ack_ms = sim->now_ms;
				}
				sess->ack_armed = 0;	/* timer stopped */
				/*
				 * The transaction is complete: authenticate it,
				 * and only then advance the persistent RPL past
				 * every SEQ it consumed.  If a newer message
				 * already advanced the entry, mesh_rpl_commit()
				 * leaves that newer value intact.
				 */
				maxseq = sess->seqauth + sess->r.segn;
				if (mesh_reasm_get(&sess->r, up, &up_len) == 0 &&
				    node_deliver_access(sim, node, pdu.src,
				    pdu.dst, sess->seqauth, sess->szmic,
				    lower.akf, lower.aid, up, up_len, iv,
				    net_idx) == 1)
					(void)mesh_rpl_commit(&node->rpl,
					    pdu.src, iv, maxseq);
				/*
				 * C4-L4: keep the session so a retransmitted
				 * segment is re-acked (handled above) until the
				 * SAR discard deadline reaps it.
				 */
				sess->complete = 1;
			}
		}
	} else {
		struct mesh_lower lower;
		const uint8_t *ctlp = pdu.transport;
		size_t ctl_len = pdu.transport_len;
		uint8_t ctlbuf[SIM_UPPER_MAX + 1];
		uint8_t op;

		if (mesh_lower_parse(1, pdu.transport, pdu.transport_len,
		    &lower) != 0)
			return;
		if (lower.seg) {
			struct mesh_sim_reasm *sess;
			uint32_t seqauth, maxseq;
			size_t data_len;
			int r;

			/*
			 * MshPRT_v1.1 Section 3.5.3.1: SeqAuth is derived from
			 * SeqZero, not from (SEQ - SegO).  A compliant peer may
			 * (re)transmit any segment with any SEQ in the window
			 * [SeqAuth, SeqAuth + 8191], so reconstruct the upper
			 * SEQ bits and borrow one 0x2000 block if SeqZero maps
			 * above this segment's SEQ.
			 */
			seqauth = (pdu.seq & ~(uint32_t)0x1fff) | lower.seqzero;
			if (seqauth > pdu.seq)
				seqauth -= 0x2000;
			if (seqauth > 0xffffff - lower.segn)
				return;
			sess = reasm_session(sim, node, pdu.src, seqauth, iv, 1);
			if (sess == NULL)
				return;
			if (!sess->used) {
				/* Peek only; commit on completion (as above). */
				if (mesh_rpl_peek(&node->rpl, pdu.src, iv,
				    seqauth) != 1)
					return;
				mesh_reasm_init(&sess->r);
				sess->seqauth = seqauth;
				sess->iv_index = iv;
				sess->dst = pdu.dst;
				sess->ctl = 1;
				sess->complete = 0;
				sess->ack_armed = 0;
				sess->acked_once = 0;
				sess->last_ack_ms = 0;
				sess->deadline_ms = sim->now_ms +
				    sar_discard_ms(node);
				sess->used = 1;
			} else if (sess->complete) {
				/* C4-L4: re-ack a retransmit of a completed
				 * SeqAuth (MshPRT 3.5.3.4); no re-delivery. */
				sess->deadline_ms = sim->now_ms +
				    sar_discard_ms(node);
				/*
				 * Most Recent SeqAuth, MshPRT_v1.1.1 Section
				 * 3.5.3.4: re-send the complete block ack, but
				 * "not more than one Segment Acknowledgment
				 * message for the same SeqAuth in a period of
				 * [acknowledgment delay increment * segment
				 * reception interval] milliseconds", so a peer
				 * that floods retransmissions of an already
				 * delivered transaction cannot make us answer
				 * every one of them.
				 */
				if (local_unicast(node, pdu.dst) &&
				    !lpn_in_use(node) &&
				    (!sess->acked_once || sim->now_ms -
				    sess->last_ack_ms >= sar_reack_min_ms())) {
					send_seg_ack(sim, node, pdu.src,
					    lower.seqzero, sess->r.blockack,
					    seg_ack_ttl(pdu.ttl), 0);
					sess->acked_once = 1;
					sess->last_ack_ms = sim->now_ms;
				}
				return;
			} else if (sess->dst != pdu.dst ||
			    sess->r.opcode != lower.opcode)
				return;
			r = mesh_reasm_input_ctl(&sess->r, pdu.src, 1,
			    pdu.transport, pdu.transport_len);
			if (r < 0)
				return;
			sess->deadline_ms = sim->now_ms +
			    sar_discard_ms(node);
			/*
			 * As for a segmented access message: a First or Next
			 * Segment starts the SAR Acknowledgment timer
			 * (Section 3.5.3.4) and only the Last Segment
			 * acknowledges immediately.
			 */
			if (local_unicast(node, pdu.dst) && !lpn_in_use(node) &&
			    r == 0)
				sar_ack_arm(sim, sess, pdu.src, lower.seqzero,
				    pdu.ttl);
			if (r == 0)
				return;
			if (local_unicast(node, pdu.dst) && !lpn_in_use(node)) {
				send_seg_ack(sim, node, pdu.src, lower.seqzero,
				    sess->r.blockack, seg_ack_ttl(pdu.ttl), 0);
				sess->acked_once = 1;
				sess->last_ack_ms = sim->now_ms;
			}
			sess->ack_armed = 0;		/* timer stopped */
			/*
			 * A Transport Control PDU carries no TransMIC: the
			 * NetMIC the network layer already verified is its
			 * authentication, so the completed transaction is
			 * accepted here and the RPL is committed now.
			 */
			maxseq = sess->seqauth + sess->r.segn;
			(void)mesh_rpl_commit(&node->rpl, pdu.src, iv, maxseq);
			ctlbuf[0] = sess->r.opcode;
			if (mesh_reasm_get(&sess->r, ctlbuf + 1, &data_len) != 0) {
				sess->used = 0;
				return;
			}
			ctlp = ctlbuf;
			ctl_len = data_len + 1;
			/* C4-L4: retain for retransmit re-ack (as above). */
			sess->complete = 1;
		} else if (mesh_rpl_check(&node->rpl, pdu.src, iv,
		    pdu.seq) != 1)
			return;

		op = (uint8_t)(ctlp[0] & 0x7f);
		if (op == 0x00) {
			struct mesh_seg_ack ack;
			size_t i;

			if (mesh_seg_ack_parse(ctlp, ctl_len, &ack) != 0)
				return;
			for (i = 0; i < MESH_SIM_SAR_TX; i++) {
				struct mesh_sim_sar_tx *s = &node->sar_tx[i];

				if (!s->used || s->seqzero != ack.seqzero)
					continue;
				/*
				 * MshPRT_v1.1.1 Section 3.5.3.4 acknowledges
				 * only a segmented message addressed to a
				 * unicast address, so a multicast transaction
				 * has no acknowledgment to validate - and must
				 * not be completed by one that happens to carry
				 * OBO = 1 and a matching SeqZero.
				 */
				if (s->multicast)
					continue;
				/*
				 * MshPRT_v1.1.1 Table 3.24, second condition:
				 * "Either the source address of the Segment
				 * Acknowledgment message matches the
				 * destination address value stored by the lower
				 * transport layer, or the value of the OBO
				 * field of the Segment Acknowledgment message
				 * is 1."  A Friend acknowledging on behalf of
				 * its Low Power node sources the ack from its
				 * OWN address, so requiring the stored
				 * destination to match rejects every
				 * acknowledgment an LPN's Friend ever sends and
				 * the transfer retransmits until the budget is
				 * exhausted.
				 */
				if (s->dst != pdu.src && !ack.obo)
					continue;
				/*
				 * MshPRT_v1.1 Section 3.5.3.4: a Segment Ack with
				 * an all-zero BlockAck cancels the segmented
				 * transmission (e.g. a busy or OBO peer), it does
				 * NOT request a full retransmission.  Abort the
				 * SAR context instead of re-queuing every segment.
				 */
				if (ack.blockack == 0) {
					s->used = 0;
					break;
				}
				s->blockack |= ack.blockack &
				    mesh_blockack_full(s->segn);
				sar_tx_requeue_missing(sim, node, s);
				break;
			}
			return;
		}

		/*
		 * Heartbeat subscription (MshPRT_v1.1.1 Sections 4.2.19 /
		 * 4.4.1.2.16 - the foundation-model states are in the
		 * Protocol specification): count a
		 * received Heartbeat and fold in its hop count.  The received
		 * network TTL is RxTTL; hops = InitTTL - RxTTL + 1.  RPL has
		 * already collapsed the relayed copies to the first (shortest-path)
		 * arrival, so the count advances once per publication.
		 */
		if (op == MESH_HB_CTL_OPCODE && node->hb_sub_active) {
			struct mesh_hb_msg hm;

			if (mesh_hb_ctl_pdu_parse(ctlp, ctl_len, &hm) == 0)
				(void)mesh_hb_sub_receive(&node->hb_sub, pdu.src,
				    pdu.dst, hm.init_ttl, pdu.ttl);
		}

		if (op == MESH_FRIEND_OP_POLL && node->is_friend &&
		    node->have_friend_cred && pdu.src == node->friend_lpn) {
			struct mesh_friend_poll poll;
			struct mesh_fq_entry out;

			if (mesh_friend_poll_parse(ctlp, ctl_len, &poll) != 0)
				return;
			if (mesh_fq_poll(&node->fq, poll.fsn, NULL, &out) == 1) {
				struct mesh_net_pdu dp;
				uint8_t tnid;
				const uint8_t *tenc, *tpriv;

				/*
				 * MshPRT_v1.1.1 Section 3.6.6.2: established
				 * friendship security material is mandatory
				 * for delivery, and Section 3.11.4.2 has it
				 * follow the subnet's transmit key across a
				 * Key Refresh.
				 */
				if (mesh_sim_friend_txsec(node, &tnid, &tenc,
				    &tpriv) != 0)
					return;
				memset(&dp, 0, sizeof(dp));
				dp.nid = tnid;
				dp.ctl = out.ctl;
				dp.ttl = out.ttl;
				dp.seq = out.seq;
				dp.src = out.src;
				dp.dst = out.dst;
				memcpy(dp.transport, out.pdu, out.pdu_len);
				dp.transport_len = out.pdu_len;
				/*
				 * A stored entry is re-secured at the IV Index
				 * captured at enqueue (mesh_fq_entry contract;
				 * mirrors meshd_friend_send_msg): only a
				 * Friend-originated Update uses the live TX
				 * index.
				 */
				(void)enqueue_net(sim, node->index, tnid, tenc,
				    tpriv, out.is_update ?
				    mesh_iv_tx_index(&node->iv) : out.iv_index,
				    &dp);
			}
		}
	}
}

/* ================================================================
 * Stepping the medium.
 * ================================================================ */

int
mesh_sim_step(struct mesh_sim *sim)
{
	struct mesh_sim_tx snap[MESH_SIM_MAX_TX];
	size_t cnt, i;
	int j;

	if (sim == NULL || sim->n_tx == 0)
		return (0);
	cnt = sim->n_tx;
	memcpy(snap, sim->tx, cnt * sizeof(snap[0]));
	sim->n_tx = 0;

	for (i = 0; i < cnt; i++) {
		if (!snap[i].valid)
			continue;
		for (j = 0; j < sim->n_nodes; j++) {
			if (j == snap[i].tx_node)
				continue;
			if (snap[i].to_node >= 0 && snap[i].to_node != j)
				continue;	/* directed forward: one hop only */
			if (sim->use_topology &&
			    !sim->linked[snap[i].tx_node][j])
				continue;
			node_recv_net(sim, &sim->nodes[j], snap[i].bytes,
			    snap[i].len, snap[i].tx_node);
		}
	}
	return ((int)cnt);
}

int
mesh_sim_run(struct mesh_sim *sim, int max_steps)
{
	int steps = 0;

	if (sim == NULL)
		return (0);
	while (sim->n_tx != 0 && steps < max_steps) {
		(void)mesh_sim_step(sim);
		steps++;
	}
	return (steps);
}

int
mesh_sim_reinject(struct mesh_sim *sim, int tx_node, const uint8_t *bytes,
    size_t len)
{
	struct mesh_sim_tx *slot;

	if (sim == NULL || bytes == NULL || len == 0 || len > MESH_NET_MAX_PDU)
		return (-1);
	if (sim->n_tx >= MESH_SIM_MAX_TX)
		return (-1);
	slot = &sim->tx[sim->n_tx++];
	memcpy(slot->bytes, bytes, len);
	slot->len = len;
	slot->tx_node = tx_node;
	slot->to_node = -1;
	slot->valid = 1;
	return (0);
}

int
mesh_sim_lpn_poll(struct mesh_sim *sim, struct mesh_node *lpn)
{
	struct mesh_friend_poll poll;
	uint8_t lt[MESH_FRIEND_POLL_LEN];
	size_t lt_len;
	uint32_t before;

	if (sim == NULL || lpn == NULL || !lpn->is_lpn ||
	    !lpn->have_friend_cred)
		return (-1);
	before = lpn->rx.count;
	lpn->awake = 1;
	poll.fsn = (uint8_t)mesh_lpn_poll_fsn(&lpn->lpn);
	if (mesh_friend_poll_build(&poll, lt, &lt_len) != 0) {
		lpn->awake = 0;
		return (-1);
	}
	if (node_tx_control(sim, lpn, lpn->lpn_friend, lt, lt_len, 0, 1) != 0) {
		lpn->awake = 0;
		return (-1);
	}
	(void)mesh_sim_run(sim, 8);
	/*
	 * Only toggle the Friend Sequence Number when the Friend actually
	 * responded (a queued message was delivered).  Advancing the FSN after a
	 * lost/empty response would make the next Poll's changed FSN look like an
	 * ack to mesh_fq_poll() and drop the still-undelivered head.
	 */
	if (lpn->rx.count > before)
		(void)mesh_lpn_on_response(&lpn->lpn, 0, sim->now * 1000);
	lpn->awake = 0;
	return (lpn->rx.count > before ? 1 : 0);
}

/* ================================================================
 * Beacons, IV Update and Key Refresh.
 * ================================================================ */

void
mesh_sim_advance(struct mesh_sim *sim, uint64_t dt_secs)
{

	mesh_sim_advance_ms(sim, dt_secs * 1000);
}

void
mesh_sim_advance_ms(struct mesh_sim *sim, uint64_t dt_ms)
{
	int i, j;

	if (sim == NULL)
		return;
	sim->now_ms += dt_ms;
	sim->now = sim->now_ms / 1000;
	for (i = 0; i < MESH_SIM_RELAY_TX; i++) {
		while (mesh_relay_tx_due(&sim->retransmit[i].timer,
		    sim->now_ms)) {
			if (sim->n_tx >= MESH_SIM_MAX_TX)
				break;
			sim->tx[sim->n_tx++] = sim->retransmit[i].pdu;
			(void)mesh_relay_tx_fire(&sim->retransmit[i].timer,
			    sim->now_ms);
		}
	}
	for (i = 0; i < sim->n_nodes; i++) {
		mesh_access_tick(sim->nodes[i].elems,
		    sim->nodes[i].n_elements, sim_now_ms(sim));
		for (j = 0; j < MESH_SIM_REASM; j++) {
			struct mesh_sim_reasm *sess = &sim->nodes[i].reasm[j];

			if (!sess->used)
				continue;
			/*
			 * MshPRT_v1.1.1 Section 3.5.3.4: "when the SAR
			 * Acknowledgment timer expires, the lower transport
			 * layer shall send a Segment Acknowledgment message
			 * with the AckedSegments field set to the AckedSegments
			 * value for the identified SeqAuth", addressed to the
			 * SRC of the first received segment.  This is the ONLY
			 * acknowledgment an incomplete transaction produces,
			 * however many segments have arrived.
			 */
			if (sess->ack_armed &&
			    sim->now_ms >= sess->ack_due_ms) {
				sess->ack_armed = 0;
				send_seg_ack(sim, &sim->nodes[i],
				    sess->ack_src, sess->ack_seqzero,
				    sess->r.blockack,
				    seg_ack_ttl(sess->ack_ttl), 0);
				sess->acked_once = 1;
				sess->last_ack_ms = sim->now_ms;
			}
			if (sim->now_ms >= sess->deadline_ms) {
				sess->ack_armed = 0;
				sess->used = 0;
			}
		}
		for (j = 0; j < MESH_SIM_SAR_TX; j++) {
			struct mesh_sim_sar_tx *st = &sim->nodes[i].sar_tx[j];

			if (!st->used || sim->now_ms < st->deadline_ms)
				continue;
			if (st->multicast)
				sar_tx_multicast_repeat(sim, &sim->nodes[i],
				    st);
			else
				sar_tx_requeue_missing(sim, &sim->nodes[i],
				    st);
		}
	}
}

/*
 * Friendship security material (MshPRT_v1.1.1 Section 3.9.6.3.1) for one
 * friendship, derived from a NetKey.  Two of these are held at once while a
 * Key Refresh is in flight: see mesh_sim_friend_cred_derive().
 */
static int
friend_cred_from_key(const uint8_t netkey[16], uint16_t lpn_addr,
    uint16_t friend_addr, uint16_t lpn_counter, uint16_t friend_counter,
    uint8_t *out_nid, uint8_t *out_enc, uint8_t *out_priv)
{
	uint8_t nid[1];

	if (mesh_friend_credentials(netkey, lpn_addr, friend_addr, lpn_counter,
	    friend_counter, nid, out_enc, out_priv) != 0)
		return (-1);
	*out_nid = nid[0];
	return (0);
}

/*
 * Re-derive the stored friendship credential pair from the CURRENT contents of
 * its subnet's key slots.  Run whenever a Key Refresh stages, promotes or
 * revokes a NetKey; a node with no friendship is a no-op.  File-local: the
 * daemon reaches it through mesh_sim_friend_cred_derive().
 */
static int
friend_cred_resync(struct mesh_node *node)
{
	const struct mesh_sim_subnet_key *sn;
	const uint8_t *cur, *new_key = NULL;
	int rc = 0;

	if (node == NULL || !node->have_friend_cred)
		return (0);
	if (node->friend_net_idx == node->primary_net_idx) {
		cur = node->netkey;
		if (node->have_new_key)
			new_key = node->new_netkey;
	} else {
		sn = find_subnet(node, node->friend_net_idx);
		if (sn == NULL)
			return (-1);
		cur = sn->netkey;
		if (sn->have_new_key)
			new_key = sn->new_netkey;
	}
	if (friend_cred_from_key(cur, node->fc_lpn_addr, node->fc_friend_addr,
	    node->fc_lpn_counter, node->fc_friend_counter, &node->friend_nid,
	    node->friend_enckey, node->friend_privkey) != 0)
		rc = -1;
	if (new_key != NULL &&
	    friend_cred_from_key(new_key, node->fc_lpn_addr,
	    node->fc_friend_addr, node->fc_lpn_counter, node->fc_friend_counter,
	    &node->new_friend_nid, node->new_friend_enckey,
	    node->new_friend_privkey) == 0) {
		node->have_new_friend_cred = 1;
		return (rc);
	}
	if (new_key != NULL)
		rc = -1;
	/* No new NetKey staged (or derivation failed): only one credential. */
	node->have_new_friend_cred = 0;
	node->new_friend_nid = 0;
	explicit_bzero(node->new_friend_enckey,
	    sizeof(node->new_friend_enckey));
	explicit_bzero(node->new_friend_privkey,
	    sizeof(node->new_friend_privkey));
	return (rc);
}

int
mesh_sim_friend_cred_derive(struct mesh_node *node, uint16_t net_idx,
    uint16_t lpn_addr, uint16_t friend_addr, uint16_t lpn_counter,
    uint16_t friend_counter)
{
	const struct mesh_sim_subnet_key *sn;

	if (node == NULL)
		return (-1);
	if (net_idx != node->primary_net_idx) {
		sn = find_subnet(node, net_idx);
		if (sn == NULL)
			return (-1);
	}
	node->friend_net_idx = net_idx;
	node->fc_lpn_addr = lpn_addr;
	node->fc_friend_addr = friend_addr;
	node->fc_lpn_counter = lpn_counter;
	node->fc_friend_counter = friend_counter;
	node->have_friend_cred = 1;
	if (friend_cred_resync(node) != 0) {
		/*
		 * A derivation failure leaves no usable credential, so the
		 * friendship is not established: clear the flag rather than
		 * leaving a half-derived credential live.
		 */
		node->have_friend_cred = 0;
		return (-1);
	}
	return (0);
}

int
mesh_sim_friend_txsec(const struct mesh_node *node, uint8_t *nid,
    const uint8_t **enc, const uint8_t **priv)
{
	const struct mesh_key_refresh *kr;
	size_t i;

	if (node == NULL || !node->have_friend_cred)
		return (-1);
	kr = NULL;
	if (node->friend_net_idx == node->primary_net_idx)
		kr = &node->kr;
	else
		for (i = 0; i < node->n_subnets; i++)
			if (node->subnets[i].valid &&
			    node->subnets[i].net_idx == node->friend_net_idx)
				kr = &node->subnets[i].kr;
	if (kr == NULL)
		return (-1);
	/*
	 * Section 3.11.4.2: "When in Phase 2, the node shall only transmit
	 * messages ... using the new keys".  The friendship material is derived
	 * from the NetKey (Section 3.9.6.3.1), so it follows the same rule as
	 * the managed-flooding material - which is what mesh_kr_tx_key()
	 * answers.
	 */
	if (node->have_new_friend_cred &&
	    mesh_kr_tx_key(kr) == MESH_KR_KEY_NEW) {
		*nid = node->new_friend_nid;
		*enc = node->new_friend_enckey;
		*priv = node->new_friend_privkey;
		return (0);
	}
	*nid = node->friend_nid;
	*enc = node->friend_enckey;
	*priv = node->friend_privkey;
	return (0);
}

void
mesh_sim_node_erase_keys(struct mesh_node *node)
{
	size_t i;

	if (node == NULL)
		return;
	/* Primary subnet: NetKey plus all three families of Section 3.9.6.3.1. */
	explicit_bzero(node->netkey, sizeof(node->netkey));
	node->nid = 0;
	explicit_bzero(node->enckey, sizeof(node->enckey));
	explicit_bzero(node->privkey, sizeof(node->privkey));
	node->directed_nid = 0;
	explicit_bzero(node->directed_enckey, sizeof(node->directed_enckey));
	explicit_bzero(node->directed_privkey, sizeof(node->directed_privkey));
	node->have_new_key = 0;
	explicit_bzero(node->new_netkey, sizeof(node->new_netkey));
	node->new_nid = 0;
	explicit_bzero(node->new_enckey, sizeof(node->new_enckey));
	explicit_bzero(node->new_privkey, sizeof(node->new_privkey));
	node->new_directed_nid = 0;
	explicit_bzero(node->new_directed_enckey,
	    sizeof(node->new_directed_enckey));
	explicit_bzero(node->new_directed_privkey,
	    sizeof(node->new_directed_privkey));
	mesh_kr_init(&node->kr);

	/* Secondary subnets. */
	for (i = 0; i < MESH_SIM_MAX_SUBNETS; i++)
		explicit_bzero(&node->subnets[i], sizeof(node->subnets[i]));
	node->n_subnets = 0;

	/* Application keys, both slots of each index. */
	for (i = 0; i < MESH_SIM_MAX_APPKEYS; i++)
		explicit_bzero(&node->appkeys[i], sizeof(node->appkeys[i]));
	node->n_appkeys = 0;

	/* Friendship credentials (Section 3.6.6.2), current and staged. */
	node->have_friend_cred = 0;
	node->friend_nid = 0;
	explicit_bzero(node->friend_enckey, sizeof(node->friend_enckey));
	explicit_bzero(node->friend_privkey, sizeof(node->friend_privkey));
	node->have_new_friend_cred = 0;
	node->new_friend_nid = 0;
	explicit_bzero(node->new_friend_enckey,
	    sizeof(node->new_friend_enckey));
	explicit_bzero(node->new_friend_privkey,
	    sizeof(node->new_friend_privkey));
	node->fc_lpn_addr = 0;
	node->fc_friend_addr = 0;
	node->fc_lpn_counter = 0;
	node->fc_friend_counter = 0;

	/* The device key. */
	node->have_devkey = 0;
	explicit_bzero(node->devkey, sizeof(node->devkey));
}

int
mesh_sim_send_beacon(struct mesh_sim *sim, struct mesh_node *node,
    uint16_t net_idx)
{
	uint8_t beacon[MESH_SECURE_BEACON_LEN];
	const uint8_t *bkey;
	struct mesh_sim_subnet_key *subnet;
	size_t blen;
	int kr_flag, iv_update, j, phase, have_new;
	uint32_t iv_index;

	if (sim == NULL || node == NULL)
		return (-1);
	iv_update = (node->iv.state == MESH_IV_UPDATE_IN_PROGRESS) ? 1 : 0;
	iv_index = node->iv.iv_index;
	subnet = NULL;
	if (net_idx == node->primary_net_idx) {
		phase = mesh_kr_phase(&node->kr);
		have_new = node->have_new_key;
		/*
		 * C4-M2: Phase-1 nodes must still beacon with the OLD key
		 * (MshPRT 3.11.4); new-key beacons begin at Phase 2.  Beaconing
		 * the new key in Phase 1 (with the Phase-1 KR=0 flag) is the
		 * Phase-3 signal and would collapse receivers straight to
		 * Phase 3, revoking the old key mid-distribution.
		 */
		bkey = have_new && phase >= MESH_KR_PHASE_2 ?
		    node->new_netkey : node->netkey;
		kr_flag = have_new ? mesh_kr_beacon_flag(&node->kr) : 0;
	} else {
		subnet = find_subnet(node, net_idx);
		if (subnet == NULL)
			return (-1);
		phase = mesh_kr_phase(&subnet->kr);
		have_new = subnet->have_new_key;
		/* C4-M2: subnet mirror of the primary fix above. */
		bkey = have_new && phase >= MESH_KR_PHASE_2 ?
		    subnet->new_netkey : subnet->netkey;
		kr_flag = have_new ? mesh_kr_beacon_flag(&subnet->kr) : 0;
	}
	if (mesh_secure_beacon_build(bkey, (uint8_t)kr_flag,
	    (uint8_t)iv_update, iv_index, beacon, &blen) != 0)
		return (-1);

	for (j = 0; j < sim->n_nodes; j++) {
		struct mesh_node *m = &sim->nodes[j];

		if (m == node)
			continue;
		(void)mesh_sim_node_recv_beacon(m, beacon, blen, sim->now, NULL);
	}
	return (0);
}

/*
 * Drive the IV Update / IV Index Recovery state machines from one
 * authenticated Secure Network beacon.
 *
 * MshPRT_v1.1.1 Section 3.11.6: the IV Index Recovery procedure observes
 * authenticated Secure Network beacons whenever it is eligible - no recovery
 * completed in the previous 192 hours, or the node cannot determine that it
 * did.  Authentication of the beacon IS the trigger; there is no operator
 * action and no separate arming step visible to the application, so the arm is
 * taken here, on the beacon path, immediately before the state machine runs.
 * `primary` restricts the arm to a beacon authenticated with the primary
 * subnet's NetKey, as Section 3.11.6 requires of a node that is a member of the
 * primary subnet.
 *
 * Without this arm the recovery branches of mesh_iv_recv_beacon() are
 * unreachable: a beacon at Current IV Index + 1 with the IV Update flag clear
 * is rejected, and so is anything from + 2 to + 42, so a node that was powered
 * off, out of range or asleep across an IV Update never rejoins.
 */
/*
 * Does this observation need the IV Index Recovery procedure at all?
 *
 * Section 3.11.6 Table 3.86 overlaps the ordinary IV Update procedure at
 * Current IV Index + 1: row 1 (Normal, flag set) is simply "the network has
 * started an IV Update", which Section 3.11.5 already handles under the
 * 96-hour dwell.  Arming recovery for it would re-anchor the dwell, defeating
 * the runaway protection, and would spend the credit Section 3.11.6 allows at
 * most once per 192 hours on a routine event.  So recovery is armed only for
 * an observation the ordinary procedure cannot explain: more than one index
 * ahead, or exactly one ahead with the IV Update flag clear or an update
 * already in progress.  Beacons past Current + 42 are ignored outright, so
 * they do not arm either.
 */
static int
iv_recovery_applies(const struct mesh_iv_state *st, uint32_t recv_iv, int flag)
{

	if (recv_iv <= st->iv_index ||
	    recv_iv - st->iv_index > MESH_IV_MAX_LOOKAHEAD)
		return (0);
	if (recv_iv > st->iv_index + 1)
		return (1);
	return (st->state == MESH_IV_UPDATE_IN_PROGRESS || !flag);
}

void
mesh_sim_node_iv_beacon(struct mesh_node *node, uint32_t recv_iv,
    int recv_iv_update, uint64_t now, int primary)
{

	if (node == NULL)
		return;
	/*
	 * MshPRT_v1.1.1 Section 3.11.5, verbatim: "If this node is a member of
	 * a primary subnet and receives a Secure Network beacon or a Mesh
	 * Private beacon on a secondary subnet with an IV Index greater than
	 * the last known IV Index of the primary subnet, the Secure Network
	 * beacon or the Mesh Private beacon shall be ignored."
	 *
	 * Ignored means ignored: not "accepted but barred from arming
	 * recovery".  Suppressing only the recovery arm still let a beacon
	 * authenticated under a secondary NetKey drive the ordinary Section
	 * 3.11.5 transition and move the node's IV Index - and the IV Index is
	 * one shared resource for the whole node, so a deliberately lower-trust
	 * guest subnet (Section 3.11.2) could advance it for the primary.
	 *
	 * INTERPRETATION, recorded as one: this node holds exactly one
	 * mesh_iv_state and it belongs to the primary subnet, so "the last
	 * known IV Index of the primary subnet" is node->iv.iv_index, and the
	 * "is a member of a primary subnet" precondition is always true here -
	 * every node in this stack is provisioned with a primary NetKey.  A
	 * secondary-subnet beacon at or below that index is still processed,
	 * which is what lets one complete an update the primary already
	 * announced.
	 */
	if (!primary && recv_iv > node->iv.iv_index)
		return;
	/*
	 * Section 3.11.5's deferral, on the beacon-driven completion this time:
	 * an In Progress node that hears the network back in Normal Operation
	 * at the same IV Index would otherwise complete here and zero its SEQ
	 * under an unacknowledged segmented transfer.  Leaving the state
	 * unchanged defers it; the node tick retries the completion once the
	 * SAR transmit table drains.  Nothing else is lost by skipping: a
	 * same-index beacon carries no other transition.
	 */
	if (recv_iv == node->iv.iv_index && !recv_iv_update &&
	    node->iv.state == MESH_IV_UPDATE_IN_PROGRESS &&
	    node_sar_tx_unacked(node)) {
		node->iv_complete_deferrals++;
		return;
	}
	if (primary && iv_recovery_applies(&node->iv, recv_iv, recv_iv_update) &&
	    mesh_iv_recovery_eligible(&node->iv, now))
		(void)mesh_iv_recovery_begin(&node->iv);
	(void)mesh_iv_recv_beacon(&node->iv, recv_iv, recv_iv_update, now);
	if (node->iv.seq_reset_pending) {
		/*
		 * Table 3.86: three of the four recovery rows carry the action
		 * "reset sequence numbers to 0x000000".  The replay protection
		 * list is keyed on (IV Index, SEQ) and every pair it holds
		 * belongs to an epoch the network has already left, so it is
		 * flushed with the same transition - otherwise the stale pairs
		 * outrank everything a peer can now send and block it forever.
		 */
		node->seq = 0;
		mesh_rpl_reset(&node->rpl);
		node->iv.seq_reset_pending = 0;
	}
}

/*
 * Authenticate one received beacon against a single NetKey and recover the
 * network state it carries.
 *
 * MshPRT_v1.1.1 Section 3.10 defines two beacons that carry it: the Secure
 * Network beacon (Section 3.10.3, Beacon Type 0x01) and the Mesh Private
 * beacon (Section 3.10.4, Beacon Type 0x02).  Section 3.10.4.2 requires that a
 * received Mesh Private beacon be authenticated against each known
 * PrivateBeaconKey to identify the network and that, for the identified
 * network, the node monitor IV Index updates (Section 3.11.5) and Key Refresh
 * procedures (Section 3.11.4) - that is, exactly the processing the Secure
 * Network beacon already drives.  Dispatching on the Beacon Type here gives
 * both beacons that processing over the same key list, so a network that has
 * enabled beacon privacy is not invisible to this node.
 *
 * Returns 0 when the beacon authenticated under netkey, -1 otherwise.
 */
static int
beacon_recv_state(const uint8_t netkey[16], const uint8_t *beacon, size_t len,
    uint8_t *key_refresh, uint8_t *iv_update, uint32_t *iv_index)
{
	struct mesh_private_beacon pb;
	struct mesh_secure_beacon sb;

	if (len > 0 && beacon[0] == MESH_BEACON_TYPE_MESH_PRIVATE) {
		if (mesh_private_beacon_parse(netkey, beacon, len, &pb) != 0)
			return (-1);
		*key_refresh = pb.key_refresh;
		*iv_update = pb.iv_update;
		*iv_index = pb.iv_index;
		return (0);
	}
	if (mesh_secure_beacon_parse(netkey, beacon, len, &sb) != 0)
		return (-1);
	*key_refresh = sb.key_refresh;
	*iv_update = sb.iv_update;
	*iv_index = sb.iv_index;
	return (0);
}

int
mesh_sim_node_recv_beacon(struct mesh_node *node, const uint8_t *beacon,
    size_t len, uint64_t now, uint16_t *net_idx)
{
	struct mesh_sim_subnet_key *subnet;
	uint32_t recv_iv;
	int before;
	size_t i;
	uint8_t recv_kr, recv_ivu;

	if (node == NULL || beacon == NULL)
		return (-1);
	/*
	 * The IV Update dwell is anchored on the wall clock so it survives a
	 * restart: when the host has supplied one (wall_now != 0), use it for
	 * the mesh_iv_recv_beacon dwell checks below.  Otherwise keep the
	 * caller's `now` (e.g. unit tests inject their own dwell clock).
	 */
	if (node->sim->wall_now != 0)
		now = node->sim->wall_now;
	/*
	 * A beacon secured with the node's current key carries the IV state
		 * only; the Key Refresh phase advance (Section 3.11.4) is driven by
	 * the beacon secured with the NEW key.
	 */
	if (beacon_recv_state(node->netkey, beacon, len, &recv_kr, &recv_ivu,
	    &recv_iv) == 0) {
		mesh_sim_node_iv_beacon(node, recv_iv, recv_ivu, now, 1);
		if (net_idx != NULL)
			*net_idx = node->primary_net_idx;
		return (0);
	}
	if (node->have_new_key &&
	    beacon_recv_state(node->new_netkey, beacon, len, &recv_kr,
	    &recv_ivu, &recv_iv) == 0) {
		mesh_sim_node_iv_beacon(node, recv_iv, recv_ivu, now, 1);
		before = mesh_kr_phase(&node->kr);
		(void)mesh_kr_beacon(&node->kr, recv_kr);
		/*
		 * Entering Phase 3 revokes the old key immediately: promote the new
		 * key so the node returns to Normal Operation with only that key.
		 */
		if (before != MESH_KR_PHASE_3 &&
		    mesh_kr_phase(&node->kr) == MESH_KR_PHASE_3)
			(void)mesh_sim_key_refresh_finalize(node);
		if (net_idx != NULL)
			*net_idx = node->primary_net_idx;
		return (0);
	}
	for (i = 0; i < node->n_subnets; i++) {
		subnet = &node->subnets[i];
		if (!subnet->valid)
			continue;
		if (beacon_recv_state(subnet->netkey, beacon, len, &recv_kr,
		    &recv_ivu, &recv_iv) == 0) {
			mesh_sim_node_iv_beacon(node, recv_iv, recv_ivu, now, 0);
			if (net_idx != NULL)
				*net_idx = subnet->net_idx;
			return (0);
		}
		if (!subnet->have_new_key ||
		    beacon_recv_state(subnet->new_netkey, beacon, len, &recv_kr,
		    &recv_ivu, &recv_iv) != 0)
			continue;
		mesh_sim_node_iv_beacon(node, recv_iv, recv_ivu, now, 0);
		before = mesh_kr_phase(&subnet->kr);
		(void)mesh_kr_beacon(&subnet->kr, recv_kr);
		if (before != MESH_KR_PHASE_3 &&
		    mesh_kr_phase(&subnet->kr) == MESH_KR_PHASE_3)
			(void)mesh_sim_subnet_key_refresh_finalize(node,
			    subnet->net_idx);
		if (net_idx != NULL)
			*net_idx = subnet->net_idx;
		return (0);
	}
	return (-1);
}

int
mesh_sim_begin_iv_update(struct mesh_node *node)
{

	if (node == NULL)
		return (-1);
	return (mesh_iv_begin_update(&node->iv, sim_iv_now(node->sim)) ==
	    MESH_IV_STARTED ? 0 : -1);
}

int
mesh_sim_complete_iv_update(struct mesh_node *node)
{

	if (node == NULL)
		return (-1);
	/* Section 3.11.5's deferral; see node_sar_tx_unacked(). */
	if (node->iv.state == MESH_IV_UPDATE_IN_PROGRESS &&
	    node_sar_tx_unacked(node)) {
		node->iv_complete_deferrals++;
		return (-1);
	}
	return (mesh_iv_complete_update(&node->iv, sim_iv_now(node->sim)) ==
	    MESH_IV_COMPLETED ? 0 : -1);
}

int
mesh_sim_begin_key_refresh(struct mesh_node *node, const uint8_t new_netkey[16])
{

	if (node == NULL || new_netkey == NULL)
		return (-1);
	memcpy(node->new_netkey, new_netkey, 16);
	if (derive_subnet_material(node->new_netkey, &node->new_nid,
	    node->new_enckey, node->new_privkey, &node->new_directed_nid,
	    node->new_directed_enckey, node->new_directed_privkey) != 0)
		return (-1);
	node->have_new_key = 1;
	if (mesh_kr_begin(&node->kr) != 0)
		return (-1);
	/*
	 * Section 3.11.4.2: the node transmits with the new keys from Phase 2
	 * and receives with both from Phase 1, and the friendship material is
	 * derived from the NetKey (Section 3.9.6.3.1).  Stage its new-key
	 * counterpart now, not at Phase 3.
	 */
	(void)friend_cred_resync(node);
	return (0);
}

int
mesh_sim_key_refresh_advance(struct mesh_node *node)
{

	if (node == NULL || !node->have_new_key)
		return (-1);
	/* Phase 1 -> Phase 2: the node starts transmitting with the new key. */
	if (mesh_kr_beacon(&node->kr, 1) < 0)
		return (-1);
	return (0);
}

int
mesh_sim_key_refresh_finalize(struct mesh_node *node)
{

	if (node == NULL || !node->have_new_key)
		return (-1);
	/* Promote the new managed-flooding credential to the sole current key. */
	memcpy(node->netkey, node->new_netkey, 16);
	node->nid = node->new_nid;
	memcpy(node->enckey, node->new_enckey, 16);
	memcpy(node->privkey, node->new_privkey, 16);
	/* The directed material (Section 3.9.6.3.1) is promoted with it. */
	node->directed_nid = node->new_directed_nid;
	memcpy(node->directed_enckey, node->new_directed_enckey, 16);
	memcpy(node->directed_privkey, node->new_directed_privkey, 16);
	/*
	 * Re-derive any friendship credential from the promoted NetKey
	 * (Section 3.9.6.3.1): friendship security is bound to the subnet key,
	 * so a refresh that did not re-derive it would silently break the LPN
	 * link.  The new-key slot staged at Phase 1 is now the current one, and
	 * the resync (run below, after have_new_key is cleared) collapses the
	 * pair back to a single credential.
	 */
	/* Reset the phase machine and scrub the (now promoted) new-key slot. */
	mesh_kr_init(&node->kr);
	node->have_new_key = 0;
	explicit_bzero(node->new_netkey, sizeof(node->new_netkey));
	node->new_nid = 0;
	explicit_bzero(node->new_enckey, sizeof(node->new_enckey));
	explicit_bzero(node->new_privkey, sizeof(node->new_privkey));
	node->new_directed_nid = 0;
	explicit_bzero(node->new_directed_enckey,
	    sizeof(node->new_directed_enckey));
	explicit_bzero(node->new_directed_privkey,
	    sizeof(node->new_directed_privkey));
	/*
	 * Section 3.9.6.3.1: the friendship material follows the NetKey, so the
	 * promotion re-derives it.  A failure here is propagated: the caller
	 * must not believe a settled refresh left the friendship link usable.
	 */
	if (friend_cred_resync(node) != 0)
		return (-1);
	return (0);
}

static struct mesh_sim_subnet_key *
find_subnet(struct mesh_node *node, uint16_t net_idx)
{
	size_t i;

	if (node == NULL)
		return (NULL);
	for (i = 0; i < node->n_subnets; i++)
		if (node->subnets[i].valid && node->subnets[i].net_idx == net_idx)
			return (&node->subnets[i]);
	return (NULL);
}

int
mesh_sim_subnet_key_refresh_begin(struct mesh_node *node, uint16_t net_idx,
    const uint8_t new_netkey[16])
{
	struct mesh_sim_subnet_key *subnet;

	if (node == NULL || new_netkey == NULL)
		return (-1);
	if (net_idx == node->primary_net_idx)
		return (mesh_sim_begin_key_refresh(node, new_netkey));
	subnet = find_subnet(node, net_idx);
	if (subnet == NULL || subnet->have_new_key)
		return (-1);
	memcpy(subnet->new_netkey, new_netkey, 16);
	if (derive_subnet_material(subnet->new_netkey, &subnet->new_nid,
	    subnet->new_enckey, subnet->new_privkey, &subnet->new_directed_nid,
	    subnet->new_directed_enckey, subnet->new_directed_privkey) != 0)
		return (-1);
	if (mesh_kr_begin(&subnet->kr) != 0)
		return (-1);
	subnet->have_new_key = 1;
	(void)friend_cred_resync(node);		/* Section 3.11.4.2 */
	return (0);
}

int
mesh_sim_subnet_key_refresh_advance(struct mesh_node *node, uint16_t net_idx)
{
	struct mesh_sim_subnet_key *subnet;

	if (node == NULL)
		return (-1);
	if (net_idx == node->primary_net_idx)
		return (mesh_sim_key_refresh_advance(node));
	subnet = find_subnet(node, net_idx);
	if (subnet == NULL || !subnet->have_new_key)
		return (-1);
	return (mesh_kr_beacon(&subnet->kr, 1) < 0 ? -1 : 0);
}

int
mesh_sim_subnet_key_refresh_finalize(struct mesh_node *node, uint16_t net_idx)
{
	struct mesh_sim_subnet_key *subnet;

	if (node == NULL)
		return (-1);
	if (net_idx == node->primary_net_idx)
		return (mesh_sim_key_refresh_finalize(node));
	subnet = find_subnet(node, net_idx);
	if (subnet == NULL || !subnet->have_new_key)
		return (-1);
	memcpy(subnet->netkey, subnet->new_netkey, 16);
	subnet->nid = subnet->new_nid;
	memcpy(subnet->enckey, subnet->new_enckey, 16);
	memcpy(subnet->privkey, subnet->new_privkey, 16);
	subnet->directed_nid = subnet->new_directed_nid;
	memcpy(subnet->directed_enckey, subnet->new_directed_enckey, 16);
	memcpy(subnet->directed_privkey, subnet->new_directed_privkey, 16);
	mesh_kr_init(&subnet->kr);
	subnet->have_new_key = 0;
	explicit_bzero(subnet->new_netkey, sizeof(subnet->new_netkey));
	subnet->new_nid = 0;
	explicit_bzero(subnet->new_enckey, sizeof(subnet->new_enckey));
	explicit_bzero(subnet->new_privkey, sizeof(subnet->new_privkey));
	subnet->new_directed_nid = 0;
	explicit_bzero(subnet->new_directed_enckey,
	    sizeof(subnet->new_directed_enckey));
	explicit_bzero(subnet->new_directed_privkey,
	    sizeof(subnet->new_directed_privkey));
	/* Section 3.9.6.3.1: the friendship material follows the NetKey. */
	if (friend_cred_resync(node) != 0)
		return (-1);
	return (0);
}

int
mesh_sim_subnet_kr_phase(const struct mesh_node *node, uint16_t net_idx)
{
	size_t i;

	if (node == NULL)
		return (-1);
	if (net_idx == node->primary_net_idx)
		return (mesh_kr_phase(&node->kr));
	for (i = 0; i < node->n_subnets; i++)
		if (node->subnets[i].valid && node->subnets[i].net_idx == net_idx)
			return (mesh_kr_phase(&node->subnets[i].kr));
	return (-1);
}

/* ================================================================
 * Directed Forwarding.
 * ================================================================ */

void
mesh_sim_set_sar(struct mesh_node *node, uint32_t retrans_ms, uint32_t retries,
    uint32_t discard_ms)
{

	if (node == NULL)
		return;
	node->sar_retrans_ms = retrans_ms;
	node->sar_retries = retries;
	node->sar_discard_ms = discard_ms;
}

void
mesh_sim_set_df(struct mesh_node *node, int managed_flood)
{

	mesh_sim_set_df_features(node, 1, 1, 1, 1, managed_flood);
}

void
mesh_sim_set_df_features(struct mesh_node *node, int enabled,
    int directed_relay, int directed_proxy, int directed_friend,
    int managed_flood)
{

	if (node == NULL)
		return;
	if (!enabled) {
		/*
		 * Disable: stop the relay/target roles AND flush the forwarding
		 * table.  Leaving established paths behind would let a node that
		 * was told to stop forwarding keep using them.
		 */
		node->df_enabled = 0;
		mesh_df_table_init(&node->df_table);
		node->df_feat.directed_relay = 0;
		node->df_feat.directed_proxy = 0;
		node->df_feat.directed_friend = 0;
		node->df_feat.managed_flood_relay = managed_flood ? 1 : 0;
		node->df_fn = 0;
		return;
	}
	/*
	 * Only a transition from disabled to enabled (re)initialises the
	 * forwarding table: re-asserting DF=1 while it is already on is a
	 * no-op re-assert, and wiping the table there discarded every
	 * established path on each repeated Directed Control Set.
	 */
	if (!node->df_enabled) {
		mesh_df_table_init(&node->df_table);
		node->df_fn = 0;
	}
	node->df_enabled = 1;
	node->df_feat.directed_relay = directed_relay ? 1 : 0;
	node->df_feat.directed_proxy = directed_proxy ? 1 : 0;
	node->df_feat.directed_friend = directed_friend ? 1 : 0;
	node->df_feat.managed_flood_relay = managed_flood ? 1 : 0;
}

int
mesh_sim_df_discover(struct mesh_sim *sim, struct mesh_node *origin,
    uint16_t target, uint8_t lifetime_sel)
{
	struct mesh_df_path_request req;
	uint8_t params[MESH_ACCESS_PAYLOAD_MAX];
	size_t plen;
	uint64_t now;

	if (sim == NULL || origin == NULL || !origin->df_enabled)
		return (-1);
	now = sim_now_ms(sim);
	/*
	 * Begin the Path Origin discovery (Section 3.6.6.5): a fresh Forwarding
	 * Number, one wanted lane, two-way path so the target confirms.  The
	 * built Path Request is flooded as a Transport Control PDU; DF relays
	 * install reverse entries and re-flood, the target replies along the
	 * reverse path, and the origin confirms - all pumped by mesh_sim_run.
	 */
	if (mesh_df_discovery_start(&origin->df_disc, origin->addr, target,
	    origin->df_fn, MESH_DF_METRIC_NODE_COUNT, lifetime_sel & 0x03, 1, 1,
	    30000, now, &req) != 0)
		return (-1);
	origin->df_fn = mesh_df_fn_next(origin->df_fn);
	if (mesh_df_path_request_build(&req, params, &plen) != 0)
		return (-1);
	if (node_tx_ctl(sim, origin, -1, MESH_ADDR_ALL_DF,
	    MESH_DF_OP_PATH_REQUEST, params, plen, 5, 1) != 0)
		return (-1);
	(void)mesh_sim_run(sim, 32);
	return (origin->df_disc.state == MESH_DF_DISC_ESTABLISHED ? 0 : -1);
}

void
mesh_sim_df_expire(struct mesh_sim *sim)
{
	int j;

	if (sim == NULL)
		return;
	for (j = 0; j < sim->n_nodes; j++) {
		if (sim->nodes[j].df_enabled)
			(void)mesh_df_table_expire(&sim->nodes[j].df_table,
			    sim_now_ms(sim));
	}
}

/* ================================================================
 * Heartbeat.
 * ================================================================ */

void
mesh_sim_hb_set_pub(struct mesh_node *node, uint16_t dst, uint8_t count_log,
    uint8_t period_log, uint8_t ttl, uint16_t trigger_features,
    uint16_t cur_features)
{

	if (node == NULL)
		return;
	memset(&node->hb_pub, 0, sizeof(node->hb_pub));
	node->hb_pub.dst = dst;
	node->hb_pub.count_log = count_log;
	node->hb_pub.period_log = period_log;
	node->hb_pub.ttl = ttl;
	node->hb_pub.features = trigger_features;
	node->hb_features = cur_features;
	mesh_hb_pub_timer_init(&node->hb_timer, &node->hb_pub);
}

int
mesh_sim_hb_set_sub(struct mesh_node *node, uint16_t src, uint16_t dst,
    uint8_t period_log)
{
	struct mesh_hb_sub_set set;

	if (node == NULL)
		return (-1);
	set.src = src;
	set.dst = dst;
	set.period_log = period_log;
	/*
	 * mesh_hb_sub_apply() validates before it touches the subscription, so
	 * a rejected Set leaves a live subscription (and its counters) intact;
	 * do not pre-init here either.  The subscription is armed when apply
	 * kept a source (a zero Source/Destination/PeriodLog disables it).
	 */
	if (mesh_hb_sub_apply(&node->hb_sub, &set) != 0)
		return (-1);
	node->hb_sub_active = (node->hb_sub.src != 0 && node->hb_sub.dst != 0);
	return (0);
}

/* Originate a Heartbeat transport control message onto the medium (flooded). */
static int
node_hb_publish(struct mesh_sim *sim, struct mesh_node *node,
    const struct mesh_hb_msg *m)
{
	uint8_t body[3];
	size_t blen;

	if (node->hb_pub.dst == 0)
		return (-1);
	if (mesh_hb_msg_build(m, body, &blen) != 0)
		return (-1);
	return (node_tx_ctl(sim, node, -1, node->hb_pub.dst, MESH_HB_CTL_OPCODE,
	    body, blen, m->init_ttl, 0));
}

int
mesh_sim_hb_feature_change(struct mesh_sim *sim, struct mesh_node *node,
    uint16_t new_features)
{
	struct mesh_hb_msg m;
	uint16_t old;
	int r;

	if (sim == NULL || node == NULL)
		return (-1);
	old = node->hb_features;
	node->hb_features = new_features;
	r = mesh_hb_pub_feature_change(&node->hb_pub, old, new_features, &m);
	if (r != 1)
		return (r == 0 ? 0 : -1);
	return (node_hb_publish(sim, node, &m) == 0 ? 1 : -1);
}

int
mesh_sim_hb_publish_periodic(struct mesh_sim *sim, struct mesh_node *node,
    uint32_t dt_secs)
{
	struct mesh_hb_msg m;
	int published = 0;

	if (sim == NULL || node == NULL)
		return (-1);
	/*
	 * Tick the publication timer one Period at a time so each crossed
	 * boundary emits a Heartbeat (MshPRT_v1.1.1 Section 4.2.18).
	 */
	while (mesh_hb_pub_timer_tick(&node->hb_timer, dt_secs,
	    node->hb_features, &m) == 1) {
		if (node_hb_publish(sim, node, &m) == 0)
			published++;
		dt_secs = 0;	/* drain any further boundaries at this instant */
		if (!mesh_hb_pub_timer_active(&node->hb_timer))
			break;
	}
	return (published);
}

/* ================================================================
 * Provisioning (PB-ADV) over the virtual bearer.
 * ================================================================ */

/* Drain a session's outbound Provisioning PDUs into that side's pending FIFO. */
static void
prov_drain_session(struct mesh_sim_prov *pv, int side)
{
	uint8_t pdu[MESH_PROV_PDU_MAX];
	size_t len, slot;

	while (mesh_prov_session_poll(&pv->sess[side], pdu, &len) == 1) {
		slot = pv->fifo_tail[side] % MESH_SIM_PROV_FIFO;
		if ((pv->fifo_tail[side] - pv->fifo_head[side]) >=
		    MESH_SIM_PROV_FIFO)
			break;			/* FIFO full (never in practice) */
		memcpy(pv->fifo[side][slot], pdu, len);
		pv->fifo_len[side][slot] = len;
		pv->fifo_tail[side]++;
	}
}

int
mesh_sim_provision_begin(struct mesh_sim *sim, struct mesh_sim_prov *pv,
    const uint8_t dev_uuid[16], uint16_t assign_addr, uint8_t dev_elements)
{
	struct mesh_prov_data data;
	struct mesh_prov_caps caps;
	uint8_t pkt[MESH_PBADV_PKT_MAX], ack[MESH_PBADV_PKT_MAX];
	size_t pktlen, acklen;
	int have_ack = 0;

	if (sim == NULL || pv == NULL || dev_uuid == NULL || dev_elements == 0)
		return (-1);
	memset(pv, 0, sizeof(*pv));
	pv->assigned_addr = assign_addr;
	pv->dev_elements = dev_elements;

	/* The Provisioner hands over the sim's subnet material. */
	memset(&data, 0, sizeof(data));
	memcpy(data.netkey, sim->netkey, 16);
	data.netkey_index = 0;
	data.flags = 0;
	data.iv_index = sim->iv_index;
	data.unicast_addr = assign_addr;

	memset(&caps, 0, sizeof(caps));
	caps.num_elements = dev_elements;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;

	if (mesh_prov_provisioner_init(&pv->sess[0], NULL, NULL, 0x00,
	    &data) != 0)
		return (-1);
	if (mesh_prov_device_init(&pv->sess[1], NULL, NULL, &caps) != 0) {
		mesh_prov_session_free(&pv->sess[0]);
		return (-1);
	}
	mesh_prov_link_init_provisioner(&pv->link[0], 0x0acce55e, dev_uuid,
	    1000, 8);
	mesh_prov_link_init_device(&pv->link[1], dev_uuid, 1000, 8);

	/* PB-ADV Link Open / Link Ack handshake (Section 5.3.1). */
	if (mesh_prov_link_open(&pv->link[0], pv->now_ms, pkt, &pktlen) != 0)
		return (-1);
	if (mesh_prov_link_recv(&pv->link[1], pkt, pktlen, pv->now_ms, NULL,
	    NULL, NULL, ack, &acklen, &have_ack) != 0 || !have_ack)
		return (-1);
	if (mesh_prov_link_recv(&pv->link[0], ack, acklen, pv->now_ms, NULL,
	    NULL, NULL, NULL, NULL, NULL) != 0)
		return (-1);
	if (!mesh_prov_link_is_open(&pv->link[0]) ||
	    !mesh_prov_link_is_open(&pv->link[1]))
		return (-1);

	/* Kick off the Provisioning PDU exchange with the Invite. */
	if (mesh_prov_session_start(&pv->sess[0]) != 0)
		return (-1);
	prov_drain_session(pv, 0);
	return (0);
}

int
mesh_sim_provision_run(struct mesh_sim *sim, struct mesh_sim_prov *pv,
    int max_iters)
{
	int iter, side;

	if (sim == NULL || pv == NULL)
		return (-1);
	for (iter = 0; iter < max_iters; iter++) {
		int progressed = 0;

		for (side = 0; side < 2; side++) {
			int other = side ^ 1;
			uint8_t pkt[MESH_PBADV_PKT_MAX];
			size_t pktlen;
			int rc;

			prov_drain_session(pv, side);
			/* Feed the next queued PDU when the link is idle. */
			if (mesh_prov_link_idle(&pv->link[side]) &&
			    pv->fifo_head[side] != pv->fifo_tail[side]) {
				size_t slot = pv->fifo_head[side] %
				    MESH_SIM_PROV_FIFO;

				if (mesh_prov_link_send(&pv->link[side],
				    pv->fifo[side][slot],
				    pv->fifo_len[side][slot], pv->now_ms) == 0) {
					pv->fifo_head[side]++;
					progressed = 1;
				}
			}
			/* Emit bearer packets and deliver them to the peer. */
			while ((rc = mesh_prov_link_poll(&pv->link[side],
			    pv->now_ms, pkt, &pktlen)) == 1) {
				uint8_t pdu[MESH_PROV_BEARER_PDU_MAX];
				uint8_t ack[MESH_PBADV_PKT_MAX];
				size_t pl = 0, al = 0;
				int have_pdu = 0, have_ack = 0;

				(void)mesh_prov_link_recv(&pv->link[other], pkt,
				    pktlen, pv->now_ms, pdu, &pl, &have_pdu, ack,
				    &al, &have_ack);
				if (have_ack)
					(void)mesh_prov_link_recv(&pv->link[side],
					    ack, al, pv->now_ms, NULL, NULL, NULL,
					    NULL, NULL, NULL);
				if (have_pdu) {
					(void)mesh_prov_session_recv(
					    &pv->sess[other], pdu, pl);
					prov_drain_session(pv, other);
				}
				progressed = 1;
			}
			if (rc < 0)
				return (-1);
		}
		if ((mesh_prov_session_done(&pv->sess[0]) ||
		    mesh_prov_session_failed(&pv->sess[0])) &&
		    (mesh_prov_session_done(&pv->sess[1]) ||
		    mesh_prov_session_failed(&pv->sess[1])))
			break;
		if (!progressed)
			pv->now_ms += 1000;	/* trip the retransmission timers */
	}

	pv->failed = mesh_prov_session_failed(&pv->sess[0]) ||
	    mesh_prov_session_failed(&pv->sess[1]);
	pv->done = mesh_prov_session_done(&pv->sess[0]) &&
	    mesh_prov_session_done(&pv->sess[1]);
	if (!pv->done || pv->failed)
		return (-1);
	/* Both sides must have derived the same DevKey (Section 5.4.2.5). */
	if (timingsafe_bcmp(mesh_prov_session_devkey(&pv->sess[0]),
	    mesh_prov_session_devkey(&pv->sess[1]), 16) != 0)
		return (-1);
	return (0);
}

struct mesh_node *
mesh_sim_provision_commit(struct mesh_sim *sim, struct mesh_sim_prov *pv)
{

	if (sim == NULL || pv == NULL || !pv->done || pv->failed)
		return (NULL);
	/*
	 * The device installed the sim's NetKey and its assigned unicast; admit
	 * it as a node deriving the same subnet/app credentials every other node
	 * holds, so it participates in network traffic immediately.
	 */
	return (mesh_sim_add_node(sim, pv->assigned_addr, pv->dev_elements));
}

const uint8_t *
mesh_sim_prov_devkey(const struct mesh_sim_prov *pv, int side)
{

	if (pv == NULL || side < 0 || side > 1)
		return (NULL);
	return (mesh_prov_session_devkey(&pv->sess[side]));
}

/* ================================================================
 * Inspection.
 * ================================================================ */

struct mesh_node *
mesh_sim_node_at(struct mesh_sim *sim, uint16_t addr)
{
	int j;

	if (sim == NULL)
		return (NULL);
	for (j = 0; j < sim->n_nodes; j++) {
		if (local_unicast(&sim->nodes[j], addr))
			return (&sim->nodes[j]);
	}
	return (NULL);
}

uint32_t
mesh_sim_node_seq(const struct mesh_node *node)
{

	return (node != NULL ? node->seq : 0);
}

uint32_t
mesh_sim_node_iv(const struct mesh_node *node)
{

	return (node != NULL ? node->iv.iv_index : 0);
}

int
mesh_sim_node_kr_phase(const struct mesh_node *node)
{

	return (node != NULL ? mesh_kr_phase(&node->kr) : -1);
}

size_t
mesh_sim_pending(const struct mesh_sim *sim)
{

	return (sim != NULL ? sim->n_tx : 0);
}
