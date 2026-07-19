/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * LE Meta event (HCI event 0x3E) decoding seam.
 *
 * blued's controller-event handler (blued_event.c) enables the LE Meta
 * subevents it consumes in the LE event mask (see
 * hci_le_default_event_mask()), so the controller will forward them.  This
 * header carries the pure, side-effect-free decoder for those subevents: it
 * overlays the wire bytes onto a caller-supplied output struct and validates
 * the spec-defined lengths.  Keeping it a standalone inline decoder (rather
 * than logic buried inside blued_handle_hci_event()) lets a unit test feed
 * crafted event bytes and assert the extracted fields against the Core Spec,
 * while blued_event.c drives the very same code on the live socket path.
 *
 * Coverage: BT 5.0 Periodic Advertising sync (Sync Established/Report/Sync
 * Lost), BT 5.1 Direction Finding (Connectionless/Connection IQ Report, CTE
 * Request Failed) and Periodic Advertising Sync Transfer Received (PAST), and
 * the BT 5.2 LE Power Control + LE Isochronous (ISO) transport subevents.
 *
 * Oracle: Core Spec Vol 4 Part E section 7.7.65.14-.33; struct field names
 * cross-checked against <netgraph/bluetooth/include/ng_hci.h>.
 *
 * Wire framing (as delivered by the raw HCI socket):
 *   pkt[0] = HCI packet type (0x04, HCI_EVENT_PKT)
 *   pkt[1] = event code (0x3E, HCI_LE_Meta)
 *   pkt[2] = parameter total length
 *   pkt[3] = subevent code
 *   pkt[4..] = subevent parameters (the ng_hci_le_*_ep payload)
 */

#ifndef _BLUED_LE_META_H_
#define _BLUED_LE_META_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <netgraph/bluetooth/include/ng_hci.h>

/* Offset of the subevent parameters within the raw HCI event packet. */
#define BLUED_LE_META_PARAM_OFF	4

/*
 * Decoded LE Meta subevent.  Only the fields relevant to the decoded
 * subevent are populated; the struct is zeroed on entry.  Multi-byte
 * fields are host-order after decoding (the wire is little-endian).
 */
struct blued_le_meta_report {
	uint8_t		subevent;

	bool		has_status;	/* event carries a Status octet */
	uint8_t		status;
	uint16_t	connection_handle;

	/* 7.7.65.32 LE Path Loss Threshold (0x20). */
	uint8_t		current_path_loss;	/* dB */
	uint8_t		zone_entered;		/* 0=low, 1=mid, 2=high */

	/* 7.7.65.33 LE Transmit Power Reporting (0x21). */
	uint8_t		reason;		/* 0=local,1=remote,2=read-complete */
	uint8_t		phy;
	int8_t		tx_power_level;		/* dBm */
	uint8_t		tx_power_level_flag;	/* bit0=min, bit1=max */
	int8_t		delta;			/* dB */

	/* 7.7.65.26 LE CIS Request (0x1A). */
	uint16_t	acl_connection_handle;
	uint16_t	cis_connection_handle;
	uint8_t		cig_id;
	uint8_t		cis_id;

	/* 7.7.65.25 LE CIS Established (0x19) -- selected fields. */
	uint8_t		phy_c_to_p;
	uint8_t		phy_p_to_c;
	uint8_t		nse;
	uint16_t	max_pdu_c_to_p;
	uint16_t	max_pdu_p_to_c;
	uint16_t	iso_interval;

	/* 7.7.65.27/.29 Create BIG Complete / BIG Sync Established. */
	uint8_t		big_handle;
	uint8_t		num_bis;
	const uint8_t  *bis_handles;	/* -> num_bis * 2 LE octets in pkt */

	/* 7.7.65.28/.30 Terminate BIG / BIG Sync Lost reason. */
	uint8_t		reason_code;

	/*
	 * 7.7.65.14 Periodic Advertising Sync Established (0x0E) and
	 * 7.7.65.24 Periodic Advertising Sync Transfer Received (0x18):
	 * the synchronised periodic advertising train and its advertiser.
	 */
	uint16_t	sync_handle;
	uint8_t		advertising_sid;
	uint8_t		advertiser_addr_type;
	uint8_t		advertiser_addr[6];
	uint8_t		advertiser_phy;
	uint16_t	periodic_adv_interval;	/* 1.25ms units */
	uint8_t		advertiser_clock_accuracy;
	uint16_t	service_data;		/* PAST Received only */

	/* 7.7.65.15 Periodic Advertising Report (0x0F). */
	int8_t		tx_power;		/* dBm, 0x7F = not available */
	int8_t		rssi;			/* dBm, 0x7F = not available */
	uint8_t		cte_type;		/* also used by IQ reports */
	uint8_t		data_status;		/* 0=complete,1=more,2=truncated */
	uint8_t		data_length;
	const uint8_t  *data;			/* -> data_length octets in pkt */

	/*
	 * 7.7.65.21 Connectionless IQ Report (0x15) and
	 * 7.7.65.22 Connection IQ Report (0x16): direction-finding samples.
	 * channel_index carries the connectionless channel; connection
	 * reports use data_channel_index + rx_phy instead.
	 */
	uint8_t		channel_index;
	uint8_t		data_channel_index;
	uint8_t		rx_phy;
	int16_t		iq_rssi;		/* 0.1 dBm units, signed */
	uint8_t		rssi_antenna_id;
	uint8_t		slot_durations;		/* 1=1us, 2=2us */
	uint8_t		packet_status;
	uint16_t	event_counter;		/* periodic or connection event */
	uint8_t		sample_count;
	const uint8_t  *iq_samples;		/* -> sample_count * {I,Q} octets */
};

static inline uint16_t
blued_le_meta_le16(const uint8_t *p)
{

	return ((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline bool
blued_le_handle_valid(uint16_t handle)
{

	return (handle <= 0x0eff);
}

static inline bool
blued_le_rssi8_valid(uint8_t value)
{
	int8_t rssi = (int8_t)value;

	return (value == 0x7f || (rssi >= -127 && rssi <= 20));
}

static inline bool
blued_le_iq_envelope_valid(uint8_t channel, uint8_t max_channel,
    uint16_t rssi, uint8_t cte_type, uint8_t slots, uint8_t packet_status)
{
	int16_t signed_rssi = (int16_t)rssi;

	if (packet_status == 0xff)
		return (true); /* channel/CTE/slots are explicitly invalid here */
	return (packet_status <= 0x02 && channel <= max_channel &&
	    signed_rssi >= -1270 && signed_rssi <= 200 && cte_type <= 0x02 &&
	    (slots == 0x01 || slots == 0x02));
}

/*
 * Decode an LE Meta subevent (Periodic Advertising, Direction Finding, PAST,
 * Power Control, or ISO transport).
 *
 * Returns:
 *    0  the subevent is one this decoder owns and the packet is long
 *       exactly framed for all spec-defined fields; *out is populated.
 *   -1  the packet framing is malformed: *out->subevent is still set when
 *       the subevent octet was present.
 *    1  the subevent is not one this decoder owns (caller handles it
 *       elsewhere, e.g. the legacy connection-management arms).
 *
 * The out->status field is populated for events that carry a Status octet,
 * but a nonzero status is NOT treated as a decode error here: the caller
 * decides whether to act (a failed CIS Established still reports a handle).
 */
static inline int
blued_parse_le_meta_event(const uint8_t *pkt, size_t len,
    struct blued_le_meta_report *out)
{
	const uint8_t *p;
	size_t avail;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));

	/* Validate the raw HCI Event packet envelope before its subevent. */
	if (pkt == NULL || len < 3)
		return (-1);
	if (pkt[0] != NG_HCI_EVENT_PKT)
		return (1);
	if (pkt[1] != NG_HCI_EVENT_LE)
		return (1);
	if (len >= BLUED_LE_META_PARAM_OFF)
		out->subevent = pkt[3];
	if (len != (size_t)3 + pkt[2])
		return (-1);
	if (pkt[2] < 1)
		return (-1);

	p = pkt + BLUED_LE_META_PARAM_OFF;
	avail = len - BLUED_LE_META_PARAM_OFF;	/* parameter bytes present */

	switch (out->subevent) {
	/* ---- BT 5.0 Periodic Advertising (observer/sync) ------------ */

	case NG_HCI_LEEV_PER_ADV_SYNC_EST:	/* 0x0e, 7.7.65.14 */
		/*
		 * ng_hci_le_periodic_adv_sync_est_ep: status(1) sync_handle(2)
		 * advertising_sid(1) advertiser_addr_type(1) advertiser_addr(6)
		 * advertiser_phy(1) periodic_adv_interval(2) clock_accuracy(1).
		 */
		if (avail != sizeof(ng_hci_le_periodic_adv_sync_est_ep))
			return (-1);
		if (p[0] == 0 && (blued_le_meta_le16(p + 1) > 0x0eff ||
		    p[3] > 0x0f || p[4] > 0x03 ||
		    (p[11] != 0x01 && p[11] != 0x03) ||
		    blued_le_meta_le16(p + 12) < 0x0006 || p[14] > 0x07))
			return (-1);
		out->has_status = true;
		out->status = p[0];
		out->sync_handle = blued_le_meta_le16(p + 1);
		out->advertising_sid = p[3];
		out->advertiser_addr_type = p[4];
		memcpy(out->advertiser_addr, p + 5, 6);
		out->advertiser_phy = p[11];
		out->periodic_adv_interval = blued_le_meta_le16(p + 12);
		out->advertiser_clock_accuracy = p[14];
		return (0);

	case NG_HCI_LEEV_PER_ADV_REPORT:	/* 0x0f, 7.7.65.15 */
		/*
		 * ng_hci_le_periodic_adv_report_ep header (7 bytes):
		 * sync_handle(2) tx_power(int8) rssi(int8) cte_type(1)
		 * data_status(1) data_length(1); then data[data_length].
		 */
		if (avail < sizeof(ng_hci_le_periodic_adv_report_ep))
			return (-1);
		if (avail != sizeof(ng_hci_le_periodic_adv_report_ep) +
		    (size_t)p[6])
			return (-1);
		if (blued_le_meta_le16(p) > 0x0eff ||
		    !blued_le_rssi8_valid(p[2]) || !blued_le_rssi8_valid(p[3]) ||
		    (p[4] > 0x02 && p[4] != 0xff) || p[5] > 0x02)
			return (-1);
		out->sync_handle = blued_le_meta_le16(p + 0);
		out->tx_power = (int8_t)p[2];
		out->rssi = (int8_t)p[3];
		out->cte_type = p[4];
		out->data_status = p[5];
		out->data_length = p[6];
		out->data = (out->data_length > 0) ? p + 7 : NULL;
		return (0);

	case NG_HCI_LEEV_PER_ADV_SYNC_LOST:	/* 0x10, 7.7.65.16 */
		/* ng_hci_le_periodic_adv_sync_lost_ep: sync_handle(2). */
		if (avail != sizeof(ng_hci_le_periodic_adv_sync_lost_ep))
			return (-1);
		if (blued_le_meta_le16(p) > 0x0eff)
			return (-1);
		out->sync_handle = blued_le_meta_le16(p + 0);
		return (0);

	/* ---- BT 5.1 Direction Finding (CTE / IQ reports) ------------ */

	case NG_HCI_LEEV_CONNECTIONLESS_IQ_REPORT:	/* 0x15, 7.7.65.21 */
		/*
		 * ng_hci_le_connectionless_iq_report_ep header (12 bytes):
		 * sync_handle(2) channel_index(1) rssi(int16) antenna_id(1)
		 * cte_type(1) slot_durations(1) packet_status(1)
		 * periodic_event_counter(2) sample_count(1); then
		 * sample_count * {i_sample(int8), q_sample(int8)}.
		 */
		if (avail < sizeof(ng_hci_le_connectionless_iq_report_ep))
			return (-1);
		if (avail != sizeof(ng_hci_le_connectionless_iq_report_ep) +
		    (size_t)p[11] * 2)
			return (-1);
		if (blued_le_meta_le16(p) > 0x0eff ||
		    !blued_le_iq_envelope_valid(p[2], 0x27,
		    blued_le_meta_le16(p + 3), p[6], p[7], p[8]))
			return (-1);
		out->sync_handle = blued_le_meta_le16(p + 0);
		out->channel_index = p[2];
		out->iq_rssi = (int16_t)blued_le_meta_le16(p + 3);
		out->rssi_antenna_id = p[5];
		out->cte_type = p[6];
		out->slot_durations = p[7];
		out->packet_status = p[8];
		out->event_counter = blued_le_meta_le16(p + 9);
		out->sample_count = p[11];
		out->iq_samples = (out->sample_count > 0) ? p + 12 : NULL;
		return (0);

	case NG_HCI_LEEV_CONNECTION_IQ_REPORT:	/* 0x16, 7.7.65.22 */
		/*
		 * ng_hci_le_connection_iq_report_ep header (13 bytes):
		 * connection_handle(2) rx_phy(1) data_channel_index(1)
		 * rssi(int16) antenna_id(1) cte_type(1) slot_durations(1)
		 * packet_status(1) connection_event_counter(2) sample_count(1);
		 * then sample_count * {i_sample(int8), q_sample(int8)}.
		 */
		if (avail < sizeof(ng_hci_le_connection_iq_report_ep))
			return (-1);
		if (avail != sizeof(ng_hci_le_connection_iq_report_ep) +
		    (size_t)p[12] * 2)
			return (-1);
		if (!blued_le_handle_valid(blued_le_meta_le16(p)) ||
		    (p[2] != 0x01 && p[2] != 0x02) ||
		    !blued_le_iq_envelope_valid(p[3], 0x24,
		    blued_le_meta_le16(p + 4), p[7], p[8], p[9]))
			return (-1);
		out->connection_handle = blued_le_meta_le16(p + 0);
		out->rx_phy = p[2];
		out->data_channel_index = p[3];
		out->iq_rssi = (int16_t)blued_le_meta_le16(p + 4);
		out->rssi_antenna_id = p[6];
		out->cte_type = p[7];
		out->slot_durations = p[8];
		out->packet_status = p[9];
		out->event_counter = blued_le_meta_le16(p + 10);
		out->sample_count = p[12];
		out->iq_samples = (out->sample_count > 0) ? p + 13 : NULL;
		return (0);

	case NG_HCI_LEEV_CTE_REQUEST_FAILED:	/* 0x17, 7.7.65.23 */
		/* ng_hci_le_cte_request_failed_ep: status(1) handle(2). */
		if (avail != sizeof(ng_hci_le_cte_request_failed_ep))
			return (-1);
		if (!blued_le_handle_valid(blued_le_meta_le16(p + 1)))
			return (-1);
		out->has_status = true;
		out->status = p[0];
		out->connection_handle = blued_le_meta_le16(p + 1);
		return (0);

	/* ---- BT 5.1 Periodic Advertising Sync Transfer (PAST) ------- */

	case NG_HCI_LEEV_PER_ADV_SYNC_XFER_RCVD:	/* 0x18, 7.7.65.24 */
		/*
		 * ng_hci_le_past_received_ep: status(1) connection_handle(2)
		 * service_data(2) sync_handle(2) advertising_sid(1)
		 * advertiser_addr_type(1) advertiser_addr(6) advertiser_phy(1)
		 * periodic_adv_interval(2) clock_accuracy(1).
		 */
		if (avail != sizeof(ng_hci_le_past_received_ep))
			return (-1);
		if (p[0] == 0 && (!blued_le_handle_valid(blued_le_meta_le16(p + 1)) ||
		    blued_le_meta_le16(p + 5) > 0x0eff || p[7] > 0x0f ||
		    p[8] > 0x03 || (p[15] != 0x01 && p[15] != 0x03) ||
		    blued_le_meta_le16(p + 16) < 0x0006 || p[18] > 0x07))
			return (-1);
		out->has_status = true;
		out->status = p[0];
		out->connection_handle = blued_le_meta_le16(p + 1);
		out->service_data = blued_le_meta_le16(p + 3);
		out->sync_handle = blued_le_meta_le16(p + 5);
		out->advertising_sid = p[7];
		out->advertiser_addr_type = p[8];
		memcpy(out->advertiser_addr, p + 9, 6);
		out->advertiser_phy = p[15];
		out->periodic_adv_interval = blued_le_meta_le16(p + 16);
		out->advertiser_clock_accuracy = p[18];
		return (0);

	/* ---- BT 5.2 LE Power Control -------------------------------- */

	case NG_HCI_LEEV_PATH_LOSS_THRESHOLD:	/* 0x20, 7.7.65.32 */
		/* ng_hci_le_path_loss_threshold_ep: handle(2) loss(1) zone(1) */
		if (avail != sizeof(ng_hci_le_path_loss_threshold_ep))
			return (-1);
		if (!blued_le_handle_valid(blued_le_meta_le16(p)) ||
		    (p[2] != 0xff && p[3] > 0x02))
			return (-1);
		out->connection_handle = blued_le_meta_le16(p + 0);
		out->current_path_loss = p[2];
		out->zone_entered = p[3];
		return (0);

	case NG_HCI_LEEV_TX_POWER_REPORTING:	/* 0x21, 7.7.65.33 */
		/*
		 * ng_hci_le_tx_power_reporting_ep: status(1) handle(2)
		 * reason(1) phy(1) tx_power_level(int8) flag(1) delta(int8)
		 */
		if (avail != sizeof(ng_hci_le_tx_power_reporting_ep))
			return (-1);
		if (!blued_le_handle_valid(blued_le_meta_le16(p + 1)))
			return (-1);
		if (p[0] == 0 && (p[3] > 0x02 || p[4] < 0x01 || p[4] > 0x04 ||
		    (!blued_le_rssi8_valid(p[5]) && p[5] != 0x7e) ||
		    ((p[5] != 0x7e && p[5] != 0x7f) && (p[6] & ~0x03u) != 0) ||
		    (p[3] == 0x02 && p[7] != 0)))
			return (-1);
		out->has_status = true;
		out->status = p[0];
		out->connection_handle = blued_le_meta_le16(p + 1);
		out->reason = p[3];
		out->phy = p[4];
		out->tx_power_level = (int8_t)p[5];
		out->tx_power_level_flag = p[6];
		out->delta = (int8_t)p[7];
		return (0);

	/* ---- BT 5.2 LE Isochronous (ISO) transport ------------------ */

	case NG_HCI_LEEV_CIS_ESTABLISHED:	/* 0x19, 7.7.65.25 */
		/* ng_hci_le_cis_established_ep is 28 bytes. */
		if (avail != sizeof(ng_hci_le_cis_established_ep))
			return (-1);
		out->has_status = true;
		out->status = p[0];
		out->connection_handle = blued_le_meta_le16(p + 1);
		/* p[3..5] CIG_Sync_Delay, p[6..8] CIS_Sync_Delay,
		 * p[9..11] Transport_Latency_C_To_P,
		 * p[12..14] Transport_Latency_P_To_C (3-octet fields). */
		out->phy_c_to_p = p[15];
		out->phy_p_to_c = p[16];
		out->nse = p[17];
		/* p[18] BN_C_To_P, p[19] BN_P_To_C,
		 * p[20] FT_C_To_P, p[21] FT_P_To_C. */
		out->max_pdu_c_to_p = blued_le_meta_le16(p + 22);
		out->max_pdu_p_to_c = blued_le_meta_le16(p + 24);
		out->iso_interval = blued_le_meta_le16(p + 26);
		return (0);

	case NG_HCI_LEEV_CIS_REQUEST:		/* 0x1a, 7.7.65.26 */
		/* ng_hci_le_cis_request_ep: acl(2) cis(2) cig_id(1) cis_id(1) */
		if (avail != sizeof(ng_hci_le_cis_request_ep))
			return (-1);
		out->acl_connection_handle = blued_le_meta_le16(p + 0);
		out->cis_connection_handle = blued_le_meta_le16(p + 2);
		out->cig_id = p[4];
		out->cis_id = p[5];
		return (0);

	case NG_HCI_LEEV_CREATE_BIG_COMPL:	/* 0x1b, 7.7.65.27 */
		/*
		 * ng_hci_le_create_big_compl_ep fixed header (18 bytes):
		 * status(1) big_handle(1) big_sync_delay(3)
		 * transport_latency_big(3) phy(1) nse(1) bn(1) pto(1) irc(1)
		 * max_pdu(2) iso_interval(2) num_bis(1); then
		 * num_bis * connection_handle(2 LE).
		 */
		if (avail < sizeof(ng_hci_le_create_big_compl_ep))
			return (-1);
		if (avail != (size_t)18 + (size_t)p[17] * 2)
			return (-1);
		out->has_status = true;
		out->status = p[0];
		out->big_handle = p[1];
		out->nse = p[9];
		out->iso_interval = blued_le_meta_le16(p + 15);
		out->num_bis = p[17];
		out->bis_handles = (out->num_bis > 0) ? p + 18 : NULL;
		return (0);

	case NG_HCI_LEEV_TERMINATE_BIG_COMPL:	/* 0x1c, 7.7.65.28 */
		/* ng_hci_le_terminate_big_compl_ep: big_handle(1) reason(1) */
		if (avail != sizeof(ng_hci_le_terminate_big_compl_ep))
			return (-1);
		out->big_handle = p[0];
		out->reason_code = p[1];
		return (0);

	case NG_HCI_LEEV_BIG_SYNC_EST:		/* 0x1d, 7.7.65.29 */
		/*
		 * ng_hci_le_big_sync_est_ep fixed header (14 bytes):
		 * status(1) big_handle(1) transport_latency_big(3) nse(1)
		 * bn(1) pto(1) irc(1) max_pdu(2) iso_interval(2) num_bis(1);
		 * then num_bis * connection_handle(2 LE).
		 */
		if (avail < sizeof(ng_hci_le_big_sync_est_ep))
			return (-1);
		if (avail != (size_t)14 + (size_t)p[13] * 2)
			return (-1);
		out->has_status = true;
		out->status = p[0];
		out->big_handle = p[1];
		out->nse = p[5];
		out->iso_interval = blued_le_meta_le16(p + 11);
		out->num_bis = p[13];
		out->bis_handles = (out->num_bis > 0) ? p + 14 : NULL;
		return (0);

	case NG_HCI_LEEV_BIG_SYNC_LOST:		/* 0x1e, 7.7.65.30 */
		/* ng_hci_le_big_sync_lost_ep: big_handle(1) reason(1) */
		if (avail != sizeof(ng_hci_le_big_sync_lost_ep))
			return (-1);
		out->big_handle = p[0];
		out->reason_code = p[1];
		return (0);

	default:
		/* Not a Power/ISO subevent: caller decodes it elsewhere. */
		return (1);
	}
}

#endif /* _BLUED_LE_META_H_ */
