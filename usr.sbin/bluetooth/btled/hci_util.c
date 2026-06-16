/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * HCI utility functions for btled.
 *
 * Wraps libbluetooth's bt_dev* API for BLE scanning, local address
 * retrieval, and connection handle lookup.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ble_util.h"
#include "hci_log.h"
#include "hci_util.h"

/* AD type codes for advertising data parsing */
#define AD_TYPE_FLAGS			0x01
#define AD_TYPE_UUID16_INCOMPLETE	0x02
#define AD_TYPE_UUID16_COMPLETE		0x03
#define AD_TYPE_SHORT_LOCAL_NAME		0x08
#define AD_TYPE_COMPLETE_LOCAL_NAME	0x09

/*
 * Open and bind a raw HCI socket to the named adapter.
 * adapter is e.g. "ubt0".  Returns fd or -1.
 */
int
hci_open(const char *adapter)
{
	return (bt_devopen(adapter));
}

/*
 * Read the local adapter's BD_ADDR.
 */
int
hci_get_bdaddr(int hci_fd, uint8_t *bdaddr)
{
	struct bt_devreq r;
	ng_hci_read_bdaddr_rp rp;
	int n;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_INFO,
	    NG_HCI_OCF_READ_BDADDR);
	r.cparam = NULL;
	r.clen = 0;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	n = bt_devreq(hci_fd, &r, 5);
	if (n < 0)
		return (-1);

	if (rp.status != 0) {
		errno = EIO;
		return (-1);
	}

	memcpy(bdaddr, &rp.bdaddr, 6);
	return (0);
}

/*
 * Find the HCI connection handle for a connected remote device.
 * Uses SIOC_HCI_RAW_NODE_GET_CON_LIST ioctl.
 */
int
hci_get_con_handle(int hci_fd, const uint8_t *remote_addr, uint16_t *handle)
{
	struct ng_btsocket_hci_raw_con_list cl;
	ng_hci_node_con_ep cons[16];
	int i;

	memset(&cl, 0, sizeof(cl));
	cl.num_connections = 16;
	cl.connections = cons;

	if (ioctl(hci_fd, SIOC_HCI_RAW_NODE_GET_CON_LIST, &cl) < 0)
		return (-1);

	for (i = 0; (uint32_t)i < cl.num_connections; i++) {
		if ((cons[i].link_type == NG_HCI_LINK_LE_PUBLIC ||
		    cons[i].link_type == NG_HCI_LINK_LE_RANDOM) &&
		    memcmp(&cons[i].bdaddr, remote_addr, 6) == 0) {
			*handle = cons[i].con_handle;
			LOG_HCI(1, "connection handle=%04x",
			    cons[i].con_handle);
			return (0);
		}
	}

	warnx("HCI: connection handle lookup failed");
	errno = ENOENT;
	return (-1);
}

/*
 * Parse a single AD structure from advertising data.
 * Returns pointer past this AD structure, or NULL if malformed.
 */
static const uint8_t *
parse_ad(const uint8_t *data, size_t len, uint8_t *type,
    const uint8_t **value, uint8_t *vlen)
{
	if (len < 2)
		return (NULL);

	uint8_t adlen = data[0];
	if (adlen == 0 || adlen > len - 1)
		return (NULL);

	*type = data[1];
	*value = data + 2;
	*vlen = adlen - 1;

	return (data + 1 + adlen);
}

/*
 * Perform a BLE active scan for the specified duration.
 * Populates results array with discovered devices.
 */
int
hci_le_scan(int hci_fd, int duration_sec,
    struct ble_scan_result *results, int maxresults, int *nresults)
{
	ng_hci_le_set_scan_parameters_cp scan_cp;
	ng_hci_status_rp rp;
	ng_hci_le_set_scan_enable_cp enable_cp;
	struct bt_devreq r;
	struct bt_devfilter flt, oldflt;
	uint8_t buf[512];
	ng_hci_event_pkt_t *evt;
	int count = 0;
	time_t end_time;

	/* Set event filter to receive LE advertising reports */
	memset(&flt, 0, sizeof(flt));
	bt_devfilter_pkt_set(&flt, NG_HCI_EVENT_PKT);
	bt_devfilter_evt_set(&flt, NG_HCI_EVENT_LE);
	bt_devfilter(hci_fd, &flt, &oldflt);

	/* Set scan parameters: active scan, 100ms interval, 50ms window */
	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.le_scan_type = 1;		/* active */
	scan_cp.le_scan_interval = htole16(160);	/* 100ms / 0.625 */
	scan_cp.le_scan_window = htole16(80);	/* 50ms / 0.625 */
	scan_cp.own_address_type = 0;		/* public */
	scan_cp.scanning_filter_policy = 0;	/* accept all */

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_SCAN_PARAMETERS);
	r.cparam = &scan_cp;
	r.clen = sizeof(scan_cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);

	if (rp.status != 0) {
		errno = EIO;
		return (-1);
	}

	/* Enable scanning with duplicate filtering */
	memset(&enable_cp, 0, sizeof(enable_cp));
	enable_cp.le_scan_enable = 1;
	enable_cp.filter_duplicates = 1;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_SCAN_ENABLE);
	r.cparam = &enable_cp;
	r.clen = sizeof(enable_cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);

	if (rp.status != 0) {
		errno = EIO;
		return (-1);
	}

	/* Receive advertising reports */
	end_time = time(NULL) + duration_sec;
	while (time(NULL) < end_time && count < maxresults) {
		ssize_t n;
		int bufsize = sizeof(buf);

		/* bt_devrecv expects int* for size */
		n = bt_devrecv(hci_fd, buf, bufsize, 1);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			break;
		}

		evt = (ng_hci_event_pkt_t *)buf;
		if ((size_t)n < sizeof(*evt))
			continue;

		/* Log raw HCI event to BTSnoop file if enabled */
		if (hci_log_enabled())
			hci_log_packet(HCI_LOG_EVT,
			    buf + 1, (uint16_t)(n - 1), true);

		if (evt->event != NG_HCI_EVENT_LE)
			continue;

		/* Parse LE Meta Event */
		uint8_t *p = (uint8_t *)(evt + 1);
		size_t remain = n - sizeof(*evt);
		if (remain < 1)
			continue;

		uint8_t subevent = p[0];
		p++;
		remain--;

		if (subevent != NG_HCI_LEEV_ADVREP)
			continue;
		if (remain < 1)
			continue;

		uint8_t num_reports = p[0];
		p++;
		remain--;

		for (int i = 0; i < num_reports && count < maxresults; i++) {
			/* event_type(1) + addr_type(1) + addr(6) */
			if (remain < 8)
				break;

			/* skip event_type */
			p++;
			remain--;

			uint8_t addr_type = p[0];
			p++;
			remain--;

			struct ble_scan_result *sr = &results[count];
			memset(sr, 0, sizeof(*sr));
			memcpy(sr->addr, p, 6);
			sr->addr_type = addr_type ? BDADDR_LE_RANDOM :
			    BDADDR_LE_PUBLIC;
			p += 6;
			remain -= 6;

			/* data length(1) + data + rssi(1) */
			if (remain < 1)
				break;
			uint8_t data_len = p[0];
			p++;
			remain--;

			if (remain < data_len)
				break;

			/* Parse AD structures for device name */
			const uint8_t *ad = p;
			size_t ad_remain = data_len;
			while (ad_remain > 0) {
				uint8_t ad_type, vlen;
				const uint8_t *val;
				const uint8_t *next;

				next = parse_ad(ad, ad_remain, &ad_type,
				    &val, &vlen);
				if (next == NULL)
					break;

				if ((ad_type == AD_TYPE_COMPLETE_LOCAL_NAME ||
				    ad_type == AD_TYPE_SHORT_LOCAL_NAME) &&
				    vlen > 0) {
					size_t cplen = vlen;
					if (cplen >= sizeof(sr->name))
						cplen = sizeof(sr->name) - 1;
					memcpy(sr->name, val, cplen);
					sr->name[cplen] = '\0';
					sr->has_name = true;
				}

				ad_remain -= (next - ad);
				ad = next;
			}

			p += data_len;
			remain -= data_len;

			/* RSSI */
			if (remain >= 1) {
				sr->rssi = (int8_t)p[0];
				p++;
				remain--;
			}

			/* Dedup by address */
			bool dup = false;
			for (int j = 0; j < count; j++) {
				if (memcmp(results[j].addr, sr->addr, 6) == 0) {
					/* Update name if we got one */
					if (sr->has_name && !results[j].has_name) {
						strlcpy(results[j].name,
						    sr->name,
						    sizeof(results[j].name));
						results[j].has_name = true;
					}
					dup = true;
					break;
				}
			}
			if (!dup)
				count++;
		}
	}

	/* Disable scanning */
	enable_cp.le_scan_enable = 0;
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_SCAN_ENABLE);
	r.cparam = &enable_cp;
	r.clen = sizeof(enable_cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;
	bt_devreq(hci_fd, &r, 5);

	/* Restore previous event filter */
	bt_devfilter(hci_fd, &oldflt, NULL);

	*nresults = count;
	return (0);
}

/*
 * Wait for HCI Encryption Change event on a given connection handle.
 * Returns 0 on success (encryption enabled), -1 on failure/timeout.
 *
 * This replaces the naive usleep() approach — we actually listen for
 * the controller's confirmation that encryption is active.
 */
int
hci_wait_encryption(int hci_fd, uint16_t con_handle, int timeout_sec)
{
	struct bt_devfilter flt, oldflt;
	uint8_t buf[512];
	ng_hci_event_pkt_t *evt;
	time_t deadline;

	/* Set filter to receive Encryption Change events */
	memset(&flt, 0, sizeof(flt));
	bt_devfilter_pkt_set(&flt, NG_HCI_EVENT_PKT);
	bt_devfilter_evt_set(&flt, NG_HCI_EVENT_ENCRYPTION_CHANGE);
	bt_devfilter_evt_set(&flt, NG_HCI_EVENT_COMMAND_STATUS);
	bt_devfilter(hci_fd, &flt, &oldflt);

	deadline = time(NULL) + timeout_sec;

	while (time(NULL) < deadline) {
		ssize_t n;

		n = bt_devrecv(hci_fd, buf, sizeof(buf), 1);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			break;
		}

		evt = (ng_hci_event_pkt_t *)buf;
		if ((size_t)n < sizeof(*evt))
			continue;

		if (hci_log_enabled())
			hci_log_packet(HCI_LOG_EVT,
			    buf + 1, (uint16_t)(n - 1), true);

		if (evt->event == NG_HCI_EVENT_ENCRYPTION_CHANGE) {
			ng_hci_encryption_change_ep *ep;

			if ((size_t)n < sizeof(*evt) + sizeof(*ep))
				continue;

			ep = (ng_hci_encryption_change_ep *)(evt + 1);
			uint16_t h = le16toh(ep->con_handle) & 0x0FFF;

			if (h == con_handle) {
				/* Restore old filter */
				bt_devfilter(hci_fd, &oldflt, NULL);

				LOG_HCI(1, "encryption change status=%d enable=%d",
				    ep->status, ep->encryption_enable);

				if (ep->status != 0 ||
				    ep->encryption_enable == 0) {
					errno = EACCES;
					return (-1);
				}
				return (0);
			}
		}
	}

	/* Restore old filter */
	bt_devfilter(hci_fd, &oldflt, NULL);
	errno = ETIMEDOUT;
	return (-1);
}

/*
 * LE Set Advertising Parameters.
 * interval_min/max are in units of 0.625ms (e.g. 0x0800 = 1.28s).
 * adv_type: 0x00 = ADV_IND (connectable undirected).
 */
int
hci_le_set_advertising_params(int hci_fd, uint16_t interval_min,
    uint16_t interval_max, uint8_t adv_type)
{
	struct bt_devreq r;
	ng_hci_le_set_advertising_parameters_cp	cp;
	ng_hci_le_set_advertising_parameters_rp	rp;

	memset(&cp, 0, sizeof(cp));
	cp.advertising_interval_min = htole16(interval_min);
	cp.advertising_interval_max = htole16(interval_max);
	cp.advertising_type = adv_type;
	cp.own_address_type = 0x00;		/* public */
	cp.advertising_channel_map = 0x07;	/* all channels */
	cp.advertising_filter_policy = 0x00;	/* any device */

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_ADVERTISING_PARAMETERS);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "set advertising params interval=%d-%d type=%d",
	    interval_min, interval_max, adv_type);

	return (0);
}

/*
 * LE Set Advertising Data.
 * data/len is the raw AD structure payload (max 31 bytes).
 */
int
hci_le_set_advertising_data(int hci_fd, const uint8_t *data, uint8_t len)
{
	struct bt_devreq r;
	ng_hci_le_set_advertising_data_cp	cp;
	ng_hci_le_set_advertising_data_rp	rp;

	if (len > NG_HCI_ADVERTISING_DATA_SIZE) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.advertising_data_length = len;
	memcpy(cp.advertising_data, data, len);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_ADVERTISING_DATA);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

/*
 * LE Set Advertise Enable / Disable.
 */
int
hci_le_set_advertise_enable(int hci_fd, bool enable)
{
	struct bt_devreq r;
	ng_hci_le_set_advertise_enable_cp	cp;
	ng_hci_le_set_advertise_enable_rp	rp;

	memset(&cp, 0, sizeof(cp));
	cp.advertising_enable = enable ? 1 : 0;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_ADVERTISE_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

/*
 * LE Long Term Key Request Reply.
 * Sent by the peripheral/responder when the controller asks for an LTK.
 */
int
hci_le_ltk_request_reply(int hci_fd, uint16_t con_handle,
    const uint8_t ltk[16])
{
	struct bt_devreq r;
	ng_hci_le_long_term_key_request_reply_cp	cp;
	ng_hci_le_long_term_key_request_reply_rp	rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	memcpy(cp.long_term_key, ltk, 16);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_LONG_TERM_KEY_REQUEST_REPLY);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

/*
 * LE Long Term Key Request Negative Reply.
 * Sent when no bond exists for the requesting device.
 */
int
hci_le_ltk_request_neg_reply(int hci_fd, uint16_t con_handle)
{
	struct bt_devreq r;
	ng_hci_le_long_term_key_request_negative_reply_cp	cp;
	ng_hci_le_long_term_key_request_negative_reply_rp	rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

/* ----------------------------------------------------------------
 * HCI Initialization and Feature Detection (Phase 2.5)
 * ---------------------------------------------------------------- */

/*
 * HCI Reset — put controller in known state.
 * Core Spec Vol 4 Part E Section 7.3.2.
 */
int
hci_reset(int hci_fd)
{
	struct bt_devreq r;
	ng_hci_status_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    NG_HCI_OCF_RESET);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00)
		return (-1);
	LOG_HCI(1, "controller reset");
	return (0);
}

/*
 * LE Read Local Supported Features — 8-byte bitmask.
 * Core Spec Vol 4 Part E Section 7.8.3 (OCF 0x0003).
 */
int
hci_le_read_local_features(int hci_fd, uint64_t *features)
{
	struct bt_devreq r;
	ng_hci_le_read_local_supported_features_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_LOCAL_SUPPORTED_FEATURES);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00)
		return (-1);

	*features = le64toh(rp.le_features);

	LOG_HCI(1, "LE features: 0x%016llx",
	    (unsigned long long)*features);
	return (0);
}

/*
 * LE Set Event Mask — enable specific LE sub-events.
 * Core Spec Vol 4 Part E Section 7.8.1 (OCF 0x0001).
 */
int
hci_le_set_event_mask(int hci_fd, uint64_t mask)
{
	struct bt_devreq r;
	ng_hci_le_set_event_mask_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	for (int i = 0; i < 8; i++)
		cp.event_mask[i] = (mask >> (i * 8)) & 0xFF;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EVENT_MASK);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00)
		return (-1);
	LOG_HCI(1, "LE event mask set: 0x%016llx",
	    (unsigned long long)mask);
	return (0);
}

/*
 * LE Connection Update — request new connection parameters.
 * Core Spec Vol 4 Part E Section 7.8.18 (OCF 0x0013).
 * Returns Command Status; result arrives via LE Connection
 * Update Complete event.
 */
int
hci_le_connection_update(int hci_fd, uint16_t handle,
    uint16_t interval_min, uint16_t interval_max,
    uint16_t latency, uint16_t timeout)
{
	struct bt_devreq r;
	ng_hci_le_connection_update_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(handle);
	cp.conn_interval_min = htole16(interval_min);
	cp.conn_interval_max = htole16(interval_max);
	cp.conn_latency = htole16(latency);
	cp.supervision_timeout = htole16(timeout);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CONNECTION_UPDATE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Connection Update failed, status=0x%02x",
		    rp.status);
		return (-1);
	}
	LOG_HCI(1, "connection update requested: interval=%d-%d "
	    "latency=%d timeout=%d",
	    interval_min, interval_max, latency, timeout);
	return (0);
}

/* ----------------------------------------------------------------
 * LE Privacy — Resolving List management
 * Core Spec Vol 4 Part E Sections 7.8.38-7.8.45, 7.8.77
 * ---------------------------------------------------------------- */

int
hci_le_clear_resolving_list(int hci_fd)
{
	struct bt_devreq r;
	ng_hci_status_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CLEAR_RESOLVING_LIST);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Clear Resolving List failed, status=0x%02x",
		    rp.status);
		return (-1);
	}
	LOG_HCI(1, "resolving list cleared");
	return (0);
}

int
hci_le_add_dev_resolving_list(int hci_fd, uint8_t addr_type,
    const uint8_t addr[6], const uint8_t peer_irk[16],
    const uint8_t local_irk[16])
{
	struct bt_devreq r;
	ng_hci_le_add_dev_resolving_list_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.peer_identity_addr_type = addr_type;
	memcpy(&cp.peer_identity_addr, addr, 6);
	memcpy(cp.peer_irk, peer_irk, 16);
	memcpy(cp.local_irk, local_irk, 16);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_ADD_DEV_RESOLVING_LIST);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Add Dev Resolving List failed, status=0x%02x",
		    rp.status);
		return (-1);
	}
	LOG_HCI(1, "added device to resolving list, addr_type=%d", addr_type);
	return (0);
}

int
hci_le_set_addr_resolution_enable(int hci_fd, uint8_t enable)
{
	struct bt_devreq r;
	ng_hci_le_set_addr_resolution_enable_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.enable = enable;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_ADDR_RESOLUTION_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Addr Resolution Enable failed, "
		    "status=0x%02x", rp.status);
		return (-1);
	}
	LOG_HCI(1, "address resolution %s", enable ? "enabled" : "disabled");
	return (0);
}

int
hci_le_set_privacy_mode(int hci_fd, uint8_t addr_type,
    const uint8_t addr[6], uint8_t mode)
{
	struct bt_devreq r;
	ng_hci_le_set_privacy_mode_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.peer_identity_addr_type = addr_type;
	memcpy(&cp.peer_identity_addr, addr, 6);
	cp.privacy_mode = mode;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PRIVACY_MODE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Privacy Mode failed, status=0x%02x",
		    rp.status);
		return (-1);
	}
	return (0);
}

int
hci_le_set_rpa_timeout(int hci_fd, uint16_t timeout_sec)
{
	struct bt_devreq r;
	ng_hci_le_set_rpa_timeout_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.rpa_timeout = htole16(timeout_sec);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_RPA_TIMEOUT);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set RPA Timeout failed, status=0x%02x",
		    rp.status);
		return (-1);
	}
	LOG_HCI(1, "RPA timeout set to %d seconds", timeout_sec);
	return (0);
}

/* ----------------------------------------------------------------
 * LE Extended Advertising
 * Core Spec Vol 4 Part E Sections 7.8.53-7.8.60
 * ---------------------------------------------------------------- */

/*
 * Set Extended Advertising Parameters (v1).
 * Simplified wrapper — sets connectable undirected on all channels,
 * 1M primary PHY, 1M secondary PHY.
 */
int
hci_le_set_ext_adv_params(int hci_fd, uint8_t handle,
    uint16_t event_props, uint16_t interval_min,
    uint16_t interval_max, uint8_t own_addr_type)
{
	struct bt_devreq r;
	ng_hci_le_set_ext_adv_params_cp cp;
	ng_hci_le_set_ext_adv_params_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.advertising_handle = handle;
	cp.advertising_event_properties = htole16(event_props);
	/* 3-byte LE interval fields */
	cp.primary_advertising_interval_min[0] = interval_min & 0xFF;
	cp.primary_advertising_interval_min[1] = (interval_min >> 8) & 0xFF;
	cp.primary_advertising_interval_min[2] = 0;
	cp.primary_advertising_interval_max[0] = interval_max & 0xFF;
	cp.primary_advertising_interval_max[1] = (interval_max >> 8) & 0xFF;
	cp.primary_advertising_interval_max[2] = 0;
	cp.primary_advertising_channel_map = 0x07;	/* all channels */
	cp.own_address_type = own_addr_type;
	cp.advertising_tx_power = 0x7F;			/* no preference */
	cp.primary_advertising_phy = 0x01;		/* 1M */
	cp.secondary_advertising_phy = 0x01;		/* 1M */

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_ADV_PARAMS);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Ext Adv Params failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "ext adv params set: handle=%d tx_power=%d",
	    handle, rp.selected_tx_power);
	return (0);
}

/*
 * Set Extended Advertising Data (complete, single operation).
 * data can be up to 251 bytes.
 */
int
hci_le_set_ext_adv_data(int hci_fd, uint8_t handle,
    const uint8_t *data, uint8_t len)
{
	struct bt_devreq r;
	ng_hci_le_set_ext_adv_data_cp cp;
	ng_hci_status_rp rp;

	if (len > NG_HCI_LE_EXT_ADV_DATA_MAX) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.advertising_handle = handle;
	cp.operation = 0x03;		/* complete data */
	cp.fragment_preference = 0x01;	/* don't fragment */
	cp.advertising_data_length = len;
	memcpy(cp.advertising_data, data, len);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_ADV_DATA);
	r.cparam = &cp;
	/* Only send the actual data, not the full 251-byte buffer */
	r.clen = 4 + len;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Ext Adv Data failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	return (0);
}

/*
 * Enable/disable a single extended advertising set.
 */
int
hci_le_set_ext_adv_enable(int hci_fd, uint8_t enable, uint8_t handle)
{
	struct bt_devreq r;
	uint8_t cp[6]; /* enable(1) + num_sets(1) + handle(1) + duration(2) + max_events(1) */
	ng_hci_status_rp rp;

	memset(cp, 0, sizeof(cp));
	cp[0] = enable;
	if (enable) {
		cp[1] = 1;		/* num_sets */
		cp[2] = handle;
		/* duration=0 (indefinite), max_events=0 (unlimited) */
	} else {
		cp[1] = 0;		/* num_sets=0 disables all */
	}

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_ADV_ENABLE);
	r.cparam = cp;
	r.clen = enable ? 6 : 2;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Ext Adv Enable failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "ext advertising %s, handle=%d",
	    enable ? "enabled" : "disabled", handle);
	return (0);
}

int
hci_le_remove_adv_set(int hci_fd, uint8_t handle)
{
	struct bt_devreq r;
	ng_hci_le_remove_adv_set_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.advertising_handle = handle;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_REMOVE_ADV_SET);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00)
		return (-1);
	return (0);
}

/*
 * LE Set Data Length — request maximum link-layer PDU size for a
 * connection.  tx_octets: 0x001B-0x00FB, tx_time: 0x0148-0x4290.
 * Core Spec Vol 4 Part E Section 7.8.33 (OCF 0x0022).
 */
int
hci_le_set_data_length(int hci_fd, uint16_t con_handle,
    uint16_t tx_octets, uint16_t tx_time)
{
	struct bt_devreq r;
	ng_hci_le_set_data_length_cp cp;
	ng_hci_le_set_data_length_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.tx_octets = htole16(tx_octets);
	cp.tx_time = htole16(tx_time);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_DATA_LENGTH);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Data Length failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "LE data length set: tx_octets=%d tx_time=%d",
	    tx_octets, tx_time);
	return (0);
}

/*
 * LE Write Suggested Default Data Length — set defaults for new
 * connections.  Core Spec Vol 4 Part E Section 7.8.35 (OCF 0x0024).
 */
int
hci_le_write_suggested_default_data_length(int hci_fd,
    uint16_t tx_octets, uint16_t tx_time)
{
	struct bt_devreq r;
	ng_hci_le_write_suggested_data_length_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.suggested_max_tx_octets = htole16(tx_octets);
	cp.suggested_max_tx_time = htole16(tx_time);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_WRITE_SUGGESTED_DATA_LENGTH);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Write Suggested Default Data Length failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "LE default data length set: tx_octets=%d tx_time=%d",
	    tx_octets, tx_time);
	return (0);
}

/*
 * LE Set Default PHY — set preferred PHY for future connections.
 * Core Spec Vol 4 Part E Section 7.8.48 (OCF 0x0031).
 */
int
hci_le_set_default_phy(int hci_fd, uint8_t all_phys,
    uint8_t tx_phys, uint8_t rx_phys)
{
	struct bt_devreq r;
	ng_hci_le_set_default_phy_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.all_phys = all_phys;
	cp.tx_phys = tx_phys;
	cp.rx_phys = rx_phys;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_DEFAULT_PHY);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Default PHY failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "LE default PHY set: all=%02x tx=%02x rx=%02x",
	    all_phys, tx_phys, rx_phys);
	return (0);
}

/*
 * LE Set PHY — request PHY change on an active connection.
 * Returns Command Status (not Complete).  PHY change result
 * arrives later as LE PHY Update Complete event (subevent 0x0C).
 * Core Spec Vol 4 Part E Section 7.8.49 (OCF 0x0032).
 */
int
hci_le_set_phy(int hci_fd, uint16_t con_handle, uint8_t all_phys,
    uint8_t tx_phys, uint8_t rx_phys, uint16_t phy_options)
{
	struct bt_devreq r;
	ng_hci_le_set_phy_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.all_phys = all_phys;
	cp.tx_phys = tx_phys;
	cp.rx_phys = rx_phys;
	cp.phy_options = htole16(phy_options);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PHY);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set PHY failed, status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "LE PHY change requested: tx=%02x rx=%02x",
	    tx_phys, rx_phys);
	return (0);
}

/*
 * LE Read PHY — read current TX/RX PHY for a connection.
 * Core Spec Vol 4 Part E Section 7.8.47 (OCF 0x0030).
 */
int
hci_le_read_phy(int hci_fd, uint16_t con_handle,
    uint8_t *tx_phy, uint8_t *rx_phy)
{
	struct bt_devreq r;
	ng_hci_le_read_phy_cp cp;
	ng_hci_le_read_phy_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_PHY);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Read PHY failed, status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}

	if (tx_phy != NULL)
		*tx_phy = rp.tx_phy;
	if (rx_phy != NULL)
		*rx_phy = rp.rx_phy;

	LOG_HCI(1, "LE PHY: tx=%d rx=%d", rp.tx_phy, rp.rx_phy);
	return (0);
}

/* ----------------------------------------------------------------
 * LE Filter Accept List management
 * Core Spec Vol 4 Part E Sections 7.8.14-7.8.17
 * (ng_hci.h uses pre-5.3 "White List" naming)
 * ---------------------------------------------------------------- */

/*
 * LE Clear Filter Accept List — remove all entries.
 * Core Spec Vol 4 Part E Section 7.8.15 (OCF 0x0010).
 */
int
hci_le_clear_filter_accept_list(int hci_fd)
{
	struct bt_devreq r;
	ng_hci_status_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CLEAR_WHITE_LIST);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Clear Filter Accept List failed, "
		    "status=0x%02x", rp.status);
		return (-1);
	}
	LOG_HCI(1, "filter accept list cleared");
	return (0);
}

/*
 * LE Add Device To Filter Accept List.
 * Core Spec Vol 4 Part E Section 7.8.16 (OCF 0x0011).
 * addr_type: 0x00 = public, 0x01 = random.
 */
int
hci_le_add_device_to_filter_accept_list(int hci_fd, uint8_t addr_type,
    const uint8_t addr[6])
{
	struct bt_devreq r;
	ng_hci_le_add_device_to_white_list_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.address_type = addr_type;
	memcpy(&cp.address, addr, 6);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_ADD_DEVICE_TO_WHITE_LIST);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Add Device To Filter Accept List failed, "
		    "status=0x%02x", rp.status);
		return (-1);
	}
	LOG_HCI(1, "added device to filter accept list, addr_type=%d",
	    addr_type);
	return (0);
}

/*
 * LE Remove Device From Filter Accept List.
 * Core Spec Vol 4 Part E Section 7.8.17 (OCF 0x0012).
 */
int
hci_le_remove_device_from_filter_accept_list(int hci_fd, uint8_t addr_type,
    const uint8_t addr[6])
{
	struct bt_devreq r;
	ng_hci_le_remove_device_from_white_list_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.address_type = addr_type;
	memcpy(&cp.address, addr, 6);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_REMOVE_DEVICE_FROM_WHITE_LIST);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Remove Device From Filter Accept List failed, "
		    "status=0x%02x", rp.status);
		return (-1);
	}
	LOG_HCI(1, "removed device from filter accept list, addr_type=%d",
	    addr_type);
	return (0);
}

/* ----------------------------------------------------------------
 * LE Set Host Feature / Create Connection Cancel
 * ---------------------------------------------------------------- */

/*
 * LE Set Host Feature — announce host-side feature support to
 * the controller.  Core Spec Vol 4 Part E Section 7.8.115 (OCF 0x0074).
 * bit_number: feature bit index, bit_value: 0=disable, 1=enable.
 */
int
hci_le_set_host_feature(int hci_fd, uint8_t bit_number, uint8_t bit_value)
{
	struct bt_devreq r;
	ng_hci_le_set_host_feature_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.bit_number = bit_number;
	cp.bit_value = bit_value;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_HOST_FEATURE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Host Feature failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "LE host feature bit %d set to %d", bit_number, bit_value);
	return (0);
}

/*
 * LE Create Connection Cancel — abort a pending LE connection attempt.
 * Core Spec Vol 4 Part E Section 7.8.13 (OCF 0x000E).
 * No parameters.  Returns status only.
 */
int
hci_le_create_connection_cancel(int hci_fd)
{
	struct bt_devreq r;
	ng_hci_status_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CREATE_CONNECTION_CANCEL);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Create Connection Cancel failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "LE connection creation cancelled");
	return (0);
}

/*
 * Build BLE advertising data with Flags, Local Name, and 16-bit UUID list.
 * Returns the number of bytes written, or -1 on error.
 */
int
ble_build_adv_data(uint8_t *buf, size_t buflen, const char *name,
    const uint16_t *uuids, int nuuids)
{
	uint8_t *p = buf;
	size_t namelen;

	if (buflen < 3)
		return (-1);

	/* Flags: LE General Discoverable + BR/EDR Not Supported */
	*p++ = 2;		/* length */
	*p++ = AD_TYPE_FLAGS;
	*p++ = 0x06;

	/* Local Name */
	if (name != NULL) {
		size_t fulllen = strlen(name);
		uint8_t name_type;

		namelen = fulllen;
		if ((size_t)(p - buf) + 2 + namelen > buflen) {
			if ((size_t)(p - buf) + 2 >= buflen)
				namelen = 0;
			else
				namelen = buflen - (p - buf) - 2;
		}

		/* Use Shortened Local Name if truncated */
		name_type = (namelen < fulllen) ?
		    AD_TYPE_SHORT_LOCAL_NAME : AD_TYPE_COMPLETE_LOCAL_NAME;

		if (namelen > 0) {
			*p++ = (uint8_t)(1 + namelen);
			*p++ = name_type;
			memcpy(p, name, namelen);
			p += namelen;
		}
	}

	/* 16-bit UUID list */
	if (nuuids > 0 && (size_t)(p - buf) + 2 + 2 * nuuids <= buflen) {
		*p++ = (uint8_t)(1 + 2 * nuuids);
		*p++ = AD_TYPE_UUID16_COMPLETE;
		for (int i = 0; i < nuuids; i++) {
			*p++ = (uint8_t)(uuids[i] & 0xFF);
			*p++ = (uint8_t)(uuids[i] >> 8);
		}
	}

	return ((int)(p - buf));
}

/* ----------------------------------------------------------------
 * LE Extended Scanning (Phase 4)
 * Core Spec Vol 4 Part E Sections 7.8.64-7.8.65
 *
 * Extended scanning uses OCF 0x0041 (Set Extended Scan Parameters)
 * and OCF 0x0042 (Set Extended Scan Enable).  It receives both
 * legacy (subevent 0x02) and extended (subevent 0x0D) advertising
 * reports, so it works with both BT 4.x and 5.x advertisers.
 * ---------------------------------------------------------------- */

/*
 * Parse a single extended advertising report from raw event data.
 * Returns bytes consumed, or 0 on error.
 *
 * Extended Advertising Report format per Core Spec 7.7.65.13:
 *   event_type(2) + addr_type(1) + addr(6) + primary_phy(1) +
 *   secondary_phy(1) + advertising_sid(1) + tx_power(1) + rssi(1) +
 *   periodic_adv_interval(2) + direct_addr_type(1) + direct_addr(6) +
 *   data_length(1) + data[data_length]
 *
 * Total fixed header: 24 bytes before variable data.
 */
#define EXT_ADV_REPORT_HDR_LEN	24

static size_t
parse_ext_adv_report(const uint8_t *p, size_t remain,
    struct ble_scan_result *sr)
{
	uint8_t addr_type, data_len;
	int8_t rssi;

	if (remain < EXT_ADV_REPORT_HDR_LEN)
		return (0);

	/* Skip event_type (2 bytes) */
	addr_type = p[2];
	memcpy(sr->addr, p + 3, 6);
	sr->addr_type = (addr_type == 0x01 || addr_type == 0x03) ?
	    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
	/* p[9]: primary_phy, p[10]: secondary_phy, p[11]: advertising_sid */
	/* p[12]: tx_power */
	rssi = (int8_t)p[13];
	sr->rssi = rssi;
	/* p[14..15]: periodic_adv_interval */
	/* p[16]: direct_addr_type, p[17..22]: direct_addr */
	data_len = p[23];

	if (remain < (size_t)(EXT_ADV_REPORT_HDR_LEN + data_len))
		return (0);

	/* Parse AD structures for device name */
	sr->has_name = false;
	sr->name[0] = '\0';

	const uint8_t *ad = p + EXT_ADV_REPORT_HDR_LEN;
	size_t ad_remain = data_len;
	while (ad_remain > 0) {
		uint8_t ad_type, vlen;
		const uint8_t *val;
		const uint8_t *next;

		next = parse_ad(ad, ad_remain, &ad_type, &val, &vlen);
		if (next == NULL)
			break;

		if ((ad_type == AD_TYPE_COMPLETE_LOCAL_NAME ||
		    ad_type == AD_TYPE_SHORT_LOCAL_NAME) &&
		    vlen > 0) {
			size_t cplen = vlen;
			if (cplen >= sizeof(sr->name))
				cplen = sizeof(sr->name) - 1;
			memcpy(sr->name, val, cplen);
			sr->name[cplen] = '\0';
			sr->has_name = true;
		}

		ad_remain -= (size_t)(next - ad);
		ad = next;
	}

	return ((size_t)(EXT_ADV_REPORT_HDR_LEN + data_len));
}

/*
 * Perform a BLE extended active scan for the specified duration.
 *
 * Uses the HCI LE Extended Scan commands (BT 5.0+).
 * Scans on 1M PHY only, with active scanning, 100ms interval,
 * 50ms window.  Receives both legacy (subevent 0x02) and
 * extended (subevent 0x0D) advertising reports.
 *
 * Returns 0 on success, -1 on failure.
 */
int
hci_le_ext_scan(int hci_fd, int duration_sec,
    struct ble_scan_result *results, int maxresults, int *nresults)
{
	struct bt_devreq r;
	ng_hci_status_rp rp;
	ng_hci_le_set_ext_scan_enable_cp enable_cp;
	struct bt_devfilter flt, oldflt;
	uint8_t buf[512];
	ng_hci_event_pkt_t *evt;
	int count = 0;
	time_t end_time;

	/*
	 * Set Extended Scan Parameters (OCF 0x0041).
	 * Uses the 1-PHY struct (scanning_phys = 0x01 for 1M only).
	 */
	{
		ng_hci_le_set_ext_scan_params_cp scan_cp;

		memset(&scan_cp, 0, sizeof(scan_cp));
		scan_cp.own_address_type = 0x00;	/* public */
		scan_cp.scanning_filter_policy = 0x00;	/* accept all */
		scan_cp.scanning_phys = 0x01;		/* 1M only */
		scan_cp.scan_type = 0x01;		/* active */
		scan_cp.scan_interval = htole16(160);	/* 100ms / 0.625 */
		scan_cp.scan_window = htole16(80);	/* 50ms / 0.625 */

		memset(&r, 0, sizeof(r));
		r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
		    NG_HCI_OCF_LE_SET_EXT_SCAN_PARAMS);
		r.cparam = &scan_cp;
		r.clen = sizeof(scan_cp);
		r.rparam = &rp;
		r.rlen = sizeof(rp);
		r.event = NG_HCI_EVENT_COMMAND_COMPL;

		if (bt_devreq(hci_fd, &r, 5) < 0)
			return (-1);
		if (rp.status != 0) {
			LOG_HCI(1, "LE Set Ext Scan Params failed, "
			    "status=0x%02x", rp.status);
			errno = EIO;
			return (-1);
		}
	}

	/* Set event filter to receive LE events */
	memset(&flt, 0, sizeof(flt));
	bt_devfilter_pkt_set(&flt, NG_HCI_EVENT_PKT);
	bt_devfilter_evt_set(&flt, NG_HCI_EVENT_LE);
	bt_devfilter(hci_fd, &flt, &oldflt);

	/*
	 * Enable extended scanning (OCF 0x0042).
	 * Duration = 0 means scan until explicitly disabled.
	 * We manage the duration ourselves with a time-based loop.
	 */
	memset(&enable_cp, 0, sizeof(enable_cp));
	enable_cp.enable = 1;
	enable_cp.filter_duplicates = 1;
	enable_cp.duration = 0;		/* we manage duration */
	enable_cp.period = 0;		/* scan continuously */

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_SCAN_ENABLE);
	r.cparam = &enable_cp;
	r.clen = sizeof(enable_cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0) {
		bt_devfilter(hci_fd, &oldflt, NULL);
		return (-1);
	}
	if (rp.status != 0) {
		LOG_HCI(1, "LE Set Ext Scan Enable failed, status=0x%02x",
		    rp.status);
		bt_devfilter(hci_fd, &oldflt, NULL);
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "extended scan started (%d seconds)", duration_sec);

	/* Receive advertising reports (both legacy and extended) */
	end_time = time(NULL) + duration_sec;
	while (time(NULL) < end_time && count < maxresults) {
		ssize_t n;

		n = bt_devrecv(hci_fd, buf, sizeof(buf), 1);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			break;
		}

		evt = (ng_hci_event_pkt_t *)buf;
		if ((size_t)n < sizeof(*evt))
			continue;

		/* Log raw HCI event to BTSnoop file if enabled */
		if (hci_log_enabled())
			hci_log_packet(HCI_LOG_EVT,
			    buf + 1, (uint16_t)(n - 1), true);

		if (evt->event != NG_HCI_EVENT_LE)
			continue;

		/* Parse LE Meta Event */
		uint8_t *p = (uint8_t *)(evt + 1);
		size_t remain = n - sizeof(*evt);
		if (remain < 1)
			continue;

		uint8_t subevent = p[0];
		p++;
		remain--;

		if (subevent == NG_HCI_LEEV_ADVREP) {
			/*
			 * Legacy advertising report (subevent 0x02).
			 * Same format as in hci_le_scan().
			 */
			if (remain < 1)
				continue;

			uint8_t num_reports = p[0];
			p++;
			remain--;

			for (int i = 0; i < num_reports &&
			    count < maxresults; i++) {
				if (remain < 8)
					break;

				/* skip event_type */
				p++;
				remain--;

				uint8_t addr_type = p[0];
				p++;
				remain--;

				struct ble_scan_result *sr = &results[count];
				memset(sr, 0, sizeof(*sr));
				memcpy(sr->addr, p, 6);
				sr->addr_type = addr_type ?
				    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
				p += 6;
				remain -= 6;

				if (remain < 1)
					break;
				uint8_t data_len = p[0];
				p++;
				remain--;

				if (remain < data_len)
					break;

				/* Parse AD structures for device name */
				const uint8_t *ad = p;
				size_t ad_remain = data_len;
				while (ad_remain > 0) {
					uint8_t ad_type, vlen;
					const uint8_t *val;
					const uint8_t *next;

					next = parse_ad(ad, ad_remain,
					    &ad_type, &val, &vlen);
					if (next == NULL)
						break;

					if ((ad_type ==
					    AD_TYPE_COMPLETE_LOCAL_NAME ||
					    ad_type ==
					    AD_TYPE_SHORT_LOCAL_NAME) &&
					    vlen > 0) {
						size_t cplen = vlen;
						if (cplen >=
						    sizeof(sr->name))
							cplen =
							    sizeof(sr->name)
							    - 1;
						memcpy(sr->name, val,
						    cplen);
						sr->name[cplen] = '\0';
						sr->has_name = true;
					}

					ad_remain -= (size_t)(next - ad);
					ad = next;
				}

				p += data_len;
				remain -= data_len;

				if (remain >= 1) {
					sr->rssi = (int8_t)p[0];
					p++;
					remain--;
				}

				/* Dedup by address */
				bool dup = false;
				for (int j = 0; j < count; j++) {
					if (memcmp(results[j].addr,
					    sr->addr, 6) == 0) {
						if (sr->has_name &&
						    !results[j].has_name) {
							strlcpy(
							    results[j].name,
							    sr->name,
							    sizeof(
							    results[j].name));
							results[j].has_name
							    = true;
						}
						dup = true;
						break;
					}
				}
				if (!dup)
					count++;
			}
		} else if (subevent == NG_HCI_LEEV_EXT_ADVREP) {
			/*
			 * Extended advertising report (subevent 0x0D).
			 * Format: num_reports(1) + report[num_reports].
			 */
			if (remain < 1)
				continue;

			uint8_t num_reports = p[0];
			p++;
			remain--;

			for (int i = 0; i < num_reports &&
			    count < maxresults; i++) {
				struct ble_scan_result sr;
				size_t consumed;

				memset(&sr, 0, sizeof(sr));
				consumed = parse_ext_adv_report(p, remain,
				    &sr);
				if (consumed == 0)
					break;

				p += consumed;
				remain -= consumed;

				/* Dedup by address */
				bool dup = false;
				for (int j = 0; j < count; j++) {
					if (memcmp(results[j].addr,
					    sr.addr, 6) == 0) {
						if (sr.has_name &&
						    !results[j].has_name) {
							strlcpy(
							    results[j].name,
							    sr.name,
							    sizeof(
							    results[j].name));
							results[j].has_name
							    = true;
						}
						dup = true;
						break;
					}
				}
				if (!dup)
					results[count++] = sr;
			}
		}
	}

	/* Disable extended scanning */
	memset(&enable_cp, 0, sizeof(enable_cp));
	enable_cp.enable = 0;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_SCAN_ENABLE);
	r.cparam = &enable_cp;
	r.clen = sizeof(enable_cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;
	bt_devreq(hci_fd, &r, 5);

	/* Restore previous event filter */
	bt_devfilter(hci_fd, &oldflt, NULL);

	LOG_HCI(1, "extended scan complete, %d device(s) found", count);

	*nresults = count;
	return (0);
}

/* ----------------------------------------------------------------
 * LE ISO Channels (BT 5.2)
 * Core Spec Vol 4 Part E Sections 7.8.96-7.8.116
 * ---------------------------------------------------------------- */

/*
 * LE Read Buffer Size v2 — query ACL and ISO buffer sizes.
 * Core Spec Vol 4 Part E Section 7.8.2 (OCF 0x0060).
 */
int
hci_le_read_buffer_size_v2(int hci_fd, uint16_t *acl_len, uint8_t *acl_num,
    uint16_t *iso_len, uint8_t *iso_num)
{
	struct bt_devreq r;
	ng_hci_le_read_buffer_size_rp_v2 rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_BUFFER_SIZE_V2);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		errno = EIO;
		return (-1);
	}

	if (acl_len != NULL)
		*acl_len = le16toh(rp.hc_le_data_packet_length);
	if (acl_num != NULL)
		*acl_num = rp.hc_total_num_le_data_packets;
	if (iso_len != NULL)
		*iso_len = le16toh(rp.hc_iso_data_packet_length);
	if (iso_num != NULL)
		*iso_num = rp.hc_total_num_iso_data_packets;

	LOG_HCI(1, "LE buffer size v2: acl_len=%d acl_num=%d "
	    "iso_len=%d iso_num=%d",
	    le16toh(rp.hc_le_data_packet_length),
	    rp.hc_total_num_le_data_packets,
	    le16toh(rp.hc_iso_data_packet_length),
	    rp.hc_total_num_iso_data_packets);
	return (0);
}

/*
 * LE Read ISO TX Sync — read packet sequence number and timestamps
 * for an ISO stream.
 * Core Spec Vol 4 Part E Section 7.8.96 (OCF 0x0061).
 */
int
hci_le_read_iso_tx_sync(int hci_fd, uint16_t con_handle,
    uint16_t *packet_seq, uint32_t *timestamp, uint32_t *offset)
{
	struct bt_devreq r;
	ng_hci_le_read_iso_tx_sync_cp cp;
	ng_hci_le_read_iso_tx_sync_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_ISO_TX_SYNC);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		errno = EIO;
		return (-1);
	}

	if (packet_seq != NULL)
		*packet_seq = le16toh(rp.packet_sequence_number);
	if (timestamp != NULL)
		*timestamp = le32toh(rp.tx_time_stamp);
	if (offset != NULL) {
		/* 3-byte little-endian time_offset */
		*offset = (uint32_t)rp.time_offset[0] |
		    ((uint32_t)rp.time_offset[1] << 8) |
		    ((uint32_t)rp.time_offset[2] << 16);
	}

	LOG_HCI(1, "ISO TX sync: handle=%04x seq=%d ts=%u offset=%u",
	    con_handle,
	    le16toh(rp.packet_sequence_number),
	    le32toh(rp.tx_time_stamp),
	    (uint32_t)rp.time_offset[0] |
	    ((uint32_t)rp.time_offset[1] << 8) |
	    ((uint32_t)rp.time_offset[2] << 16));
	return (0);
}

/*
 * LE Set CIG Parameters — configure a Connected Isochronous Group.
 * Variable-length command: fixed 15-byte header + per-CIS params.
 * Core Spec Vol 4 Part E Section 7.8.97 (OCF 0x0062).
 *
 * cis_params/cis_params_len: raw per-CIS parameter bytes (9 bytes each:
 *   CIS_ID(1)+Max_SDU_C_To_P(2)+Max_SDU_P_To_C(2)+PHY_C_To_P(1)+
 *   PHY_P_To_C(1)+RTN_C_To_P(1)+RTN_P_To_C(1)).
 *
 * On success, out_cig_id, out_cis_count, and out_cis_handles are filled
 * from the return parameters.
 */
int
hci_le_set_cig_params(int hci_fd, uint8_t cig_id,
    uint32_t sdu_interval_c, uint32_t sdu_interval_p,
    uint8_t worst_case_sca, uint8_t packing, uint8_t framing,
    uint16_t max_transport_latency_c, uint16_t max_transport_latency_p,
    uint8_t cis_count, const void *cis_params, size_t cis_params_len,
    uint8_t *out_cig_id, uint8_t *out_cis_count, uint16_t *out_cis_handles)
{
	struct bt_devreq r;
	uint8_t cmd[256];	/* 15-byte header + up to 31 CIS * 9 bytes */
	uint8_t rpbuf[64];	/* status(1)+cig_id(1)+cis_count(1)+handles(2*n) */
	size_t cmdlen;

	/* Build the fixed 15-byte header */
	cmdlen = 15 + cis_params_len;
	if (cmdlen > sizeof(cmd)) {
		errno = EINVAL;
		return (-1);
	}

	memset(cmd, 0, sizeof(cmd));
	cmd[0] = cig_id;
	/* SDU_Interval_C_To_P: 3 bytes LE */
	cmd[1] = sdu_interval_c & 0xFF;
	cmd[2] = (sdu_interval_c >> 8) & 0xFF;
	cmd[3] = (sdu_interval_c >> 16) & 0xFF;
	/* SDU_Interval_P_To_C: 3 bytes LE */
	cmd[4] = sdu_interval_p & 0xFF;
	cmd[5] = (sdu_interval_p >> 8) & 0xFF;
	cmd[6] = (sdu_interval_p >> 16) & 0xFF;
	cmd[7] = worst_case_sca;
	cmd[8] = packing;
	cmd[9] = framing;
	cmd[10] = max_transport_latency_c & 0xFF;
	cmd[11] = (max_transport_latency_c >> 8) & 0xFF;
	cmd[12] = max_transport_latency_p & 0xFF;
	cmd[13] = (max_transport_latency_p >> 8) & 0xFF;
	cmd[14] = cis_count;
	if (cis_params_len > 0)
		memcpy(cmd + 15, cis_params, cis_params_len);

	memset(rpbuf, 0, sizeof(rpbuf));
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_CIG_PARAMS);
	r.cparam = cmd;
	r.clen = cmdlen;
	r.rparam = rpbuf;
	r.rlen = sizeof(rpbuf);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rpbuf[0] != 0x00) {
		LOG_HCI(1, "LE Set CIG Params failed, status=0x%02x",
		    rpbuf[0]);
		errno = EIO;
		return (-1);
	}

	/* Return parameters: status(1)+CIG_ID(1)+CIS_Count(1)+handles(2*n) */
	if (out_cig_id != NULL)
		*out_cig_id = rpbuf[1];
	if (out_cis_count != NULL)
		*out_cis_count = rpbuf[2];
	if (out_cis_handles != NULL) {
		uint8_t n = rpbuf[2];
		for (uint8_t i = 0; i < n; i++) {
			memcpy(&out_cis_handles[i], rpbuf + 3 + i * 2, 2);
			out_cis_handles[i] = le16toh(out_cis_handles[i]);
		}
	}

	LOG_HCI(1, "CIG params set: cig_id=%d cis_count=%d",
	    rpbuf[1], rpbuf[2]);
	return (0);
}

/*
 * LE Create CIS — establish one or more Connected Isochronous Streams.
 * Variable-length command: CIS_Count(1) + [CIS_Handle(2)+ACL_Handle(2)]*n.
 * Returns Command_Status; completion arrives via LE CIS Established event.
 * Core Spec Vol 4 Part E Section 7.8.99 (OCF 0x0064).
 */
int
hci_le_create_cis(int hci_fd, uint8_t cis_count,
    const uint16_t *cis_handles, const uint16_t *acl_handles)
{
	struct bt_devreq r;
	uint8_t cmd[1 + 31 * 4];	/* count + up to 31 pairs */
	ng_hci_status_rp rp;
	size_t cmdlen;

	if (cis_count == 0 || cis_count > 31) {
		errno = EINVAL;
		return (-1);
	}

	cmdlen = 1 + cis_count * 4;
	memset(cmd, 0, cmdlen);
	cmd[0] = cis_count;
	for (uint8_t i = 0; i < cis_count; i++) {
		uint16_t ch = htole16(cis_handles[i]);
		uint16_t ah = htole16(acl_handles[i]);
		memcpy(cmd + 1 + i * 4, &ch, 2);
		memcpy(cmd + 1 + i * 4 + 2, &ah, 2);
	}

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CREATE_CIS);
	r.cparam = cmd;
	r.clen = cmdlen;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Create CIS failed, status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "LE Create CIS requested, count=%d", cis_count);
	return (0);
}

/*
 * LE Remove CIG — remove a Connected Isochronous Group and all its CISes.
 * Core Spec Vol 4 Part E Section 7.8.100 (OCF 0x0065).
 */
int
hci_le_remove_cig(int hci_fd, uint8_t cig_id)
{
	struct bt_devreq r;
	ng_hci_le_remove_cig_cp cp;
	ng_hci_le_remove_cig_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.cig_id = cig_id;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_REMOVE_CIG);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Remove CIG failed, status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "CIG removed: cig_id=%d", cig_id);
	return (0);
}

/*
 * LE Accept CIS Request — accept an incoming CIS connection.
 * Returns Command_Status; completion arrives via LE CIS Established event.
 * Core Spec Vol 4 Part E Section 7.8.101 (OCF 0x0066).
 */
int
hci_le_accept_cis_request(int hci_fd, uint16_t con_handle)
{
	struct bt_devreq r;
	ng_hci_le_accept_cis_request_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_ACCEPT_CIS_REQUEST);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Accept CIS Request failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "CIS request accepted: handle=%04x", con_handle);
	return (0);
}

/*
 * LE Reject CIS Request — reject an incoming CIS connection.
 * Core Spec Vol 4 Part E Section 7.8.102 (OCF 0x0067).
 */
int
hci_le_reject_cis_request(int hci_fd, uint16_t con_handle, uint8_t reason)
{
	struct bt_devreq r;
	ng_hci_le_reject_cis_request_cp cp;
	ng_hci_le_reject_cis_request_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.reason = reason;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_REJECT_CIS_REQUEST);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Reject CIS Request failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "CIS request rejected: handle=%04x reason=0x%02x",
	    con_handle, reason);
	return (0);
}

/*
 * LE Create BIG — create a Broadcast Isochronous Group.
 * Variable-length command built manually (no fixed struct in ng_hci.h).
 * Returns Command_Status; completion arrives via LE Create BIG Complete event.
 * Core Spec Vol 4 Part E Section 7.8.103 (OCF 0x0068).
 */
int
hci_le_create_big(int hci_fd, uint8_t big_handle, uint8_t adv_handle,
    uint8_t num_bis, uint32_t sdu_interval, uint16_t max_sdu,
    uint16_t max_transport_latency, uint8_t rtn, uint8_t phy,
    uint8_t packing, uint8_t framing, uint8_t encryption,
    const uint8_t broadcast_code[16])
{
	struct bt_devreq r;
	uint8_t cmd[31];	/* fixed 31-byte command */
	ng_hci_status_rp rp;

	memset(cmd, 0, sizeof(cmd));
	cmd[0] = big_handle;
	cmd[1] = adv_handle;
	cmd[2] = num_bis;
	/* SDU_Interval: 3 bytes LE */
	cmd[3] = sdu_interval & 0xFF;
	cmd[4] = (sdu_interval >> 8) & 0xFF;
	cmd[5] = (sdu_interval >> 16) & 0xFF;
	/* Max_SDU: 2 bytes LE */
	cmd[6] = max_sdu & 0xFF;
	cmd[7] = (max_sdu >> 8) & 0xFF;
	/* Max_Transport_Latency: 2 bytes LE */
	cmd[8] = max_transport_latency & 0xFF;
	cmd[9] = (max_transport_latency >> 8) & 0xFF;
	cmd[10] = rtn;
	cmd[11] = phy;
	cmd[12] = packing;
	cmd[13] = framing;
	cmd[14] = encryption;
	if (broadcast_code != NULL)
		memcpy(cmd + 15, broadcast_code, 16);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CREATE_BIG);
	r.cparam = cmd;
	r.clen = sizeof(cmd);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Create BIG failed, status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "LE Create BIG requested: big=%d adv=%d num_bis=%d",
	    big_handle, adv_handle, num_bis);
	return (0);
}

/*
 * LE Terminate BIG — terminate a Broadcast Isochronous Group.
 * Returns Command_Status; completion arrives via LE Terminate BIG
 * Complete event.
 * Core Spec Vol 4 Part E Section 7.8.105 (OCF 0x006A).
 */
int
hci_le_terminate_big(int hci_fd, uint8_t big_handle, uint8_t reason)
{
	struct bt_devreq r;
	ng_hci_le_terminate_big_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.big_handle = big_handle;
	cp.reason = reason;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_TERMINATE_BIG);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Terminate BIG failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "LE Terminate BIG requested: big=%d reason=0x%02x",
	    big_handle, reason);
	return (0);
}

/*
 * LE BIG Create Sync — synchronize to a Broadcast Isochronous Group.
 * Variable-length command: fixed 24-byte header + BIS indices.
 * Returns Command_Status; completion arrives via LE BIG Sync
 * Established event.
 * Core Spec Vol 4 Part E Section 7.8.106 (OCF 0x006B).
 */
int
hci_le_big_create_sync(int hci_fd, uint8_t big_handle,
    uint16_t sync_handle, uint8_t encryption,
    const uint8_t broadcast_code[16], uint8_t mse,
    uint16_t big_sync_timeout, uint8_t num_bis,
    const uint8_t *bis_indices)
{
	struct bt_devreq r;
	uint8_t cmd[256];	/* 24-byte header + up to 31 BIS indices */
	ng_hci_status_rp rp;
	size_t cmdlen;

	cmdlen = 24 + num_bis;
	if (cmdlen > sizeof(cmd)) {
		errno = EINVAL;
		return (-1);
	}

	memset(cmd, 0, cmdlen);
	cmd[0] = big_handle;
	/* Sync_Handle: 2 bytes LE */
	cmd[1] = sync_handle & 0xFF;
	cmd[2] = (sync_handle >> 8) & 0xFF;
	cmd[3] = encryption;
	if (broadcast_code != NULL)
		memcpy(cmd + 4, broadcast_code, 16);
	cmd[20] = mse;
	/* BIG_Sync_Timeout: 2 bytes LE */
	cmd[21] = big_sync_timeout & 0xFF;
	cmd[22] = (big_sync_timeout >> 8) & 0xFF;
	cmd[23] = num_bis;
	if (num_bis > 0 && bis_indices != NULL)
		memcpy(cmd + 24, bis_indices, num_bis);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_BIG_CREATE_SYNC);
	r.cparam = cmd;
	r.clen = cmdlen;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE BIG Create Sync failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "LE BIG Create Sync requested: big=%d sync=%04x "
	    "num_bis=%d", big_handle, sync_handle, num_bis);
	return (0);
}

/*
 * LE BIG Terminate Sync — stop synchronizing to a BIG.
 * Core Spec Vol 4 Part E Section 7.8.107 (OCF 0x006C).
 */
int
hci_le_big_terminate_sync(int hci_fd, uint8_t big_handle)
{
	struct bt_devreq r;
	ng_hci_le_big_terminate_sync_cp cp;
	ng_hci_le_big_terminate_sync_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.big_handle = big_handle;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_BIG_TERMINATE_SYNC);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE BIG Terminate Sync failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "BIG sync terminated: big=%d", big_handle);
	return (0);
}

/*
 * LE Setup ISO Data Path — configure the data path for an ISO channel.
 * Variable-length due to codec_config; builds PDU manually.
 * Core Spec Vol 4 Part E Section 7.8.109 (OCF 0x006E).
 */
int
hci_le_setup_iso_data_path(int hci_fd, uint16_t con_handle,
    uint8_t direction, uint8_t path_id, const uint8_t codec_id[5],
    uint32_t controller_delay, uint8_t codec_config_len,
    const uint8_t *codec_config)
{
	struct bt_devreq r;
	/*
	 * Fixed header: connection_handle(2)+direction(1)+path_id(1)+
	 * codec_id(5)+controller_delay(3)+codec_config_len(1) = 13 bytes.
	 * Plus variable codec_config.
	 */
	uint8_t cmd[13 + 255];
	ng_hci_le_setup_iso_data_path_rp rp;
	size_t cmdlen;

	cmdlen = 13 + codec_config_len;
	if (cmdlen > sizeof(cmd)) {
		errno = EINVAL;
		return (-1);
	}

	memset(cmd, 0, cmdlen);
	/* connection_handle: 2 bytes LE */
	cmd[0] = con_handle & 0xFF;
	cmd[1] = (con_handle >> 8) & 0xFF;
	cmd[2] = direction;
	cmd[3] = path_id;
	if (codec_id != NULL)
		memcpy(cmd + 4, codec_id, 5);
	/* controller_delay: 3 bytes LE */
	cmd[9] = controller_delay & 0xFF;
	cmd[10] = (controller_delay >> 8) & 0xFF;
	cmd[11] = (controller_delay >> 16) & 0xFF;
	cmd[12] = codec_config_len;
	if (codec_config_len > 0 && codec_config != NULL)
		memcpy(cmd + 13, codec_config, codec_config_len);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SETUP_ISO_DATA_PATH);
	r.cparam = cmd;
	r.clen = cmdlen;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Setup ISO Data Path failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "ISO data path set: handle=%04x dir=%d path_id=%d",
	    con_handle, direction, path_id);
	return (0);
}

/*
 * LE Remove ISO Data Path — remove the data path for an ISO channel.
 * Core Spec Vol 4 Part E Section 7.8.110 (OCF 0x006F).
 */
int
hci_le_remove_iso_data_path(int hci_fd, uint16_t con_handle,
    uint8_t direction)
{
	struct bt_devreq r;
	ng_hci_le_remove_iso_data_path_cp cp;
	ng_hci_le_remove_iso_data_path_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.data_path_direction = direction;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_REMOVE_ISO_DATA_PATH);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Remove ISO Data Path failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "ISO data path removed: handle=%04x dir=%d",
	    con_handle, direction);
	return (0);
}

/*
 * LE Request Peer SCA — request the peer's Sleep Clock Accuracy.
 * Returns Command_Status; result arrives via LE Request Peer SCA
 * Complete event.
 * Core Spec Vol 4 Part E Section 7.8.108 (OCF 0x006D).
 */
int
hci_le_request_peer_sca(int hci_fd, uint16_t con_handle)
{
	struct bt_devreq r;
	ng_hci_le_request_peer_sca_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_REQUEST_PEER_SCA);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Request Peer SCA failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "LE Request Peer SCA requested: handle=%04x",
	    con_handle);
	return (0);
}

/*
 * LE Read ISO Link Quality — read link quality counters for an
 * ISO channel.
 * Core Spec Vol 4 Part E Section 7.8.116 (OCF 0x0075).
 */
int
hci_le_read_iso_link_quality(int hci_fd, uint16_t con_handle,
    uint32_t *tx_unacked, uint32_t *tx_flushed,
    uint32_t *tx_last_subevent, uint32_t *retransmitted,
    uint32_t *crc_error, uint32_t *rx_unreceived,
    uint32_t *duplicate)
{
	struct bt_devreq r;
	ng_hci_le_read_iso_link_quality_cp cp;
	ng_hci_le_read_iso_link_quality_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_ISO_LINK_QUALITY);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Read ISO Link Quality failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}

	if (tx_unacked != NULL)
		*tx_unacked = le32toh(rp.tx_unacked_packets);
	if (tx_flushed != NULL)
		*tx_flushed = le32toh(rp.tx_flushed_packets);
	if (tx_last_subevent != NULL)
		*tx_last_subevent = le32toh(rp.tx_last_subevent_packets);
	if (retransmitted != NULL)
		*retransmitted = le32toh(rp.retransmitted_packets);
	if (crc_error != NULL)
		*crc_error = le32toh(rp.crc_error_packets);
	if (rx_unreceived != NULL)
		*rx_unreceived = le32toh(rp.rx_unreceived_packets);
	if (duplicate != NULL)
		*duplicate = le32toh(rp.duplicate_packets);

	LOG_HCI(1, "ISO link quality: handle=%04x unacked=%u flushed=%u "
	    "last_sub=%u retrans=%u crc_err=%u unreceived=%u dup=%u",
	    con_handle,
	    le32toh(rp.tx_unacked_packets),
	    le32toh(rp.tx_flushed_packets),
	    le32toh(rp.tx_last_subevent_packets),
	    le32toh(rp.retransmitted_packets),
	    le32toh(rp.crc_error_packets),
	    le32toh(rp.rx_unreceived_packets),
	    le32toh(rp.duplicate_packets));
	return (0);
}

/* ----------------------------------------------------------------
 * LE Periodic Advertising (BT 5.0)
 * Core Spec Vol 4 Part E Sections 7.8.61-7.8.73
 * ---------------------------------------------------------------- */

/*
 * LE Set Periodic Advertising Parameters v1.
 * Core Spec Vol 4 Part E Section 7.8.61 (OCF 0x003E).
 * interval_min/max in units of 1.25ms (range 0x0006-0xFFFF).
 */
int
hci_le_set_periodic_adv_params(int hci_fd, uint8_t handle,
    uint16_t interval_min, uint16_t interval_max, uint16_t properties)
{
	struct bt_devreq r;
	ng_hci_le_set_periodic_adv_params_cp cp;
	ng_hci_le_set_periodic_adv_params_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.advertising_handle = handle;
	cp.periodic_adv_interval_min = htole16(interval_min);
	cp.periodic_adv_interval_max = htole16(interval_max);
	cp.periodic_adv_properties = htole16(properties);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PERIODIC_ADV_PARAMS);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Periodic Adv Params failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic adv params set: handle=%d interval=%d-%d",
	    handle, interval_min, interval_max);
	return (0);
}

/*
 * LE Set Periodic Advertising Data.
 * Core Spec Vol 4 Part E Section 7.8.62 (OCF 0x003F).
 * Sends complete data in a single operation (max 252 bytes).
 */
int
hci_le_set_periodic_adv_data(int hci_fd, uint8_t handle,
    const uint8_t *data, uint8_t len)
{
	struct bt_devreq r;
	ng_hci_le_set_periodic_adv_data_cp cp;
	ng_hci_le_set_periodic_adv_data_rp rp;

	if (len > NG_HCI_LE_PERIODIC_ADV_DATA_MAX) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.advertising_handle = handle;
	cp.operation = 0x03;		/* complete data */
	cp.advertising_data_length = len;
	memcpy(cp.advertising_data, data, len);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PERIODIC_ADV_DATA);
	r.cparam = &cp;
	/* Only send the actual data, not the full 252-byte buffer */
	r.clen = 3 + len;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Periodic Adv Data failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	return (0);
}

/*
 * LE Set Periodic Advertising Enable.
 * Core Spec Vol 4 Part E Section 7.8.63 (OCF 0x0040).
 */
int
hci_le_set_periodic_adv_enable(int hci_fd, uint8_t enable, uint8_t handle)
{
	struct bt_devreq r;
	ng_hci_le_set_periodic_adv_enable_cp cp;
	ng_hci_le_set_periodic_adv_enable_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.enable = enable;
	cp.advertising_handle = handle;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PERIODIC_ADV_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Periodic Adv Enable failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic advertising %s, handle=%d",
	    enable ? "enabled" : "disabled", handle);
	return (0);
}

/*
 * LE Periodic Advertising Create Sync.
 * Core Spec Vol 4 Part E Section 7.8.67 (OCF 0x0044).
 * Returns Command Status; result arrives via LE Periodic
 * Advertising Sync Established event.
 */
int
hci_le_periodic_adv_create_sync(int hci_fd, uint8_t options,
    uint8_t adv_sid, uint8_t addr_type, const uint8_t addr[6],
    uint16_t skip, uint16_t sync_timeout)
{
	struct bt_devreq r;
	ng_hci_le_periodic_adv_create_sync_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.options = options;
	cp.advertising_sid = adv_sid;
	cp.advertiser_address_type = addr_type;
	memcpy(&cp.advertiser_address, addr, 6);
	cp.skip = htole16(skip);
	cp.sync_timeout = htole16(sync_timeout);
	cp.sync_cte_type = 0;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_PERIODIC_ADV_CREATE_SYNC);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Periodic Adv Create Sync failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic adv sync create requested: sid=%d skip=%d "
	    "timeout=%d", adv_sid, skip, sync_timeout);
	return (0);
}

/*
 * LE Periodic Advertising Create Sync Cancel.
 * Core Spec Vol 4 Part E Section 7.8.68 (OCF 0x0045).
 */
int
hci_le_periodic_adv_create_sync_cancel(int hci_fd)
{
	struct bt_devreq r;
	ng_hci_le_periodic_adv_create_sync_cancel_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_PERIODIC_ADV_CREATE_SYNC_CANCEL);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Periodic Adv Create Sync Cancel failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic adv sync create cancelled");
	return (0);
}

/*
 * LE Periodic Advertising Terminate Sync.
 * Core Spec Vol 4 Part E Section 7.8.69 (OCF 0x0046).
 */
int
hci_le_periodic_adv_terminate_sync(int hci_fd, uint16_t sync_handle)
{
	struct bt_devreq r;
	ng_hci_le_periodic_adv_terminate_sync_cp cp;
	ng_hci_le_periodic_adv_terminate_sync_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.sync_handle = htole16(sync_handle);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_PERIODIC_ADV_TERMINATE_SYNC);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Periodic Adv Terminate Sync failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic adv sync terminated: handle=%04x", sync_handle);
	return (0);
}

/*
 * LE Add Device To Periodic Advertiser List.
 * Core Spec Vol 4 Part E Section 7.8.70 (OCF 0x0047).
 */
int
hci_le_add_dev_to_periodic_adv_list(int hci_fd, uint8_t addr_type,
    const uint8_t addr[6], uint8_t adv_sid)
{
	struct bt_devreq r;
	ng_hci_le_add_dev_periodic_adv_list_cp cp;
	ng_hci_le_add_dev_periodic_adv_list_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.advertiser_address_type = addr_type;
	memcpy(&cp.advertiser_address, addr, 6);
	cp.advertising_sid = adv_sid;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_ADD_DEV_PERIODIC_ADV_LIST);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Add Dev To Periodic Adv List failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "added device to periodic adv list, sid=%d", adv_sid);
	return (0);
}

/*
 * LE Remove Device From Periodic Advertiser List.
 * Core Spec Vol 4 Part E Section 7.8.71 (OCF 0x0048).
 */
int
hci_le_remove_dev_from_periodic_adv_list(int hci_fd, uint8_t addr_type,
    const uint8_t addr[6], uint8_t adv_sid)
{
	struct bt_devreq r;
	ng_hci_le_remove_dev_periodic_adv_list_cp cp;
	ng_hci_le_remove_dev_periodic_adv_list_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.advertiser_address_type = addr_type;
	memcpy(&cp.advertiser_address, addr, 6);
	cp.advertising_sid = adv_sid;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_REMOVE_DEV_PERIODIC_ADV_LIST);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Remove Dev From Periodic Adv List failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "removed device from periodic adv list, sid=%d", adv_sid);
	return (0);
}

/*
 * LE Clear Periodic Advertiser List.
 * Core Spec Vol 4 Part E Section 7.8.72 (OCF 0x0049).
 */
int
hci_le_clear_periodic_adv_list(int hci_fd)
{
	struct bt_devreq r;
	ng_hci_le_clear_periodic_adv_list_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CLEAR_PERIODIC_ADV_LIST);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Clear Periodic Adv List failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic advertiser list cleared");
	return (0);
}

/*
 * LE Read Periodic Advertiser List Size.
 * Core Spec Vol 4 Part E Section 7.8.73 (OCF 0x004A).
 */
int
hci_le_read_periodic_adv_list_size(int hci_fd, uint8_t *size)
{
	struct bt_devreq r;
	ng_hci_le_read_periodic_adv_list_size_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_PERIODIC_ADV_LIST_SIZE);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Read Periodic Adv List Size failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}

	if (size != NULL)
		*size = rp.periodic_advertiser_list_size;
	LOG_HCI(1, "periodic adv list size: %d",
	    rp.periodic_advertiser_list_size);
	return (0);
}

/* ----------------------------------------------------------------
 * LE Periodic Advertising Sync Transfer — PAST (BT 5.1)
 * Core Spec Vol 4 Part E Sections 7.8.88-7.8.92
 * ---------------------------------------------------------------- */

/*
 * LE Set Periodic Advertising Receive Enable.
 * Core Spec Vol 4 Part E Section 7.8.88 (OCF 0x0059).
 */
int
hci_le_set_periodic_adv_receive_enable(int hci_fd, uint16_t sync_handle,
    uint8_t enable)
{
	struct bt_devreq r;
	ng_hci_le_set_periodic_adv_rcv_enable_cp cp;
	ng_hci_le_set_periodic_adv_rcv_enable_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.sync_handle = htole16(sync_handle);
	cp.enable = enable;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PERIODIC_ADV_RCV_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Periodic Adv Receive Enable failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic adv receive %s, sync_handle=%04x",
	    enable ? "enabled" : "disabled", sync_handle);
	return (0);
}

/*
 * LE Periodic Advertising Sync Transfer.
 * Core Spec Vol 4 Part E Section 7.8.89 (OCF 0x005A).
 * Sends sync info for an existing periodic advertising train
 * to a connected peer.
 */
int
hci_le_periodic_adv_sync_transfer(int hci_fd, uint16_t con_handle,
    uint16_t service_data, uint16_t sync_handle)
{
	struct bt_devreq r;
	ng_hci_le_periodic_adv_sync_transfer_cp cp;
	ng_hci_le_periodic_adv_sync_transfer_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.service_data = htole16(service_data);
	cp.sync_handle = htole16(sync_handle);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_PERIODIC_ADV_SYNC_TRANSFER);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Periodic Adv Sync Transfer failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic adv sync transferred: con=%04x sync=%04x",
	    con_handle, sync_handle);
	return (0);
}

/*
 * LE Periodic Advertising Set Info Transfer.
 * Core Spec Vol 4 Part E Section 7.8.90 (OCF 0x005B).
 * Sends sync info for a local periodic advertising set
 * to a connected peer.
 */
int
hci_le_periodic_adv_set_info_transfer(int hci_fd, uint16_t con_handle,
    uint16_t service_data, uint8_t adv_handle)
{
	struct bt_devreq r;
	ng_hci_le_periodic_adv_set_info_transfer_cp cp;
	ng_hci_le_periodic_adv_set_info_transfer_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.service_data = htole16(service_data);
	cp.advertising_handle = adv_handle;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_PERIODIC_ADV_SET_INFO_TRANSFER);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Periodic Adv Set Info Transfer failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic adv set info transferred: con=%04x adv=%d",
	    con_handle, adv_handle);
	return (0);
}

/*
 * LE Set Periodic Advertising Sync Transfer Parameters.
 * Core Spec Vol 4 Part E Section 7.8.91 (OCF 0x005C).
 * Configures PAST reception on a per-connection basis.
 */
int
hci_le_set_past_params(int hci_fd, uint16_t con_handle, uint8_t mode,
    uint16_t skip, uint16_t sync_timeout, uint8_t cte_type)
{
	struct bt_devreq r;
	ng_hci_le_set_past_params_cp cp;
	ng_hci_le_set_past_params_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.mode = mode;
	cp.skip = htole16(skip);
	cp.sync_timeout = htole16(sync_timeout);
	cp.cte_type = cte_type;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PAST_PARAMS);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set PAST Params failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "PAST params set: con=%04x mode=%d skip=%d timeout=%d",
	    con_handle, mode, skip, sync_timeout);
	return (0);
}

/*
 * LE Set Default Periodic Advertising Sync Transfer Parameters.
 * Core Spec Vol 4 Part E Section 7.8.92 (OCF 0x005D).
 * Configures default PAST reception for all future connections.
 */
int
hci_le_set_default_past_params(int hci_fd, uint8_t mode, uint16_t skip,
    uint16_t sync_timeout, uint8_t cte_type)
{
	struct bt_devreq r;
	ng_hci_le_set_default_past_params_cp cp;
	ng_hci_le_set_default_past_params_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.mode = mode;
	cp.skip = htole16(skip);
	cp.sync_timeout = htole16(sync_timeout);
	cp.cte_type = cte_type;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_DEFAULT_PAST_PARAMS);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Default PAST Params failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "default PAST params set: mode=%d skip=%d timeout=%d",
	    mode, skip, sync_timeout);
	return (0);
}

/* ----------------------------------------------------------------
 * LE Connection Subrating (BT 5.3)
 * Core Spec Vol 4 Part E Sections 7.8.123-7.8.124
 * ---------------------------------------------------------------- */

/*
 * LE Set Default Subrate — set default subrate parameters for
 * all future connections.
 * Core Spec Vol 4 Part E Section 7.8.123 (OCF 0x007D).
 */
int
hci_le_set_default_subrate(int hci_fd, uint16_t min_subrate,
    uint16_t max_subrate, uint16_t max_latency, uint16_t cont_num,
    uint16_t timeout)
{
	struct bt_devreq r;
	ng_hci_le_set_default_subrate_cp cp;
	ng_hci_le_set_default_subrate_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.subrate_min = htole16(min_subrate);
	cp.subrate_max = htole16(max_subrate);
	cp.max_latency = htole16(max_latency);
	cp.continuation_number = htole16(cont_num);
	cp.supervision_timeout = htole16(timeout);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_DEFAULT_SUBRATE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Default Subrate failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "default subrate set: min=%d max=%d latency=%d "
	    "cont=%d timeout=%d", min_subrate, max_subrate,
	    max_latency, cont_num, timeout);
	return (0);
}

/*
 * LE Subrate Request — request subrate change on an active connection.
 * Returns Command Status; result arrives via LE Subrate Change event.
 * Core Spec Vol 4 Part E Section 7.8.124 (OCF 0x007E).
 */
int
hci_le_subrate_request(int hci_fd, uint16_t con_handle,
    uint16_t min_subrate, uint16_t max_subrate, uint16_t max_latency,
    uint16_t cont_num, uint16_t timeout)
{
	struct bt_devreq r;
	ng_hci_le_subrate_request_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.subrate_min = htole16(min_subrate);
	cp.subrate_max = htole16(max_subrate);
	cp.max_latency = htole16(max_latency);
	cp.continuation_number = htole16(cont_num);
	cp.supervision_timeout = htole16(timeout);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SUBRATE_REQUEST);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Subrate Request failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "subrate requested: con=%04x min=%d max=%d",
	    con_handle, min_subrate, max_subrate);
	return (0);
}

/* ----------------------------------------------------------------
 * LE Power Control (BT 5.2)
 * Core Spec Vol 4 Part E Sections 7.8.117-7.8.121
 * ---------------------------------------------------------------- */

/*
 * LE Enhanced Read Transmit Power Level.
 * Core Spec Vol 4 Part E Section 7.8.117 (OCF 0x0076).
 * phy: 1=1M, 2=2M, 3=Coded S=8, 4=Coded S=2.
 */
int
hci_le_enhanced_read_tx_power_level(int hci_fd, uint16_t con_handle,
    uint8_t phy, int8_t *cur_level, int8_t *max_level)
{
	struct bt_devreq r;
	ng_hci_le_enh_read_tx_power_cp cp;
	ng_hci_le_enh_read_tx_power_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.phy = phy;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_ENH_READ_TX_POWER_LEVEL);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Enhanced Read TX Power Level failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}

	if (cur_level != NULL)
		*cur_level = rp.current_tx_power_level;
	if (max_level != NULL)
		*max_level = rp.max_tx_power_level;
	LOG_HCI(1, "LE TX power: phy=%d cur=%d dBm max=%d dBm",
	    phy, rp.current_tx_power_level, rp.max_tx_power_level);
	return (0);
}

/*
 * LE Read Remote Transmit Power Level.
 * Core Spec Vol 4 Part E Section 7.8.118 (OCF 0x0077).
 * Returns Command Status; result arrives via LE Transmit
 * Power Reporting event.
 */
int
hci_le_read_remote_tx_power_level(int hci_fd, uint16_t con_handle,
    uint8_t phy)
{
	struct bt_devreq r;
	ng_hci_le_read_remote_tx_power_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.phy = phy;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_REMOTE_TX_POWER_LEVEL);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Read Remote TX Power Level failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "remote TX power read requested: con=%04x phy=%d",
	    con_handle, phy);
	return (0);
}

/*
 * LE Set Path Loss Reporting Parameters.
 * Core Spec Vol 4 Part E Section 7.8.119 (OCF 0x0078).
 * Thresholds and hysteresis in dB; min_time in connection events.
 */
int
hci_le_set_path_loss_reporting_params(int hci_fd, uint16_t con_handle,
    uint8_t high_thresh, uint8_t high_hyst, uint8_t low_thresh,
    uint8_t low_hyst, uint16_t min_time)
{
	struct bt_devreq r;
	ng_hci_le_set_path_loss_reporting_params_cp cp;
	ng_hci_le_set_path_loss_reporting_params_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.high_threshold = high_thresh;
	cp.high_hysteresis = high_hyst;
	cp.low_threshold = low_thresh;
	cp.low_hysteresis = low_hyst;
	cp.min_time_spent = htole16(min_time);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PATH_LOSS_REPORTING_PARAMS);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Path Loss Reporting Params failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "path loss params set: con=%04x high=%d/%d low=%d/%d "
	    "min_time=%d", con_handle, high_thresh, high_hyst,
	    low_thresh, low_hyst, min_time);
	return (0);
}

/*
 * LE Set Path Loss Reporting Enable.
 * Core Spec Vol 4 Part E Section 7.8.120 (OCF 0x0079).
 */
int
hci_le_set_path_loss_reporting_enable(int hci_fd, uint16_t con_handle,
    uint8_t enable)
{
	struct bt_devreq r;
	ng_hci_le_set_path_loss_reporting_enable_cp cp;
	ng_hci_le_set_path_loss_reporting_enable_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.enable = enable;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PATH_LOSS_REPORTING_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Path Loss Reporting Enable failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "path loss reporting %s, con=%04x",
	    enable ? "enabled" : "disabled", con_handle);
	return (0);
}

/*
 * LE Set Transmit Power Reporting Enable.
 * Core Spec Vol 4 Part E Section 7.8.121 (OCF 0x007A).
 */
int
hci_le_set_tx_power_reporting_enable(int hci_fd, uint16_t con_handle,
    uint8_t local_enable, uint8_t remote_enable)
{
	struct bt_devreq r;
	ng_hci_le_set_tx_power_reporting_enable_cp cp;
	ng_hci_le_set_tx_power_reporting_enable_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.local_enable = local_enable;
	cp.remote_enable = remote_enable;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_TX_POWER_REPORTING_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set TX Power Reporting Enable failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "TX power reporting: con=%04x local=%d remote=%d",
	    con_handle, local_enable, remote_enable);
	return (0);
}

/* ----------------------------------------------------------------
 * LE Extended Create Connection (BT 5.0)
 * Core Spec Vol 4 Part E Section 7.8.66
 * ---------------------------------------------------------------- */

/*
 * LE Extended Create Connection v1.
 * Core Spec Vol 4 Part E Section 7.8.66 (OCF 0x0043).
 *
 * phys is a bitmask (bit0=1M, bit1=2M, bit2=Coded).
 * phy_params points to popcount(phys) copies of
 * ng_hci_le_ext_create_conn_phy_t, already in little-endian.
 * phy_len is the total byte length of that array.
 *
 * Returns Command Status; result arrives via LE Enhanced
 * Connection Complete event.
 */
int
hci_le_ext_create_connection(int hci_fd, uint8_t filter,
    uint8_t own_addr, uint8_t peer_addr_type,
    const uint8_t peer_addr[6], uint8_t phys,
    const void *phy_params, size_t phy_len)
{
	struct bt_devreq r;
	uint8_t buf[sizeof(ng_hci_le_ext_create_connection_cp) +
	    3 * sizeof(ng_hci_le_ext_create_conn_phy_t)];
	ng_hci_le_ext_create_connection_cp *cp;
	ng_hci_status_rp rp;
	size_t cplen;

	cplen = sizeof(*cp) + phy_len;
	if (cplen > sizeof(buf)) {
		errno = EINVAL;
		return (-1);
	}

	memset(buf, 0, sizeof(buf));
	cp = (ng_hci_le_ext_create_connection_cp *)buf;
	cp->initiator_filter_policy = filter;
	cp->own_address_type = own_addr;
	cp->peer_address_type = peer_addr_type;
	memcpy(&cp->peer_address, peer_addr, 6);
	cp->initiating_phys = phys;
	memcpy(buf + sizeof(*cp), phy_params, phy_len);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_EXT_CREATE_CONNECTION);
	r.cparam = buf;
	r.clen = cplen;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (bt_devreq(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Extended Create Connection failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "extended connection create requested: phys=0x%02x",
	    phys);
	return (0);
}

/* ----------------------------------------------------------------
 * LE CoC (Connection-Oriented Channel) Initiation
 *
 * LE CoC uses L2CAP Credit Based Flow Control to create dynamic
 * channels over an LE link.  The kernel L2CAP layer currently
 * blocks LE dynamic channel initiation (returns ENOTSUP in
 * ng_l2cap_l2ca_con_req for NG_L2CAP_L2CA_IDTYPE_LE).
 *
 * This stub documents the userspace interface that will be used
 * once the kernel CoC initiation path is implemented.
 * ---------------------------------------------------------------- */

/*
 * Initiate an LE CoC connection to the specified peer.
 *
 * Creates an L2CAP SOCK_SEQPACKET socket, binds to BDADDR_ANY with
 * LE address type, sets l2cap_psm to the LE PSM, and connects to the
 * remote device.  The kernel L2CAP layer sends LE_CREDIT_BASED_CONNECTION_REQ
 * (code 0x14) on CID 0x0005 (LE signaling) and negotiates credits/MTU/MPS.
 *
 * Returns the connected socket fd on success, -1 on failure.
 */
int
ble_coc_connect(const uint8_t *addr, uint8_t addr_type,
    uint16_t psm, uint16_t mtu)
{
	struct sockaddr_l2cap bind_sa, con_sa;
	struct timeval tv;
	int fd, optval;

	(void)mtu; /* kernel negotiates MTU via LE CoC parameters */

	fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BLUETOOTH_PROTO_L2CAP);
	if (fd < 0) {
		LOG_L2C(1, "LE CoC: socket() failed: %s", strerror(errno));
		return (-1);
	}

	/* Bind to BDADDR_ANY with LE address type */
	memset(&bind_sa, 0, sizeof(bind_sa));
	bind_sa.l2cap_len = sizeof(bind_sa);
	bind_sa.l2cap_family = AF_BLUETOOTH;
	bind_sa.l2cap_bdaddr_type = BDADDR_LE_PUBLIC;
	/* l2cap_bdaddr = all zeros for any adapter */

	if (bind(fd, (struct sockaddr *)&bind_sa, sizeof(bind_sa)) < 0) {
		LOG_L2C(1, "LE CoC: bind() failed: %s", strerror(errno));
		close(fd);
		return (-1);
	}

	/* Connect to remote device with LE PSM */
	memset(&con_sa, 0, sizeof(con_sa));
	con_sa.l2cap_len = sizeof(con_sa);
	con_sa.l2cap_family = AF_BLUETOOTH;
	memcpy(&con_sa.l2cap_bdaddr, addr, sizeof(con_sa.l2cap_bdaddr));
	con_sa.l2cap_psm = htole16(psm);
	con_sa.l2cap_cid = 0;		/* dynamic allocation */
	con_sa.l2cap_bdaddr_type = addr_type;

	if (connect(fd, (struct sockaddr *)&con_sa, sizeof(con_sa)) < 0) {
		LOG_L2C(1, "LE CoC: connect() failed: psm=%d %s",
		    psm, strerror(errno));
		close(fd);
		return (-1);
	}

	/* Set receive timeout for CoC data transfers */
	tv.tv_sec = 30;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	/* Enable SO_NOSIGPIPE to avoid SIGPIPE on broken connections */
	optval = 1;
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval));

	LOG_L2C(1, "LE CoC connected: fd=%d psm=%d addr_type=%d",
	    fd, psm, addr_type);

	return (fd);
}
