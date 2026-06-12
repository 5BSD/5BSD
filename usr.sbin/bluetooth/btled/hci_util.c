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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
			return (0);
		}
	}

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
	uint8_t buf[512];
	ng_hci_event_pkt_t *evt;
	int count = 0;
	time_t end_time;

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

	*nresults = count;
	return (0);
}
