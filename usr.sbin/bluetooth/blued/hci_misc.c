/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * HCI miscellaneous commands for blued.
 *
 * Reset, node init, LE host support, event masks, feature
 * detection, encryption, LTK, ISO channels (CIG/BIG),
 * authenticated payload timeout, min encryption key size.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netgraph/bluetooth/include/ng_btsocket.h>

#include "ble_util.h"
#include "hci_log.h"
#include "hci_util.h"
#include "hci_internal.h"

/* ----------------------------------------------------------------
 * Encryption — wait for Encryption Change event
 * ---------------------------------------------------------------- */

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
	struct timespec deadline, now;
	pthread_mutex_t *hci_mtx;
	int saved_errno = ETIMEDOUT;	/* C3-L: real failure errno, not always ETIMEDOUT */

	/*
	 * Finding H-H4: this runs on a detached worker thread doing raw
	 * bt_devfilter/bt_devrecv on the shared HCI fd — the same fd the main
	 * event loop drains.  Hold hci_devreq_mutex across the filter swap and
	 * the receive loop so the worker and the event loop cannot both consume
	 * HCI events (consistent with the finding-43 trylock in the event loop,
	 * which backs off while this lock is held).
	 *
	 * C3-M10: hci_devreq_mutex is per-fd, so on any one adapter fd only a
	 * single encryption wait is ever active — a second pairing's wait
	 * blocks here on the mutex until the first completes, i.e. same-adapter
	 * pairings serialize.  C3-H1 additionally removed the redundant OUTER
	 * hci_wait_encryption() calls, so each pairing now performs exactly one
	 * wait instead of two, halving the window.  A residual remains: an
	 * Encryption Change for a DIFFERENT handle that the controller delivers
	 * while this wait holds the fd is drained here and dropped (the `h ==
	 * con_handle` mismatch just `continue`s), because the kernel HCI socket
	 * offers no per-handle filtering and there is no way to re-queue it.
	 * Fully closing that would require a shared HCI-event demux rather than
	 * a per-worker recv loop; that is out of scope for this pass.  Given the
	 * mutex serialization and the C3-H1 halving, the practical concurrent-
	 * pairing case on a single adapter is not exercised by the current
	 * setup/REKEY paths (each conn spawns at most one pairing worker).
	 */
	hci_mtx = hci_devreq_mutex(hci_fd);
	pthread_mutex_lock(hci_mtx);

	/* Set filter to receive Encryption Change events */
	memset(&flt, 0, sizeof(flt));
	bt_devfilter_pkt_set(&flt, NG_HCI_EVENT_PKT);
	bt_devfilter_evt_set(&flt, NG_HCI_EVENT_ENCRYPTION_CHANGE);
	bt_devfilter_evt_set(&flt, NG_HCI_EVENT_ENCRYPTION_CHANGE_V2);
	bt_devfilter_evt_set(&flt, NG_HCI_EVENT_COMMAND_STATUS);
	bt_devfilter(hci_fd, &flt, &oldflt);

	/*
	 * Use the monotonic clock for the timeout so a wall-clock step
	 * (e.g. NTP correction) cannot shorten or extend the wait.
	 */
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += timeout_sec;

	for (;;) {
		ssize_t n;

		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec > deadline.tv_sec ||
		    (now.tv_sec == deadline.tv_sec &&
		    now.tv_nsec >= deadline.tv_nsec))
			break;

		n = bt_devrecv(hci_fd, buf, sizeof(buf), 1);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			/* C3-L: propagate the real recv errno to the caller. */
			saved_errno = errno;
			break;
		}

		evt = (ng_hci_event_pkt_t *)buf;
		if ((size_t)n < sizeof(*evt) || evt->type != NG_HCI_EVENT_PKT ||
		    (size_t)n != sizeof(*evt) + evt->length)
			continue;

		if (hci_log_enabled())
			hci_log_packet(HCI_LOG_EVT,
			    buf + 1, (uint16_t)(n - 1), true);

		/*
		 * LE Enable Encryption (§7.8.24) returns no Command Complete;
		 * on failure the controller reports a nonzero Command Status for
		 * that opcode and NEVER generates an Encryption Change.  Without
		 * inspecting it the wait would burn the full timeout holding the
		 * adapter mutex.  Fast-fail on a nonzero status for our opcode.
		 */
		if (evt->event == NG_HCI_EVENT_COMMAND_STATUS &&
		    evt->length == sizeof(ng_hci_command_status_ep)) {
			ng_hci_command_status_ep *cs =
			    (ng_hci_command_status_ep *)(evt + 1);

			if (le16toh(cs->opcode) == NG_HCI_OPCODE(NG_HCI_OGF_LE,
			    NG_HCI_OCF_LE_START_ENCRYPTION) && cs->status != 0) {
				bt_devfilter(hci_fd, &oldflt, NULL);
				pthread_mutex_unlock(hci_mtx);
				LOG_HCI(1, "LE Enable Encryption command status "
				    "0x%02x", cs->status);
				errno = EIO;
				return (-1);
			}
			continue;
		}

		if (evt->event == NG_HCI_EVENT_ENCRYPTION_CHANGE ||
		    evt->event == NG_HCI_EVENT_ENCRYPTION_CHANGE_V2) {
			uint8_t status, encryption_enable;
			uint16_t h;

			if (evt->event == NG_HCI_EVENT_ENCRYPTION_CHANGE) {
				ng_hci_encryption_change_ep *ep;

				if (evt->length != sizeof(*ep))
					continue;
				ep = (ng_hci_encryption_change_ep *)(evt + 1);
				status = ep->status;
				h = le16toh(ep->con_handle);
				encryption_enable = ep->encryption_enable;
			} else {
				ng_hci_encryption_change_v2_ep *ep;

				if (evt->length != sizeof(*ep))
					continue;
				ep = (ng_hci_encryption_change_v2_ep *)(evt + 1);
				status = ep->status;
				h = le16toh(ep->con_handle);
				encryption_enable = ep->encryption_enable;
			}
			/*
			 * Core 6.3 Vol 4, Part E, Section 7.7.8 defines this
			 * event field as 12 meaningful bits in 0x0000-0x0EFF;
			 * unlike an ACL data header, it has no PB/BC flags.
			 */
			if (h <= BLUED_HCI_CONNECTION_HANDLE_MAX &&
			    con_handle <= BLUED_HCI_CONNECTION_HANDLE_MAX &&
			    h == con_handle) {
				/* Restore old filter */
				bt_devfilter(hci_fd, &oldflt, NULL);
				pthread_mutex_unlock(hci_mtx);

				LOG_HCI(1, "encryption change status=%d enable=%d",
				    status, encryption_enable);

				/* This daemon's SMP links are LE: only value 0x01 is ON. */
				if (status != 0 || encryption_enable != 0x01) {
					errno = EACCES;
					return (-1);
				}
				return (0);
			}
		}
	}

	/* Restore old filter */
	bt_devfilter(hci_fd, &oldflt, NULL);
	pthread_mutex_unlock(hci_mtx);
	/* C3-L: ETIMEDOUT only when the deadline actually expired; otherwise
	 * report the recv failure that broke the loop. */
	errno = saved_errno;
	return (-1);
}

/* ----------------------------------------------------------------
 * LTK Request Reply / Negative Reply
 * ---------------------------------------------------------------- */

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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

/* ----------------------------------------------------------------
 * HCI Initialization and Feature Detection
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

	memset(&rp, 0, sizeof(rp));	/* Finding H-H3 */
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    NG_HCI_OCF_RESET);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 2) < 0)
		return (-1);
	/*
	 * Finding H-H3: a truncated/empty Command Complete (r.rlen short of the
	 * status byte) must not be mistaken for a successful reset just because
	 * the pre-zeroed status reads 0x00.
	 */
	if ((size_t)r.rlen < sizeof(rp) || rp.status != 0x00) {
		warnx("hci_reset: controller status 0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "controller reset");
	return (0);
}

int
hci_node_init(int hci_fd)
{
	if (ioctl(hci_fd, SIOC_HCI_RAW_NODE_INIT) < 0)
		return (-1);

	LOG_HCI(1, "HCI node initialized");
	return (0);
}

int
hci_write_le_host_support(int hci_fd, uint8_t le_host, uint8_t simultaneous)
{
	struct bt_devreq r;
	ng_hci_write_le_host_supported_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.le_supported_host = le_host ? 1 : 0;
	cp.simultaneous_le_host = simultaneous ? 1 : 0;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    NG_HCI_OCF_WRITE_LE_HOST_SUPPORTED);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		warnx("hci_write_le_host_support: controller status 0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "LE host support enabled");
	return (0);
}

int
hci_set_event_mask(int hci_fd, uint64_t mask)
{
	struct bt_devreq r;
	ng_hci_set_event_mask_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	for (int i = 0; i < 8; i++)
		cp.event_mask[i] = (mask >> (i * 8)) & 0xFF;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    NG_HCI_OCF_SET_EVENT_MASK);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		warnx("hci_set_event_mask: controller status 0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "event mask set: 0x%016llx",
	    (unsigned long long)mask);
	return (0);
}

/*
 * HCI Set Event Mask Page 2 — Core Spec Vol 4 Part E Section 7.3.69.
 *
 * Page 2 governs events introduced after the original 8-octet page-1
 * mask ran out of bits, including the Authenticated Payload Timeout
 * Expired event (page-2 bit 23) that terminates a link whose LE Ping
 * authenticated-payload timer expires.  OGF Controller & Baseband,
 * OCF 0x0063; the command carries the same 8-octet mask layout as
 * Set Event Mask, so the page-1 command parameter type is reused.
 */
int
hci_set_event_mask_page2(int hci_fd, uint64_t mask)
{
	struct bt_devreq r;
	ng_hci_set_event_mask_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	for (int i = 0; i < 8; i++)
		cp.event_mask[i] = (mask >> (i * 8)) & 0xFF;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    BLUED_HCI_OCF_SET_EVENT_MASK_PAGE_2);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		warnx("hci_set_event_mask_page2: controller status 0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "event mask page 2 set: 0x%016llx",
	    (unsigned long long)mask);
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

	memset(&rp, 0, sizeof(rp));	/* Finding H-H3 */
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_LOCAL_SUPPORTED_FEATURES);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	/* Finding H-H3: reject a short/absent CC before reading le_features. */
	if ((size_t)r.rlen < sizeof(rp)) {
		errno = EIO;
		return (-1);
	}
	if (rp.status != 0x00) {
		warnx("hci_le_read_local_features: controller status 0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}

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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		warnx("hci_le_set_event_mask: controller status 0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "LE event mask set: 0x%016llx",
	    (unsigned long long)mask);
	return (0);
}

uint64_t
hci_le_default_event_mask(uint64_t features)
{
	uint64_t mask;

	mask = LE_EVTMASK_CONN_COMPLETE |
	    LE_EVTMASK_ADV_REPORT |
	    LE_EVTMASK_CONN_UPDATE |
	    LE_EVTMASK_READ_REMOTE_FEAT |
	    LE_EVTMASK_LTK_REQUEST |
	    LE_EVTMASK_DATA_LENGTH_CHANGE |
	    LE_EVTMASK_ENH_CONN_COMPLETE |
	    LE_EVTMASK_PHY_UPDATE_COMPL |
	    LE_EVTMASK_SCAN_TIMEOUT;

	if ((features & LE_FEAT_EXT_ADVERTISING) != 0) {
		mask |= LE_EVTMASK_EXT_ADV_REPORT |
		    LE_EVTMASK_ADV_SET_TERM |
		    LE_EVTMASK_SCAN_REQ_RCVD;
	}
	if ((features & LE_FEAT_PERIODIC_ADV) != 0) {
		mask |= LE_EVTMASK_PER_ADV_SYNC_EST |
		    LE_EVTMASK_PER_ADV_REPORT |
		    LE_EVTMASK_PER_ADV_SYNC_LOST |
		    LE_EVTMASK_PER_ADV_SYNC_XFER;
	}
	if ((features & LE_FEAT_CIS_CENTRAL) != 0)
		mask |= LE_EVTMASK_CIS_ESTABLISHED;
	if ((features & LE_FEAT_CIS_PERIPH) != 0)
		mask |= LE_EVTMASK_CIS_REQUEST;
	if ((features & LE_FEAT_ISO_BROADCASTER) != 0) {
		mask |= LE_EVTMASK_CREATE_BIG_COMPL |
		    LE_EVTMASK_TERM_BIG_COMPL;
	}
	if ((features & LE_FEAT_ISO_SYNC_RECEIVER) != 0) {
		mask |= LE_EVTMASK_BIG_SYNC_EST |
		    LE_EVTMASK_BIG_SYNC_LOST |
		    LE_EVTMASK_BIGINFO_ADV_REP;
	}

	/*
	 * LE Power Control (BT 5.2): the TX Power Reporting subevent (0x21)
	 * is delivered for LE Read Remote Transmit Power Level and autonomous
	 * reports, and the Path Loss Threshold subevent (0x20) for LE Set Path
	 * Loss Reporting.  Unmask each only when its feature is present.
	 */
	if ((features & LE_FEAT_POWER_CONTROL) != 0)
		mask |= LE_EVTMASK_TX_POWER_REPORT;
	if ((features & LE_FEAT_PATH_LOSS_MONITORING) != 0)
		mask |= LE_EVTMASK_PATH_LOSS_THRESH;

	/* Connection Subrating (BT 5.3): Subrate Change subevent (0x23). */
	if ((features & LE_FEAT_CONN_SUBRATING) != 0)
		mask |= LE_EVTMASK_SUBRATE_CHANGE;

	/*
	 * Direction Finding (BT 5.1): unmask the IQ Report subevents that a
	 * controller can deliver given the CTE features it advertises.
	 * Connectionless IQ Report (0x15) for a receiver of connectionless
	 * CTE, Connection IQ Report (0x16) and CTE Request Failed (0x17) for
	 * the connection-oriented CTE request/response roles.
	 */
	if ((features & (LE_FEAT_CONNLESS_CTE_TX | LE_FEAT_CONNLESS_CTE_RX)) != 0)
		mask |= LE_EVTMASK_CONNLESS_IQ_REPORT;
	if ((features & (LE_FEAT_CONN_CTE_REQ | LE_FEAT_CONN_CTE_RSP)) != 0)
		mask |= LE_EVTMASK_CONN_IQ_REPORT | LE_EVTMASK_CTE_REQ_FAILED;

	return (mask);
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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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

	if (con_handle > 0x0EFF) {
		errno = EINVAL;
		return (-1);
	}

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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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
 * Core Spec Vol 4 Part E Section 7.8.97 (OCF 0x0062).
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
	/*
	 * 15-byte header + up to 31 CIS parameter records of 9 bytes each
	 * = 15 + 279 = 294.  A previous [256] undersized this and wrongly
	 * rejected a spec-legal 31-CIS group (Core Spec Vol 4 Part E §7.8.97).
	 */
	uint8_t cmd[15 + 31 * 9];
	uint8_t rpbuf[66];	/* status(1)+cig_id(1)+cis_count(1)+handles(2*31) */
	size_t cmdlen;

	if (cig_id > 0xEF ||
	    sdu_interval_c < 0x0000FF || sdu_interval_c > 0x0FFFFF ||
	    sdu_interval_p < 0x0000FF || sdu_interval_p > 0x0FFFFF ||
	    worst_case_sca > 0x07 || packing > 0x01 || framing > 0x02 ||
	    max_transport_latency_c < 0x0005 ||
	    max_transport_latency_c > 0x0FA0 ||
	    max_transport_latency_p < 0x0005 ||
	    max_transport_latency_p > 0x0FA0 ||
	    cis_count > 31 || cis_params_len != (size_t)cis_count * 9 ||
	    (cis_params_len != 0 && cis_params == NULL)) {
		errno = EINVAL;
		return (-1);
	}

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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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
		/* Clamp to spec max (31) and rpbuf capacity */
		if (n > 31)
			n = 31;
		for (uint8_t i = 0; i < n && i < cis_count; i++) {
			memcpy(&out_cis_handles[i], rpbuf + 3 + i * 2, 2);
			out_cis_handles[i] = le16toh(out_cis_handles[i]);
		}
	}

	LOG_HCI(1, "CIG params set: cig_id=%d cis_count=%d",
	    rpbuf[1], rpbuf[2]);
	return (0);
}

static bool
hci_iso_phy_is_single_valid(uint8_t phy)
{

	return (phy == 0x01 || phy == 0x02 || phy == 0x04);
}

/*
 * LE Set CIG Parameters Test — configure a CIG with explicit test scheduling
 * parameters.  Core Spec Vol 4 Part E Section 7.8.98 (OCF 0x0063).
 */
int
hci_le_set_cig_params_test(int hci_fd, uint8_t cig_id,
    uint32_t sdu_interval_c, uint32_t sdu_interval_p,
    uint8_t ft_c_to_p, uint8_t ft_p_to_c, uint16_t iso_interval,
    uint8_t worst_case_sca, uint8_t packing, uint8_t framing,
    uint8_t cis_count, const struct hci_le_cig_params_test_cis *cis,
    uint8_t *out_cig_id, uint8_t *out_cis_count, uint16_t *out_cis_handles)
{
	struct bt_devreq r;
	uint8_t cmd[15 + 31 * 14];
	uint8_t rpbuf[66];	/* status(1)+cig_id(1)+cis_count(1)+handles */
	size_t off;

	if (cig_id > 0xEF ||
	    sdu_interval_c < 0x0000FF || sdu_interval_c > 0x0FFFFF ||
	    sdu_interval_p < 0x0000FF || sdu_interval_p > 0x0FFFFF ||
	    ft_c_to_p == 0 || ft_p_to_c == 0 ||
	    iso_interval < 0x0004 || iso_interval > 0x0C80 ||
	    worst_case_sca > 0x07 || packing > 0x01 || framing > 0x02 ||
	    cis_count > 0x1F || (cis_count != 0 && cis == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	for (uint8_t i = 0; i < cis_count; i++) {
		if (cis[i].cis_id > 0xEF || cis[i].nse == 0 ||
		    cis[i].nse > 0x1F ||
		    cis[i].max_sdu_c_to_p > 0x0FFF ||
		    cis[i].max_sdu_p_to_c > 0x0FFF ||
		    cis[i].max_pdu_c_to_p > 0x00FB ||
		    cis[i].max_pdu_p_to_c > 0x00FB ||
		    !hci_iso_phy_is_single_valid(cis[i].phy_c_to_p) ||
		    !hci_iso_phy_is_single_valid(cis[i].phy_p_to_c) ||
		    cis[i].bn_c_to_p > 0x0F ||
		    cis[i].bn_p_to_c > 0x0F) {
			errno = EINVAL;
			return (-1);
		}
	}

	memset(cmd, 0, sizeof(cmd));
	cmd[0] = cig_id;
	cmd[1] = sdu_interval_c & 0xFF;
	cmd[2] = (sdu_interval_c >> 8) & 0xFF;
	cmd[3] = (sdu_interval_c >> 16) & 0xFF;
	cmd[4] = sdu_interval_p & 0xFF;
	cmd[5] = (sdu_interval_p >> 8) & 0xFF;
	cmd[6] = (sdu_interval_p >> 16) & 0xFF;
	cmd[7] = ft_c_to_p;
	cmd[8] = ft_p_to_c;
	cmd[9] = iso_interval & 0xFF;
	cmd[10] = (iso_interval >> 8) & 0xFF;
	cmd[11] = worst_case_sca;
	cmd[12] = packing;
	cmd[13] = framing;
	cmd[14] = cis_count;
	off = 15;
	for (uint8_t i = 0; i < cis_count; i++) {
		cmd[off++] = cis[i].cis_id;
		cmd[off++] = cis[i].nse;
		cmd[off++] = cis[i].max_sdu_c_to_p & 0xFF;
		cmd[off++] = (cis[i].max_sdu_c_to_p >> 8) & 0xFF;
		cmd[off++] = cis[i].max_sdu_p_to_c & 0xFF;
		cmd[off++] = (cis[i].max_sdu_p_to_c >> 8) & 0xFF;
		cmd[off++] = cis[i].max_pdu_c_to_p & 0xFF;
		cmd[off++] = (cis[i].max_pdu_c_to_p >> 8) & 0xFF;
		cmd[off++] = cis[i].max_pdu_p_to_c & 0xFF;
		cmd[off++] = (cis[i].max_pdu_p_to_c >> 8) & 0xFF;
		cmd[off++] = cis[i].phy_c_to_p;
		cmd[off++] = cis[i].phy_p_to_c;
		cmd[off++] = cis[i].bn_c_to_p;
		cmd[off++] = cis[i].bn_p_to_c;
	}

	memset(rpbuf, 0, sizeof(rpbuf));
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_CIG_PARAMS_TEST);
	r.cparam = cmd;
	r.clen = off;
	r.rparam = rpbuf;
	r.rlen = sizeof(rpbuf);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rpbuf[0] != 0x00) {
		LOG_HCI(1, "LE Set CIG Params Test failed, status=0x%02x",
		    rpbuf[0]);
		errno = EIO;
		return (-1);
	}

	if (out_cig_id != NULL)
		*out_cig_id = rpbuf[1];
	if (out_cis_count != NULL)
		*out_cis_count = rpbuf[2];
	if (out_cis_handles != NULL) {
		uint8_t n = rpbuf[2];

		if (n > 31)
			n = 31;
		for (uint8_t i = 0; i < n && i < cis_count; i++) {
			memcpy(&out_cis_handles[i], rpbuf + 3 + i * 2, 2);
			out_cis_handles[i] = le16toh(out_cis_handles[i]);
		}
	}

	LOG_HCI(1, "CIG test params set: cig_id=%d cis_count=%d",
	    rpbuf[1], rpbuf[2]);
	return (0);
}

/*
 * LE Create CIS — establish one or more Connected Isochronous Streams.
 * Core Spec Vol 4 Part E Section 7.8.99 (OCF 0x0064).
 */
int
hci_le_create_cis(int hci_fd, uint8_t cis_count,
    const uint16_t *cis_handles, const uint16_t *acl_handles)
{
	struct bt_devreq r;
	uint8_t cmd[1 + 31 * 4];	/* count + up to 31 pairs */
	ng_hci_command_status_ep rp;	/* 4-byte Command Status event (finding 40) */
	size_t cmdlen;

	if (cis_count == 0 || cis_count > 31 || cis_handles == NULL ||
	    acl_handles == NULL) {
		errno = EINVAL;
		return (-1);
	}
	for (uint8_t i = 0; i < cis_count; i++) {
		if (cis_handles[i] > 0x0EFF || acl_handles[i] > 0x0EFF) {
			errno = EINVAL;
			return (-1);
		}
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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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

	if (cig_id > 0xEF) {
		errno = EINVAL;
		return (-1);
	}

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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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
 * LE Accept CIS Request.
 * Core Spec Vol 4 Part E Section 7.8.101 (OCF 0x0066).
 */
int
hci_le_accept_cis_request(int hci_fd, uint16_t con_handle)
{
	struct bt_devreq r;
	ng_hci_le_accept_cis_request_cp cp;
	ng_hci_command_status_ep rp;	/* 4-byte Command Status event (finding 40) */

	if (con_handle > 0x0EFF) {
		errno = EINVAL;
		return (-1);
	}

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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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
 * LE Reject CIS Request.
 * Core Spec Vol 4 Part E Section 7.8.102 (OCF 0x0067).
 */
int
hci_le_reject_cis_request(int hci_fd, uint16_t con_handle, uint8_t reason)
{
	struct bt_devreq r;
	ng_hci_le_reject_cis_request_cp cp;
	ng_hci_le_reject_cis_request_rp rp;

	if (con_handle > 0x0EFF) {
		errno = EINVAL;
		return (-1);
	}

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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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
 * Core Spec Vol 4 Part E Section 7.8.103 (OCF 0x0068).
 */
static bool
hci_broadcast_code_zero(const uint8_t broadcast_code[16])
{
	uint8_t acc;

	if (broadcast_code == NULL)
		return (true);
	acc = 0;
	for (int i = 0; i < 16; i++)
		acc |= broadcast_code[i];
	return (acc == 0);
}

int
hci_le_create_big(int hci_fd, uint8_t big_handle, uint8_t adv_handle,
    uint8_t num_bis, uint32_t sdu_interval, uint16_t max_sdu,
    uint16_t max_transport_latency, uint8_t rtn, uint8_t phy,
    uint8_t packing, uint8_t framing, uint8_t encryption,
    const uint8_t broadcast_code[16])
{
	struct bt_devreq r;
	uint8_t cmd[31];	/* fixed 31-byte command */
	ng_hci_command_status_ep rp;	/* 4-byte Command Status event (finding 40) */

	if (big_handle > 0xEF || adv_handle > 0xEF ||
	    num_bis < 0x01 || num_bis > 0x1F ||
	    sdu_interval < 0x0000FF || sdu_interval > 0x0FFFFF ||
	    max_sdu < 0x0001 || max_sdu > 0x0FFF ||
	    max_transport_latency < 0x0005 ||
	    max_transport_latency > 0x0FA0 ||
	    rtn > 0x1E || phy == 0 || (phy & ~0x07) != 0 ||
	    packing > 0x01 || framing > 0x02 || encryption > 0x01 ||
	    (encryption == 0x01 && broadcast_code == NULL) ||
	    (encryption == 0x00 && !hci_broadcast_code_zero(broadcast_code))) {
		errno = EINVAL;
		return (-1);
	}

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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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
 * LE Create BIG Test — create a BIG with explicit test scheduling parameters.
 * Core Spec Vol 4 Part E Section 7.8.104 (OCF 0x0069).
 */
int
hci_le_create_big_test(int hci_fd, uint8_t big_handle, uint8_t adv_handle,
    uint8_t num_bis, uint32_t sdu_interval, uint16_t iso_interval,
    uint8_t nse, uint16_t max_sdu, uint16_t max_pdu, uint8_t phy,
    uint8_t packing, uint8_t framing, uint8_t bn, uint8_t irc,
    uint8_t pto, uint8_t encryption, const uint8_t broadcast_code[16])
{
	struct bt_devreq r;
	uint8_t cmd[36];
	ng_hci_command_status_ep rp;	/* 4-byte Command Status event (finding 40) */

	if (big_handle > 0xEF || adv_handle > 0xEF ||
	    num_bis < 0x01 || num_bis > 0x1F ||
	    sdu_interval < 0x0000FF || sdu_interval > 0x0FFFFF ||
	    iso_interval < 0x0004 || iso_interval > 0x0C80 ||
	    nse < 0x01 || nse > 0x1F ||
	    max_sdu < 0x0001 || max_sdu > 0x0FFF ||
	    max_pdu < 0x0001 || max_pdu > 0x00FB ||
	    !hci_iso_phy_is_single_valid(phy) ||
	    packing > 0x01 || framing > 0x02 ||
	    bn < 0x01 || bn > 0x07 || irc < 0x01 || irc > 0x0F ||
	    pto > 0x0F || encryption > 0x01 ||
	    (encryption == 0x01 && broadcast_code == NULL) ||
	    (encryption == 0x00 && !hci_broadcast_code_zero(broadcast_code))) {
		errno = EINVAL;
		return (-1);
	}

	memset(cmd, 0, sizeof(cmd));
	cmd[0] = big_handle;
	cmd[1] = adv_handle;
	cmd[2] = num_bis;
	cmd[3] = sdu_interval & 0xFF;
	cmd[4] = (sdu_interval >> 8) & 0xFF;
	cmd[5] = (sdu_interval >> 16) & 0xFF;
	cmd[6] = iso_interval & 0xFF;
	cmd[7] = (iso_interval >> 8) & 0xFF;
	cmd[8] = nse;
	cmd[9] = max_sdu & 0xFF;
	cmd[10] = (max_sdu >> 8) & 0xFF;
	cmd[11] = max_pdu & 0xFF;
	cmd[12] = (max_pdu >> 8) & 0xFF;
	cmd[13] = phy;
	cmd[14] = packing;
	cmd[15] = framing;
	cmd[16] = bn;
	cmd[17] = irc;
	cmd[18] = pto;
	cmd[19] = encryption;
	if (broadcast_code != NULL)
		memcpy(cmd + 20, broadcast_code, 16);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CREATE_BIG_TEST);
	r.cparam = cmd;
	r.clen = sizeof(cmd);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Create BIG Test failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "LE Create BIG Test requested: big=%d adv=%d num_bis=%d",
	    big_handle, adv_handle, num_bis);
	return (0);
}

/*
 * LE Terminate BIG.
 * Core Spec Vol 4 Part E Section 7.8.105 (OCF 0x006A).
 */
int
hci_le_terminate_big(int hci_fd, uint8_t big_handle, uint8_t reason)
{
	struct bt_devreq r;
	ng_hci_le_terminate_big_cp cp;
	ng_hci_command_status_ep rp;	/* 4-byte Command Status event (finding 40) */

	if (big_handle > 0xEF) {
		errno = EINVAL;
		return (-1);
	}

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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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
 * LE BIG Create Sync.
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
	ng_hci_command_status_ep rp;	/* 4-byte Command Status event (finding 40) */
	size_t cmdlen;

	if (big_handle > 0xEF || sync_handle > 0x0EFF ||
	    encryption > 0x01 || mse > 0x1F ||
	    big_sync_timeout < 0x000A || big_sync_timeout > 0x4000 ||
	    num_bis < 0x01 || num_bis > 0x1F || bis_indices == NULL ||
	    (encryption == 0x01 && broadcast_code == NULL) ||
	    (encryption == 0x00 && !hci_broadcast_code_zero(broadcast_code))) {
		errno = EINVAL;
		return (-1);
	}
	for (uint8_t i = 0; i < num_bis; i++) {
		if (bis_indices[i] < 0x01 || bis_indices[i] > 0x1F ||
		    (i > 0 && bis_indices[i] <= bis_indices[i - 1])) {
			errno = EINVAL;
			return (-1);
		}
	}

	cmdlen = 24 + num_bis;

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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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
 * LE BIG Terminate Sync.
 * Core Spec Vol 4 Part E Section 7.8.107 (OCF 0x006C).
 */
int
hci_le_big_terminate_sync(int hci_fd, uint8_t big_handle)
{
	struct bt_devreq r;
	ng_hci_le_big_terminate_sync_cp cp;
	ng_hci_le_big_terminate_sync_rp rp;

	if (big_handle > 0xEF) {
		errno = EINVAL;
		return (-1);
	}

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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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
 * LE Setup ISO Data Path.
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
	 * An HCI Command packet has a one-octet Parameter_Total_Length
	 * (Core 6.3, Vol 4, Part E, §5.4.1).  The fixed parameters for
	 * LE Setup ISO Data Path consume 13 octets, leaving at most 242
	 * octets for Codec_Configuration.
	 */
	uint8_t cmd[255];
	ng_hci_le_setup_iso_data_path_rp rp;
	size_t cmdlen;

	if (con_handle > 0x0EFF || direction > 0x01 ||
	    path_id == 0xFF || codec_id == NULL ||
	    controller_delay > 0x3D0900 || codec_config_len > 255 - 13 ||
	    (codec_id[0] == 0x03 && codec_config_len != 0) ||
	    (codec_config_len != 0 && codec_config == NULL)) {
		errno = EINVAL;
		return (-1);
	}

	cmdlen = 13 + codec_config_len;
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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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
 * LE Remove ISO Data Path.
 * Core Spec Vol 4 Part E Section 7.8.110 (OCF 0x006F).
 */
int
hci_le_remove_iso_data_path(int hci_fd, uint16_t con_handle,
    uint8_t direction)
{
	struct bt_devreq r;
	ng_hci_le_remove_iso_data_path_cp cp;
	ng_hci_le_remove_iso_data_path_rp rp;

	if (con_handle > 0x0EFF || direction == 0 || (direction & ~0x03) != 0) {
		errno = EINVAL;
		return (-1);
	}

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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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
 * LE Request Peer SCA.
 * Core Spec Vol 4 Part E Section 7.8.108 (OCF 0x006D).
 */
int
hci_le_request_peer_sca(int hci_fd, uint16_t con_handle)
{
	struct bt_devreq r;
	ng_hci_le_request_peer_sca_cp cp;
	ng_hci_command_status_ep rp;	/* 4-byte Command Status event (finding 40) */

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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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
 * LE Read ISO Link Quality.
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

	if (con_handle > 0x0EFF) {
		errno = EINVAL;
		return (-1);
	}

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

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
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
 * LE ISO control-plane callers (drive the encoders above)
 * Core Spec Vol 4 Part E §7.8.97, §7.8.109
 * ---------------------------------------------------------------- */

/*
 * Provision a CIG via LE Set CIG Parameters (§7.8.97).  Serialise the
 * caller's per-CIS records into the 9-octet wire records the command
 * carries — CIS_ID(1), Max_SDU_C_To_P(2 LE), Max_SDU_P_To_C(2 LE),
 * PHY_C_To_P(1), PHY_P_To_C(1), RTN_C_To_P(1), RTN_P_To_C(1) — then hand
 * them to the encoder, which prepends the 15-octet CIG header.
 */
int
hci_le_setup_cig(int hci_fd, uint8_t cig_id,
    uint32_t sdu_interval_c, uint32_t sdu_interval_p,
    uint8_t worst_case_sca, uint8_t packing, uint8_t framing,
    uint16_t max_latency_c, uint16_t max_latency_p,
    uint8_t cis_count, const struct hci_cis_param *cises,
    uint8_t *out_cig_id, uint8_t *out_cis_count, uint16_t *out_cis_handles)
{
	uint8_t recs[31 * 9];
	size_t off = 0;

	if (cis_count > 31 || (cis_count > 0 && cises == NULL)) {
		errno = EINVAL;
		return (-1);
	}

	for (uint8_t i = 0; i < cis_count; i++) {
		const struct hci_cis_param *c = &cises[i];

		recs[off + 0] = c->cis_id;
		recs[off + 1] = c->max_sdu_c_to_p & 0xFF;
		recs[off + 2] = (c->max_sdu_c_to_p >> 8) & 0xFF;
		recs[off + 3] = c->max_sdu_p_to_c & 0xFF;
		recs[off + 4] = (c->max_sdu_p_to_c >> 8) & 0xFF;
		recs[off + 5] = c->phy_c_to_p;
		recs[off + 6] = c->phy_p_to_c;
		recs[off + 7] = c->rtn_c_to_p;
		recs[off + 8] = c->rtn_p_to_c;
		off += 9;
	}

	return (hci_le_set_cig_params(hci_fd, cig_id,
	    sdu_interval_c, sdu_interval_p, worst_case_sca, packing, framing,
	    max_latency_c, max_latency_p, cis_count, recs, off,
	    out_cig_id, out_cis_count, out_cis_handles));
}

/*
 * Set up an HCI-transport ISO data path on one direction of an
 * established CIS/BIS (§7.8.109).  Data_Path_ID 0x00 selects the HCI
 * transport; the Transparent coding format (0x03, with zero Company and
 * Vendor Codec IDs) forwards SDUs unframed by any codec, which is what a
 * host that carries raw isochronous payload over the ISO socket wants.
 */
int
hci_le_setup_iso_hci_path(int hci_fd, uint16_t con_handle, uint8_t direction)
{
	/* Codec_ID: Coding_Format(1)=Transparent, Company(2)=0, Vendor(2)=0. */
	static const uint8_t transparent_codec[5] = { 0x03, 0, 0, 0, 0 };

	return (hci_le_setup_iso_data_path(hci_fd, con_handle, direction,
	    HCI_ISO_PATH_HCI, transparent_codec, 0, 0, NULL));
}

/*
 * Set up the data path(s) a newly established isochronous stream needs
 * to carry payload (§7.8.109):
 *   - a CIS is bidirectional, so both Input (Host->Controller) and
 *     Output (Controller->Host) are set up;
 *   - a BIS the local device broadcasts sources SDUs, so only Input;
 *   - a BIS the local device is synchronized to sinks SDUs, so only
 *     Output.
 * Returns the number of directions successfully set up.  A CIS whose
 * peer configured only one direction (the other Max_SDU is zero) has the
 * unused direction rejected by the Controller with Command Disallowed;
 * that is logged and does not fail the established stream.
 */
int
hci_le_setup_iso_stream_paths(int hci_fd, uint16_t con_handle,
    enum hci_iso_stream_kind kind)
{
	int ok = 0;

	switch (kind) {
	case HCI_ISO_STREAM_CIS:
		if (hci_le_setup_iso_hci_path(hci_fd, con_handle,
		    HCI_ISO_DIR_INPUT) == 0)
			ok++;
		if (hci_le_setup_iso_hci_path(hci_fd, con_handle,
		    HCI_ISO_DIR_OUTPUT) == 0)
			ok++;
		break;
	case HCI_ISO_STREAM_BIS_SOURCE:
		if (hci_le_setup_iso_hci_path(hci_fd, con_handle,
		    HCI_ISO_DIR_INPUT) == 0)
			ok++;
		break;
	case HCI_ISO_STREAM_BIS_SINK:
		if (hci_le_setup_iso_hci_path(hci_fd, con_handle,
		    HCI_ISO_DIR_OUTPUT) == 0)
			ok++;
		break;
	}

	LOG_HCI(1, "ISO data path setup: handle=%04x kind=%d dirs=%d",
	    con_handle, (int)kind, ok);
	return (ok);
}

/* ----------------------------------------------------------------
 * LE Ping (Authenticated Payload Timeout) — BT 4.1
 * Core Spec Vol 4 Part E Sections 7.3.93-7.3.94
 * ---------------------------------------------------------------- */

int
hci_le_read_auth_payload_timeout(int fd, uint16_t con_handle,
    uint16_t *timeout)
{
	struct bt_devreq r;
	ng_hci_read_auth_payload_timeout_cp cp;
	ng_hci_read_auth_payload_timeout_rp rp;

	if (con_handle > 0x0EFF) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.con_handle = htole16(con_handle);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    NG_HCI_OCF_READ_AUTH_PAYLOAD_TIMEOUT);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "Read Authenticated Payload Timeout failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	if (timeout != NULL)
		*timeout = le16toh(rp.timeout);
	LOG_HCI(1, "auth payload timeout: con=%04x timeout=%u (x10ms)",
	    con_handle, le16toh(rp.timeout));
	return (0);
}

int
hci_le_write_auth_payload_timeout(int fd, uint16_t con_handle,
    uint16_t timeout)
{
	struct bt_devreq r;
	ng_hci_write_auth_payload_timeout_cp cp;
	ng_hci_write_auth_payload_timeout_rp rp;

	if (con_handle > 0x0EFF || timeout == 0) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.con_handle = htole16(con_handle);
	cp.timeout = htole16(timeout);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    NG_HCI_OCF_WRITE_AUTH_PAYLOAD_TIMEOUT);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "Write Authenticated Payload Timeout failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "auth payload timeout set: con=%04x timeout=%u (x10ms)",
	    con_handle, timeout);
	return (0);
}

/*
 * Set Min Encryption Key Size (BT 5.3).
 * Core Spec Vol 4 Part E §7.3.102
 *
 * Note: This is a BT 5.3 command and is not called by the daemon.
 * Provided as an API stub for potential future use.
 */
int
hci_set_min_enc_key_size(int fd, uint8_t key_size)
{
	ng_hci_set_min_enc_key_size_cp	cp;
	ng_hci_set_min_enc_key_size_rp	rp;
	struct bt_devreq		r;

	if (key_size < 7 || key_size > 16) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.min_enc_key_size = key_size;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    NG_HCI_OCF_SET_MIN_ENC_KEY_SIZE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "Set Min Encryption Key Size failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "min encryption key size set to %u bytes", key_size);
	return (0);
}
