/*
 * ng_hci_evnt.c
 */

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) Maksim Yevmenkin <m_evmenkin@yahoo.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: ng_hci_evnt.c,v 1.6 2003/09/08 18:57:51 max Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/endian.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/queue.h>
#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/bluetooth/include/ng_bluetooth.h>
#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/hci/ng_hci_var.h>
#include <netgraph/bluetooth/hci/ng_hci_cmds.h>
#include <netgraph/bluetooth/hci/ng_hci_evnt.h>
#include <netgraph/bluetooth/hci/ng_hci_ulpi.h>
#include <netgraph/bluetooth/hci/ng_hci_misc.h>

#include <sys/sdt.h>

SDT_PROVIDER_DECLARE(bluetooth);

/* LE connection lifecycle */
SDT_PROBE_DEFINE3(bluetooth, hci, le_connection, complete,
    "uint16_t",		/* connection handle */
    "uint8_t",		/* role (0=central, 1=peripheral) */
    "uint8_t *"		/* peer address (6 bytes) */
);

SDT_PROBE_DEFINE2(bluetooth, hci, encryption, change,
    "uint16_t",		/* connection handle */
    "uint8_t"		/* encryption_enable */
);

SDT_PROBE_DEFINE1(bluetooth, hci, le_connection, disconnect,
    "uint16_t"		/* connection handle */
);

/* LE connection parameter changes */
SDT_PROBE_DEFINE4(bluetooth, hci, le_connection, param_change,
    "uint16_t",		/* connection handle */
    "uint16_t",		/* connection interval */
    "uint16_t",		/* peripheral latency */
    "uint16_t"		/* supervision timeout */
);

/* LE data length change */
SDT_PROBE_DEFINE3(bluetooth, hci, le_data_length, change,
    "uint16_t",		/* connection handle */
    "uint16_t",		/* max tx octets */
    "uint16_t"		/* max rx octets */
);

/* LE PHY update */
SDT_PROBE_DEFINE3(bluetooth, hci, le_phy, update,
    "uint16_t",		/* connection handle */
    "uint8_t",		/* tx PHY (1=1M, 2=2M, 3=Coded) */
    "uint8_t"		/* rx PHY */
);

/* ISO CIS lifecycle */
SDT_PROBE_DEFINE2(bluetooth, hci, iso_cis, established,
    "uint16_t",		/* CIS connection handle */
    "uint8_t"		/* status (0 = success) */
);

SDT_PROBE_DEFINE3(bluetooth, hci, iso_cis, request,
    "uint16_t",		/* CIS handle */
    "uint16_t",		/* ACL handle */
    "uint8_t"		/* accepted (1) or rejected (0) */
);

/* Security audit probes */
SDT_PROBE_DEFINE2(bluetooth, security, pairing, complete,
    "uint16_t",		/* connection handle */
    "uint8_t"		/* encryption_key_size (0 if unknown/v1) */
);

SDT_PROBE_DEFINE3(bluetooth, security, ltk, request,
    "uint16_t",		/* connection handle */
    "uint16_t",		/* encrypted_diversifier (EDIV) */
    "uint64_t"		/* random_number */
);

SDT_PROBE_DEFINE1(bluetooth, security, auth_payload, timeout,
    "uint16_t"		/* connection handle */
);

/* ISO BIG lifecycle */
SDT_PROBE_DEFINE3(bluetooth, hci, iso_big, complete,
    "uint8_t",		/* BIG handle */
    "uint8_t",		/* status */
    "uint8_t"		/* num_bis */
);

SDT_PROBE_DEFINE3(bluetooth, hci, iso_big, sync,
    "uint8_t",		/* BIG handle */
    "uint8_t",		/* status */
    "uint8_t"		/* num_bis */
);

/******************************************************************************
 ******************************************************************************
 **                     HCI event processing module
 ******************************************************************************
 ******************************************************************************/

/* 
 * Event processing routines 
 */

static int inquiry_result             (ng_hci_unit_p, struct mbuf *);
static int inquiry_result_with_rssi   (ng_hci_unit_p, struct mbuf *);
static int ext_inquiry_result         (ng_hci_unit_p, struct mbuf *);
static int con_compl                  (ng_hci_unit_p, struct mbuf *);
static int con_req                    (ng_hci_unit_p, struct mbuf *);
static int discon_compl               (ng_hci_unit_p, struct mbuf *);
static int encryption_change          (ng_hci_unit_p, struct mbuf *);
static int read_remote_features_compl (ng_hci_unit_p, struct mbuf *);
static int qos_setup_compl            (ng_hci_unit_p, struct mbuf *);
static int hardware_error             (ng_hci_unit_p, struct mbuf *);
static int role_change                (ng_hci_unit_p, struct mbuf *);
static int num_compl_pkts             (ng_hci_unit_p, struct mbuf *);
static int mode_change                (ng_hci_unit_p, struct mbuf *);
static int data_buffer_overflow       (ng_hci_unit_p, struct mbuf *);
static int read_clock_offset_compl    (ng_hci_unit_p, struct mbuf *);
static int qos_violation              (ng_hci_unit_p, struct mbuf *);
static int page_scan_mode_change      (ng_hci_unit_p, struct mbuf *);
static int page_scan_rep_mode_change  (ng_hci_unit_p, struct mbuf *);
static int encryption_change_v2        (ng_hci_unit_p, struct mbuf *);
static int sync_con_compl             (ng_hci_unit_p, struct mbuf *);
static int sync_con_queue             (ng_hci_unit_p, ng_hci_unit_con_p, int);
static int send_data_packets          (ng_hci_unit_p, int, int);
static int le_event		      (ng_hci_unit_p, struct mbuf *);

/*
 * Process HCI event packet
 */

int
ng_hci_process_event(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_event_pkt_t	*hdr = NULL;
	int			 error = 0;

	/* Get event packet header */
	NG_HCI_M_PULLUP(event, sizeof(*hdr));
	if (event == NULL)
		return (ENOBUFS);

	hdr = mtod(event, ng_hci_event_pkt_t *);

	NG_HCI_INFO(
"%s: %s - got HCI event=%#x, length=%d\n",
		__func__, NG_NODE_NAME(unit->node), hdr->event, hdr->length);

	/* Validate that the mbuf contains the full event payload */
	if (event->m_pkthdr.len < (int)(sizeof(*hdr) + hdr->length)) {
		NG_HCI_WARN(
"%s: truncated HCI event (expected %d, got %d)\n",
			__func__,
			(int)(sizeof(*hdr) + hdr->length),
			event->m_pkthdr.len);
		NG_FREE_M(event);
		return (EMSGSIZE);
	}

	/* Get rid of event header and process event */
	m_adj(event, sizeof(*hdr));

	switch (hdr->event) {
	case NG_HCI_EVENT_INQUIRY_COMPL:
	case NG_HCI_EVENT_RETURN_LINK_KEYS:
	case NG_HCI_EVENT_PIN_CODE_REQ:
	case NG_HCI_EVENT_LINK_KEY_REQ:
	case NG_HCI_EVENT_LINK_KEY_NOTIFICATION:
	case NG_HCI_EVENT_LOOPBACK_COMMAND:
	case NG_HCI_EVENT_AUTH_COMPL:
	case NG_HCI_EVENT_CHANGE_CON_LINK_KEY_COMPL:
	case NG_HCI_EVENT_MASTER_LINK_KEY_COMPL:
	case NG_HCI_EVENT_FLUSH_OCCUR:	/* XXX Do we have to handle it? */
	case NG_HCI_EVENT_MAX_SLOT_CHANGE:
	case NG_HCI_EVENT_CON_PKT_TYPE_CHANGED:
	case NG_HCI_EVENT_BT_LOGO:
	case NG_HCI_EVENT_VENDOR:
	case NG_HCI_EVENT_REMOTE_NAME_REQ_COMPL:
	case NG_HCI_EVENT_READ_REMOTE_VER_INFO_COMPL:
	case NG_HCI_EVENT_READ_REMOTE_EXT_FEATURES_COMPL:
	case NG_HCI_EVENT_IO_CAPABILITY_REQUEST:
	case NG_HCI_EVENT_IO_CAPABILITY_RESPONSE:
	case NG_HCI_EVENT_SIMPLE_PAIRING_COMPLETE:
	case NG_HCI_EVENT_SNIFF_SUBRATING:
	case NG_HCI_EVENT_ENCRYPTION_KEY_REFRESH:
	case NG_HCI_EVENT_USER_CONFIRMATION_REQUEST:
	case NG_HCI_EVENT_USER_PASSKEY_REQUEST:
	case NG_HCI_EVENT_SYNC_TRAIN_COMPLETE:
	case NG_HCI_EVENT_SYNC_TRAIN_RECEIVED:
	case NG_HCI_EVENT_CPB_RECEIVE:
	case NG_HCI_EVENT_CPB_TIMEOUT:
	case NG_HCI_EVENT_TRUNCATED_PAGE_COMPLETE:
	case NG_HCI_EVENT_PERIPHERAL_PAGE_RSP_TIMEOUT:
	case NG_HCI_EVENT_CPB_CHANNEL_MAP_CHANGE:
	case NG_HCI_EVENT_SYNC_CON_CHANGED:
	case NG_HCI_EVENT_FLOW_SPEC_COMPL:
	case NG_HCI_EVENT_REMOTE_OOB_DATA_REQ:
	case NG_HCI_EVENT_LINK_SUPERV_TO_CHANGED:
	case NG_HCI_EVENT_ENH_FLUSH_COMPL:
	case NG_HCI_EVENT_USER_PASSKEY_NOTIFICATION:
	case NG_HCI_EVENT_KEYPRESS_NOTIFICATION:
	case NG_HCI_EVENT_REM_HOST_SUPP_FEAT_NOTIFI:
	case NG_HCI_EVENT_NUM_COMPL_DATA_BLOCKS:
		/* These do not need post processing */
		NG_FREE_M(event);
		break;
	case NG_HCI_EVENT_AUTH_PAYLOAD_TIMEOUT: {
		ng_hci_auth_payload_timeout_ep	*apt;

		NG_HCI_M_PULLUP(event, sizeof(*apt));
		if (event != NULL) {
			apt = mtod(event, ng_hci_auth_payload_timeout_ep *);
			SDT_PROBE1(bluetooth, security, auth_payload, timeout,
			    NG_HCI_CON_HANDLE(le16toh(apt->con_handle)));
			NG_HCI_WARN(
"%s: %s - Authenticated Payload Timeout, handle=%d\n",
			    __func__, NG_NODE_NAME(unit->node),
			    NG_HCI_CON_HANDLE(le16toh(apt->con_handle)));
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_EVENT_LE:
		error = le_event(unit, event);
		break;

	case NG_HCI_EVENT_INQUIRY_RESULT:
		error = inquiry_result(unit, event);
		break;

	case NG_HCI_EVENT_INQUIRY_RESULT_WITH_RSSI:
		error = inquiry_result_with_rssi(unit, event);
		break;

	case NG_HCI_EVENT_EXT_INQUIRY_RESULT:
		error = ext_inquiry_result(unit, event);
		break;

	case NG_HCI_EVENT_CON_COMPL:
		error = con_compl(unit, event);
		break;

	case NG_HCI_EVENT_CON_REQ:
		error = con_req(unit, event);
		break;

	case NG_HCI_EVENT_DISCON_COMPL:
		error = discon_compl(unit, event);
		break;

	case NG_HCI_EVENT_ENCRYPTION_CHANGE:
		error = encryption_change(unit, event);
		break;

	case NG_HCI_EVENT_ENCRYPTION_CHANGE_V2:
		error = encryption_change_v2(unit, event);
		break;

	case NG_HCI_EVENT_SYNC_CON_COMPL:
		error = sync_con_compl(unit, event);
		break;

	case NG_HCI_EVENT_READ_REMOTE_FEATURES_COMPL:
		error = read_remote_features_compl(unit, event);
		break;

	case NG_HCI_EVENT_QOS_SETUP_COMPL:
		error = qos_setup_compl(unit, event);
		break;

	case NG_HCI_EVENT_COMMAND_COMPL:
		error = ng_hci_process_command_complete(unit, event);
		break;

	case NG_HCI_EVENT_COMMAND_STATUS:
		error = ng_hci_process_command_status(unit, event);
		break;

	case NG_HCI_EVENT_HARDWARE_ERROR:
		error = hardware_error(unit, event);
		break;

	case NG_HCI_EVENT_ROLE_CHANGE:
		error = role_change(unit, event);
		break;

	case NG_HCI_EVENT_NUM_COMPL_PKTS:
		error = num_compl_pkts(unit, event);
		break;

	case NG_HCI_EVENT_MODE_CHANGE:
		error = mode_change(unit, event);
		break;

	case NG_HCI_EVENT_DATA_BUFFER_OVERFLOW:
		error = data_buffer_overflow(unit, event);
		break;

	case NG_HCI_EVENT_READ_CLOCK_OFFSET_COMPL:
		error = read_clock_offset_compl(unit, event);
		break;

	case NG_HCI_EVENT_QOS_VIOLATION:
		error = qos_violation(unit, event);
		break;

	case NG_HCI_EVENT_PAGE_SCAN_MODE_CHANGE:
		error = page_scan_mode_change(unit, event);
		break;

	case NG_HCI_EVENT_PAGE_SCAN_REP_MODE_CHANGE:
		error = page_scan_rep_mode_change(unit, event);
		break;

	default:
		NG_FREE_M(event);
		error = EINVAL;
		break;
	}

	return (error);
} /* ng_hci_process_event */

/*
 * Send ACL and/or SCO data to the unit driver
 */

void
ng_hci_send_data(ng_hci_unit_p unit)
{
	int	count;

	/* Send ACL data */
	NG_HCI_BUFF_ACL_AVAIL(unit->buffer, count);

	NG_HCI_INFO(
"%s: %s - sending ACL data packets, count=%d\n",
		__func__, NG_NODE_NAME(unit->node), count);

	if (count > 0) {
		count = send_data_packets(unit, NG_HCI_LINK_ACL, count);
		NG_HCI_STAT_ACL_SENT(unit->stat, count);
		NG_HCI_BUFF_ACL_USE(unit->buffer, count);
	}

	/* Send SCO data */
	NG_HCI_BUFF_SCO_AVAIL(unit->buffer, count);

	NG_HCI_INFO(
"%s: %s - sending SCO data packets, count=%d\n",
		__func__, NG_NODE_NAME(unit->node), count);

	if (count > 0) {
		count = send_data_packets(unit, NG_HCI_LINK_SCO, count);
		NG_HCI_STAT_SCO_SENT(unit->stat, count);
		NG_HCI_BUFF_SCO_USE(unit->buffer, count);
	}

	/* Send LE data from dedicated LE buffers if available */
	if (unit->buffer.le_pkts > 0) {
		NG_HCI_BUFF_LE_AVAIL(unit->buffer, count);

		NG_HCI_INFO(
"%s: %s - sending LE data packets, count=%d\n",
			__func__, NG_NODE_NAME(unit->node), count);

		if (count > 0) {
			count = send_data_packets(unit,
			    NG_HCI_LINK_LE_PUBLIC, count);
			NG_HCI_STAT_ACL_SENT(unit->stat, count);
			NG_HCI_BUFF_LE_USE(unit->buffer, count);
		}
	}

	/* Send ISO data from dedicated ISO buffers if available */
	if (unit->buffer.iso_pkts > 0) {
		NG_HCI_BUFF_ISO_AVAIL(unit->buffer, count);

		NG_HCI_INFO(
"%s: %s - sending ISO data packets, count=%d\n",
			__func__, NG_NODE_NAME(unit->node), count);

		if (count > 0) {
			count = send_data_packets(unit,
			    NG_HCI_LINK_ISO_CIS, count);
			NG_HCI_STAT_ACL_SENT(unit->stat, count);
			NG_HCI_BUFF_ISO_USE(unit->buffer, count);
		}
	}
} /* ng_hci_send_data */

/*
 * Send data packets to the lower layer.
 */

static int
send_data_packets(ng_hci_unit_p unit, int link_type, int limit)
{
	ng_hci_unit_con_p	con = NULL, winner = NULL;
	int			reallink_type;
	item_p			item = NULL;
	int			min_pending, total_sent, sent, error, v;

	for (total_sent = 0; limit > 0; ) {
		min_pending = 0x0fffffff;
		winner = NULL;

		/*
		 * Find the connection that has has data to send 
		 * and the smallest number of pending packets
		 */

		LIST_FOREACH(con, &unit->con_list, next) {
			if (con->link_type == NG_HCI_LINK_SCO)
				reallink_type = NG_HCI_LINK_SCO;
			else if ((con->link_type == NG_HCI_LINK_LE_PUBLIC ||
				  con->link_type == NG_HCI_LINK_LE_RANDOM) &&
				 unit->buffer.le_pkts > 0)
				reallink_type = NG_HCI_LINK_LE_PUBLIC;
			else if ((con->link_type == NG_HCI_LINK_ISO_CIS ||
				  con->link_type == NG_HCI_LINK_ISO_BIS) &&
				 unit->buffer.iso_pkts > 0)
				reallink_type = NG_HCI_LINK_ISO_CIS;
			else
				reallink_type = NG_HCI_LINK_ACL;
			if (reallink_type != link_type){
				continue;
			}
			if (NG_BT_ITEMQ_LEN(&con->conq) == 0)
				continue;
        
			if (con->pending < min_pending) {
				winner = con;
				min_pending = con->pending;
			}
		}

	        if (winner == NULL)
			break;

		/* 
		 * OK, we have a winner now send as much packets as we can
		 * Count the number of packets we have sent and then sync
		 * winner connection queue.
		 */

		for (sent = 0; limit > 0; limit --, total_sent ++, sent ++) {
			NG_BT_ITEMQ_DEQUEUE(&winner->conq, item);
			if (item == NULL)
				break;
		
			NG_HCI_INFO(
"%s: %s - sending data packet, handle=%d, len=%d\n",
				__func__, NG_NODE_NAME(unit->node), 
				winner->con_handle, NGI_M(item)->m_pkthdr.len);

			/* Check if driver hook still there */
			v = (unit->drv != NULL && NG_HOOK_IS_VALID(unit->drv));
			if (!v || (unit->state & NG_HCI_UNIT_READY) != 
					NG_HCI_UNIT_READY) {
				NG_HCI_ERR(
"%s: %s - could not send data. Hook \"%s\" is %svalid, state=%#x\n",
					__func__, NG_NODE_NAME(unit->node),
					NG_HCI_HOOK_DRV, ((v)? "" : "not "),
					unit->state);

				NG_FREE_ITEM(item);
				error = ENOTCONN;
			} else {
				v = NGI_M(item)->m_pkthdr.len;

				/* Give packet to raw hook */
				ng_hci_mtap(unit, NGI_M(item));

				/* ... and forward item to the driver */
				NG_FWD_ITEM_HOOK(error, item, unit->drv);
			}

			if (error != 0) {
				NG_HCI_ERR(
"%s: %s - could not send data packet, handle=%d, error=%d\n",
					__func__, NG_NODE_NAME(unit->node),
					winner->con_handle, error);
				break;
			}

			winner->pending ++;
			NG_HCI_STAT_BYTES_SENT(unit->stat, v);
		}

		/*
		 * Sync connection queue for the winner
		 */
		sync_con_queue(unit, winner, sent);
	}

	return (total_sent);
} /* send_data_packets */

/*
 * Send flow control messages to the upper layer
 */

static int
sync_con_queue(ng_hci_unit_p unit, ng_hci_unit_con_p con, int completed)
{
	hook_p				 hook = NULL;
	struct ng_mesg			*msg = NULL;
	ng_hci_sync_con_queue_ep	*state = NULL;
	int				 error;

	if (con->link_type == NG_HCI_LINK_SCO)
		hook = unit->sco;
	else if ((con->link_type == NG_HCI_LINK_ISO_CIS ||
		  con->link_type == NG_HCI_LINK_ISO_BIS) &&
		 unit->iso != NULL)
		hook = unit->iso;
	else
		hook = unit->acl;
	if (hook == NULL || NG_HOOK_NOT_VALID(hook))
		return (ENOTCONN);

	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_SYNC_CON_QUEUE,
		sizeof(*state), M_NOWAIT);
	if (msg == NULL)
		return (ENOMEM);

	state = (ng_hci_sync_con_queue_ep *)(msg->data);
	state->con_handle = con->con_handle;
	state->completed = completed;

	NG_SEND_MSG_HOOK(error, unit->node, msg, hook, 0);

	return (error);
} /* sync_con_queue */
/* le meta event */
/* Inquiry result event */
static int
le_advertizing_report(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_le_advertising_report_ep	*ep = NULL;
	ng_hci_neighbor_p		 n = NULL;
	bdaddr_t			 bdaddr;
	int				 error = 0;
	int				 num_reports = 0;
	u_int8_t addr_type;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_le_advertising_report_ep *);
	num_reports = ep->num_reports;
	m_adj(event, sizeof(*ep));
	ep = NULL;

	for (; num_reports > 0; num_reports --) {
		/*
		 * Each report: event_type(1) + addr_type(1) + bdaddr(6)
		 *              + length_data(1) + data(N) + rssi(1)
		 * Minimum per report (with length_data=0): 10 bytes.
		 */
		if (event->m_pkthdr.len < 10) {
			NG_HCI_WARN("%s: truncated advertising report\n",
			    __func__);
			break;
		}

		/* event_type */
		m_adj(event, sizeof(u_int8_t));

		/* Get remote unit address */
		NG_HCI_M_PULLUP(event, sizeof(u_int8_t));
		if (event == NULL) {
			error = ENOBUFS;
			goto out;
		}
		addr_type = *mtod(event, u_int8_t *);
		m_adj(event, sizeof(u_int8_t));

		if (event->m_pkthdr.len < (int)sizeof(bdaddr)) {
			NG_HCI_WARN("%s: truncated bdaddr in adv report\n",
			    __func__);
			break;
		}
		m_copydata(event, 0, sizeof(bdaddr), (caddr_t) &bdaddr);
		m_adj(event, sizeof(bdaddr));
		
		/* Lookup entry in the cache */
		n = ng_hci_get_neighbor(unit, &bdaddr, (addr_type) ? NG_HCI_LINK_LE_RANDOM:NG_HCI_LINK_LE_PUBLIC);
		if (n == NULL) {
			/* Create new entry */
			n = ng_hci_new_neighbor(unit);
			if (n == NULL) {
				error = ENOMEM;
				break;
			}
			bcopy(&bdaddr, &n->bdaddr, sizeof(n->bdaddr));
			n->addrtype = (addr_type)? NG_HCI_LINK_LE_RANDOM :
			  NG_HCI_LINK_LE_PUBLIC;
			
		} else
			getmicrotime(&n->updated);
		
		{
			/* 
			 * TODO: Make these information 
			 * Available from userland.
			 */
			u_int8_t length_data;
			
			NG_HCI_M_PULLUP(event, sizeof(u_int8_t));
			if (event == NULL)
				goto out;
			length_data = *mtod(event, u_int8_t *);
			m_adj(event, sizeof(u_int8_t));
			n->extinq_size = (length_data < NG_HCI_EXTINQ_MAX)?
				length_data : NG_HCI_EXTINQ_MAX;
			
			/*Advertizement data*/
			if (event->m_pkthdr.len < length_data) {
				NG_HCI_WARN("%s: truncated adv data\n",
				    __func__);
				break;
			}
			if (n->extinq_size > 0) {
				NG_HCI_M_PULLUP(event, n->extinq_size);
				if (event == NULL)
					goto out;
				m_copydata(event, 0, n->extinq_size,
				    n->extinq_data);
			}
			/* Skip the FULL advertised data length, not just
			 * the clamped extinq_size, to keep parsing aligned */
			m_adj(event, length_data);
			NG_HCI_M_PULLUP(event, sizeof(char));
			if (event == NULL)
				goto out;				
			n->page_scan_mode = *mtod(event, char *);
			m_adj(event, sizeof(u_int8_t));
		}
	}
 out:
	NG_FREE_M(event);

	return (error);
} /* inquiry_result */

/*
 * Common handler for LE Connection Complete and LE Enhanced
 * Connection Complete events.  Takes the extracted fields so
 * both event formats share one code path.
 */
static int
le_con_compl_common(ng_hci_unit_p unit, u_int8_t status, u_int16_t handle,
    u_int8_t role, u_int8_t addr_type, bdaddr_t *addr)
{
	ng_hci_unit_con_p	con = NULL;
	int			link_type, error = 0;
	uint8_t			uclass[3] = {0, 0, 0};

	link_type = (addr_type == 0x01 || addr_type == 0x03) ?
	    NG_HCI_LINK_LE_RANDOM : NG_HCI_LINK_LE_PUBLIC;

	LIST_FOREACH(con, &unit->con_list, next)
		if (con->link_type == link_type &&
		    con->state == NG_HCI_CON_W4_CONN_COMPLETE &&
		    bcmp(&con->bdaddr, addr, sizeof(bdaddr_t)) == 0)
			break;

	if (con == NULL) {
		if (status != 0)
			return (0);

		con = ng_hci_new_con(unit, link_type);
		if (con == NULL)
			return (ENOMEM);

		bcopy(addr, &con->bdaddr, sizeof(con->bdaddr));
		con->con_handle = NG_HCI_CON_HANDLE(le16toh(handle));
		con->encryption_mode = NG_HCI_ENCRYPTION_MODE_NONE;

		/*
		 * LE connections are already established at the
		 * controller level when we receive this event.
		 * Send LP_CON_IND so L2CAP creates a connection
		 * descriptor, but do NOT start a connection timeout
		 * or wait for Accept_Connection -- neither applies
		 * to LE.  Then transition directly to OPEN and send
		 * LP_CON_CFM so L2CAP opens the ATT/SMP channels.
		 *
		 * L2CAP will reply with LP_CON_RSP (to "accept"
		 * the connection), but ng_hci_lp_con_rsp will not
		 * find a matching connection in W4_LP_CON_RSP state
		 * and will silently drop it -- this is correct
		 * because LE needs no Accept_Connection command.
		 */
		con->state = NG_HCI_CON_W4_LP_CON_RSP;
		error = ng_hci_lp_con_ind(con, uclass);
		if (error != 0) {
			ng_hci_free_con(con);
			return (error);
		}

		con->state = NG_HCI_CON_OPEN;
		con->flags |= NG_HCI_CON_NOTIFY_ACL;

		ng_hci_lp_con_cfm(con, 0);

		SDT_PROBE3(bluetooth, hci, le_connection, complete,
		    con->con_handle, role, &addr->b[0]);

		return (0);
	} else if ((error = ng_hci_con_untimeout(con)) != 0)
		return (error);

	con->con_handle = NG_HCI_CON_HANDLE(le16toh(handle));
	con->encryption_mode = NG_HCI_ENCRYPTION_MODE_NONE;

	ng_hci_lp_con_cfm(con, status);

	if (status != 0)
		ng_hci_free_con(con);
	else {
		con->state = NG_HCI_CON_OPEN;
		SDT_PROBE3(bluetooth, hci, le_connection, complete,
		    con->con_handle, role, &addr->b[0]);
	}

	return (0);
}

static int
le_connection_complete(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_le_connection_complete_ep *ep;
	int error;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_le_connection_complete_ep *);
	error = le_con_compl_common(unit, ep->status, ep->handle,
	    ep->role, ep->address_type, &ep->address);

	NG_FREE_M(event);
	return (error);
}

static int
le_enh_connection_complete(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_le_enh_conn_compl_ep *ep;
	int error;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_le_enh_conn_compl_ep *);
	error = le_con_compl_common(unit, ep->status, ep->connection_handle,
	    ep->role, ep->peer_addr_type, &ep->peer_addr);

	NG_FREE_M(event);
	return (error);
}

static int le_connection_update(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_connection_update_complete_ep	*ep;
	ng_hci_unit_con_p			 con;
	u_int16_t				 h;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_connection_update_complete_ep *);

	if (ep->status == 0) {
		h = NG_HCI_CON_HANDLE(le16toh(ep->connection_handle));
		con = ng_hci_con_by_handle(unit, h);
		if (con != NULL) {
			SDT_PROBE4(bluetooth, hci, le_connection,
			    param_change, h,
			    le16toh(ep->conn_interval),
			    le16toh(ep->conn_latency),
			    le16toh(ep->supervision_timeout));
			NG_HCI_INFO(
"%s: %s - LE connection update complete, handle=%d, "
"interval=%d, latency=%d, timeout=%d\n",
				__func__, NG_NODE_NAME(unit->node), h,
				le16toh(ep->conn_interval),
				le16toh(ep->conn_latency),
				le16toh(ep->supervision_timeout));
		} else {
			NG_HCI_ALERT(
"%s: %s - LE connection update complete, invalid handle=%d\n",
				__func__, NG_NODE_NAME(unit->node), h);
		}
	} else {
		NG_HCI_ERR(
"%s: %s - LE connection update failed, status=%d\n",
			__func__, NG_NODE_NAME(unit->node), ep->status);
	}

	NG_FREE_M(event);
	return (0);
}

/*
 * LE Enhanced Connection Complete v2 (7.7.65.41, BT 5.3)
 *
 * Same core fields as v1 plus advertising_handle and sync_handle.
 * Reuse le_con_compl_common() since the connection setup logic is
 * identical.
 */
static int
le_enh_connection_complete_v2(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_le_enh_conn_compl_v2_ep *ep;
	int error;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_le_enh_conn_compl_v2_ep *);

	NG_HCI_INFO(
"%s: %s - LE Enhanced Connection Complete v2, status=%d handle=%d "
"adv_handle=%d sync_handle=%d\n",
	    __func__, NG_NODE_NAME(unit->node),
	    ep->status, NG_HCI_CON_HANDLE(le16toh(ep->connection_handle)),
	    ep->advertising_handle, le16toh(ep->sync_handle));

	error = le_con_compl_common(unit, ep->status, ep->connection_handle,
	    ep->role, ep->peer_addr_type, &ep->peer_addr);

	NG_FREE_M(event);
	return (error);
}

static int
le_event(ng_hci_unit_p unit, struct mbuf *event)
{
	int error = 0;
	ng_hci_le_ep *lep;

	NG_HCI_M_PULLUP(event, sizeof(*lep));
	if (event == NULL) {
		return ENOBUFS;
	}
	lep = mtod(event, ng_hci_le_ep *);
	{
	u_int8_t subevent = lep->subevent_code;
	m_adj(event, sizeof(*lep));
	switch (subevent) {
	case NG_HCI_LEEV_CON_COMPL:
		error = le_connection_complete(unit, event);
		break;
	case NG_HCI_LEEV_ADVREP:
		error = le_advertizing_report(unit, event);
		break;
	case NG_HCI_LEEV_CON_UPDATE_COMPL:
		error = le_connection_update(unit, event);
		break;
	case NG_HCI_LEEV_READ_REMOTE_FEATURES_COMPL: {
		ng_hci_le_read_remote_features_ep *rfep;
		ng_hci_unit_con_p rfcon;
		u_int16_t rfh;

		NG_HCI_M_PULLUP(event, sizeof(*rfep));
		if (event != NULL) {
			rfep = mtod(event,
			    ng_hci_le_read_remote_features_ep *);
			rfh = NG_HCI_CON_HANDLE(
			    le16toh(rfep->connection_handle));
			rfcon = ng_hci_con_by_handle(unit, rfh);
			if (rfcon != NULL && rfep->status == 0) {
				memcpy(&rfcon->le_features,
				    rfep->features,
				    sizeof(rfcon->le_features));
				rfcon->le_features =
				    le64toh(rfcon->le_features);
			}
			NG_HCI_INFO(
"%s: %s - LE read remote features complete, handle=%d, status=%d\n",
			    __func__, NG_NODE_NAME(unit->node),
			    rfh, rfep->status);
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_ENH_CONN_COMPL:
		error = le_enh_connection_complete(unit, event);
		break;

	case NG_HCI_LEEV_LONG_TERM_KEY_REQUEST: {
		/*
		 * The controller is asking for an LTK to encrypt a
		 * connection.  Userspace receives this event via the
		 * raw HCI socket (ng_hci_mtap) and must respond with
		 * LE_Long_Term_Key_Request_Reply or Negative_Reply.
		 */
		ng_hci_le_long_term_key_request_ep *ltkep;

		NG_HCI_M_PULLUP(event, sizeof(*ltkep));
		if (event != NULL) {
			ltkep = mtod(event,
			    ng_hci_le_long_term_key_request_ep *);
			SDT_PROBE3(bluetooth, security, ltk, request,
			    NG_HCI_CON_HANDLE(
			    le16toh(ltkep->connection_handle)),
			    le16toh(ltkep->encrypted_diversifier),
			    le64toh(ltkep->random_number));
		}
		NG_HCI_INFO(
"%s: %s - LE LTK request, userspace must reply via raw HCI\n",
			__func__, NG_NODE_NAME(unit->node));
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_DATA_LENGTH_CHANGE: {
		ng_hci_le_data_length_change_ep *dlep;
		ng_hci_unit_con_p con;
		u_int16_t h;

		NG_HCI_M_PULLUP(event, sizeof(*dlep));
		if (event != NULL) {
			dlep = mtod(event,
			    ng_hci_le_data_length_change_ep *);
			h = NG_HCI_CON_HANDLE(le16toh(dlep->connection_handle));
			con = ng_hci_con_by_handle(unit, h);
			if (con != NULL) {
				con->max_tx_octets = le16toh(dlep->max_tx_octets);
				con->max_rx_octets = le16toh(dlep->max_rx_octets);
			}
			SDT_PROBE3(bluetooth, hci, le_data_length, change,
			    h,
			    le16toh(dlep->max_tx_octets),
			    le16toh(dlep->max_rx_octets));
			NG_HCI_INFO(
"%s: %s - LE Data Length Change, handle=%d, tx=%d, rx=%d\n",
			    __func__, NG_NODE_NAME(unit->node), h,
			    le16toh(dlep->max_tx_octets),
			    le16toh(dlep->max_rx_octets));
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_PHY_UPDATE_COMPLETE: {
		ng_hci_le_phy_update_compl_ep	*phep;
		ng_hci_unit_con_p		 con;
		u_int16_t			 ph;

		NG_HCI_M_PULLUP(event, sizeof(*phep));
		if (event != NULL) {
			phep = mtod(event, ng_hci_le_phy_update_compl_ep *);
			ph = NG_HCI_CON_HANDLE(
			    le16toh(phep->connection_handle));
			SDT_PROBE3(bluetooth, hci, le_phy, update,
			    ph, phep->tx_phy, phep->rx_phy);
			con = ng_hci_con_by_handle(unit, ph);
			if (con != NULL) {
				con->tx_phy = phep->tx_phy;
				con->rx_phy = phep->rx_phy;
			}
			NG_HCI_INFO(
"%s: %s - LE PHY update, handle=%d, tx_phy=%d, rx_phy=%d\n",
			    __func__, NG_NODE_NAME(unit->node),
			    ph, phep->tx_phy, phep->rx_phy);
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_REMOTE_CONN_PARAM_REQUEST: {
		ng_hci_le_remote_conn_param_ep *rpep;
		ng_hci_unit_con_p con;
		u_int16_t h;

		NG_HCI_M_PULLUP(event, sizeof(*rpep));
		if (event != NULL) {
			rpep = mtod(event,
			    ng_hci_le_remote_conn_param_ep *);
			h = NG_HCI_CON_HANDLE(
			    le16toh(rpep->connection_handle));
			con = ng_hci_con_by_handle(unit, h);
			if (con != NULL) {
				struct __conn_param_reply {
					ng_hci_cmd_pkt_t		 hdr;
					ng_hci_le_remote_conn_param_req_reply_cp cp;
				} __attribute__ ((packed))	*req;
				struct mbuf			*m;

				MGETHDR(m, M_NOWAIT, MT_DATA);
				if (m != NULL) {
					m->m_pkthdr.len = m->m_len =
					    sizeof(*req);
					req = mtod(m,
					    struct __conn_param_reply *);
					req->hdr.type = NG_HCI_CMD_PKT;
					req->hdr.length = sizeof(req->cp);
					req->hdr.opcode = htole16(
					    NG_HCI_OPCODE(NG_HCI_OGF_LE,
					    NG_HCI_OCF_LE_REMOTE_CONN_PARAM_REQ_REPLY));

					req->cp.connection_handle =
					    htole16(NG_HCI_CON_HANDLE(le16toh(rpep->connection_handle)));
					req->cp.interval_min =
					    rpep->interval_min;
					req->cp.interval_max =
					    rpep->interval_max;
					req->cp.max_latency =
					    rpep->latency;
					req->cp.timeout =
					    rpep->timeout;
					req->cp.min_ce_length =
					    htole16(0x0000);
					req->cp.max_ce_length =
					    htole16(0x0000);

					NG_BT_MBUFQ_ENQUEUE(&unit->cmdq, m);
					if (!(unit->state &
					    NG_HCI_UNIT_COMMAND_PENDING))
						ng_hci_send_command(unit);
				}
			}
			NG_HCI_INFO(
"%s: %s - LE Remote Conn Param Request auto-accepted, handle=%d\n",
				__func__, NG_NODE_NAME(unit->node), h);
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_EXT_ADVREP:
		NG_HCI_INFO(
"%s: %s - LE extended advertising report\n",
		    __func__, NG_NODE_NAME(unit->node));
		NG_FREE_M(event);
		break;

	case NG_HCI_LEEV_READ_LOCAL_P256_PK_COMPL:
	case NG_HCI_LEEV_GEN_DHKEY_COMPL:
		NG_HCI_INFO(
"%s: %s - LE crypto subevent (passthrough)\n",
		    __func__, NG_NODE_NAME(unit->node));
		NG_FREE_M(event);
		break;

	case NG_HCI_LEEV_DIRECT_ADV_REP:
		NG_HCI_INFO(
"%s: %s - LE directed advertising report (passthrough)\n",
		    __func__, NG_NODE_NAME(unit->node));
		NG_FREE_M(event);
		break;

	case NG_HCI_LEEV_PER_ADV_SYNC_EST: {
		ng_hci_le_periodic_adv_sync_est_ep *ep;

		NG_HCI_M_PULLUP(event, sizeof(*ep));
		if (event != NULL) {
			ep = mtod(event,
			    ng_hci_le_periodic_adv_sync_est_ep *);
			NG_HCI_INFO(
"%s: %s - Periodic Adv Sync Established: status=%d sync_handle=%d sid=%d phy=%d\n",
			    __func__, NG_NODE_NAME(unit->node),
			    ep->status, le16toh(ep->sync_handle),
			    ep->advertising_sid, ep->advertiser_phy);
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_PER_ADV_REPORT: {
		ng_hci_le_periodic_adv_report_ep *ep;

		NG_HCI_M_PULLUP(event, sizeof(*ep));
		if (event != NULL) {
			ep = mtod(event,
			    ng_hci_le_periodic_adv_report_ep *);
			NG_HCI_INFO(
"%s: %s - Periodic Adv Report: sync_handle=%d tx_power=%d rssi=%d data_status=%d len=%d\n",
			    __func__, NG_NODE_NAME(unit->node),
			    le16toh(ep->sync_handle), (int8_t)ep->tx_power,
			    (int8_t)ep->rssi, ep->data_status,
			    ep->data_length);
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_PER_ADV_SYNC_LOST: {
		ng_hci_le_periodic_adv_sync_lost_ep *ep;

		NG_HCI_M_PULLUP(event, sizeof(*ep));
		if (event != NULL) {
			ep = mtod(event,
			    ng_hci_le_periodic_adv_sync_lost_ep *);
			NG_HCI_INFO(
"%s: %s - Periodic Adv Sync Lost: sync_handle=%d\n",
			    __func__, NG_NODE_NAME(unit->node),
			    le16toh(ep->sync_handle));
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_SCAN_TIMEOUT:
		/* No parameters (7.7.65.17) */
		NG_HCI_INFO(
"%s: %s - LE Scan Timeout\n",
		    __func__, NG_NODE_NAME(unit->node));
		NG_FREE_M(event);
		break;

	case NG_HCI_LEEV_ADV_SET_TERMINATED: {
		ng_hci_le_adv_set_terminated_ep	*ep;

		NG_HCI_M_PULLUP(event, sizeof(*ep));
		if (event != NULL) {
			ep = mtod(event,
			    ng_hci_le_adv_set_terminated_ep *);
			NG_HCI_INFO(
"%s: %s - Adv Set Terminated: status=%d adv_handle=%d conn_handle=%d num_events=%d\n",
			    __func__, NG_NODE_NAME(unit->node),
			    ep->status, ep->advertising_handle,
			    NG_HCI_CON_HANDLE(
			    le16toh(ep->connection_handle)),
			    ep->num_completed_ext_adv_events);
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_SCAN_REQ_RECEIVED: {
		ng_hci_le_scan_req_received_ep *ep;

		NG_HCI_M_PULLUP(event, sizeof(*ep));
		if (event != NULL) {
			ep = mtod(event,
			    ng_hci_le_scan_req_received_ep *);
			NG_HCI_INFO(
"%s: %s - Scan Req Received: adv_handle=%d scanner_addr_type=%d\n",
			    __func__, NG_NODE_NAME(unit->node),
			    ep->advertising_handle,
			    ep->scanner_addr_type);
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_CHAN_SEL_ALGO: {
		ng_hci_le_chan_sel_algo_ep	*ep;
		ng_hci_unit_con_p		 con;
		u_int16_t			 h;

		NG_HCI_M_PULLUP(event, sizeof(*ep));
		if (event != NULL) {
			ep = mtod(event,
			    ng_hci_le_chan_sel_algo_ep *);
			h = NG_HCI_CON_HANDLE(
			    le16toh(ep->connection_handle));
			con = ng_hci_con_by_handle(unit, h);
			NG_HCI_INFO(
"%s: %s - Channel Selection Algorithm: handle=%d algo=%d con=%s\n",
			    __func__, NG_NODE_NAME(unit->node),
			    h, ep->channel_selection_algorithm,
			    con != NULL ? "found" : "not found");
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_CONNECTIONLESS_IQ_REPORT: {
		ng_hci_le_connectionless_iq_report_ep *ep;

		NG_HCI_M_PULLUP(event, sizeof(*ep));
		if (event != NULL) {
			ep = mtod(event,
			    ng_hci_le_connectionless_iq_report_ep *);
			NG_HCI_INFO(
"%s: %s - Connectionless IQ Report: sync_handle=%d sample_count=%d cte_type=%d\n",
			    __func__, NG_NODE_NAME(unit->node),
			    le16toh(ep->sync_handle), ep->sample_count,
			    ep->cte_type);
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_CONNECTION_IQ_REPORT: {
		ng_hci_le_connection_iq_report_ep *ep;

		NG_HCI_M_PULLUP(event, sizeof(*ep));
		if (event != NULL) {
			ep = mtod(event,
			    ng_hci_le_connection_iq_report_ep *);
			NG_HCI_INFO(
"%s: %s - Connection IQ Report: handle=%d sample_count=%d rx_phy=%d\n",
			    __func__, NG_NODE_NAME(unit->node),
			    NG_HCI_CON_HANDLE(
			    le16toh(ep->connection_handle)),
			    ep->sample_count, ep->rx_phy);
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_CTE_REQUEST_FAILED: {
		ng_hci_le_cte_request_failed_ep *ep;

		NG_HCI_M_PULLUP(event, sizeof(*ep));
		if (event != NULL) {
			ep = mtod(event,
			    ng_hci_le_cte_request_failed_ep *);
			NG_HCI_INFO(
"%s: %s - CTE Request Failed: status=%d handle=%d\n",
			    __func__, NG_NODE_NAME(unit->node),
			    ep->status, NG_HCI_CON_HANDLE(
			    le16toh(ep->connection_handle)));
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_PATH_LOSS_THRESHOLD: {
		ng_hci_le_path_loss_threshold_ep	*pltep;

		NG_HCI_M_PULLUP(event, sizeof(*pltep));
		if (event != NULL) {
			pltep = mtod(event,
			    ng_hci_le_path_loss_threshold_ep *);
			NG_HCI_INFO(
"%s: %s - LE Path Loss Threshold: handle=%d path_loss=%d zone=%d\n",
			    __func__, NG_NODE_NAME(unit->node),
			    NG_HCI_CON_HANDLE(
			    le16toh(pltep->connection_handle)),
			    pltep->current_path_loss,
			    pltep->zone_entered);
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_TX_POWER_REPORTING: {
		ng_hci_le_tx_power_reporting_ep	*tpep;

		NG_HCI_M_PULLUP(event, sizeof(*tpep));
		if (event != NULL) {
			tpep = mtod(event,
			    ng_hci_le_tx_power_reporting_ep *);
			NG_HCI_INFO(
"%s: %s - LE TX Power Reporting: status=%d handle=%d reason=%d "
"phy=%d level=%d flag=%d delta=%d\n",
			    __func__, NG_NODE_NAME(unit->node),
			    tpep->status,
			    NG_HCI_CON_HANDLE(
			    le16toh(tpep->connection_handle)),
			    tpep->reason, tpep->phy,
			    (int8_t)tpep->tx_power_level,
			    tpep->tx_power_level_flag,
			    tpep->delta);
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_BIGINFO_ADV_REPORT: {
		ng_hci_le_biginfo_adv_report_ep	*biep;

		NG_HCI_M_PULLUP(event, sizeof(*biep));
		if (event != NULL) {
			biep = mtod(event,
			    ng_hci_le_biginfo_adv_report_ep *);
			NG_HCI_INFO(
"%s: %s - BIGInfo Adv Report: sync_handle=%d num_bis=%d "
"nse=%d iso_interval=%d encryption=%d\n",
			    __func__, NG_NODE_NAME(unit->node),
			    le16toh(biep->sync_handle), biep->num_bis,
			    biep->nse, le16toh(biep->iso_interval),
			    biep->encryption);
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_SUBRATE_CHANGE:
		NG_HCI_INFO(
"%s: %s - LE subrate change (passthrough)\n",
		    __func__, NG_NODE_NAME(unit->node));
		NG_FREE_M(event);
		break;

	case NG_HCI_LEEV_PER_ADV_SYNC_XFER_RCVD: {
		ng_hci_le_past_received_ep *ep;

		NG_HCI_M_PULLUP(event, sizeof(*ep));
		if (event != NULL) {
			ep = mtod(event,
			    ng_hci_le_past_received_ep *);
			NG_HCI_INFO(
"%s: %s - PAST Received: status=%d con_handle=%d sync_handle=%d sid=%d\n",
			    __func__, NG_NODE_NAME(unit->node),
			    ep->status,
			    NG_HCI_CON_HANDLE(
			    le16toh(ep->connection_handle)),
			    le16toh(ep->sync_handle),
			    ep->advertising_sid);
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_CIS_ESTABLISHED: {
		ng_hci_le_cis_established_ep	*cisep;
		ng_hci_unit_con_p		 con;
		u_int16_t			 h;

		NG_HCI_M_PULLUP(event, sizeof(*cisep));
		if (event == NULL)
			break;

		cisep = mtod(event, ng_hci_le_cis_established_ep *);
		h = NG_HCI_CON_HANDLE(le16toh(cisep->connection_handle));

		/*
		 * Per Core Spec Vol 4 Part E §7.7.65.25: the handle is
		 * the CIS handle from LE_Create_CIS or LE_CIS_Request.
		 * Find the existing pending connection descriptor that
		 * was created in ng_hci_lp_con_req (initiator) or
		 * le_cis_request (acceptor).  Preserve its BD_ADDR and
		 * notify flags so the confirmation reaches the socket.
		 */
		con = ng_hci_con_by_handle(unit, h);
		if (con == NULL) {
			/*
			 * No pending descriptor — this shouldn't happen if
			 * CIS Request was properly handled, but create one
			 * as a fallback.  Try to derive BD_ADDR from an
			 * existing LE ACL connection.
			 */
			ng_hci_unit_con_p acl;

			con = ng_hci_new_con(unit, NG_HCI_LINK_ISO_CIS);
			if (con != NULL) {
				con->con_handle = h;
				con->flags |= NG_HCI_CON_NOTIFY_ISO;
				LIST_FOREACH(acl, &unit->con_list, next) {
					if ((acl->link_type ==
					    NG_HCI_LINK_LE_PUBLIC ||
					    acl->link_type ==
					    NG_HCI_LINK_LE_RANDOM) &&
					    acl->state == NG_HCI_CON_OPEN) {
						bcopy(&acl->bdaddr,
						    &con->bdaddr,
						    sizeof(con->bdaddr));
						NG_HCI_WARN(
"%s: %s - CIS handle=%d has no pending descriptor, "
"BD_ADDR copied from ACL handle=%d (may be incorrect)\n",
						    __func__,
						    NG_NODE_NAME(unit->node),
						    h, acl->con_handle);
						break;
					}
				}
			}
		}

		if (con != NULL) {
			if (cisep->status == 0) {
				con->con_handle = h;
				con->state = NG_HCI_CON_OPEN;
				if (con->flags & NG_HCI_CON_TIMEOUT_PENDING)
					ng_hci_con_untimeout(con);
				ng_hci_lp_con_cfm(con, 0);
			} else {
				if (con->flags & NG_HCI_CON_TIMEOUT_PENDING)
					ng_hci_con_untimeout(con);
				ng_hci_lp_con_cfm(con, cisep->status);
				ng_hci_free_con(con);
			}
		}

		SDT_PROBE2(bluetooth, hci, iso_cis, established,
		    h, cisep->status);
		NG_HCI_INFO(
"%s: %s - CIS established, status=%d handle=%d\n",
		    __func__, NG_NODE_NAME(unit->node),
		    cisep->status, h);
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_CIS_REQUEST: {
		ng_hci_le_cis_request_ep	*cisrep;
		u_int16_t			 acl_h, cis_h;

		NG_HCI_M_PULLUP(event, sizeof(*cisrep));
		if (event == NULL)
			break;

		cisrep = mtod(event, ng_hci_le_cis_request_ep *);
		acl_h = NG_HCI_CON_HANDLE(
		    le16toh(cisrep->acl_connection_handle));
		cis_h = NG_HCI_CON_HANDLE(
		    le16toh(cisrep->cis_connection_handle));

		NG_HCI_INFO(
"%s: %s - CIS request, acl_handle=%d cis_handle=%d cig=%d cis=%d\n",
		    __func__, NG_NODE_NAME(unit->node),
		    acl_h, cis_h, cisrep->cig_id, cisrep->cis_id);

		/*
		 * Per Core Spec Vol 4 Part E Section 7.7.65.26, the host
		 * must respond with Accept or Reject CIS Request.
		 *
		 * Forward the request to the ISO socket layer via
		 * LP_CON_IND so that listen()/accept() can decide.
		 * If no ISO hook is connected, reject immediately.
		 */
		{
			ng_hci_unit_con_p acl_con;

			acl_con = ng_hci_con_by_handle(unit, acl_h);
			if (acl_con != NULL &&
			    unit->iso != NULL && NG_HOOK_IS_VALID(unit->iso)) {
			ng_hci_unit_con_p	 cis_con;
			struct ng_mesg		*msg;
			ng_hci_lp_con_ind_ep	*ep;

			/*
			 * Create pending CIS descriptor with the peer's
			 * BD_ADDR from the ACL connection so that
			 * LP_CON_RSP can find it by address, and later
			 * CIS Established can match it.
			 */
			cis_con = ng_hci_new_con(unit, NG_HCI_LINK_ISO_CIS);
			if (cis_con != NULL) {
				cis_con->con_handle = cis_h;
				bcopy(&acl_con->bdaddr, &cis_con->bdaddr,
				    sizeof(cis_con->bdaddr));
				cis_con->flags |= NG_HCI_CON_NOTIFY_ISO;
				cis_con->state = NG_HCI_CON_W4_LP_CON_RSP;
				ng_hci_con_timeout(cis_con);
			}

			/* Send LP_CON_IND to the ISO socket layer */
			NG_MKMESSAGE(msg, NGM_HCI_COOKIE,
			    NGM_HCI_LP_CON_IND, sizeof(*ep), M_NOWAIT);
			if (msg != NULL) {
				ep = (ng_hci_lp_con_ind_ep *)(msg->data);
				ep->link_type = NG_HCI_LINK_ISO_CIS;
				bzero(&ep->uclass, sizeof(ep->uclass));
				bcopy(&acl_con->bdaddr, &ep->bdaddr,
				    sizeof(ep->bdaddr));
				NG_SEND_MSG_HOOK(error, unit->node, msg,
				    unit->iso, 0);
				if (error != 0 && cis_con != NULL) {
					struct __cis_rej2 {
						ng_hci_cmd_pkt_t		 hdr;
						ng_hci_le_reject_cis_request_cp	 cp;
					} __attribute__((packed))	*rej2;
					struct mbuf			*m2;

					ng_hci_con_untimeout(cis_con);
					ng_hci_free_con(cis_con);
					cis_con = NULL;

					MGETHDR(m2, M_NOWAIT, MT_DATA);
					if (m2 != NULL) {
						m2->m_pkthdr.len = m2->m_len =
						    sizeof(*rej2);
						rej2 = mtod(m2,
						    struct __cis_rej2 *);
						rej2->hdr.type = NG_HCI_CMD_PKT;
						rej2->hdr.length =
						    sizeof(rej2->cp);
						rej2->hdr.opcode = htole16(
						    NG_HCI_OPCODE(
						    NG_HCI_OGF_LE,
						    NG_HCI_OCF_LE_REJECT_CIS_REQUEST));
						rej2->cp.connection_handle =
						    cisrep->cis_connection_handle;
						rej2->cp.reason =
						    NG_HCI_ERROR_UNSUPPORTED_REMOTE_FEATURE;

						NG_BT_MBUFQ_ENQUEUE(
						    &unit->cmdq, m2);
						if (!(unit->state &
						    NG_HCI_UNIT_COMMAND_PENDING))
							ng_hci_send_command(
							    unit);
					}
				}
			} else if (cis_con != NULL) {
				/* NG_MKMESSAGE failed; reject CIS */
				struct __cis_rej2 {
					ng_hci_cmd_pkt_t		 hdr;
					ng_hci_le_reject_cis_request_cp	 cp;
				} __attribute__((packed))	*rej2;
				struct mbuf			*rm;

				ng_hci_con_untimeout(cis_con);
				ng_hci_free_con(cis_con);
				cis_con = NULL;

				MGETHDR(rm, M_NOWAIT, MT_DATA);
				if (rm != NULL) {
					rm->m_pkthdr.len = rm->m_len =
					    sizeof(*rej2);
					rej2 = mtod(rm,
					    struct __cis_rej2 *);
					rej2->hdr.type = NG_HCI_CMD_PKT;
					rej2->hdr.length =
					    sizeof(rej2->cp);
					rej2->hdr.opcode = htole16(
					    NG_HCI_OPCODE(NG_HCI_OGF_LE,
					    NG_HCI_OCF_LE_REJECT_CIS_REQUEST));
					rej2->cp.connection_handle =
					    cisrep->cis_connection_handle;
					rej2->cp.reason =
					    NG_HCI_ERROR_REJECTED_LIMITED_RESOURCES;

					NG_BT_MBUFQ_ENQUEUE(
					    &unit->cmdq, rm);
					if (!(unit->state &
					    NG_HCI_UNIT_COMMAND_PENDING))
						ng_hci_send_command(unit);
				}
			}

			SDT_PROBE3(bluetooth, hci, iso_cis, request,
			    cis_h, acl_h, 1);
			NG_HCI_INFO(
"%s: %s - CIS request forwarded to socket layer, cis_handle=%d\n",
			    __func__, NG_NODE_NAME(unit->node), cis_h);
		} else {
			/*
			 * Reject: either no ACL connection, or no ISO
			 * hook connected to consume the data.
			 */
			struct __cis_reject {
				ng_hci_cmd_pkt_t		 hdr;
				ng_hci_le_reject_cis_request_cp	 cp;
			} __attribute__((packed))	*rej;
			struct mbuf			*m;

			MGETHDR(m, M_NOWAIT, MT_DATA);
			if (m != NULL) {
				m->m_pkthdr.len = m->m_len =
				    sizeof(*rej);
				rej = mtod(m,
				    struct __cis_reject *);
				rej->hdr.type = NG_HCI_CMD_PKT;
				rej->hdr.length = sizeof(rej->cp);
				rej->hdr.opcode = htole16(
				    NG_HCI_OPCODE(NG_HCI_OGF_LE,
				    NG_HCI_OCF_LE_REJECT_CIS_REQUEST));
				rej->cp.connection_handle =
				    cisrep->cis_connection_handle;
				rej->cp.reason = NG_HCI_ERROR_UNSUPPORTED_REMOTE_FEATURE;

				NG_BT_MBUFQ_ENQUEUE(&unit->cmdq, m);
				if (!(unit->state &
				    NG_HCI_UNIT_COMMAND_PENDING)) {
					error = ng_hci_send_command(unit);
					if (error != 0)
						NG_HCI_ERR(
"%s: %s - failed to send CIS reject, error=%d\n",
						    __func__,
						    NG_NODE_NAME(unit->node),
						    error);
				}
			}
			SDT_PROBE3(bluetooth, hci, iso_cis, request,
			    cis_h, acl_h, 0);
			NG_HCI_INFO(
"%s: %s - CIS request rejected, cis_handle=%d "
"(acl=%s, iso_hook=%s)\n",
			    __func__, NG_NODE_NAME(unit->node), cis_h,
			    ng_hci_con_by_handle(unit, acl_h) ? "ok" : "missing",
			    (unit->iso != NULL) ? "connected" : "none");
		}
		} /* block scope for acl_con */

		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_CREATE_BIG_COMPL: {
		ng_hci_le_create_big_compl_ep	*bigep;
		ng_hci_unit_con_p		 con;
		u_int8_t			 num_bis, i;
		u_int16_t			 bis_handle;

		NG_HCI_M_PULLUP(event, sizeof(*bigep));
		if (event == NULL)
			break;

		bigep = mtod(event, ng_hci_le_create_big_compl_ep *);
		num_bis = bigep->num_bis;

		SDT_PROBE3(bluetooth, hci, iso_big, complete,
		    bigep->big_handle, bigep->status, bigep->num_bis);
		NG_HCI_INFO(
"%s: %s - Create BIG complete, status=%d big_handle=%d num_bis=%d\n",
		    __func__, NG_NODE_NAME(unit->node),
		    bigep->status, bigep->big_handle, num_bis);

		if (bigep->status == 0 && num_bis > 0) {
			/* Pull up the variable-length handle array */
			NG_HCI_M_PULLUP(event,
			    sizeof(*bigep) + num_bis * sizeof(u_int16_t));
			if (event == NULL)
				break;

			bigep = mtod(event,
			    ng_hci_le_create_big_compl_ep *);

			for (i = 0; i < num_bis; i++) {
				u_int16_t raw_handle;

				m_copydata(event,
				    (int)(sizeof(*bigep) +
				    i * sizeof(u_int16_t)),
				    sizeof(raw_handle),
				    (caddr_t)&raw_handle);
				bis_handle = NG_HCI_CON_HANDLE(
				    le16toh(raw_handle));

				con = ng_hci_new_con(unit,
				    NG_HCI_LINK_ISO_BIS);
				if (con != NULL) {
					con->con_handle = bis_handle;
					con->big_handle = bigep->big_handle;
					con->state = NG_HCI_CON_OPEN;
					con->flags |= NG_HCI_CON_NOTIFY_ISO;
					ng_hci_lp_con_cfm(con, 0);
				}
			}
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_TERMINATE_BIG_COMPL: {
		ng_hci_le_terminate_big_compl_ep	*tbigep;
		ng_hci_unit_con_p			 con, con_next;

		NG_HCI_M_PULLUP(event, sizeof(*tbigep));
		if (event == NULL)
			break;

		tbigep = mtod(event,
		    ng_hci_le_terminate_big_compl_ep *);
		NG_HCI_INFO(
"%s: %s - Terminate BIG complete, big_handle=%d reason=%d\n",
		    __func__, NG_NODE_NAME(unit->node),
		    tbigep->big_handle, tbigep->reason);

		/*
		 * Clean up all BIS connection descriptors that were
		 * created by Create BIG Complete.  Iterate safely
		 * since ng_hci_free_con removes from the list.
		 */
		for (con = LIST_FIRST(&unit->con_list); con != NULL;
		    con = con_next) {
			con_next = LIST_NEXT(con, next);
			if (con->link_type != NG_HCI_LINK_ISO_BIS)
				continue;
			if (con->big_handle != tbigep->big_handle)
				continue;
			ng_hci_lp_discon_ind(con, tbigep->reason);
			if (con->flags & NG_HCI_CON_TIMEOUT_PENDING)
				ng_hci_con_untimeout(con);
			ng_hci_free_con(con);
		}

		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_BIG_SYNC_EST: {
		ng_hci_le_big_sync_est_ep	*bsep;
		ng_hci_unit_con_p		 con;
		u_int8_t			 num_bis, i;
		u_int16_t			 bis_handle;

		NG_HCI_M_PULLUP(event, sizeof(*bsep));
		if (event == NULL)
			break;

		bsep = mtod(event, ng_hci_le_big_sync_est_ep *);
		num_bis = bsep->num_bis;

		SDT_PROBE3(bluetooth, hci, iso_big, sync,
		    bsep->big_handle, bsep->status, num_bis);
		NG_HCI_INFO(
"%s: %s - BIG Sync established, status=%d big_handle=%d num_bis=%d\n",
		    __func__, NG_NODE_NAME(unit->node),
		    bsep->status, bsep->big_handle, num_bis);

		if (bsep->status == 0 && num_bis > 0) {
			NG_HCI_M_PULLUP(event,
			    sizeof(*bsep) + num_bis * sizeof(u_int16_t));
			if (event == NULL)
				break;

			bsep = mtod(event,
			    ng_hci_le_big_sync_est_ep *);

			for (i = 0; i < num_bis; i++) {
				u_int16_t raw_handle;

				m_copydata(event,
				    (int)(sizeof(*bsep) +
				    i * sizeof(u_int16_t)),
				    sizeof(raw_handle),
				    (caddr_t)&raw_handle);
				bis_handle = NG_HCI_CON_HANDLE(
				    le16toh(raw_handle));

				con = ng_hci_new_con(unit,
				    NG_HCI_LINK_ISO_BIS);
				if (con != NULL) {
					con->con_handle = bis_handle;
					con->big_handle = bsep->big_handle;
					con->state = NG_HCI_CON_OPEN;
					con->flags |= NG_HCI_CON_NOTIFY_ISO;
					ng_hci_lp_con_cfm(con, 0);
				}
			}
		}
		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_BIG_SYNC_LOST: {
		ng_hci_le_big_sync_lost_ep	*bslep;
		ng_hci_unit_con_p		 con, con_next;

		NG_HCI_M_PULLUP(event, sizeof(*bslep));
		if (event == NULL)
			break;

		bslep = mtod(event, ng_hci_le_big_sync_lost_ep *);
		NG_HCI_INFO(
"%s: %s - BIG Sync lost, big_handle=%d reason=%d\n",
		    __func__, NG_NODE_NAME(unit->node),
		    bslep->big_handle, bslep->reason);

		/*
		 * Clean up all BIS connection descriptors that were
		 * created by BIG Sync Established.  Same cleanup as
		 * Terminate BIG Complete.
		 */
		for (con = LIST_FIRST(&unit->con_list); con != NULL;
		    con = con_next) {
			con_next = LIST_NEXT(con, next);
			if (con->link_type != NG_HCI_LINK_ISO_BIS)
				continue;
			if (con->big_handle != bslep->big_handle)
				continue;
			ng_hci_lp_discon_ind(con, bslep->reason);
			if (con->flags & NG_HCI_CON_TIMEOUT_PENDING)
				ng_hci_con_untimeout(con);
			ng_hci_free_con(con);
		}

		NG_FREE_M(event);
		break;
	}

	case NG_HCI_LEEV_REQ_PEER_SCA_COMPL:
		NG_HCI_INFO(
"%s: %s - LE Request Peer SCA Complete (passthrough)\n",
		    __func__, NG_NODE_NAME(unit->node));
		NG_FREE_M(event);
		break;

	case NG_HCI_LEEV_ENH_CONN_COMPL_V2:
		error = le_enh_connection_complete_v2(unit, event);
		break;

	default:
		NG_FREE_M(event);
		break;
	}
	}
	return (error);
}

/* Inquiry result event */
static int
inquiry_result(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_inquiry_result_ep	*ep = NULL;
	ng_hci_neighbor_p		 n = NULL;
	bdaddr_t			 bdaddr;
	int				 error = 0;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_inquiry_result_ep *);
	{
	int				 num_responses = ep->num_responses;
	m_adj(event, sizeof(*ep));

	for (; num_responses > 0; num_responses --) {
		/* Validate remaining mbuf length:
		 * bdaddr(6) + page_scan_rep_mode(1) +
		 * page_scan_period_mode(1) + page_scan_mode(1) +
		 * class(3) + clock_offset(2) = 14 bytes */
		if (event->m_pkthdr.len < 14)
			break;

		/* Get remote unit address */
		m_copydata(event, 0, sizeof(bdaddr), (caddr_t) &bdaddr);
		m_adj(event, sizeof(bdaddr));

		/* Lookup entry in the cache */
		n = ng_hci_get_neighbor(unit, &bdaddr, NG_HCI_LINK_ACL);
		if (n == NULL) {
			/* Create new entry */
			n = ng_hci_new_neighbor(unit);
			if (n == NULL) {
				error = ENOMEM;
				break;
			}
		} else
			getmicrotime(&n->updated);

		bcopy(&bdaddr, &n->bdaddr, sizeof(n->bdaddr));
		n->addrtype = NG_HCI_LINK_ACL;

		/* Use m_copydata instead of mtod to avoid m_pullup issues */
		m_copydata(event, 0, sizeof(u_int8_t),
		    (caddr_t)&n->page_scan_rep_mode);
		m_adj(event, sizeof(u_int8_t));

		/* page_scan_period_mode */
		m_adj(event, sizeof(u_int8_t));

		m_copydata(event, 0, sizeof(u_int8_t),
		    (caddr_t)&n->page_scan_mode);
		m_adj(event, sizeof(u_int8_t));

		/* class */
		m_adj(event, NG_HCI_CLASS_SIZE);

		/* clock offset */
		m_copydata(event, 0, sizeof(n->clock_offset),
			(caddr_t) &n->clock_offset);
		n->clock_offset = le16toh(n->clock_offset);
		m_adj(event, sizeof(n->clock_offset));
	}
	}

	NG_FREE_M(event);

	return (error);
} /* inquiry_result */

/* Inquiry result with RSSI event */
static int
inquiry_result_with_rssi(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_inquiry_result_with_rssi_ep	*ep = NULL;
	ng_hci_neighbor_p			 n = NULL;
	bdaddr_t				 bdaddr;
	int					 error = 0;
	u_int8_t				 tmp;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_inquiry_result_with_rssi_ep *);
	{
	int				 num_responses = ep->num_responses;
	m_adj(event, sizeof(*ep));

	for (; num_responses > 0; num_responses --) {
		/* Validate remaining mbuf length:
		 * bdaddr(6) + page_scan_rep_mode(1) + reserved(1) +
		 * class(3) + clock_offset(2) + rssi(1) = 14 bytes */
		if (event->m_pkthdr.len < 14)
			break;

		/* Get remote unit address */
		m_copydata(event, 0, sizeof(bdaddr), (caddr_t) &bdaddr);
		m_adj(event, sizeof(bdaddr));

		/* Lookup entry in the cache */
		n = ng_hci_get_neighbor(unit, &bdaddr, NG_HCI_LINK_ACL);
		if (n == NULL) {
			/* Create new entry */
			n = ng_hci_new_neighbor(unit);
			if (n == NULL) {
				error = ENOMEM;
				break;
			}
		} else
			getmicrotime(&n->updated);

		bcopy(&bdaddr, &n->bdaddr, sizeof(n->bdaddr));
		n->addrtype = NG_HCI_LINK_ACL;

		/* page_scan_rep_mode */
		m_copydata(event, 0, sizeof(u_int8_t),
		    (caddr_t)&n->page_scan_rep_mode);
		m_adj(event, sizeof(u_int8_t));

		/* reserved (page_scan_mode is reserved/0 in RSSI variant) */
		m_copydata(event, 0, sizeof(u_int8_t), (caddr_t)&tmp);
		n->page_scan_mode = 0;
		m_adj(event, sizeof(u_int8_t));

		/* class */
		m_adj(event, NG_HCI_CLASS_SIZE);

		/* clock offset */
		m_copydata(event, 0, sizeof(n->clock_offset),
			(caddr_t) &n->clock_offset);
		n->clock_offset = le16toh(n->clock_offset);
		m_adj(event, sizeof(n->clock_offset));

		/* rssi */
		m_adj(event, sizeof(int8_t));
	}
	}

	NG_FREE_M(event);

	return (error);
} /* inquiry_result_with_rssi */

/* Extended inquiry result event */
static int
ext_inquiry_result(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_ext_inquiry_result_ep	*ep = NULL;
	ng_hci_neighbor_p		 n = NULL;
	int				 error = 0;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_ext_inquiry_result_ep *);

	/* Lookup entry in the cache */
	n = ng_hci_get_neighbor(unit, &ep->bdaddr, NG_HCI_LINK_ACL);
	if (n == NULL) {
		/* Create new entry */
		n = ng_hci_new_neighbor(unit);
		if (n == NULL) {
			error = ENOMEM;
			goto out;
		}
	} else
		getmicrotime(&n->updated);

	bcopy(&ep->bdaddr, &n->bdaddr, sizeof(n->bdaddr));
	n->addrtype = NG_HCI_LINK_ACL;
	n->page_scan_rep_mode = ep->page_scan_rep_mode;
	n->page_scan_mode = 0; /* reserved in extended inquiry result */
	n->clock_offset = le16toh(ep->clock_offset);

	/* Save Extended Inquiry Response data */
	n->extinq_size = sizeof(ep->ext_inquiry_response);
	bcopy(ep->ext_inquiry_response, n->extinq_data,
	    sizeof(ep->ext_inquiry_response));

out:
	NG_FREE_M(event);

	return (error);
} /* ext_inquiry_result */

/* Connection complete event */
static int
con_compl(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_con_compl_ep	*ep = NULL;
	ng_hci_unit_con_p	 con = NULL;
	int			 error = 0;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_con_compl_ep *);

	/*
	 * Find the first connection descriptor that matches the following:
	 *
	 * 1) con->link_type == ep->link_type
	 * 2) con->state == NG_HCI_CON_W4_CONN_COMPLETE
	 * 3) con->bdaddr == ep->bdaddr
	 */

	LIST_FOREACH(con, &unit->con_list, next)
		if (con->link_type == ep->link_type &&
		    con->state == NG_HCI_CON_W4_CONN_COMPLETE &&
		    bcmp(&con->bdaddr, &ep->bdaddr, sizeof(bdaddr_t)) == 0)
			break;

	/*
	 * Two possible cases:
	 *
	 * 1) We have found connection descriptor. That means upper layer has
	 *    requested this connection via LP_CON_REQ message. In this case
	 *    connection must have timeout set. If ng_hci_con_untimeout() fails
	 *    then timeout message already went into node's queue. In this case
	 *    ignore Connection_Complete event and let timeout deal with it.
	 *
	 * 2) We do not have connection descriptor. That means upper layer
	 *    nas not requested this connection or (less likely) we gave up
	 *    on this connection (timeout). The most likely scenario is that
	 *    we have received Create_Connection/Add_SCO_Connection command 
	 *    from the RAW hook
	 */

	if (con == NULL) {
		if (ep->status != 0)
			goto out;

		con = ng_hci_new_con(unit, ep->link_type);
		if (con == NULL) {
			error = ENOMEM;
			goto out;
		}

		bcopy(&ep->bdaddr, &con->bdaddr, sizeof(con->bdaddr));
	} else if ((error = ng_hci_con_untimeout(con)) != 0)
			goto out;

	/*
	 * Update connection descriptor and send notification 
	 * to the upper layers.
	 */

	con->con_handle = NG_HCI_CON_HANDLE(le16toh(ep->con_handle));
	con->encryption_mode = ep->encryption_mode;

	ng_hci_lp_con_cfm(con, ep->status);

	/* Adjust connection state */
	if (ep->status != 0)
		ng_hci_free_con(con);
	else {
		con->state = NG_HCI_CON_OPEN;

		/*	
		 * Change link policy for the ACL connections. Enable all 
		 * supported link modes. Enable Role switch as well if
		 * device supports it.
		 */

		if (ep->link_type == NG_HCI_LINK_ACL) {
			struct __link_policy {
				ng_hci_cmd_pkt_t			 hdr;
				ng_hci_write_link_policy_settings_cp	 cp;
			} __attribute__ ((packed))			*lp;
			struct mbuf					*m;

			MGETHDR(m, M_NOWAIT, MT_DATA);
			if (m != NULL) {
				m->m_pkthdr.len = m->m_len = sizeof(*lp);
				lp = mtod(m, struct __link_policy *);

				lp->hdr.type = NG_HCI_CMD_PKT;
				lp->hdr.opcode = htole16(NG_HCI_OPCODE(
					NG_HCI_OGF_LINK_POLICY,
					NG_HCI_OCF_WRITE_LINK_POLICY_SETTINGS));
				lp->hdr.length = sizeof(lp->cp);

				lp->cp.con_handle = htole16(con->con_handle);

				lp->cp.settings = 0;
				if ((unit->features[0] & NG_HCI_LMP_SWITCH) &&
				    unit->role_switch)
					lp->cp.settings |= NG_HCI_LINK_POLICY_ENABLE_ROLE_SWITCH;
				if (unit->features[0] & NG_HCI_LMP_HOLD_MODE)
					lp->cp.settings |= NG_HCI_LINK_POLICY_ENABLE_HOLD_MODE;
				if (unit->features[0] & NG_HCI_LMP_SNIFF_MODE)
					lp->cp.settings |= NG_HCI_LINK_POLICY_ENABLE_SNIFF_MODE;
				if (unit->features[1] & NG_HCI_LMP_PARK_MODE)
					lp->cp.settings |= NG_HCI_LINK_POLICY_ENABLE_PARK_MODE;

				lp->cp.settings &= unit->link_policy_mask;
				lp->cp.settings = htole16(lp->cp.settings);

				NG_BT_MBUFQ_ENQUEUE(&unit->cmdq, m);
				if (!(unit->state & NG_HCI_UNIT_COMMAND_PENDING))
					ng_hci_send_command(unit);
			}
		}
	}
out:
	NG_FREE_M(event);

	return (error);
} /* con_compl */

/* Connection request event */
static int
con_req(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_con_req_ep	*ep = NULL;
	ng_hci_unit_con_p	 con = NULL;
	int			 error = 0;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_con_req_ep *);

	/*
	 * Find the first connection descriptor that matches the following:
	 *
	 * 1) con->link_type == ep->link_type
	 *
	 * 2) con->state == NG_HCI_CON_W4_LP_CON_RSP ||
	 *    con->state == NG_HCI_CON_W4_CONN_COMPL
	 * 
	 * 3) con->bdaddr == ep->bdaddr
	 *
	 * Possible cases:
	 *
	 * 1) We do not have connection descriptor. This is simple. Create
	 *    new fresh connection descriptor and send notification to the
	 *    appropriate upstream hook (based on link_type).
	 *
	 * 2) We found connection handle. This is more complicated.
	 * 
	 * 2.1) ACL links
	 *
	 *      Since only one ACL link can exist between each pair of
	 *      units then we have a race. Our upper layer has requested 
	 *      an ACL connection to the remote unit, but we did not send 
	 *      command yet. At the same time the remote unit has requested
	 *      an ACL connection from us. In this case we will ignore 
	 *	Connection_Request event. This probably will cause connect
	 *      failure	on both units.
	 *
	 * 2.2) SCO links
	 *
	 *      The spec on page 45 says :
	 *
	 *      "The master can support up to three SCO links to the same 
	 *       slave or to different slaves. A slave can support up to 
	 *       three SCO links from the same master, or two SCO links if 
	 *       the links originate from different masters."
	 *
	 *      The only problem is how to handle multiple SCO links between
	 *      matster and slave. For now we will assume that multiple SCO
	 *      links MUST be opened one after another. 
	 */

	LIST_FOREACH(con, &unit->con_list, next)
		if (con->link_type == ep->link_type &&
		    (con->state == NG_HCI_CON_W4_LP_CON_RSP ||
		     con->state == NG_HCI_CON_W4_CONN_COMPLETE) &&
		    bcmp(&con->bdaddr, &ep->bdaddr, sizeof(bdaddr_t)) == 0)
			break;

	if (con == NULL) {
		con = ng_hci_new_con(unit, ep->link_type);
		if (con != NULL) {
			bcopy(&ep->bdaddr, &con->bdaddr, sizeof(con->bdaddr));

			con->state = NG_HCI_CON_W4_LP_CON_RSP;
			ng_hci_con_timeout(con);

			error = ng_hci_lp_con_ind(con, ep->uclass);
			if (error != 0) {
				ng_hci_con_untimeout(con);
				ng_hci_free_con(con);
			}
		} else
			error = ENOMEM;
	}

	NG_FREE_M(event);

	return (error);
} /* con_req */

/* Disconnect complete event */
static int
discon_compl(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_discon_compl_ep	*ep = NULL;
	ng_hci_unit_con_p	 con = NULL;
	int			 error = 0;
	u_int16_t		 h;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_discon_compl_ep *);

	/* 
	 * XXX 
	 * Do we have to send notification if ep->status != 0? 
	 * For now we will send notification for both ACL and SCO connections
	 * ONLY if ep->status == 0.
	 */

	if (ep->status == 0) {
		h = NG_HCI_CON_HANDLE(le16toh(ep->con_handle));
		con = ng_hci_con_by_handle(unit, h);
		if (con != NULL) {
			error = ng_hci_lp_discon_ind(con, ep->reason);

			SDT_PROBE1(bluetooth, hci, le_connection, disconnect,
			    con->con_handle);

			/* Remove all timeouts (if any) */
			if (con->flags & NG_HCI_CON_TIMEOUT_PENDING)
				ng_hci_con_untimeout(con);

			ng_hci_free_con(con);
		} else {
			NG_HCI_ALERT(
"%s: %s - invalid connection handle=%d\n",
				__func__, NG_NODE_NAME(unit->node), h);
			error = ENOENT;
		}
	}

	NG_FREE_M(event);

	return (error);
} /* discon_compl */

/*
 * Common logic for encryption_change and encryption_change_v2.
 * Interprets the encryption_enable value and updates con->encryption_mode.
 */
static int
encryption_change_common(ng_hci_unit_p unit, ng_hci_unit_con_p con,
    u_int16_t handle, u_int8_t status, u_int8_t encryption_enable)
{
	int	error = 0;

	if (status == 0) {
		if (con == NULL) {
			NG_HCI_ALERT(
"%s: %s - invalid connection handle=%d\n",
				__func__, NG_NODE_NAME(unit->node), handle);
			error = ENOENT;
		} else if (con->link_type == NG_HCI_LINK_SCO) {
			NG_HCI_ALERT(
"%s: %s - invalid link type=%d\n",
				__func__, NG_NODE_NAME(unit->node),
				con->link_type);
			error = EINVAL;
		} else if (encryption_enable == 0x00)
			con->encryption_mode = NG_HCI_ENCRYPTION_MODE_NONE;
		else if (con->link_type == NG_HCI_LINK_LE_PUBLIC ||
			 con->link_type == NG_HCI_LINK_LE_RANDOM)
			con->encryption_mode = NG_HCI_ENCRYPTION_MODE_AES_CCM;
		else if (encryption_enable == 0x02)
			con->encryption_mode = NG_HCI_ENCRYPTION_MODE_AES_CCM;
		else
			con->encryption_mode = NG_HCI_ENCRYPTION_MODE_P2P;
	} else {
		NG_HCI_ERR(
"%s: %s - failed to change encryption mode, status=%d\n",
			__func__, NG_NODE_NAME(unit->node), status);

		/*
		 * On failure, explicitly set encryption_mode to NONE so
		 * the upper layer does not interpret a stale non-zero
		 * mode from a previous successful encryption as "still
		 * encrypted."
		 */
		if (con != NULL)
			con->encryption_mode = NG_HCI_ENCRYPTION_MODE_NONE;
	}

	/* Propagate encryption status to upper layer */
	if (con != NULL)
		ng_hci_lp_enc_change(con, con->encryption_mode);

	return (error);
}

/* Encryption change event */
static int
encryption_change(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_encryption_change_ep	*ep = NULL;
	ng_hci_unit_con_p		 con = NULL;
	int				 error = 0;
	u_int16_t	h;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_encryption_change_ep *);
	h = NG_HCI_CON_HANDLE(le16toh(ep->con_handle));
	con = ng_hci_con_by_handle(unit, h);

	error = encryption_change_common(unit, con, h,
	    ep->status, ep->encryption_enable);

	SDT_PROBE2(bluetooth, hci, encryption, change,
	    h, ep->encryption_enable);

	/* Fire security pairing probe when LE encryption is first enabled */
	if (ep->status == 0 && ep->encryption_enable != 0 && con != NULL &&
	    (con->link_type == NG_HCI_LINK_LE_PUBLIC ||
	     con->link_type == NG_HCI_LINK_LE_RANDOM))
		SDT_PROBE2(bluetooth, security, pairing, complete,
		    h, (uint8_t)0);

	NG_FREE_M(event);

	return (error);
} /* encryption_change */

/* Encryption change v2 event (BT 5.3+, adds encryption_key_size field) */
static int
encryption_change_v2(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_encryption_change_v2_ep	*ep = NULL;
	ng_hci_unit_con_p		 con = NULL;
	int				 error = 0;
	u_int16_t	h;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_encryption_change_v2_ep *);
	h = NG_HCI_CON_HANDLE(le16toh(ep->con_handle));
	con = ng_hci_con_by_handle(unit, h);

	error = encryption_change_common(unit, con, h,
	    ep->status, ep->encryption_enable);

	/* Store the encryption key size (v2 only) */
	if (con != NULL && ep->status == 0)
		con->encryption_key_size = ep->encryption_key_size;

	SDT_PROBE2(bluetooth, hci, encryption, change,
	    h, ep->encryption_enable);

	/* Fire security pairing probe when LE encryption is first enabled */
	if (ep->status == 0 && ep->encryption_enable != 0 && con != NULL &&
	    (con->link_type == NG_HCI_LINK_LE_PUBLIC ||
	     con->link_type == NG_HCI_LINK_LE_RANDOM))
		SDT_PROBE2(bluetooth, security, pairing, complete,
		    h, ep->encryption_key_size);

	NG_FREE_M(event);

	return (error);
} /* encryption_change_v2 */

/* Synchronous Connection Complete event */
static int
sync_con_compl(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_sync_con_compl_ep	*ep = NULL;
	ng_hci_unit_con_p		 con = NULL;
	int				 error = 0;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_sync_con_compl_ep *);

	/*
	 * Look for an existing SCO connection descriptor that we are
	 * waiting to complete (e.g. initiated via Add_SCO_Connection or
	 * Setup_Synchronous_Connection from the upper layer).
	 */
	LIST_FOREACH(con, &unit->con_list, next)
		if (con->link_type == NG_HCI_LINK_SCO &&
		    con->state == NG_HCI_CON_W4_CONN_COMPLETE &&
		    bcmp(&con->bdaddr, &ep->bdaddr, sizeof(bdaddr_t)) == 0)
			break;

	if (con == NULL) {
		if (ep->status != 0)
			goto out;

		/* Incoming SCO connection or one initiated from raw HCI */
		con = ng_hci_new_con(unit, NG_HCI_LINK_SCO);
		if (con == NULL) {
			error = ENOMEM;
			goto out;
		}

		bcopy(&ep->bdaddr, &con->bdaddr, sizeof(con->bdaddr));
	} else if ((error = ng_hci_con_untimeout(con)) != 0)
			goto out;

	con->con_handle = NG_HCI_CON_HANDLE(le16toh(ep->con_handle));
	con->encryption_mode = NG_HCI_ENCRYPTION_MODE_NONE;

	ng_hci_lp_con_cfm(con, ep->status);

	if (ep->status != 0)
		ng_hci_free_con(con);
	else
		con->state = NG_HCI_CON_OPEN;
out:
	NG_FREE_M(event);

	return (error);
} /* sync_con_compl */

/* Read remote feature complete event */
static int
read_remote_features_compl(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_read_remote_features_compl_ep	*ep = NULL;
	ng_hci_unit_con_p			 con = NULL;
	ng_hci_neighbor_p			 n = NULL;
	u_int16_t				 h;
	int					 error = 0;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_read_remote_features_compl_ep *);

	if (ep->status == 0) {
		/* Check if we have this connection handle */
		h = NG_HCI_CON_HANDLE(le16toh(ep->con_handle));
		con = ng_hci_con_by_handle(unit, h);
		if (con == NULL) {
			NG_HCI_ALERT(
"%s: %s - invalid connection handle=%d\n",
				__func__, NG_NODE_NAME(unit->node), h);
			error = ENOENT;
			goto out;
		}

		/* Update cache entry */
		n = ng_hci_get_neighbor(unit, &con->bdaddr, NG_HCI_LINK_ACL);
		if (n == NULL) {
			n = ng_hci_new_neighbor(unit);
			if (n == NULL) {
				error = ENOMEM;
				goto out;
			}

			bcopy(&con->bdaddr, &n->bdaddr, sizeof(n->bdaddr));
			n->addrtype = NG_HCI_LINK_ACL;
		} else
			getmicrotime(&n->updated);

		bcopy(ep->features, n->features, sizeof(n->features));
	} else
		NG_HCI_ERR(
"%s: %s - failed to read remote unit features, status=%d\n",
			__func__, NG_NODE_NAME(unit->node), ep->status);
out:
	NG_FREE_M(event);

	return (error);
} /* read_remote_features_compl */

/* QoS setup complete event */
static int
qos_setup_compl(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_qos_setup_compl_ep	*ep = NULL;
	ng_hci_unit_con_p		 con = NULL;
	u_int16_t			 h;
	int				 error = 0;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_qos_setup_compl_ep *);

	/* Check if we have this connection handle */
	h = NG_HCI_CON_HANDLE(le16toh(ep->con_handle));
	con = ng_hci_con_by_handle(unit, h);
	if (con == NULL) {
		NG_HCI_ALERT(
"%s: %s - invalid connection handle=%d\n",
			__func__, NG_NODE_NAME(unit->node), h);
		error = ENOENT;
	} else if (con->link_type != NG_HCI_LINK_ACL) {
		NG_HCI_ALERT(
"%s: %s - invalid link type=%d, handle=%d\n",
			__func__, NG_NODE_NAME(unit->node), con->link_type, h);
		error = EINVAL;
	} else if (con->state != NG_HCI_CON_OPEN) {
		NG_HCI_ALERT(
"%s: %s - invalid connection state=%d, handle=%d\n",
			__func__, NG_NODE_NAME(unit->node), 
			con->state, h);
		error = EINVAL;
	} else /* Notify upper layer */
		error = ng_hci_lp_qos_cfm(con, ep->status);

	NG_FREE_M(event);

	return (error);
} /* qos_setup_compl */

/* Hardware error event */
static int
hardware_error(ng_hci_unit_p unit, struct mbuf *event)
{
	NG_HCI_M_PULLUP(event, sizeof(u_int8_t));
	if (event != NULL) {
		NG_HCI_ALERT(
"%s: %s - hardware error %#x\n",
			__func__, NG_NODE_NAME(unit->node),
			*mtod(event, u_int8_t *));
	}

	NG_FREE_M(event);

	return (0);
} /* hardware_error */

/* Role change event */
static int
role_change(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_role_change_ep	*ep = NULL;
	ng_hci_unit_con_p	 con = NULL;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_role_change_ep *);

	if (ep->status == 0) {
		/* XXX shoud we also change "role" for SCO connections? */
		con = ng_hci_con_by_bdaddr(unit, &ep->bdaddr, NG_HCI_LINK_ACL);
		if (con != NULL)
			con->role = ep->role;
		else
			NG_HCI_ALERT(
"%s: %s - ACL connection does not exist, bdaddr=%x:%x:%x:%x:%x:%x\n",
				__func__, NG_NODE_NAME(unit->node),
				ep->bdaddr.b[5], ep->bdaddr.b[4], 
				ep->bdaddr.b[3], ep->bdaddr.b[2], 
				ep->bdaddr.b[1], ep->bdaddr.b[0]);
	} else
		NG_HCI_ERR(
"%s: %s - failed to change role, status=%d, bdaddr=%x:%x:%x:%x:%x:%x\n",
			__func__, NG_NODE_NAME(unit->node), ep->status,
			ep->bdaddr.b[5], ep->bdaddr.b[4], ep->bdaddr.b[3],
			ep->bdaddr.b[2], ep->bdaddr.b[1], ep->bdaddr.b[0]);

	NG_FREE_M(event);

	return (0);
} /* role_change */

/* Number of completed packets event */
static int
num_compl_pkts(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_num_compl_pkts_ep	*ep = NULL;
	ng_hci_unit_con_p		 con = NULL;
	u_int16_t			 h, p;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_num_compl_pkts_ep *);
	{
	u_int8_t			 num_handles = ep->num_con_handles;
	m_adj(event, sizeof(*ep));

	for (; num_handles > 0; num_handles --) {
		/* Validate remaining mbuf length */
		if (event->m_pkthdr.len < sizeof(h) + sizeof(p))
			break;

		/* Get connection handle */
		m_copydata(event, 0, sizeof(h), (caddr_t) &h);
		m_adj(event, sizeof(h));
		h = NG_HCI_CON_HANDLE(le16toh(h));

		/* Get number of completed packets */
		m_copydata(event, 0, sizeof(p), (caddr_t) &p);
		m_adj(event, sizeof(p));
		p = le16toh(p);

		/* Check if we have this connection handle */
		con = ng_hci_con_by_handle(unit, h);
		if (con != NULL) {
			int old_pending = con->pending;
			con->pending -= p;
			if (con->pending < 0) {
				NG_HCI_WARN(
"%s: %s - pending packet counter is out of sync! " \
"handle=%d, pending=%d, ncp=%d\n",	__func__, NG_NODE_NAME(unit->node),
					con->con_handle, con->pending, p);

				p = old_pending; /* only free what was pending */
				con->pending = 0;
			}

			/* Update buffer descriptor */
			if (con->link_type == NG_HCI_LINK_SCO)
				NG_HCI_BUFF_SCO_FREE(unit->buffer, p);
			else if ((con->link_type == NG_HCI_LINK_LE_PUBLIC ||
				  con->link_type == NG_HCI_LINK_LE_RANDOM) &&
				 unit->buffer.le_pkts > 0)
				NG_HCI_BUFF_LE_FREE(unit->buffer, p);
			else if (con->link_type == NG_HCI_LINK_ISO_CIS ||
				 con->link_type == NG_HCI_LINK_ISO_BIS) {
				if (unit->buffer.iso_pkts > 0)
					NG_HCI_BUFF_ISO_FREE(
					    unit->buffer, p);
				else
					NG_HCI_BUFF_ACL_FREE(
					    unit->buffer, p);
			} else
				NG_HCI_BUFF_ACL_FREE(unit->buffer, p);
		} else
			NG_HCI_ALERT(
"%s: %s - invalid connection handle=%d\n",
				__func__, NG_NODE_NAME(unit->node), h);
	}
	}

	NG_FREE_M(event);

	/* Send more data */
	ng_hci_send_data(unit);

	return (0);
} /* num_compl_pkts */

/* Mode change event */
static int
mode_change(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_mode_change_ep	*ep = NULL;
	ng_hci_unit_con_p	 con = NULL;
	uint16_t		 h;
	int			 error = 0;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_mode_change_ep *);

	if (ep->status == 0) {
		h = NG_HCI_CON_HANDLE(le16toh(ep->con_handle));

		con = ng_hci_con_by_handle(unit, h);
		if (con == NULL) {
			NG_HCI_ALERT(
"%s: %s - invalid connection handle=%d\n",
				__func__, NG_NODE_NAME(unit->node), h);
			error = ENOENT;
		} else if (con->link_type != NG_HCI_LINK_ACL) {
			NG_HCI_ALERT(
"%s: %s - invalid link type=%d\n",
				__func__, NG_NODE_NAME(unit->node), 
				con->link_type);
			error = EINVAL;
		} else
			con->mode = ep->unit_mode;
	} else
		NG_HCI_ERR(
"%s: %s - failed to change mode, status=%d\n",
			__func__, NG_NODE_NAME(unit->node), ep->status);

	NG_FREE_M(event);

	return (error);
} /* mode_change */

/* Data buffer overflow event */
static int
data_buffer_overflow(ng_hci_unit_p unit, struct mbuf *event)
{
	uint8_t		 lt;
	const char	*ltname;

	NG_HCI_M_PULLUP(event, sizeof(uint8_t));
	if (event != NULL) {
		lt = *mtod(event, uint8_t *);

		switch (lt) {
		case 0x00: ltname = "Synchronous"; break;
		case 0x01: ltname = "ACL"; break;
		case 0x02: ltname = "ISO"; break;
		default:   ltname = "Unknown"; break;
		}
		NG_HCI_ALERT(
"%s: %s - %s data buffer overflow\n",
			__func__, NG_NODE_NAME(unit->node), ltname);
	}

	NG_FREE_M(event);

	return (0);
} /* data_buffer_overflow */

/* Read clock offset complete event */
static int
read_clock_offset_compl(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_read_clock_offset_compl_ep	*ep = NULL;
	ng_hci_unit_con_p			 con = NULL;
	ng_hci_neighbor_p			 n = NULL;
	int					 error = 0;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_read_clock_offset_compl_ep *);

	if (ep->status == 0) {
		u_int16_t	h = NG_HCI_CON_HANDLE(le16toh(ep->con_handle));

		con = ng_hci_con_by_handle(unit, h);
		if (con == NULL) {
			NG_HCI_ALERT(
"%s: %s - invalid connection handle=%d\n",
				__func__, NG_NODE_NAME(unit->node), h);
			error = ENOENT;
			goto out;
		}

		/* Update cache entry */
		n = ng_hci_get_neighbor(unit, &con->bdaddr, NG_HCI_LINK_ACL);
		if (n == NULL) {
			n = ng_hci_new_neighbor(unit);
			if (n == NULL) {
				error = ENOMEM;
				goto out;
			}

			bcopy(&con->bdaddr, &n->bdaddr, sizeof(n->bdaddr));
			n->addrtype = NG_HCI_LINK_ACL;
		} else
			getmicrotime(&n->updated);

		n->clock_offset = le16toh(ep->clock_offset);
	} else
		NG_HCI_ERR(
"%s: %s - failed to Read Remote Clock Offset, status=%d\n",
			__func__, NG_NODE_NAME(unit->node), ep->status);
out:
	NG_FREE_M(event);

	return (error);
} /* read_clock_offset_compl */

/* QoS violation event */
static int
qos_violation(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_qos_violation_ep	*ep = NULL;
	ng_hci_unit_con_p	 con = NULL;
	u_int16_t		 h;
	int			 error = 0;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_qos_violation_ep *);

	/* Check if we have this connection handle */
	h = NG_HCI_CON_HANDLE(le16toh(ep->con_handle));
	con = ng_hci_con_by_handle(unit, h);
	if (con == NULL) {
		NG_HCI_ALERT(
"%s: %s - invalid connection handle=%d\n",
			__func__, NG_NODE_NAME(unit->node), h);
		error = ENOENT;
	} else if (con->link_type != NG_HCI_LINK_ACL) {
		NG_HCI_ALERT(
"%s: %s - invalid link type=%d\n",
			__func__, NG_NODE_NAME(unit->node), con->link_type);
		error = EINVAL;
	} else if (con->state != NG_HCI_CON_OPEN) {
		NG_HCI_ALERT(
"%s: %s - invalid connection state=%d, handle=%d\n",
			__func__, NG_NODE_NAME(unit->node), con->state, h);
		error = EINVAL;
	} else /* Notify upper layer */
		error = ng_hci_lp_qos_ind(con); 

	NG_FREE_M(event);

	return (error);
} /* qos_violation */

/* Page scan mode change event */
static int
page_scan_mode_change(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_page_scan_mode_change_ep	*ep = NULL;
	ng_hci_neighbor_p		 n = NULL;
	int				 error = 0;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_page_scan_mode_change_ep *);

	/* Update cache entry */
	n = ng_hci_get_neighbor(unit, &ep->bdaddr, NG_HCI_LINK_ACL);
	if (n == NULL) {
		n = ng_hci_new_neighbor(unit);
		if (n == NULL) {
			error = ENOMEM;
			goto out;
		}

		bcopy(&ep->bdaddr, &n->bdaddr, sizeof(n->bdaddr));
		n->addrtype = NG_HCI_LINK_ACL;
	} else
		getmicrotime(&n->updated);

	n->page_scan_mode = ep->page_scan_mode;
out:
	NG_FREE_M(event);

	return (error);
} /* page_scan_mode_change */

/* Page scan repetition mode change event */
static int
page_scan_rep_mode_change(ng_hci_unit_p unit, struct mbuf *event)
{
	ng_hci_page_scan_rep_mode_change_ep	*ep = NULL;
	ng_hci_neighbor_p			 n = NULL;
	int					 error = 0;

	NG_HCI_M_PULLUP(event, sizeof(*ep));
	if (event == NULL)
		return (ENOBUFS);

	ep = mtod(event, ng_hci_page_scan_rep_mode_change_ep *);

	/* Update cache entry */
	n = ng_hci_get_neighbor(unit, &ep->bdaddr, NG_HCI_LINK_ACL);
	if (n == NULL) {
		n = ng_hci_new_neighbor(unit);
		if (n == NULL) {
			error = ENOMEM;
			goto out;
		}

		bcopy(&ep->bdaddr, &n->bdaddr, sizeof(n->bdaddr));
		n->addrtype = NG_HCI_LINK_ACL;
	} else
		getmicrotime(&n->updated);

	n->page_scan_rep_mode = ep->page_scan_rep_mode;
out:
	NG_FREE_M(event);

	return (error);
} /* page_scan_rep_mode_change */
