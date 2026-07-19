/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * HCI utility functions for blued — common helpers.
 *
 * Wraps libbluetooth's bt_dev* API for raw HCI socket management,
 * local address retrieval, and connection handle lookup.
 *
 * The remaining HCI command wrappers live in:
 *   hci_adv.c    — advertising commands (legacy + extended + periodic)
 *   hci_scan.c   — scanning commands (legacy + extended)
 *   hci_conn.c   — connection parameter, PHY, and data-length commands
 *   hci_privacy.c — resolving list, filter accept list, privacy
 *   hci_misc.c   — reset, event masks, features, encryption, ISO
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netgraph/bluetooth/include/ng_btsocket.h>

#include "ble_util.h"
#include "blued_probes.h"
#include "hci_log.h"
#include "hci_util.h"
#include "hci_internal.h"

/*
 * Mutex protecting the shared HCI socket fd against concurrent
 * bt_devreq / bt_devrecv callers from different threads.
 */
#define HCI_LOCK_SLOTS 8
struct hci_lock_slot {
	int fd;
	pthread_mutex_t mutex;
};
static struct hci_lock_slot hci_locks[HCI_LOCK_SLOTS];
static pthread_once_t hci_locks_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t hci_locks_guard = PTHREAD_MUTEX_INITIALIZER;

static void
hci_locks_init(void)
{
	int i;

	for (i = 0; i < HCI_LOCK_SLOTS; i++) {
		hci_locks[i].fd = -1;
		pthread_mutex_init(&hci_locks[i].mutex, NULL);
	}
}

pthread_mutex_t *
hci_devreq_mutex(int fd)
{
	int i, free_slot = -1;
	pthread_mutex_t *mutex;

	pthread_once(&hci_locks_once, hci_locks_init);
	pthread_mutex_lock(&hci_locks_guard);
	mutex = NULL;
	for (i = 0; i < HCI_LOCK_SLOTS; i++) {
		if (hci_locks[i].fd == fd) {
			mutex = &hci_locks[i].mutex;
			break;
		}
		if (free_slot < 0 && hci_locks[i].fd < 0)
			free_slot = i;
	}
	if (mutex == NULL && free_slot >= 0) {
		hci_locks[free_slot].fd = fd;
		mutex = &hci_locks[free_slot].mutex;
	}
	/* BLUED_MAX_ADAPTERS bounds live controllers; this is defensive. */
	if (mutex == NULL)
		mutex = &hci_locks[(unsigned)fd % HCI_LOCK_SLOTS].mutex;
	pthread_mutex_unlock(&hci_locks_guard);
	return (mutex);
}

/*
 * Internal bt_devreq wrapper with BTSnoop logging.  Caller must hold hci_mtx.
 */
int
hci_devreq_logged_locked(int fd, struct bt_devreq *r, int timeout)
{
	int ret;

	/* Log outgoing command if BTSnoop is active */
	if (hci_log_enabled()) {
		uint8_t cmd[260];	/* max HCI command is 258 bytes */
		uint16_t opcode = r->opcode;
		int plen = r->cparam != NULL ? r->clen : 0;

		cmd[0] = opcode & 0xFF;
		cmd[1] = (opcode >> 8) & 0xFF;
		if (plen > 255)
			plen = 255;
		cmd[2] = (uint8_t)plen;
		if (plen > 0)
			memcpy(cmd + 3, r->cparam, plen);
		hci_log_packet(HCI_LOG_CMD, cmd, 3 + plen, false);
	}

	ret = bt_devreq(fd, r, timeout);

	/*
	 * Every HCI command funnels through here.  Emit the opcode, the
	 * controller status (first byte of the Command Complete/Status return
	 * parameters when the request completed, else the bt_devreq errno),
	 * and the command parameter length -- opcode/status/len only, never
	 * command payload.
	 */
	{
		int status = (ret == 0 && r->rparam != NULL && r->rlen > 0) ?
		    ((const uint8_t *)r->rparam)[0] : ret;
		int clen = (r->cparam != NULL) ? (int)r->clen : 0;

		/* Keep used when the probe backend compiles the macro out. */
		(void)status;
		(void)clen;
		BLUED_PROBE_HCI_CMD_REQ(r->opcode, status, clen);
	}

	/* Log incoming event response if BTSnoop is active */
	if (ret == 0 && hci_log_enabled() && r->rlen > 0 &&
	    r->rparam != NULL) {
		uint8_t evt[260];
		int elen;
		uint16_t opcode = r->opcode;

		if (r->event == NG_HCI_EVENT_COMMAND_COMPL) {
			/* Command Complete */
			int log_rlen = r->rlen;

			if (log_rlen > 252)
				log_rlen = 252;
			evt[0] = NG_HCI_EVENT_COMMAND_COMPL;
			evt[1] = (uint8_t)(3 + log_rlen);
			evt[2] = 1;		/* num_hci_cmd_packets */
			evt[3] = opcode & 0xFF;
			evt[4] = (opcode >> 8) & 0xFF;
			memcpy(evt + 5, r->rparam, log_rlen);
			elen = 5 + log_rlen;
		} else {
			/* Command Status */
			evt[0] = NG_HCI_EVENT_COMMAND_STATUS;
			evt[1] = 4;
			evt[2] = *((uint8_t *)r->rparam);
			evt[3] = 1;
			evt[4] = opcode & 0xFF;
			evt[5] = (opcode >> 8) & 0xFF;
			elen = 6;
		}
		hci_log_packet(HCI_LOG_EVT, evt, elen, true);
	}

	return (ret);
}

/*
 * Wrapper around bt_devreq() that logs outgoing HCI commands and
 * their responses to BTSnoop when capture is active.
 * Serialises all HCI command/response pairs through hci_mtx.
 */
int
hci_devreq_logged(int fd, struct bt_devreq *r, int timeout)
{
	pthread_mutex_t *mutex;
	int ret;

	mutex = hci_devreq_mutex(fd);
	pthread_mutex_lock(mutex);
	ret = hci_devreq_logged_locked(fd, r, timeout);
	pthread_mutex_unlock(mutex);
	return (ret);
}

/*
 * Open and bind a raw HCI socket to the named adapter.
 * adapter is e.g. "ubt0".  Returns fd or -1.
 */
int
hci_open(const char *adapter)
{
	int fd;

	fd = bt_devopen(adapter);
	if (fd >= 0) {
		int flags;

		flags = fcntl(fd, F_GETFD);
		if (flags >= 0)
			fcntl(fd, F_SETFD, flags | FD_CLOEXEC | FD_CLOFORK);
	}
	return (fd);
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

	n = hci_devreq_logged(hci_fd, &r, 1);
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

	/*
	 * The kernel writes back the number of connections it reported.
	 * Clamp it to the caller-supplied array size so a controller (or
	 * kernel) returning more entries than requested cannot drive the
	 * loop past the end of cons[].
	 */
	if (cl.num_connections > nitems(cons))
		cl.num_connections = nitems(cons);

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
 * Send a raw HCI command, bypassing libbluetooth's bt_devreq().
 *
 * This is needed for commands like LE_Start_Encryption that generate a
 * Command Status event (not Command Complete), followed by an asynchronous
 * Encryption Change event.  bt_devreq() blocks waiting for the completion
 * event, which doesn't match this flow.
 *
 * Raw HCI socket expects: [type(1), opcode(2), param_len(1), params...]
 * where type = 0x01 for HCI command packets.
 */
int
hci_send_raw_cmd(int hci_fd, uint16_t opcode, const void *params,
    uint8_t plen)
{
	uint8_t pkt[260];	/* max HCI command: 4 + 255 */

	if (plen > 0 && params == NULL) {
		errno = EINVAL;
		return (-1);
	}

	pkt[0] = 0x01;			/* HCI command packet type */
	pkt[1] = opcode & 0xFF;
	pkt[2] = (opcode >> 8) & 0xFF;
	pkt[3] = plen;
	if (plen > 0)
		memcpy(pkt + 4, params, plen);

	pthread_mutex_lock(hci_devreq_mutex(hci_fd));

	/* Log outgoing HCI command to BTSnoop capture */
	hci_log_packet(HCI_LOG_CMD, pkt + 1, 3 + plen, false);

	if (send(hci_fd, pkt, 4 + plen, 0) < 0) {
		pthread_mutex_unlock(hci_devreq_mutex(hci_fd));
		return (-1);
	}
	BLUED_PROBE_HCI_CMD_RAW(opcode, plen);

	pthread_mutex_unlock(hci_devreq_mutex(hci_fd));

	return (0);
}

/*
 * Send HCI Disconnect command to tear down an ACL link.
 *
 * reason is an HCI error code — 0x13 is "Remote User Terminated Connection".
 * This uses bt_devreq with a short timeout; the actual disconnection
 * completes asynchronously via the Disconnection Complete event.
 */
int
hci_disconnect(int hci_fd, uint16_t con_handle, uint8_t reason)
{
	struct bt_devreq r;
	ng_hci_discon_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.con_handle = htole16(con_handle);
	cp.reason = reason;

	memset(&rp, 0, sizeof(rp));

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL,
	    NG_HCI_OCF_DISCON);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (hci_devreq_logged(hci_fd, &r, 1) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "HCI Disconnect failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	return (0);
}
