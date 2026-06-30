/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * blued control socket — Unix domain socket for runtime management.
 *
 * Commands are newline-terminated text:
 *   ADAPTERS   — list active adapters
 *   LIST       — list connected devices
 *   SCAN       — start LE scan, stream results
 *   CONNECT <addr> [public|random] — initiate connection
 *   DISCONNECT <addr> — disconnect device
 *   PAIR <addr> — check bond status
 *   STATUS     — daemon status summary
 *   SERVICES   — list local GATT database
 *   DISCOVER <addr> — run GATT discovery on remote device
 *   READ <addr> <handle> — read characteristic from remote device
 *   WRITE <addr> <handle> <hex> — write characteristic on remote device
 *   ADD_SERVICE <uuid> — add a service to the live GATT database
 *   ADD_CHAR <svc_handle> <uuid> <props> <perms> [value_hex]
 *   REMOVE_SERVICE <handle> — remove a service and all its attributes
 *   LOGLEVEL [level] — get or set log level (0-5)
 *   HOGP_READ <addr> <report_id> — read a Feature report from HOGP device
 *   HOGP_WRITE <addr> <report_id> <hex> — write a Feature report to HOGP device
 *   SUBSCRIBE <addr> <handle> — subscribe to characteristic notifications
 *   UNSUBSCRIBE <addr> <handle> — unsubscribe from notifications
 *   SET_VALUE <handle> <hex> — update a local GATT attribute value
 *   PASSKEY_REPLY <addr> <passkey> — reply to passkey input request
 *   NUMCMP_REPLY <addr> yes|no — reply to numeric comparison request
 *   ECBFC_CONNECT <addr> <psm> <count> — open ECBFC channels (BT 5.2)
 *   ECBFC_RECONFIG <addr> <mtu> <mps> — reconfigure ECBFC channel params
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "blued.h"
#include "ble_util.h"
#include "blued_probes.h"
#include "config.h"
#include "conn.h"
#include "ctl.h"
#include "gatt.h"
#include "hci_util.h"
#include "smp.h"

/* Peripheral GATT database — defined in blued.c */
extern struct att_db periph_gatt_db;

#define CTL_MAXLINE	256

static char	*ctl_sock_path;		/* saved for cleanup unlink */

/*
 * Send a text response to a control client.
 */
static void
blued_ctl_respond(int client_fd, const char *fmt, ...)
{
	va_list ap;
	char buf[1024];
	int len;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (len > 0) {
		if (len >= (int)sizeof(buf))
			len = (int)sizeof(buf) - 1;
		(void)send(client_fd, buf, (size_t)len, MSG_NOSIGNAL);
	}
}

/*
 * Send a file descriptor to a control client via SCM_RIGHTS.
 * The fd is dup'd and capability-limited before sending.
 */
void
blued_ctl_send_fd(int client_fd, int fd_to_send)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(sizeof(int))];
	char byte;
	int dup_fd;

	dup_fd = fcntl(fd_to_send, F_DUPFD_CLOEXEC, 0);
	if (dup_fd < 0)
		return;

	/* Capability-limit the sent fd */
	{
		cap_rights_t rights;

		cap_rights_init(&rights, CAP_SEND, CAP_RECV, CAP_EVENT);
		(void)cap_rights_limit(dup_fd, &rights);
	}

	/* Restrict transfer/inheritance properties */
	(void)cap_xfer_limit(dup_fd, CAP_XFER_ONCE);
	(void)cap_cloexec_limit(dup_fd, CAP_CLOEXEC_LOCKED);
	(void)cap_clofork_limit(dup_fd, CAP_CLOFORK_LOCKED);
	if (cap_ambient_limit(dup_fd) < 0) {
		close(dup_fd);
		blued_ctl_respond(client_fd, "ERROR fd hardening failed\n");
		return;
	}

	memset(&msg, 0, sizeof(msg));
	byte = '\0';
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	memset(cbuf, 0, sizeof(cbuf));
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &dup_fd, sizeof(int));

	if (sendmsg(client_fd, &msg, 0) < 0) {
		close(dup_fd);
		blued_ctl_respond(client_fd, "ERROR fd transfer failed\n");
		return;
	}

	close(dup_fd);
}

/*
 * Handle the ADAPTERS command.
 */
static void
ctl_cmd_adapters(int client_fd)
{
	struct blued_adapter *adp;
	char addr_str[18];

	blued_ctl_respond(client_fd, "ADAPTERS\n");
	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (!adp->active)
			continue;
		bt_ntoa(&adp->addr, addr_str);
		blued_ctl_respond(client_fd, "%s %s\n",
		    adp->name, addr_str);
	}
	blued_ctl_respond(client_fd, "END\n");
}

/*
 * Handle the LIST command — list connected devices.
 */
static void
ctl_cmd_list(int client_fd)
{
	struct blued_conn *conn;
	char addr_str[18];

	blued_ctl_respond(client_fd, "LIST\n");
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		const char *dev_name = "";
		struct smp_bond *bond;

		bt_ntoa(&conn->dst, addr_str);

		/* Look up name from bond DB */
		pthread_mutex_lock(&blued_g.bond_db_lock);
		if (blued_g.bond_db != NULL) {
			bond = smp_find_bond(blued_g.bond_db,
			    (const uint8_t *)&conn->dst, conn->addr_type);
			if (bond != NULL && bond->has_name)
				dev_name = bond->name;
		}
		pthread_mutex_unlock(&blued_g.bond_db_lock);

		blued_ctl_respond(client_fd,
		    "%s state=%d handle=%04x role=%s "
		    "encrypted=%d authenticated=%d key_size=%d "
		    "name=%s\n",
		    addr_str, conn->state, conn->con_handle,
		    conn->role == BLUED_ROLE_PERIPHERAL ?
		        "peripheral" : "central",
		    conn->att != NULL ? conn->att->encrypted : 0,
		    conn->att != NULL ? conn->att->authenticated : 0,
		    conn->att != NULL ? conn->att->enc_key_size : 0,
		    dev_name);
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
	blued_ctl_respond(client_fd, "END\n");
}

/*
 * Handle the SCAN command — start LE scan on all active adapters.
 *
 * Note: cap_enter() is called before the kqueue event loop, so the
 * ctl dispatch runs inside the Capsicum sandbox.  Scanning requires
 * HCI socket operations (send/recv) which are permitted under the
 * sandbox's capability rights.
 */
static void
ctl_cmd_scan(int client_fd)
{
	struct blued_adapter *adp;
	struct ble_scan_result results[BLE_MAX_SCAN_RESULTS];
	int nresults, i;
	char addr_str[18];
	int nadapters_scanned = 0;

	blued_ctl_respond(client_fd, "SCANNING\n");

	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (!adp->active)
			continue;

		BLUED_PROBE_SCAN_START(adp->name);
		nresults = 0;
		if (adp->le_features & LE_FEAT_EXT_ADVERTISING) {
			if (hci_le_ext_scan(adp->hci_fd, 5, results,
			    BLE_MAX_SCAN_RESULTS, &nresults) != 0)
				nresults = 0;
		}
		if (nresults == 0) {
			if (hci_le_scan(adp->hci_fd, 5, results,
			    BLE_MAX_SCAN_RESULTS, &nresults) < 0) {
				blued_ctl_respond(client_fd,
				    "WARN %s: scan failed\n", adp->name);
				continue;
			}
		}

		nadapters_scanned++;

		for (i = 0; i < nresults; i++) {
			struct ble_scan_result *r = &results[i];
			char svc_str[128];
			int soff;

			bt_ntoa((bdaddr_t *)r->addr, addr_str);
			BLUED_PROBE_SCAN_RESULT(addr_str, r->rssi);

			/* Build comma-separated service UUID list */
			svc_str[0] = '\0';
			soff = 0;
			for (int s = 0; s < r->num_svc_uuids; s++) {
				int w;

				if (soff >= (int)sizeof(svc_str) - 8)
					break;
				w = snprintf(svc_str + soff,
				    sizeof(svc_str) - (size_t)soff,
				    "%s0x%04X",
				    s > 0 ? "," : "",
				    r->svc_uuids[s]);
				if (w > 0)
					soff += w;
			}

			blued_ctl_respond(client_fd,
			    "DEVICE [%s] %s %s rssi=%d name=%s "
			    "mfr=0x%04X svcs=%s\n",
			    adp->name,
			    addr_str,
			    r->addr_type == BDADDR_LE_RANDOM ?
			        "random" : "public",
			    r->rssi,
			    r->has_name ? r->name : "",
			    r->mfr_id,
			    svc_str);
		}
	}

	if (nadapters_scanned == 0) {
		blued_ctl_respond(client_fd, "ERROR no active adapter\n");
		return;
	}

	blued_ctl_respond(client_fd, "END\n");
}

/*
 * Handle the STATUS command.
 */
static void
ctl_cmd_status(int client_fd)
{
	struct blued_adapter *adp;
	struct blued_conn *conn;
	int nadp, nconn;

	nadp = 0;
	LIST_FOREACH(adp, &blued_g.adapters, entries)
		if (adp->active)
			nadp++;

	nconn = 0;
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries)
		nconn++;
	pthread_rwlock_unlock(&blued_g.conns_lock);

	blued_ctl_respond(client_fd,
	    "STATUS adapters=%d connections=%d\n", nadp, nconn);
}

/*
 * Handle the CONNECT command.
 * Syntax: CONNECT <addr> [public|random]
 */
static void
ctl_cmd_connect(int client_fd, const char *args)
{
	struct blued_adapter *adp;
	bdaddr_t addr;
	char addr_str[18];
	char buf[64];
	uint8_t addr_type;

	while (*args == ' ')
		args++;
	strlcpy(buf, args, sizeof(buf));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' ||
		    buf[len - 1] == '\r' || buf[len - 1] == ' '))
			buf[--len] = '\0';
	}

	/* Parse address and optional type */
	addr_type = BDADDR_LE_PUBLIC;
	{
		char *sp = strchr(buf, ' ');
		if (sp != NULL) {
			*sp = '\0';
			sp++;
			while (*sp == ' ')
				sp++;
			if (strcmp(sp, "random") == 0)
				addr_type = BDADDR_LE_RANDOM;
		}
	}

	strlcpy(addr_str, buf, sizeof(addr_str));
	if (!bt_aton(addr_str, &addr)) {
		blued_ctl_respond(client_fd, "ERROR invalid address\n");
		return;
	}

	/* Check not already connected */
	if (blued_conn_by_addr(&addr) != NULL) {
		blued_ctl_respond(client_fd, "ERROR already connected\n");
		return;
	}

	/* Find first active adapter */
	adp = LIST_FIRST(&blued_g.adapters);
	while (adp != NULL && !adp->active)
		adp = LIST_NEXT(adp, entries);
	if (adp == NULL) {
		blued_ctl_respond(client_fd, "ERROR no active adapter\n");
		return;
	}

	{
		struct blued_conn *conn;
		struct hogp_device *hdev;
		pthread_t tid;
		pthread_attr_t pattr;

		hdev = blued_hogp_alloc(adp, (const uint8_t *)&addr,
		    addr_type, false);
		if (hdev == NULL) {
			blued_ctl_respond(client_fd,
			    "ERROR out of memory\n");
			return;
		}

		conn = blued_conn_alloc();
		if (conn == NULL) {
			free(hdev);
			blued_ctl_respond(client_fd,
			    "ERROR out of memory\n");
			return;
		}
		conn->hogp = hdev;
		memcpy(&conn->dst, &addr, sizeof(conn->dst));
		conn->addr_type = addr_type;
		conn->adapter = adp;
		conn->role = BLUED_ROLE_CENTRAL;
		conn->reconnect = false;
		blued_conn_set_state(conn, BLUED_CONN_CONNECTING);

		pthread_attr_init(&pattr);
		pthread_attr_setdetachstate(&pattr,
		    PTHREAD_CREATE_DETACHED);
		if (pthread_create(&tid, &pattr,
		    blued_conn_setup_central, conn) != 0) {
			blued_conn_free(conn);
			free(hdev);
			pthread_attr_destroy(&pattr);
			blued_ctl_respond(client_fd,
			    "ERROR setup thread failed\n");
			return;
		}
		pthread_attr_destroy(&pattr);

		bt_ntoa(&addr, addr_str);
		LOG_HOGP(1, "CONNECT %s %s — setup thread spawned",
		    addr_str,
		    addr_type == BDADDR_LE_RANDOM ? "random" : "public");

		blued_ctl_respond(client_fd,
		    "OK CONNECT %s %s connecting\n",
		    addr_str,
		    addr_type == BDADDR_LE_RANDOM ? "random" : "public");
	}
}

/*
 * Handle the CONNECT_NAME command — scan for a device by name, then connect.
 * Syntax: CONNECT_NAME <device_name>
 *
 * Performs a quick scan on all active adapters, finds the first device
 * whose advertised name matches (case-insensitive prefix), and connects.
 */
static void
ctl_cmd_connect_name(int client_fd, const char *args)
{
	struct blued_adapter *adp;
	struct ble_scan_result results[BLE_MAX_SCAN_RESULTS];
	int nresults, i;
	char name[64];
	char addr_str[18];
	struct ble_scan_result *match;

	while (*args == ' ')
		args++;
	strlcpy(name, args, sizeof(name));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(name);
		while (len > 0 && (name[len - 1] == '\n' ||
		    name[len - 1] == '\r' || name[len - 1] == ' '))
			name[--len] = '\0';
	}

	if (name[0] == '\0') {
		blued_ctl_respond(client_fd,
		    "ERROR usage: CONNECT_NAME <device_name>\n");
		return;
	}

	/* Scan for the device */
	match = NULL;
	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (!adp->active)
			continue;

		nresults = 0;
		if (adp->le_features & LE_FEAT_EXT_ADVERTISING) {
			if (hci_le_ext_scan(adp->hci_fd, 5, results,
			    BLE_MAX_SCAN_RESULTS, &nresults) != 0)
				nresults = 0;
		}
		if (nresults == 0) {
			if (hci_le_scan(adp->hci_fd, 5, results,
			    BLE_MAX_SCAN_RESULTS, &nresults) < 0)
				continue;
		}

		for (i = 0; i < nresults; i++) {
			if (!results[i].has_name)
				continue;
			if (strcasecmp(results[i].name, name) == 0) {
				match = &results[i];
				break;
			}
		}
		if (match != NULL)
			break;
	}

	if (match == NULL) {
		blued_ctl_respond(client_fd,
		    "ERROR device '%s' not found\n", name);
		return;
	}

	bt_ntoa((bdaddr_t *)match->addr, addr_str);

	/* Now connect using the found address */
	{
		char connect_args[64];
		snprintf(connect_args, sizeof(connect_args), "%s %s",
		    addr_str,
		    match->addr_type == BDADDR_LE_RANDOM ?
		        "random" : "public");
		ctl_cmd_connect(client_fd, connect_args);
	}
}

/*
 * Handle the DISCONNECT command.
 */
static void
ctl_cmd_disconnect(int client_fd, const char *args)
{
	struct blued_conn *conn;
	bdaddr_t addr;
	char addr_str[18];

	while (*args == ' ')
		args++;
	strlcpy(addr_str, args, sizeof(addr_str));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(addr_str);
		while (len > 0 && (addr_str[len - 1] == '\n' ||
		    addr_str[len - 1] == '\r' ||
		    addr_str[len - 1] == ' '))
			addr_str[--len] = '\0';
	}

	if (!bt_aton(addr_str, &addr)) {
		blued_ctl_respond(client_fd, "ERROR invalid address\n");
		return;
	}

	pthread_rwlock_wrlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (memcmp(&conn->dst, &addr, sizeof(addr)) == 0) {
			/*
			 * Refuse to disconnect a conn whose setup thread
			 * is still running — closing the fd under it would
			 * cause use-after-free / double-close.
			 *
			 * Hold the write lock through the entire operation
			 * to prevent another thread from freeing the conn
			 * between lookup and access.
			 */
			if (atomic_load(&conn->state) ==
			    BLUED_CONN_CONNECTING) {
				pthread_rwlock_unlock(&blued_g.conns_lock);
				blued_ctl_respond(client_fd,
				    "ERROR connection still setting up\n");
				return;
			}
			/* Close the ATT fd — the event loop will detect
			 * the disconnect and clean up */
			if (conn->att_fd >= 0) {
				close(conn->att_fd);
				conn->att_fd = -1;
			}
			atomic_store(&conn->state, BLUED_CONN_IDLE);
			pthread_rwlock_unlock(&blued_g.conns_lock);
			blued_ctl_respond(client_fd, "OK disconnected\n");
			return;
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
	blued_ctl_respond(client_fd, "ERROR device not found\n");
}

/*
 * Handle the BONDS command — list all bonded devices.
 */
static void
ctl_cmd_bonds(int client_fd)
{

	blued_ctl_respond(client_fd, "BONDS\n");
	pthread_mutex_lock(&blued_g.bond_db_lock);
	if (blued_g.bond_db != NULL) {
		for (int i = 0; i < blued_g.bond_db->count; i++) {
			struct smp_bond *b = &blued_g.bond_db->bonds[i];
			char addr_str[18];

			bt_ntoa((bdaddr_t *)b->addr, addr_str);
			blued_ctl_respond(client_fd,
			    "%s %s ltk=%d irk=%d sc=%d lk=%d csrk=%d name=%s\n",
			    addr_str,
			    b->addr_type == BDADDR_LE_RANDOM ?
			    "random" : "public",
			    b->has_ltk, b->has_irk, b->is_sc,
			    b->has_link_key, b->has_csrk,
			    b->has_name ? b->name : "");
		}
	}
	pthread_mutex_unlock(&blued_g.bond_db_lock);
	blued_ctl_respond(client_fd, "END\n");
}

/*
 * Handle the UNBOND command — remove a bond by address.
 * Syntax: UNBOND <addr>
 */
static void
ctl_cmd_unbond(int client_fd, const char *args)
{
	bdaddr_t addr;
	char addr_str[18];
	struct blued_adapter *adp;

	while (*args == ' ')
		args++;
	strlcpy(addr_str, args, sizeof(addr_str));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(addr_str);
		while (len > 0 && (addr_str[len - 1] == '\n' ||
		    addr_str[len - 1] == '\r' ||
		    addr_str[len - 1] == ' '))
			addr_str[--len] = '\0';
	}

	if (!bt_aton(addr_str, &addr)) {
		blued_ctl_respond(client_fd, "ERROR invalid address\n");
		return;
	}

	pthread_mutex_lock(&blued_g.bond_db_lock);

	if (blued_g.bond_db == NULL) {
		pthread_mutex_unlock(&blued_g.bond_db_lock);
		blued_ctl_respond(client_fd, "ERROR no bond database\n");
		return;
	}

	/* Find and remove the bond */
	{
		struct smp_bond *bond;

		bond = smp_find_bond(blued_g.bond_db,
		    (const uint8_t *)&addr, BDADDR_LE_PUBLIC);
		if (bond == NULL)
			bond = smp_find_bond(blued_g.bond_db,
			    (const uint8_t *)&addr, BDADDR_LE_RANDOM);
		if (bond == NULL) {
			pthread_mutex_unlock(&blued_g.bond_db_lock);
			blued_ctl_respond(client_fd,
			    "ERROR device not bonded\n");
			return;
		}

		/* Remove from filter accept list */
		adp = LIST_FIRST(&blued_g.adapters);
		if (adp != NULL) {
			uint8_t at = (bond->addr_type == BDADDR_LE_RANDOM) ?
			    0x01 : 0x00;
			hci_le_remove_device_from_filter_accept_list(
			    adp->hci_fd, at, bond->addr);
		}

		/* Remove bond by shifting array */
		{
			int idx = (int)(bond - blued_g.bond_db->bonds);
			int remain = blued_g.bond_db->count - idx - 1;

			if (remain > 0)
				memmove(bond, bond + 1,
				    remain * sizeof(*bond));
			blued_g.bond_db->count--;
		}

		smp_bond_db_save(blued_g.bond_db);

		pthread_mutex_unlock(&blued_g.bond_db_lock);

		BLUED_LOG_SECURITY("bond removed addr=%s", addr_str);
		BLUED_PROBE_BOND_REMOVE(addr_str);
		blued_ctl_respond(client_fd, "OK unbonded %s\n", addr_str);
	}
}

/*
 * Handle the PAIR command — check bond status for a device.
 *
 * SMP pairing is initiated automatically during connection setup:
 * central mode pairs on GATT auth errors, peripheral mode responds
 * to pairing requests.  This command checks whether the device is
 * already bonded and provides guidance for re-pairing.
 */
static void
ctl_cmd_pair(int client_fd, const char *args)
{
	struct blued_conn *conn;
	bdaddr_t addr;
	char addr_str[18];
	char buf[64];

	while (*args == ' ')
		args++;
	strlcpy(buf, args, sizeof(buf));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' ||
		    buf[len - 1] == '\r' || buf[len - 1] == ' '))
			buf[--len] = '\0';
	}

	strlcpy(addr_str, buf, sizeof(addr_str));
	if (!bt_aton(addr_str, &addr)) {
		blued_ctl_respond(client_fd, "ERROR invalid address\n");
		return;
	}

	conn = blued_conn_by_addr(&addr);
	if (conn == NULL) {
		blued_ctl_respond(client_fd,
		    "ERROR device not connected\n");
		return;
	}

	/*
	 * SMP pairing is initiated automatically during connection setup:
	 * central mode pairs on GATT auth errors, peripheral mode responds
	 * to pairing requests.  To re-pair, unbond and reconnect.
	 */
	{
		struct smp_bond *bond = NULL;

		pthread_mutex_lock(&blued_g.bond_db_lock);
		if (blued_g.bond_db != NULL)
			bond = smp_find_bond(blued_g.bond_db,
			    (const uint8_t *)&conn->dst, conn->addr_type);
		pthread_mutex_unlock(&blued_g.bond_db_lock);
		if (bond != NULL)
			blued_ctl_respond(client_fd,
			    "OK already bonded (use UNBOND to re-pair)\n");
		else
			blued_ctl_respond(client_fd,
			    "OK pairing in progress or pending "
			    "auth request\n");
	}
}

/*
 * Handle the PHY command — show PHY for all active connections.
 */
static void
ctl_cmd_phy(int client_fd)
{
	struct blued_adapter *adp;
	struct blued_conn *conn;
	char addr_str[18];

	adp = LIST_FIRST(&blued_g.adapters);
	if (adp == NULL) {
		blued_ctl_respond(client_fd, "ERROR no adapter\n");
		return;
	}

	blued_ctl_respond(client_fd, "PHY\n");
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		uint8_t tx_phy, rx_phy;

		if (conn->con_handle == 0)
			continue;
		bt_ntoa(&conn->dst, addr_str);
		if (hci_le_read_phy(adp->hci_fd, conn->con_handle,
		    &tx_phy, &rx_phy) == 0) {
			blued_ctl_respond(client_fd,
			    "%s tx=%s rx=%s\n", addr_str,
			    tx_phy == 2 ? "2M" :
			    tx_phy == 3 ? "Coded" : "1M",
			    rx_phy == 2 ? "2M" :
			    rx_phy == 3 ? "Coded" : "1M");
		} else {
			blued_ctl_respond(client_fd,
			    "%s phy=unknown\n", addr_str);
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
	blued_ctl_respond(client_fd, "END\n");
}

/*
 * Build a human-readable string of characteristic properties.
 */
static void
ctl_props_str(uint8_t props, char *buf, size_t buflen)
{
	buf[0] = '\0';

	if (props & GATT_PROP_BROADCAST)
		strlcat(buf, "broadcast|", buflen);
	if (props & GATT_PROP_READ)
		strlcat(buf, "read|", buflen);
	if (props & GATT_PROP_WRITE_NO_RSP)
		strlcat(buf, "write_no_rsp|", buflen);
	if (props & GATT_PROP_WRITE)
		strlcat(buf, "write|", buflen);
	if (props & GATT_PROP_NOTIFY)
		strlcat(buf, "notify|", buflen);
	if (props & GATT_PROP_INDICATE)
		strlcat(buf, "indicate|", buflen);
	if (props & GATT_PROP_AUTH_SIGNED_WRITE)
		strlcat(buf, "auth_signed|", buflen);
	if (props & GATT_PROP_EXTENDED)
		strlcat(buf, "extended|", buflen);

	/* Remove trailing '|' */
	{
		size_t len = strlen(buf);
		if (len > 0 && buf[len - 1] == '|')
			buf[len - 1] = '\0';
	}
}

/*
 * Set ATT socket I/O timeouts for control socket commands.
 * Prevents a slow or unresponsive remote device from blocking
 * the main event loop indefinitely.  Returns the previous timeout
 * so the caller can restore it.
 */
/*
 * ATT I/O timeout for control socket commands (DISCOVER, READ, WRITE,
 * HOGP_READ, HOGP_WRITE).  These commands block the main event loop
 * while waiting for the BLE device to respond.  A malicious or slow
 * device can stall event processing for up to this duration.
 *
 * Kept short (2s) to minimize the DoS window.  A proper fix would
 * dispatch these to worker threads, but ATT is a sequential protocol
 * on a single socket: the kqueue event loop and a worker thread cannot
 * both recv() from the same fd without stealing each other's data.
 * Moving to async ATT would require splitting request/response I/O
 * from the notification path, which is a larger refactor.
 */
#define CTL_ATT_TIMEOUT_SEC	2

static void
ctl_set_att_timeout(int att_fd, struct timeval *old_tv)
{
	struct timeval tv = { .tv_sec = CTL_ATT_TIMEOUT_SEC, .tv_usec = 0 };
	socklen_t len = sizeof(*old_tv);

	if (getsockopt(att_fd, SOL_SOCKET, SO_RCVTIMEO, old_tv, &len) < 0)
		memset(old_tv, 0, sizeof(*old_tv));
	(void)setsockopt(att_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(att_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static void
ctl_restore_att_timeout(int att_fd, const struct timeval *old_tv)
{

	(void)setsockopt(att_fd, SOL_SOCKET, SO_RCVTIMEO, old_tv,
	    sizeof(*old_tv));
	(void)setsockopt(att_fd, SOL_SOCKET, SO_SNDTIMEO, old_tv,
	    sizeof(*old_tv));
}

/*
 * Handle the SERVICES command — list the local GATT database.
 */
static void
ctl_cmd_services(int client_fd)
{
	struct att_db *db = &periph_gatt_db;

	if (db->count == 0) {
		blued_ctl_respond(client_fd, "ERROR no GATT database\n");
		return;
	}

	blued_ctl_respond(client_fd, "SERVICES\n");
	for (int i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];
		char line[256];

		switch (a->uuid16) {
		case GATT_UUID_PRIMARY_SERVICE:
			/* Service UUID is stored in the value */
			if (a->value_len == 2) {
				uint16_t svc_uuid =
				    (uint16_t)a->value[0] |
				    ((uint16_t)a->value[1] << 8);
				snprintf(line, sizeof(line),
				    "  handle=0x%04X type=primary_service "
				    "uuid=0x%04X\n",
				    a->handle, svc_uuid);
			} else {
				snprintf(line, sizeof(line),
				    "  handle=0x%04X type=primary_service "
				    "uuid=128bit\n",
				    a->handle);
			}
			break;

		case GATT_UUID_SECONDARY_SERVICE:
			snprintf(line, sizeof(line),
			    "  handle=0x%04X type=secondary_service\n",
			    a->handle);
			break;

		case GATT_UUID_INCLUDE:
			snprintf(line, sizeof(line),
			    "  handle=0x%04X type=include\n",
			    a->handle);
			break;

		case GATT_UUID_CHARACTERISTIC: {
			/*
			 * Characteristic declaration value layout:
			 *   byte 0: properties
			 *   bytes 1-2: value handle (little-endian)
			 *   bytes 3+: UUID (2 or 16 bytes)
			 */
			uint8_t props = 0;
			uint16_t char_uuid = 0;
			char props_str[128];

			if (a->value_len >= 5)
				props = a->value[0];
			ctl_props_str(props, props_str, sizeof(props_str));
			if (a->value_len == 5) {
				/* 16-bit UUID */
				char_uuid =
				    (uint16_t)a->value[3] |
				    ((uint16_t)a->value[4] << 8);
				snprintf(line, sizeof(line),
				    "  handle=0x%04X type=characteristic "
				    "uuid=0x%04X props=%s\n",
				    a->handle, char_uuid, props_str);
			} else {
				/* 128-bit UUID */
				snprintf(line, sizeof(line),
				    "  handle=0x%04X type=characteristic "
				    "uuid=128bit props=%s\n",
				    a->handle, props_str);
			}
			break;
		}

		case GATT_UUID_CCCD:
			snprintf(line, sizeof(line),
			    "  handle=0x%04X type=cccd\n",
			    a->handle);
			break;

		default:
			if (a->is_char_value) {
				snprintf(line, sizeof(line),
				    "  handle=0x%04X type=value "
				    "value_len=%u\n",
				    a->handle, a->value_len);
			} else {
				snprintf(line, sizeof(line),
				    "  handle=0x%04X type=descriptor "
				    "uuid=0x%04X\n",
				    a->handle, a->uuid16);
			}
			break;
		}

		blued_ctl_respond(client_fd, "%s", line);
	}
	blued_ctl_respond(client_fd, "END\n");
}

/*
 * Handle the DISCOVER command — GATT discovery on a remote device.
 * Syntax: DISCOVER <addr>
 *
 * Note: this command blocks in the main thread while performing BLE
 * I/O (ATT transactions for service, characteristic, and descriptor
 * discovery).  This is acceptable for a diagnostic/management command
 * but should be made asynchronous if latency becomes a concern.
 */
static void
ctl_cmd_discover(int client_fd, const char *args)
{
	struct blued_conn *conn;
	bdaddr_t addr;
	char addr_str[18];
	struct gatt_service svcs[GATT_MAX_SERVICES];
	struct timeval old_tv;
	int nsvcs, i;

	while (*args == ' ')
		args++;
	strlcpy(addr_str, args, sizeof(addr_str));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(addr_str);
		while (len > 0 && (addr_str[len - 1] == '\n' ||
		    addr_str[len - 1] == '\r' || addr_str[len - 1] == ' '))
			addr_str[--len] = '\0';
	}

	if (!bt_aton(addr_str, &addr)) {
		blued_ctl_respond(client_fd, "ERROR invalid address\n");
		return;
	}

	conn = blued_conn_by_addr(&addr);
	if (conn == NULL) {
		blued_ctl_respond(client_fd, "ERROR device not connected\n");
		return;
	}
	if (conn->att == NULL) {
		blued_ctl_respond(client_fd, "ERROR no ATT channel\n");
		return;
	}

	ctl_set_att_timeout(conn->att->fd, &old_tv);

	/* Discover primary services */
	nsvcs = 0;
	if (gatt_discover_primary_services(conn->att, svcs,
	    GATT_MAX_SERVICES, &nsvcs) != 0) {
		ctl_restore_att_timeout(conn->att->fd, &old_tv);
		blued_ctl_respond(client_fd,
		    "ERROR service discovery failed\n");
		return;
	}

	bt_ntoa(&addr, addr_str);
	blued_ctl_respond(client_fd, "DISCOVER %s\n", addr_str);

	for (i = 0; i < nsvcs; i++) {
		struct gatt_service *svc = &svcs[i];
		struct gatt_char chars[GATT_MAX_CHARS];
		int nchars, j;

		if (svc->uuid16 != 0) {
			blued_ctl_respond(client_fd,
			    "  service uuid=0x%04X "
			    "handles=0x%04X-0x%04X\n",
			    svc->uuid16,
			    svc->start_handle, svc->end_handle);
		} else {
			blued_ctl_respond(client_fd,
			    "  service uuid=128bit "
			    "handles=0x%04X-0x%04X\n",
			    svc->start_handle, svc->end_handle);
		}

		/* Discover characteristics within this service */
		nchars = 0;
		if (gatt_discover_characteristics(conn->att,
		    svc->start_handle, svc->end_handle,
		    chars, GATT_MAX_CHARS, &nchars) != 0)
			continue;

		for (j = 0; j < nchars; j++) {
			struct gatt_char *ch = &chars[j];
			struct gatt_desc descs[GATT_MAX_DESCS];
			int ndescs, k;
			uint16_t desc_start, desc_end;
			char props_str[128];

			ctl_props_str(ch->properties, props_str,
			    sizeof(props_str));

			if (ch->uuid16 != 0) {
				blued_ctl_respond(client_fd,
				    "    char uuid=0x%04X "
				    "handle=0x%04X props=%s\n",
				    ch->uuid16,
				    ch->value_handle,
				    props_str);
			} else {
				blued_ctl_respond(client_fd,
				    "    char uuid=128bit "
				    "handle=0x%04X props=%s\n",
				    ch->value_handle,
				    props_str);
			}

			/* Discover descriptors between this char value
			 * handle + 1 and the next char decl (or service end) */
			desc_start = ch->value_handle + 1;
			if (j + 1 < nchars)
				desc_end = chars[j + 1].decl_handle - 1;
			else
				desc_end = svc->end_handle;

			if (desc_start > desc_end)
				continue;

			ndescs = 0;
			if (gatt_discover_descriptors(conn->att,
			    desc_start, desc_end,
			    descs, GATT_MAX_DESCS, &ndescs) != 0)
				continue;

			for (k = 0; k < ndescs; k++) {
				if (descs[k].uuid16 != 0) {
					blued_ctl_respond(client_fd,
					    "      desc uuid=0x%04X "
					    "handle=0x%04X\n",
					    descs[k].uuid16,
					    descs[k].handle);
				} else {
					blued_ctl_respond(client_fd,
					    "      desc uuid=128bit "
					    "handle=0x%04X\n",
					    descs[k].handle);
				}
			}
		}
	}

	ctl_restore_att_timeout(conn->att->fd, &old_tv);
	blued_ctl_respond(client_fd, "END\n");
}

/*
 * Handle the READ command — read a characteristic from a remote device.
 * Syntax: READ <addr> <handle>
 *
 * Note: this command blocks in the main thread while performing a
 * single ATT Read Request/Response exchange.
 */
static void
ctl_cmd_read(int client_fd, const char *args)
{
	struct blued_conn *conn;
	bdaddr_t addr;
	char addr_str[18];
	char buf[64];
	char *sp;
	uint16_t handle;
	uint8_t valbuf[ATT_PDU_BUF_SIZE];
	size_t outlen;
	char hexbuf[ATT_PDU_BUF_SIZE * 2 + 1];
	struct timeval old_tv;
	size_t hi;

	while (*args == ' ')
		args++;
	strlcpy(buf, args, sizeof(buf));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' ||
		    buf[len - 1] == '\r' || buf[len - 1] == ' '))
			buf[--len] = '\0';
	}

	/* Split into addr and handle */
	sp = strchr(buf, ' ');
	if (sp == NULL) {
		blued_ctl_respond(client_fd,
		    "ERROR usage: READ <addr> <handle>\n");
		return;
	}
	*sp = '\0';
	sp++;
	while (*sp == ' ')
		sp++;

	strlcpy(addr_str, buf, sizeof(addr_str));
	if (!bt_aton(addr_str, &addr)) {
		blued_ctl_respond(client_fd, "ERROR invalid address\n");
		return;
	}

	/* Parse handle — accept 0x prefix or decimal */
	{
		char *endp;
		unsigned long hval;

		hval = strtoul(sp, &endp, 0);
		if (endp == sp || (*endp != '\0' && *endp != ' ') ||
		    hval == 0 || hval > 0xFFFF) {
			blued_ctl_respond(client_fd,
			    "ERROR invalid handle\n");
			return;
		}
		handle = (uint16_t)hval;
	}

	conn = blued_conn_by_addr(&addr);
	if (conn == NULL) {
		blued_ctl_respond(client_fd, "ERROR device not connected\n");
		return;
	}
	if (conn->att == NULL) {
		blued_ctl_respond(client_fd, "ERROR no ATT channel\n");
		return;
	}

	ctl_set_att_timeout(conn->att->fd, &old_tv);
	outlen = 0;
	if (att_read(conn->att, handle, valbuf, sizeof(valbuf),
	    &outlen) != 0) {
		ctl_restore_att_timeout(conn->att->fd, &old_tv);
		blued_ctl_respond(client_fd, "ERROR read failed\n");
		return;
	}
	ctl_restore_att_timeout(conn->att->fd, &old_tv);

	/* Format value as hex string */
	for (hi = 0; hi < outlen; hi++)
		snprintf(hexbuf + hi * 2, 3, "%02X", valbuf[hi]);
	if (outlen == 0)
		hexbuf[0] = '\0';

	blued_ctl_respond(client_fd,
	    "OK READ 0x%04X len=%zu value=%s\n",
	    handle, outlen, hexbuf);
}

/*
 * Handle the WRITE command — write to a characteristic on a remote device.
 * Syntax: WRITE <addr> <handle> <hex>
 *
 * Note: this command blocks in the main thread while performing a
 * single ATT Write Request/Response exchange.
 */
static void
ctl_cmd_write(int client_fd, const char *args)
{
	struct blued_conn *conn;
	bdaddr_t addr;
	char addr_str[18];
	char buf[CTL_MAXLINE];
	char *sp, *hex;
	uint16_t handle;
	uint8_t data[ATT_PDU_BUF_SIZE];
	struct timeval old_tv;
	size_t dlen, hexlen, i;

	while (*args == ' ')
		args++;
	strlcpy(buf, args, sizeof(buf));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' ||
		    buf[len - 1] == '\r' || buf[len - 1] == ' '))
			buf[--len] = '\0';
	}

	/* Split: addr handle hex */
	sp = strchr(buf, ' ');
	if (sp == NULL) {
		blued_ctl_respond(client_fd,
		    "ERROR usage: WRITE <addr> <handle> <hex>\n");
		return;
	}
	*sp = '\0';
	sp++;
	while (*sp == ' ')
		sp++;

	strlcpy(addr_str, buf, sizeof(addr_str));
	if (!bt_aton(addr_str, &addr)) {
		blued_ctl_respond(client_fd, "ERROR invalid address\n");
		return;
	}

	/* Parse handle */
	hex = strchr(sp, ' ');
	if (hex == NULL) {
		blued_ctl_respond(client_fd,
		    "ERROR usage: WRITE <addr> <handle> <hex>\n");
		return;
	}
	*hex = '\0';
	hex++;
	while (*hex == ' ')
		hex++;

	{
		char *endp;
		unsigned long hval;

		hval = strtoul(sp, &endp, 0);
		if (endp == sp || (*endp != '\0' && *endp != ' ') ||
		    hval == 0 || hval > 0xFFFF) {
			blued_ctl_respond(client_fd,
			    "ERROR invalid handle\n");
			return;
		}
		handle = (uint16_t)hval;
	}

	/* Convert hex string to bytes */
	hexlen = strlen(hex);
	if (hexlen % 2 != 0 || hexlen == 0) {
		blued_ctl_respond(client_fd,
		    "ERROR hex value must be even length\n");
		return;
	}
	dlen = hexlen / 2;
	if (dlen > sizeof(data)) {
		blued_ctl_respond(client_fd, "ERROR value too long\n");
		return;
	}
	for (i = 0; i < dlen; i++) {
		unsigned int byte;
		if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
			blued_ctl_respond(client_fd,
			    "ERROR invalid hex value\n");
			return;
		}
		data[i] = (uint8_t)byte;
	}

	conn = blued_conn_by_addr(&addr);
	if (conn == NULL) {
		blued_ctl_respond(client_fd, "ERROR device not connected\n");
		return;
	}
	if (conn->att == NULL) {
		blued_ctl_respond(client_fd, "ERROR no ATT channel\n");
		return;
	}

	ctl_set_att_timeout(conn->att->fd, &old_tv);
	if (att_write_req(conn->att, handle, data, dlen) != 0) {
		ctl_restore_att_timeout(conn->att->fd, &old_tv);
		blued_ctl_respond(client_fd, "ERROR write failed\n");
		return;
	}
	ctl_restore_att_timeout(conn->att->fd, &old_tv);

	blued_ctl_respond(client_fd,
	    "OK WRITE 0x%04X len=%zu\n", handle, dlen);
}

/*
 * Helper: recompute the GATT Database Hash after a live DB change
 * and send Service Changed indication to all connected peripheral
 * clients that have enabled indications.
 */
static void
ctl_recompute_hash_and_notify(uint16_t start, uint16_t end)
{
	struct att_db *db = &periph_gatt_db;
	uint8_t db_hash[16];
	struct blued_conn *conn;

	/* Recompute DB hash */
	attdb_compute_db_hash(db, db_hash);
	for (int i = 0; i < db->count; i++) {
		if (db->attrs[i].uuid16 == 0x2B2A /* UUID_DATABASE_HASH */ &&
		    db->attrs[i].value_len == 16) {
			memcpy(db->attrs[i].value, db_hash, 16);
			break;
		}
	}

	/*
	 * Mark all connected clients with Robust Caching as
	 * change-unaware.  They will receive ATT_ERR_DATABASE_OUT_OF_SYNC
	 * (0x12) on subsequent requests until they read the new DB hash.
	 * Core Spec Vol 3 Part G Section 2.5.2.1.
	 */
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (conn->att != NULL && conn->att->robust_caching)
			conn->att->change_aware = false;
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);

	/*
	 * Send Service Changed indication to all connected peripheral
	 * clients.  Walk the connection list and notify each that has
	 * an ATT connection and is in peripheral role.
	 */
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (conn->role != BLUED_ROLE_PERIPHERAL)
			continue;
		if (conn->att == NULL)
			continue;
		if (atomic_load(&conn->state) != BLUED_CONN_ACTIVE)
			continue;

		/* Build the affected handle range [start, end] */
		{
			uint8_t val[4];
			uint16_t sc_handle = 0;
			uint16_t cccd_handle = 0;
			bool ind_enabled = false;

			/* Find Service Changed characteristic */
			for (int i = 0; i < db->count; i++) {
				if (db->attrs[i].uuid16 == 0x2A05 &&
				    db->attrs[i].is_char_value) {
					sc_handle = db->attrs[i].handle;
					if (i + 1 < db->count &&
					    db->attrs[i + 1].uuid16 ==
					    GATT_UUID_CCCD)
						cccd_handle =
						    db->attrs[i + 1].handle;
					break;
				}
			}
			if (sc_handle == 0 || cccd_handle == 0)
				continue;

			/* Check if indications enabled */
			for (int j = 0; j < conn->att->cccd_count; j++) {
				if (conn->att->cccds[j].handle ==
				    cccd_handle &&
				    (conn->att->cccds[j].value &
				    GATT_CCCD_INDICATE) != 0) {
					ind_enabled = true;
					break;
				}
			}
			if (!ind_enabled)
				continue;

			put_le16(val, start);
			put_le16(val + 2, end);
			(void)att_send_indication(conn->att, sc_handle,
			    val, sizeof(val));
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
}

/*
 * Handle the ADD_SERVICE command.
 * Syntax: ADD_SERVICE <uuid>
 *
 * Creates a new service in the live GATT database.
 * <uuid> is either "0xNNNN" for 16-bit or a 128-bit UUID string.
 */
static void
ctl_cmd_add_service(int client_fd, const char *args)
{
	struct att_db *db = &periph_gatt_db;
	char buf[64];
	uint16_t uuid16 = 0;
	uint8_t uuid128[16];
	uint16_t handle;

	while (*args == ' ')
		args++;
	strlcpy(buf, args, sizeof(buf));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' ||
		    buf[len - 1] == '\r' || buf[len - 1] == ' '))
			buf[--len] = '\0';
	}

	if (blued_parse_uuid(buf, &uuid16, uuid128) != 0) {
		blued_ctl_respond(client_fd, "ERROR invalid uuid\n");
		return;
	}

	/* Reject reserved GATT infrastructure UUIDs */
	if (uuid16 != 0 && (uuid16 >= 0x2800 && uuid16 <= 0x2803)) {
		blued_ctl_respond(client_fd,
		    "ERROR reserved GATT infrastructure UUID\n");
		return;
	}
	/* Reject reserved GAP/GATT service UUIDs */
	if (uuid16 == 0x1800 || uuid16 == 0x1801) {
		blued_ctl_respond(client_fd,
		    "ERROR reserved service UUID\n");
		return;
	}

	if (uuid16 != 0)
		handle = attdb_add_service(db, uuid16);
	else
		handle = attdb_add_service128(db, uuid128);

	if (handle == 0) {
		blued_ctl_respond(client_fd,
		    "ERROR database full\n");
		return;
	}

	ctl_recompute_hash_and_notify(handle, 0xFFFF);

	BLUED_PROBE_GATT_SVC_ADD(handle, uuid16);

	if (uuid16 != 0)
		blued_ctl_respond(client_fd,
		    "OK ADD_SERVICE handle=0x%04X uuid=0x%04X\n",
		    handle, uuid16);
	else
		blued_ctl_respond(client_fd,
		    "OK ADD_SERVICE handle=0x%04X uuid=128bit\n",
		    handle);
}

/*
 * Handle the ADD_CHAR command.
 * Syntax: ADD_CHAR <service_handle> <uuid> <properties> <permissions> [value_hex]
 *
 * Adds a characteristic to an existing service in the live GATT database.
 * If properties include notify or indicate, a CCCD is auto-added.
 */
static void
ctl_cmd_add_char(int client_fd, const char *args)
{
	struct att_db *db = &periph_gatt_db;
	char buf[CTL_MAXLINE];
	char *tok, *saveptr;
	uint16_t svc_handle;
	uint16_t uuid16 = 0;
	uint8_t uuid128[16];
	uint8_t props, perms;
	uint8_t value[64];
	int value_len = 0;
	uint16_t handle;
	unsigned long ulval;

	while (*args == ' ')
		args++;
	strlcpy(buf, args, sizeof(buf));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' ||
		    buf[len - 1] == '\r' || buf[len - 1] == ' '))
			buf[--len] = '\0';
	}

	/* Token 1: service handle */
	tok = strtok_r(buf, " ", &saveptr);
	if (tok == NULL) {
		blued_ctl_respond(client_fd,
		    "ERROR usage: ADD_CHAR <svc_handle> <uuid> "
		    "<props> <perms> [value_hex]\n");
		return;
	}
	{
		char *endp;
		ulval = strtoul(tok, &endp, 16);
		if (*endp != '\0') {
			blued_ctl_respond(client_fd,
			    "ERROR invalid service handle\n");
			return;
		}
	}
	if (ulval == 0 || ulval > 0xFFFF) {
		blued_ctl_respond(client_fd,
		    "ERROR invalid service handle\n");
		return;
	}
	svc_handle = (uint16_t)ulval;

	/*
	 * Validate that svc_handle refers to an existing primary or
	 * secondary service declaration.  The characteristic is still
	 * appended at the end of the database (not inserted within the
	 * service's handle range) to avoid handle renumbering.  It
	 * remains discoverable via Read By Type Request across the full
	 * handle range, but will NOT appear in handle-range-based
	 * service discovery (Discover All Characteristics of a Service).
	 */
	{
		bool found = false;
		int i;

		for (i = 0; i < db->count; i++) {
			if (db->attrs[i].handle == svc_handle &&
			    (db->attrs[i].uuid16 == GATT_UUID_PRIMARY_SERVICE ||
			     db->attrs[i].uuid16 == GATT_UUID_SECONDARY_SERVICE)) {
				found = true;
				break;
			}
		}
		if (!found) {
			blued_ctl_respond(client_fd,
			    "ERROR service handle 0x%04X not found or "
			    "not a service declaration\n", svc_handle);
			return;
		}
	}

	/* Token 2: UUID */
	tok = strtok_r(NULL, " ", &saveptr);
	if (tok == NULL) {
		blued_ctl_respond(client_fd, "ERROR missing uuid\n");
		return;
	}
	if (blued_parse_uuid(tok, &uuid16, uuid128) != 0) {
		blued_ctl_respond(client_fd, "ERROR invalid uuid\n");
		return;
	}

	/* Token 3: properties */
	tok = strtok_r(NULL, " ", &saveptr);
	if (tok == NULL) {
		blued_ctl_respond(client_fd, "ERROR missing properties\n");
		return;
	}
	props = blued_parse_gatt_properties(tok);

	/* Token 4: permissions */
	tok = strtok_r(NULL, " ", &saveptr);
	if (tok == NULL) {
		blued_ctl_respond(client_fd, "ERROR missing permissions\n");
		return;
	}
	perms = blued_parse_gatt_permissions(tok);

	/* Token 5 (optional): value hex */
	tok = strtok_r(NULL, " ", &saveptr);
	if (tok != NULL) {
		value_len = blued_parse_hex_value(tok, value, sizeof(value));
		if (value_len < 0) {
			blued_ctl_respond(client_fd,
			    "ERROR invalid hex value\n");
			return;
		}
	}

	/* Add the characteristic */
	if (uuid16 != 0)
		handle = attdb_add_characteristic(db, uuid16, props, perms,
		    value_len > 0 ? value : NULL, (uint16_t)value_len);
	else
		handle = attdb_add_characteristic128(db, uuid128, props, perms,
		    value_len > 0 ? value : NULL, (uint16_t)value_len);

	if (handle == 0) {
		blued_ctl_respond(client_fd, "ERROR database full\n");
		return;
	}

	/* Track which ctl client owns this attribute for write forwarding */
	{
		struct att_attr *val_attr;
		val_attr = attdb_find_by_handle(db, handle);
		if (val_attr != NULL)
			val_attr->owner_fd = client_fd;
	}

	/* Auto-add CCCD if notify or indicate */
	if (props & (GATT_PROP_NOTIFY | GATT_PROP_INDICATE))
		attdb_add_cccd(db);

	ctl_recompute_hash_and_notify(handle, 0xFFFF);

	if (uuid16 != 0)
		blued_ctl_respond(client_fd,
		    "OK ADD_CHAR handle=0x%04X uuid=0x%04X\n",
		    handle, uuid16);
	else
		blued_ctl_respond(client_fd,
		    "OK ADD_CHAR handle=0x%04X uuid=128bit\n",
		    handle);
}

/*
 * Handle the REMOVE_SERVICE command.
 * Syntax: REMOVE_SERVICE <handle>
 *
 * Removes a service and all its attributes from the live GATT database.
 */
static void
ctl_cmd_remove_service(int client_fd, const char *args)
{
	struct att_db *db = &periph_gatt_db;
	char buf[64];
	unsigned long ulval;
	uint16_t handle;

	while (*args == ' ')
		args++;
	strlcpy(buf, args, sizeof(buf));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' ||
		    buf[len - 1] == '\r' || buf[len - 1] == ' '))
			buf[--len] = '\0';
	}

	{
		char *endp;
		ulval = strtoul(buf, &endp, 16);
		if (*endp != '\0') {
			blued_ctl_respond(client_fd,
			    "ERROR invalid handle\n");
			return;
		}
	}
	if (ulval == 0 || ulval > 0xFFFF) {
		blued_ctl_respond(client_fd,
		    "ERROR invalid handle\n");
		return;
	}
	handle = (uint16_t)ulval;

	if (attdb_remove_service(db, handle) != 0) {
		blued_ctl_respond(client_fd,
		    "ERROR service not found or not a service\n");
		return;
	}

	BLUED_PROBE_GATT_SVC_REMOVE(handle);
	ctl_recompute_hash_and_notify(handle, 0xFFFF);

	blued_ctl_respond(client_fd,
	    "OK REMOVE_SERVICE handle=0x%04X\n", handle);
}

/*
 * Handle the LOGLEVEL command — get or set the log level.
 * Without argument: returns the current log level.
 * With argument: sets the log level (0-5).
 */
static void
ctl_cmd_loglevel(int client_fd, const char *args)
{
	int level;

	if (args == NULL || *args == '\0') {
		blued_ctl_respond(client_fd, "OK LOGLEVEL %d\n",
		    blued_verbose);
		return;
	}

	while (*args == ' ')
		args++;
	{
		char *endp;
		level = (int)strtol(args, &endp, 10);
		if (endp == args || *endp != '\0') {
			blued_ctl_respond(client_fd,
			    "ERROR invalid number\n");
			return;
		}
	}
	if (level < 0 || level > 5) {
		blued_ctl_respond(client_fd,
		    "ERROR level must be 0-5\n");
		return;
	}
	blued_verbose = level;
	LOG_HOGP(1, "log level set to %d via control socket", level);
	blued_ctl_respond(client_fd, "OK LOGLEVEL %d\n", level);
}

/*
 * Handle the HOGP_READ command -- read a Feature report from a HOGP device.
 * Syntax: HOGP_READ <addr> <report_id>
 *
 * Reads the Feature Report characteristic with the given report ID using
 * ATT Read Request, as required by HOGP v1.0 Section 3.3.4.
 */
static void
ctl_cmd_hogp_read(int client_fd, const char *args)
{
	struct blued_conn *conn;
	bdaddr_t addr;
	char addr_str[18];
	char buf[64];
	char *sp;
	int report_id;
	uint8_t valbuf[ATT_PDU_BUF_SIZE];
	size_t outlen;
	char hexbuf[ATT_PDU_BUF_SIZE * 2 + 1];
	struct timeval old_tv;
	size_t hi;

	while (*args == ' ')
		args++;
	strlcpy(buf, args, sizeof(buf));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' ||
		    buf[len - 1] == '\r' || buf[len - 1] == ' '))
			buf[--len] = '\0';
	}

	/* Split into addr and report_id */
	sp = strchr(buf, ' ');
	if (sp == NULL) {
		blued_ctl_respond(client_fd,
		    "ERROR usage: HOGP_READ <addr> <report_id>\n");
		return;
	}
	*sp = '\0';
	sp++;
	while (*sp == ' ')
		sp++;

	strlcpy(addr_str, buf, sizeof(addr_str));
	if (!bt_aton(addr_str, &addr)) {
		blued_ctl_respond(client_fd, "ERROR invalid address\n");
		return;
	}

	report_id = (int)strtol(sp, NULL, 0);

	conn = blued_conn_by_addr(&addr);
	if (conn == NULL) {
		blued_ctl_respond(client_fd, "ERROR device not connected\n");
		return;
	}
	if (conn->att == NULL) {
		blued_ctl_respond(client_fd, "ERROR no ATT channel\n");
		return;
	}

	ctl_set_att_timeout(conn->att->fd, &old_tv);

	/* Find the Feature Report handle for this report ID */
	{
		uint16_t handle;

		handle = hogp_find_feature_handle(conn, (uint8_t)report_id);
		if (handle == 0) {
			ctl_restore_att_timeout(conn->att->fd, &old_tv);
			blued_ctl_respond(client_fd,
			    "ERROR no Feature report with id=%d\n", report_id);
			return;
		}

		outlen = 0;
		if (att_read(conn->att, handle, valbuf, sizeof(valbuf),
		    &outlen) != 0) {
			ctl_restore_att_timeout(conn->att->fd, &old_tv);
			blued_ctl_respond(client_fd, "ERROR read failed\n");
			return;
		}
		ctl_restore_att_timeout(conn->att->fd, &old_tv);

		/* Format value as hex string */
		for (hi = 0; hi < outlen; hi++)
			snprintf(hexbuf + hi * 2, 3, "%02X", valbuf[hi]);
		if (outlen == 0)
			hexbuf[0] = '\0';

		blued_ctl_respond(client_fd,
		    "OK HOGP_READ id=%d handle=0x%04X len=%zu value=%s\n",
		    report_id, handle, outlen, hexbuf);
	}
}

/*
 * Handle the HOGP_WRITE command -- write a Feature report to a HOGP device.
 * Syntax: HOGP_WRITE <addr> <report_id> <hex>
 *
 * Writes to the Feature Report characteristic using ATT Write Request
 * (with response), as required by HOGP v1.0 Section 3.3.4.
 */
static void
ctl_cmd_hogp_write(int client_fd, const char *args)
{
	struct blued_conn *conn;
	bdaddr_t addr;
	char addr_str[18];
	char buf[CTL_MAXLINE];
	char *sp, *hex;
	int report_id;
	uint8_t data[ATT_PDU_BUF_SIZE];
	struct timeval old_tv;
	size_t dlen, hexlen, i;

	while (*args == ' ')
		args++;
	strlcpy(buf, args, sizeof(buf));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' ||
		    buf[len - 1] == '\r' || buf[len - 1] == ' '))
			buf[--len] = '\0';
	}

	/* Split: addr report_id hex */
	sp = strchr(buf, ' ');
	if (sp == NULL) {
		blued_ctl_respond(client_fd,
		    "ERROR usage: HOGP_WRITE <addr> <report_id> <hex>\n");
		return;
	}
	*sp = '\0';
	sp++;
	while (*sp == ' ')
		sp++;

	strlcpy(addr_str, buf, sizeof(addr_str));
	if (!bt_aton(addr_str, &addr)) {
		blued_ctl_respond(client_fd, "ERROR invalid address\n");
		return;
	}

	/* Parse report_id */
	hex = strchr(sp, ' ');
	if (hex == NULL) {
		blued_ctl_respond(client_fd,
		    "ERROR usage: HOGP_WRITE <addr> <report_id> <hex>\n");
		return;
	}
	*hex = '\0';
	hex++;
	while (*hex == ' ')
		hex++;

	report_id = (int)strtol(sp, NULL, 0);

	/* Convert hex string to bytes */
	hexlen = strlen(hex);
	if (hexlen % 2 != 0 || hexlen == 0) {
		blued_ctl_respond(client_fd,
		    "ERROR hex value must be even length\n");
		return;
	}
	dlen = hexlen / 2;
	if (dlen > sizeof(data)) {
		blued_ctl_respond(client_fd, "ERROR value too long\n");
		return;
	}
	for (i = 0; i < dlen; i++) {
		unsigned int byte;
		if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
			blued_ctl_respond(client_fd,
			    "ERROR invalid hex value\n");
			return;
		}
		data[i] = (uint8_t)byte;
	}

	conn = blued_conn_by_addr(&addr);
	if (conn == NULL) {
		blued_ctl_respond(client_fd, "ERROR device not connected\n");
		return;
	}
	if (conn->att == NULL) {
		blued_ctl_respond(client_fd, "ERROR no ATT channel\n");
		return;
	}

	ctl_set_att_timeout(conn->att->fd, &old_tv);

	/* Find the Feature Report handle for this report ID */
	{
		uint16_t handle;

		handle = hogp_find_feature_handle(conn, (uint8_t)report_id);
		if (handle == 0) {
			ctl_restore_att_timeout(conn->att->fd, &old_tv);
			blued_ctl_respond(client_fd,
			    "ERROR no Feature report with id=%d\n", report_id);
			return;
		}

		/*
		 * HOGP v1.0 Section 3.3.4: Feature Reports use Write
		 * Request (ATT Write Request with response).
		 */
		if (att_write_req(conn->att, handle, data, dlen) != 0) {
			ctl_restore_att_timeout(conn->att->fd, &old_tv);
			blued_ctl_respond(client_fd, "ERROR write failed\n");
			return;
		}
		ctl_restore_att_timeout(conn->att->fd, &old_tv);

		blued_ctl_respond(client_fd,
		    "OK HOGP_WRITE id=%d handle=0x%04X len=%zu\n",
		    report_id, handle, dlen);
	}
}

/*
 * Rate-limit blocking ATT commands (DISCOVER, READ, WRITE, HOGP_READ, HOGP_WRITE).
 * Allow at most 4 blocking commands per 10-second window per client.
 * Returns true if the command should be allowed, false if rate-limited.
 */
#define CTL_BLOCKING_LIMIT	4
#define CTL_BLOCKING_WINDOW	10
static bool
ctl_check_blocking_rate(int client_fd)
{
	struct blued_ctl_client *c;
	struct timespec now;

	LIST_FOREACH(c, &blued_g.ctl_clients, entries) {
		if (c->fd == client_fd)
			break;
	}
	if (c == NULL)
		return (true);

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (now.tv_sec - c->blocking_window >= CTL_BLOCKING_WINDOW) {
		c->blocking_window = now.tv_sec;
		c->blocking_count = 0;
	}
	if (c->blocking_count >= CTL_BLOCKING_LIMIT) {
		blued_ctl_respond(client_fd,
		    "ERROR rate limited, try again later\n");
		return (false);
	}
	c->blocking_count++;
	return (true);
}

/*
 * Handle the SUBSCRIBE command — subscribe to characteristic notifications.
 * Syntax: SUBSCRIBE <addr> <handle>
 */
static void
ctl_cmd_subscribe(struct blued_ctl_client *client, const char *args)
{
	bdaddr_t addr;
	char buf[64], addr_str[18], *sp;
	uint16_t handle;
	int i;

	while (*args == ' ')
		args++;
	strlcpy(buf, args, sizeof(buf));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' ||
		    buf[len - 1] == '\r' || buf[len - 1] == ' '))
			buf[--len] = '\0';
	}

	sp = strchr(buf, ' ');
	if (sp == NULL) {
		blued_ctl_respond(client->fd,
		    "ERROR usage: SUBSCRIBE <addr> <handle>\n");
		return;
	}
	*sp = '\0';
	sp++;
	while (*sp == ' ')
		sp++;

	strlcpy(addr_str, buf, sizeof(addr_str));
	if (!bt_aton(addr_str, &addr)) {
		blued_ctl_respond(client->fd, "ERROR invalid address\n");
		return;
	}

	{
		char *endp;
		unsigned long hval = strtoul(sp, &endp, 0);
		if (endp == sp || (*endp != '\0' && *endp != ' ') ||
		    hval == 0 || hval > 0xFFFF) {
			blued_ctl_respond(client->fd,
			    "ERROR invalid handle\n");
			return;
		}
		handle = (uint16_t)hval;
	}

	/* Check for duplicate */
	for (i = 0; i < client->nsubs; i++) {
		if (memcmp(&client->subs[i].addr, &addr, sizeof(addr)) == 0 &&
		    client->subs[i].handle == handle) {
			blued_ctl_respond(client->fd,
			    "OK already subscribed\n");
			return;
		}
	}

	if (client->nsubs >= CTL_MAX_SUBSCRIPTIONS) {
		blued_ctl_respond(client->fd,
		    "ERROR too many subscriptions\n");
		return;
	}

	memcpy(&client->subs[client->nsubs].addr, &addr, sizeof(addr));
	client->subs[client->nsubs].handle = handle;
	client->nsubs++;

	blued_ctl_respond(client->fd, "OK SUBSCRIBE 0x%04X\n", handle);
}

/*
 * Handle the UNSUBSCRIBE command.
 * Syntax: UNSUBSCRIBE <addr> <handle>
 */
static void
ctl_cmd_unsubscribe(struct blued_ctl_client *client, const char *args)
{
	bdaddr_t addr;
	char buf[64], addr_str[18], *sp;
	uint16_t handle;
	int i;

	while (*args == ' ')
		args++;
	strlcpy(buf, args, sizeof(buf));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' ||
		    buf[len - 1] == '\r' || buf[len - 1] == ' '))
			buf[--len] = '\0';
	}

	sp = strchr(buf, ' ');
	if (sp == NULL) {
		blued_ctl_respond(client->fd,
		    "ERROR usage: UNSUBSCRIBE <addr> <handle>\n");
		return;
	}
	*sp = '\0';
	sp++;
	while (*sp == ' ')
		sp++;

	strlcpy(addr_str, buf, sizeof(addr_str));
	if (!bt_aton(addr_str, &addr)) {
		blued_ctl_respond(client->fd, "ERROR invalid address\n");
		return;
	}

	{
		char *endp;
		unsigned long hval = strtoul(sp, &endp, 0);
		if (endp == sp || (*endp != '\0' && *endp != ' ') ||
		    hval == 0 || hval > 0xFFFF) {
			blued_ctl_respond(client->fd,
			    "ERROR invalid handle\n");
			return;
		}
		handle = (uint16_t)hval;
	}

	for (i = 0; i < client->nsubs; i++) {
		if (memcmp(&client->subs[i].addr, &addr, sizeof(addr)) == 0 &&
		    client->subs[i].handle == handle) {
			/* Remove by shifting */
			int remain = client->nsubs - i - 1;
			if (remain > 0)
				memmove(&client->subs[i],
				    &client->subs[i + 1],
				    remain * sizeof(client->subs[0]));
			client->nsubs--;
			blued_ctl_respond(client->fd,
			    "OK UNSUBSCRIBE 0x%04X\n", handle);
			return;
		}
	}

	blued_ctl_respond(client->fd, "ERROR not subscribed\n");
}

/*
 * Handle the SET_VALUE command — update a local GATT attribute value.
 * Syntax: SET_VALUE <handle> <hex>
 *
 * Allows a ctl client that registered a service to pre-set the value
 * of a characteristic before a remote central reads it.
 */
static void
ctl_cmd_set_value(int client_fd, const char *args)
{
	struct att_db *db = &periph_gatt_db;
	char buf[CTL_MAXLINE], *sp;
	uint16_t handle;
	uint8_t data[ATT_PDU_BUF_SIZE];
	size_t dlen, hexlen, i;
	struct att_attr *a;

	while (*args == ' ')
		args++;
	strlcpy(buf, args, sizeof(buf));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' ||
		    buf[len - 1] == '\r' || buf[len - 1] == ' '))
			buf[--len] = '\0';
	}

	sp = strchr(buf, ' ');
	if (sp == NULL) {
		blued_ctl_respond(client_fd,
		    "ERROR usage: SET_VALUE <handle> <hex>\n");
		return;
	}
	*sp = '\0';
	sp++;
	while (*sp == ' ')
		sp++;

	{
		char *endp;
		unsigned long hval = strtoul(buf, &endp, 0);
		if (endp == buf || (*endp != '\0' && *endp != ' ') ||
		    hval == 0 || hval > 0xFFFF) {
			blued_ctl_respond(client_fd,
			    "ERROR invalid handle\n");
			return;
		}
		handle = (uint16_t)hval;
	}

	hexlen = strlen(sp);
	if (hexlen % 2 != 0 || hexlen == 0) {
		blued_ctl_respond(client_fd,
		    "ERROR hex value must be even length\n");
		return;
	}
	dlen = hexlen / 2;
	if (dlen > sizeof(data)) {
		blued_ctl_respond(client_fd, "ERROR value too long\n");
		return;
	}
	for (i = 0; i < dlen; i++) {
		unsigned int byte;
		if (sscanf(sp + i * 2, "%2x", &byte) != 1) {
			blued_ctl_respond(client_fd,
			    "ERROR invalid hex value\n");
			return;
		}
		data[i] = (uint8_t)byte;
	}

	pthread_mutex_lock(&blued_g.gatt_db_lock);
	a = attdb_find_by_handle(db, handle);
	if (a == NULL) {
		pthread_mutex_unlock(&blued_g.gatt_db_lock);
		blued_ctl_respond(client_fd, "ERROR handle not found\n");
		return;
	}
	if (a->owner_fd >= 0 && a->owner_fd != client_fd) {
		pthread_mutex_unlock(&blued_g.gatt_db_lock);
		blued_ctl_respond(client_fd,
		    "ERROR attribute owned by another client\n");
		return;
	}
	if (a->value == NULL || dlen > a->value_maxlen) {
		pthread_mutex_unlock(&blued_g.gatt_db_lock);
		blued_ctl_respond(client_fd,
		    "ERROR value too long for attribute\n");
		return;
	}
	memcpy(a->value, data, dlen);
	a->value_len = (uint16_t)dlen;
	pthread_mutex_unlock(&blued_g.gatt_db_lock);

	blued_ctl_respond(client_fd,
	    "OK SET_VALUE handle=0x%04X len=%zu\n", handle, dlen);
}

/*
 * Handle PASSKEY_REPLY command — provide passkey in response to
 * EVENT PASSKEY_INPUT.
 * Syntax: PASSKEY_REPLY <addr> <passkey>
 */
static void
ctl_cmd_passkey_reply(int client_fd, const char *args)
{
	char buf[64];
	uint32_t passkey;
	char *sp;

	while (*args == ' ')
		args++;
	strlcpy(buf, args, sizeof(buf));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' ||
		    buf[len - 1] == '\r' || buf[len - 1] == ' '))
			buf[--len] = '\0';
	}

	/* Parse address and validate it matches the pending device */
	sp = strchr(buf, ' ');
	if (sp == NULL) {
		blued_ctl_respond(client_fd,
		    "ERROR usage: PASSKEY_REPLY <addr> <passkey>\n");
		return;
	}
	*sp = '\0';
	{
		bdaddr_t reply_addr;

		if (bt_aton(buf, &reply_addr) &&
		    memcmp(&reply_addr, &blued_g.passkey_target,
		    sizeof(bdaddr_t)) != 0) {
			blued_ctl_respond(client_fd,
			    "ERROR address does not match pending "
			    "passkey request\n");
			return;
		}
	}
	sp++;
	while (*sp == ' ')
		sp++;

	{
		char *endp;
		unsigned long val = strtoul(sp, &endp, 10);
		if (endp == sp || val > 999999) {
			blued_ctl_respond(client_fd,
			    "ERROR invalid passkey\n");
			return;
		}
		passkey = (uint32_t)val;
	}

	pthread_mutex_lock(&blued_g.passkey_lock);
	if (blued_g.passkey_reply_status != 0) {
		pthread_mutex_unlock(&blued_g.passkey_lock);
		blued_ctl_respond(client_fd,
		    "ERROR no passkey request pending\n");
		return;
	}
	blued_g.passkey_reply = passkey;
	blued_g.passkey_reply_status = 1;
	pthread_cond_signal(&blued_g.passkey_cond);
	pthread_mutex_unlock(&blued_g.passkey_lock);

	blued_ctl_respond(client_fd, "OK PASSKEY_REPLY\n");
}

/*
 * Handle NUMCMP_REPLY command — confirm or reject numeric comparison.
 * Syntax: NUMCMP_REPLY <addr> yes|no
 */
static void
ctl_cmd_numcmp_reply(int client_fd, const char *args)
{
	char buf[64];
	char *sp;
	bool confirm;

	while (*args == ' ')
		args++;
	strlcpy(buf, args, sizeof(buf));

	/* Trim trailing whitespace */
	{
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' ||
		    buf[len - 1] == '\r' || buf[len - 1] == ' '))
			buf[--len] = '\0';
	}

	/* Parse address and validate it matches the pending device */
	sp = strchr(buf, ' ');
	if (sp == NULL) {
		blued_ctl_respond(client_fd,
		    "ERROR usage: NUMCMP_REPLY <addr> yes|no\n");
		return;
	}
	*sp = '\0';
	{
		bdaddr_t reply_addr;

		if (bt_aton(buf, &reply_addr) &&
		    memcmp(&reply_addr, &blued_g.passkey_target,
		    sizeof(bdaddr_t)) != 0) {
			blued_ctl_respond(client_fd,
			    "ERROR address does not match pending "
			    "numcmp request\n");
			return;
		}
	}
	sp++;
	while (*sp == ' ')
		sp++;

	if (strcmp(sp, "yes") == 0)
		confirm = true;
	else if (strcmp(sp, "no") == 0)
		confirm = false;
	else {
		blued_ctl_respond(client_fd,
		    "ERROR expected yes or no\n");
		return;
	}

	pthread_mutex_lock(&blued_g.passkey_lock);
	if (blued_g.numcmp_reply_status != 0) {
		pthread_mutex_unlock(&blued_g.passkey_lock);
		blued_ctl_respond(client_fd,
		    "ERROR no numcmp request pending\n");
		return;
	}
	blued_g.numcmp_reply = confirm;
	blued_g.numcmp_reply_status = 1;
	pthread_cond_signal(&blued_g.passkey_cond);
	pthread_mutex_unlock(&blued_g.passkey_lock);

	blued_ctl_respond(client_fd, "OK NUMCMP_REPLY\n");
}

/*
 * Send a notification event to all subscribed ctl clients.
 * Called from blued.c when an ATT notification/indication arrives
 * on a central connection.
 */
void
blued_ctl_notify_value(const bdaddr_t *addr, uint16_t handle,
    const uint8_t *value, uint16_t len)
{
	struct blued_ctl_client *client;
	char addr_str[18];
	char hexbuf[ATT_PDU_BUF_SIZE * 2 + 1];
	int i;

	bt_ntoa(addr, addr_str);

	for (i = 0; i < (int)len && i < ATT_PDU_BUF_SIZE; i++)
		snprintf(hexbuf + i * 2, 3, "%02X", value[i]);
	if (len == 0)
		hexbuf[0] = '\0';

	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		int j;

		for (j = 0; j < client->nsubs; j++) {
			if (memcmp(&client->subs[j].addr, addr,
			    sizeof(*addr)) == 0 &&
			    client->subs[j].handle == handle) {
				blued_ctl_respond(client->fd,
				    "EVENT NOTIFY %s 0x%04X %s\n",
				    addr_str, handle, hexbuf);
				break;
			}
		}
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

/*
 * Send a write event to the ctl client that owns an attribute.
 * Called from att_server.c handle_write when owner_fd >= 0.
 */
void
blued_ctl_notify_write(int owner_fd, uint16_t handle,
    const uint8_t *value, uint16_t len)
{
	char hexbuf[ATT_PDU_BUF_SIZE * 2 + 1];
	int i;

	for (i = 0; i < (int)len && i < ATT_PDU_BUF_SIZE; i++)
		snprintf(hexbuf + i * 2, 3, "%02X", value[i]);
	if (len == 0)
		hexbuf[0] = '\0';

	blued_ctl_respond(owner_fd,
	    "EVENT WRITE 0x%04X %s\n", handle, hexbuf);
}

/*
 * Handle the BOND_EXPORT command — dump bonds as portable text.
 * Syntax: BOND_EXPORT
 *
 * Outputs each bond as key=value fields for backup/migration.
 * Does NOT include raw key material (LTK, IRK, CSRK) — only
 * metadata suitable for diagnostics.  Full export would require
 * authentication (this is a control socket accessible to root).
 */
static void
ctl_cmd_bond_export(int client_fd)
{

	blued_ctl_respond(client_fd, "BOND_EXPORT\n");
	pthread_mutex_lock(&blued_g.bond_db_lock);
	if (blued_g.bond_db != NULL) {
		for (int i = 0; i < blued_g.bond_db->count; i++) {
			struct smp_bond *b = &blued_g.bond_db->bonds[i];
			char addr_str[18];

			bt_ntoa((bdaddr_t *)b->addr, addr_str);
			blued_ctl_respond(client_fd,
			    "BOND addr=%s type=%s "
			    "ltk=%d irk=%d csrk=%d sc=%d mitm=%d "
			    "link_key=%d name=%s\n",
			    addr_str,
			    b->addr_type == BDADDR_LE_RANDOM ?
			    "random" : "public",
			    b->has_ltk, b->has_irk, b->has_csrk,
			    b->is_sc, b->is_mitm, b->has_link_key,
			    b->has_name ? b->name : "");
		}
	}
	pthread_mutex_unlock(&blued_g.bond_db_lock);
	blued_ctl_respond(client_fd, "END\n");
}

/*
 * Handle the CONNPARAMS command — show connection parameters.
 * Syntax: CONNPARAMS [addr]
 *
 * Displays connection interval, latency, and supervision timeout
 * for all connections (or a specific one).  The values are stored
 * in the blued_conn struct, populated from LE Connection Complete
 * and Connection Update Complete events.
 */
static void
ctl_cmd_connparams(int client_fd, const char *args)
{
	struct blued_conn *conn;
	char addr_str[18];
	bdaddr_t addr;
	bool specific = false;

	if (args != NULL && *args != '\0') {
		while (*args == ' ')
			args++;
		strlcpy(addr_str, args, sizeof(addr_str));
		{
			size_t len = strlen(addr_str);
			while (len > 0 && (addr_str[len - 1] == '\n' ||
			    addr_str[len - 1] == '\r' ||
			    addr_str[len - 1] == ' '))
				addr_str[--len] = '\0';
		}
		if (bt_aton(addr_str, &addr))
			specific = true;
	}

	blued_ctl_respond(client_fd, "CONNPARAMS\n");
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (specific &&
		    memcmp(&conn->dst, &addr, sizeof(addr)) != 0)
			continue;

		bt_ntoa(&conn->dst, addr_str);
		blued_ctl_respond(client_fd,
		    "%s interval=%d.%02dms latency=%d timeout=%dms\n",
		    addr_str,
		    conn->conn_interval * 125 / 100,
		    conn->conn_interval * 125 % 100,
		    conn->conn_latency,
		    conn->supervision_timeout * 10);
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
	blued_ctl_respond(client_fd, "END\n");
}

/*
 * Handle ECBFC_CONNECT <addr> <psm> <count>
 * Opens multiple ECBFC channels to a remote device.
 */
static void
ctl_cmd_ecbfc_connect(int client_fd, char *args)
{
	char addr_str[18];
	unsigned int psm_ui, count_ui;
	bdaddr_t dst;
	int fds[5];
	int n, opened, i;

	/* socket() is not allowed inside Capsicum sandbox */
	if (cap_sandboxed()) {
		blued_ctl_respond(client_fd,
		    "ERROR ECBFC_CONNECT not available inside Capsicum sandbox\n");
		return;
	}

	n = sscanf(args, "%17s %u %u", addr_str, &psm_ui, &count_ui);
	if (n < 3 || psm_ui > 0xFFFF || count_ui < 1 || count_ui > 5) {
		blued_ctl_respond(client_fd,
		    "ERROR usage: ECBFC_CONNECT <addr> <psm> <count>\n");
		return;
	}

	if (!bt_aton(addr_str, &dst)) {
		blued_ctl_respond(client_fd, "ERROR invalid address\n");
		return;
	}

	opened = ble_ecbfc_connect((const uint8_t *)&dst,
	    BDADDR_LE_PUBLIC, (uint16_t)psm_ui, 0, (int)count_ui, fds);

	if (opened <= 0) {
		blued_ctl_respond(client_fd,
		    "ERROR ECBFC connect failed: %s\n", strerror(errno));
		return;
	}

	blued_ctl_respond(client_fd, "ECBFC_CONNECTED %d\n", opened);
	for (i = 0; i < opened; i++) {
		uint16_t omtu = 0;
		socklen_t optlen = sizeof(omtu);

		(void)getsockopt(fds[i], SOL_L2CAP, SO_L2CAP_OMTU,
		    &omtu, &optlen);
		blued_ctl_respond(client_fd, "  CID %d fd=%d omtu=%d\n",
		    i, fds[i], omtu);
	}

	/*
	 * Close the fds -- in a real integration these would be
	 * registered with the connection state machine, but for
	 * the control interface we report success and close them
	 * since the ctl client cannot use raw fds.
	 */
	for (i = 0; i < opened; i++)
		close(fds[i]);

	blued_ctl_respond(client_fd, "END\n");
}

/*
 * Handle ECBFC_RECONFIG <addr> <mtu> <mps>
 * Reconfigure MTU/MPS on all EATT bearers for the given connection.
 */
static void
ctl_cmd_ecbfc_reconfig(int client_fd, char *args)
{
	char addr_str[18];
	unsigned int mtu_ui, mps_ui;
	bdaddr_t dst;
	struct blued_conn *conn;
	int n, i, reconfigured;

	n = sscanf(args, "%17s %u %u", addr_str, &mtu_ui, &mps_ui);
	if (n < 3 || mtu_ui < 64 || mtu_ui > 0xFFFF ||
	    mps_ui < 64 || mps_ui > 65533) {
		blued_ctl_respond(client_fd,
		    "ERROR usage: ECBFC_RECONFIG <addr> <mtu> <mps>\n");
		return;
	}

	if (!bt_aton(addr_str, &dst)) {
		blued_ctl_respond(client_fd, "ERROR invalid address\n");
		return;
	}

	/* Find connection by address — hold lock through reconfig */
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	conn = blued_conn_by_addr(&dst);

	if (conn == NULL || conn->att == NULL) {
		pthread_rwlock_unlock(&blued_g.conns_lock);
		blued_ctl_respond(client_fd, "ERROR not connected\n");
		return;
	}

	/* Reconfigure each EATT bearer */
	reconfigured = 0;
	for (i = 0; i < conn->att->eatt_count; i++) {
		if (conn->att->eatt[i].fd < 0 || !conn->att->eatt[i].active)
			continue;
		if (ble_ecbfc_reconfig(conn->att->eatt[i].fd,
		    (uint16_t)mtu_ui, (uint16_t)mps_ui) == 0)
			reconfigured++;
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);

	if (reconfigured > 0) {
		blued_ctl_respond(client_fd,
		    "OK ECBFC_RECONFIG %d bearers mtu=%u mps=%u\n",
		    reconfigured, mtu_ui, mps_ui);
	} else {
		blued_ctl_respond(client_fd,
		    "ERROR no ECBFC bearers to reconfigure\n");
	}
}

/*
 * Process a single complete command line from a control client.
 */
static void
blued_ctl_process(struct blued_ctl_client *client, char *line)
{
	int client_fd = client->fd;
	char *nl;

	/* Strip trailing \r */
	nl = strchr(line, '\r');
	if (nl != NULL)
		*nl = '\0';

	BLUED_PROBE_CTL_CMD(line);

	if (strcmp(line, "ADAPTERS") == 0) {
		ctl_cmd_adapters(client_fd);
	} else if (strcmp(line, "LIST") == 0) {
		ctl_cmd_list(client_fd);
	} else if (strcmp(line, "SCAN") == 0) {
		ctl_cmd_scan(client_fd);
	} else if (strcmp(line, "STATUS") == 0) {
		ctl_cmd_status(client_fd);
	} else if (strcmp(line, "BONDS") == 0) {
		ctl_cmd_bonds(client_fd);
	} else if (strcmp(line, "PHY") == 0) {
		ctl_cmd_phy(client_fd);
	} else if (strncmp(line, "CONNECT_NAME ", 13) == 0) {
		ctl_cmd_connect_name(client_fd, line + 13);
	} else if (strncmp(line, "CONNECT ", 8) == 0) {
		ctl_cmd_connect(client_fd, line + 8);
	} else if (strncmp(line, "DISCONNECT ", 11) == 0) {
		ctl_cmd_disconnect(client_fd, line + 11);
	} else if (strncmp(line, "PAIR ", 5) == 0) {
		ctl_cmd_pair(client_fd, line + 5);
	} else if (strncmp(line, "UNBOND ", 7) == 0) {
		ctl_cmd_unbond(client_fd, line + 7);
	} else if (strcmp(line, "SERVICES") == 0) {
		pthread_mutex_lock(&blued_g.gatt_db_lock);
		ctl_cmd_services(client_fd);
		pthread_mutex_unlock(&blued_g.gatt_db_lock);
	} else if (strncmp(line, "DISCOVER ", 9) == 0) {
		if (ctl_check_blocking_rate(client_fd))
			ctl_cmd_discover(client_fd, line + 9);
	} else if (strncmp(line, "READ ", 5) == 0) {
		if (ctl_check_blocking_rate(client_fd))
			ctl_cmd_read(client_fd, line + 5);
	} else if (strncmp(line, "WRITE ", 6) == 0) {
		if (ctl_check_blocking_rate(client_fd))
			ctl_cmd_write(client_fd, line + 6);
	} else if (strncmp(line, "ADD_SERVICE ", 12) == 0) {
		pthread_mutex_lock(&blued_g.gatt_db_lock);
		ctl_cmd_add_service(client_fd, line + 12);
		pthread_mutex_unlock(&blued_g.gatt_db_lock);
	} else if (strncmp(line, "ADD_CHAR ", 9) == 0) {
		pthread_mutex_lock(&blued_g.gatt_db_lock);
		ctl_cmd_add_char(client_fd, line + 9);
		pthread_mutex_unlock(&blued_g.gatt_db_lock);
	} else if (strncmp(line, "REMOVE_SERVICE ", 15) == 0) {
		pthread_mutex_lock(&blued_g.gatt_db_lock);
		ctl_cmd_remove_service(client_fd, line + 15);
		pthread_mutex_unlock(&blued_g.gatt_db_lock);
	} else if (strcmp(line, "LOGLEVEL") == 0) {
		ctl_cmd_loglevel(client_fd, NULL);
	} else if (strncmp(line, "LOGLEVEL ", 9) == 0) {
		ctl_cmd_loglevel(client_fd, line + 9);
	} else if (strncmp(line, "HOGP_READ ", 10) == 0) {
		if (ctl_check_blocking_rate(client_fd))
			ctl_cmd_hogp_read(client_fd, line + 10);
	} else if (strncmp(line, "HOGP_WRITE ", 11) == 0) {
		if (ctl_check_blocking_rate(client_fd))
			ctl_cmd_hogp_write(client_fd, line + 11);
	} else if (strncmp(line, "SUBSCRIBE ", 10) == 0) {
		ctl_cmd_subscribe(client, line + 10);
	} else if (strncmp(line, "UNSUBSCRIBE ", 12) == 0) {
		ctl_cmd_unsubscribe(client, line + 12);
	} else if (strncmp(line, "SET_VALUE ", 10) == 0) {
		pthread_mutex_lock(&blued_g.gatt_db_lock);
		ctl_cmd_set_value(client_fd, line + 10);
		pthread_mutex_unlock(&blued_g.gatt_db_lock);
	} else if (strncmp(line, "PASSKEY_REPLY ", 14) == 0) {
		ctl_cmd_passkey_reply(client_fd, line + 14);
	} else if (strncmp(line, "NUMCMP_REPLY ", 13) == 0) {
		ctl_cmd_numcmp_reply(client_fd, line + 13);
	} else if (strcmp(line, "BOND_EXPORT") == 0) {
		ctl_cmd_bond_export(client_fd);
	} else if (strcmp(line, "CONNPARAMS") == 0) {
		ctl_cmd_connparams(client_fd, NULL);
	} else if (strncmp(line, "CONNPARAMS ", 11) == 0) {
		ctl_cmd_connparams(client_fd, line + 11);
	} else if (strncmp(line, "ECBFC_CONNECT ", 14) == 0) {
		if (ctl_check_blocking_rate(client_fd))
			ctl_cmd_ecbfc_connect(client_fd, line + 14);
	} else if (strncmp(line, "ECBFC_RECONFIG ", 15) == 0) {
		if (ctl_check_blocking_rate(client_fd))
			ctl_cmd_ecbfc_reconfig(client_fd, line + 15);
	} else {
		blued_ctl_respond(client_fd, "ERROR unknown command\n");
	}
}

/*
 * Dispatch a control command from a client.
 * Appends received data to the per-client buffer and processes
 * complete newline-terminated lines.
 */
int
blued_ctl_dispatch(struct blued_ctl_client *client)
{
	ssize_t n;
	char *nl;
	size_t avail;

	avail = sizeof(client->buf) - client->buflen - 1;
	if (avail == 0) {
		/* Buffer full with no newline — discard and reset */
		client->buflen = 0;
		blued_ctl_respond(client->fd, "ERROR line too long\n");
		return (0);
	}

	n = recv(client->fd, client->buf + client->buflen, avail, 0);
	if (n == 0)
		return (-1);	/* Client disconnected */
	if (n < 0) {
		if (errno == EINTR)
			return (0);
		return (-1);	/* Error — caller removes client */
	}
	client->buflen += (size_t)n;
	client->buf[client->buflen] = '\0';

	/* Process all complete lines */
	while ((nl = strchr(client->buf, '\n')) != NULL) {
		*nl = '\0';
		blued_ctl_process(client, client->buf);

		/* Shift remainder */
		{
			size_t consumed = (size_t)(nl - client->buf) + 1;
			size_t remain = client->buflen - consumed;

			if (remain > 0)
				memmove(client->buf, nl + 1, remain);
			client->buflen = remain;
			client->buf[client->buflen] = '\0';
		}
	}

	return (0);
}

/*
 * Initialize the control socket.
 * Creates a Unix domain stream socket, binds, listens, and registers
 * with the global kqueue.  Must be called before cap_enter().
 */
int
blued_ctl_init(const char *path)
{
	struct sockaddr_un sun;
	struct kevent kev;
	int fd;

	fd = socket(AF_UNIX,
	    SOCK_STREAM | SOCK_CLOEXEC | SOCK_CLOFORK | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return (-1);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlen(path) >= sizeof(sun.sun_path)) {
		warnx("control socket path too long");
		close(fd);
		return (-1);
	}
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

	/* Remove stale socket */
	(void)unlink(path);

	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		close(fd);
		return (-1);
	}

	if (chmod(path, 0660) < 0) {
		close(fd);
		(void)unlink(path);
		return (-1);
	}

	if (listen(fd, BLUED_MAX_CTL) < 0) {
		close(fd);
		(void)unlink(path);
		return (-1);
	}

	/* Register with kqueue — use sentinel so blued_handle_readable()
	 * can identify the control socket listener */
	blued_g.ctl_fd = fd;
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0,
	    BLUED_KQ_CTL_LISTEN);
	if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0) {
		close(fd);
		(void)unlink(path);
		blued_g.ctl_fd = -1;
		return (-1);
	}

	/* Save path for cleanup */
	ctl_sock_path = strdup(path);

	LOG_HCI(1, "control socket: %s", path);
	return (0);
}

/*
 * Reset owner_fd for all GATT attributes owned by a disconnected client.
 * Called when a ctl client disconnects so that stale fds are not retained.
 */
void
blued_ctl_reset_owner(int client_fd)
{
	struct att_db *db = &periph_gatt_db;
	int i;

	pthread_mutex_lock(&blued_g.gatt_db_lock);
	for (i = 0; i < db->count; i++) {
		if (db->attrs[i].owner_fd == client_fd)
			db->attrs[i].owner_fd = -1;
	}
	pthread_mutex_unlock(&blued_g.gatt_db_lock);
}

/*
 * Accept a new control client connection.
 */
void
blued_ctl_accept(void)
{
	struct blued_ctl_client *client;
	struct kevent kev;
	int fd, nclients;

	fd = accept4(blued_g.ctl_fd, NULL, NULL,
	    SOCK_CLOEXEC | SOCK_CLOFORK | SOCK_NONBLOCK);
	if (fd < 0)
		return;

	/* Capability-limit accepted client fd to send/recv/event only */
	{
		cap_rights_t rights;

		cap_rights_init(&rights, CAP_RECV, CAP_SEND, CAP_EVENT);
		(void)cap_rights_limit(fd, &rights);
		(void)cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED);
		(void)cap_clofork_limit(fd, CAP_CLOFORK_LOCKED);
		(void)cap_xfer_limit(fd, CAP_XFER_ONCE);
		(void)cap_ambient_limit(fd);
	}

	/* Enforce maximum control client count to prevent fd exhaustion */
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	nclients = 0;
	LIST_FOREACH(client, &blued_g.ctl_clients, entries)
		nclients++;
	if (nclients >= BLUED_MAX_CTL) {
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		LOG_HCI(1, "control socket: max clients (%d) reached, "
		    "rejecting", BLUED_MAX_CTL);
		close(fd);
		return;
	}

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		close(fd);
		return;
	}
	client->fd = fd;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);

	/* Register for read events */
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, client);
	if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0) {
		pthread_mutex_lock(&blued_g.ctl_clients_lock);
		LIST_REMOVE(client, entries);
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		close(fd);
		free(client);
	}
}

/*
 * Clean up the control socket and all connected clients.
 */
void
blued_ctl_cleanup(void)
{
	struct blued_ctl_client *client, *tmp;

	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH_SAFE(client, &blued_g.ctl_clients, entries, tmp) {
		close(client->fd);
		LIST_REMOVE(client, entries);
		free(client);
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);

	if (blued_g.ctl_fd >= 0) {
		close(blued_g.ctl_fd);
		blued_g.ctl_fd = -1;
	}

	if (ctl_sock_path != NULL) {
		(void)unlink(ctl_sock_path);
		free(ctl_sock_path);
		ctl_sock_path = NULL;
	}
}
