/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * blued control socket — connection management commands.
 *
 * Commands handled here:
 *   SCAN, STATUS, CONNECT, CONNECT_NAME, DISCONNECT, PHY
 */

#include <sys/event.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "att.h"
#include "ble_util.h"
#include "blued.h"
#include "blued_internal.h"
#include "blued_probes.h"
#include "conn.h"
#include "ctl.h"
#include "ctl_internal.h"
#include "hci_util.h"
#include "ipc_proto.h"
#include "smp.h"

/*
 * Handle the SCAN command — start LE scan on active adapters.
 *
 * A target restricts the scan to one adapter.  A NULL target is reserved for
 * internal discovery that intentionally scans every active adapter.
 *
 * Note: cap_enter() is called before the kqueue event loop, so the
 * ctl dispatch runs inside the Capsicum sandbox.  Scanning requires
 * HCI socket operations (send/recv) which are permitted under the
 * sandbox's capability rights.
 */

int
ctl_scan_result(const struct ctl_scan_params *params,
    struct blued_adapter *target, ctl_scan_result_cb cb, void *arg,
    int duration_sec)
{
	struct blued_adapter *adp;
	struct ble_scan_result results[BLE_MAX_SCAN_RESULTS];
	struct hci_scan_params sp;
	struct ble_scan_filter filt;
	char addr_str[18];
	int nresults, i;
	int nadapters_scanned = 0;

	/*
	 * Finding C-M1: this scan runs synchronously on the main event-loop
	 * thread and blocks it for the whole duration per adapter.  Bound the
	 * caller-requested duration so a single request cannot freeze the loop
	 * for an unbounded time.
	 */
	if (duration_sec < 1)
		duration_sec = 1;
	if (duration_sec > 5)
		duration_sec = 5;

	hci_scan_params_default(&sp);
	memset(&filt, 0, sizeof(filt));
	if (params != NULL) {
		sp.active = params->passive ? 0 : 1;
		if (params->interval != 0)
			sp.interval = params->interval;
		if (params->window != 0)
			sp.window = params->window;
		sp.filter_policy = params->accept_list ? 1 : 0;
		sp.filter_dup = params->no_dedup ? 0 : 1;
		if (params->uuid16 != 0) {
			filt.has_uuid = true;
			filt.uuid16 = params->uuid16;
		}
		if (params->rssi_min != INT8_MIN) {
			filt.has_rssi = true;
			filt.rssi_min = params->rssi_min;
		}
		if (params->name_sub[0] != '\0') {
			filt.has_name = true;
			strlcpy(filt.name_sub, params->name_sub,
			    sizeof(filt.name_sub));
		}
	}
	if (sp.interval < 0x0004 || sp.interval > 0x4000 ||
	    sp.window < 0x0004 || sp.window > sp.interval)
		return (IPC_ERR_INVAL);
	if (target != NULL && (!target->active || !target->powered ||
	    target->power_quiescing))
		return (IPC_ERR_NOT_FOUND);

	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (!adp->active || !adp->powered || adp->power_quiescing)
			continue;
		if (target != NULL && adp != target)
			continue;

		BLUED_PROBE_SCAN_START(adp->name);
		nresults = 0;
		if (adp->le_features & LE_FEAT_EXT_ADVERTISING) {
			uint8_t sphys = 0x01;
			if (adp->le_features & LE_FEAT_CODED_PHY)
				sphys = 0x05;
			if (hci_le_ext_scan_ex(adp->hci_fd, duration_sec, &sp,
			    results, BLE_MAX_SCAN_RESULTS, &nresults, sphys) != 0)
				nresults = 0;
		}
		if (nresults == 0) {
			if (hci_le_scan_ex(adp->hci_fd, duration_sec, &sp,
			    results, BLE_MAX_SCAN_RESULTS, &nresults) < 0)
				continue;
		}

		nadapters_scanned++;

		for (i = 0; i < nresults; i++) {
			struct ble_scan_result *r = &results[i];

			/* Post-scan filter (uuid/rssi/name). */
			if (!ble_scan_result_match(r, &filt))
				continue;
			bt_ntoa((bdaddr_t *)r->addr, addr_str);
			BLUED_PROBE_SCAN_RESULT(addr_str, r->rssi);
			if (cb != NULL)
				cb(adp, r, arg);
		}
	}

	if (nadapters_scanned == 0)
		return (IPC_ERR_NOT_FOUND);

	/*
	 * A synchronous SCAN burst reprograms and then disables the controller
	 * scanner; if a mesh subscription wants the scanner always-on, re-assert
	 * it now so the mesh RX path is never left stuck-off by an unrelated
	 * SCAN (broker step C scanner reconciliation).
	 */
	blued_mesh_scan_resume();
	return (IPC_ERR_NONE);
}



/*
 * Handle the STATUS command.
 */
void
ctl_status_snapshot(uint16_t *adapters, uint16_t *connections,
    uint16_t *clients, uint16_t *flags)
{
	struct blued_adapter *adp;
	struct blued_conn *conn;
	struct blued_ctl_client *client;
	uint16_t nadp, nconn, nclients, fl;

	nadp = 0;
	LIST_FOREACH(adp, &blued_g.adapters, entries)
		if (adp->active)
			nadp++;

	nconn = 0;
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries)
		nconn++;
	pthread_rwlock_unlock(&blued_g.conns_lock);

	nclients = 0;
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(client, &blued_g.ctl_clients, entries)
		nclients++;
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);

	fl = 0;
	if (blued_g.periph_active)
		fl |= IPC_STATUS_F_PERIPH_ACTIVE;

	*adapters = nadp;
	*connections = nconn;
	*clients = nclients;
	*flags = fl;
}




int
ctl_connect_result(const bdaddr_t *addr, uint8_t addr_type,
    struct blued_adapter *adp, const struct ctl_connect_params *params)
{
	struct blued_conn *conn;
	struct hogp_device *hdev;
	pthread_t tid;
	pthread_attr_t pattr;

	if (addr_type != BDADDR_LE_PUBLIC && addr_type != BDADDR_LE_RANDOM)
		return (IPC_ERR_INVAL);
	if (params != NULL) {
		if (params->has_conn_params &&
		    (params->interval_min < 0x0006 ||
		    params->interval_max > 0x0c80 ||
		    params->interval_min > params->interval_max ||
		    params->timeout < 0x000a))
			return (IPC_ERR_INVAL);
		if (params->has_phy &&
		    ((params->tx_phys & ~0x07) != 0 ||
		    (params->rx_phys & ~0x07) != 0))
			return (IPC_ERR_INVAL);
	}
	if (adp == NULL) {
		adp = LIST_FIRST(&blued_g.adapters);
		while (adp != NULL && !adp->active)
			adp = LIST_NEXT(adp, entries);
	}
	if (adp == NULL || !adp->active)
		return (IPC_ERR_NOT_FOUND);
	if (blued_conn_by_peer(adp, addr, addr_type) != NULL)
		return (IPC_ERR_BUSY);
	hdev = blued_hogp_alloc(adp, (const uint8_t *)addr, addr_type, false);
	if (hdev == NULL)
		return (errno == ENOSPC ? IPC_ERR_BUSY : IPC_ERR_NOMEM);
	conn = blued_conn_alloc();
	if (conn == NULL) {
		free(hdev);
		return (IPC_ERR_NOMEM);
	}
	conn->hogp = hdev;
	memcpy(&conn->dst, addr, sizeof(conn->dst));
	conn->addr_type = addr_type;
	conn->adapter = adp;
	conn->role = BLUED_ROLE_CENTRAL;
	conn->reconnect = false;
	conn->local_own_addr_type = adp->privacy ? 0x03 : 0x00;
	blued_conn_reset_local(conn);
	if (params != NULL && params->has_conn_params) {
		conn->has_req_conn_params = true;
		conn->req_itvl_min = params->interval_min;
		conn->req_itvl_max = params->interval_max;
		conn->req_latency = params->latency;
		conn->req_timeout = params->timeout;
	}
	if (params != NULL && params->has_phy) {
		conn->has_req_phy = true;
		conn->req_tx_phys = params->tx_phys;
		conn->req_rx_phys = params->rx_phys;
	}
	blued_conn_set_state(conn, BLUED_CONN_CONNECTING);
	pthread_attr_init(&pattr);
	pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED);
	blued_conn_ref(conn);
	blued_setup_worker_start(conn);
	if (pthread_create(&tid, &pattr, blued_conn_setup_central, conn) != 0) {
		blued_setup_worker_finish(conn);
		blued_conn_unref(conn);
		blued_conn_free(conn);
		free(hdev);
		pthread_attr_destroy(&pattr);
		return (IPC_ERR_IO);
	}
	pthread_attr_destroy(&pattr);
	return (IPC_ERR_NONE);
}

struct ctl_connect_name_match {
	const char	*name;
	bool		found;
	bdaddr_t	addr;
	uint8_t		addr_type;
};

static void
ctl_connect_name_scan_result(const struct blued_adapter *adapter,
    const struct ble_scan_result *result, void *arg)
{
	struct ctl_connect_name_match *match = arg;

	(void)adapter;
	if (!match->found && result->has_name &&
	    strcasecmp(result->name, match->name) == 0) {
		memcpy(&match->addr, result->addr, sizeof(match->addr));
		match->addr_type = result->addr_type;
		match->found = true;
	}
}

int
ctl_connect_name_result(const char *name, struct blued_adapter *adapter,
    bdaddr_t *addr, uint8_t *addr_type)
{
	struct ctl_connect_name_match match;
	struct ctl_scan_params params;
	int error;

	if (name == NULL || name[0] == '\0' || strnlen(name, 32) >= 32 ||
	    adapter == NULL || !adapter->active || addr == NULL || addr_type == NULL)
		return (IPC_ERR_INVAL);
	memset(&match, 0, sizeof(match));
	memset(&params, 0, sizeof(params));
	match.name = name;
	params.rssi_min = INT8_MIN;
	strlcpy(params.name_sub, name, sizeof(params.name_sub));
	error = ctl_scan_result(&params, adapter, ctl_connect_name_scan_result,
	    &match, 5);
	if (error != IPC_ERR_NONE)
		return (error);
	if (!match.found)
		return (IPC_ERR_NOT_FOUND);
	error = ctl_connect_result(&match.addr, match.addr_type, adapter, NULL);
	if (error != IPC_ERR_NONE)
		return (error);
	*addr = match.addr;
	*addr_type = match.addr_type;
	return (IPC_ERR_NONE);
}



int
ctl_disconnect_result(uint8_t adapter_index, const bdaddr_t *addr,
    uint8_t addr_type)
{
	struct blued_conn *conn;

	/*
	 * Find the connection under rdlock, check state, then release
	 * the lock before calling blued_conn_disconnect() which handles
	 * the full lifecycle (CCCD save, kqueue cleanup, reconnect or
	 * free).  This avoids holding the lock during disk I/O.
	 *
	 * Safe because: (1) the control socket handler runs on the
	 * main event loop thread, same as blued_conn_disconnect;
	 * (2) blued_conn_disconnect has an atomic double-disconnect guard.
	 */
	conn = blued_conn_by_peer(blued_adapter_by_index_powered(adapter_index), addr,
	    addr_type);
	if (conn == NULL) {
		return (IPC_ERR_NOT_FOUND);
	}
	conn->reconnect = false; /* prevent auto-reconnect */
	/*
	 * Finding H-L8: a CONNECTING conn is owned by its detached setup thread,
	 * so blued_conn_disconnect latches disconnect_pending and lets the
	 * thread tear the conn down at its handoff barrier rather than freeing
	 * state under it.  Route through it instead of refusing with BUSY so the
	 * operator's disconnect is honoured once setup completes/aborts.
	 */
	blued_conn_disconnect(conn);
	return (IPC_ERR_NONE);
}


/*
 * Look up a live connection by address and return its controller fd and
 * connection handle.  Returns 0 on success, -1 when the address is malformed,
 * -2 when no matching device is known, -3 when it is known but has no live
 * HCI handle yet.
 */
static int
ctl_conn_lookup(uint8_t adapter_index, const bdaddr_t *addr, uint8_t addr_type,
    int *hci_fd, uint16_t *handle, uint64_t *le_features)
{
	struct blued_conn *conn;

	conn = blued_conn_by_peer(blued_adapter_by_index_powered(adapter_index), addr,
	    addr_type);
	if (conn == NULL) {
		return (-2);
	}
	if (!conn->con_handle_valid) {
		return (-3);
	}
	*hci_fd = conn->adapter != NULL ? conn->adapter->hci_fd : -1;
	*handle = conn->con_handle;
	if (le_features != NULL)
		*le_features = conn->adapter != NULL ?
		    conn->adapter->le_features : 0;
	return (0);
}



int
ctl_set_phy_result(uint8_t adapter_index, const bdaddr_t *addr,
    uint8_t addr_type, uint8_t tx_phys, uint8_t rx_phys)
{
	uint8_t all_phys;
	uint16_t handle;
	int hci_fd, rc;

	if ((tx_phys & ~0x07) != 0 || (rx_phys & ~0x07) != 0)
		return (IPC_ERR_INVAL);
	rc = ctl_conn_lookup(adapter_index, addr, addr_type, &hci_fd, &handle,
	    NULL);
	if (rc == -2)
		return (IPC_ERR_NOT_FOUND);
	if (rc != 0)
		return (IPC_ERR_NOT_CONN);
	all_phys = (tx_phys == 0 ? 0x01 : 0) |
	    (rx_phys == 0 ? 0x02 : 0);
	if (hci_le_set_phy(hci_fd, handle, all_phys, tx_phys, rx_phys,
	    0x0000) < 0)
		return (IPC_ERR_IO);
	return (IPC_ERR_NONE);
}


int
ctl_set_data_len_result(uint8_t adapter_index, const bdaddr_t *addr,
    uint8_t addr_type, uint16_t tx_octets, uint16_t tx_time)
{
	uint16_t handle;
	int hci_fd, rc;

	if (tx_octets < 0x001B || tx_octets > 0x00FB ||
	    tx_time < 0x0148 || tx_time > 0x4290)
		return (IPC_ERR_INVAL);
	rc = ctl_conn_lookup(adapter_index, addr, addr_type, &hci_fd, &handle,
	    NULL);
	if (rc == -2)
		return (IPC_ERR_NOT_FOUND);
	if (rc != 0)
		return (IPC_ERR_NOT_CONN);
	if (hci_le_set_data_length(hci_fd, handle, tx_octets, tx_time) < 0)
		return (IPC_ERR_IO);
	return (IPC_ERR_NONE);
}


int
ctl_path_loss_result(uint8_t adapter_index, const bdaddr_t *addr,
    uint8_t addr_type, uint8_t low,
    uint8_t low_hysteresis, uint8_t high, uint8_t high_hysteresis,
    uint16_t min_time, bool enable)
{
	int hci_fd, rc;
	uint16_t handle;
	uint64_t features;

	if (low > high)
		return (IPC_ERR_INVAL);
	rc = ctl_conn_lookup(adapter_index, addr, addr_type, &hci_fd, &handle,
	    &features);
	if (rc == -2)
		return (IPC_ERR_NOT_FOUND);
	if (rc != 0)
		return (IPC_ERR_NOT_CONN);
	if ((features & LE_FEAT_PATH_LOSS_MONITORING) == 0)
		return (IPC_ERR_NOT_FOUND);
	if (hci_le_set_path_loss_reporting_params(hci_fd, handle, high,
	    high_hysteresis, low, low_hysteresis, min_time) < 0 ||
	    hci_le_set_path_loss_reporting_enable(hci_fd, handle, enable) < 0)
		return (IPC_ERR_IO);
	return (IPC_ERR_NONE);
}


int
ctl_connparams_update_result(uint8_t adapter_index, const bdaddr_t *addr,
    uint8_t addr_type, uint16_t interval_min, uint16_t interval_max,
    uint16_t latency, uint16_t timeout)
{
	uint64_t le_features;
	uint16_t handle;
	int hci_fd, rc;

	if (interval_min > interval_max)
		return (IPC_ERR_INVAL);
	rc = ctl_conn_lookup(adapter_index, addr, addr_type, &hci_fd, &handle,
	    &le_features);
	if (rc == -2)
		return (IPC_ERR_NOT_FOUND);
	if (rc != 0)
		return (IPC_ERR_NOT_CONN);
	if (!l2cap_conn_param_use_hci_update(le_features))
		return (IPC_ERR_INVAL);
	if (hci_le_connection_update(hci_fd, handle, interval_min,
	    interval_max, latency, timeout) < 0)
		return (IPC_ERR_INVAL);
	return (IPC_ERR_NONE);
}
