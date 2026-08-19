/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Internal declarations shared between ctl.c, ctl_gatt.c, and ctl_conn.c.
 * Not part of the public interface (use ctl.h for that).
 */

#ifndef _BLUED_CTL_INTERNAL_H_
#define _BLUED_CTL_INTERNAL_H_

#include <sys/time.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Forward declarations */
struct blued_ctl_client;
struct blued_conn;

/* Maximum command line length */
#define CTL_MAXLINE	256

/*
 * ATT I/O timeout for control socket commands (seconds).
 */
#define CTL_ATT_TIMEOUT_SEC	2

/*
 * Address types have two deliberately different domains in blued:
 *
 *   control IPC / HCI wire:  0 = public, 1 = random
 *   FreeBSD socket/internal: BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM (1, 2)
 *
 * Keep connection keys, subscriptions, and all ctl_*_result() arguments in
 * the internal BDADDR_LE_* domain.  Convert exactly once while decoding a
 * request and exactly once while encoding an event/reply.  In particular,
 * never compare an IPC byte directly with struct blued_conn::addr_type.
 */
static inline bool
ctl_addr_type_from_ipc(uint8_t wire, uint8_t *internal)
{

	if (internal == NULL || wire > 1)
		return (false);
	*internal = wire == 0 ? BDADDR_LE_PUBLIC : BDADDR_LE_RANDOM;
	return (true);
}

static inline bool
ctl_addr_type_to_ipc(uint8_t internal, uint8_t *wire)
{

	if (wire == NULL || (internal != BDADDR_LE_PUBLIC &&
	    internal != BDADDR_LE_RANDOM))
		return (false);
	*wire = internal == BDADDR_LE_RANDOM ? 1 : 0;
	return (true);
}

/* ctl.c — ATT timeout helpers */
void	ctl_set_att_timeout(int att_fd, struct timeval *old_tv);
void	ctl_restore_att_timeout(int att_fd, const struct timeval *old_tv);

/*
 * ctl_conn.c — resolve an optional "adapter=<index>" token in a command's
 * argument buffer (edited in place; token removed).  Returns 0 (no token,
 * *out untouched), 1 (token resolved, *out set), or -1 (malformed/out of
 * range).  Shared by the per-adapter verbs and the mesh-bearer send path.
 */
struct blued_adapter;
struct ctl_connect_params {
	bool		has_conn_params;
	bool		has_phy;
	uint16_t	interval_min;
	uint16_t	interval_max;
	uint16_t	latency;
	uint16_t	timeout;
	uint8_t		tx_phys;
	uint8_t		rx_phys;
};
struct ctl_scan_params {
	bool		passive;
	bool		accept_list;
	bool		no_dedup;
	uint16_t	interval;
	uint16_t	window;
	uint16_t	uuid16;
	int8_t		rssi_min;
	char		name_sub[32];
};
struct ble_scan_result;
struct gatt_service;
struct gatt_char;
typedef void (*ctl_scan_result_cb)(const struct blued_adapter *,
	    const struct ble_scan_result *, void *);
typedef void (*ctl_gatt_discover_cb)(const struct gatt_service *,
	    const struct gatt_char *, void *);
/* ctl_conn.c — connection commands */
int	ctl_scan_result(const struct ctl_scan_params *params,
	    struct blued_adapter *target, ctl_scan_result_cb cb, void *arg,
	    int duration_sec);
void	ctl_status_snapshot(uint16_t *adapters, uint16_t *connections,
	    uint16_t *clients, uint16_t *flags);
int	ctl_disconnect_result(uint8_t adapter_index, const bdaddr_t *addr,
	    uint8_t addr_type);
int	ctl_connect_result(const bdaddr_t *addr, uint8_t addr_type,
	    struct blued_adapter *adapter, const struct ctl_connect_params *params);
int	ctl_connect_name_result(const char *name, struct blued_adapter *adapter,
		    bdaddr_t *addr, uint8_t *addr_type);
int	ctl_set_phy_result(uint8_t adapter_index, const bdaddr_t *addr,
	    uint8_t addr_type, uint8_t tx_phys, uint8_t rx_phys);
int	ctl_set_data_len_result(uint8_t adapter_index, const bdaddr_t *addr,
	    uint8_t addr_type, uint16_t tx_octets, uint16_t tx_time);
int	ctl_path_loss_result(uint8_t adapter_index, const bdaddr_t *addr,
	    uint8_t addr_type, uint8_t low,
	    uint8_t low_hysteresis, uint8_t high, uint8_t high_hysteresis,
	    uint16_t min_time, bool enable);
int	ctl_connparams_update_result(uint8_t adapter_index,
	    const bdaddr_t *addr, uint8_t addr_type,
	    uint16_t interval_min, uint16_t interval_max, uint16_t latency,
	    uint16_t timeout);

/*
 * ctl_gatt.c — GATT commands.
 *
 * These run on a GATT worker thread over the specific connection the job was
 * admitted against — passed as job_conn (finding 90).  Operating on job_conn
 * (which the admission ref-counted and gated with att_ops_active) instead of
 * re-resolving by address prevents a duplicate-accept second connection for the
 * same peer from being picked up and driven with no ref / no att_ops_active.
 */
int	ctl_gatt_read_result(struct blued_conn *job_conn, uint8_t adapter_index,
	    const bdaddr_t *addr, uint8_t addr_type, uint16_t handle,
	    uint8_t *value, size_t value_size, size_t *value_len);
int	ctl_gatt_write_result(struct blued_conn *job_conn, uint8_t adapter_index,
	    const bdaddr_t *addr, uint8_t addr_type, uint16_t handle,
	    const uint8_t *value, size_t value_len, bool command);
int	ctl_gatt_subscribe_result(struct blued_conn *job_conn, int client_fd,
	    uint64_t client_generation, uint8_t adapter_index,
	    const bdaddr_t *addr, uint8_t addr_type,
	    uint16_t handle, bool subscribe);
int	ctl_gatt_discover_result(struct blued_conn *job_conn,
	    uint8_t adapter_index, const bdaddr_t *addr, uint8_t addr_type,
	    ctl_gatt_discover_cb cb, void *arg);
int	ctl_gatt_read_reply_result(int client_fd, uint16_t handle,
	    const uint8_t *value, uint16_t value_len);
int	ctl_gatt_read_reject_result(int client_fd, uint16_t handle,
	    uint8_t att_error);
int	ctl_gatt_authorize_reply_result(int client_fd, uint16_t handle,
	    bool allow);
int	ctl_gatt_set_value_result(int client_fd, uint16_t handle,
	    const uint8_t *value, uint16_t value_len);
int	ctl_gatt_notify_result(uint16_t handle, const uint8_t *value,
	    uint16_t value_len, bool indicate, int *sent);
int	ctl_gatt_remove_service_result(int client_fd, uint16_t handle);
int	ctl_gatt_add_service_result(int client_fd, uint16_t uuid16,
	    const uint8_t uuid128[16], uint16_t *handle);
int	ctl_gatt_add_char_result(int client_fd, uint16_t service_handle,
	    uint16_t uuid16, const uint8_t uuid128[16], uint8_t properties,
	    uint8_t permissions, uint8_t flags, const uint8_t *value,
	    uint16_t value_len, uint16_t *handle);
int	ctl_gatt_add_include_result(int client_fd, uint16_t service_handle,
	    uint16_t included_start, uint16_t included_end, uint16_t uuid16,
	    uint16_t *handle);
int	ctl_gatt_add_desc_result(int client_fd, uint16_t char_handle,
	    uint16_t uuid16, const uint8_t uuid128[16], uint8_t permissions,
	    const uint8_t *value, uint16_t value_len, uint16_t *handle);

/*
 * ctl_gatt.c — atomic GATT-application registration (the common atomic
 * GATT-application registration model).  GATT_BEGIN opens a per-client staged
 * build (a scratch DB seeded from the live DB); ADD_SERVICE/ADD_INCLUDE/
 * ADD_CHAR/ADD_DESC/REMOVE_SERVICE issued by the owner then stage into the
 * scratch instead of mutating the live DB.  GATT_COMMIT swaps the scratch into
 * the live DB with a single DB-hash recompute and Service Changed;
 * GATT_ROLLBACK (or a staging error, or the owner disconnecting) discards it
 * with the live DB untouched.  All run under gatt_db_lock (held by the
 * dispatcher).
 */
int	ctl_gatt_begin_result(int client_fd);
int	ctl_gatt_commit_result(int client_fd);
int	ctl_gatt_rollback_result(int client_fd);
void	ctl_gatt_txn_client_gone(int client_fd);

/*
 * ctl_iso.c — LE Isochronous (CIS/BIS) operator verbs.  Recognises and handles
 * the ISO_* verb family (CIG/CIS/BIG create, accept/reject, acquire, teardown)
 * and returns true when it consumed the line, false when the verb is not an ISO
 * verb (so the caller can keep matching).  The daemon's privilege gate has
 * already run; the fd-passing acquire verbs additionally require the client to
 * have negotiated fd-passing.
 */
void	ctl_iso_process_typed(struct blued_ctl_client *, const uint8_t *,
	    size_t);
int	ctl_send_frame(struct blued_ctl_client *, uint16_t, uint16_t,
	    const void *, size_t);
bool	ctl_tx_has_room(const struct blued_ctl_client *, size_t);
int	ctl_send_fd_to_client(struct blued_ctl_client *, int);
int	ctl_send_ecbfc_fd_to_client(struct blued_ctl_client *, int);
void	ctl_send_op_ack(struct blued_ctl_client *, uint16_t);
void	ctl_send_op_error(struct blued_ctl_client *, uint16_t, uint16_t,
	    const char *);

/* ctl_gatt.c — deferred-access replies (dynamic read / authorization) */

#endif /* _BLUED_CTL_INTERNAL_H_ */
