/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libble — BLE client library for the blued(8) daemon.
 *
 * Provides a callback-driven C API for Bluetooth Low Energy
 * operations, similar in spirit to Apple's CoreBluetooth framework.
 * All BLE operations are proxied through blued's Unix domain control
 * socket — this library does not access HCI or L2CAP directly.
 *
 * Thread safety:
 *   A ble_ctx_t is NOT thread-safe.  Each context must be used from
 *   a single thread at a time.  Multiple threads may each have their
 *   own independent contexts.
 *
 * Event-driven usage:
 *   Use ble_fd(ctx) to obtain the socket descriptor for integration
 *   with kqueue(2), poll(2), or select(2).  Call ble_process(ctx)
 *   when the descriptor becomes readable.
 *
 * Usage:
 *   ble_ctx_t *ctx = ble_open(NULL);  // connect to default socket
 *   ble_scan(ctx, my_scan_cb, NULL);
 *   while (ble_process(ctx) == 0)
 *       ;  // or integrate ble_fd(ctx) with kqueue/poll
 *   ble_close(ctx);
 */

#ifndef _BLE_H_
#define _BLE_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* Opaque library context */
typedef struct ble_ctx ble_ctx_t;

/* BLE device address */
typedef struct {
	uint8_t		addr[6];
	uint8_t		addr_type;	/* 0 = public, 1 = random */
	uint8_t		adapter_index;	/* controller index, 0 = primary */
} ble_addr_t;

/* UUID (16-bit or 128-bit) */
typedef struct {
	uint16_t	uuid16;		/* non-zero for 16-bit UUIDs */
	uint8_t		uuid128[16];	/* used when uuid16 == 0 */
} ble_uuid_t;

/* Scan result */
typedef struct {
	ble_addr_t	addr;
	char		name[64];
	int8_t		rssi;
	uint16_t	mfr_id;
	ble_uuid_t	svc_uuids[8];
	int		num_svc_uuids;
} ble_scan_result_t;

/*
 * Controller capabilities reported by blued for one active adapter.  The
 * le_features field is the Bluetooth Core LE Read Local Supported Features
 * octet mask (Vol 4, Part E, 7.8.3); applications should test it before using
 * an optional controller procedure rather than treating an HCI failure as an
 * unsupported-feature error.
 */
typedef struct {
	int		index;
	char		name[16];
	ble_addr_t	addr;
	uint64_t	le_features;
	bool		powered;
} ble_adapter_caps_t;

typedef struct {
	uint16_t	adapters;
	uint16_t	connections;
	uint16_t	clients;
	bool		peripheral_active;
} ble_status_t;

/* Bits in ble_adapter_caps_t.le_features (Core Vol 4, Part E, 7.8.3). */
#define	BLE_LE_FEAT_PERIODIC_ADV	(1ULL << 13)
#define	BLE_LE_FEAT_PAST_SENDER	(1ULL << 24)
#define	BLE_LE_FEAT_PAST_RECIPIENT	(1ULL << 25)
#define	BLE_LE_FEAT_POWER_CONTROL	(1ULL << 33)
#define	BLE_LE_FEAT_PATH_LOSS_MONITORING	(1ULL << 35)

/* LE Set Periodic Advertising Parameters properties (Vol 4, Part E, 7.8.61). */
#define	BLE_PERIODIC_ADV_PROP_INCLUDE_TX_POWER	0x0040u

/* Discovered service */
typedef struct {
	ble_uuid_t	uuid;
	uint16_t	start_handle;
	uint16_t	end_handle;
} ble_service_t;

/* Discovered characteristic */
typedef struct {
	ble_uuid_t	uuid;
	uint16_t	handle;		/* value handle */
	uint8_t		properties;
} ble_characteristic_t;

/* Characteristic properties (Core 6.3 Vol 3 Part G §3.3.1.1, Table 3.5). */
#define	BLE_PROP_BROADCAST		0x01
#define	BLE_PROP_READ			0x02
#define	BLE_PROP_WRITE_NO_RSP		0x04
#define	BLE_PROP_WRITE			0x08
#define	BLE_PROP_NOTIFY			0x10
#define	BLE_PROP_INDICATE		0x20
/* 0x40 is "Previously used"; exposed only for legacy peer compatibility. */
#define	BLE_PROP_LEGACY_AUTH_SIGNED_WRITE 0x40
#define	BLE_PROP_AUTH_SIGNED_WRITE BLE_PROP_LEGACY_AUTH_SIGNED_WRITE
#define	BLE_PROP_EXTENDED		0x80

/*
 * Well-known GATT service UUIDs.
 */
#define	BLE_SVC_GAP			0x1800
#define	BLE_SVC_GATT			0x1801
#define	BLE_SVC_IMMEDIATE_ALERT		0x1802
#define	BLE_SVC_LINK_LOSS		0x1803
#define	BLE_SVC_TX_POWER		0x1804
#define	BLE_SVC_CURRENT_TIME		0x1805
#define	BLE_SVC_GLUCOSE			0x1808
#define	BLE_SVC_HEALTH_THERMOMETER	0x1809
#define	BLE_SVC_DEVICE_INFORMATION	0x180A
#define	BLE_SVC_HEART_RATE		0x180D
#define	BLE_SVC_PHONE_ALERT_STATUS	0x180E
#define	BLE_SVC_BATTERY			0x180F
#define	BLE_SVC_BLOOD_PRESSURE		0x1810
#define	BLE_SVC_ALERT_NOTIFICATION	0x1811
#define	BLE_SVC_HID			0x1812
#define	BLE_SVC_RUNNING_SPEED		0x1814
#define	BLE_SVC_CYCLING_SPEED		0x1816
#define	BLE_SVC_LOCATION_NAVIGATION	0x1819
#define	BLE_SVC_ENVIRONMENTAL_SENSING	0x181A
#define	BLE_SVC_WEIGHT_SCALE		0x181D
#define	BLE_SVC_CONTINUOUS_GLUCOSE	0x181F

/*
 * Well-known GATT characteristic UUIDs.
 */
#define	BLE_CHR_DEVICE_NAME		0x2A00
#define	BLE_CHR_BATTERY_LEVEL		0x2A19
#define	BLE_CHR_SYSTEM_ID		0x2A23
#define	BLE_CHR_MODEL_NUMBER		0x2A24
#define	BLE_CHR_SERIAL_NUMBER		0x2A25
#define	BLE_CHR_FIRMWARE_REV		0x2A26
#define	BLE_CHR_HARDWARE_REV		0x2A27
#define	BLE_CHR_SOFTWARE_REV		0x2A28
#define	BLE_CHR_MANUFACTURER_NAME	0x2A29
#define	BLE_CHR_HEART_RATE_MEASUREMENT	0x2A37
#define	BLE_CHR_PNP_ID			0x2A50
#define	BLE_CHR_ALERT_LEVEL		0x2A06
#define	BLE_CHR_TEMPERATURE_MEASUREMENT	0x2A1C
#define	BLE_CHR_CURRENT_TIME		0x2A2B

/* Attribute permissions */
#define	BLE_PERM_READ			0x01
#define	BLE_PERM_WRITE			0x02
#define	BLE_PERM_READ_ENCRYPT		0x04
#define	BLE_PERM_WRITE_ENCRYPT		0x08
#define	BLE_PERM_READ_AUTHEN		0x10
#define	BLE_PERM_WRITE_AUTHEN		0x20

/* PHY values for connection snapshots and advertising selection. */
#define	BLE_PHY_1M			1
#define	BLE_PHY_2M			2
#define	BLE_PHY_CODED			3

/* PHY preference bit masks for ble_set_phy / ble_conn_params_t (OR together). */
#define	BLE_PHY_MASK_1M			0x01
#define	BLE_PHY_MASK_2M			0x02
#define	BLE_PHY_MASK_CODED		0x04

/* Advertising mode for ble_adv_params_t (parity with LEAdvertisingManager1). */
#define	BLE_ADV_MODE_AUTO		0	/* extended if supported */
#define	BLE_ADV_MODE_LEGACY		1
#define	BLE_ADV_MODE_EXTENDED		2

/* Advertising type for ble_adv_params_t (parity with ble_gap_adv_params). */
#define	BLE_ADV_TYPE_CONN_UND		0	/* connectable undirected */
#define	BLE_ADV_TYPE_CONN_DIR_HIGH	1	/* connectable directed, high duty */
#define	BLE_ADV_TYPE_CONN_DIR_LOW	2	/* connectable directed, low duty */
#define	BLE_ADV_TYPE_SCAN_UND		3	/* scannable undirected */
#define	BLE_ADV_TYPE_NONCONN_UND	4	/* non-connectable undirected */

/*
 * Advertising parameters (parity with the common LE-advertisement
 * model and NimBLE ble_gap_adv_params / ble_gap_ext_adv_params).
 * Intervals are in units of 0.625 ms.  primary_phy/secondary_phy use BLE_PHY_*
 * single values and apply only to the extended path.  For a directed type set
 * has_peer and fill peer.
 */
typedef struct {
	int		mode;		/* BLE_ADV_MODE_* */
	int		type;		/* BLE_ADV_TYPE_* */
	uint16_t	interval_min;	/* units of 0.625 ms */
	uint16_t	interval_max;	/* units of 0.625 ms */
	uint8_t		channel_map;	/* bit0=ch37 bit1=ch38 bit2=ch39 (0=>all) */
	int8_t		tx_power;	/* extended only; dBm, 127 = no pref */
	uint8_t		own_addr_type;	/* 0=public 1=random 2/3=RPA */
	uint8_t		primary_phy;	/* BLE_PHY_1M or BLE_PHY_CODED */
	uint8_t		secondary_phy;	/* BLE_PHY_1M/2M/CODED */
	bool		has_peer;	/* directed target present */
	ble_addr_t	peer;		/* directed peer address + type */
} ble_adv_params_t;

/*
 * Initial / updated connection parameters (parity with ble_gap_conn_params /
 * ble_gap_upd_params).  interval_* in units of 1.25 ms, timeout in units of
 * 10 ms, latency in connection events.  tx_phys/rx_phys are BLE_PHY_MASK_*
 * bit masks (0 = no preference).
 */
typedef struct {
	uint16_t	interval_min;	/* units of 1.25 ms */
	uint16_t	interval_max;	/* units of 1.25 ms */
	uint16_t	latency;	/* peripheral latency */
	uint16_t	timeout;	/* units of 10 ms */
	uint8_t		tx_phys;	/* BLE_PHY_MASK_* (0 = no preference) */
	uint8_t		rx_phys;	/* BLE_PHY_MASK_* (0 = no preference) */
} ble_conn_params_t;

/*
 * Scan / discovery parameters (parity with the common discovery-filter model and NimBLE
 * ble_gap_disc_params).  An all-zero value is equivalent to the bare ble_scan():
 * active scan, controller default interval/window, accept-all policy, duplicate
 * filtering on, and no post-scan result filter.  interval/window are in units of
 * 0.625 ms (0 = daemon default).  The uuid16/rssi_min/name_sub fields filter the
 * parsed results before they are reported: uuid16 0 = any, rssi_min BLE_RSSI_ANY
 * = any, empty name_sub = any.
 */
#define	BLE_RSSI_ANY			(-128)
typedef struct {
	bool		passive;	/* false = active scan (default) */
	uint16_t	interval;	/* units of 0.625 ms; 0 = default */
	uint16_t	window;		/* units of 0.625 ms; 0 = default */
	bool		accept_list;	/* true = accept-list filter policy */
	bool		no_dedup;	/* true = do not filter duplicates */
	uint16_t	uuid16;		/* require service UUID; 0 = any */
	int8_t		rssi_min;	/* drop weaker; BLE_RSSI_ANY = any */
	char		name_sub[32];	/* require name substring; "" = any */
} ble_scan_params_t;

/* Error codes returned by ble_errno() */
#define	BLE_ERR_NONE			0
#define	BLE_ERR_SOCKET			1	/* socket I/O error */
#define	BLE_ERR_PROTO			2	/* protocol parse error */
#define	BLE_ERR_BUSY			3	/* operation in progress */
#define	BLE_ERR_NOTCONN			4	/* not connected */
#define	BLE_ERR_INVAL			5	/* invalid argument */
#define	BLE_ERR_DAEMON			6	/* daemon returned ERROR */
#define	BLE_ERR_NOMEM			7	/* out of memory */
#define	BLE_ERR_TIMEOUT			8	/* operation timed out */
#define	BLE_ERR_PERM			9	/* permission denied (privilege tier) */
#define	BLE_ERR_NOTFOUND		10	/* device/handle/service not found */

/* Maximum number of bonds returned by ble_bond_list() */
#define	BLE_MAX_BONDS			32

/* Bond information entry */
typedef struct {
	ble_addr_t	addr;
	bool		has_ltk;
	bool		has_irk;
	bool		has_csrk;
	bool		is_sc;		/* Secure Connections pairing */
	bool		has_link_key;
	char		name[64];
} ble_bond_t;

#define	BLE_CONNECTION_IDLE		0
#define	BLE_CONNECTION_CONNECTING	1
#define	BLE_CONNECTION_ACTIVE		2
#define	BLE_CONNECTION_RECONNECTING	3

#define	BLE_ROLE_CENTRAL		0
#define	BLE_ROLE_PERIPHERAL		1

/* Structured connection snapshot returned by ble_connections(). */
typedef struct {
	ble_addr_t	addr;
	uint8_t		adapter_index;
	uint8_t		state;
	uint8_t		role;
	uint16_t	handle;
	uint16_t	mtu;
	bool		encrypted;
	bool		authenticated;
	uint8_t		key_size;
	bool		phy_valid;
	uint8_t		tx_phy;
	uint8_t		rx_phy;
	uint16_t	interval;
	uint16_t	latency;
	uint16_t	supervision_timeout;
	char		name[64];
} ble_connection_info_t;

typedef struct {
	ble_addr_t	addr;
	bool		in_controller;
} ble_resolv_entry_t;

/*
 * Opaque, key-bearing bond record for backup, restore, and migration (PC4).
 *
 * ble_bond_export() asks the (privileged) daemon for a full serialized bond --
 * LTK/IRK/CSRK, sign counter, and metadata -- as one opaque handle.  The record
 * bytes can be persisted and later reloaded with ble_bond_record_from_data()
 * to feed ble_bond_import() on this or another host.  SECURITY: the record
 * contains raw key material; store it protected.  Both export and import
 * require the privileged tier (uid 0) at the daemon.
 */
typedef struct ble_bond_record ble_bond_record_t;

/*
 * Callbacks — Central mode
 */
typedef void (*ble_scan_cb)(const ble_scan_result_t *result, void *arg);
typedef void (*ble_connect_cb)(const ble_addr_t *addr, int error, void *arg);
typedef void (*ble_discover_cb)(const ble_addr_t *addr,
	    const ble_service_t *svcs, int nsvc,
	    const ble_characteristic_t *chars, int nchar, void *arg);
typedef void (*ble_read_cb)(const ble_addr_t *addr, uint16_t handle,
	    const uint8_t *value, uint16_t len, int error, void *arg);
typedef void (*ble_notify_cb)(const ble_addr_t *addr, uint16_t handle,
	    const uint8_t *value, uint16_t len, void *arg);

/*
 * Callbacks — Peripheral mode
 */
typedef void (*ble_write_req_cb)(uint16_t handle,
	    const uint8_t *value, uint16_t len, void *arg);

/*
 * ble_read_req_cb fires on EVENT READ when a peer reads a characteristic added
 * "dynamic": the app must supply the current value with ble_gatt_read_reply()
 * (or decline with ble_gatt_read_reject()).  offset is non-zero for a
 * Read-Blob continuation; supply the full value and the daemon slices it.
 *
 * ble_authorize_cb fires on EVENT AUTHORIZE when a peer reads/writes a
 * characteristic added "authorize": answer with ble_gatt_authorize_reply().
 * is_write distinguishes a write from a read; addr identifies the peer.
 */
typedef void (*ble_read_req_cb)(uint16_t handle, uint16_t offset, void *arg);
typedef void (*ble_authorize_cb)(const ble_addr_t *addr, uint16_t handle,
	    bool is_write, void *arg);

/*
 * Callbacks — Connection lifecycle (push events)
 *
 * ble_conn_event_cb fires on EVENT CONNECTED when the LE link + ATT channel
 * are actually up (handle + negotiated ATT MTU supplied); ble_disconn_event_cb
 * fires on EVENT DISCONNECTED (HCI-style reason code).  Requires the daemon to
 * have accepted the push-events feature (negotiated automatically by ble_open).
 */
typedef void (*ble_conn_event_cb)(const ble_addr_t *addr, uint16_t handle,
	    uint16_t mtu, void *arg);
typedef void (*ble_disconn_event_cb)(const ble_addr_t *addr, uint16_t reason,
	    void *arg);

/*
 * Callbacks — Pairing
 */
typedef void (*ble_passkey_display_cb)(const ble_addr_t *addr,
	    uint32_t passkey, void *arg);
typedef void (*ble_passkey_input_cb)(const ble_addr_t *addr, void *arg);
typedef void (*ble_numcmp_cb)(const ble_addr_t *addr,
	    uint32_t value, void *arg);

/*
 * Lifecycle
 */

/* Open a connection to blued.  sock_path NULL uses default. */
ble_ctx_t	*ble_open(const char *sock_path);

/* Wrap an already-connected fd in a ble_ctx_t (for testing). */
ble_ctx_t	*ble_open_fd(int fd);

/*
 * Perform the framed-protocol HELLO handshake on an already-open context.
 * Sends the client protocol version and requested capability mask, waits for
 * the server's HELLO reply, and on success records the negotiated version and
 * capabilities.  Called automatically by ble_open(); exposed so a caller wrapping
 * a raw fd (ble_open_fd) can negotiate explicitly.  Returns 0 on success, -1
 * on version mismatch, timeout, or I/O error (the error is retrievable via
 * ble_errno()/ble_strerror()); never blocks indefinitely.
 */
int		 ble_handshake(ble_ctx_t *ctx);

/* Close the connection and free resources. */
void		 ble_close(ble_ctx_t *ctx);

/* Return the socket fd for integration with poll/kqueue/select. */
int		 ble_fd(ble_ctx_t *ctx);

/*
 * Read available data from the daemon and dispatch callbacks.
 * Returns 0 on success, -1 on connection loss.
 * Non-blocking if no data is available (use with poll).
 */
int		 ble_process(ble_ctx_t *ctx);

/*
 * Number of correlated operations awaiting their OP_REPLY.  A one-shot client
 * that issued a fire-and-forget operation (write/disconnect/pair/...) can pump
 * ble_process() until this reaches 0 to surface the daemon's correlated result
 * instead of exiting before the reply arrives.
 */
size_t		 ble_pending_count(const ble_ctx_t *ctx);

/*
 * Error handling
 *
 * All functions that return int set the error state on failure.
 * Use ble_errno() and ble_strerror() to inspect the most recent error.
 */

/* Return the last error code (BLE_ERR_*). */
int		 ble_errno(ble_ctx_t *ctx);

/* Return a human-readable description of the last error. */
const char	*ble_strerror(ble_ctx_t *ctx);

/*
 * Connection state
 */

/* Check whether at least one connection is established. */
bool		 ble_is_connected(ble_ctx_t *ctx);

/*
 * Legacy single-peer convenience: return the negotiated ATT MTU only when
 * exactly one peer is connected.  Returns 0 when none or multiple are active.
 */
uint16_t	 ble_get_mtu(ble_ctx_t *ctx);

/* Address-type- and adapter-specific connection state and negotiated ATT MTU. */
bool		 ble_is_peer_connected(ble_ctx_t *ctx, const ble_addr_t *addr);
uint16_t	 ble_get_peer_mtu(ble_ctx_t *ctx, const ble_addr_t *addr);

/*
 * Central mode — scanning and connection
 */

/*
 * Start a scan.  Results arrive via the callback.
 * Returns -1 if a scan is already in progress.
 */
int	ble_scan(ble_ctx_t *ctx, ble_scan_cb cb, void *arg);

/*
 * Start a scan with explicit scan/discovery parameters and result filters
 * (the common discovery-filter model + NimBLE ble_gap_disc_params).  Pass params==NULL
 * for the ble_scan() defaults.  Returns -1 if a scan is already in progress or
 * the parameters are invalid.
 */
int	ble_scan_filtered(ble_ctx_t *ctx, const ble_scan_params_t *params,
	    ble_scan_cb cb, void *arg);

/*
 * Connect to a device.
 * Returns -1 if a connect is already in progress.
 */
int	ble_connect(ble_ctx_t *ctx, const ble_addr_t *addr,
	    ble_connect_cb cb, void *arg);

/*
 * Connect with explicit initial connection parameters and/or PHY preference.
 * Pass params==NULL for the daemon defaults (equivalent to ble_connect()).
 * Returns -1 if a connect is already in progress or params are invalid.
 */
int	ble_connect_params(ble_ctx_t *ctx, const ble_addr_t *addr,
	    const ble_conn_params_t *params, ble_connect_cb cb, void *arg);

/*
 * Connect to a device by name.
 * Scans for a device matching the name, then connects.
 * Returns -1 if a connect is already in progress.
 */
int	ble_connect_name(ble_ctx_t *ctx, uint8_t adapter_index, const char *name,
	    ble_connect_cb cb, void *arg);

/* Disconnect a device. */
int	ble_disconnect(ble_ctx_t *ctx, const ble_addr_t *addr);

/*
 * Pairing / bond management
 */

/* Initiate or check SMP pairing for a connected device. */
int	ble_pair(ble_ctx_t *ctx, const ble_addr_t *addr);

/*
 * Re-pair a bonded, central-role peer in place to rotate its keys (BLE has no
 * in-place rekey; this drives a controlled re-bond, Core Spec Vol 3 Part H
 * §2.4).  The peer must already be bonded and connected.  Maps to the REKEY
 * verb.
 */
int	ble_rekey(ble_ctx_t *ctx, const ble_addr_t *addr);

/* List all bonded devices.  Returns count, fills bonds up to max_bonds. */
int	ble_bond_list(ble_ctx_t *ctx, ble_bond_t *bonds, int max_bonds);

/* Return a typed snapshot of active and pending LE connections. */
int	ble_connections(ble_ctx_t *ctx, ble_connection_info_t *connections,
	    int max_connections);

/* Remove a bond for the given address. */
int	ble_unbond(ble_ctx_t *ctx, const ble_addr_t *addr);

/*
 * Bond backup / restore / migration (PC4).  Privileged-tier (uid 0) only.
 *
 * ble_bond_export() returns a newly-allocated opaque record for one identity,
 * or NULL on error (see ble_error()); free it with ble_bond_record_free().
 * ble_bond_import() re-inserts a record into the daemon's live bond DB
 * (replace-by-identity or append), returning 0 on success or -1 on error.
 * ble_bond_record_data() exposes the serialized bytes for protected storage;
 * ble_bond_record_from_data() rebuilds a record from saved bytes.
 * SECURITY: the record carries raw keys -- keep it secret.
 */
ble_bond_record_t *ble_bond_export(ble_ctx_t *ctx, const ble_addr_t *addr);
int	ble_bond_import(ble_ctx_t *ctx, const ble_bond_record_t *rec);
const void *ble_bond_record_data(const ble_bond_record_t *rec, size_t *len);
ble_bond_record_t *ble_bond_record_from_data(const void *data, size_t len);
void	ble_bond_record_free(ble_bond_record_t *rec);

/*
 * PHY management
 */

/*
 * Request a PHY change on a live connection (LE Set PHY).  tx_phys/rx_phys are
 * BLE_PHY_MASK_* bit masks; a zero mask means "no preference".
 */
int	ble_set_phy(ble_ctx_t *ctx, const ble_addr_t *addr, uint8_t tx_phys,
	    uint8_t rx_phys);

/*
 * Suggest the connection's maximum LL data PDU size (LE Set Data Length).
 * tx_octets 27-251, tx_time 328-17040 microseconds-units per the spec.
 */
int	ble_set_data_length(ble_ctx_t *ctx, const ble_addr_t *addr,
	    uint16_t tx_octets, uint16_t tx_time);

/*
 * Connection parameter queries
 */

/*
 * Request an LE Connection Update on a live connection.  interval_* in units of
 * 1.25 ms, timeout in units of 10 ms, latency in connection events.  Honoured
 * only when the controller supports the Connection Parameters Request
 * procedure; otherwise the daemon returns an error.
 */
int	ble_conn_params_update(ble_ctx_t *ctx, const ble_addr_t *addr,
	    uint16_t interval_min, uint16_t interval_max, uint16_t latency,
	    uint16_t timeout);

/* Get RSSI of last scan result for an address (-127 if unavailable). */
int	ble_get_rssi(ble_ctx_t *ctx, const ble_addr_t *addr);

/*
 * Central mode — GATT operations
 */

/*
 * Discover all services and characteristics on a connected device.
 * The callback fires once with all accumulated results when END
 * is received.  On error, the callback fires with nsvc=0, nchar=0.
 */
int	ble_discover(ble_ctx_t *ctx, const ble_addr_t *addr,
	    ble_discover_cb cb, void *arg);

/* Read a characteristic value. */
int	ble_read(ble_ctx_t *ctx, const ble_addr_t *addr,
	    uint16_t handle, ble_read_cb cb, void *arg);

/*
 * Write a characteristic value (with response).
 * Note: the underlying send is blocking.  If the daemon's receive
 * buffer is full, this call will block until space is available.
 */
int	ble_write(ble_ctx_t *ctx, const ble_addr_t *addr,
	    uint16_t handle, const uint8_t *value, uint16_t len);

/*
 * Write a value to a characteristic without waiting for a response.
 * Uses ATT Write Command (no acknowledgment from the peer).
 * Suitable for low-latency writes where reliability is not required.
 */
int	ble_write_no_response(ble_ctx_t *ctx, const ble_addr_t *addr,
	    uint16_t handle, const void *value, uint16_t len);

/*
 * Subscribe to notifications for a characteristic.
 *
 * Each call registers a per-handle callback (up to 16 handles).
 * When a notification arrives, the per-handle callback is invoked if
 * one was registered for that handle; otherwise the most recently set
 * global callback is used as a fallback.  When the per-handle table
 * is full, the callback is installed as the global fallback instead.
 */
int	ble_subscribe(ble_ctx_t *ctx, const ble_addr_t *addr,
	    uint16_t handle, ble_notify_cb cb, void *arg);

/* Unsubscribe from notifications. */
int	ble_unsubscribe(ble_ctx_t *ctx, const ble_addr_t *addr,
	    uint16_t handle);

/*
 * Peripheral mode — GATT server
 */

/* Add a service to the local GATT database. */
int	ble_add_service(ble_ctx_t *ctx, const ble_uuid_t *uuid,
	    uint16_t *out_handle);

/* Add a characteristic to a service. */
int	ble_add_characteristic(ble_ctx_t *ctx, uint16_t svc_handle,
	    const ble_uuid_t *uuid, uint8_t props, uint8_t perms,
	    const uint8_t *value, uint16_t len, uint16_t *out_handle);

/* Add an included-service declaration to a service. */
int	ble_add_include(ble_ctx_t *ctx, uint16_t svc_handle,
	    uint16_t included_start, uint16_t included_end, uint16_t uuid16,
	    uint16_t *out_handle);

/* Add a descriptor to the most recently added local characteristic. */
int	ble_add_descriptor(ble_ctx_t *ctx, uint16_t char_handle,
	    const ble_uuid_t *uuid, uint8_t perms,
	    const uint8_t *value, uint16_t len, uint16_t *out_handle);

/* Update a local attribute value. */
int	ble_set_value(ble_ctx_t *ctx, uint16_t handle,
	    const uint8_t *value, uint16_t len);

/* Send a server-side notification/indication to subscribed peers. */
int	ble_notify(ble_ctx_t *ctx, uint16_t handle,
	    const uint8_t *value, uint16_t len);
int	ble_indicate(ble_ctx_t *ctx, uint16_t handle,
	    const uint8_t *value, uint16_t len);

/* Remove a service and all its attributes. */
int	ble_remove_service(ble_ctx_t *ctx, uint16_t handle);

/*
 * Atomic GATT-application registration (the common atomic GATT-application registration)
 *
 * ble_gatt_begin() opens a staged build: subsequent ble_add_service() /
 * ble_add_characteristic() / ble_add_descriptor() / ble_remove_service() calls
 * on this connection stage into a scratch database instead of mutating the
 * live one, so peers do not see a partially-built application.
 * ble_gatt_commit() atomically swaps the whole staged application into the
 * live database (a single Database-Hash recompute).
 * ble_gatt_rollback() discards the staged build, leaving the live
 * database untouched; a staging error also auto-rolls-back.  Outside a
 * transaction the same add/remove helpers mutate the live database immediately
 * (unchanged behaviour).  A privileged connection is required.
 */
int	ble_gatt_begin(ble_ctx_t *ctx);
int	ble_gatt_commit(ble_ctx_t *ctx);
int	ble_gatt_rollback(ble_ctx_t *ctx);

/* Register a callback for remote write requests. */
void	ble_on_write(ble_ctx_t *ctx, ble_write_req_cb cb, void *arg);

/*
 * Dynamic reads and per-access authorization for app-backed characteristics.
 *
 * Add a characteristic with BLE_CHAR_F_DYNAMIC and/or BLE_CHAR_F_AUTHORIZE
 * (ble_add_char_ex) to have the daemon defer each peer read/write to the app.
 * Register the callbacks below to receive the requests, and answer with the
 * reply helpers.  A read reply must arrive within the ATT transaction timeout
 * or the peer receives an error.
 */
#define BLE_CHAR_F_DYNAMIC	0x01	/* value supplied on demand per read */
#define BLE_CHAR_F_AUTHORIZE	0x02	/* each read/write authorized by app */

void	ble_on_read_request(ble_ctx_t *ctx, ble_read_req_cb cb, void *arg);
void	ble_on_authorize(ble_ctx_t *ctx, ble_authorize_cb cb, void *arg);

/* Add a characteristic with app-backing flags (BLE_CHAR_F_*). */
int	ble_add_char_ex(ble_ctx_t *ctx, uint16_t svc_handle,
	    const ble_uuid_t *uuid, uint8_t props, uint8_t perms,
	    const uint8_t *value, uint16_t len, uint8_t flags,
	    uint16_t *out_handle);

/* Supply the value for a deferred dynamic read (EVENT READ). */
int	ble_gatt_read_reply(ble_ctx_t *ctx, uint16_t handle,
	    const uint8_t *value, uint16_t len);

/* Decline a deferred dynamic read with an ATT error code (e.g. 0x0E). */
int	ble_gatt_read_reject(ble_ctx_t *ctx, uint16_t handle,
	    uint8_t att_error);

/* Allow or deny a deferred access (EVENT AUTHORIZE). */
int	ble_gatt_authorize_reply(ble_ctx_t *ctx, uint16_t handle, bool allow);

/*
 * Pairing
 */

/* Reply to a passkey input request. */
int	ble_passkey_reply(ble_ctx_t *ctx, const ble_addr_t *addr,
	    uint32_t passkey);

/* Reply to a numeric comparison request. */
int	ble_numcmp_reply(ble_ctx_t *ctx, const ble_addr_t *addr,
	    bool accept);

/* Register pairing event callbacks. */
void	ble_on_passkey_display(ble_ctx_t *ctx,
	    ble_passkey_display_cb cb, void *arg);
void	ble_on_passkey_input(ble_ctx_t *ctx,
	    ble_passkey_input_cb cb, void *arg);
void	ble_on_numcmp(ble_ctx_t *ctx, ble_numcmp_cb cb, void *arg);

/*
 * Pairing agent (the common pairing-agent model)
 *
 * IO capability declared when registering as the pairing agent; selects the
 * pairing association model together with the peer's capability (Core Spec
 * Vol 3 Part H §2.3.5.1).
 */
typedef enum {
	BLE_IO_DISPLAY_ONLY = 0,
	BLE_IO_DISPLAY_YESNO = 1,
	BLE_IO_KEYBOARD_ONLY = 2,
	BLE_IO_NO_INPUT_NO_OUTPUT = 3,
	BLE_IO_KEYBOARD_DISPLAY = 4,
} ble_io_cap_t;

/*
 * Register this client as THE runtime pairing agent with the given IO
 * capability.  While registered, every pairing prompt routes to this client
 * (answer via ble_passkey_reply()/ble_numcmp_reply(), delivered through the
 * ble_on_passkey_display/input and ble_on_numcmp callbacks) and this IO
 * capability overrides the daemon static config for the association-model
 * choice (Core Spec Vol 3 Part H §2.3.5.1).  Requires the
 * push-events feature (negotiated automatically by ble_open).  A privileged
 * connection is required.  ble_unregister_agent() restores the static config.
 */
int	ble_register_agent(ble_ctx_t *ctx, ble_io_cap_t io_cap);
int	ble_unregister_agent(ble_ctx_t *ctx);

/*
 * Connection lifecycle push events (findings C1/C2/C5).  Register callbacks
 * fired when the daemon reports a device truly connected / disconnected.
 */
void	ble_on_connected(ble_ctx_t *ctx, ble_conn_event_cb cb, void *arg);
void	ble_on_disconnected(ble_ctx_t *ctx, ble_disconn_event_cb cb, void *arg);

/*
 * Peripheral advertising control (finding C10).  Requires the daemon to have
 * been started in peripheral mode.  Enable/disable advertising, and set the
 * advertising / scan-response payloads (<= 31 bytes each).
 */
int	ble_advertise(ble_ctx_t *ctx, bool enable);

/*
 * Configure the advertising set's parameters (mode/type/interval/channels/TX
 * power/own-address/PHY/directed peer).  Does not enable advertising; call
 * ble_advertise(ctx, true) afterwards.  Returns -1 on invalid parameters.
 */
int	ble_set_adv_params(ble_ctx_t *ctx, const ble_adv_params_t *params);

/*
 * Adapter runtime settings (parity with the common adapter power / discoverable /
 * pairable / alias controls).  Each returns 0 on success, -1 on invalid argument or I/O
 * error (privileged; the daemon replies BLE_ERR_PERM to an unprivileged peer).
 *
 * ble_adapter_power:      power the addressed adapter up/down (idx < 0 => primary).
 * ble_set_discoverable:   general/limited discoverable advertising, timeout=0 for
 *                         no auto-off.
 * ble_set_pairable:       gate whether incoming pairing is accepted.
 * ble_set_name:           set the GAP device name (0x2A00) + advertising name.
 */
int	ble_adapter_power(ble_ctx_t *ctx, int adapter_idx, bool on);
int	ble_status(ble_ctx_t *ctx, ble_status_t *out);
int	ble_adapter_caps(ble_ctx_t *ctx, int adapter_idx,
	    ble_adapter_caps_t *out);
int	ble_set_discoverable(ble_ctx_t *ctx, bool enable, unsigned int timeout,
	    bool limited);
int	ble_set_pairable(ble_ctx_t *ctx, bool enable);
int	ble_set_name(ble_ctx_t *ctx, const char *name);
int	ble_set_adv_data(ble_ctx_t *ctx, const uint8_t *data, uint16_t len);
int	ble_set_scan_response(ble_ctx_t *ctx, const uint8_t *data,
	    uint16_t len);

/*
 * Owned extended-advertising sets.  Handle zero remains reserved for the
 * primary advertising API.  The set owns its daemon allocation until
 * ble_adv_set_close(); ctx must outlive every set created from it.
 */
typedef struct ble_adv_set ble_adv_set_t;
int	ble_adv_set_create(ble_ctx_t *ctx, ble_adv_set_t **out);
/*
 * Wrap an advertising-set handle the daemon already owns (e.g. one printed by
 * a previous `adv-set-create`) so a fresh client process can drive
 * ble_adv_set_params/data/enable on it without re-creating it.  Free the
 * wrapper with ble_adv_set_free() (which does NOT remove the daemon set) or
 * ble_adv_set_close() (which removes it).
 */
int	ble_adv_set_open(ble_ctx_t *ctx, uint8_t handle, ble_adv_set_t **out);
void	ble_adv_set_free(ble_adv_set_t *set);
uint8_t ble_adv_set_handle(const ble_adv_set_t *set);
int	ble_adv_set_params(ble_adv_set_t *set, uint16_t event_properties,
	    uint32_t interval_min, uint32_t interval_max, uint8_t primary_phy,
	    uint8_t secondary_phy);
int	ble_adv_set_data(ble_adv_set_t *set, const uint8_t *data, uint8_t len);
int	ble_adv_set_enable(ble_adv_set_t *set, bool enable);
void	ble_adv_set_close(ble_adv_set_t *set);

/*
 * Optional Core 5.0 periodic advertising/synchronization.  These functions
 * use advertising set zero; callers must first verify BLE_LE_FEAT_PERIODIC_ADV
 * with ble_adapter_caps().  No LE Audio profile is implied by this transport.
 */
int	ble_periodic_adv_params(ble_ctx_t *ctx, uint8_t adapter_index,
	    uint16_t interval_min, uint16_t interval_max, uint16_t properties);
int	ble_periodic_adv_data(ble_ctx_t *ctx, uint8_t adapter_index,
	    const uint8_t *data, uint8_t len);
int	ble_periodic_adv_enable(ble_ctx_t *ctx, uint8_t adapter_index,
	    bool enable);
int	ble_periodic_sync_create(ble_ctx_t *ctx, const ble_addr_t *addr,
	    uint8_t sid, uint16_t skip, uint16_t timeout);
int	ble_periodic_sync_cancel(ble_ctx_t *ctx, uint8_t adapter_index);
int	ble_periodic_sync_terminate(ble_ctx_t *ctx, uint8_t adapter_index,
	    uint16_t sync_handle);
int	ble_periodic_adv_list_add(ble_ctx_t *ctx, const ble_addr_t *addr,
	    uint8_t sid);
int	ble_periodic_adv_list_remove(ble_ctx_t *ctx, const ble_addr_t *addr,
	    uint8_t sid);
int	ble_periodic_adv_list_clear(ble_ctx_t *ctx, uint8_t adapter_index);
int	ble_periodic_adv_list_size(ble_ctx_t *ctx, uint8_t adapter_index,
	    uint8_t *size);

/* Core 5.1 Periodic Advertising Sync Transfer (PAST).  Sender and recipient
 * roles are independent controller capabilities; check the corresponding
 * BLE_LE_FEAT_PAST_* bit before issuing either operation. */
int	ble_past_transfer(ble_ctx_t *ctx, const ble_addr_t *peer,
    uint16_t service_data, uint16_t sync_handle);
int	ble_past_receive_enable(ble_ctx_t *ctx, uint8_t adapter_index,
	    uint16_t sync_handle, bool enable);
int	ble_past_set_info_transfer(ble_ctx_t *ctx, const ble_addr_t *peer,
	    uint16_t service_data, uint8_t adv_handle);
int	ble_past_params(ble_ctx_t *ctx, const ble_addr_t *peer, uint8_t mode,
	    uint16_t skip, uint16_t timeout, uint8_t cte_type);
int	ble_past_default_params(ble_ctx_t *ctx, uint8_t adapter_index,
	    uint8_t mode, uint16_t skip, uint16_t timeout, uint8_t cte_type);
/* Core 5.2 path-loss monitoring only; TX-power reporting remains internal. */
int	ble_path_loss_reporting(ble_ctx_t *ctx, const ble_addr_t *addr,
    uint8_t low, uint8_t low_hysteresis, uint8_t high,
    uint8_t high_hysteresis, uint16_t min_time, bool enable);

/*
 * Runtime LE privacy control (parity with the common adapter privacy control).  Enable or
 * disable Resolvable Private Addresses across advertising/scanning/connecting.
 */
int	ble_set_privacy(ble_ctx_t *ctx, bool on);

/*
 * Set the preferred ATT MTU requested in the Exchange MTU procedure on
 * subsequent connections (parity with the common preferred-MTU control).  Bounded to
 * [23, 517]; returns -1 on an out-of-range value.
 */
int	ble_set_preferred_mtu(ble_ctx_t *ctx, uint16_t mtu);

/*
 * Runtime SMP security / pairing policy (de-hardcoded parity with NimBLE
 * ble_hs_cfg.sm_* and the common Bondable / SecureConnections / KeySize
 * controls).  Every field also has a config-file default seeded to today's
 * behaviour, so nothing changes unless a policy is set here.
 *
 * LE Secure Connections mode (mirrors the common SecureConnections tri-state):
 *   BLE_SC_OFF  advertise legacy only
 *   BLE_SC_ON   advertise SC, allow legacy fallback (the historical default)
 *   BLE_SC_ONLY advertise SC and reject legacy pairing
 *
 * Minimum pairing security floor (LE Mode 1, Core Spec Vol 3 Part C §10.2.1):
 *   BLE_SEC_NONE / BLE_SEC_ENC / BLE_SEC_AUTH / BLE_SEC_SC.
 */
typedef enum {
	BLE_SC_OFF = 0,
	BLE_SC_ON = 1,
	BLE_SC_ONLY = 2,
} ble_sc_mode_t;

typedef enum {
	BLE_SEC_NONE = 0,
	BLE_SEC_ENC = 1,
	BLE_SEC_AUTH = 2,
	BLE_SEC_SC = 3,
} ble_sec_level_t;

/* Key-distribution flags (Core Spec Vol 3 Part H §3.6.1). */
#define BLE_KEY_DIST_ENC	0x01	/* LTK / EDIV / Rand */
#define BLE_KEY_DIST_ID		0x02	/* IRK + identity address */
#define BLE_KEY_DIST_SIGN	0x04	/* CSRK */

typedef struct {
	bool		mitm;		/* require MITM-authenticated pairing */
	bool		bonding;	/* request bonding (persist keys) */
	ble_sc_mode_t	sc_mode;	/* LE Secure Connections mode */
	bool		keypress;	/* advertise Keypress Notifications */
	ble_io_cap_t	io_cap;		/* IO capability */
	ble_sec_level_t	min_security;	/* pairing floor */
	uint8_t		min_key_size;	/* minimum encryption key size (7-16) */
	uint8_t		key_dist;	/* BLE_KEY_DIST_* mask */
	int		rpa_timeout;	/* RPA rotation timeout (informational) */
} ble_security_policy_t;

/*
 * Apply a full security policy in one call, or read the daemon's current
 * policy.  ble_set_security_policy sends every field; the granular helpers set
 * exactly one knob.  All are privileged (the daemon replies BLE_ERR_PERM to an
 * unprivileged peer).  Return 0 on success, -1 on error.
 */
int	ble_set_security_policy(ble_ctx_t *ctx,
	    const ble_security_policy_t *pol);
int	ble_get_security_policy(ble_ctx_t *ctx, ble_security_policy_t *out);
int	ble_set_mitm(ble_ctx_t *ctx, bool require_mitm);
int	ble_set_bondable(ble_ctx_t *ctx, bool bondable);
int	ble_set_sc_mode(ble_ctx_t *ctx, ble_sc_mode_t mode);
int	ble_set_keypress(ble_ctx_t *ctx, bool enable);
int	ble_set_io_capability(ble_ctx_t *ctx, ble_io_cap_t io_cap);
int	ble_set_min_security(ble_ctx_t *ctx, ble_sec_level_t level);
int	ble_set_min_key_size(ble_ctx_t *ctx, uint8_t key_size);
int	ble_set_key_distribution(ble_ctx_t *ctx, uint8_t key_dist);

/* Set the resolvable-private-address rotation timeout (1..3600s). */
int	ble_set_rpa_timeout(ble_ctx_t *ctx, unsigned int seconds);

/*
 * Structured per-connection security query.  Fills
 * the negotiated encryption key size, LE security level (1-4), authentication
 * tier, and bond flags for the addressed connection.  Returns 0 on success, -1
 * if the address is not connected or on error.
 */
typedef struct {
	ble_addr_t	addr;
	uint8_t		key_size;	/* negotiated encryption key size */
	uint8_t		level;		/* LE Mode 1 level 1-4 */
	bool		encrypted;
	bool		authenticated;	/* MITM-authenticated */
	bool		secure_connections;
	bool		bonded;
} ble_security_info_t;

int	ble_get_security_info(ble_ctx_t *ctx, const ble_addr_t *addr,
	    ble_security_info_t *out);

/*
 * OOB pairing data (Core Spec Vol 3 Part H §2.3.5.6.4; NimBLE ble_sm_inject_io
 * / sc_oob_generate analogues).  The OOB engine was wired but unexposed.
 *
 * ble_oob_sc_generate: generate local LE Secure Connections OOB {confirm,
 *   random} plus our public-key x-coordinate, to publish to the peer via an
 *   out-of-band channel; the daemon ties it to the next SC pairing.
 * ble_oob_inject_sc / ble_oob_inject_legacy: supply the peer's OOB data,
 *   consumed by the next pairing with that peer.
 * ble_oob_clear: drop pending OOB (this peer, or all peers if addr is NULL).
 */
typedef struct {
	uint8_t		confirm[16];
	uint8_t		random[16];
	uint8_t		pkx[32];	/* our public-key x-coordinate (LE) */
} ble_oob_sc_t;

int	ble_oob_sc_generate(ble_ctx_t *ctx, ble_oob_sc_t *out);
int	ble_oob_inject_sc(ble_ctx_t *ctx, const ble_addr_t *addr,
	    const uint8_t confirm[16], const uint8_t random[16]);
int	ble_oob_inject_legacy(ble_ctx_t *ctx, const ble_addr_t *addr,
	    const uint8_t tk[16]);
int	ble_oob_clear(ble_ctx_t *ctx, const ble_addr_t *addr);

/*
 * LE privacy resolving-list management (parity with the common resolving-list
 * controls; hci_privacy add/remove were previously bond-driven only).
 *
 * ble_resolv_add: program a peer identity + IRK into the controller resolving
 *   list.  If irk is NULL the daemon uses the peer's bonded IRK.
 * ble_resolv_remove / ble_resolv_clear: drop one / all entries.
 * ble_resolv_entries: return a structured resolving-list snapshot.
 */
int	ble_resolv_add(ble_ctx_t *ctx, const ble_addr_t *addr,
	    const uint8_t irk[16]);
int	ble_resolv_remove(ble_ctx_t *ctx, const ble_addr_t *addr);
int	ble_resolv_clear(ble_ctx_t *ctx);
int	ble_resolv_entries(ble_ctx_t *ctx, ble_resolv_entry_t *entries,
	    int max_entries);

/*
 * Controller Filter Accept List management (finding 135).  Add/remove/list/
 * clear the operator-managed (non-bond) accept-list entries.  ble_acceptlist_add
 * and _remove program every powered adapter; _clear drops only the runtime
 * entries; _entries returns a snapshot of the runtime entries.
 */
int	ble_acceptlist_add(ble_ctx_t *ctx, const ble_addr_t *addr);
int	ble_acceptlist_remove(ble_ctx_t *ctx, const ble_addr_t *addr);
int	ble_acceptlist_clear(ble_ctx_t *ctx);
int	ble_acceptlist_entries(ble_ctx_t *ctx, ble_addr_t *entries,
	    int max_entries);

/*
 * Inbound Keypress Notification callback (Core Spec Vol 3 Part H §3.5.8).
 * Fires for each keypress the peer sends during Passkey Entry; 'type' is one of
 * the BLE_KEYPRESS_* codes.  Requires the push-events feature.
 */
#define BLE_KEYPRESS_STARTED		0
#define BLE_KEYPRESS_DIGIT_ENTERED	1
#define BLE_KEYPRESS_DIGIT_ERASED	2
#define BLE_KEYPRESS_CLEARED		3
#define BLE_KEYPRESS_COMPLETED		4

typedef void (*ble_keypress_cb)(const ble_addr_t *addr, uint8_t type,
	    void *arg);
void	ble_on_keypress(ble_ctx_t *ctx, ble_keypress_cb cb, void *arg);

/*
 * Capability broker (fd-passing)
 *
 * Acquire a direct, capability-scoped data socket from the daemon and leave
 * the daemon out of the data path.  The returned fd is a connected socket the
 * caller owns outright; the daemon narrows it to send/recv/poll only
 * (CAP_SEND|CAP_RECV|CAP_EVENT) with a one-shot transfer limit, so it cannot
 * be re-passed or widened.  Both require the "fd-passing" feature (negotiated
 * automatically at ble_open) and a privileged peer; otherwise they fail with
 * BLE_ERR_PERM.  Return 0 and store the fd in *out_fd on success, -1 on error.
 */
int	ble_acquire_coc(ble_ctx_t *ctx, const ble_addr_t *addr, uint16_t psm,
	    int *out_fd);

/*
 * Enhanced Credit Based Flow Control session.  The session owns every fd
 * returned by ACQUIRE_COC until ble_ecbfc_session_take_fd() transfers one to
 * the caller or ble_ecbfc_session_close() closes the remaining descriptors.
 * ble_ecbfc_session_fd() is borrowed and must not be closed by the caller.
 */
typedef struct ble_ecbfc_session ble_ecbfc_session_t;
int	ble_ecbfc_session_open(ble_ctx_t *ctx, const ble_addr_t *addr,
	    uint16_t psm, unsigned count, ble_ecbfc_session_t **out);
unsigned ble_ecbfc_session_count(const ble_ecbfc_session_t *session);
int	ble_ecbfc_session_fd(const ble_ecbfc_session_t *session,
	    unsigned channel);
int	ble_ecbfc_session_take_fd(ble_ecbfc_session_t *session,
	    unsigned channel);
uint16_t ble_ecbfc_session_omtu(const ble_ecbfc_session_t *session,
	    unsigned channel);
int	ble_ecbfc_session_reconfigure(ble_ctx_t *ctx,
	    ble_ecbfc_session_t *session, uint16_t mtu, uint16_t mps);
void	ble_ecbfc_session_close(ble_ecbfc_session_t *session);
/* EATT bearers remain daemon-owned and are closed with the LE connection. */
int	ble_eatt_open(ble_ctx_t *ctx, const ble_addr_t *addr, unsigned count);
int	ble_eatt_close(ble_ctx_t *ctx, const ble_addr_t *addr);
int	ble_acquire_iso(ble_ctx_t *ctx, const ble_addr_t *addr,
	    uint16_t cis_handle, int *out_fd);

/*
 * Per-characteristic GATT data-path acquire (the common GATT-characteristic
 * AcquireNotify / AcquireWrite pattern; Core Spec Vol 3 Part G notify/write).  Same
 * capability scoping and fd-passing/privilege gate as the broker acquires
 * above, over a SOCK_SEQPACKET fd (one datagram per notification / per write).
 *
 * ble_acquire_notify: subscribe to <handle> on the connected peer and receive
 * each notification/indication value as one datagram on *out_fd; the negotiated
 * ATT MTU is stored in *out_mtu (like the common AcquireNotify returning fd + MTU).
 * ble_acquire_write: each datagram written to *out_fd becomes an ATT
 * Write-Without-Response PDU to <handle>, bounded to the ATT MTU.
 * Return 0 and store the fd on success, -1 with ble_errno() set otherwise.
 */
int	ble_acquire_notify(ble_ctx_t *ctx, const ble_addr_t *addr,
	    uint16_t handle, int *out_fd, uint16_t *out_mtu);
int	ble_acquire_write(ble_ctx_t *ctx, const ble_addr_t *addr,
	    uint16_t handle, int *out_fd);

/*
 * LE Isochronous (ISO) streams — CIS (connected, unicast) and BIS (broadcast).
 *
 * A stream is SET UP with one of the create operations, which return once the
 * HCI request is issued; establishment is asynchronous and reported via
 * the event callbacks below (mirroring ble_connect / EVENT CONNECTED).  Once a
 * stream is established the data-path socket is ACQUIRED with ble_iso_acquire /
 * ble_iso_bis_acquire — a capability-scoped SOCK_SEQPACKET fd the caller owns
 * outright, over which each write()/read() carries exactly one ISO SDU.  The
 * Max_Transport_Latency knobs are first-class QoS parameters (kept for the
 * future LE-Audio transport).  Core Spec 6.x Vol 4 Part E §7.8.97-.111.
 */

/* Opaque data-path handle wrapping the SEQPACKET ISO socket fd. */
typedef struct ble_iso_stream ble_iso_stream_t;

typedef struct {
	uint8_t  cig_id;
	uint32_t sdu_interval_c_us, sdu_interval_p_us;
	uint8_t  sca, packing, framing;
	uint16_t max_transport_latency_c_ms, max_transport_latency_p_ms;
	int      num_cis;
	struct {
		uint8_t  cis_id;
		uint16_t max_sdu_c, max_sdu_p;
		uint8_t  phy_c, phy_p, rtn_c, rtn_p;
	} cis[8];
} ble_cig_params_t;

typedef struct {
	uint8_t  big_handle, adv_handle, num_bis;
	uint32_t sdu_interval_us;
	uint16_t max_sdu, max_transport_latency_ms;
	uint8_t  rtn, phy, packing, framing, encryption;
	uint8_t  broadcast_code[16];
} ble_big_params_t;

/* EVENT ISO_CIS_REQUEST <addr> cis=0x<h> cig=<id> cis_id=<id> (peripheral). */
typedef void (*ble_iso_cis_req_cb)(const ble_addr_t *addr, uint16_t cis_handle,
	    uint8_t cig_id, uint8_t cis_id, void *arg);
/* EVENT ISO_ESTABLISHED <addr> cis=0x<h> mtu=<n>. */
typedef void (*ble_iso_est_cb)(const ble_addr_t *addr, uint16_t cis_handle,
	    uint16_t mtu, void *arg);

/* Central / CIS. */
int	ble_iso_cig_create(ble_ctx_t *ctx, uint8_t adapter_index,
	    const ble_cig_params_t *params, uint16_t *out_cis_handles, int max);
int	ble_iso_cis_create(ble_ctx_t *ctx, const ble_addr_t *peer,
	    uint8_t cig_id, uint8_t cis_id);
int	ble_iso_cis_teardown(ble_ctx_t *ctx, uint8_t adapter_index,
	    uint16_t cis_handle);
int	ble_iso_cig_remove(ble_ctx_t *ctx, uint8_t adapter_index,
	    uint8_t cig_id);

/* Peripheral / CIS. */
int	ble_iso_cis_accept(ble_ctx_t *ctx, uint8_t adapter_index,
	    uint16_t cis_handle);
int	ble_iso_cis_reject(ble_ctx_t *ctx, uint8_t adapter_index,
	    uint16_t cis_handle, uint8_t reason);
void	ble_on_iso_cis_request(ble_ctx_t *ctx, ble_iso_cis_req_cb cb, void *arg);

/* Broadcaster / BIS source. */
int	ble_iso_big_create(ble_ctx_t *ctx, uint8_t adapter_index,
	    const ble_big_params_t *params);
int	ble_iso_big_terminate(ble_ctx_t *ctx, uint8_t adapter_index,
	    uint8_t big_handle, uint8_t reason);

/* Sync / BIS sink. */
int	ble_iso_big_create_sync(ble_ctx_t *ctx, uint8_t adapter_index,
	    uint8_t big_handle,
	    uint16_t sync_handle, const uint8_t *bis_indices, int num_bis,
	    uint8_t mse, uint16_t timeout, const uint8_t broadcast_code[16]);
int	ble_iso_big_terminate_sync(ble_ctx_t *ctx, uint8_t adapter_index,
	    uint8_t big_handle);

/* fd handout — the returned stream owns a capability-scoped SEQPACKET fd. */
int	ble_iso_acquire(ble_ctx_t *ctx, uint8_t adapter_index,
	    uint16_t cis_handle, ble_iso_stream_t **out);
int	ble_iso_bis_acquire(ble_ctx_t *ctx, uint8_t adapter_index,
	    uint8_t big_handle, uint8_t bis_index, ble_iso_stream_t **out);

/* async establish notification (fires on EVENT ISO_ESTABLISHED). */
void	ble_on_iso_established(ble_ctx_t *ctx, ble_iso_est_cb cb, void *arg);

/* Data plane — the fd IS the SDU channel (one SDU per send/recv). */
int	ble_iso_fd(ble_iso_stream_t *s);
int	ble_iso_send(ble_iso_stream_t *s, const void *sdu, size_t len);
int	ble_iso_recv(ble_iso_stream_t *s, void *buf, size_t len);
void	ble_iso_close(ble_iso_stream_t *s);

/*
 * Convenience
 */

/* Read battery level (auto-discovers Battery Service). */
int	ble_read_battery(ble_ctx_t *ctx, const ble_addr_t *addr,
	    ble_read_cb cb, void *arg);

/* Format a ble_addr_t as "XX:XX:XX:XX:XX:XX". */
const char *ble_addr_str(const ble_addr_t *addr, char buf[18]);
int	ble_addr_parse(const char *text, uint8_t addr_type, ble_addr_t *out);

#endif /* _BLE_H_ */
