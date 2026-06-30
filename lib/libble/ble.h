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

/* Opaque library context */
typedef struct ble_ctx ble_ctx_t;

/* BLE device address */
typedef struct {
	uint8_t		addr[6];
	uint8_t		addr_type;	/* 0 = public, 1 = random */
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

/* Characteristic properties (matches GATT_PROP_*) */
#define	BLE_PROP_BROADCAST		0x01
#define	BLE_PROP_READ			0x02
#define	BLE_PROP_WRITE_NO_RSP		0x04
#define	BLE_PROP_WRITE			0x08
#define	BLE_PROP_NOTIFY			0x10
#define	BLE_PROP_INDICATE		0x20
#define	BLE_PROP_AUTH_SIGNED_WRITE	0x40
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
 * Callbacks — Pairing
 */
typedef void (*ble_passkey_display_cb)(const ble_addr_t *addr,
	    uint32_t passkey, void *arg);
typedef void (*ble_passkey_input_cb)(const ble_addr_t *addr, void *arg);
typedef void (*ble_numcmp_cb)(const ble_addr_t *addr,
	    uint32_t value, void *arg);

/*
 * Raw command callback — receive individual response lines.
 *
 * line:     the response line (no trailing newline)
 * terminal: true if this is a terminal line (OK, ERROR, END, STATUS)
 * status:   1 = success terminal (OK/END/STATUS)
 *          -1 = error terminal (ERROR)
 *           0 = non-terminal line
 */
typedef void (*ble_line_cb)(const char *line, bool terminal, int status,
	    void *arg);

/*
 * Lifecycle
 */

/* Open a connection to blued.  sock_path NULL uses default. */
ble_ctx_t	*ble_open(const char *sock_path);

/* Wrap an already-connected fd in a ble_ctx_t (for testing). */
ble_ctx_t	*ble_open_fd(int fd);

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
 * Raw command interface — send any protocol command and receive
 * response lines via a callback.  This is the escape hatch for
 * commands that don't have a typed ble_*() wrapper.
 *
 * The callback fires for each response line.  For non-streaming
 * commands, the callback is automatically cleared when a terminal
 * line arrives.
 *
 * flags: 0 for normal (one-shot), BLE_CMD_STREAMING for commands
 *        whose callback should persist past the first terminal
 *        (e.g., subscribe).
 */
#define	BLE_CMD_STREAMING	0x01

int	ble_command(ble_ctx_t *ctx, const char *cmd, ble_line_cb cb,
	    void *arg, int flags);

/*
 * Register a persistent callback for unsolicited lines (async
 * events like EVENT NOTIFY, EVENT PASSKEY_*) that arrive when
 * no ble_command() is pending.
 */
void	ble_on_line(ble_ctx_t *ctx, ble_line_cb cb, void *arg);

/*
 * Central mode — scanning and connection
 */

/*
 * Start a scan.  Results arrive via the callback.
 * Returns -1 if a scan is already in progress.
 */
int	ble_scan(ble_ctx_t *ctx, ble_scan_cb cb, void *arg);

/*
 * Connect to a device.
 * Returns -1 if a connect is already in progress.
 */
int	ble_connect(ble_ctx_t *ctx, const ble_addr_t *addr,
	    ble_connect_cb cb, void *arg);

/*
 * Connect to a device by name.
 * Scans for a device matching the name, then connects.
 * Returns -1 if a connect is already in progress.
 */
int	ble_connect_name(ble_ctx_t *ctx, const char *name,
	    ble_connect_cb cb, void *arg);

/* Disconnect a device. */
int	ble_disconnect(ble_ctx_t *ctx, const ble_addr_t *addr);

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

/* Subscribe to notifications for a characteristic. */
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

/* Update a local attribute value. */
int	ble_set_value(ble_ctx_t *ctx, uint16_t handle,
	    const uint8_t *value, uint16_t len);

/* Remove a service and all its attributes. */
int	ble_remove_service(ble_ctx_t *ctx, uint16_t handle);

/* Register a callback for remote write requests. */
void	ble_on_write(ble_ctx_t *ctx, ble_write_req_cb cb, void *arg);

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
 * Convenience
 */

/* Read battery level (auto-discovers Battery Service). */
int	ble_read_battery(ble_ctx_t *ctx, const ble_addr_t *addr,
	    ble_read_cb cb, void *arg);

/* Format a ble_addr_t as "XX:XX:XX:XX:XX:XX". */
const char *ble_addr_str(const ble_addr_t *addr, char buf[18]);

#endif /* _BLE_H_ */
