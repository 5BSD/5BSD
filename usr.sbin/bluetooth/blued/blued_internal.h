/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Internal shared declarations between blued split files.
 *
 * Not part of the public interface (blued.h); only included by
 * blued.c, blued_event.c, blued_central.c, blued_peripheral.c.
 */

#ifndef _BLUED_INTERNAL_H_
#define _BLUED_INTERNAL_H_

#include "hogp_boot.h"

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/un.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libservice.h>
#include <libutil.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <syslog.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef USE_BSM_AUDIT
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_kevents.h>
#endif

#include <dev/hid/vhid.h>

#include "att.h"
#include "att_server.h"
#include "blued.h"
#include "blued_probes.h"
#include "hci_log.h"
#include "ble_util.h"
#include "config.h"
#include "conn.h"
#include "ctl.h"
#include "gatt.h"
#include "hci_util.h"
#include "smp.h"

/* ATT transaction timeout: 30 seconds (Core Spec Vol 3 Part F 3.3.3) */
#define ATT_TIMEOUT_SEC		30

/*
 * Monotonic timer ident counter for kqueue EVFILT_TIMER.
 * Avoids pointer-to-int truncation on 64-bit (which could cause
 * timer ident collisions between connections).  Each connection
 * timer gets a unique ident by incrementing this counter.
 * Separate ranges for reconnect, idle, and indication timers
 * are achieved by using different base offsets.
 */
extern _Atomic uintptr_t blued_next_timer_id;
extern uintptr_t blued_rpa_retry_timer;

/* Idle connection timeout: disconnect peers that send no ATT PDUs for 5 min */
#define BLUED_IDLE_TIMEOUT_SEC	300

/* Kqueue udata tags (file-scoped sentinel addresses) */
extern const int _blued_kq_ind_timeout_tag;
#define BLUED_KQ_IND_TIMEOUT	((void *)(uintptr_t)&_blued_kq_ind_timeout_tag)

extern const int _blued_kq_vhid_output_tag;
#define BLUED_KQ_VHID_OUTPUT	((void *)(uintptr_t)&_blued_kq_vhid_output_tag)

extern const int _blued_kq_idle_timeout_tag;
#define BLUED_KQ_IDLE_TIMEOUT	((void *)(uintptr_t)&_blued_kq_idle_timeout_tag)

/* Re-advertise retry: arm a 1-second oneshot timer on HCI failure */
#define BLUED_READVERTISE_MAX_RETRIES	3
extern const int _blued_kq_readvertise_tag;
#define BLUED_KQ_READVERTISE	((void *)(uintptr_t)&_blued_kq_readvertise_tag)

/*
 * Connection handle poll: after ATT connect(), the kernel needs time to
 * populate its connection table.  We poll with exponential backoff
 * (50ms, 100ms, 200ms, 400ms, 800ms) for up to 5 retries.
 */
#define CON_HANDLE_POLL_INIT_USEC	50000	/* 50ms initial */
#define CON_HANDLE_POLL_RETRIES		5

/* GAP/GATT Service UUIDs */
#define UUID_GAP_SERVICE		0x1800
#define UUID_DEVICE_NAME		0x2A00

/*
 * Upper bound on the GAP Device Name (0x2A00) value and the advertising Local
 * Name.  Fits a Complete Local Name AD inside a 31-byte legacy advertising PDU
 * alongside the 3-byte Flags AD (31 - 3 - 2 header = 26).
 */
#define BLUED_GAP_NAME_MAXLEN		26
#define UUID_DATABASE_HASH		GATT_UUID_DATABASE_HASH

/* HID Service UUIDs (HOGP v1.0 Section 2) */
#define UUID_HID_SERVICE		0x1812
#define UUID_DEVICE_INFO_SERVICE	0x180A
#define UUID_BATTERY_SERVICE		0x180F

/* HID Service Characteristic UUIDs */
#define UUID_REPORT_MAP			0x2A4B
#define UUID_REPORT			0x2A4D
#define UUID_HID_INFORMATION		0x2A4A
#define UUID_HID_CONTROL_POINT		0x2A4C
#define UUID_BOOT_KB_OUTPUT_REPORT	0x2A32

/* Device Information Service Characteristic UUIDs */
#define UUID_PNP_ID			0x2A50

/* Battery Service Characteristic UUIDs */
#define UUID_BATTERY_LEVEL		0x2A19

/* Peripheral GATT service UUIDs */
#define UUID_GATT_SERVICE		0x1801
#define UUID_DIS_SERVICE		0x180A
#define UUID_CUSTOM_SERVICE		0xFFE0
#define UUID_APPEARANCE			0x2A01
#define UUID_MANUFACTURER		0x2A29
#define UUID_MODEL_NUMBER		0x2A24
#define UUID_FIRMWARE_REV		0x2A26
#define UUID_CUSTOM_CHAR		0xFFE1
#define UUID_CLIENT_SUPP_FEAT		0x2B29
#define UUID_SERVER_SUPP_FEAT		0x2B3A

/* Default peripheral name; overridden by cfg.peripheral_name at runtime */
#define PERIPHERAL_NAME_DEFAULT		"5BSD-blued"
#define ADV_INTERVAL_100MS		0x00A0	/* 160 * 0.625ms = 100ms */

#include "hogp_report.h"

struct hogp_device {
	struct att_conn		att;
	struct smp_conn		smp;
	struct smp_bond_db	*bond_db;	/* daemon-owned shared repository */

	struct gatt_discovery	hid_disc;
	struct hogp_report	reports[HOGP_MAX_REPORTS];
	int			nreports;

	uint8_t			*report_map;
	size_t			report_map_len;

	uint16_t		hid_ctrl_handle;  /* HID Control Point */
	uint16_t		hid_bcdHID;	  /* from HID Information */

	/*
	 * Service Changed characteristic value handle (GATT Service 0x1801,
	 * char 0x2A05), recorded at discovery so a Service Changed indication
	 * is matched by handle, not by length (Core Spec Vol 3 Part G §2.5.2).
	 * Zero if the characteristic is absent.
	 */
	uint16_t		svc_changed_handle;

	uint16_t		idVendor;	  /* from DIS PnP ID */
	uint16_t		idProduct;	  /* from DIS PnP ID */

	char			device_name[32]; /* from GAP Device Name 0x2A00 */
	bool			has_device_name;
	bool			boot_protocol;	/* using Boot Protocol fallback */

	int			vhid_ctl_fd;	/* /dev/vhid */
	int			vhid_fd;	/* /dev/vhidN */
	int			vhid_unit;
	int			hci_fd;		/* raw HCI socket */
	int			bond_fd;	/* bond storage */

	uint8_t			addr[6];
	uint8_t			addr_type;
	uint8_t			local_addr[6];
	uint16_t		con_handle;

	uint64_t		le_features;	/* controller feature bitmask */

	const char		*adapter;	/* e.g. "ubt0" */
	bool			debug;
	bool			reconnect;	/* auto-reconnect on loss */

};

/* Shared state between split files */
extern volatile sig_atomic_t running;
extern struct pidfh *blued_pfh;
extern const char *blued_config_path;
extern struct blued_config blued_cfg;
extern const char *blued_peripheral_name;

/*
 * Operator runtime pairing gate (the common adapter pairable control).  When false the SMP
 * responder declines an incoming Pairing Request with "Pairing Not Supported"
 * (Core Spec Vol 3 Part H §2.4.1 / §3.5.1).  Toggled by the PAIRABLE ctl verb;
 * default true.
 */
extern atomic_bool blued_pairable;

/* Shared GATT database for peripheral mode (built once in main) */
extern struct att_db periph_gatt_db;
extern struct att_attr periph_gatt_attrs[64];
extern uint8_t periph_gatt_val_buf[2048];

/* Shared config reference for reconnect_max_delay */
extern int blued_reconnect_max_delay;

/* Persistent local IRK for RPA generation */
extern uint8_t blued_local_irk[16];
extern bool blued_has_local_irk;

/* ---- Functions shared across the split files ---- */

/* blued.c — daemon lifecycle and utility */
void	blued_capsicum_limit_fds(void);
int	blued_socket_broker_take(void);

/*
 * BSM audit helper.  Submits an audit record if BSM is enabled.
 */
#ifdef USE_BSM_AUDIT
void	blued_audit(int event, int error, const char *fmt, ...);
#else
#define	blued_audit(event, error, ...)	((void)0)
#endif

/* SIGHUP config reload (blued.c, called from blued_event.c) */
void	blued_reload_config(void);

/*
 * Adapter runtime power control (the common adapter power control).  on=true re-inits the
 * controller (reuses the adapter init path) and marks it powered; on=false
 * quiesces advertising/scanning, drops this adapter's links, and disarms the
 * discoverable timer, leaving the HCI socket open.  Returns 0 on success.
 */
int	blued_adapter_set_power(struct blued_adapter *adp, bool on);

/*
 * Update the local GAP device name (0x2A00) attribute value and the
 * advertising / scan-response Local Name.  Bounded copy; returns 0 on success,
 * -1 if the name is empty or too long.  Consulted by the SET_NAME ctl verb.
 */
int	blued_set_device_name(const char *name);

/*
 * Drive general/limited discoverable advertising for an adapter and arm/refresh
 * the auto-off timer (0 = no timeout).  disable turns it off and disarms the
 * timer.  Returns 0 on success.
 */
int	blued_adapter_set_discoverable(struct blued_adapter *adp, bool enable,
	    bool limited, unsigned int timeout_sec);
bool	blued_discoverable_timer_fired(uintptr_t timer_id);

/* SMP passkey/numcmp callbacks (blued.c) */
int	passkey_display(uint32_t *passkey, bool display, void *arg);
int	numcmp_confirm(uint32_t value, void *arg);
void	blued_keypress_notify(uint8_t type, void *arg);

/*
 * Consume any operator-injected OOB pairing data (OOB_INJECT) for a peer into
 * caller storage; returns true if legacy and/or SC OOB was present.  Defined in
 * ctl.c, called from the pairing setup path.
 */
struct smp_oob_legacy;
struct smp_oob_sc;
bool	blued_oob_take(const uint8_t *addr, struct smp_oob_legacy *lg,
	    bool *has_lg, struct smp_oob_sc *scd, bool *has_sc);

/* blued_event.c — event loop and connection handling */
void	blued_event_loop(void);
void	blued_conn_disconnect(struct blued_conn *conn);
void	blued_conn_central_teardown(struct blued_conn *conn);
void	blued_ind_arm_timeout(struct blued_conn *conn);
void	blued_ind_disarm_timeout(struct blued_conn *conn);
void	blued_idle_arm(struct blued_conn *conn);
void	blued_idle_disarm(struct blued_conn *conn);
void	blued_handle_hci_event(struct blued_adapter *adp);

/* blued_central.c — central role */
void	blued_central_setup_fail(struct blued_conn *conn);
void	hogp_event_loop_once(struct blued_conn *conn);
int	hogp_event_loop_bearer(struct blued_conn *conn, int fd, uint16_t mtu);
void	hogp_handle_vhid_output(struct hogp_device *dev);

/* blued_peripheral.c — peripheral role */
void	blued_periph_readvertise(void);
bool	blued_periph_readvertise_timer_fired(uintptr_t);
void	blued_periph_readvertise_cancel(struct blued_adapter *);
void	blued_periph_accept(struct blued_adapter *);
void	blued_periph_setup_fail(struct blued_conn *conn);
void	peripheral_build_gattdb(struct att_db *, struct att_attr *,
	    uint8_t *, size_t, const struct blued_config *);
int	peripheral_att_listen(struct blued_adapter *);
int	blued_eatt_listen(struct blued_adapter *);
void	blued_eatt_accept(struct blued_adapter *);

#endif /* _BLUED_INTERNAL_H_ */
