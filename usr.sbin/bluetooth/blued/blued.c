/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * blued - Bluetooth Low Energy HID daemon
 *
 * Connects to BLE HID devices (HOGP - HID over GATT Profile),
 * discovers HID services, subscribes to report notifications, and
 * injects raw HID reports into the kernel via /dev/vhidN.
 *
 * Runs in a Capsicum sandbox after initialization.
 *
 * Usage: blued [-d] [-f bonds_file] <bdaddr> [addr_type]
 */

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
#include <stdbool.h>
#include <syslog.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

int blued_verbose = 0;
int blued_daemonized = 0;
static int blued_serviced;
struct blued_ctx blued_g;
const int _blued_kq_ctl_tag;	/* sentinel address for BLUED_KQ_CTL_LISTEN */
const int _blued_kq_setup_pipe_tag;
const int _blued_kq_periph_listen_tag;

#include <dev/hid/vhid.h>

/* GAP/GATT Service UUIDs */
#define UUID_GAP_SERVICE		0x1800
#define UUID_DEVICE_NAME		0x2A00
#define UUID_DATABASE_HASH		0x2B2A

/* HID Service UUIDs (HOGP v1.0 Section 2) */
#define UUID_HID_SERVICE		0x1812
#define UUID_DEVICE_INFO_SERVICE	0x180A
#define UUID_BATTERY_SERVICE		0x180F

/* HID Service Characteristic UUIDs */
#define UUID_REPORT_MAP			0x2A4B
#define UUID_REPORT			0x2A4D
#define UUID_HID_INFORMATION		0x2A4A
#define UUID_HID_CONTROL_POINT		0x2A4C
#define UUID_PROTOCOL_MODE		0x2A4E
#define UUID_BOOT_KB_INPUT_REPORT	0x2A22
#define UUID_BOOT_KB_OUTPUT_REPORT	0x2A32
#define UUID_BOOT_MOUSE_INPUT_REPORT	0x2A33

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

#define PERIPHERAL_NAME			"5BSD-blued"
#define ADV_INTERVAL_100MS		0x00A0	/* 160 * 0.625ms = 100ms */

/* Report Reference descriptor report types */
#define HID_REPORT_TYPE_INPUT		0x01
#define HID_REPORT_TYPE_OUTPUT		0x02
#define HID_REPORT_TYPE_FEATURE		0x03

/* Protocol Mode values */
#define HID_PROTOCOL_BOOT		0x00
#define HID_PROTOCOL_REPORT		0x01

/*
 * HOGP report mapping: maps a GATT characteristic value handle
 * to its report ID and type.
 */
struct hogp_report {
	uint16_t	value_handle;
	uint16_t	cccd_handle;
	uint8_t		report_id;
	uint8_t		report_type;
};

#define HOGP_MAX_REPORTS	16

struct hogp_device {
	struct att_conn		att;
	struct smp_conn		smp;
	struct smp_bond_db	bond_db;

	struct gatt_discovery	hid_disc;
	struct hogp_report	reports[HOGP_MAX_REPORTS];
	int			nreports;

	uint8_t			*report_map;
	size_t			report_map_len;

	uint16_t		hid_ctrl_handle;  /* HID Control Point */
	uint16_t		hid_bcdHID;	  /* from HID Information */

	uint16_t		idVendor;	  /* from DIS PnP ID */
	uint16_t		idProduct;	  /* from DIS PnP ID */

	char			device_name[32]; /* from GAP Device Name 0x2A00 */
	bool			has_device_name;

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

	/*
	 * Pre-allocated socket pool for ATT reconnection inside Capsicum.
	 * Created before cap_enter(), consumed on reconnect via cap_connect().
	 * SMP is not pooled: re-pairing after Capsicum entry requires
	 * restarting blued.  Reconnection with an existing bond uses HCI
	 * LE_Start_Encryption, which does not need an SMP socket.
	 */
#define SOCK_POOL_SIZE	8
	int			att_pool[SOCK_POOL_SIZE];
	int			att_pool_next;
};

static volatile sig_atomic_t running = 1;
static struct pidfh *blued_pfh;

static void	usage(void) __dead2;
static void	blued_periph_accept(void);
static void	peripheral_build_gattdb(struct att_db *, struct att_attr *,
		    uint8_t *, size_t);
static int	peripheral_att_listen(void);
static int	hogp_discover(struct hogp_device *dev);
static int	hogp_subscribe(struct hogp_device *dev);
static int	hogp_setup_vhid(struct hogp_device *dev);
static void	hogp_event_loop(struct hogp_device *dev);
static int	capsicum_sandbox(struct hogp_device *dev);
static void	hogp_cleanup(struct hogp_device *dev);

static struct hogp_device *cleanup_dev;

/*
 * Pre-allocate a pool of bound L2CAP sockets for reconnection
 * inside capability mode.  Each socket is created, bound to
 * BDADDR_ANY, and left unconnected.  cap_connect() can then
 * connect them inside the sandbox.
 */
static int
pool_create(int *pool, int count)
{
	struct sockaddr_l2cap sa;
	int i;

	for (i = 0; i < count; i++) {
		pool[i] = socket(PF_BLUETOOTH,
		    SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_CLOFORK,
		    BLUETOOTH_PROTO_L2CAP);
		if (pool[i] < 0) {
			for (int j = 0; j < i; j++) {
				close(pool[j]);
				pool[j] = -1;
			}
			return (-1);
		}

		memset(&sa, 0, sizeof(sa));
		sa.l2cap_len = sizeof(sa);
		sa.l2cap_family = AF_BLUETOOTH;

		if (bind(pool[i], (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			close(pool[i]);
			pool[i] = -1;
			for (int j = 0; j < i; j++) {
				close(pool[j]);
				pool[j] = -1;
			}
			return (-1);
		}
	}
	return (0);
}

static int
pool_take(int *pool, int *next, int size)
{
	int fd;

	if (*next >= size)
		return (-1);
	fd = pool[*next];
	pool[*next] = -1;
	(*next)++;
	return (fd);
}

static void
atexit_cleanup(void)
{
	if (cleanup_dev != NULL)
		hogp_cleanup(cleanup_dev);
	if (blued_pfh != NULL)
		pidfile_remove(blued_pfh);
}

/*
 * Passkey callback for SMP pairing.
 * Displays the passkey on stderr for the user to enter on the device.
 */
static int
passkey_display(uint32_t *passkey, bool display, void *arg __unused)
{
	if (display) {
		fprintf(stderr,
		    "\n*** Enter this passkey on the BLE device: %06u ***\n\n",
		    *passkey);
		return (0);
	}

	/* Input mode — prompt user */
	fprintf(stderr, "Enter the passkey shown on the BLE device: ");
	if (scanf("%u", passkey) != 1) {
		fprintf(stderr, "Passkey entry cancelled.\n");
		return (-1);
	}
	return (0);
}

/*
 * Numeric Comparison callback.
 * Shows the 6-digit value and asks user to confirm match.
 */
static int
numcmp_confirm(uint32_t value, void *arg __unused)
{
	char buf[8];

	fprintf(stderr,
	    "\n*** Confirm this number matches the BLE device: %06u ***\n"
	    "Does it match? [y/n] ", value);

	if (fgets(buf, sizeof(buf), stdin) == NULL)
		return (-1);
	if (buf[0] == 'y' || buf[0] == 'Y')
		return (0);
	fprintf(stderr, "Pairing rejected by user.\n");
	return (-1);
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: blued [-Bdrv] [-a adapter] [-f bonds] [-L logfile] -s\n"
	    "       blued [-Bdrv] [-a adapter] [-f bonds] [-L logfile] "
	    "<bdaddr> [public|random] ...\n"
	    "       blued [-Bdv] [-a adapter] [-f bonds] [-L logfile] -p\n"
	    "\n"
	    "  -B       run as daemon (background, syslog, pidfile)\n"
	    "  -d       debug mode (same as -v)\n"
	    "  -v       verbose (repeat for trace: -vv)\n"
	    "  -L file  log HCI packets to file (BTSnoop format, "
	    "view in Wireshark)\n"
	    "  -r       auto-reconnect\n"
	    "  -s       scan mode\n"
	    "  -p       peripheral mode\n");
	exit(1);
}

/*
 * Load bonded device IRKs into the controller's resolving list.
 * Enables hardware-level RPA resolution for reconnection with
 * privacy-enabled devices.  Best-effort — silently ignored if
 * the controller doesn't support it.
 */
static void
load_resolving_list(struct hogp_device *dev)
{
	static const uint8_t zero_irk[16] = {0};
	int loaded = 0;

	/* Clear any stale entries */
	hci_le_clear_resolving_list(dev->hci_fd);

	for (int i = 0; i < dev->bond_db.count; i++) {
		struct smp_bond *b = &dev->bond_db.bonds[i];

		if (!b->has_irk)
			continue;

		uint8_t at = (b->addr_type == BDADDR_LE_RANDOM) ? 0x01 : 0x00;

		if (hci_le_add_dev_resolving_list(dev->hci_fd, at,
		    b->addr, b->irk, zero_irk) == 0) {
			/* Set device privacy mode so we can receive
			 * both RPAs and identity addresses from this peer */
			hci_le_set_privacy_mode(dev->hci_fd, at,
			    b->addr, 0x01 /* device privacy */);
			loaded++;
		}
	}

	if (loaded > 0) {
		hci_le_set_rpa_timeout(dev->hci_fd, 900); /* 15 min */
		hci_le_set_addr_resolution_enable(dev->hci_fd, 1);
		LOG_HCI(1, "resolving list: %d device(s) loaded", loaded);
	}
}

static void
do_scan(struct hogp_device *dev)
{
	struct ble_scan_result results[BLE_MAX_SCAN_RESULTS];
	int nresults, i;
	char addr_str[18];
	bool used_ext = false;

	fprintf(stderr, "blued: scanning for BLE devices (5 seconds)...\n");

	/*
	 * Try extended scanning first (BT 5.0+).  Extended scan
	 * receives both legacy and extended advertising reports,
	 * so it is strictly a superset of legacy scanning.
	 * Fall back to legacy scan if the controller does not
	 * support extended advertising/scanning.
	 */
	if (dev->le_features & LE_FEAT_EXT_ADVERTISING) {
		if (hci_le_ext_scan(dev->hci_fd, 5, results,
		    BLE_MAX_SCAN_RESULTS, &nresults) == 0) {
			used_ext = true;
		} else {
			LOG_HCI(1, "extended scan failed, "
			    "falling back to legacy");
		}
	}

	if (!used_ext) {
		if (hci_le_scan(dev->hci_fd, 5, results,
		    BLE_MAX_SCAN_RESULTS, &nresults) < 0)
			err(1, "BLE scan");
	}

	fprintf(stdout, "Found %d device(s)%s:\n\n", nresults,
	    used_ext ? " (extended scan)" : "");

	for (i = 0; i < nresults; i++) {
		bt_ntoa((bdaddr_t *)results[i].addr, addr_str);
		fprintf(stdout, "  %s  %-8s  RSSI: %d  %s\n",
		    addr_str,
		    results[i].addr_type == BDADDR_LE_RANDOM ?
		    "random" : "public",
		    results[i].rssi,
		    results[i].has_name ? results[i].name : "(unknown)");
	}
}

static int
blued_enumerate_adapters(struct blued_config *cfg)
{
	struct blued_adapter *adp;
	int i, nfound;
	char name[16];

	LIST_INIT(&blued_g.adapters);
	nfound = 0;

	if (cfg->nadapters > 0) {
		/* Use explicitly configured adapters */
		for (i = 0; i < cfg->nadapters; i++) {
			int fd;

			fd = hci_open(cfg->adapters[i]);
			if (fd < 0) {
				warn("open adapter %s", cfg->adapters[i]);
				continue;
			}
			adp = calloc(1, sizeof(*adp));
			if (adp == NULL) {
				close(fd);
				continue;
			}
			adp->hci_fd = fd;
			strlcpy(adp->name, cfg->adapters[i],
			    sizeof(adp->name));
			adp->active = true;
			LIST_INSERT_HEAD(&blued_g.adapters, adp, entries);
			nfound++;
		}
	} else {
		/* Auto-discover: try ubt0..ubt7 */
		for (i = 0; i < BLUED_MAX_ADAPTERS; i++) {
			int fd;

			snprintf(name, sizeof(name), "ubt%d", i);
			fd = hci_open(name);
			if (fd < 0)
				continue;
			adp = calloc(1, sizeof(*adp));
			if (adp == NULL) {
				close(fd);
				continue;
			}
			adp->hci_fd = fd;
			strlcpy(adp->name, name, sizeof(adp->name));
			adp->active = true;
			LIST_INSERT_HEAD(&blued_g.adapters, adp, entries);
			nfound++;
		}
	}

	return (nfound);
}

static int
blued_adapter_init(struct blued_adapter *adp)
{

	hci_reset(adp->hci_fd);
	usleep(100000);

	if (hci_get_bdaddr(adp->hci_fd, (uint8_t *)&adp->addr) < 0) {
		warn("read BD_ADDR for %s", adp->name);
		return (-1);
	}

	if (hci_le_read_local_features(adp->hci_fd, &adp->le_features) < 0)
		adp->le_features = 0;

	/* Set LE event mask for all supported features */
	hci_le_set_event_mask(adp->hci_fd, adp->le_features);

	if (blued_verbose >= 1) {
		char addr_str[18];
		bt_ntoa(&adp->addr, addr_str);
		LOG_HOGP(1, "adapter %s: address %s, features 0x%llx",
		    adp->name, addr_str,
		    (unsigned long long)adp->le_features);
	}

	return (0);
}

static void	hogp_event_loop_once(struct blued_conn *conn);

static void	blued_conn_disconnect(struct blued_conn *conn);

/* Shared GATT database for peripheral mode (built once in main) */
static struct att_db periph_gatt_db;
static struct att_attr periph_gatt_attrs[64];
static uint8_t periph_gatt_val_buf[2048];
/* Shared config reference for reconnect_max_delay */
static int blued_reconnect_max_delay = 60;

/*
 * Central connection setup thread — failure cleanup.
 *
 * Closes ATT/SMP, frees partial state.  If reconnect is enabled,
 * schedules an EVFILT_TIMER to retry.  Otherwise flags the conn
 * for cleanup by the main thread (via the self-pipe handler) to
 * avoid a data race on blued_g.conns.
 */
static void
blued_central_setup_fail(struct blued_conn *conn)
{
	struct hogp_device *dev = conn->hogp;

	if (dev != NULL) {
		att_close(&dev->att);
		if (dev->smp.fd >= 0)
			smp_close(&dev->smp);
		free(dev->report_map);
		dev->report_map = NULL;
		dev->nreports = 0;
	}
	conn->att_fd = -1;
	conn->att = NULL;

	if (conn->reconnect) {
		struct kevent kev;

		conn->state = BLUED_CONN_RECONNECTING;
		if (conn->reconnect_delay == 0)
			conn->reconnect_delay = 3;
		LOG_HOGP(1, "setup failed, reconnecting in %d seconds...",
		    conn->reconnect_delay);

		conn->reconnect_timer = (int)(uintptr_t)conn;
		EV_SET(&kev, (uintptr_t)conn->reconnect_timer,
		    EVFILT_TIMER,
		    EV_ADD | EV_ONESHOT, NOTE_SECONDS,
		    conn->reconnect_delay, conn);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);

		conn->reconnect_delay *= 2;
		if (conn->reconnect_delay > blued_reconnect_max_delay)
			conn->reconnect_delay = blued_reconnect_max_delay;
	} else {
		conn->state = BLUED_CONN_IDLE;
		atomic_store_explicit(&conn->needs_cleanup, true,
		    memory_order_release);
	}
	(void)write(blued_g.setup_pipe[1], "x", 1);
}

/*
 * Central connection setup thread entry point.
 *
 * Performs the blocking ATT connect, MTU exchange, bond/pair,
 * HOGP discovery, and vhid setup.  On success, registers the
 * connection with the kqueue event loop via the self-pipe.
 */
void *
blued_conn_setup_central(void *arg)
{
	struct blued_conn *conn = arg;
	struct hogp_device *dev;
	int ret;

	dev = conn->hogp;
	if (dev == NULL) {
		blued_central_setup_fail(conn);
		return (NULL);
	}

	dev->att.fd = -1;
	dev->smp.fd = -1;

	/* Connect ATT */
	{
		char addr_str[18];
		bt_ntoa((bdaddr_t *)dev->addr, addr_str);
		LOG_HOGP(1, "connecting to %s...", addr_str);
	}

	{
		int att_fd;

		att_fd = pool_take(dev->att_pool, &dev->att_pool_next,
		    SOCK_POOL_SIZE);
		if (att_fd >= 0) {
			ret = att_open_fd(&dev->att, att_fd, dev->addr,
			    dev->addr_type);
		} else {
			ret = att_open(&dev->att, dev->addr,
			    dev->addr_type);
		}

		if (ret < 0) {
			warn("ATT connect failed");
			blued_central_setup_fail(conn);
			return (NULL);
		}
	}

	LOG_HOGP(1, "connected, exchanging MTU");

	/* Get connection handle */
	{
		int retries;
		for (retries = 0; retries < 5; retries++) {
			if (hci_get_con_handle(dev->hci_fd, dev->addr,
			    &dev->con_handle) == 0)
				break;
			usleep(200000);
		}
		if (retries == 5) {
			warnx("could not get HCI connection handle");
			blued_central_setup_fail(conn);
			return (NULL);
		}
		LOG_HOGP(1, "connection handle=%04x", dev->con_handle);
		dev->att.con_handle = dev->con_handle;
	}

	/* Request optimal link parameters */
	if (dev->le_features & LE_FEAT_DATA_LENGTH_EXT)
		hci_le_set_data_length(dev->hci_fd, dev->con_handle,
		    0x00FB, 0x0848);
	if (dev->le_features & LE_FEAT_2M_PHY)
		hci_le_set_phy(dev->hci_fd, dev->con_handle, 0x00,
		    0x02, 0x02, 0x0000);

	hci_le_connection_update(dev->hci_fd, dev->con_handle,
	    6, 12, 4, 500);

	if (att_exchange_mtu(&dev->att, ATT_MAX_MTU) < 0)
		warn("MTU exchange failed, using default %d",
		    ATT_DEFAULT_MTU);
	else
		LOG_HOGP(1, "MTU=%d", dev->att.mtu);

	/* Attempt encryption with existing bond, or pair */
	{
		struct smp_bond *bond;

		bond = smp_find_bond(&dev->bond_db, dev->addr,
		    dev->addr_type);
		if (bond != NULL) {
			LOG_HOGP(1, "found existing bond, encrypting...");
			dev->smp.hci_fd = dev->hci_fd;
			dev->smp.con_handle = dev->con_handle;
			if (smp_encrypt_with_ltk(&dev->smp, bond) < 0) {
				warn("bonded encryption failed");
			} else {
				LOG_HOGP(1, "waiting for encryption...");
				if (hci_wait_encryption(dev->hci_fd,
				    dev->con_handle, 10) < 0)
					warn("encryption timeout");
				else {
					dev->att.encrypted = true;
					LOG_HOGP(1, "encrypted");
				}
			}
		}
	}

	/* Discover HOGP services */
	{
		ret = hogp_discover(dev);

		if (ret == ATT_ERR_INSUFF_AUTHEN ||
		    ret == ATT_ERR_INSUFF_ENCRYPTION) {
			LOG_HOGP(1, "device requires pairing");

			if (smp_open(&dev->smp, dev->addr,
			    dev->addr_type, dev->local_addr, 0,
			    dev->hci_fd, dev->con_handle,
			    &dev->bond_db) < 0) {
				warnx("SMP open failed");
				blued_central_setup_fail(conn);
				return (NULL);
			}
			dev->smp.passkey_cb = passkey_display;
			dev->smp.numcmp_cb = numcmp_confirm;

			if (smp_pair(&dev->smp) < 0) {
				warnx("SMP pairing failed");
				blued_central_setup_fail(conn);
				return (NULL);
			}

			if (hci_wait_encryption(dev->hci_fd,
			    dev->con_handle, 10) < 0)
				warn("post-pairing encryption timeout");
			else
				dev->att.encrypted = true;

			LOG_HOGP(1, "pairing complete, retrying discovery");

			ret = hogp_discover(dev);
		}
		if (ret != 0) {
			warnx("HOGP discovery failed: %d", ret);
			blued_central_setup_fail(conn);
			return (NULL);
		}
	}

	/* Read GATT Database Hash for caching */
	{
		uint8_t remote_hash[16];
		size_t hlen = 0;

		if (att_read_by_type(&dev->att, 0x0001, 0xFFFF,
		    UUID_DATABASE_HASH, remote_hash, 16, &hlen) == 0 &&
		    hlen == 16) {
			struct smp_bond *bond = smp_find_bond(
			    &dev->bond_db, dev->addr, dev->addr_type);
			if (bond != NULL) {
				if (bond->has_db_hash &&
				    memcmp(bond->db_hash, remote_hash,
				    16) == 0)
					LOG_HOGP(1, "GATT DB hash "
					    "unchanged, cache valid");
				else
					LOG_HOGP(1, "GATT DB hash "
					    "changed or new, full "
					    "discovery done");
				memcpy(bond->db_hash, remote_hash, 16);
				bond->has_db_hash = true;
				smp_bond_db_save(&dev->bond_db);
			}
		}
	}

	/* Save device name to bond */
	if (dev->has_device_name) {
		struct smp_bond *bond = smp_find_bond(&dev->bond_db,
		    dev->addr, dev->addr_type);
		if (bond != NULL && !bond->has_name) {
			strlcpy(bond->name, dev->device_name,
			    sizeof(bond->name));
			bond->has_name = true;
			smp_bond_db_save(&dev->bond_db);
		}
	}

	/* Set up vhid device */
	if (dev->vhid_fd < 0) {
		if (hogp_setup_vhid(dev) != 0) {
			warnx("vhid setup failed");
			blued_central_setup_fail(conn);
			return (NULL);
		}
	}

	/* Subscribe to report notifications */
	if (hogp_subscribe(dev) != 0) {
		warnx("HOGP subscribe failed");
		blued_central_setup_fail(conn);
		return (NULL);
	}

	/* Write Exit Suspend to HID Control Point */
	if (dev->hid_ctrl_handle != 0) {
		uint8_t exit_suspend = 0x01;
		att_write_cmd(&dev->att, dev->hid_ctrl_handle,
		    &exit_suspend, 1);
	}

	/* Close SMP — not needed during active session */
	smp_close(&dev->smp);

	/* Register the connection with the event loop */
	conn->att_fd = dev->att.fd;
	conn->att = &dev->att;
	conn->con_handle = dev->con_handle;
	conn->state = BLUED_CONN_ACTIVE;

	{
		char addr_str[18];
		bt_ntoa(&conn->dst, addr_str);
		BLUED_PROBE_CONN_OPEN(addr_str, 0 /* central */);
	}

	if (blued_conn_register(conn) < 0) {
		warnx("blued_conn_register failed");
		blued_central_setup_fail(conn);
		return (NULL);
	}

	/* Reset backoff on successful connection */
	conn->reconnect_delay = 0;

	LOG_HOGP(1, "setup complete, entering event loop");
	(void)write(blued_g.setup_pipe[1], "x", 1);
	return (NULL);
}

/*
 * Re-enable advertising after a peripheral connection ends or
 * fails setup.  Called from both the main thread (disconnect)
 * and the setup thread (failure), but only one peripheral
 * connection exists at a time so no lock is needed.
 */
static void
blued_periph_readvertise(void)
{
	struct blued_adapter *adp;

	adp = LIST_FIRST(&blued_g.adapters);
	if (adp != NULL && blued_g.periph_active) {
		if (adp->le_features & LE_FEAT_EXT_ADVERTISING)
			hci_le_set_ext_adv_enable(adp->hci_fd, 1, 0x00);
		else
			hci_le_set_advertise_enable(adp->hci_fd, true);
		LOG_HOGP(1, "re-advertising");
	}
}

/*
 * Accept an incoming peripheral ATT connection from the listen socket.
 * Called when EVFILT_READ fires on blued_g.periph_listen_fd.
 *
 * Allocates the connection and att_conn, disables advertising, then
 * spawns blued_conn_setup_peripheral() to handle SMP and kqueue
 * registration.
 */
static void
blued_periph_accept(void)
{
	struct sockaddr_l2cap peer_sa;
	socklen_t peer_len;
	struct blued_conn *conn;
	struct att_conn *ac;
	int client_fd;
	pthread_t tid;
	pthread_attr_t attr;

	peer_len = sizeof(peer_sa);
	client_fd = accept4(blued_g.periph_listen_fd,
	    (struct sockaddr *)&peer_sa, &peer_len,
	    SOCK_CLOEXEC | SOCK_CLOFORK);
	if (client_fd < 0) {
		if (errno != EINTR)
			warn("peripheral accept");
		return;
	}

	conn = blued_conn_alloc();
	if (conn == NULL) {
		close(client_fd);
		return;
	}
	conn->role = BLUED_ROLE_PERIPHERAL;
	memcpy(&conn->dst, peer_sa.l2cap_bdaddr.b, sizeof(conn->dst));
	conn->addr_type = peer_sa.l2cap_bdaddr_type;

	/* Heap-allocate att_conn for peripheral */
	ac = calloc(1, sizeof(struct att_conn));
	if (ac == NULL) {
		close(client_fd);
		blued_conn_free(conn);
		return;
	}
	ac->fd = client_fd;
	ac->mtu = ATT_DEFAULT_MTU;
	ac->buf = malloc(ATT_MAX_MTU);
	if (ac->buf == NULL) {
		close(client_fd);
		free(ac);
		blued_conn_free(conn);
		return;
	}

	conn->att_owned = ac;
	conn->att = ac;
	conn->att_fd = client_fd;
	conn->gatt_db = &periph_gatt_db;
	conn->state = BLUED_CONN_CONNECTING;

	/* Disable advertising while connected */
	{
		struct blued_adapter *adp = LIST_FIRST(&blued_g.adapters);
		if (adp != NULL) {
			if (adp->le_features & LE_FEAT_EXT_ADVERTISING)
				hci_le_set_ext_adv_enable(adp->hci_fd, 0, 0x00);
			else
				hci_le_set_advertise_enable(adp->hci_fd, false);
		}
	}

	{
		char addr_str[18];
		bt_ntoa(&conn->dst, addr_str);
		LOG_HOGP(1, "peripheral client accepted: %s", addr_str);
	}

	/* Spawn setup thread for SMP + kqueue registration */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&tid, &attr, blued_conn_setup_peripheral,
	    conn) != 0) {
		warn("peripheral setup thread");
		blued_conn_free(conn);
		blued_periph_readvertise(); /* main thread context, safe */
		pthread_attr_destroy(&attr);
		return;
	}
	pthread_attr_destroy(&attr);
}

/*
 * Peripheral setup thread failure cleanup.
 *
 * Flags the conn for cleanup and re-advertising, both deferred to
 * the main thread's self-pipe handler to avoid data races on
 * blued_g.conns and HCI advertising commands.
 */
static void
blued_periph_setup_fail(struct blued_conn *conn)
{

	conn->state = BLUED_CONN_IDLE;
	atomic_store_explicit(&conn->needs_readvertise, true,
	    memory_order_release);
	atomic_store_explicit(&conn->needs_cleanup, true,
	    memory_order_release);
	(void)write(blued_g.setup_pipe[1], "x", 1);
}

/*
 * Peripheral connection setup thread.
 *
 * Gets the HCI connection handle, attempts SMP pairing as responder
 * (if the peer initiates it within 5 seconds), waits for encryption,
 * restores CCCDs, and registers the ATT fd with the kqueue event
 * loop via the self-pipe.
 *
 * Only one peripheral connection is active at a time (advertising
 * is disabled in blued_periph_accept before this thread starts),
 * so CCCD state in periph_gatt_db does not need per-connection
 * isolation.
 */
void *
blued_conn_setup_peripheral(void *arg)
{
	struct blued_conn *conn = arg;
	struct att_conn *ac = conn->att;
	struct blued_adapter *adp;

	adp = LIST_FIRST(&blued_g.adapters);

	/* Get connection handle */
	{
		uint16_t ch = 0;
		int retries;

		for (retries = 0; retries < 5; retries++) {
			if (hci_get_con_handle(adp->hci_fd,
			    (const uint8_t *)&conn->dst, &ch) == 0)
				break;
			usleep(200000);
		}
		if (retries < 5) {
			conn->con_handle = ch;
			ac->con_handle = ch;
		}
	}

	/*
	 * SMP responder: open an SMP channel and wait for the peer
	 * to initiate pairing.  Use poll() with a 5-second timeout
	 * to avoid blocking the connection if the peer never sends
	 * a Pairing Request (already bonded, or no security needed).
	 *
	 * SMP on LE uses fixed CID 0x0006.  The kernel's L2CAP layer
	 * requires bind(local) + connect(peer) even for fixed CIDs,
	 * matching the pattern used by smp_open() for central mode.
	 */
	if (conn->con_handle != 0 && blued_g.bond_db != NULL) {
		struct smp_bond *bond;

		bond = smp_find_bond(blued_g.bond_db,
		    (const uint8_t *)&conn->dst, conn->addr_type);
		if (bond == NULL) {
			struct smp_conn sc;
			struct pollfd pfd;
			int smp_fd, pr;

			smp_fd = socket(PF_BLUETOOTH,
			    SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_CLOFORK,
			    BLUETOOTH_PROTO_L2CAP);
			if (smp_fd >= 0) {
				struct sockaddr_l2cap sa;

				/* Bind to local address, SMP CID */
				memset(&sa, 0, sizeof(sa));
				sa.l2cap_len = sizeof(sa);
				sa.l2cap_family = AF_BLUETOOTH;
				sa.l2cap_cid = htole16(NG_L2CAP_SMP_CID);
				sa.l2cap_bdaddr_type = BDADDR_LE_PUBLIC;
				memcpy(&sa.l2cap_bdaddr, &adp->addr,
				    sizeof(sa.l2cap_bdaddr));

				if (bind(smp_fd, (struct sockaddr *)&sa,
				    sizeof(sa)) < 0) {
					warn("SMP bind");
					close(smp_fd);
					goto skip_smp;
				}

				/* Connect to peer on SMP CID */
				memset(&sa, 0, sizeof(sa));
				sa.l2cap_len = sizeof(sa);
				sa.l2cap_family = AF_BLUETOOTH;
				sa.l2cap_cid = htole16(NG_L2CAP_SMP_CID);
				sa.l2cap_bdaddr_type = conn->addr_type;
				memcpy(&sa.l2cap_bdaddr, &conn->dst,
				    sizeof(sa.l2cap_bdaddr));

				if (connect(smp_fd, (struct sockaddr *)&sa,
				    sizeof(sa)) < 0) {
					warn("SMP connect");
					close(smp_fd);
					goto skip_smp;
				}

				/*
				 * Wait up to 5 seconds for a Pairing Request.
				 * If the peer doesn't initiate, skip SMP and
				 * proceed with an unencrypted connection.
				 */
				pfd.fd = smp_fd;
				pfd.events = POLLIN;
				pr = poll(&pfd, 1, 5000);
				if (pr <= 0) {
					if (pr == 0)
						LOG_HOGP(2, "no pairing "
						    "request, skipping SMP");
					close(smp_fd);
					goto skip_smp;
				}

				if (smp_open_accepted(&sc, smp_fd,
				    (const uint8_t *)&adp->addr,
				    BDADDR_LE_PUBLIC,
				    (const uint8_t *)&conn->dst,
				    conn->addr_type,
				    adp->hci_fd, conn->con_handle,
				    blued_g.bond_db) < 0) {
					close(smp_fd);
					goto skip_smp;
				}

				if (smp_respond(&sc) == 0) {
					LOG_HOGP(1, "peripheral SMP pairing "
					    "complete, waiting for encryption");
					if (hci_wait_encryption(adp->hci_fd,
					    conn->con_handle, 10) < 0)
						warn("post-pairing encryption "
						    "timeout");
					else
						ac->encrypted = true;
				}
				smp_close(&sc);
			}
		}
	}
skip_smp:

	/* Restore CCCDs for bonded device */
	if (blued_g.bond_db != NULL) {
		struct smp_bond *bond;

		bond = smp_find_bond(blued_g.bond_db,
		    (const uint8_t *)&conn->dst, conn->addr_type);
		if (bond != NULL && bond->num_cccds > 0) {
			smp_bond_restore_cccds(bond, &periph_gatt_db);
			LOG_HOGP(1, "restored %d CCCD(s) for bonded device",
			    bond->num_cccds);
		} else {
			/* Reset CCCDs to default */
			for (int i = 0; i < periph_gatt_db.count; i++) {
				if (periph_gatt_attrs[i].uuid16 ==
				    GATT_UUID_CCCD)
					memset(periph_gatt_attrs[i].value, 0,
					    periph_gatt_attrs[i].value_len);
			}
		}
	}

	/* Register with kqueue event loop */
	conn->state = BLUED_CONN_ACTIVE;
	if (blued_conn_register(conn) < 0) {
		warnx("peripheral conn register failed");
		blued_periph_setup_fail(conn);
		return (NULL);
	}

	{
		char addr_str[18];
		bt_ntoa(&conn->dst, addr_str);
		LOG_HOGP(1, "peripheral client connected: %s", addr_str);
		BLUED_PROBE_CONN_OPEN(addr_str, 1 /* peripheral */);
	}

	(void)write(blued_g.setup_pipe[1], "x", 1);
	return (NULL);
}

static void
blued_handle_readable(struct kevent *ev)
{
	struct blued_conn *conn;
	struct blued_ctl_client *client;

	if (ev->udata == BLUED_KQ_SETUP_PIPE) {
		struct blued_conn *c, *tmp;
		char buf[32];

		(void)read(blued_g.setup_pipe[0], buf, sizeof(buf));

		/*
		 * Sweep conns flagged by setup threads.
		 * This runs in the main thread so LIST_REMOVE is safe.
		 * Use acquire to pair with the release store in the
		 * setup thread failure helpers.
		 */
		LIST_FOREACH_SAFE(c, &blued_g.conns, entries, tmp) {
			if (atomic_load_explicit(&c->needs_readvertise,
			    memory_order_acquire)) {
				atomic_store(&c->needs_readvertise, false);
				blued_periph_readvertise();
			}
			if (atomic_load_explicit(&c->needs_cleanup,
			    memory_order_acquire))
				blued_conn_free(c);
		}
		return;
	}

	if (ev->udata == BLUED_KQ_PERIPH_LISTEN) {
		blued_periph_accept();
		return;
	}

	if (ev->udata == BLUED_KQ_CTL_LISTEN) {
		blued_ctl_accept();
		return;
	}

	/* Check if it's a control client */
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		if (ev->udata == client) {
			if ((ev->flags & EV_EOF) ||
			    blued_ctl_dispatch(client) < 0) {
				/* Client disconnected or error */
				LIST_REMOVE(client, entries);
				close(client->fd);
				free(client);
			}
			return;
		}
	}

	/* Check if it's a device connection */
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (ev->udata == conn) {
			if (ev->flags & EV_EOF) {
				blued_conn_disconnect(conn);
			} else if (conn->role == BLUED_ROLE_PERIPHERAL) {
				uint8_t buf[ATT_MAX_MTU];
				ssize_t nr = recv(conn->att_fd, buf,
				    conn->att->mtu, 0);
				if (nr <= 0) {
					blued_conn_disconnect(conn);
				} else {
					att_server_handle(conn->att,
					    conn->gatt_db, buf, (size_t)nr);
				}
			} else {
				hogp_event_loop_once(conn);
			}
			return;
		}
	}
}

static void
blued_event_loop(void)
{
	struct kevent events[32];
	int n, i;

	for (;;) {
		if (!running)
			return;
		n = kevent(blued_g.kq, NULL, 0, events,
		    (int)nitems(events), NULL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			warn("kevent");
			break;
		}
		for (i = 0; i < n; i++) {
			if (events[i].filter == EVFILT_SIGNAL) {
				LOG_HOGP(1, "signal %lu, shutting down",
				    (unsigned long)events[i].ident);
				return;
			}
			if (events[i].filter == EVFILT_TIMER) {
				struct blued_conn *tconn = events[i].udata;
				pthread_t tid;
				pthread_attr_t attr;

				pthread_attr_init(&attr);
				pthread_attr_setdetachstate(&attr,
				    PTHREAD_CREATE_DETACHED);
				tconn->state = BLUED_CONN_CONNECTING;
				if (pthread_create(&tid, &attr,
				    blued_conn_setup_central, tconn) != 0) {
					warn("reconnect thread");
					/*
					 * Re-arm the timer so we retry
					 * instead of leaving a zombie conn.
					 */
					tconn->state =
					    BLUED_CONN_RECONNECTING;
					{
						struct kevent tkev;
						EV_SET(&tkev,
						    (uintptr_t)tconn->reconnect_timer,
						    EVFILT_TIMER,
						    EV_ADD | EV_ONESHOT,
						    NOTE_SECONDS,
						    tconn->reconnect_delay,
						    tconn);
						(void)kevent(blued_g.kq,
						    &tkev, 1, NULL, 0, NULL);
					}
				}
				pthread_attr_destroy(&attr);
				continue;
			}
			if (events[i].filter == EVFILT_READ)
				blued_handle_readable(&events[i]);
			/* Stop processing stale events after disconnect */
			if (!running)
				return;
		}
	}
}

/*
 * Handle device disconnection detected by kqueue EV_EOF.
 * For peripheral: save CCCDs, free resources, re-enable advertising.
 * For central: if reconnect enabled, schedule reconnect timer.
 */
static void
blued_conn_disconnect(struct blued_conn *conn)
{
	struct kevent kev;
	char addr_str[18];

	bt_ntoa(&conn->dst, addr_str);
	LOG_HOGP(1, "device %s disconnected", addr_str);
	BLUED_PROBE_CONN_CLOSE(addr_str, 0);

	/* Deregister fd from kqueue before freeing */
	if (conn->att_fd >= 0) {
		EV_SET(&kev, conn->att_fd, EVFILT_READ,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	}

	if (conn->role == BLUED_ROLE_PERIPHERAL) {
		/* Save CCCDs for bonded device */
		if (blued_g.bond_db != NULL) {
			struct smp_bond *bond;

			bond = smp_find_bond(blued_g.bond_db,
			    (const uint8_t *)&conn->dst, conn->addr_type);
			if (bond != NULL) {
				smp_bond_save_cccds(bond, &periph_gatt_db);
				smp_bond_db_save(blued_g.bond_db);
				LOG_HOGP(1, "saved CCCD(s) for bonded device");
			}
		}

		/* blued_conn_free closes att_owned fd and frees att_owned */
		blued_conn_free(conn);

		/* Re-enable advertising */
		blued_periph_readvertise();
	} else {
		/* Central role */
		if (conn->reconnect) {
			/* Schedule reconnect via EVFILT_TIMER */
			conn->state = BLUED_CONN_RECONNECTING;
			if (conn->reconnect_delay == 0)
				conn->reconnect_delay = 3;
			LOG_HOGP(1, "reconnecting in %d seconds...",
			    conn->reconnect_delay);

			/* Close the old ATT fd */
			if (conn->att_fd >= 0) {
				close(conn->att_fd);
				conn->att_fd = -1;
			}
			if (conn->hogp != NULL) {
				att_close(&conn->hogp->att);
				if (conn->hogp->smp.fd >= 0)
					smp_close(&conn->hogp->smp);
				free(conn->hogp->report_map);
				conn->hogp->report_map = NULL;
				conn->hogp->nreports = 0;
			}

			/* Use a unique timer ident based on conn address */
			conn->reconnect_timer = (int)(uintptr_t)conn;
			EV_SET(&kev, (uintptr_t)conn->reconnect_timer,
			    EVFILT_TIMER,
			    EV_ADD | EV_ONESHOT, NOTE_SECONDS,
			    conn->reconnect_delay, conn);
			(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);

			/* Exponential backoff */
			conn->reconnect_delay *= 2;
			if (conn->reconnect_delay > blued_reconnect_max_delay)
				conn->reconnect_delay =
				    blued_reconnect_max_delay;
		} else {
			/* No reconnect — clean up */
			if (conn->hogp != NULL) {
				att_close(&conn->hogp->att);
				if (conn->hogp->smp.fd >= 0)
					smp_close(&conn->hogp->smp);
				free(conn->hogp->report_map);
				conn->hogp->report_map = NULL;
			}
			blued_conn_free(conn);
		}
	}
}

int
main(int argc, char *argv[])
{
	struct blued_config cfg;
	struct blued_adapter *adp;
	struct hogp_device dev;
	const char *config_path;
	int ch, i, nfound;

	/* 0. serviced integration: if launched by serviced, init service lib */
	if (getenv("ORACLED_PAIR_FD") != NULL) {
		if (service_init() == 0)
			blued_serviced = 1;
	}

	/* 1. Set config defaults */
	blued_config_defaults(&cfg);

	/* 2. First pass: find -c config file path */
	config_path = NULL;
	optreset = 1;
	optind = 1;
	while ((ch = getopt(argc, argv, "a:Bc:df:L:prsv")) != -1) {
		if (ch == 'c')
			config_path = optarg;
	}

	/* 3. Load config file (optional, ENOENT is OK) */
	if (blued_config_load(&cfg, config_path) < 0)
		warnx("failed to load config");

	/* 4. Apply all CLI overrides */
	blued_config_apply_cli(&cfg, argc, argv);
	argc -= optind;
	argv += optind;

	/* Apply config to globals */
	blued_verbose = cfg.loglevel;
	if (cfg.logfile[0] != '\0')
		hci_log_open(cfg.logfile);

	/* 5. Daemonize if requested (skip under serviced) */
	if (cfg.daemonize && !blued_serviced) {
		{
			pid_t otherpid;

			blued_pfh = pidfile_open(cfg.pidfile, 0600, &otherpid);
			if (blued_pfh == NULL) {
				if (errno == EEXIST)
					errx(1, "already running, pid %jd",
					    (intmax_t)otherpid);
				warn("pidfile_open");
			}
		}
		if (daemon(0, 0) < 0)
			err(1, "daemon");
		if (blued_pfh != NULL)
			pidfile_write(blued_pfh);
		openlog("blued", LOG_PID | LOG_NDELAY, LOG_DAEMON);
		blued_daemonized = 1;
		if (blued_verbose < 1)
			blued_verbose = 1;	/* at least log to syslog */
	}

	/*
	 * 6. Initialize global context.
	 * blued_g is BSS-initialized to zero; only set non-zero fields.
	 */
	LIST_INIT(&blued_g.adapters);
	LIST_INIT(&blued_g.conns);
	LIST_INIT(&blued_g.ctl_clients);
	blued_g.kq = -1;
	blued_g.ctl_fd = -1;
	blued_g.bond_fd = -1;
	blued_g.vhid_ctl_fd = -1;
	for (i = 0; i < BLUED_SOCK_POOL; i++)
		blued_g.att_pool[i] = -1;

	/* 7. Create kqueue */
	blued_g.kq = kqueue();
	if (blued_g.kq < 0)
		err(1, "kqueue");

	/* 8. Register EVFILT_SIGNAL for SIGTERM, SIGINT, SIGHUP */
	signal(SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	{
		struct kevent sigkev[3];

		EV_SET(&sigkev[0], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
		EV_SET(&sigkev[1], SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
		EV_SET(&sigkev[2], SIGHUP, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
		if (kevent(blued_g.kq, sigkev, nitems(sigkev),
		    NULL, 0, NULL) < 0)
			warn("kevent EVFILT_SIGNAL");
	}

	/* 9. Enumerate adapters */
	nfound = blued_enumerate_adapters(&cfg);
	if (nfound == 0)
		errx(1, "no Bluetooth adapters found");

	/* 10. Init each adapter */
	{
		struct blued_adapter *adp_tmp;

		LIST_FOREACH_SAFE(adp, &blued_g.adapters, entries, adp_tmp) {
			if (blued_adapter_init(adp) < 0) {
				close(adp->hci_fd);
				LIST_REMOVE(adp, entries);
				free(adp);
				continue;
			}
		}
	}

	/*
	 * 11. Adapter HCI fds are not yet registered with kqueue.
	 * TODO: register each adapter's hci_fd with EVFILT_READ once
	 * blued_handle_readable() has a handler branch for adapter events.
	 */

	/*
	 * For legacy hogp_device paths (scan, peripheral, central connect),
	 * bridge the first active adapter into the hogp_device struct.
	 */
	adp = LIST_FIRST(&blued_g.adapters);
	while (adp != NULL && !adp->active)
		adp = LIST_NEXT(adp, entries);
	if (adp == NULL)
		errx(1, "no active adapters after init");

	memset(&dev, 0, sizeof(dev));
	for (i = 0; i < SOCK_POOL_SIZE; i++)
		dev.att_pool[i] = -1;
	dev.addr_type = BDADDR_LE_PUBLIC;
	dev.bond_fd = -1;
	dev.vhid_ctl_fd = -1;
	dev.vhid_fd = -1;
	dev.hci_fd = adp->hci_fd;
	dev.adapter = adp->name;
	dev.le_features = adp->le_features;
	memcpy(dev.local_addr, &adp->addr, 6);
	dev.reconnect = cfg.reconnect;
	dev.debug = (blued_verbose >= 1);

	/* 16a. Scan mode: just show devices and exit */
	if (cfg.scan_mode) {
		do_scan(&dev);
		close(blued_g.kq);
		return (0);
	}

	/*
	 * 16b. Peripheral mode: build GATT DB, open bond file,
	 * start advertising, register ATT listen socket with kqueue,
	 * and fall through to the event loop.
	 */
	if (cfg.peripheral_mode) {
		uint8_t adv_data[31];
		int adv_len, listen_fd;

		/* Build the shared GATT database */
		peripheral_build_gattdb(&periph_gatt_db, periph_gatt_attrs,
		    periph_gatt_val_buf, sizeof(periph_gatt_val_buf));

		/* Open bond database — heap-allocate so threads can safely
		 * reference blued_g.bond_db without depending on main()'s
		 * stack frame lifetime. */
		blued_g.bond_fd = open(cfg.bonddb,
		    O_RDWR | O_CREAT | O_CLOEXEC | O_CLOFORK, 0600);
		if (blued_g.bond_fd >= 0) {
			struct smp_bond_db *bdb;

			bdb = calloc(1, sizeof(*bdb));
			if (bdb == NULL)
				err(1, "bond_db alloc");
			smp_bond_db_load(bdb, blued_g.bond_fd);
			blued_g.bond_db = bdb;
			/* Bridge into hogp_device for load_resolving_list */
			dev.bond_db = *bdb;
			dev.bond_fd = blued_g.bond_fd;
			load_resolving_list(&dev);
		}

		/* Build advertising data */
		{
			uint16_t uuids[] = { UUID_DIS_SERVICE,
			    UUID_CUSTOM_SERVICE };
			adv_len = ble_build_adv_data(adv_data,
			    sizeof(adv_data), PERIPHERAL_NAME, uuids, 2);
			if (adv_len < 0)
				err(1, "build advertising data");
		}

		/*
		 * Start advertising — try extended (BT 5.0+) first,
		 * fall back to legacy.
		 */
		if (hci_le_set_ext_adv_params(dev.hci_fd, 0x00,
		    0x0013 /* connectable + scannable + legacy ADV_IND */,
		    ADV_INTERVAL_100MS, ADV_INTERVAL_100MS, 0x00) == 0 &&
		    hci_le_set_ext_adv_data(dev.hci_fd, 0x00,
		    adv_data, (uint8_t)adv_len) == 0 &&
		    hci_le_set_ext_adv_enable(dev.hci_fd, 1, 0x00) == 0) {
			LOG_HOGP(1, "using extended advertising");
		} else {
			LOG_HOGP(1, "ext adv not supported, using legacy");
			if (hci_le_set_advertising_params(dev.hci_fd,
			    ADV_INTERVAL_100MS, ADV_INTERVAL_100MS,
			    0x00) < 0)
				err(1, "set advertising parameters");
			if (hci_le_set_advertising_data(dev.hci_fd,
			    adv_data, (uint8_t)adv_len) < 0)
				err(1, "set advertising data");
			if (hci_le_set_advertise_enable(dev.hci_fd,
			    true) < 0)
				err(1, "enable advertising");
		}

		LOG_HOGP(1, "advertising as \"%s\"", PERIPHERAL_NAME);

		/* Create ATT listen socket and register with kqueue */
		listen_fd = peripheral_att_listen();
		if (listen_fd < 0)
			err(1, "ATT listen socket");
		blued_g.periph_listen_fd = listen_fd;
		blued_g.periph_active = true;

		{
			struct kevent kev;

			EV_SET(&kev, listen_fd, EVFILT_READ,
			    EV_ADD | EV_ENABLE, 0, 0,
			    BLUED_KQ_PERIPH_LISTEN);
			if (kevent(blued_g.kq, &kev, 1, NULL, 0,
			    NULL) < 0)
				err(1, "kevent periph listen");
		}

		/* Create self-pipe for thread signaling */
		if (pipe2(blued_g.setup_pipe, O_CLOEXEC | O_NONBLOCK) < 0)
			err(1, "setup_pipe");
		{
			struct kevent kev;

			EV_SET(&kev, blued_g.setup_pipe[0], EVFILT_READ,
			    EV_ADD | EV_ENABLE, 0, 0, BLUED_KQ_SETUP_PIPE);
			if (kevent(blued_g.kq, &kev, 1, NULL, 0,
			    NULL) < 0)
				err(1, "kevent setup_pipe");
		}

		/* Init control socket */
		if (blued_ctl_init(cfg.ctlsock) < 0)
			warn("control socket init failed (non-fatal)");

		LOG_HOGP(1, "peripheral mode, entering event loop");
		running = 1;
		blued_event_loop();

		/* Shutdown: disable advertising */
		if (adp->le_features & LE_FEAT_EXT_ADVERTISING)
			hci_le_set_ext_adv_enable(adp->hci_fd, 0, 0x00);
		else
			hci_le_set_advertise_enable(adp->hci_fd, false);

		close(listen_fd);
		blued_ctl_cleanup();
		free(blued_g.bond_db);
		blued_g.bond_db = NULL;
		if (blued_g.bond_fd >= 0) {
			close(blued_g.bond_fd);
			blued_g.bond_fd = -1;
		}
		close(blued_g.kq);
		return (0);
	}

	/*
	 * Central mode: parse device addresses from config and/or argv.
	 */
	{
		int ndevs, ai;
		struct {
			uint8_t	addr[6];
			uint8_t	addr_type;
		} devs[16];

		ndevs = 0;

		/* Add devices from config file */
		for (i = 0; i < cfg.ndevices && ndevs < 16; i++) {
			memcpy(devs[ndevs].addr, cfg.devices[i].addr, 6);
			devs[ndevs].addr_type = cfg.devices[i].addr_type;
			ndevs++;
		}

		/* Add devices from argv */
		ai = 0;
		while (ai < argc && ndevs < 16) {
			if (!bt_aton(argv[ai],
			    (bdaddr_t *)devs[ndevs].addr))
				errx(1, "invalid bdaddr: %s", argv[ai]);
			devs[ndevs].addr_type = BDADDR_LE_PUBLIC;
			if (ai + 1 < argc &&
			    (strcmp(argv[ai + 1], "random") == 0 ||
			     strcmp(argv[ai + 1], "public") == 0)) {
				if (strcmp(argv[ai + 1], "random") == 0)
					devs[ndevs].addr_type =
					    BDADDR_LE_RANDOM;
				ai += 2;
			} else {
				ai += 1;
			}
			ndevs++;
		}

		if (ndevs == 0)
			usage();

		/* Use first device for the legacy hogp_device path */
		memcpy(dev.addr, devs[0].addr, 6);
		dev.addr_type = devs[0].addr_type;
	}

	/* 12. Open bond database */
	blued_g.bond_fd = open(cfg.bonddb,
	    O_RDWR | O_CREAT | O_CLOEXEC | O_CLOFORK, 0600);
	if (blued_g.bond_fd < 0)
		err(1, "open %s", cfg.bonddb);
	dev.bond_fd = blued_g.bond_fd;
	smp_bond_db_load(&dev.bond_db, dev.bond_fd);

	/* 13. Load resolving list */
	load_resolving_list(&dev);

	/* Open vhid control */
	blued_g.vhid_ctl_fd = open("/dev/vhid", O_RDWR | O_CLOEXEC | O_CLOFORK);
	if (blued_g.vhid_ctl_fd < 0)
		err(1, "open /dev/vhid");
	dev.vhid_ctl_fd = blued_g.vhid_ctl_fd;

	cleanup_dev = &dev;
	atexit(atexit_cleanup);

	/* 14. Init control socket */
	if (blued_ctl_init(cfg.ctlsock) < 0)
		warn("control socket init failed (non-fatal)");

	/* 15. serviced: register pair fd with kqueue, report ready */
	if (blued_serviced) {
		int pair_fd;

		pair_fd = service_pair_fd();
		if (pair_fd >= 0) {
			struct kevent kev;

			EV_SET(&kev, pair_fd, EVFILT_READ,
			    EV_ADD | EV_ENABLE, 0, 0, NULL);
			if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0)
				warn("kevent service_pair_fd");
		}
		service_register("org.5bsd.blued");
		service_ready();
	}

	/*
	 * 16c. Central mode: connect to the device using the legacy
	 * connection path.  This preserves all existing HOGP logic
	 * (pairing, discovery, vhid, capsicum) while the kqueue event
	 * loop is phased in.
	 */
	{
		static int reconnect_delay = 0;	/* exponential backoff */
		static bool sandboxed = false;

	do {
		if (reconnect_delay > 0) {
			LOG_HOGP(1, "reconnecting in %d seconds...",
			    reconnect_delay);
			sleep(reconnect_delay);
			reconnect_delay = reconnect_delay * 2;
			if (reconnect_delay > cfg.reconnect_max_delay)
				reconnect_delay = cfg.reconnect_max_delay;
		}
		dev.att.fd = -1;
		dev.smp.fd = -1;

		/*
		 * Phase 1: Connect ATT
		 */
		{
			char addr_str[18];
			bt_ntoa((bdaddr_t *)dev.addr, addr_str);
			LOG_HOGP(1, "connecting to %s...", addr_str);
		}

		{
			int att_fd, ret;

			att_fd = pool_take(dev.att_pool, &dev.att_pool_next,
			    SOCK_POOL_SIZE);
			if (att_fd >= 0) {
				ret = att_open_fd(&dev.att, att_fd, dev.addr,
				    dev.addr_type);
			} else if (sandboxed) {
				warnx("socket pool exhausted, "
				    "cannot reconnect in sandbox");
				break;
			} else {
				ret = att_open(&dev.att, dev.addr,
				    dev.addr_type);
			}

			if (ret < 0) {
				if (dev.reconnect && running) {
					warn("ATT connect failed");
					if (reconnect_delay == 0)
						reconnect_delay = 3;
					continue;
				}
				err(1, "ATT connect");
			}
		}

		reconnect_delay = 0;
		LOG_HOGP(1, "connected, exchanging MTU");

		/* Get connection handle */
		{
			int retries;
			for (retries = 0; retries < 5; retries++) {
				if (hci_get_con_handle(dev.hci_fd, dev.addr,
				    &dev.con_handle) == 0)
					break;
				usleep(200000);
			}
			if (retries == 5)
				errx(1, "could not get HCI connection handle");
			LOG_HOGP(1, "connection handle=%04x",
			    dev.con_handle);
			dev.att.con_handle = dev.con_handle;
		}

		/* Request optimal link parameters */
		if (dev.le_features & LE_FEAT_DATA_LENGTH_EXT)
			hci_le_set_data_length(dev.hci_fd, dev.con_handle,
			    0x00FB, 0x0848);
		if (dev.le_features & LE_FEAT_2M_PHY)
			hci_le_set_phy(dev.hci_fd, dev.con_handle, 0x00,
			    0x02, 0x02, 0x0000);

		hci_le_connection_update(dev.hci_fd, dev.con_handle,
		    6, 12, 4, 500);

		if (att_exchange_mtu(&dev.att, ATT_MAX_MTU) < 0)
			warn("MTU exchange failed, using default %d",
			    ATT_DEFAULT_MTU);
		else
			LOG_HOGP(1, "MTU=%d", dev.att.mtu);

		/* Try EATT bearers */
		if (cfg.eatt)
			att_open_eatt(&dev.att, dev.addr, dev.addr_type, 2);

		/*
		 * Phase 2a: Attempt encryption with existing bond, or pair.
		 */
		{
			struct smp_bond *bond;

			bond = smp_find_bond(&dev.bond_db, dev.addr,
			    dev.addr_type);
			if (bond != NULL) {
				LOG_HOGP(1, "found existing bond, "
				    "encrypting...");
				dev.smp.hci_fd = dev.hci_fd;
				dev.smp.con_handle = dev.con_handle;
				if (smp_encrypt_with_ltk(&dev.smp, bond) < 0) {
					warn("bonded encryption failed");
				} else {
					LOG_HOGP(1, "waiting for "
					    "encryption...");
					if (hci_wait_encryption(dev.hci_fd,
					    dev.con_handle, 10) < 0)
						warn("encryption timeout");
					else {
						dev.att.encrypted = true;
						LOG_HOGP(1, "encrypted");
					}
				}
			}
		}

		/*
		 * Phase 2b: Discover HOGP services
		 */
		{
			int ret = hogp_discover(&dev);

			if (ret == ATT_ERR_INSUFF_AUTHEN ||
			    ret == ATT_ERR_INSUFF_ENCRYPTION) {
				LOG_HOGP(1, "device requires pairing");

				if (smp_open(&dev.smp, dev.addr,
				    dev.addr_type, dev.local_addr, 0,
				    dev.hci_fd, dev.con_handle,
				    &dev.bond_db) < 0)
					err(1, "SMP open");
				dev.smp.passkey_cb = passkey_display;
				dev.smp.numcmp_cb = numcmp_confirm;

				if (smp_pair(&dev.smp) < 0)
					err(1, "SMP pairing");

				if (hci_wait_encryption(dev.hci_fd,
				    dev.con_handle, 10) < 0)
					warn("post-pairing encryption "
					    "timeout");
				else
					dev.att.encrypted = true;

				LOG_HOGP(1, "pairing complete, retrying "
				    "discovery");

				ret = hogp_discover(&dev);
			}
			if (ret != 0)
				errx(1, "HOGP discovery failed: %d", ret);
		}

		/*
		 * Read GATT Database Hash for caching.
		 */
		{
			uint8_t remote_hash[16];
			size_t hlen = 0;

			if (att_read_by_type(&dev.att, 0x0001, 0xFFFF,
			    UUID_DATABASE_HASH, remote_hash, 16, &hlen) == 0 &&
			    hlen == 16) {
				struct smp_bond *bond = smp_find_bond(
				    &dev.bond_db, dev.addr, dev.addr_type);
				if (bond != NULL) {
					if (bond->has_db_hash &&
					    memcmp(bond->db_hash, remote_hash,
					    16) == 0)
						LOG_HOGP(1, "GATT DB hash "
						    "unchanged, cache valid");
					else
						LOG_HOGP(1, "GATT DB hash "
						    "changed or new, full "
						    "discovery done");
					memcpy(bond->db_hash, remote_hash, 16);
					bond->has_db_hash = true;
					smp_bond_db_save(&dev.bond_db);
				}
			}
		}

		/* Save device name to bond */
		if (dev.has_device_name) {
			struct smp_bond *bond = smp_find_bond(&dev.bond_db,
			    dev.addr, dev.addr_type);
			if (bond != NULL && !bond->has_name) {
				strlcpy(bond->name, dev.device_name,
				    sizeof(bond->name));
				bond->has_name = true;
				smp_bond_db_save(&dev.bond_db);
			}
		}

		/*
		 * Phase 3: Set up vhid device
		 */
		if (dev.vhid_fd < 0) {
			if (hogp_setup_vhid(&dev) != 0)
				err(1, "vhid setup");
		}

		/*
		 * Phase 4: Subscribe to report notifications
		 */
		if (hogp_subscribe(&dev) != 0)
			err(1, "HOGP subscribe");

		/* Write Exit Suspend to HID Control Point */
		if (dev.hid_ctrl_handle != 0) {
			uint8_t exit_suspend = 0x01;
			att_write_cmd(&dev.att, dev.hid_ctrl_handle,
			    &exit_suspend, 1);
		}

		/*
		 * Phase 5: Enter Capsicum sandbox (once only).
		 *
		 * 17. Pre-allocate socket pools for Capsicum.
		 * 18. Enter Capsicum sandbox.
		 */
		{
			if (!sandboxed) {
				smp_close(&dev.smp);

				if (dev.reconnect) {
					dev.att_pool_next = 0;
					if (pool_create(dev.att_pool,
					    SOCK_POOL_SIZE) < 0)
						warn("ATT socket pool "
						    "creation failed");
				}
				if (capsicum_sandbox(&dev) != 0)
					err(1, "capsicum sandbox");
				sandboxed = true;
			}
		}

		LOG_HOGP(1, "sandbox active, entering event loop");

		/*
		 * Phase 6: Event loop — register ATT fd with kqueue
		 * and enter the unified event loop.
		 */
		{
			struct blued_conn *conn;

			conn = blued_conn_alloc();
			if (conn == NULL)
				err(1, "blued_conn_alloc");
			conn->att_fd = dev.att.fd;
			conn->att = &dev.att;
			conn->hogp = &dev;
			memcpy(&conn->dst, dev.addr, sizeof(conn->dst));
			conn->addr_type = dev.addr_type;
			conn->con_handle = dev.con_handle;
			conn->state = BLUED_CONN_ACTIVE;

			{
				char addr_str[18];
				bt_ntoa(&conn->dst, addr_str);
				BLUED_PROBE_CONN_OPEN(addr_str,
				    0 /* central */);
			}

			if (blued_conn_register(conn) < 0)
				err(1, "blued_conn_register");

			running = 1;
			blued_event_loop();

			/*
			 * blued_event_loop() returned — either signal
			 * or disconnect.  Remove conn if still in list.
			 */
			LIST_FOREACH(conn, &blued_g.conns, entries) {
				if (conn->att == &dev.att) {
					blued_conn_free(conn);
					break;
				}
			}
		}

		/*
		 * Write Suspend before disconnect — only if we
		 * exited by signal (fd still connected), not if
		 * the peer already disconnected (EV_EOF).
		 */
		if (dev.att.fd >= 0 && dev.hid_ctrl_handle != 0) {
			struct pollfd pfd;

			pfd.fd = dev.att.fd;
			pfd.events = 0;
			if (poll(&pfd, 1, 0) >= 0 &&
			    !(pfd.revents & (POLLERR | POLLHUP))) {
				uint8_t suspend = 0x00;

				att_write_cmd(&dev.att,
				    dev.hid_ctrl_handle, &suspend, 1);
			}
		}

		/* Clean up connection resources */
		att_close(&dev.att);
		if (dev.smp.fd >= 0)
			smp_close(&dev.smp);

		if (!dev.reconnect || !running) {
			if (dev.vhid_fd >= 0) {
				close(dev.vhid_fd);
				dev.vhid_fd = -1;
			}
			if (dev.vhid_ctl_fd >= 0)
				ioctl(dev.vhid_ctl_fd, VHID_DESTROY,
				    &dev.vhid_unit);
		}

		free(dev.report_map);
		dev.report_map = NULL;
		dev.nreports = 0;

		if (dev.reconnect && running)
			reconnect_delay = 3;
	} while (dev.reconnect && running);
	}

	/* Prevent atexit from double-cleaning */
	cleanup_dev = NULL;

	/* Final cleanup — close fds through blued_g/adp (canonical owners) */
	blued_ctl_cleanup();
	if (blued_g.vhid_ctl_fd >= 0) {
		close(blued_g.vhid_ctl_fd);
		blued_g.vhid_ctl_fd = -1;
	}
	if (blued_g.bond_fd >= 0) {
		close(blued_g.bond_fd);
		blued_g.bond_fd = -1;
	}
	if (blued_g.kq >= 0)
		close(blued_g.kq);

	/* Close all adapter fds */
	{
		struct blued_adapter *adp_tmp;
		while ((adp_tmp = LIST_FIRST(&blued_g.adapters)) != NULL) {
			LIST_REMOVE(adp_tmp, entries);
			if (adp_tmp->hci_fd >= 0)
				close(adp_tmp->hci_fd);
			free(adp_tmp);
		}
	}

	for (i = 0; i < SOCK_POOL_SIZE; i++) {
		if (dev.att_pool[i] >= 0)
			close(dev.att_pool[i]);
	}
	if (blued_pfh != NULL) {
		pidfile_remove(blued_pfh);
		blued_pfh = NULL;
	}

	return (0);
}

/*
 * Process a single HID Service instance: read its Report Map,
 * classify Report characteristics, read HID Information,
 * save HID Control Point handle, set Protocol Mode.
 */
static int
hogp_process_service(struct hogp_device *dev, struct gatt_discovery *disc)
{
	int ret;
	size_t len;

	/*
	 * Read Report Map characteristic (UUID 0x2A4B).
	 * This contains the HID Report Descriptor.
	 * Report Map can be longer than MTU-1, use read blob.
	 */
	for (int i = 0; i < disc->nchars; i++) {
		if (disc->chars[i].uuid16 != UUID_REPORT_MAP)
			continue;

		uint8_t buf[4096];
		size_t total = 0;
		uint16_t handle = disc->chars[i].value_handle;

		ret = att_read(&dev->att, handle, buf, sizeof(buf), &len);
		if (ret != 0) {
			warnx("failed to read Report Map");
			return (ret);
		}
		total = len;

		while (len == (size_t)(dev->att.mtu - 1) &&
		    total < sizeof(buf)) {
			ret = att_read_blob(&dev->att, handle, total,
			    buf + total, sizeof(buf) - total, &len);
			if (ret != 0)
				break;
			total += len;
		}

		if (dev->report_map == NULL) {
			dev->report_map = malloc(total);
			if (dev->report_map == NULL)
				return (ENOMEM);
			memcpy(dev->report_map, buf, total);
			dev->report_map_len = total;
		} else {
			/* Concatenate report maps from multiple services */
			uint8_t *p = realloc(dev->report_map,
			    dev->report_map_len + total);
			if (p == NULL)
				return (ENOMEM);
			memcpy(p + dev->report_map_len, buf, total);
			dev->report_map = p;
			dev->report_map_len += total;
		}

		LOG_HOGP(1, "Report Map: %zu bytes", total);
		break;
	}

	/*
	 * Classify Report characteristics (UUID 0x2A4D).
	 * Each Report has a Report Reference descriptor (UUID 0x2908)
	 * that tells us the report ID and type (input/output/feature).
	 */
	for (int i = 0; i < disc->nchars; i++) {
		if (disc->chars[i].uuid16 != UUID_REPORT)
			continue;
		if (dev->nreports >= HOGP_MAX_REPORTS)
			break;

		struct hogp_report *rpt = &dev->reports[dev->nreports];
		rpt->value_handle = disc->chars[i].value_handle;
		rpt->cccd_handle = 0;
		rpt->report_id = 0;
		rpt->report_type = 0;

		uint16_t desc_start = rpt->value_handle + 1;
		uint16_t desc_end;
		if (i + 1 < disc->nchars)
			desc_end = disc->chars[i + 1].decl_handle - 1;
		else
			desc_end = disc->service.end_handle;

		for (int j = 0; j < disc->ndescs; j++) {
			uint16_t dh = disc->descs[j].handle;
			if (dh < desc_start || dh > desc_end)
				continue;

			if (disc->descs[j].uuid16 ==
			    GATT_UUID_REPORT_REFERENCE) {
				uint8_t ref[2];
				ret = att_read(&dev->att, dh, ref,
				    sizeof(ref), &len);
				if (ret == 0 && len >= 2) {
					rpt->report_id = ref[0];
					rpt->report_type = ref[1];
				}
			} else if (disc->descs[j].uuid16 ==
			    GATT_UUID_CCCD) {
				rpt->cccd_handle = dh;
			}
		}

		dev->nreports++;

		LOG_HOGP(1, "Report handle=%04x id=%d type=%d "
			    "cccd=%04x",
			    rpt->value_handle, rpt->report_id,
			    rpt->report_type, rpt->cccd_handle);
	}

	/*
	 * Read HID Information (UUID 0x2A4A) — mandatory per HOGP §3.2.
	 * Format: [bcdHID (2 LE), bCountryCode (1), Flags (1)]
	 */
	for (int i = 0; i < disc->nchars; i++) {
		if (disc->chars[i].uuid16 != UUID_HID_INFORMATION)
			continue;

		uint8_t info[4];
		ret = att_read(&dev->att, disc->chars[i].value_handle,
		    info, sizeof(info), &len);
		if (ret == 0 && len >= 4) {
			dev->hid_bcdHID = (uint16_t)info[0] |
			    ((uint16_t)info[1] << 8);
			LOG_HOGP(1, "HID Information: bcdHID=%04x "
				    "country=%d flags=%02x",
				    dev->hid_bcdHID, info[2], info[3]);
		}
		break;
	}

	/*
	 * Save HID Control Point handle (UUID 0x2A4C).
	 * Used for Suspend/Exit Suspend per HOGP.
	 */
	for (int i = 0; i < disc->nchars; i++) {
		if (disc->chars[i].uuid16 == UUID_HID_CONTROL_POINT) {
			dev->hid_ctrl_handle = disc->chars[i].value_handle;
			break;
		}
	}

	/*
	 * Set Protocol Mode to Report Protocol (0x01).
	 */
	for (int i = 0; i < disc->nchars; i++) {
		if (disc->chars[i].uuid16 == UUID_PROTOCOL_MODE) {
			uint8_t mode = HID_PROTOCOL_REPORT;
			att_write_cmd(&dev->att,
			    disc->chars[i].value_handle,
			    &mode, 1);
			LOG_HOGP(1, "set Report Protocol mode");
			break;
		}
	}

	return (0);
}

/*
 * Read PnP ID from Device Information Service (0x180A).
 * PnP ID (UUID 0x2A50) is 7 bytes:
 *   vendor_id_source(1) + vendor_id(2 LE) + product_id(2 LE) + product_version(2 LE)
 *
 * Non-fatal: if DIS or PnP ID is absent, idVendor/idProduct stay 0.
 */
static void
hogp_read_dis_pnpid(struct hogp_device *dev, struct gatt_service *dis)
{
	struct gatt_char chars[GATT_MAX_CHARS];
	int nchars, ret;
	size_t len;

	ret = gatt_discover_characteristics(&dev->att,
	    dis->start_handle, dis->end_handle,
	    chars, GATT_MAX_CHARS, &nchars);
	if (ret != 0)
		return;

	for (int i = 0; i < nchars; i++) {
		if (chars[i].uuid16 != UUID_PNP_ID)
			continue;

		uint8_t pnp[7];
		ret = att_read(&dev->att, chars[i].value_handle,
		    pnp, sizeof(pnp), &len);
		if (ret != 0 || len < 7)
			break;

		dev->idVendor = (uint16_t)pnp[1] |
		    ((uint16_t)pnp[2] << 8);
		dev->idProduct = (uint16_t)pnp[3] |
		    ((uint16_t)pnp[4] << 8);

		LOG_HOGP(1, "DIS PnP ID: source=%d vendor=%04x "
			    "product=%04x version=%04x",
			    pnp[0], dev->idVendor, dev->idProduct,
			    (uint16_t)pnp[5] | ((uint16_t)pnp[6] << 8));
		break;
	}
}

/*
 * Read Battery Level from Battery Service (0x180F).
 * Battery Level (UUID 0x2A19) is a single byte (0-100 %).
 *
 * Non-fatal: if Battery Service or Battery Level is absent, nothing happens.
 * Per HOGP v1.0 Section 2: the HID Host shall discover the Battery Service.
 */
static void
hogp_read_battery(struct hogp_device *dev, struct gatt_service *bas)
{
	struct gatt_char chars[GATT_MAX_CHARS];
	int nchars, ret;
	size_t len;

	ret = gatt_discover_characteristics(&dev->att,
	    bas->start_handle, bas->end_handle,
	    chars, GATT_MAX_CHARS, &nchars);
	if (ret != 0)
		return;

	for (int i = 0; i < nchars; i++) {
		if (chars[i].uuid16 != UUID_BATTERY_LEVEL)
			continue;

		uint8_t level;
		ret = att_read(&dev->att, chars[i].value_handle,
		    &level, sizeof(level), &len);
		if (ret != 0 || len < 1)
			break;

		LOG_HOGP(1, "Battery Level: %u%%", level);
		break;
	}
}

/*
 * Discover HID Service (0x1812), read Report Map, classify reports.
 * Handles multiple HID Service instances (e.g., combo keyboard+mouse).
 */
static int
hogp_discover(struct hogp_device *dev)
{
	struct gatt_service svcs[GATT_MAX_SERVICES];
	int nsvcs, ret, nsvc_found = 0;

	free(dev->report_map);
	dev->report_map = NULL;
	dev->report_map_len = 0;
	dev->nreports = 0;
	dev->hid_ctrl_handle = 0;
	dev->hid_bcdHID = 0;
	dev->idVendor = 0;
	dev->idProduct = 0;

	/* Discover all primary services */
	ret = gatt_discover_primary_services(&dev->att, svcs,
	    GATT_MAX_SERVICES, &nsvcs);
	if (ret != 0)
		return (ret);

	/* Read Device Name from GAP Service (UUID 0x2A00) if present */
	for (int s = 0; s < nsvcs; s++) {
		if (svcs[s].uuid16 == UUID_GAP_SERVICE) {
			uint8_t val[32];
			size_t vlen = 0;

			if (att_read_by_type(&dev->att, svcs[s].start_handle,
			    svcs[s].end_handle, UUID_DEVICE_NAME, val,
			    sizeof(val),
			    &vlen) == 0 && vlen > 0) {
				int nlen = (int)(vlen > 31 ? 31 : vlen);
				memcpy(dev->device_name, val, nlen);
				dev->device_name[nlen] = '\0';
				dev->has_device_name = true;
				LOG_HOGP(1, "device name: %s",
				    dev->device_name);
			}
			break;
		}
	}

	/* Read PnP ID from Device Information Service if present */
	for (int s = 0; s < nsvcs; s++) {
		if (svcs[s].uuid16 == UUID_DEVICE_INFO_SERVICE) {
			hogp_read_dis_pnpid(dev, &svcs[s]);
			break;
		}
	}

	/* Read Battery Level from Battery Service if present
	 * (mandatory per HOGP v1.0 Section 2) */
	for (int s = 0; s < nsvcs; s++) {
		if (svcs[s].uuid16 == UUID_BATTERY_SERVICE) {
			hogp_read_battery(dev, &svcs[s]);
			break;
		}
	}

	/* Iterate all HID Service instances */
	for (int s = 0; s < nsvcs; s++) {
		if (svcs[s].uuid16 != UUID_HID_SERVICE)
			continue;

		nsvc_found++;

		LOG_HOGP(1, "HID Service found, handles %04x-%04x",
			    svcs[s].start_handle, svcs[s].end_handle);

		/* Discover characteristics and descriptors for this instance */
		struct gatt_discovery disc;
		memset(&disc, 0, sizeof(disc));
		disc.service = svcs[s];

		ret = gatt_discover_characteristics(&dev->att,
		    disc.service.start_handle, disc.service.end_handle,
		    disc.chars, GATT_MAX_CHARS, &disc.nchars);
		if (ret != 0)
			return (ret);

		disc.ndescs = 0;
		for (int i = 0; i < disc.nchars; i++) {
			uint16_t desc_start = disc.chars[i].value_handle + 1;
			uint16_t desc_end;
			if (i + 1 < disc.nchars)
				desc_end = disc.chars[i + 1].decl_handle - 1;
			else
				desc_end = disc.service.end_handle;
			if (desc_start > desc_end)
				continue;

			int ndesc;
			ret = gatt_discover_descriptors(&dev->att,
			    desc_start, desc_end,
			    disc.descs + disc.ndescs,
			    GATT_MAX_DESCS - disc.ndescs, &ndesc);
			if (ret != 0)
				return (ret);
			disc.ndescs += ndesc;
		}

		/* Keep first instance for backward compat */
		if (svcs[s].start_handle == svcs[0].start_handle ||
		    dev->hid_disc.service.start_handle == 0)
			dev->hid_disc = disc;

		ret = hogp_process_service(dev, &disc);
		if (ret != 0)
			return (ret);
	}

	if (nsvc_found == 0) {
		warnx("HID Service (0x1812) not found");
		return (ENOENT);
	}

	if (dev->report_map == NULL) {
		warnx("Report Map characteristic not found");
		return (ENOENT);
	}

	LOG_HOGP(1, "total: %d reports, %zu bytes report map"
		    " from %d service(s)",
		    dev->nreports, dev->report_map_len, nsvc_found);

	return (0);
}

/*
 * Create a /dev/vhidN device and configure it with the Report Map.
 */
static int
hogp_setup_vhid(struct hogp_device *dev)
{
	struct vhid_attach_arg arg;
	char path[32];
	ssize_t n;

	/* Create a new vhid instance */
	if (ioctl(dev->vhid_ctl_fd, VHID_CREATE, &dev->vhid_unit) < 0)
		return (-1);

	snprintf(path, sizeof(path), "/dev/vhid%d", dev->vhid_unit);
	dev->vhid_fd = open(path, O_RDWR | O_CLOEXEC | O_CLOFORK);
	if (dev->vhid_fd < 0)
		return (-1);

	/* Write report descriptor, then attach */
	n = write(dev->vhid_fd, dev->report_map, dev->report_map_len);
	if (n < 0 || (size_t)n != dev->report_map_len)
		return (-1);

	memset(&arg, 0, sizeof(arg));
	arg.idVendor = dev->idVendor;
	arg.idProduct = dev->idProduct;
	arg.idVersion = dev->hid_bcdHID;	/* from HID Information */
	strlcpy(arg.name, "BLE HID Device", sizeof(arg.name));

	if (ioctl(dev->vhid_fd, VHID_ATTACH, &arg) < 0)
		return (-1);

	LOG_HOGP(1, "vhid%d configured", dev->vhid_unit);

	return (0);
}

/*
 * Subscribe to notifications on all Input Report characteristics.
 */
static int
hogp_subscribe(struct hogp_device *dev)
{
	int ret, any_success = 0, any_input = 0;

	for (int i = 0; i < dev->nreports; i++) {
		struct hogp_report *rpt = &dev->reports[i];

		if (rpt->report_type != HID_REPORT_TYPE_INPUT)
			continue;
		if (rpt->cccd_handle == 0)
			continue;

		any_input = 1;

		/* Write 0x0001 to CCCD to enable notifications */
		uint8_t val[2] = { 0x01, 0x00 };
		ret = att_write_req(&dev->att, rpt->cccd_handle,
		    val, sizeof(val));
		if (ret != 0)
			warnx("failed to enable notifications for "
			    "handle %04x", rpt->value_handle);
		else {
			any_success = 1;
			LOG_HOGP(1, "notifications enabled "
				    "for report id=%d handle=%04x",
				    rpt->report_id, rpt->value_handle);
		}
	}

	if (any_input && !any_success) {
		warnx("all CCCD writes failed, no notifications will arrive");
		return (-1);
	}
	return (0);
}

/*
 * Enter Capsicum sandbox.
 *
 * At this point we hold all the fds we need:
 *   - att.fd (L2CAP ATT socket)
 *   - vhid_fd (/dev/vhidN for report injection)
 *   - bond_fd (bond storage file)
 *   - hci_fd (raw HCI socket)
 *
 * We no longer need:
 *   - vhid_ctl_fd (/dev/vhid — already created the instance)
 *   - filesystem access
 */
static int
capsicum_sandbox(struct hogp_device *dev)
{
	cap_rights_t rights;

	/* vhid control: ioctl only (for VHID_DESTROY on cleanup) */
	cap_rights_init(&rights, CAP_IOCTL);
	if (cap_rights_limit(dev->vhid_ctl_fd, &rights) < 0)
		return (-1);
	{
		unsigned long ioctls[] = { VHID_DESTROY };
		if (cap_ioctls_limit(dev->vhid_ctl_fd, ioctls, 1) < 0)
			return (-1);
	}

	/* ATT socket: send + recv */
	cap_rights_init(&rights, CAP_SEND, CAP_RECV, CAP_EVENT);
	if (cap_rights_limit(dev->att.fd, &rights) < 0)
		return (-1);

	/* EATT bearer sockets: same rights as primary ATT */
	{
		int ei;
		for (ei = 0; ei < dev->att.eatt_count; ei++) {
			if (dev->att.eatt[ei].active &&
			    dev->att.eatt[ei].fd >= 0) {
				cap_rights_init(&rights, CAP_SEND, CAP_RECV,
				    CAP_EVENT);
				if (cap_rights_limit(dev->att.eatt[ei].fd,
				    &rights) < 0)
					return (-1);
			}
		}
	}

	/* vhid device: write only (report injection) */
	cap_rights_init(&rights, CAP_WRITE);
	if (cap_rights_limit(dev->vhid_fd, &rights) < 0)
		return (-1);

	/* Bond storage: read + write + seek + flock */
	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_SEEK, CAP_FLOCK);
	if (cap_rights_limit(dev->bond_fd, &rights) < 0)
		return (-1);

	/*
	 * HCI socket: send/recv for raw HCI commands, read/write for
	 * libbluetooth bt_devrecv()/bt_devsend() which use read()/writev(),
	 * ioctl for connection list, sockopt for devfilter.
	 */
	cap_rights_init(&rights, CAP_SEND, CAP_RECV, CAP_READ, CAP_WRITE,
	    CAP_EVENT, CAP_IOCTL, CAP_SETSOCKOPT, CAP_GETSOCKOPT);
	if (cap_rights_limit(dev->hci_fd, &rights) < 0)
		return (-1);
	{
		unsigned long hci_ioctls[] = {
		    SIOC_HCI_RAW_NODE_GET_CON_LIST
		};
		if (cap_ioctls_limit(dev->hci_fd, hci_ioctls,
		    nitems(hci_ioctls)) < 0)
			return (-1);
	}

	/* Pool sockets: connect + send + recv (for reconnection) */
	if (dev->reconnect) {
		cap_rights_init(&rights, CAP_CONNECT, CAP_SEND, CAP_RECV,
		    CAP_EVENT, CAP_SETSOCKOPT);
		for (int i = dev->att_pool_next; i < SOCK_POOL_SIZE; i++) {
			if (dev->att_pool[i] >= 0)
				cap_rights_limit(dev->att_pool[i], &rights);
		}
	}

	/* kqueue fd: event registration and polling only */
	cap_rights_init(&rights, CAP_KQUEUE_EVENT, CAP_EVENT);
	if (cap_rights_limit(blued_g.kq, &rights) < 0)
		return (-1);

	/* control socket: accept + event + send/recv */
	if (blued_g.ctl_fd >= 0) {
		cap_rights_init(&rights, CAP_ACCEPT, CAP_EVENT, CAP_RECV,
		    CAP_SEND);
		if (cap_rights_limit(blued_g.ctl_fd, &rights) < 0)
			return (-1);
	}

	/* Enter capability mode */
	if (cap_enter() < 0)
		return (-1);

	BLUED_PROBE_SANDBOX_ENTER();
	LOG_HOGP(1, "entered Capsicum sandbox");

	return (0);
}

/*
 * Process a single ATT notification/indication from a kqueue-managed
 * connection.  Called when EVFILT_READ fires on the ATT fd.
 */
static void
hogp_event_loop_once(struct blued_conn *conn)
{
	struct hogp_device *dev;
	uint8_t buf[ATT_MAX_MTU];
	size_t len;

	dev = conn->hogp;
	if (dev == NULL)
		return;

	if (att_recv(&dev->att, buf, sizeof(buf), &len) < 0)
		return;

	if (len < 3)
		return;

	{
		uint8_t opcode = buf[0];

		if (opcode == ATT_OP_HANDLE_NOTIFY) {
			uint16_t handle = (uint16_t)buf[1] |
			    ((uint16_t)buf[2] << 8);
			uint8_t *report_data = buf + 3;
			size_t report_len = len - 3;
			int i;

			for (i = 0; i < dev->nreports; i++) {
				if (dev->reports[i].value_handle != handle)
					continue;

				BLUED_PROBE_HID_REPORT(
				    dev->reports[i].report_id,
				    (int)report_len);

				if (dev->reports[i].report_id != 0) {
					uint8_t full[VHID_MAX_REPORT];
					full[0] = dev->reports[i].report_id;
					if (report_len + 1 > sizeof(full))
						break;
					memcpy(full + 1, report_data,
					    report_len);
					if (write(dev->vhid_fd, full,
					    report_len + 1) < 0 &&
					    errno != EAGAIN)
						warn("vhid write");
				} else {
					if (write(dev->vhid_fd, report_data,
					    report_len) < 0 &&
					    errno != EAGAIN)
						warn("vhid write");
				}
				break;
			}
		} else if (opcode == ATT_OP_HANDLE_IND) {
			att_confirm(&dev->att);
		}
	}
}

/*
 * Main event loop: receive ATT notifications and inject reports.
 *
 * BLE HID devices send Handle Value Notifications (opcode 0x1B)
 * on Report characteristics.  We extract the handle and data,
 * match to a report, and write to /dev/vhidN.
 */
static void __unused
hogp_event_loop(struct hogp_device *dev)
{
	struct pollfd pfd;
	uint8_t buf[ATT_MAX_MTU];
	size_t len;

	pfd.fd = dev->att.fd;
	pfd.events = POLLIN;

	while (running) {
		if (poll(&pfd, 1, 1000) < 0) {
			if (errno == EINTR)
				continue;
			warn("poll");
			break;
		}

		if (pfd.revents & (POLLERR | POLLHUP)) {
			warnx("BLE link disconnected, exiting for restart");
			break;
		}

		if (!(pfd.revents & POLLIN))
			continue;

		if (att_recv(&dev->att, buf, sizeof(buf), &len) < 0) {
			warn("att_recv");
			break;
		}

		if (len < 3)
			continue;

		uint8_t opcode = buf[0];

		if (opcode == ATT_OP_HANDLE_NOTIFY) {
			uint16_t handle = (uint16_t)buf[1] |
			    ((uint16_t)buf[2] << 8);
			uint8_t *report_data = buf + 3;
			size_t report_len = len - 3;

			/* Match handle to a report */
			for (int i = 0; i < dev->nreports; i++) {
				if (dev->reports[i].value_handle != handle)
					continue;

				/*
				 * Prepend report ID if non-zero.
				 * HID spec requires the report ID byte
				 * at the start of the report when there
				 * are multiple report IDs.
				 */
				if (dev->reports[i].report_id != 0) {
					uint8_t full[VHID_MAX_REPORT];
					full[0] = dev->reports[i].report_id;
					if (report_len + 1 > sizeof(full))
						break;
					memcpy(full + 1, report_data,
					    report_len);
					if (write(dev->vhid_fd, full,
					    report_len + 1) < 0 &&
					    errno != EAGAIN)
						warn("vhid write");
				} else {
					if (write(dev->vhid_fd, report_data,
					    report_len) < 0 &&
					    errno != EAGAIN)
						warn("vhid write");
				}
				break;
			}
		} else if (opcode == ATT_OP_HANDLE_IND) {
			/* Indication — must confirm */
			att_confirm(&dev->att);
		}
	}
}

static void
hogp_cleanup(struct hogp_device *dev)
{

	hci_log_close();
	att_close(&dev->att);
	smp_close(&dev->smp);
	if (dev->vhid_fd >= 0) {
		close(dev->vhid_fd);
		dev->vhid_fd = -1;
	}
	if (dev->vhid_ctl_fd >= 0) {
		ioctl(dev->vhid_ctl_fd, VHID_DESTROY, &dev->vhid_unit);
		close(dev->vhid_ctl_fd);
		dev->vhid_ctl_fd = -1;
	}
	if (dev->hci_fd >= 0) {
		close(dev->hci_fd);
		dev->hci_fd = -1;
	}
	if (dev->bond_fd >= 0) {
		close(dev->bond_fd);
		dev->bond_fd = -1;
	}
	free(dev->report_map);
	dev->report_map = NULL;
}

/* ----------------------------------------------------------------
 *  Peripheral mode — GATT server
 * ---------------------------------------------------------------- */

static void
peripheral_build_gattdb(struct att_db *db, struct att_attr *attrs,
    uint8_t *val_buf, size_t val_size)
{
	static const uint8_t appearance[] = { 0x00, 0x00 }; /* Unknown */

	attdb_init(db, attrs, 64, val_buf, val_size);

	/* GAP Service (required) */
	attdb_add_service(db, UUID_GAP_SERVICE);
	attdb_add_characteristic(db, UUID_DEVICE_NAME,
	    GATT_PROP_READ, ATT_PERM_READ,
	    PERIPHERAL_NAME, sizeof(PERIPHERAL_NAME) - 1);
	attdb_add_characteristic(db, UUID_APPEARANCE,
	    GATT_PROP_READ, ATT_PERM_READ,
	    appearance, sizeof(appearance));

	/* GATT Service (required) with Service Changed characteristic */
	attdb_add_service(db, UUID_GATT_SERVICE);
	attdb_add_characteristic(db, 0x2A05 /* Service Changed */,
	    GATT_PROP_INDICATE, 0,
	    "\x01\x00\xFF\xFF", 4); /* handle range: 0x0001-0xFFFF */
	attdb_add_cccd(db);

	/*
	 * Client Supported Features (Core Spec Vol 3 Part G §7.2).
	 * Writable by client.  Bit 0 = Robust Caching, Bit 1 = EATT,
	 * Bit 2 = Multiple Handle Value Notifications.
	 *
	 * BT 5.1 GATT Robust Caching (§7.3.1): when a client sets the
	 * Robust Caching bit (ATT_CLIENT_FEAT_ROBUST_CACHING), the
	 * server must track change-awareness and return
	 * ATT_ERR_DATABASE_OUT_OF_SYNC until the client becomes
	 * change-aware (by reading the Database Hash).  Since blued's
	 * GATT database is built once at startup and never changes at
	 * runtime, all clients are inherently change-aware after their
	 * first connection.  No out-of-sync errors will ever be
	 * generated, which is the correct behaviour for a static
	 * database per the spec.
	 */
	attdb_add_characteristic(db, UUID_CLIENT_SUPP_FEAT,
	    GATT_PROP_READ | GATT_PROP_WRITE, ATT_PERM_READ | ATT_PERM_WRITE,
	    "\x00", 1);

	/*
	 * Server Supported Features (Core Spec Vol 3 Part G §7.4).
	 * Read-only.  Bit 0 = EATT supported.
	 */
	{
		static const uint8_t ssf[] = { 0x01 }; /* EATT supported */
		attdb_add_characteristic(db, UUID_SERVER_SUPP_FEAT,
		    GATT_PROP_READ, ATT_PERM_READ,
		    ssf, sizeof(ssf));
	}

	/*
	 * Database Hash characteristic (Core Spec Vol 3 Part G §7.3).
	 * Must be inside the GATT Service attribute group.
	 * Placeholder value; computed after full DB build below.
	 */
	attdb_add_characteristic(db, UUID_DATABASE_HASH,
	    GATT_PROP_READ, ATT_PERM_READ,
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00", 16);

	/* Device Information Service */
	attdb_add_service(db, UUID_DIS_SERVICE);
	attdb_add_characteristic(db, UUID_MANUFACTURER,
	    GATT_PROP_READ, ATT_PERM_READ, "FreeBSD", 7);
	attdb_add_characteristic(db, UUID_MODEL_NUMBER,
	    GATT_PROP_READ, ATT_PERM_READ, "blued", 5);
	attdb_add_characteristic(db, UUID_FIRMWARE_REV,
	    GATT_PROP_READ, ATT_PERM_READ, "1.0", 3);

	/* Custom service with read/write/notify */
	attdb_add_service(db, UUID_CUSTOM_SERVICE);
	attdb_add_characteristic(db, UUID_CUSTOM_CHAR,
	    GATT_PROP_READ | GATT_PROP_WRITE | GATT_PROP_NOTIFY,
	    ATT_PERM_READ | ATT_PERM_WRITE,
	    "\x00", 1);
	attdb_add_cccd(db);

	/*
	 * Compute Database Hash and update the placeholder.
	 * The hash characteristic was added inside the GATT service above.
	 */
	{
		uint8_t db_hash[16];

		attdb_compute_db_hash(db, db_hash);
		for (int i = 0; i < db->count; i++) {
			if (db->attrs[i].uuid16 == UUID_DATABASE_HASH &&
			    db->attrs[i].value_len == 16) {
				memcpy(db->attrs[i].value, db_hash, 16);
				break;
			}
		}
	}

	LOG_ATT(1, "GATT database built: %d attributes", db->count);
}

static int
peripheral_att_listen(void)
{
	struct sockaddr_l2cap sa;
	int fd;

	fd = socket(PF_BLUETOOTH,
	    SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_CLOFORK,
	    BLUETOOTH_PROTO_L2CAP);
	if (fd < 0)
		return (-1);

	memset(&sa, 0, sizeof(sa));
	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;
	sa.l2cap_cid = htole16(NG_L2CAP_ATT_CID);
	sa.l2cap_bdaddr_type = BDADDR_LE_PUBLIC;
	/* l2cap_bdaddr = BDADDR_ANY (all zeros) */

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return (-1);
	}

	if (listen(fd, 1) < 0) {
		close(fd);
		return (-1);
	}

	return (fd);
}

/* peripheral_run() removed — peripheral mode now uses the unified kqueue
 * event loop with blued_periph_accept() and blued_conn_setup_peripheral(). */
