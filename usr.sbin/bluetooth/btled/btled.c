/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * btled - Bluetooth Low Energy HID daemon
 *
 * Connects to BLE HID devices (HOGP - HID over GATT Profile),
 * discovers HID services, subscribes to report notifications, and
 * injects raw HID reports into the kernel via /dev/vhidN.
 *
 * Runs in a Capsicum sandbox after initialization.
 *
 * Usage: btled [-d] [-f bonds_file] <bdaddr> [addr_type]
 */

#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/poll.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libutil.h>
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
#include "hci_log.h"
#include "ble_util.h"
#include "gatt.h"
#include "hci_util.h"
#include "smp.h"

int btled_verbose = 0;
int btled_daemonized = 0;

#include <dev/hid/vhid.h>

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
	 * restarting btled.  Reconnection with an existing bond uses HCI
	 * LE_Start_Encryption, which does not need an SMP socket.
	 */
#define SOCK_POOL_SIZE	8
	int			att_pool[SOCK_POOL_SIZE];
	int			att_pool_next;
};

static volatile sig_atomic_t running = 1;

static pid_t child_pids[16];
static int nchildren = 0;

static void	usage(void) __dead2;
static void	peripheral_run(struct hogp_device *, const char *);
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
		pool[i] = socket(PF_BLUETOOTH, SOCK_SEQPACKET,
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
	if (*next >= size)
		return (-1);
	return (pool[(*next)++]);
}

static void
atexit_cleanup(void)
{
	if (cleanup_dev != NULL)
		hogp_cleanup(cleanup_dev);
}

static void
sig_handler(int sig)
{
	running = 0;

	/* Propagate signal to forked children */
	for (int i = 0; i < nchildren; i++) {
		if (child_pids[i] > 0)
			kill(child_pids[i], sig);
	}
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
	    "usage: btled [-Bdrv] [-a adapter] [-f bonds] [-L logfile] -s\n"
	    "       btled [-Bdrv] [-a adapter] [-f bonds] [-L logfile] "
	    "<bdaddr> [public|random] ...\n"
	    "       btled [-Bdv] [-a adapter] [-f bonds] [-L logfile] -p\n"
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

	fprintf(stderr, "btled: scanning for BLE devices (5 seconds)...\n");

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

int
main(int argc, char *argv[])
{
	struct hogp_device dev;
	struct pidfh *pfh = NULL;
	int ch;
	bool scan_mode = false;
	bool peripheral_mode = false;
	bool daemon_mode = false;

	memset(&dev, 0, sizeof(dev));
	for (int i = 0; i < SOCK_POOL_SIZE; i++) {
		dev.att_pool[i] = -1;
	}
	dev.addr_type = BDADDR_LE_PUBLIC;
	dev.bond_fd = -1;
	dev.vhid_ctl_fd = -1;
	dev.vhid_fd = -1;
	dev.hci_fd = -1;
	dev.adapter = "ubt0";

	const char *bond_path = "/var/db/btled/bonds";

	while ((ch = getopt(argc, argv, "a:BdL:f:prsv")) != -1) {
		switch (ch) {
		case 'a':
			dev.adapter = optarg;
			break;
		case 'B':
			daemon_mode = true;
			break;
		case 'd':
			dev.debug = true;
			if (btled_verbose < 1)
				btled_verbose = 1;
			break;
		case 'L':
			hci_log_open(optarg);
			break;
		case 'f':
			bond_path = optarg;
			break;
		case 'p':
			peripheral_mode = true;
			break;
		case 'r':
			dev.reconnect = true;
			break;
		case 's':
			scan_mode = true;
			break;
		case 'v':
			btled_verbose++;
			dev.debug = true;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/* Daemonize if requested */
	if (daemon_mode) {
		pfh = pidfile_open("/var/run/btled.pid", 0600, NULL);
		if (daemon(0, 0) < 0)
			err(1, "daemon");
		if (pfh != NULL)
			pidfile_write(pfh);
		openlog("btled", LOG_PID | LOG_NDELAY, LOG_DAEMON);
		btled_daemonized = 1;
		if (btled_verbose < 1)
			btled_verbose = 1; /* at least log to syslog */
	}

	/* Open raw HCI socket bound to the adapter */
	dev.hci_fd = hci_open(dev.adapter);
	if (dev.hci_fd < 0)
		err(1, "open HCI adapter %s", dev.adapter);

	/*
	 * HCI initialization sequence per Core Spec Vol 4 Part E:
	 * 1. Reset controller to known state
	 * 2. Read local address
	 * 3. Read LE feature support bitmask
	 * 4. Set LE event mask for features we use
	 * 5. Configure defaults for supported features
	 */
	hci_reset(dev.hci_fd);
	usleep(100000);	/* 100ms settle after reset */

	if (hci_get_bdaddr(dev.hci_fd, dev.local_addr) < 0)
		err(1, "read local BD_ADDR");

	if (btled_verbose >= 1) {
		char addr_str[18];
		bt_ntoa((bdaddr_t *)dev.local_addr, addr_str);
		LOG_HOGP(1, "adapter %s, address %s",
		    dev.adapter, addr_str);
	}

	/* Read LE feature support */
	if (hci_le_read_local_features(dev.hci_fd, &dev.le_features) < 0)
		dev.le_features = 0; /* assume nothing supported */

	/* Enable LE events we care about */
	{
		uint64_t evtmask =
		    LE_EVTMASK_CONN_COMPLETE |
		    LE_EVTMASK_ADV_REPORT |
		    LE_EVTMASK_CONN_UPDATE |
		    LE_EVTMASK_READ_REMOTE_FEAT |
		    LE_EVTMASK_LTK_REQUEST |
		    LE_EVTMASK_ENH_CONN_COMPLETE;

		if (dev.le_features & LE_FEAT_DATA_LENGTH_EXT)
			evtmask |= LE_EVTMASK_DATA_LENGTH_CHANGE;
		if (dev.le_features & LE_FEAT_2M_PHY)
			evtmask |= LE_EVTMASK_PHY_UPDATE_COMPL;
		if (dev.le_features & LE_FEAT_EXT_ADVERTISING) {
			evtmask |= LE_EVTMASK_EXT_ADV_REPORT;
			evtmask |= LE_EVTMASK_ADV_SET_TERM;
		}
		hci_le_set_event_mask(dev.hci_fd, evtmask);
	}

	/* Read controller's TX power range for diagnostics */
	if (dev.le_features & LE_FEAT_POWER_CONTROL) {
		struct bt_devreq r;
		ng_hci_le_read_transmit_power_rp rp;

		memset(&r, 0, sizeof(r));
		r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
		    NG_HCI_OCF_LE_READ_TRANSMIT_POWER);
		r.rparam = &rp;
		r.rlen = sizeof(rp);
		r.event = NG_HCI_EVENT_COMMAND_COMPL;

		if (bt_devreq(dev.hci_fd, &r, 5) == 0 && rp.status == 0)
			LOG_HCI(1, "TX power range: %d to %d dBm",
			    rp.min_tx_power, rp.max_tx_power);
	}

	/* Configure defaults for supported features */
	if (dev.le_features & LE_FEAT_DATA_LENGTH_EXT)
		hci_le_write_suggested_default_data_length(dev.hci_fd,
		    0x00FB, 0x0848);
	if (dev.le_features & LE_FEAT_2M_PHY)
		hci_le_set_default_phy(dev.hci_fd, 0x00,
		    0x03 /* 1M + 2M */, 0x03 /* 1M + 2M */);

	/* Scan mode: just show devices and exit */
	if (scan_mode) {
		do_scan(&dev);
		close(dev.hci_fd);
		return (0);
	}

	/* Peripheral mode: advertise and serve GATT */
	if (peripheral_mode) {
		peripheral_run(&dev, bond_path);
		close(dev.hci_fd);
		return (0);
	}

	if (argc < 1)
		usage();

	/* Open shared resources before forking */
	dev.bond_fd = open(bond_path, O_RDWR | O_CREAT, 0600);
	if (dev.bond_fd < 0)
		err(1, "open %s", bond_path);
	smp_bond_db_load(&dev.bond_db, dev.bond_fd);
	load_resolving_list(&dev);

	dev.vhid_ctl_fd = open("/dev/vhid", O_RDWR);
	if (dev.vhid_ctl_fd < 0)
		err(1, "open /dev/vhid");

	cleanup_dev = &dev;
	atexit(atexit_cleanup);

	/*
	 * Multi-device: parse bdaddr [type] pairs from argv.
	 * Fork a child for each device beyond the first.
	 */
	{
		int ndevs = 0;
		struct {
			uint8_t	addr[6];
			uint8_t	addr_type;
		} devs[16];
		int ai = 0;

		while (ai < argc && ndevs < 16) {
			if (!bt_aton(argv[ai], (bdaddr_t *)devs[ndevs].addr))
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

		/* Automatically reap zombie children */
		signal(SIGCHLD, SIG_IGN);

		/* Fork children for devices 1..N-1 */
		for (int i = 1; i < ndevs; i++) {
			pid_t pid = fork();
			if (pid < 0)
				err(1, "fork");
			if (pid == 0) {
				/* Child: reset child tracking */
				nchildren = 0;
				cleanup_dev = NULL;
				/* Child: set this device's address */
				memcpy(dev.addr, devs[i].addr, 6);
				dev.addr_type = devs[i].addr_type;
				goto child_start;
			}
			/* Parent: record child PID */
			if (nchildren < (int)nitems(child_pids))
				child_pids[nchildren++] = pid;
		}

		/* Parent handles device 0 */
		memcpy(dev.addr, devs[0].addr, 6);
		dev.addr_type = devs[0].addr_type;
	}

child_start:

	/*
	 * Connection loop.  Runs once without -r, retries on disconnect
	 * with -r.  Capsicum is skipped in reconnect mode because we
	 * need to open new sockets on each reconnection.
	 */
	{
		static int reconnect_delay = 0; /* exponential backoff */
connect_loop:
	if (reconnect_delay > 0) {
		LOG_HOGP(1, "reconnecting in %d seconds...", reconnect_delay);
		sleep(reconnect_delay);
		reconnect_delay = reconnect_delay * 2;
		if (reconnect_delay > 60)
			reconnect_delay = 60;
	}
	dev.att.fd = -1;
	dev.smp.fd = -1;

	/*
	 * Phase 1: Connect ATT
	 *
	 * On first connect, use att_open() (creates its own socket).
	 * On reconnect inside Capsicum, use att_open_fd() with a
	 * pre-allocated socket from the pool.
	 */
	LOG_HOGP(1, "connecting to %s...", argv[0]);

	{
		int att_fd, ret;

		att_fd = pool_take(dev.att_pool, &dev.att_pool_next,
		    SOCK_POOL_SIZE);
		if (att_fd >= 0)
			ret = att_open_fd(&dev.att, att_fd, dev.addr,
			    dev.addr_type);
		else
			ret = att_open(&dev.att, dev.addr, dev.addr_type);

		if (ret < 0) {
			if (dev.reconnect && running) {
				warn("ATT connect failed");
				if (reconnect_delay == 0)
					reconnect_delay = 3;
				goto connect_loop;
			}
			err(1, "ATT connect");
		}
	}

	reconnect_delay = 0; /* reset backoff on successful connect */
	LOG_HOGP(1, "connected, exchanging MTU");

	/* Get connection handle (needed for SMP encryption) */
	{
		int retries;
		for (retries = 0; retries < 5; retries++) {
			if (hci_get_con_handle(dev.hci_fd, dev.addr,
			    &dev.con_handle) == 0)
				break;
			usleep(200000); /* 200ms — wait for HCI con list */
		}
		if (retries == 5)
			errx(1, "could not get HCI connection handle");
		LOG_HOGP(1, "connection handle=%04x",
			    dev.con_handle);
	}

	/* Request optimal link parameters for this connection */
	if (dev.le_features & LE_FEAT_DATA_LENGTH_EXT)
		hci_le_set_data_length(dev.hci_fd, dev.con_handle,
		    0x00FB, 0x0848);
	if (dev.le_features & LE_FEAT_2M_PHY)
		hci_le_set_phy(dev.hci_fd, dev.con_handle, 0x00,
		    0x02 /* prefer 2M */, 0x02 /* prefer 2M */, 0x0000);

	/* Request low-latency HID connection parameters:
	 * 7.5-15ms interval, latency 4, timeout 5s */
	hci_le_connection_update(dev.hci_fd, dev.con_handle,
	    6 /* 7.5ms */, 12 /* 15ms */, 4, 500 /* 5s */);

	if (att_exchange_mtu(&dev.att, ATT_MAX_MTU) < 0)
		warn("MTU exchange failed, using default %d", ATT_DEFAULT_MTU);
	else
		LOG_HOGP(1, "MTU=%d", dev.att.mtu);

	/* Try to establish EATT bearers for parallel GATT operations */
	att_open_eatt(&dev.att, dev.addr, dev.addr_type, 2);

	/*
	 * Phase 2a: Attempt encryption with existing bond, or pair.
	 *
	 * Many BLE HID devices require encryption before they expose
	 * their GATT services.  Try bonded reconnect first; if no bond
	 * exists, attempt pairing after the first Insufficient
	 * Authentication error during discovery.
	 */
	{
		struct smp_bond *bond;

		bond = smp_find_bond(&dev.bond_db, dev.addr,
		    dev.addr_type);
		if (bond != NULL) {
			LOG_HOGP(1, "found existing bond, encrypting...");
			/*
			 * For bonded reconnect, smp_encrypt_with_ltk()
			 * only needs hci_fd and con_handle — no SMP
			 * L2CAP socket required.  Set them directly to
			 * avoid calling smp_open() which would fail
			 * inside Capsicum (socket() returns ECAPMODE).
			 */
			dev.smp.hci_fd = dev.hci_fd;
			dev.smp.con_handle = dev.con_handle;
			if (smp_encrypt_with_ltk(&dev.smp, bond) < 0) {
				warn("bonded encryption failed");
			} else {
				LOG_HOGP(1, "waiting for encryption...");
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
			/*
			 * Device requires encryption.  Pair now.
			 */
			LOG_HOGP(1, "device requires pairing");

			if (smp_open(&dev.smp, dev.addr, dev.addr_type,
			    dev.local_addr, 0, dev.hci_fd,
			    dev.con_handle, &dev.bond_db) < 0)
				err(1, "SMP open");
			dev.smp.passkey_cb = passkey_display;
			dev.smp.numcmp_cb = numcmp_confirm;

			if (smp_pair(&dev.smp) < 0)
				err(1, "SMP pairing");

			/* Wait for encryption to complete */
			if (hci_wait_encryption(dev.hci_fd,
			    dev.con_handle, 10) < 0)
				warn("post-pairing encryption timeout");
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
	 * Phase 3: Set up vhid device (skip on reconnect if already open)
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

	/*
	 * Write Exit Suspend (0x01) to HID Control Point per HOGP spec.
	 * This signals the device we are ready for reports.
	 */
	if (dev.hid_ctrl_handle != 0) {
		uint8_t exit_suspend = 0x01;
		att_write_cmd(&dev.att, dev.hid_ctrl_handle,
		    &exit_suspend, 1);
	}

	/*
	 * Install signal handlers before sandbox
	 */
	signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);
	signal(SIGHUP, sig_handler);

	/*
	 * Phase 5: Enter Capsicum sandbox (once only).
	 *
	 * Close the SMP socket first — it was used for initial pairing
	 * and must not leak into the sandbox.  Bonded reconnect uses
	 * HCI LE_Start_Encryption, not the SMP L2CAP channel.
	 *
	 * Pool creation and cap_enter() are one-shot; on reconnect
	 * (goto connect_loop) we skip this block.
	 */
	{
		static bool sandboxed = false;

		if (!sandboxed) {
			smp_close(&dev.smp);

			if (dev.reconnect) {
				dev.att_pool_next = 0;
				if (pool_create(dev.att_pool,
				    SOCK_POOL_SIZE) < 0)
					warn("ATT socket pool creation "
					    "failed");
			}
			if (capsicum_sandbox(&dev) != 0)
				err(1, "capsicum sandbox");
			sandboxed = true;
		}
	}

	LOG_HOGP(1, "sandbox active, entering event loop");

	/*
	 * Phase 6: Event loop — receive notifications, inject reports
	 */
	hogp_event_loop(&dev);

	/*
	 * Write Suspend (0x00) to HID Control Point before disconnect
	 * per HOGP spec.  Best-effort — may fail if link already dropped.
	 */
	if (dev.hid_ctrl_handle != 0) {
		uint8_t suspend = 0x00;
		att_write_cmd(&dev.att, dev.hid_ctrl_handle, &suspend, 1);
	}

	/*
	 * Clean up this connection's resources.
	 * If -r and the loop broke due to disconnect (running still true),
	 * close sockets and vhid, then reconnect.
	 */
	att_close(&dev.att);
	smp_close(&dev.smp);

	if (!dev.reconnect || !running) {
		/* Full cleanup on final exit */
		if (dev.vhid_fd >= 0) {
			close(dev.vhid_fd);
			dev.vhid_fd = -1;
		}
		if (dev.vhid_ctl_fd >= 0)
			ioctl(dev.vhid_ctl_fd, VHID_DESTROY, &dev.vhid_unit);
	}

	/* Free report state; vhid_fd stays open for reconnect */
	free(dev.report_map);
	dev.report_map = NULL;
	dev.nreports = 0;

	if (dev.reconnect && running) {
		reconnect_delay = 3; /* reset backoff on clean disconnect */
		goto connect_loop;
	}
	}

	/* Final cleanup */
	if (dev.vhid_ctl_fd >= 0)
		close(dev.vhid_ctl_fd);
	if (dev.hci_fd >= 0)
		close(dev.hci_fd);
	if (dev.bond_fd >= 0)
		close(dev.bond_fd);
	for (int i = 0; i < SOCK_POOL_SIZE; i++) {
		if (dev.att_pool[i] >= 0)
			close(dev.att_pool[i]);
	}
	cleanup_dev = NULL;

	return (running ? 1 : 0);
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
	dev->vhid_fd = open(path, O_RDWR);
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

	/* Enter capability mode */
	if (cap_enter() < 0)
		return (-1);

	LOG_HOGP(1, "entered Capsicum sandbox");

	return (0);
}

/*
 * Main event loop: receive ATT notifications and inject reports.
 *
 * BLE HID devices send Handle Value Notifications (opcode 0x1B)
 * on Report characteristics.  We extract the handle and data,
 * match to a report, and write to /dev/vhidN.
 */
static void
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

/* UUIDs for peripheral GATT services */
#define UUID_GAP_SERVICE	0x1800
#define UUID_GATT_SERVICE	0x1801
#define UUID_DIS_SERVICE	0x180A
#define UUID_CUSTOM_SERVICE	0xFFE0
#define UUID_DEVICE_NAME	0x2A00
#define UUID_APPEARANCE		0x2A01
#define UUID_MANUFACTURER	0x2A29
#define UUID_MODEL_NUMBER	0x2A24
#define UUID_FIRMWARE_REV	0x2A26
#define UUID_CUSTOM_CHAR	0xFFE1

#define PERIPHERAL_NAME		"5BSD-btled"
#define ADV_INTERVAL_100MS	0x00A0	/* 160 * 0.625ms = 100ms */

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
	 * Database Hash characteristic (Core Spec Vol 3 Part G §7.3)
	 * is omitted: a correct implementation requires AES-CMAC over
	 * the serialized GATT database.  A static all-zero hash is
	 * worse than absent because clients would cache a wrong value.
	 */

	/* Device Information Service */
	attdb_add_service(db, UUID_DIS_SERVICE);
	attdb_add_characteristic(db, UUID_MANUFACTURER,
	    GATT_PROP_READ, ATT_PERM_READ, "FreeBSD", 7);
	attdb_add_characteristic(db, UUID_MODEL_NUMBER,
	    GATT_PROP_READ, ATT_PERM_READ, "btled", 5);
	attdb_add_characteristic(db, UUID_FIRMWARE_REV,
	    GATT_PROP_READ, ATT_PERM_READ, "1.0", 3);

	/* Custom service with read/write/notify */
	attdb_add_service(db, UUID_CUSTOM_SERVICE);
	attdb_add_characteristic(db, UUID_CUSTOM_CHAR,
	    GATT_PROP_READ | GATT_PROP_WRITE | GATT_PROP_NOTIFY,
	    ATT_PERM_READ | ATT_PERM_WRITE,
	    "\x00", 1);
	attdb_add_cccd(db);
}

static int
peripheral_att_listen(void)
{
	struct sockaddr_l2cap sa;
	int fd;

	fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BLUETOOTH_PROTO_L2CAP);
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

static void
peripheral_run(struct hogp_device *dev, const char *bond_path)
{
	struct att_db db;
	struct att_attr attrs[64];
	uint8_t val_buf[2048];
	struct att_conn ac;
	int listen_fd, client_fd;
	struct pollfd pfd;
	uint8_t buf[ATT_MAX_MTU];
	size_t n;
	uint8_t adv_data[31];
	int adv_len;

	/* Build the GATT database */
	peripheral_build_gattdb(&db, attrs, val_buf, sizeof(val_buf));

	/* Open bond file */
	dev->bond_fd = open(bond_path, O_RDWR | O_CREAT, 0600);
	if (dev->bond_fd >= 0) {
		smp_bond_db_load(&dev->bond_db, dev->bond_fd);
		load_resolving_list(dev);
	}

	/* Create ATT listening socket */
	listen_fd = peripheral_att_listen();
	if (listen_fd < 0)
		err(1, "ATT listen socket");

	LOG_HOGP(1, "peripheral mode, ATT listening");

	/* Build advertising data */
	{
		uint16_t uuids[] = { UUID_DIS_SERVICE, UUID_CUSTOM_SERVICE };
		adv_len = ble_build_adv_data(adv_data, sizeof(adv_data),
		    PERIPHERAL_NAME, uuids, 2);
		if (adv_len < 0)
			err(1, "build advertising data");
	}

	/*
	 * Try extended advertising first (BT 5.0+, supports >31 bytes,
	 * multiple sets, PHY selection).  Fall back to legacy if the
	 * controller doesn't support it.
	 */
	bool use_ext_adv = false;
	if (hci_le_set_ext_adv_params(dev->hci_fd, 0x00,
	    0x0013 /* connectable + scannable + legacy ADV_IND */,
	    ADV_INTERVAL_100MS, ADV_INTERVAL_100MS, 0x00) == 0 &&
	    hci_le_set_ext_adv_data(dev->hci_fd, 0x00,
	    adv_data, (uint8_t)adv_len) == 0 &&
	    hci_le_set_ext_adv_enable(dev->hci_fd, 1, 0x00) == 0) {
		LOG_HOGP(1, "using extended advertising");
		use_ext_adv = true;
	} else {
		/* Legacy advertising fallback */
		LOG_HOGP(1, "ext adv not supported, using legacy");
		if (hci_le_set_advertising_params(dev->hci_fd,
		    ADV_INTERVAL_100MS, ADV_INTERVAL_100MS, 0x00) < 0)
			err(1, "set advertising parameters");
		if (hci_le_set_advertising_data(dev->hci_fd, adv_data,
		    (uint8_t)adv_len) < 0)
			err(1, "set advertising data");
		if (hci_le_set_advertise_enable(dev->hci_fd, true) < 0)
			err(1, "enable advertising");
	}

	LOG_HOGP(1, "advertising as \"%s\"", PERIPHERAL_NAME);

	/* Signal handling */
	signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);
	signal(SIGHUP, sig_handler);

	while (running) {
		/* Wait for incoming connection */
		pfd.fd = listen_fd;
		pfd.events = POLLIN;
		pfd.revents = 0;

		{
			int pr = poll(&pfd, 1, 1000);
			if (pr < 0) {
				if (errno == EINTR)
					continue;
				break;
			}
			if (pr == 0)
				continue;
		}

		{
			struct sockaddr_l2cap peer_sa;
			socklen_t peer_len = sizeof(peer_sa);
			client_fd = accept(listen_fd,
			    (struct sockaddr *)&peer_sa, &peer_len);
			if (client_fd < 0) {
				if (errno == EINTR)
					continue;
				warn("accept");
				continue;
			}
			memcpy(dev->addr, peer_sa.l2cap_bdaddr.b, 6);
			dev->addr_type = peer_sa.l2cap_bdaddr_type;
		}

		LOG_HOGP(1, "client connected");

		/*
		 * CCCD handling per Core Spec Vol 3 Part G Section 2.4.5.1:
		 * For bonded devices, restore persisted CCCD values.
		 * For non-bonded devices, reset CCCDs to default 0x0000.
		 */
		{
			struct smp_bond *bond;

			bond = smp_find_bond(&dev->bond_db, dev->addr,
			    dev->addr_type);
			if (bond != NULL && bond->num_cccds > 0) {
				smp_bond_restore_cccds(bond, &db);
				LOG_HOGP(1, "restored %d CCCD(s) for "
				    "bonded device", bond->num_cccds);
			} else {
				for (int i = 0; i < db.count; i++) {
					if (attrs[i].uuid16 == GATT_UUID_CCCD)
						memset(attrs[i].value, 0,
						    attrs[i].value_len);
				}
			}
		}

		/* Disable advertising while connected */
		if (use_ext_adv)
			hci_le_set_ext_adv_enable(dev->hci_fd, 0, 0x00);
		else
			hci_le_set_advertise_enable(dev->hci_fd, false);

		/* Set up ATT connection on accepted socket */
		memset(&ac, 0, sizeof(ac));
		ac.fd = client_fd;
		ac.mtu = ATT_DEFAULT_MTU;
		ac.buf = malloc(ATT_MAX_MTU);
		if (ac.buf == NULL) {
			close(client_fd);
			continue;
		}

		/* Set receive timeout */
		{
			struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
			setsockopt(ac.fd, SOL_SOCKET, SO_RCVTIMEO,
			    &tv, sizeof(tv));
		}

		/* Serve this connection */
		pfd.fd = ac.fd;
		pfd.events = POLLIN;

		while (running) {
			pfd.revents = 0;
			if (poll(&pfd, 1, 1000) < 0) {
				if (errno == EINTR)
					continue;
				break;
			}
			if (pfd.revents & (POLLERR | POLLHUP)) {
				LOG_HOGP(1, "client disconnected");
				break;
			}
			if (!(pfd.revents & POLLIN))
				continue;

			ssize_t nr = recv(ac.fd, buf, ac.mtu, 0);
			if (nr <= 0)
				break;
			n = (size_t)nr;

			att_server_handle(&ac, &db, buf, n);
		}

		/*
		 * Save CCCD values for bonded device before cleanup.
		 * Core Spec Vol 3 Part G Section 2.4.5.1.
		 */
		{
			struct smp_bond *bond;

			bond = smp_find_bond(&dev->bond_db, dev->addr,
			    dev->addr_type);
			if (bond != NULL) {
				smp_bond_save_cccds(bond, &db);
				smp_bond_db_save(&dev->bond_db);
				LOG_HOGP(1, "saved %d CCCD(s) for "
				    "bonded device", bond->num_cccds);
			}
		}

		/* Clean up connection */
		free(ac.buf);
		close(ac.fd);

		/* Re-enable advertising for next connection */
		if (running) {
			if (use_ext_adv)
				hci_le_set_ext_adv_enable(dev->hci_fd, 1, 0x00);
			else
				hci_le_set_advertise_enable(dev->hci_fd, true);
			LOG_HOGP(1, "re-advertising");
		}
	}

	/* Shutdown */
	if (use_ext_adv)
		hci_le_set_ext_adv_enable(dev->hci_fd, 0, 0x00);
	else
		hci_le_set_advertise_enable(dev->hci_fd, false);
	close(listen_fd);

	if (dev->bond_fd >= 0) {
		close(dev->bond_fd);
		dev->bond_fd = -1;
	}
}
