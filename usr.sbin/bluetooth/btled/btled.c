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
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "gatt.h"
#include "hci_util.h"
#include "smp.h"

int btled_debug = 0;

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

	int			vhid_ctl_fd;	/* /dev/vhid */
	int			vhid_fd;	/* /dev/vhidN */
	int			vhid_unit;
	int			hci_fd;		/* raw HCI socket */
	int			bond_fd;	/* bond storage */

	uint8_t			addr[6];
	uint8_t			addr_type;
	uint8_t			local_addr[6];
	uint16_t		con_handle;

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
	    "usage: btled [-dr] [-a adapter] [-f bonds] -s\n"
	    "       btled [-dr] [-a adapter] [-f bonds] <bdaddr> "
	    "[public|random] ...\n"
	    "       btled [-d] [-a adapter] [-f bonds] -p\n");
	exit(1);
}

static void
do_scan(struct hogp_device *dev)
{
	struct ble_scan_result results[BLE_MAX_SCAN_RESULTS];
	int nresults, i;
	char addr_str[18];

	fprintf(stderr, "btled: scanning for BLE devices (5 seconds)...\n");

	if (hci_le_scan(dev->hci_fd, 5, results, BLE_MAX_SCAN_RESULTS,
	    &nresults) < 0)
		err(1, "BLE scan");

	fprintf(stdout, "Found %d device(s):\n\n", nresults);

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
	int ch;
	bool scan_mode = false;
	bool peripheral_mode = false;

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

	while ((ch = getopt(argc, argv, "a:df:prs")) != -1) {
		switch (ch) {
		case 'a':
			dev.adapter = optarg;
			break;
		case 'd':
			dev.debug = true;
			btled_debug = 1;
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
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/* Open raw HCI socket bound to the adapter */
	dev.hci_fd = hci_open(dev.adapter);
	if (dev.hci_fd < 0)
		err(1, "open HCI adapter %s", dev.adapter);

	/* Read local adapter address (needed for SMP) */
	if (hci_get_bdaddr(dev.hci_fd, dev.local_addr) < 0)
		err(1, "read local BD_ADDR");

	if (dev.debug) {
		char addr_str[18];
		bt_ntoa((bdaddr_t *)dev.local_addr, addr_str);
		fprintf(stderr, "btled: adapter %s, address %s\n",
		    dev.adapter, addr_str);
	}

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
connect_loop:
	dev.att.fd = -1;
	dev.smp.fd = -1;

	/*
	 * Phase 1: Connect ATT
	 *
	 * On first connect, use att_open() (creates its own socket).
	 * On reconnect inside Capsicum, use att_open_fd() with a
	 * pre-allocated socket from the pool.
	 */
	if (dev.debug)
		fprintf(stderr, "btled: connecting to %s...\n", argv[0]);

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
				warn("ATT connect failed, retrying in 5s");
				sleep(5);
				goto connect_loop;
			}
			err(1, "ATT connect");
		}
	}

	if (dev.debug)
		fprintf(stderr, "btled: connected, exchanging MTU\n");

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
		if (dev.debug)
			fprintf(stderr, "btled: connection handle=%04x\n",
			    dev.con_handle);
	}

	if (att_exchange_mtu(&dev.att, ATT_MAX_MTU) < 0)
		warn("MTU exchange failed, using default %d", ATT_DEFAULT_MTU);
	else if (dev.debug)
		fprintf(stderr, "btled: MTU=%d\n", dev.att.mtu);

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
			if (dev.debug)
				fprintf(stderr,
				    "btled: found existing bond, "
				    "encrypting...\n");
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
				if (dev.debug)
					fprintf(stderr,
					    "btled: waiting for "
					    "encryption...\n");
				if (hci_wait_encryption(dev.hci_fd,
				    dev.con_handle, 10) < 0)
					warn("encryption timeout");
				else if (dev.debug)
					fprintf(stderr,
					    "btled: encrypted\n");
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
			if (dev.debug)
				fprintf(stderr,
				    "btled: device requires pairing\n");

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

			if (dev.debug)
				fprintf(stderr,
				    "btled: pairing complete, retrying "
				    "discovery\n");

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

	if (dev.debug)
		fprintf(stderr,
		    "btled: sandbox active, entering event loop\n");

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
		warnx("reconnecting in 3 seconds...");
		sleep(3);
		goto connect_loop;
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

		if (dev->debug)
			fprintf(stderr, "btled: Report Map: %zu bytes\n",
			    total);
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

		if (dev->debug)
			fprintf(stderr,
			    "btled: Report handle=%04x id=%d type=%d "
			    "cccd=%04x\n",
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
			if (dev->debug)
				fprintf(stderr,
				    "btled: HID Information: bcdHID=%04x "
				    "country=%d flags=%02x\n",
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
			if (dev->debug)
				fprintf(stderr,
				    "btled: set Report Protocol mode\n");
			break;
		}
	}

	return (0);
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

	/* Discover all primary services */
	ret = gatt_discover_primary_services(&dev->att, svcs,
	    GATT_MAX_SERVICES, &nsvcs);
	if (ret != 0)
		return (ret);

	/* Iterate all HID Service instances */
	for (int s = 0; s < nsvcs; s++) {
		if (svcs[s].uuid16 != UUID_HID_SERVICE)
			continue;

		nsvc_found++;

		if (dev->debug)
			fprintf(stderr,
			    "btled: HID Service found, handles %04x-%04x\n",
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

	if (dev->debug)
		fprintf(stderr, "btled: total: %d reports, %zu bytes report map"
		    " from %d service(s)\n",
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
	arg.idVendor = 0;	/* filled from DIS if available */
	arg.idProduct = 0;
	arg.idVersion = dev->hid_bcdHID;	/* from HID Information */
	strlcpy(arg.name, "BLE HID Device", sizeof(arg.name));

	if (ioctl(dev->vhid_fd, VHID_ATTACH, &arg) < 0)
		return (-1);

	if (dev->debug)
		fprintf(stderr, "btled: vhid%d configured\n", dev->vhid_unit);

	return (0);
}

/*
 * Subscribe to notifications on all Input Report characteristics.
 */
static int
hogp_subscribe(struct hogp_device *dev)
{
	int ret;

	for (int i = 0; i < dev->nreports; i++) {
		struct hogp_report *rpt = &dev->reports[i];

		if (rpt->report_type != HID_REPORT_TYPE_INPUT)
			continue;
		if (rpt->cccd_handle == 0)
			continue;

		/* Write 0x0001 to CCCD to enable notifications */
		uint8_t val[2] = { 0x01, 0x00 };
		ret = att_write_req(&dev->att, rpt->cccd_handle,
		    val, sizeof(val));
		if (ret != 0)
			warnx("failed to enable notifications for "
			    "handle %04x", rpt->value_handle);
		else if (dev->debug)
			fprintf(stderr, "btled: notifications enabled for "
			    "report id=%d handle=%04x\n",
			    rpt->report_id, rpt->value_handle);
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

	if (dev->debug)
		fprintf(stderr, "btled: entered Capsicum sandbox\n");

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

	/* GATT Service (required, can be empty) */
	attdb_add_service(db, UUID_GATT_SERVICE);

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
	if (dev->bond_fd >= 0)
		smp_bond_db_load(&dev->bond_db, dev->bond_fd);

	/* Create ATT listening socket */
	listen_fd = peripheral_att_listen();
	if (listen_fd < 0)
		err(1, "ATT listen socket");

	if (dev->debug)
		fprintf(stderr, "btled: peripheral mode, ATT listening\n");

	/* Set advertising parameters: connectable undirected, 100ms interval */
	if (hci_le_set_advertising_params(dev->hci_fd,
	    ADV_INTERVAL_100MS, ADV_INTERVAL_100MS,
	    0x00) < 0)
		err(1, "set advertising parameters");

	/* Build and set advertising data */
	{
		uint16_t uuids[] = { UUID_DIS_SERVICE, UUID_CUSTOM_SERVICE };
		adv_len = ble_build_adv_data(adv_data, sizeof(adv_data),
		    PERIPHERAL_NAME, uuids, 2);
		if (adv_len < 0)
			err(1, "build advertising data");
	}
	if (hci_le_set_advertising_data(dev->hci_fd, adv_data,
	    (uint8_t)adv_len) < 0)
		err(1, "set advertising data");

	/* Enable advertising */
	if (hci_le_set_advertise_enable(dev->hci_fd, true) < 0)
		err(1, "enable advertising");

	if (dev->debug)
		fprintf(stderr, "btled: advertising as \"%s\"\n",
		    PERIPHERAL_NAME);

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

		client_fd = accept(listen_fd, NULL, NULL);
		if (client_fd < 0) {
			if (errno == EINTR)
				continue;
			warn("accept");
			continue;
		}

		if (dev->debug)
			fprintf(stderr, "btled: client connected\n");

		/* Reset CCCDs to default 0x0000 for non-bonded client */
		for (int i = 0; i < db.count; i++) {
			if (attrs[i].uuid16 == GATT_UUID_CCCD)
				memset(attrs[i].value, 0, attrs[i].value_len);
		}

		/* Disable advertising while connected */
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
				if (dev->debug)
					fprintf(stderr,
					    "btled: client disconnected\n");
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

		/* Clean up connection */
		free(ac.buf);
		close(ac.fd);

		/* Re-enable advertising for next connection */
		if (running) {
			hci_le_set_advertise_enable(dev->hci_fd, true);
			if (dev->debug)
				fprintf(stderr,
				    "btled: re-advertising\n");
		}
	}

	/* Shutdown */
	hci_le_set_advertise_enable(dev->hci_fd, false);
	close(listen_fd);

	if (dev->bond_fd >= 0) {
		close(dev->bond_fd);
		dev->bond_fd = -1;
	}
}
