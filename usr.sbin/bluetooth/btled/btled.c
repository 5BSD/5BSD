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
#include <syslog.h>
#include <unistd.h>

#include "att.h"
#include "ble_util.h"
#include "gatt.h"
#include "hci_util.h"
#include "smp.h"

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
	 * Pre-allocated socket pool for reconnection inside Capsicum.
	 * Created before cap_enter(), consumed on reconnect via cap_connect().
	 */
#define SOCK_POOL_SIZE	8
	int			att_pool[SOCK_POOL_SIZE];
	int			smp_pool[SOCK_POOL_SIZE];
	int			att_pool_next;
	int			smp_pool_next;
};

static volatile sig_atomic_t running = 1;

static void	usage(void) __dead2;
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
		if (pool[i] < 0)
			return (-1);

		memset(&sa, 0, sizeof(sa));
		sa.l2cap_len = sizeof(sa);
		sa.l2cap_family = AF_BLUETOOTH;

		if (bind(pool[i], (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			close(pool[i]);
			pool[i] = -1;
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
sig_handler(int sig __unused)
{
	running = 0;
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
	    "[public|random] ...\n");
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

	memset(&dev, 0, sizeof(dev));
	dev.addr_type = BDADDR_LE_PUBLIC;
	dev.bond_fd = -1;
	dev.vhid_ctl_fd = -1;
	dev.vhid_fd = -1;
	dev.hci_fd = -1;
	dev.adapter = "ubt0";

	const char *bond_path = "/var/db/btled/bonds";

	while ((ch = getopt(argc, argv, "a:df:rs")) != -1) {
		switch (ch) {
		case 'a':
			dev.adapter = optarg;
			break;
		case 'd':
			dev.debug = true;
			break;
		case 'f':
			bond_path = optarg;
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

		/* Fork children for devices 1..N-1 */
		for (int i = 1; i < ndevs; i++) {
			pid_t pid = fork();
			if (pid < 0)
				err(1, "fork");
			if (pid == 0) {
				/* Child: set this device's address */
				memcpy(dev.addr, devs[i].addr, 6);
				dev.addr_type = devs[i].addr_type;
				goto child_start;
			}
			/* Parent continues to fork remaining */
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
			if (smp_open(&dev.smp, dev.addr, dev.addr_type,
			    dev.local_addr, 0, dev.hci_fd,
			    dev.con_handle, &dev.bond_db) == 0) {
				dev.smp.passkey_cb = passkey_display;
				dev.smp.numcmp_cb = numcmp_confirm;
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
	 * Phase 3: Set up vhid device
	 */
	if (hogp_setup_vhid(&dev) != 0)
		err(1, "vhid setup");

	/*
	 * Phase 4: Subscribe to report notifications
	 */
	if (hogp_subscribe(&dev) != 0)
		err(1, "HOGP subscribe");

	/*
	 * Install signal handlers before sandbox
	 */
	signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);
	signal(SIGHUP, sig_handler);

	/*
	 * Phase 5: Enter Capsicum sandbox.
	 * When reconnect is enabled, pre-create a pool of bound sockets
	 * before entering capability mode.  cap_connect() can then
	 * connect them inside the sandbox without needing socket().
	 */
	if (dev.reconnect) {
		dev.att_pool_next = 0;
		dev.smp_pool_next = 0;
		if (pool_create(dev.att_pool, SOCK_POOL_SIZE) < 0)
			warn("ATT socket pool creation failed");
		if (pool_create(dev.smp_pool, SOCK_POOL_SIZE) < 0)
			warn("SMP socket pool creation failed");
	}
	if (capsicum_sandbox(&dev) != 0)
		err(1, "capsicum sandbox");

	if (dev.debug)
		fprintf(stderr,
		    "btled: sandbox active, entering event loop\n");

	/*
	 * Phase 6: Event loop — receive notifications, inject reports
	 */
	hogp_event_loop(&dev);

	/*
	 * Clean up this connection's resources.
	 * If -r and the loop broke due to disconnect (running still true),
	 * close sockets and vhid, then reconnect.
	 */
	att_close(&dev.att);
	smp_close(&dev.smp);
	if (dev.vhid_fd >= 0) {
		close(dev.vhid_fd);
		dev.vhid_fd = -1;
	}
	if (dev.vhid_ctl_fd >= 0)
		ioctl(dev.vhid_ctl_fd, VHID_DESTROY, &dev.vhid_unit);
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
	cleanup_dev = NULL;

	return (running ? 1 : 0);
}

/*
 * Discover HID Service (0x1812), read Report Map, classify reports.
 */
static int
hogp_discover(struct hogp_device *dev)
{
	int ret;
	size_t len;

	/* Discover HID Service */
	ret = gatt_discover_service(&dev->att, UUID_HID_SERVICE,
	    &dev->hid_disc);
	if (ret != 0) {
		warnx("HID Service (0x1812) not found");
		return (ret);
	}

	if (dev->debug)
		fprintf(stderr, "btled: HID Service found, handles %04x-%04x, "
		    "%d chars, %d descs\n",
		    dev->hid_disc.service.start_handle,
		    dev->hid_disc.service.end_handle,
		    dev->hid_disc.nchars, dev->hid_disc.ndescs);

	/*
	 * Read Report Map characteristic (UUID 0x2A4B).
	 * This contains the HID Report Descriptor.
	 */
	dev->report_map = NULL;
	dev->report_map_len = 0;

	for (int i = 0; i < dev->hid_disc.nchars; i++) {
		if (dev->hid_disc.chars[i].uuid16 != UUID_REPORT_MAP)
			continue;

		/* Report Map can be longer than MTU-1, use read blob */
		uint8_t buf[4096];
		size_t total = 0;
		uint16_t handle = dev->hid_disc.chars[i].value_handle;

		/* Initial read */
		ret = att_read(&dev->att, handle, buf, sizeof(buf), &len);
		if (ret != 0) {
			warnx("failed to read Report Map");
			return (ret);
		}
		total = len;

		/* Continue with read blob if needed */
		while (len == (size_t)(dev->att.mtu - 1) &&
		    total < sizeof(buf)) {
			ret = att_read_blob(&dev->att, handle, total,
			    buf + total, sizeof(buf) - total, &len);
			if (ret != 0)
				break;
			total += len;
		}

		dev->report_map = malloc(total);
		if (dev->report_map == NULL)
			return (ENOMEM);
		memcpy(dev->report_map, buf, total);
		dev->report_map_len = total;

		if (dev->debug)
			fprintf(stderr, "btled: Report Map: %zu bytes\n",
			    total);
		break;
	}

	if (dev->report_map == NULL) {
		warnx("Report Map characteristic not found");
		return (ENOENT);
	}

	/*
	 * Classify Report characteristics (UUID 0x2A4D).
	 * Each Report has a Report Reference descriptor (UUID 0x2908)
	 * that tells us the report ID and type (input/output/feature).
	 */
	dev->nreports = 0;

	for (int i = 0; i < dev->hid_disc.nchars; i++) {
		if (dev->hid_disc.chars[i].uuid16 != UUID_REPORT)
			continue;
		if (dev->nreports >= HOGP_MAX_REPORTS)
			break;

		struct hogp_report *rpt = &dev->reports[dev->nreports];
		rpt->value_handle = dev->hid_disc.chars[i].value_handle;
		rpt->cccd_handle = 0;
		rpt->report_id = 0;
		rpt->report_type = 0;

		/* Find Report Reference and CCCD descriptors */
		uint16_t desc_start = rpt->value_handle + 1;
		uint16_t desc_end;
		if (i + 1 < dev->hid_disc.nchars)
			desc_end = dev->hid_disc.chars[i + 1].decl_handle - 1;
		else
			desc_end = dev->hid_disc.service.end_handle;

		for (int j = 0; j < dev->hid_disc.ndescs; j++) {
			uint16_t dh = dev->hid_disc.descs[j].handle;
			if (dh < desc_start || dh > desc_end)
				continue;

			if (dev->hid_disc.descs[j].uuid16 ==
			    GATT_UUID_REPORT_REFERENCE) {
				/* Read Report Reference: [report_id, type] */
				uint8_t ref[2];
				ret = att_read(&dev->att, dh, ref,
				    sizeof(ref), &len);
				if (ret == 0 && len >= 2) {
					rpt->report_id = ref[0];
					rpt->report_type = ref[1];
				}
			} else if (dev->hid_disc.descs[j].uuid16 ==
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
	 * Set Protocol Mode to Report Protocol (0x01).
	 */
	for (int i = 0; i < dev->hid_disc.nchars; i++) {
		if (dev->hid_disc.chars[i].uuid16 == UUID_PROTOCOL_MODE) {
			uint8_t mode = HID_PROTOCOL_REPORT;
			att_write_cmd(&dev->att,
			    dev->hid_disc.chars[i].value_handle,
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
	arg.idVersion = 0;
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

	/* Bond storage: read + write + seek */
	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_SEEK);
	if (cap_rights_limit(dev->bond_fd, &rights) < 0)
		return (-1);

	/* HCI socket: send (for encryption commands) */
	cap_rights_init(&rights, CAP_SEND, CAP_RECV, CAP_EVENT);
	if (cap_rights_limit(dev->hci_fd, &rights) < 0)
		return (-1);

	/* Pool sockets: connect + send + recv (for reconnection) */
	if (dev->reconnect) {
		cap_rights_init(&rights, CAP_CONNECT, CAP_SEND, CAP_RECV,
		    CAP_EVENT, CAP_SETSOCKOPT);
		for (int i = dev->att_pool_next; i < SOCK_POOL_SIZE; i++) {
			if (dev->att_pool[i] >= 0)
				cap_rights_limit(dev->att_pool[i], &rights);
		}
		for (int i = dev->smp_pool_next; i < SOCK_POOL_SIZE; i++) {
			if (dev->smp_pool[i] >= 0)
				cap_rights_limit(dev->smp_pool[i], &rights);
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
					write(dev->vhid_fd, full,
					    report_len + 1);
				} else {
					write(dev->vhid_fd, report_data,
					    report_len);
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
