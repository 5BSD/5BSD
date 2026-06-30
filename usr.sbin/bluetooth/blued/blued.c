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

atomic_int blued_verbose = 0;
int blued_daemonized = 0;
atomic_bool blued_shutting_down = false;
static int blued_serviced;
static const char *blued_peripheral_name;
struct blued_ctx blued_g;
const int _blued_kq_ctl_tag;	/* sentinel address for BLUED_KQ_CTL_LISTEN */
const int _blued_kq_setup_pipe_tag;
const int _blued_kq_periph_listen_tag;
const int _blued_kq_rpa_timer_tag;
static const int _blued_kq_ind_timeout_tag;
#define BLUED_KQ_IND_TIMEOUT	((void *)(uintptr_t)&_blued_kq_ind_timeout_tag)
static const int _blued_kq_vhid_output_tag;
#define BLUED_KQ_VHID_OUTPUT	((void *)(uintptr_t)&_blued_kq_vhid_output_tag)

/* ATT transaction timeout: 30 seconds (Core Spec Vol 3 Part F §3.3.3) */
#define ATT_TIMEOUT_SEC		30

/*
 * Monotonic timer ident counter for kqueue EVFILT_TIMER.
 * Avoids pointer-to-int truncation on 64-bit (which could cause
 * timer ident collisions between connections).  Each connection
 * timer gets a unique ident by incrementing this counter.
 * Separate ranges for reconnect, idle, and indication timers
 * are achieved by using different base offsets.
 */
static _Atomic uintptr_t blued_next_timer_id = 1;

/* Idle connection timeout: disconnect peers that send no ATT PDUs for 5 min */
#define BLUED_IDLE_TIMEOUT_SEC	300
static const int _blued_kq_idle_timeout_tag;
#define BLUED_KQ_IDLE_TIMEOUT	((void *)(uintptr_t)&_blued_kq_idle_timeout_tag)

/* Re-advertise retry: arm a 1-second oneshot timer on HCI failure */
#define BLUED_READVERTISE_MAX_RETRIES	3
static const int _blued_kq_readvertise_tag;
#define BLUED_KQ_READVERTISE	((void *)(uintptr_t)&_blued_kq_readvertise_tag)

/*
 * Connection handle poll: after ATT connect(), the kernel needs time to
 * populate its connection table.  We poll with exponential backoff
 * (50ms, 100ms, 200ms, 400ms, 800ms) for up to 5 retries.
 */
#define CON_HANDLE_POLL_INIT_USEC	50000	/* 50ms initial */
#define CON_HANDLE_POLL_RETRIES		5

/* Adapter HCI fd events use the blued_adapter pointer as kqueue udata */

/* Setup timeout: disconnect if connection setup takes > 60 seconds */
#define BLUED_SETUP_TIMEOUT_SEC	60
static const int _blued_kq_setup_timeout_tag;
#define BLUED_KQ_SETUP_TIMEOUT	((void *)(uintptr_t)&_blued_kq_setup_timeout_tag)

#include <dev/hid/vhid.h>

/* GAP/GATT Service UUIDs */
#define UUID_GAP_SERVICE		0x1800
#define UUID_DEVICE_NAME		0x2A00
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

/* Default peripheral name; overridden by cfg.peripheral_name at runtime */
#define PERIPHERAL_NAME_DEFAULT		"5BSD-blued"
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
#define SOCK_POOL_SIZE	BLUED_SOCK_POOL_MAX /* sized to max; only socket_pool_size used */
	int			att_pool[SOCK_POOL_SIZE];
	int			att_pool_next;
};

static volatile sig_atomic_t running = 1;
static struct pidfh *blued_pfh;
static const char *blued_config_path;	/* saved for SIGHUP reload */
static struct blued_config blued_cfg;	/* current daemon config */

static void	usage(void) __dead2;
static void	blued_reload_config(void);
static void	blued_periph_accept(void);
static void	peripheral_build_gattdb(struct att_db *, struct att_attr *,
		    uint8_t *, size_t, const struct blued_config *);
static void	gatt_send_service_changed(struct att_conn *, struct att_db *,
		    uint16_t, uint16_t);
static int	peripheral_att_listen(void);
static int	hogp_discover(struct hogp_device *dev);
static int	hogp_discover_cached(struct hogp_device *dev,
		    struct smp_bond *bond, bool hash_valid);
static void	hogp_cache_save(struct hogp_device *dev, struct smp_bond *bond);
static int	hogp_cache_restore(struct hogp_device *dev, struct smp_bond *bond);
static int	hogp_subscribe(struct hogp_device *dev);
static void	hogp_handle_vhid_output(struct hogp_device *dev);
static int	hogp_setup_vhid(struct hogp_device *dev);

/*
 * BSM audit helper.  Submits an audit record if BSM is enabled.
 * Silently succeeds if audit is not configured or if called from
 * inside the Capsicum sandbox (where /dev/audit is inaccessible).
 */
#ifdef USE_BSM_AUDIT
static void
blued_audit(int event, int error, const char *fmt, ...)
{
	char buf[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	(void)audit_submit(event, getuid(), error, error ? 1 : 0, "%s", buf);
}
#else
#define	blued_audit(event, error, ...)	((void)0)
#endif

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

/*
 * Limit Capsicum capability rights on a single fd.
 * Warns but does not fail if the kernel lacks CAPABILITIES.
 */
static void
cap_limit_fd(int fd, const cap_rights_t *rights, const char *label)
{

	if (cap_rights_limit(fd, rights) < 0 && errno != ENOSYS) {
		warn("cap_rights_limit(%s, fd=%d)", label, fd);
		return;
	}
	LOG_HOGP(2, "capsicum: limited fd %d (%s)", fd, label);
}

/*
 * Limit Capsicum capability rights and lock cloexec/clofork on a
 * single fd.  Used for fds that must never be inherited.
 */
static void
cap_limit_fd_locked(int fd, const cap_rights_t *rights, const char *label)
{

	cap_limit_fd(fd, rights, label);
	(void)cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED);
	(void)cap_clofork_limit(fd, CAP_CLOFORK_LOCKED);
}

/*
 * Restrict all pre-opened fds to minimum required Capsicum rights
 * before entering capability mode.  Called immediately before
 * cap_enter() in both peripheral and central code paths.
 */
static void
blued_capsicum_limit_fds(void)
{
	cap_rights_t rights;
	struct blued_adapter *adp;
	unsigned long hci_ioctls[] = {
		SIOC_HCI_RAW_NODE_GET_CON_LIST,
		SIOC_HCI_RAW_NODE_INIT,
	};

	/* 1. kqueue fd */
	cap_rights_init(&rights, CAP_KQUEUE_EVENT, CAP_KQUEUE_CHANGE);
	cap_limit_fd_locked(blued_g.kq, &rights, "kqueue");

	/* 2. HCI adapter fds */
	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (!adp->active || adp->hci_fd < 0)
			continue;
		cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_EVENT,
		    CAP_IOCTL, CAP_SETSOCKOPT, CAP_GETSOCKOPT);
		cap_limit_fd_locked(adp->hci_fd, &rights, adp->name);
		if (cap_ioctls_limit(adp->hci_fd, hci_ioctls,
		    nitems(hci_ioctls)) < 0 && errno != ENOSYS)
			warn("cap_ioctls_limit(%s)", adp->name);
	}

	/* 3. Bond database fd */
	if (blued_g.bond_fd >= 0) {
		cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_SEEK,
		    CAP_FLOCK, CAP_FSTAT, CAP_FTRUNCATE);
		cap_limit_fd_locked(blued_g.bond_fd, &rights, "bond_db");
	}

	/* 4. Control socket listen fd */
	if (blued_g.ctl_fd >= 0) {
		cap_rights_init(&rights, CAP_ACCEPT, CAP_EVENT);
		cap_limit_fd_locked(blued_g.ctl_fd, &rights, "ctl_listen");
	}

	/* 5. vhid control fd */
	if (blued_g.vhid_ctl_fd >= 0) {
		unsigned long vhid_ioctls[] = { VHID_CREATE };

		cap_rights_init(&rights, CAP_IOCTL, CAP_READ, CAP_WRITE);
		cap_limit_fd_locked(blued_g.vhid_ctl_fd, &rights, "vhid_ctl");
		if (cap_ioctls_limit(blued_g.vhid_ctl_fd, vhid_ioctls,
		    nitems(vhid_ioctls)) < 0 && errno != ENOSYS)
			warn("cap_ioctls_limit(vhid_ctl)");
	}

	/* 6. Self-pipe fds */
	if (blued_g.setup_pipe[0] >= 0) {
		cap_rights_init(&rights, CAP_READ, CAP_EVENT);
		cap_limit_fd_locked(blued_g.setup_pipe[0], &rights,
		    "setup_pipe[0]");
	}
	if (blued_g.setup_pipe[1] >= 0) {
		cap_rights_init(&rights, CAP_WRITE);
		cap_limit_fd_locked(blued_g.setup_pipe[1], &rights,
		    "setup_pipe[1]");
	}

	/* 7. Peripheral listen fd */
	if (blued_g.periph_listen_fd >= 0) {
		cap_rights_init(&rights, CAP_ACCEPT, CAP_EVENT);
		cap_limit_fd_locked(blued_g.periph_listen_fd, &rights,
		    "periph_listen");
	}

	/* 8. Socket pool fds (global pool) */
	cap_rights_init(&rights, CAP_CONNECT, CAP_READ, CAP_WRITE,
	    CAP_EVENT, CAP_SETSOCKOPT, CAP_GETSOCKOPT);
	for (int i = 0; i < blued_g.att_pool_size; i++) {
		if (blued_g.att_pool[i] >= 0)
			cap_limit_fd(blued_g.att_pool[i], &rights,
			    "att_pool");
	}
}

/*
 * Limit socket pool fds inside a per-device hogp_device.
 * Called before cap_enter() in central mode for each spawned device.
 */
static void
blued_capsicum_limit_dev_pool(struct hogp_device *hdev)
{
	cap_rights_t rights;
	int i;

	cap_rights_init(&rights, CAP_CONNECT, CAP_READ, CAP_WRITE,
	    CAP_EVENT, CAP_SETSOCKOPT, CAP_GETSOCKOPT);
	for (i = 0; i < SOCK_POOL_SIZE; i++) {
		if (hdev->att_pool[i] >= 0)
			cap_limit_fd(hdev->att_pool[i], &rights,
			    "hdev_att_pool");
	}
}

static void
atexit_cleanup(void)
{
	if (blued_serviced)
		service_unregister("org.5bsd.blued");
	blued_ctl_cleanup();
	if (blued_pfh != NULL)
		pidfile_remove(blued_pfh);
}

/*
 * Check if any ctl clients are connected.
 */
static bool
ctl_clients_connected(void)
{

	return (!LIST_EMPTY(&blued_g.ctl_clients));
}

/*
 * Send a passkey/numcmp event to all connected ctl clients.
 */
static void
ctl_broadcast_event(const char *fmt, ...)
{
	struct blued_ctl_client *c;
	va_list ap;
	char buf[256];
	int len;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (len <= 0)
		return;
	if (len >= (int)sizeof(buf))
		len = (int)sizeof(buf) - 1;

	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(c, &blued_g.ctl_clients, entries)
		(void)send(c->fd, buf, (size_t)len, MSG_NOSIGNAL);
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

/*
 * Passkey callback for SMP pairing.
 *
 * When ctl clients are connected, sends an event and waits for a reply.
 * Falls back to stderr/stdin when no ctl clients are connected (non-daemon).
 */
static int
passkey_display(uint32_t *passkey, bool display, void *arg)
{
	char addr_str[18];

	if (arg != NULL) {
		bt_ntoa((bdaddr_t *)arg, addr_str);
		memcpy(&blued_g.passkey_target, arg, sizeof(bdaddr_t));
	} else {
		strlcpy(addr_str, "00:00:00:00:00:00", sizeof(addr_str));
		memset(&blued_g.passkey_target, 0, sizeof(bdaddr_t));
	}

	if (display) {
		/*
		 * Display mode — show the passkey to the user.
		 * Send to ctl clients if any are connected.
		 */
		if (ctl_clients_connected())
			ctl_broadcast_event(
			    "EVENT PASSKEY_DISPLAY %s %06u\n",
			    addr_str, *passkey);
		else
			fprintf(stderr,
			    "\n*** Enter this passkey on the BLE device: "
			    "%06u ***\n\n", *passkey);
		return (0);
	}

	/* Input mode — need a passkey from the user */
	if (ctl_clients_connected()) {
		struct timespec ts;
		int ret;

		ctl_broadcast_event(
		    "EVENT PASSKEY_INPUT %s\n", addr_str);

		/* Wait for PASSKEY_REPLY with 30-second timeout */
		pthread_mutex_lock(&blued_g.passkey_lock);
		blued_g.passkey_reply_status = 0; /* pending */
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 30;

		while (blued_g.passkey_reply_status == 0) {
			ret = pthread_cond_timedwait(&blued_g.passkey_cond,
			    &blued_g.passkey_lock, &ts);
			if (ret != 0) {
				blued_g.passkey_reply_status = -1;
				break;
			}
		}

		if (blued_g.passkey_reply_status == 1) {
			*passkey = blued_g.passkey_reply;
			blued_g.passkey_reply_status = -1;
			pthread_mutex_unlock(&blued_g.passkey_lock);
			return (0);
		}
		blued_g.passkey_reply_status = -1;
		pthread_mutex_unlock(&blued_g.passkey_lock);
		return (-1);
	}

	/* Fallback: stdin (non-daemon mode) */
	fprintf(stderr, "Enter the passkey shown on the BLE device: ");
	if (scanf("%u", passkey) != 1) {
		fprintf(stderr, "Passkey entry cancelled.\n");
		return (-1);
	}
	return (0);
}

/*
 * Numeric Comparison callback.
 *
 * When ctl clients are connected, sends an event and waits for a reply.
 * Falls back to stderr/stdin when no ctl clients are connected.
 */
static int
numcmp_confirm(uint32_t value, void *arg)
{
	char addr_str[18];

	if (arg != NULL) {
		bt_ntoa((bdaddr_t *)arg, addr_str);
		memcpy(&blued_g.passkey_target, arg, sizeof(bdaddr_t));
	} else {
		strlcpy(addr_str, "00:00:00:00:00:00", sizeof(addr_str));
		memset(&blued_g.passkey_target, 0, sizeof(bdaddr_t));
	}

	if (ctl_clients_connected()) {
		struct timespec ts;
		int ret;

		ctl_broadcast_event(
		    "EVENT NUMCMP_REQUEST %s %06u\n",
		    addr_str, value);

		/* Wait for NUMCMP_REPLY with 30-second timeout */
		pthread_mutex_lock(&blued_g.passkey_lock);
		blued_g.numcmp_reply_status = 0; /* pending */
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 30;

		while (blued_g.numcmp_reply_status == 0) {
			ret = pthread_cond_timedwait(&blued_g.passkey_cond,
			    &blued_g.passkey_lock, &ts);
			if (ret != 0) {
				blued_g.numcmp_reply_status = -1;
				break;
			}
		}

		if (blued_g.numcmp_reply_status == 1 &&
		    blued_g.numcmp_reply) {
			blued_g.numcmp_reply_status = -1;
			pthread_mutex_unlock(&blued_g.passkey_lock);
			return (0);
		}
		blued_g.numcmp_reply_status = -1;
		pthread_mutex_unlock(&blued_g.passkey_lock);
		return (-1);
	}

	/* Fallback: stdin/stderr (non-daemon mode) */
	{
		char buf[8];

		fprintf(stderr,
		    "\n*** Confirm this number matches the BLE device: "
		    "%06u ***\nDoes it match? [y/n] ", value);
		if (fgets(buf, sizeof(buf), stdin) == NULL)
			return (-1);
		if (buf[0] == 'y' || buf[0] == 'Y')
			return (0);
		fprintf(stderr, "Pairing rejected by user.\n");
		return (-1);
	}
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: blued [-Bdrv] [-a adapter] [-c config] [-f bonds] "
	    "[-L logfile] -s\n"
	    "       blued [-Bdrv] [-a adapter] [-c config] [-f bonds] "
	    "[-L logfile] <bdaddr> [public|random] ...\n"
	    "       blued [-Bdv] [-a adapter] [-c config] [-f bonds] "
	    "[-L logfile] -p\n"
	    "\n"
	    "  -B       run as daemon (background, syslog, pidfile)\n"
	    "  -c file  configuration file\n"
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
 * Load or generate a persistent local IRK for RPA generation.
 * Stored in a file alongside the bond database (bonddb path + ".irk").
 * Returns 0 on success with irk_out filled, -1 on failure.
 */
static int
load_local_irk(const char *bonddb_path, uint8_t irk_out[16])
{
	char irk_path[PATH_MAX];
	int fd;
	ssize_t n;

	snprintf(irk_path, sizeof(irk_path), "%s.irk", bonddb_path);

	fd = open(irk_path, O_RDWR | O_CLOEXEC | O_CLOFORK, 0600);
	if (fd >= 0) {
		n = read(fd, irk_out, 16);
		close(fd);
		if (n == 16) {
			LOG_HCI(1, "loaded local IRK from %s", irk_path);
			return (0);
		}
	}

	/* Generate new IRK */
	arc4random_buf(irk_out, 16);

	fd = open(irk_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		warn("cannot create %s", irk_path);
		return (-1);
	}
	n = write(fd, irk_out, 16);
	fsync(fd);
	close(fd);
	if (n != 16)
		return (-1);

	LOG_HCI(1, "generated new local IRK, saved to %s", irk_path);
	return (0);
}

/* Persistent local IRK for RPA generation */
static uint8_t blued_local_irk[16];
static bool blued_has_local_irk;

/*
 * Load bonded device IRKs into the controller's resolving list.
 * Enables hardware-level RPA resolution for reconnection with
 * privacy-enabled devices.  Best-effort — silently ignored if
 * the controller doesn't support it.
 *
 * If a local IRK is available, it's passed to the controller so
 * it can generate RPAs for our advertising address.
 */
static void
load_resolving_list(struct hogp_device *dev, int rpa_timeout)
{
	const uint8_t *local_irk;
	int loaded = 0;

	local_irk = blued_has_local_irk ? blued_local_irk :
	    (const uint8_t *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	/* Clear any stale entries */
	hci_le_clear_resolving_list(dev->hci_fd);

	for (int i = 0; i < dev->bond_db.count; i++) {
		struct smp_bond *b = &dev->bond_db.bonds[i];

		if (!b->has_irk)
			continue;

		uint8_t at = (b->addr_type == BDADDR_LE_RANDOM) ? 0x01 : 0x00;

		if (hci_le_add_dev_resolving_list(dev->hci_fd, at,
		    b->addr, b->irk, local_irk) == 0) {
			/* Set device privacy mode so we can receive
			 * both RPAs and identity addresses from this peer */
			hci_le_set_privacy_mode(dev->hci_fd, at,
			    b->addr, blued_cfg.privacy_mode);
			loaded++;
		}
	}

	if (loaded > 0) {
		hci_le_set_rpa_timeout(dev->hci_fd, rpa_timeout);
		hci_le_set_addr_resolution_enable(dev->hci_fd, 1);
		LOG_HCI(1, "resolving list: %d device(s) loaded "
		    "(local_irk=%s)", loaded,
		    blued_has_local_irk ? "yes" : "no");

		/* Register host-side RPA rotation timer */
		if (blued_has_local_irk && blued_g.kq >= 0) {
			struct kevent rkev;
			uintptr_t rpa_tid = blued_next_timer_id++;

			EV_SET(&rkev, rpa_tid, EVFILT_TIMER,
			    EV_ADD, NOTE_SECONDS, rpa_timeout,
			    BLUED_KQ_RPA_TIMER);
			if (kevent(blued_g.kq, &rkev, 1, NULL, 0,
			    NULL) == 0)
				LOG_HCI(1, "RPA rotation timer: %ds",
				    rpa_timeout);
		}
	}
}

/*
 * Populate the controller's Filter Accept List with bonded device
 * addresses.  Returns the number of devices loaded.  Used to decide
 * advertising_filter_policy: if > 0, use 0x01 (connect only from
 * accept list); if 0, use 0x00 (allow all for initial pairing).
 *
 * Core Spec Vol 4 Part E §7.8.16 / §7.8.5.
 */
static int
load_filter_accept_list(int hci_fd, struct smp_bond_db *bdb)
{
	int loaded = 0;

	hci_le_clear_filter_accept_list(hci_fd);

	if (bdb == NULL)
		return (0);

	for (int i = 0; i < bdb->count; i++) {
		struct smp_bond *b = &bdb->bonds[i];
		uint8_t at;

		if (!b->has_ltk)
			continue;

		at = (b->addr_type == BDADDR_LE_RANDOM) ? 0x01 : 0x00;
		if (hci_le_add_device_to_filter_accept_list(hci_fd,
		    at, b->addr) == 0)
			loaded++;
	}

	if (loaded > 0)
		LOG_HCI(1, "filter accept list: %d bonded device(s) loaded",
		    loaded);

	return (loaded);
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
		struct ble_scan_result *r = &results[i];

		bt_ntoa((bdaddr_t *)r->addr, addr_str);
		fprintf(stdout, "  %s  %-8s  RSSI: %-4d",
		    addr_str,
		    r->addr_type == BDADDR_LE_RANDOM ? "random" : "public",
		    r->rssi);
		if (r->has_name)
			fprintf(stdout, "  %s", r->name);
		if (r->mfr_id != 0xFFFF)
			fprintf(stdout, "  [mfr:0x%04X]", r->mfr_id);
		for (int j = 0; j < r->num_svc_uuids; j++)
			fprintf(stdout, "  [svc:0x%04X]", r->svc_uuids[j]);
		if (!r->has_name && r->mfr_id == 0xFFFF &&
		    r->num_svc_uuids == 0)
			fprintf(stdout, "  (unknown)");
		fprintf(stdout, "\n");
	}
}

/*
 * bt_devenum callback: open each discovered HCI node and add it
 * to the adapter list.  bt_devenum queries the kernel for real
 * HCI nodes via SIOC_HCI_RAW_NODE_LIST_NAMES — no guessing.
 *
 * Skip nodes with all-zero BD_ADDR — these are phantom netgraph
 * nodes without a real USB transport behind them.
 */
static int
blued_devenum_cb(int s __unused, struct bt_devinfo const *di, void *arg)
{
	int *nfound = arg;
	struct blued_adapter *adp;
	int fd;

	/* Skip nodes not connected to a transport (phantom netgraph nodes) */
	if (!(di->state & NG_HCI_UNIT_CONNECTED)) {
		if (blued_verbose >= 2)
			LOG_HCI(2, "skipping %s: not connected (state=0x%x)",
			    di->devname, di->state);
		return (0);
	}

	fd = hci_open(di->devname);
	if (fd < 0)
		return (0);	/* skip, continue enumeration */

	adp = calloc(1, sizeof(*adp));
	if (adp == NULL) {
		close(fd);
		return (0);
	}
	adp->hci_fd = fd;
	strlcpy(adp->name, di->devname, sizeof(adp->name));
	adp->active = true;
	LIST_INSERT_HEAD(&blued_g.adapters, adp, entries);
	(*nfound)++;

	return (0);	/* continue enumeration */
}

static int
blued_enumerate_adapters(struct blued_config *cfg)
{
	struct blued_adapter *adp;
	int i, nfound;

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
		/* Ask the kernel for real HCI nodes */
		if (bt_devenum(blued_devenum_cb, &nfound) < 0)
			warn("bt_devenum");
	}

	return (nfound);
}

static int
blued_adapter_init(struct blued_adapter *adp)
{

	if (hci_reset(adp->hci_fd) < 0) {
		warn("reset %s", adp->name);
		return (-1);
	}
	/*
	 * Post-reset settle time: the kernel's ng_hci Reset Complete
	 * handler clears the INITED flag asynchronously.  Without a
	 * brief delay, subsequent HCI commands can race with the flag
	 * clear.  100ms is empirically sufficient on all tested USB
	 * adapters; BlueZ uses 0ms but operates through the kernel
	 * MGMT layer which serializes internally.
	 */
	usleep(100000); /* 100ms post-reset settle */

	if (hci_get_bdaddr(adp->hci_fd, (uint8_t *)&adp->addr) < 0) {
		warn("read BD_ADDR for %s", adp->name);
		return (-1);
	}

	if (hci_write_le_host_support(adp->hci_fd, 1, 1) < 0 && blued_verbose)
		warn("write LE host support for %s", adp->name);

	if (hci_le_read_local_features(adp->hci_fd, &adp->le_features) < 0)
		adp->le_features = 0;

	hci_set_event_mask(adp->hci_fd,
	    NG_HCI_EVENT_MASK_DEFAULT | NG_HCI_EVENT_MASK_LE);

	/* Set LE event mask. Feature bits and event-mask bits differ. */
	hci_le_set_event_mask(adp->hci_fd,
	    hci_le_default_event_mask(adp->le_features));

	/*
	 * Set controller-wide defaults for Data Length Extension and PHY.
	 * These apply to all future connections so they must be set once
	 * at init rather than per-connection.  Best-effort: silently
	 * ignored if the controller doesn't support the feature.
	 */
	if (adp->le_features & LE_FEAT_DATA_LENGTH_EXT)
		hci_le_write_suggested_default_data_length(adp->hci_fd,
		    0x00FB /* 251 octets */, 0x0848 /* 2120 μs */);
	if (adp->le_features & LE_FEAT_2M_PHY)
		hci_le_set_default_phy(adp->hci_fd, 0x00 /* no preference */,
		    0x02 /* prefer 2M TX */, 0x02 /* prefer 2M RX */);

	/*
	 * Query controller buffer sizes for flow control awareness.
	 * Log capabilities for diagnostics.
	 */
	{
		uint16_t acl_len = 0, iso_len = 0;
		uint8_t acl_num = 0, iso_num = 0;

		if (hci_le_read_buffer_size_v2(adp->hci_fd,
		    &acl_len, &acl_num, &iso_len, &iso_num) == 0 &&
		    blued_verbose >= 1)
			LOG_HCI(1, "%s: LE buffers: acl_len=%d acl_num=%d",
			    adp->name, acl_len, acl_num);
	}

	/*
	 * Query advertising capabilities for diagnostics.
	 */
	if (adp->le_features & LE_FEAT_EXT_ADVERTISING) {
		uint8_t num_sets = 0;
		uint16_t max_adv_len = 0;

		if (hci_le_read_num_supported_adv_sets(adp->hci_fd,
		    &num_sets) == 0)
			LOG_HCI(1, "%s: %d advertising sets supported",
			    adp->name, num_sets);
		if (hci_le_read_max_adv_data_length(adp->hci_fd,
		    &max_adv_len) == 0)
			LOG_HCI(1, "%s: max adv data length=%d",
			    adp->name, max_adv_len);
	}

	/*
	 * Log LL-level connection parameter request support.
	 * If supported, the controller handles parameter negotiation
	 * at the Link Layer, making our l2cap_conn_param_update_req
	 * stub acceptable.
	 */
	if (adp->le_features & LE_FEAT_CONN_PARAM_REQ)
		LOG_HCI(1, "%s: LL Connection Parameter Request supported",
		    adp->name);

	/*
	 * NODE_INIT must come LAST.  hci_reset() triggers the kernel's
	 * Reset Complete handler which clears the INITED flag.  That
	 * handler runs asynchronously in the Netgraph thread, so if we
	 * call NODE_INIT too early the flag gets cleared after we set
	 * it.  Putting NODE_INIT after all other HCI commands gives the
	 * kernel time to finish processing the reset.  The bdaddr must
	 * also be read first since NODE_INIT requires a non-zero bdaddr.
	 */
	if (hci_node_init(adp->hci_fd) < 0 && blued_verbose)
		warn("node init for %s", adp->name);

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
struct att_db periph_gatt_db;
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

		blued_conn_set_state(conn, BLUED_CONN_RECONNECTING);
		if (conn->reconnect_delay == 0)
			conn->reconnect_delay = 3;
		LOG_HOGP(1, "setup failed, reconnecting in %d seconds...",
		    conn->reconnect_delay);

		conn->reconnect_timer = blued_next_timer_id++;
		EV_SET(&kev, conn->reconnect_timer,
		    EVFILT_TIMER,
		    EV_ADD | EV_ONESHOT, NOTE_SECONDS,
		    conn->reconnect_delay, conn);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);

		conn->reconnect_delay *= 2;
		if (conn->reconnect_delay > blued_reconnect_max_delay)
			conn->reconnect_delay = blued_reconnect_max_delay;
	} else {
		blued_conn_set_state(conn, BLUED_CONN_IDLE);
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

	/*
	 * Connection limit is now enforced atomically in
	 * blued_conn_alloc() under the write lock.
	 */

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

	/* Check for daemon shutdown between blocking steps */
	if (atomic_load(&blued_shutting_down)) {
		blued_central_setup_fail(conn);
		return (NULL);
	}

	LOG_HOGP(1, "connected, exchanging MTU");

	/* Get connection handle — poll with exponential backoff */
	{
		int retries;
		useconds_t delay = CON_HANDLE_POLL_INIT_USEC;

		for (retries = 0; retries < CON_HANDLE_POLL_RETRIES;
		    retries++) {
			if (hci_get_con_handle(dev->hci_fd, dev->addr,
			    &dev->con_handle) == 0)
				break;
			usleep(delay);
			delay *= 2;
		}
		if (retries == CON_HANDLE_POLL_RETRIES) {
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
					dev->att.enc_key_size = 16;
					LOG_HOGP(1, "encrypted");
				}
			}
		}
	}

	/*
	 * Check GATT Database Hash before discovery.
	 * Per Core Spec Vol 3 Part G §7.3.1 (Robust Caching), if the
	 * hash matches the bonded value, attribute handles are unchanged
	 * and we can use cached handles to skip full GATT discovery.
	 */
	{
		uint8_t remote_hash[16];
		struct smp_bond *bond;
		bool hash_valid = false;

		bond = smp_find_bond(&dev->bond_db, dev->addr,
		    dev->addr_type);
		if (bond != NULL && bond->has_db_hash) {
			if (gatt_read_database_hash(&dev->att,
			    remote_hash) == 0) {
				if (memcmp(bond->db_hash, remote_hash,
				    16) == 0) {
					LOG_HOGP(1, "GATT DB hash "
					    "unchanged, cache valid");
					hash_valid = true;
				} else {
					LOG_HOGP(1, "GATT DB hash "
					    "changed, full discovery "
					    "needed");
					memcpy(bond->db_hash, remote_hash,
					    16);
					bond->has_handle_cache = false;
					smp_bond_db_save(&dev->bond_db);
				}
			}
		}

		ret = hogp_discover_cached(dev, bond, hash_valid);
	}

	/* Handle Database Out Of Sync — full rediscovery */
	if (ret == ATT_ERR_DATABASE_OUT_OF_SYNC) {
		struct smp_bond *bond;

		LOG_HOGP(1, "ATT Database Out Of Sync, full rediscovery");
		bond = smp_find_bond(&dev->bond_db, dev->addr,
		    dev->addr_type);
		if (bond != NULL) {
			bond->has_handle_cache = false;
			bond->has_db_hash = false;
		}
		ret = hogp_discover(dev);
	}

	/* Handle auth errors — pair and retry */
	{
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
			dev->smp.passkey_cb_arg = &conn->dst;
			dev->smp.numcmp_cb = numcmp_confirm;
			dev->smp.numcmp_cb_arg = &conn->dst;
			dev->smp.io_capability = blued_cfg.io_capability;
			dev->smp.min_key_size = blued_cfg.min_key_size;
			dev->att.min_key_size = blued_cfg.min_key_size;
			dev->smp.sc_only = blued_cfg.sc_only;

			if (smp_pair(&dev->smp) < 0) {
				warnx("SMP pairing failed");
				blued_central_setup_fail(conn);
				return (NULL);
			}

			if (hci_wait_encryption(dev->hci_fd,
			    dev->con_handle, 10) < 0)
				warn("post-pairing encryption timeout");
			else {
				dev->att.encrypted = true;
				dev->att.enc_key_size = 16;
			}

			LOG_HOGP(1, "pairing complete, retrying discovery");

			ret = hogp_discover(dev);
		}
		if (ret != 0) {
			warnx("HOGP discovery failed: %d", ret);
			blued_central_setup_fail(conn);
			return (NULL);
		}
	}

	/* Update GATT Database Hash and handle cache after discovery */
	{
		uint8_t remote_hash[16];
		struct smp_bond *bond;

		bond = smp_find_bond(&dev->bond_db, dev->addr,
		    dev->addr_type);
		if (bond != NULL) {
			if (!bond->has_db_hash) {
				if (gatt_read_database_hash(&dev->att,
				    remote_hash) == 0) {
					memcpy(bond->db_hash, remote_hash, 16);
					bond->has_db_hash = true;
				}
			}
			hogp_cache_save(dev, bond);
			smp_bond_db_save(&dev->bond_db);
			LOG_HOGP(1, "GATT DB hash and handle cache saved");
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
	blued_conn_set_state(conn, BLUED_CONN_ACTIVE);

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

	/*
	 * Register vhid fd for Output reports (LED state etc.).
	 * The kernel vhid driver sends Output reports via read() on
	 * the vhid fd when applications set HID output state.
	 */
	if (dev->vhid_fd >= 0) {
		struct kevent vkev;

		EV_SET(&vkev, dev->vhid_fd, EVFILT_READ,
		    EV_ADD | EV_ENABLE, 0, 0, BLUED_KQ_VHID_OUTPUT);
		if (kevent(blued_g.kq, &vkev, 1, NULL, 0, NULL) < 0)
			warn("kevent vhid output (non-fatal)");
		else
			LOG_HOGP(1, "vhid output reports enabled");
	}

	/* Reset backoff on successful connection */
	conn->reconnect_delay = 0;

	/* Log negotiated PHY for diagnostics */
	{
		uint8_t tx_phy, rx_phy;

		if (hci_le_read_phy(dev->hci_fd, dev->con_handle,
		    &tx_phy, &rx_phy) == 0)
			LOG_HCI(1, "PHY: tx=%s rx=%s",
			    tx_phy == 2 ? "2M" : tx_phy == 3 ? "Coded" : "1M",
			    rx_phy == 2 ? "2M" : rx_phy == 3 ? "Coded" : "1M");
	}

	/* Log TX power for link quality diagnostics */
	if (dev->le_features & LE_FEAT_POWER_CONTROL) {
		int8_t cur_lvl, max_lvl;

		if (hci_le_enhanced_read_tx_power_level(dev->hci_fd,
		    dev->con_handle, 0x01 /* LE */,
		    &cur_lvl, &max_lvl) == 0)
			LOG_HCI(1, "TX power: current=%d dBm max=%d dBm",
			    cur_lvl, max_lvl);
	}

	/*
	 * Proactively open EATT bearers if both sides support it.
	 * Core Spec Vol 3 Part G Section 2.4.1: enhanced bearers
	 * provide parallel GATT operations.  Only attempted after
	 * encryption is active (EATT requires security).
	 */
	if (blued_cfg.eatt && dev->att.encrypted && !cap_sandboxed()) {
		int eatt_opened;

		eatt_opened = att_open_eatt(&dev->att,
		    dev->addr, dev->addr_type, 2);
		if (eatt_opened > 0)
			LOG_ATT(1, "opened %d EATT bearer(s)", eatt_opened);
	}

	/*
	 * Request connection subrating if the controller supports it
	 * and a subrate factor is configured.  This reduces power
	 * consumption for idle HID connections by allowing the
	 * peripheral to skip connection events.
	 */
	if (blued_cfg.subrate_factor > 0 &&
	    (dev->le_features & LE_FEAT_CONN_SUBRATING)) {
		if (hci_le_subrate_request(dev->hci_fd, dev->con_handle,
		    (uint16_t)blued_cfg.subrate_factor,
		    (uint16_t)blued_cfg.subrate_factor,
		    0, 0, 200) == 0)
			LOG_HCI(1, "subrate requested: factor=%d",
			    blued_cfg.subrate_factor);
	}

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
/*
 * Arm the 30-second ATT indication timeout (Core Spec Vol 3 Part F §3.3.3).
 * Called after successfully sending an indication.  If the client does not
 * confirm within 30 seconds, the bearer must be disconnected.
 */
static void __unused
blued_ind_arm_timeout(struct blued_conn *conn)
{
	struct kevent kev;
	uintptr_t ident;

	if (conn->att == NULL)
		return;

	ident = blued_next_timer_id++;
	conn->att->ind_timer = ident;

	EV_SET(&kev, ident, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS, ATT_TIMEOUT_SEC,
	    BLUED_KQ_IND_TIMEOUT);
	(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
}

/*
 * Disarm the indication timeout (called when confirmation is received).
 */
static void
blued_ind_disarm_timeout(struct blued_conn *conn)
{
	struct kevent kev;

	if (conn->att == NULL || conn->att->ind_timer == 0)
		return;

	EV_SET(&kev, conn->att->ind_timer, EVFILT_TIMER,
	    EV_DELETE, 0, 0, NULL);
	(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	conn->att->ind_timer = 0;
}

/*
 * Arm or reset the idle connection timeout.
 * Called on connection setup and on each received ATT PDU.
 */
static void
blued_idle_arm(struct blued_conn *conn)
{
	struct kevent kev;

	/* Only for peripheral connections */
	if (conn->role != BLUED_ROLE_PERIPHERAL)
		return;

	if (conn->idle_timer == 0)
		conn->idle_timer = blued_next_timer_id++;

	EV_SET(&kev, conn->idle_timer, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS, BLUED_IDLE_TIMEOUT_SEC,
	    BLUED_KQ_IDLE_TIMEOUT);
	(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
}

static void
blued_idle_disarm(struct blued_conn *conn)
{
	struct kevent kev;

	if (conn->idle_timer == 0)
		return;

	EV_SET(&kev, conn->idle_timer, EVFILT_TIMER,
	    EV_DELETE, 0, 0, NULL);
	(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	conn->idle_timer = 0;
}

static void
blued_periph_readvertise(void)
{
	static int readvertise_retries;
	struct blued_adapter *adp;

	adp = LIST_FIRST(&blued_g.adapters);
	if (adp != NULL && blued_g.periph_active) {
		int adv_err;

		if (adp->le_features & LE_FEAT_EXT_ADVERTISING)
			adv_err = hci_le_set_ext_adv_enable(adp->hci_fd,
			    1, 0x00);
		else
			adv_err = hci_le_set_advertise_enable(adp->hci_fd,
			    true);
		if (adv_err < 0) {
			warn("re-advertise failed");
			if (readvertise_retries <
			    BLUED_READVERTISE_MAX_RETRIES) {
				struct kevent kev;

				readvertise_retries++;
				LOG_HOGP(1, "re-advertise retry %d/%d "
				    "in 1 second",
				    readvertise_retries,
				    BLUED_READVERTISE_MAX_RETRIES);
				EV_SET(&kev, blued_next_timer_id++,
				    EVFILT_TIMER,
				    EV_ADD | EV_ONESHOT, NOTE_SECONDS,
				    1, BLUED_KQ_READVERTISE);
				(void)kevent(blued_g.kq, &kev, 1,
				    NULL, 0, NULL);
			} else {
				LOG_HOGP(0, "re-advertise failed after "
				    "%d retries, peripheral not "
				    "discoverable",
				    BLUED_READVERTISE_MAX_RETRIES);
			}
		} else {
			readvertise_retries = 0;
			LOG_HOGP(1, "re-advertising");
		}
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

	LOG_HOGP(2, "peripheral listen socket readable, accepting");

	/*
	 * Rate-limit accept() to mitigate rapid connect/disconnect DoS.
	 * Token bucket: 2 tokens/sec, max burst of 4.
	 */
	{
		static time_t last_accept;
		static int tokens;
		time_t now = time(NULL);

		if (now != last_accept) {
			/* Refill: 2 tokens per second, max 4 */
			int elapsed = (int)(now - last_accept);
			if (elapsed > 4)
				elapsed = 4;
			tokens += elapsed * 2;
			if (tokens > 4)
				tokens = 4;
			last_accept = now;
		}
		if (tokens <= 0) {
			LOG_HOGP(1, "accept rate limit, rejecting");
			client_fd = accept4(blued_g.periph_listen_fd, NULL,
			    NULL, SOCK_CLOEXEC | SOCK_CLOFORK);
			if (client_fd >= 0)
				close(client_fd);
			return;
		}
		tokens--;
	}

	/* Enforce maximum simultaneous connections */
	{
		struct blued_conn *cc;
		int nactive = 0;

		pthread_rwlock_rdlock(&blued_g.conns_lock);
		LIST_FOREACH(cc, &blued_g.conns, entries)
			nactive++;
		pthread_rwlock_unlock(&blued_g.conns_lock);
		if (nactive >= BLUED_MAX_CONNS) {
			LOG_HOGP(1, "max connections (%d) reached, rejecting",
			    BLUED_MAX_CONNS);
			/* Drain the pending accept to avoid busy-loop */
			client_fd = accept4(blued_g.periph_listen_fd, NULL,
			    NULL, SOCK_CLOEXEC | SOCK_CLOFORK);
			if (client_fd >= 0)
				close(client_fd);
			return;
		}
	}

	peer_len = sizeof(peer_sa);
	client_fd = accept4(blued_g.periph_listen_fd,
	    (struct sockaddr *)&peer_sa, &peer_len,
	    SOCK_CLOEXEC | SOCK_CLOFORK);
	if (client_fd < 0) {
		if (errno != EINTR)
			warn("peripheral accept");
		return;
	}

	/* Guard against duplicate connections from the same device */
	{
		struct blued_conn *existing;

		existing = blued_conn_by_addr(
		    (const bdaddr_t *)peer_sa.l2cap_bdaddr.b);
		if (existing != NULL) {
			char addr_str[18];
			bt_ntoa((bdaddr_t *)peer_sa.l2cap_bdaddr.b, addr_str);
			LOG_HOGP(1, "duplicate connection from %s, "
			    "closing stale", addr_str);
			blued_conn_disconnect(existing);
		}
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
	ac->min_key_size = blued_cfg.min_key_size;
	ac->ind_timer = 0;
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
	blued_conn_set_state(conn, BLUED_CONN_CONNECTING);

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

	blued_conn_set_state(conn, BLUED_CONN_IDLE);
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

	/* Get connection handle — poll with exponential backoff */
	{
		uint16_t ch = 0;
		int retries;
		useconds_t delay = CON_HANDLE_POLL_INIT_USEC;

		for (retries = 0; retries < CON_HANDLE_POLL_RETRIES;
		    retries++) {
			if (hci_get_con_handle(adp->hci_fd,
			    (const uint8_t *)&conn->dst, &ch) == 0)
				break;
			usleep(delay);
			delay *= 2;
		}
		if (retries < CON_HANDLE_POLL_RETRIES) {
			conn->con_handle = ch;
			ac->con_handle = ch;

			/* Request DLE for peripheral connections */
			if (adp->le_features & LE_FEAT_DATA_LENGTH_EXT)
				hci_le_set_data_length(adp->hci_fd, ch,
				    0x00FB, 0x0848);
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

		pthread_mutex_lock(&blued_g.bond_db_lock);
		bond = smp_find_bond(blued_g.bond_db,
		    (const uint8_t *)&conn->dst, conn->addr_type);
		pthread_mutex_unlock(&blued_g.bond_db_lock);
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
				sc.io_capability = blued_cfg.io_capability;
				sc.min_key_size = blued_cfg.min_key_size;
				sc.sc_only = blued_cfg.sc_only;

				if (smp_respond(&sc) == 0) {
					LOG_HOGP(1, "peripheral SMP pairing "
					    "complete, waiting for encryption");
					if (hci_wait_encryption(adp->hci_fd,
					    conn->con_handle, 10) < 0)
						warn("post-pairing encryption "
						    "timeout");
					else {
						ac->encrypted = true;
						ac->enc_key_size = 16;
						/* LE Ping: set auth payload
						 * timeout to 30s (3000 * 10ms)
						 * per Core Spec Vol 6 §5.4 */
						hci_le_write_auth_payload_timeout(
						    adp->hci_fd,
						    conn->con_handle, 3000);
					}
				}
				smp_close(&sc);
			}
		}
	}
skip_smp:

	/*
	 * Reset per-connection CCCD state, then restore for a bonded
	 * device if applicable.  CCCDs are per-connection (stored in
	 * ac->cccds[]), not in the shared att_db.  This ensures unbonded
	 * connections start with all CCCDs at zero (Core Spec Vol 3
	 * Part G §2.5.3).
	 */
	att_server_reset(ac);
	pthread_mutex_lock(&blued_g.bond_db_lock);
	if (blued_g.bond_db != NULL) {
		struct smp_bond *bond;

		bond = smp_find_bond(blued_g.bond_db,
		    (const uint8_t *)&conn->dst, conn->addr_type);
		if (bond != NULL && bond->num_cccds > 0) {
			smp_bond_restore_cccds(bond, ac);
			LOG_HOGP(1, "restored %d CCCD(s) for bonded device",
			    bond->num_cccds);
		}

		/* Restore CSRK and sign counter for Signed Write verification */
		if (bond != NULL && bond->has_csrk) {
			memcpy(ac->peer_csrk, bond->csrk, 16);
			ac->has_peer_csrk = true;
			ac->peer_sign_counter = bond->peer_sign_counter;
			ac->has_peer_sign_counter =
			    (bond->peer_sign_counter > 0);
			LOG_HOGP(1, "restored peer CSRK and sign "
			    "counter (%u) for bonded device",
			    bond->peer_sign_counter);
		}

		/*
		 * Service Changed indication for bonded devices.
		 * If the server's GATT database has changed since this
		 * client last connected (db_hash mismatch), send a
		 * Service Changed indication so the client invalidates
		 * its attribute cache (Core Spec Vol 3 Part G §2.5.2,
		 * §7.1).
		 */
		if (bond != NULL && bond->has_db_hash) {
			uint8_t cur_hash[16];

			attdb_compute_db_hash(&periph_gatt_db, cur_hash);
			if (memcmp(bond->db_hash, cur_hash, 16) != 0) {
				LOG_GATT(1, "db_hash changed for bonded "
				    "device, sending Service Changed");
				gatt_send_service_changed(ac,
				    &periph_gatt_db, 0x0001, 0xFFFF);
				memcpy(bond->db_hash, cur_hash, 16);
				smp_bond_db_save(blued_g.bond_db);
			}
		} else if (bond != NULL && !bond->has_db_hash) {
			/*
			 * First connection after bonding — save the
			 * server's current db_hash so future reconnects
			 * can detect changes.
			 */
			attdb_compute_db_hash(&periph_gatt_db,
			    bond->db_hash);
			bond->has_db_hash = true;
			smp_bond_db_save(blued_g.bond_db);
			LOG_GATT(1, "saved server db_hash for bonded "
			    "device");
		}
	}
	pthread_mutex_unlock(&blued_g.bond_db_lock);

	/*
	 * Arm idle timeout before registering with kqueue, so the main
	 * thread cannot race on conn->idle_timer between register and arm.
	 */
	blued_conn_set_state(conn, BLUED_CONN_ACTIVE);
	blued_idle_arm(conn);

	/* Register with kqueue event loop */
	if (blued_conn_register(conn) < 0) {
		warnx("peripheral conn register failed");
		blued_idle_disarm(conn);
		blued_periph_setup_fail(conn);
		return (NULL);
	}

	{
		char addr_str[18];
		bt_ntoa(&conn->dst, addr_str);
		LOG_HOGP(1, "peripheral client connected: %s "
		    "(handle=%04x encrypted=%d)",
		    addr_str, conn->con_handle, ac->encrypted);
		BLUED_PROBE_CONN_OPEN(addr_str, 1 /* peripheral */);
	}

	/* Log negotiated PHY */
	{
		struct blued_adapter *pa = LIST_FIRST(&blued_g.adapters);
		uint8_t tx_phy, rx_phy;

		if (pa != NULL && conn->con_handle != 0 &&
		    hci_le_read_phy(pa->hci_fd, conn->con_handle,
		    &tx_phy, &rx_phy) == 0)
			LOG_HCI(1, "PHY: tx=%s rx=%s",
			    tx_phy == 2 ? "2M" : tx_phy == 3 ? "Coded" : "1M",
			    rx_phy == 2 ? "2M" : rx_phy == 3 ? "Coded" : "1M");
	}

	/*
	 * Request better connection parameters as peripheral.
	 * iOS/Android use conservative defaults (30ms interval).
	 * Request 30-50ms interval, 0 latency, 2s supervision timeout.
	 * Core Spec Vol 3 Part A §4.20.
	 */
	{
		struct blued_adapter *a = LIST_FIRST(&blued_g.adapters);
		if (a != NULL) {
			if (l2cap_conn_param_update_req(
			    (const uint8_t *)&a->addr,
			    (const uint8_t *)&conn->dst, conn->addr_type,
			    24, 40, 0, 200) < 0 && blued_verbose >= 2)
				warn("L2CAP conn param update");
		}
	}

	(void)write(blued_g.setup_pipe[1], "x", 1);
	return (NULL);
}

/*
 * Handle asynchronous HCI events from the adapter.
 *
 * Registered with kqueue in peripheral mode to catch LE LTK Request
 * events (subevent 0x05) that arrive when a bonded device reconnects
 * and initiates encryption.  The kernel forwards these to userspace
 * via the raw HCI socket — we must reply with either LTK Reply or
 * Negative Reply, otherwise the controller stalls.
 *
 * Also handles Authenticated Payload Timeout Expired (0x57).
 */
static void
blued_handle_hci_event(struct blued_adapter *adp)
{
	uint8_t buf[256];
	ssize_t n;

	if (adp == NULL)
		return;

	do {
		n = recv(adp->hci_fd, buf, sizeof(buf), MSG_DONTWAIT);
	} while (n < 0 && errno == EINTR);
	if (n < 5)
		return;

	/*
	 * HCI event packet from raw socket includes packet type prefix:
	 * [type(1), event_code(1), param_len(1), params...]
	 * type is always 0x04 (HCI_EVENT_PKT).
	 * For LE Meta: params = [subevent(1), ...]
	 */
	uint8_t event_code = buf[1];

	/* LE Meta Event (0x3E) */
	if (event_code == 0x3E && n >= 5) {
		uint8_t subevent = buf[3];

		/* LE Connection Complete (subevent 0x01):
		 * [type(1), evt(1), len(1), subevent(1), status(1),
		 *  handle(2), role(1), addr_type(1), addr(6),
		 *  interval(2), latency(2), timeout(2), accuracy(1)]
		 * = 22 bytes total */
		if (subevent == 0x01 && n >= 22 && buf[4] == 0) {
			uint16_t interval = get_le16(buf + 15);
			uint16_t latency = get_le16(buf + 17);
			uint16_t timeout = get_le16(buf + 19);
			const uint8_t *peer_addr = buf + 9;
			struct blued_conn *conn;

			/*
			 * Match by peer address, not con_handle,
			 * because con_handle may not be set yet
			 * in the blued_conn during connection setup.
			 */
			pthread_rwlock_wrlock(&blued_g.conns_lock);
			LIST_FOREACH(conn, &blued_g.conns, entries) {
				if (memcmp(&conn->dst, peer_addr, 6) == 0) {
					conn->conn_interval = interval;
					conn->conn_latency = latency;
					conn->supervision_timeout = timeout;
					break;
				}
			}
			pthread_rwlock_unlock(&blued_g.conns_lock);
		}

		/* LE Enhanced Connection Complete (subevent 0x0A):
		 * Same conn param offsets as 0x01 but with
		 * additional local/peer RPA fields.
		 * [type(1), evt(1), len(1), subevent(1), status(1),
		 *  handle(2), role(1), addr_type(1), addr(6),
		 *  local_rpa(6), peer_rpa(6),
		 *  interval(2), latency(2), timeout(2), accuracy(1)]
		 * = 34 bytes total */
		if (subevent == 0x0A && n >= 34 && buf[4] == 0) {
			uint16_t interval = get_le16(buf + 27);
			uint16_t latency = get_le16(buf + 29);
			uint16_t timeout = get_le16(buf + 31);
			const uint8_t *peer_addr = buf + 9;
			struct blued_conn *conn;

			pthread_rwlock_wrlock(&blued_g.conns_lock);
			LIST_FOREACH(conn, &blued_g.conns, entries) {
				if (memcmp(&conn->dst, peer_addr, 6) == 0) {
					conn->conn_interval = interval;
					conn->conn_latency = latency;
					conn->supervision_timeout = timeout;
					break;
				}
			}
			pthread_rwlock_unlock(&blued_g.conns_lock);
		}

		/* LE Connection Update Complete (subevent 0x03):
		 * [type(1), evt(1), len(1), subevent(1), status(1),
		 *  handle(2), interval(2), latency(2), timeout(2)]
		 * = 13 bytes total */
		if (subevent == 0x03 && n >= 13 && buf[4] == 0) {
			uint16_t handle = get_le16(buf + 5);
			uint16_t interval = get_le16(buf + 7);
			uint16_t latency = get_le16(buf + 9);
			uint16_t timeout = get_le16(buf + 11);
			struct blued_conn *conn;

			pthread_rwlock_wrlock(&blued_g.conns_lock);
			LIST_FOREACH(conn, &blued_g.conns, entries) {
				if (conn->con_handle == handle) {
					conn->conn_interval = interval;
					conn->conn_latency = latency;
					conn->supervision_timeout = timeout;
					break;
				}
			}
			pthread_rwlock_unlock(&blued_g.conns_lock);
		}

		/* LE PHY Update Complete (subevent 0x0C):
		 * [type(1), evt(1), len(1), subevent(1), status(1),
		 *  handle(2), tx_phy(1), rx_phy(1)] = 9 bytes total */
		if (subevent == 0x0C && n >= 9 && buf[4] == 0) {
			uint16_t handle = get_le16(buf + 5);
			uint8_t tx_phy = buf[7];
			uint8_t rx_phy = buf[8];

			LOG_HCI(1, "PHY update: handle=%04x tx=%s rx=%s",
			    handle,
			    tx_phy == 2 ? "2M" : tx_phy == 3 ? "Coded" : "1M",
			    rx_phy == 2 ? "2M" : rx_phy == 3 ? "Coded" : "1M");
		}

		/* LE Read Remote Features Complete (subevent 0x04):
		 * [type(1), evt(1), len(1), subevent(1), status(1),
		 *  handle(2), features(8)] = 15 bytes total */
		if (subevent == 0x04 && n >= 15 && buf[4] == 0) {
			uint16_t handle = get_le16(buf + 5);
			uint64_t features;

			memcpy(&features, buf + 7, 8);
			LOG_HCI(1, "remote features: handle=%04x "
			    "features=0x%016llx", handle,
			    (unsigned long long)features);
		}

		/* LE LTK Request (subevent 0x05):
		 * [type(1), evt(1), len(1), subevent(1), handle(2),
		 *  random(8), ediv(2)] = 16 bytes total */
		if (subevent == 0x05 && n >= 16) {
			uint16_t handle = get_le16(buf + 4);
			uint64_t rand_val;
			uint16_t ediv;

			memcpy(&rand_val, buf + 6, 8);
			ediv = get_le16(buf + 14);

			LOG_SMP(1, "LTK request: handle=%04x ediv=%04x",
			    handle, ediv);

			/* Find the bond for this connection */
			if (blued_g.bond_db != NULL) {
				struct blued_conn *conn;
				struct smp_bond *bond = NULL;
				uint8_t ltk_copy[16];
				bool has_ltk = false;

				/*
				 * Look up bond under conns_lock and set
				 * encrypted while still holding the lock
				 * to prevent a TOCTOU race with setup
				 * threads that could free the conn.
				 *
				 * Lock ordering: conns_lock → bond_db_lock.
				 */
				/*
				 * Use wrlock because we may write
				 * conn->att->encrypted below.
				 */
				pthread_rwlock_wrlock(&blued_g.conns_lock);
				LIST_FOREACH(conn, &blued_g.conns, entries) {
					if (conn->con_handle == handle) {
						pthread_mutex_lock(
						    &blued_g.bond_db_lock);
						bond = smp_find_bond(
						    blued_g.bond_db,
						    (const uint8_t *)&conn->dst,
						    conn->addr_type);
						if (bond != NULL &&
						    bond->has_ltk) {
							memcpy(ltk_copy,
							    bond->ltk, 16);
							has_ltk = true;
						}
						pthread_mutex_unlock(
						    &blued_g.bond_db_lock);
						break;
					}
				}

				if (has_ltk) {
					if (hci_le_ltk_request_reply(
					    adp->hci_fd, handle,
					    ltk_copy) == 0) {
						LOG_SMP(1, "LTK reply sent "
						    "for handle=%04x", handle);
						if (conn != NULL &&
						    conn->att != NULL)
							conn->att->encrypted =
							    true;
						hci_le_write_auth_payload_timeout(
						    adp->hci_fd, handle,
						    3000);
					} else {
						warn("LTK reply failed");
					}
					explicit_bzero(ltk_copy,
					    sizeof(ltk_copy));
				} else {
					LOG_SMP(1, "no bond for handle=%04x, "
					    "sending negative reply", handle);
					hci_le_ltk_request_neg_reply(
					    adp->hci_fd, handle);
				}
				pthread_rwlock_unlock(&blued_g.conns_lock);
			} else {
				hci_le_ltk_request_neg_reply(
				    adp->hci_fd, handle);
			}
		}
	}

	/* Authenticated Payload Timeout Expired (0x57)
	 * [type(1), evt(1), len(1), handle(2)] = 5 bytes */
	if (event_code == 0x57 && n >= 5) {
		uint16_t handle = get_le16(buf + 3);
		struct blued_conn *conn;

		LOG_SMP(1, "auth payload timeout expired: handle=%04x",
		    handle);
		BLUED_LOG_SECURITY("auth payload timeout expired "
		    "handle=%04x — disconnecting", handle);

		{
			bool found = false;

			pthread_rwlock_rdlock(&blued_g.conns_lock);
			LIST_FOREACH(conn, &blued_g.conns, entries) {
				if (conn->con_handle == handle) {
					atomic_store_explicit(
					    &conn->needs_cleanup, true,
					    memory_order_release);
					found = true;
					break;
				}
			}
			pthread_rwlock_unlock(&blued_g.conns_lock);
			/* Signal main loop to process the cleanup */
			if (found) {
				uint8_t sig = 1;
				(void)write(blued_g.setup_pipe[1], &sig, 1);
			}
		}
	}
}

static void
blued_handle_readable(struct kevent *ev)
{
	struct blued_conn *conn;
	struct blued_ctl_client *client;

	/* Check if the event is from an adapter HCI fd */
	{
		struct blued_adapter *a;

		LIST_FOREACH(a, &blued_g.adapters, entries) {
			if (ev->udata == a) {
				blued_handle_hci_event(a);
				return;
			}
		}
	}

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
		LOG_HOGP(2, "kqueue: peripheral listen fd readable");
		blued_periph_accept();
		return;
	}

	if (ev->udata == BLUED_KQ_CTL_LISTEN) {
		blued_ctl_accept();
		return;
	}

	/* Check if it's a vhid Output report */
	if (ev->udata == BLUED_KQ_VHID_OUTPUT) {
		struct blued_conn *vc;

		/*
		 * Find the central HOGP connection that owns this vhid fd
		 * by matching the kqueue event ident to the hogp vhid_fd.
		 */
		pthread_rwlock_rdlock(&blued_g.conns_lock);
		LIST_FOREACH(vc, &blued_g.conns, entries) {
			if (vc->hogp != NULL &&
			    vc->hogp->vhid_fd == (int)ev->ident) {
				pthread_rwlock_unlock(&blued_g.conns_lock);
				hogp_handle_vhid_output(vc->hogp);
				return;
			}
		}
		pthread_rwlock_unlock(&blued_g.conns_lock);
		LOG_HOGP(2, "vhid output event for unknown fd %lu",
		    (unsigned long)ev->ident);
		return;
	}

	/* Check if it's a control client */
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		if (ev->udata == client) {
			if ((ev->flags & EV_EOF) ||
			    blued_ctl_dispatch(client) < 0) {
				/* Client disconnected or error */
				int dead_fd = client->fd;
				LIST_REMOVE(client, entries);
				blued_ctl_reset_owner(dead_fd);
				close(dead_fd);
				free(client);
			}
			pthread_mutex_unlock(&blued_g.ctl_clients_lock);
			return;
		}
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);

	/* Check if it's a device connection */
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (ev->udata == conn) {
			pthread_rwlock_unlock(&blued_g.conns_lock);
			if (ev->flags & EV_EOF) {
				blued_conn_disconnect(conn);
			} else if (conn->role == BLUED_ROLE_PERIPHERAL) {
				uint8_t buf[ATT_PDU_BUF_SIZE];
				ssize_t nr;

				do {
					nr = recv(conn->att_fd, buf,
					    sizeof(buf), 0);
				} while (nr < 0 && errno == EINTR);
				if (nr <= 0) {
					LOG_ATT(1, "peripheral recv: %s",
					    nr == 0 ? "closed" :
					    strerror(errno));
					blued_conn_disconnect(conn);
				} else {
					bool was_pending =
					    conn->att->ind_pending;
					pthread_mutex_lock(
					    &blued_g.gatt_db_lock);
					att_server_handle(conn->att,
					    conn->gatt_db, buf, (size_t)nr,
					    -1, 0);
					pthread_mutex_unlock(
					    &blued_g.gatt_db_lock);
					/* Disarm timeout on confirmation */
					if (was_pending &&
					    !conn->att->ind_pending)
						blued_ind_disarm_timeout(conn);
					/* Reset idle timer on activity */
					blued_idle_arm(conn);
				}
			} else {
				hogp_event_loop_once(conn);
			}
			return;
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);

	LOG_HOGP(1, "unhandled kqueue event: fd=%lu filter=%d flags=0x%x "
	    "udata=%p", (unsigned long)ev->ident, ev->filter,
	    ev->flags, ev->udata);
}

/*
 * Reload configuration from disk on SIGHUP.
 *
 * Only runtime-changeable settings are applied.  Structural settings
 * (adapters, peripheral_mode, scan_mode, service definitions, pidfile,
 * ctlsock, bonddb paths) require a full restart.
 */
static void
blued_reload_config(void)
{
	struct blued_config newcfg;
	struct blued_config *old;

	old = &blued_cfg;

	blued_config_defaults(&newcfg);
	if (blued_config_load(&newcfg, blued_config_path) < 0) {
		LOG_HOGP(1, "SIGHUP: failed to reload config, keeping "
		    "current settings");
		return;
	}

	/* --- Runtime-changeable settings --- */

	/* Log level */
	if (newcfg.loglevel != old->loglevel) {
		LOG_HOGP(1, "config reload: loglevel %d -> %d",
		    old->loglevel, newcfg.loglevel);
		blued_verbose = newcfg.loglevel;
		old->loglevel = newcfg.loglevel;
	}

	/* Reconnect settings */
	if (newcfg.reconnect != old->reconnect) {
		LOG_HOGP(1, "config reload: reconnect %s -> %s",
		    old->reconnect ? "on" : "off",
		    newcfg.reconnect ? "on" : "off");
		old->reconnect = newcfg.reconnect;
	}
	if (newcfg.reconnect_max_delay != old->reconnect_max_delay) {
		LOG_HOGP(1, "config reload: reconnect_max_delay %d -> %d",
		    old->reconnect_max_delay, newcfg.reconnect_max_delay);
		old->reconnect_max_delay = newcfg.reconnect_max_delay;
	}

	/* RPA timeout */
	if (newcfg.rpa_timeout != old->rpa_timeout) {
		LOG_HOGP(1, "config reload: rpa_timeout %d -> %d",
		    old->rpa_timeout, newcfg.rpa_timeout);
		old->rpa_timeout = newcfg.rpa_timeout;
		/* Re-send to all active adapters */
		{
			struct blued_adapter *a;

			LIST_FOREACH(a, &blued_g.adapters, entries) {
				if (a->active)
					hci_le_set_rpa_timeout(a->hci_fd,
					    newcfg.rpa_timeout);
			}
		}
	}

	/* Security settings */
	if (newcfg.bondable != old->bondable) {
		LOG_HOGP(1, "config reload: bondable %s -> %s",
		    old->bondable ? "yes" : "no",
		    newcfg.bondable ? "yes" : "no");
		old->bondable = newcfg.bondable;
	}
	if (newcfg.sc_only != old->sc_only) {
		LOG_HOGP(1, "config reload: sc_only %s -> %s",
		    old->sc_only ? "yes" : "no",
		    newcfg.sc_only ? "yes" : "no");
		old->sc_only = newcfg.sc_only;
	}
	if (newcfg.io_capability != old->io_capability) {
		LOG_HOGP(1, "config reload: io_capability %d -> %d",
		    old->io_capability, newcfg.io_capability);
		old->io_capability = newcfg.io_capability;
	}
	if (newcfg.min_key_size != old->min_key_size) {
		LOG_HOGP(1, "config reload: min_key_size %d -> %d",
		    old->min_key_size, newcfg.min_key_size);
		old->min_key_size = newcfg.min_key_size;
	}

	/* Privacy */
	if (newcfg.privacy != old->privacy) {
		LOG_HOGP(1, "config reload: privacy %s -> %s",
		    old->privacy ? "on" : "off",
		    newcfg.privacy ? "on" : "off");
		old->privacy = newcfg.privacy;
	}

	/* Peripheral name */
	if (strcmp(newcfg.peripheral_name, old->peripheral_name) != 0) {
		LOG_HOGP(1, "config reload: peripheral_name '%s' -> '%s'",
		    old->peripheral_name, newcfg.peripheral_name);
		strlcpy(old->peripheral_name, newcfg.peripheral_name,
		    sizeof(old->peripheral_name));
		blued_peripheral_name = old->peripheral_name;
		/* Update advertising data if peripheral mode is active */
		if (blued_g.periph_active) {
			struct blued_adapter *a;
			uint8_t adv[31], sr[31];
			uint16_t uuids[] = { UUID_DIS_SERVICE,
			    UUID_CUSTOM_SERVICE };
			int alen, srlen;
			size_t namelen;

			a = LIST_FIRST(&blued_g.adapters);
			if (a != NULL && a->active) {
				alen = ble_build_adv_data(adv, sizeof(adv),
				    blued_peripheral_name, uuids, 2);
				namelen = strlen(blued_peripheral_name);
				if (namelen > 29)
					namelen = 29;
				srlen = 0;
				sr[srlen++] = (uint8_t)(1 + namelen);
				sr[srlen++] = 0x09;
				memcpy(sr + srlen, blued_peripheral_name,
				    namelen);
				srlen += (int)namelen;
				if (alen > 0) {
					hci_le_set_ext_adv_data(a->hci_fd,
					    0x00, adv, (uint8_t)alen);
					hci_le_set_ext_scan_response_data(
					    a->hci_fd, 0x00, sr,
					    (uint8_t)srlen);
					/* Fall back to legacy */
					hci_le_set_advertising_data(
					    a->hci_fd, adv, (uint8_t)alen);
					hci_le_set_scan_response_data(
					    a->hci_fd, sr, (uint8_t)srlen);
				}
			}
		}
	}

	/* --- Settings that require restart --- */
	if (newcfg.nadapters != old->nadapters ||
	    (newcfg.nadapters > 0 &&
	    memcmp(newcfg.adapters, old->adapters,
	    (size_t)newcfg.nadapters * sizeof(newcfg.adapters[0])) != 0))
		LOG_HOGP(1, "config reload: adapters changed (restart "
		    "required)");
	if (newcfg.peripheral_mode != old->peripheral_mode)
		LOG_HOGP(1, "config reload: peripheral_mode changed "
		    "(restart required)");
	if (newcfg.scan_mode != old->scan_mode)
		LOG_HOGP(1, "config reload: scan_mode changed "
		    "(restart required)");
	if (newcfg.nservices != old->nservices)
		LOG_HOGP(1, "config reload: service definitions changed "
		    "(restart required)");
	if (strcmp(newcfg.pidfile, old->pidfile) != 0)
		LOG_HOGP(1, "config reload: pidfile changed "
		    "(restart required)");
	if (strcmp(newcfg.ctlsock, old->ctlsock) != 0)
		LOG_HOGP(1, "config reload: ctlsock changed "
		    "(restart required)");
	if (strcmp(newcfg.bonddb, old->bonddb) != 0)
		LOG_HOGP(1, "config reload: bonddb changed "
		    "(restart required)");
	if (newcfg.eatt != old->eatt)
		LOG_HOGP(1, "config reload: eatt changed "
		    "(restart required)");
	if (newcfg.socket_pool_size != old->socket_pool_size)
		LOG_HOGP(1, "config reload: socket_pool_size changed "
		    "(restart required)");
	if (strcmp(newcfg.logfile, old->logfile) != 0)
		LOG_HOGP(1, "config reload: logfile changed "
		    "(restart required)");
	if (newcfg.daemonize != old->daemonize)
		LOG_HOGP(1, "config reload: daemonize changed "
		    "(restart required)");

	LOG_HOGP(1, "configuration reloaded");
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
				if (events[i].ident == SIGHUP) {
					LOG_HOGP(1, "SIGHUP received, "
					    "reloading configuration");
					blued_reload_config();
					continue;
				}
				LOG_HOGP(1, "signal %lu, shutting down",
				    (unsigned long)events[i].ident);
				running = 0;
				return;
			}
			if (events[i].filter == EVFILT_TIMER &&
			    events[i].udata == BLUED_KQ_IDLE_TIMEOUT) {
				/*
				 * Idle connection timeout.  Disconnect
				 * peripheral clients that send no ATT
				 * PDUs for BLUED_IDLE_TIMEOUT_SEC.
				 */
				struct blued_conn *ic;
				uintptr_t tident = events[i].ident;

				pthread_rwlock_rdlock(&blued_g.conns_lock);
				LIST_FOREACH(ic, &blued_g.conns, entries) {
					if (ic->idle_timer == tident)
						break;
				}
				pthread_rwlock_unlock(&blued_g.conns_lock);
				if (ic != NULL) {
					LOG_ATT(1, "idle timeout "
					    "(%ds), disconnecting",
					    BLUED_IDLE_TIMEOUT_SEC);
					ic->idle_timer = 0;
					blued_conn_disconnect(ic);
				}
				continue;
			}
			if (events[i].filter == EVFILT_TIMER &&
			    events[i].udata == BLUED_KQ_IND_TIMEOUT) {
				/*
				 * ATT indication timeout (30s).
				 * Core Spec Vol 3 Part F §3.3.3:
				 * disconnect the bearer.
				 */
				struct blued_conn *ic;
				uintptr_t tident = events[i].ident;

				pthread_rwlock_rdlock(&blued_g.conns_lock);
				LIST_FOREACH(ic, &blued_g.conns, entries) {
					if (ic->att != NULL &&
					    ic->att->ind_timer == tident)
						break;
				}
				pthread_rwlock_unlock(&blued_g.conns_lock);
				if (ic != NULL) {
					LOG_ATT(1, "indication "
					    "timeout (30s), "
					    "disconnecting");
					ic->att->ind_pending = false;
					ic->att->ind_timer = 0;
					blued_conn_disconnect(ic);
				}
				continue;
			}
			if (events[i].filter == EVFILT_TIMER &&
			    events[i].udata == BLUED_KQ_RPA_TIMER) {
				/*
				 * RPA rotation timer fired.  Generate a
				 * new RPA from the local IRK and update
				 * the advertising address.
				 */
				struct blued_adapter *ra;
				uint8_t rpa[6];

				smp_generate_rpa(blued_local_irk, rpa);
				ra = LIST_FIRST(&blued_g.adapters);
				if (ra != NULL) {
					if (hci_le_set_adv_set_random_address(
					    ra->hci_fd, 0, rpa) == 0)
						LOG_HCI(1, "RPA rotated: "
						    "%02x:%02x:%02x:%02x:%02x:%02x",
						    rpa[5], rpa[4], rpa[3],
						    rpa[2], rpa[1], rpa[0]);
				}
				continue;
			}
			if (events[i].filter == EVFILT_TIMER &&
			    events[i].udata == BLUED_KQ_READVERTISE) {
				blued_periph_readvertise();
				continue;
			}
			if (events[i].filter == EVFILT_TIMER) {
				struct blued_conn *tconn = events[i].udata;
				pthread_t tid;
				pthread_attr_t attr;

				pthread_attr_init(&attr);
				pthread_attr_setdetachstate(&attr,
				    PTHREAD_CREATE_DETACHED);
				blued_conn_set_state(tconn, BLUED_CONN_CONNECTING);
				if (pthread_create(&tid, &attr,
				    blued_conn_setup_central, tconn) != 0) {
					warn("reconnect thread");
					/*
					 * Re-arm the timer so we retry
					 * instead of leaving a zombie conn.
					 */
					blued_conn_set_state(tconn,
					    BLUED_CONN_RECONNECTING);
					{
						struct kevent tkev;
						tconn->reconnect_timer =
						    blued_next_timer_id++;
						EV_SET(&tkev,
						    tconn->reconnect_timer,
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

	/* Guard against double-disconnect (EV_EOF + timer, etc.) */
	if (atomic_load(&conn->state) == BLUED_CONN_IDLE)
		return;

	bt_ntoa(&conn->dst, addr_str);
	LOG_HOGP(1, "device %s disconnected (role=%s handle=%04x)",
	    addr_str,
	    conn->role == BLUED_ROLE_PERIPHERAL ? "peripheral" : "central",
	    conn->con_handle);
	BLUED_PROBE_CONN_CLOSE(addr_str, 0);

	/* Disarm idle and indication timers */
	blued_idle_disarm(conn);
	blued_ind_disarm_timeout(conn);

	/* Deregister fd from kqueue before freeing */
	if (conn->att_fd >= 0) {
		EV_SET(&kev, conn->att_fd, EVFILT_READ,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	}

	/* Deregister vhid fd from kqueue */
	if (conn->hogp != NULL && conn->hogp->vhid_fd >= 0) {
		EV_SET(&kev, conn->hogp->vhid_fd, EVFILT_READ,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	}

	if (conn->role == BLUED_ROLE_PERIPHERAL) {
		/* Save per-connection CCCDs for bonded device */
		pthread_mutex_lock(&blued_g.bond_db_lock);
		if (blued_g.bond_db != NULL && conn->att_owned != NULL) {
			struct smp_bond *bond;

			bond = smp_find_bond(blued_g.bond_db,
			    (const uint8_t *)&conn->dst, conn->addr_type);
			if (bond != NULL) {
				smp_bond_save_cccds(bond, conn->att_owned);
				smp_bond_db_save(blued_g.bond_db);
				LOG_HOGP(1, "saved %d CCCD(s) for bonded "
				    "device", bond->num_cccds);
			}
		}
		pthread_mutex_unlock(&blued_g.bond_db_lock);

		/* blued_conn_free closes att_owned fd and frees att_owned */
		blued_conn_free(conn);

		/* Re-enable advertising */
		blued_periph_readvertise();
	} else {
		/* Central role */
		if (conn->reconnect) {
			/* Schedule reconnect via EVFILT_TIMER */
			blued_conn_set_state(conn, BLUED_CONN_RECONNECTING);
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
				/*
				 * att.fd is the same fd as conn->att_fd
				 * (already closed above); mark it invalid
				 * to prevent att_close from double-closing.
				 */
				conn->hogp->att.fd = -1;
				att_close(&conn->hogp->att);
				if (conn->hogp->smp.fd >= 0)
					smp_close(&conn->hogp->smp);
				free(conn->hogp->report_map);
				conn->hogp->report_map = NULL;
				conn->hogp->nreports = 0;
			}

			conn->reconnect_timer = blued_next_timer_id++;
			EV_SET(&kev, conn->reconnect_timer,
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
	struct blued_config *cfgp = &blued_cfg;
	struct blued_adapter *adp;
	struct hogp_device dev;
	const char *config_path;
	int ch, i, nfound;

	/* Alias for minimal diff with existing code */
#define cfg (*cfgp)

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
	while ((ch = getopt(argc, argv, "a:Bc:df:hL:prsv")) != -1) {
		if (ch == 'c')
			config_path = optarg;
		else if (ch == 'h')
			usage();
	}

	/* 3. Load config file (optional, ENOENT is OK) */
	if (blued_config_load(&cfg, config_path) < 0)
		warnx("failed to load config");

	/* Save config path for SIGHUP reload */
	blued_config_path = config_path;

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
	pthread_rwlock_init(&blued_g.conns_lock, NULL);
	pthread_mutex_init(&blued_g.bond_db_lock, NULL);
	pthread_mutex_init(&blued_g.gatt_db_lock, NULL);
	pthread_mutex_init(&blued_g.passkey_lock, NULL);
	pthread_cond_init(&blued_g.passkey_cond, NULL);
	blued_g.passkey_reply_status = -1;
	blued_g.numcmp_reply_status = -1;
	LIST_INIT(&blued_g.ctl_clients);
	pthread_mutex_init(&blued_g.ctl_clients_lock, NULL);
	blued_g.kq = -1;
	blued_g.ctl_fd = -1;
	blued_g.bond_fd = -1;
	blued_g.vhid_ctl_fd = -1;
	blued_g.att_pool_size = cfg.socket_pool_size;
	blued_g.att_pool = calloc((size_t)blued_g.att_pool_size,
	    sizeof(int));
	if (blued_g.att_pool == NULL)
		err(1, "socket pool alloc");
	for (i = 0; i < blued_g.att_pool_size; i++)
		blued_g.att_pool[i] = -1;

	/* Record main thread for conn_by_addr safety assertion */
	blued_g.main_thread = pthread_self();

	/* 7. Create kqueue */
	blued_g.kq = kqueue();
	if (blued_g.kq < 0)
		err(1, "kqueue");

	/* 8. Register EVFILT_SIGNAL for SIGTERM, SIGINT, SIGHUP */
	signal(SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);	/* prevent setup threads from crashing on broken sockets */
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
	 * 11. Register each adapter's HCI fd with kqueue for async
	 * LE events (LTK Request, Auth Payload Timeout).  Use the
	 * adapter pointer as udata so the event handler can identify
	 * which adapter the event came from.
	 */
	{
		struct blued_adapter *a;

		LIST_FOREACH(a, &blued_g.adapters, entries) {
			struct bt_devfilter flt;
			struct kevent kev;

			if (!a->active)
				continue;
			memset(&flt, 0, sizeof(flt));
			bt_devfilter_pkt_set(&flt, NG_HCI_EVENT_PKT);
			bt_devfilter_evt_set(&flt, NG_HCI_EVENT_LE);
			bt_devfilter_evt_set(&flt, 0x57);
			bt_devfilter(a->hci_fd, &flt, NULL);

			EV_SET(&kev, a->hci_fd, EVFILT_READ,
			    EV_ADD | EV_ENABLE, 0, 0, a);
			if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0)
				warn("kevent HCI adapter %s (non-fatal)",
				    a->name);
		}
	}

	/*
	 * Bridge the first active adapter into a local hogp_device for
	 * scan mode and for seeding per-adapter state (resolving list,
	 * filter accept list) used by both peripheral and central modes.
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
	blued_peripheral_name = cfg.peripheral_name;

	if (cfg.peripheral_mode) {
		uint8_t adv_data[31];
		int adv_len, listen_fd;
		int nbonded = 0;
		/*
		 * own_address_type for advertising:
		 * 0x00 = public (no privacy)
		 * 0x02 = RPA, fallback to public (privacy enabled)
		 * Core Spec Vol 4 Part E §7.8.53
		 */
		uint8_t own_addr_type = 0x00;

		/* Build the shared GATT database */
		peripheral_build_gattdb(&periph_gatt_db, periph_gatt_attrs,
		    periph_gatt_val_buf, sizeof(periph_gatt_val_buf), &cfg);

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

			/* Load or generate persistent local IRK for RPA */
			if (cfg.privacy &&
			    load_local_irk(cfg.bonddb, blued_local_irk) == 0) {
				blued_has_local_irk = true;
				own_addr_type = 0x02; /* RPA, fallback public */
			}

			load_resolving_list(&dev, cfg.rpa_timeout);

			/*
			 * Populate Filter Accept List with bonded devices.
			 * If any bonds exist, use filter_policy=0x01 so
			 * only bonded devices can connect.  Otherwise
			 * use 0x00 to allow initial pairing from any device.
			 */
			nbonded = load_filter_accept_list(adp->hci_fd,
			    blued_g.bond_db);
		}

		/* Build advertising data */
		{
			uint16_t uuids[] = { UUID_DIS_SERVICE,
			    UUID_CUSTOM_SERVICE };
			adv_len = ble_build_adv_data(adv_data,
			    sizeof(adv_data), blued_peripheral_name,
			    uuids, 2);
			if (adv_len < 0)
				err(1, "build advertising data");
		}

		/*
		 * Build scan response with Complete Local Name.
		 * Ensures active scanners see the full device name.
		 */
		{
			uint8_t scan_rsp[31];
			int scan_rsp_len = 0;
			size_t namelen = strlen(blued_peripheral_name);

			if (namelen > 29)
				namelen = 29;
			scan_rsp[scan_rsp_len++] = (uint8_t)(1 + namelen);
			scan_rsp[scan_rsp_len++] = 0x09; /* Complete Local Name */
			memcpy(scan_rsp + scan_rsp_len,
			    blued_peripheral_name, namelen);
			scan_rsp_len += (int)namelen;

			/*
			 * Clear stale advertising sets from a previous
			 * daemon instance that crashed without cleanup.
			 * Best-effort — ignored if controller doesn't
			 * support extended advertising.
			 */
			hci_le_clear_adv_sets(dev.hci_fd);

			/*
			 * Advertising filter policy: if we have bonded
			 * devices, restrict connections to the filter
			 * accept list (0x01).  Otherwise allow any
			 * device to connect for initial pairing (0x00).
			 */
			{
			uint8_t filt = (nbonded > 0) ? 0x01 : 0x00;

			/*
			 * Start advertising — try extended (BT 5.0+) first,
			 * fall back to legacy.
			 */
			if (hci_le_set_ext_adv_params_phy(dev.hci_fd, 0x00,
			    0x0013 /* connectable+scannable+legacy ADV_IND */,
			    ADV_INTERVAL_100MS, ADV_INTERVAL_100MS,
			    own_addr_type, filt, 0x01, 0x01) == 0 &&
			    hci_le_set_ext_adv_data(dev.hci_fd, 0x00,
			    adv_data, (uint8_t)adv_len) == 0 &&
			    hci_le_set_ext_scan_response_data(dev.hci_fd,
			    0x00, scan_rsp, (uint8_t)scan_rsp_len) == 0 &&
			    hci_le_set_ext_adv_enable(dev.hci_fd, 1,
			    0x00) == 0) {
				LOG_HOGP(1, "using extended advertising "
				    "(filter=%d)", filt);

				/*
				 * If the controller supports Coded PHY,
				 * add a second advertising set on Coded
				 * PHY for long-range discovery.
				 * Non-connectable (connectable uses set 0).
				 */
				if (adp->le_features &
				    LE_FEAT_CODED_PHY) {
					if (hci_le_set_ext_adv_params_phy(
					    dev.hci_fd, 0x01,
					    0x0000 /* non-conn, non-scan */,
					    ADV_INTERVAL_100MS * 4,
					    ADV_INTERVAL_100MS * 4,
					    own_addr_type, filt,
					    0x03 /* Coded */, 0x03) == 0 &&
					    hci_le_set_ext_adv_data(
					    dev.hci_fd, 0x01,
					    adv_data, (uint8_t)adv_len) == 0 &&
					    hci_le_set_ext_adv_enable(
					    dev.hci_fd, 1, 0x01) == 0)
						LOG_HOGP(1, "Coded PHY "
						    "advertising on set 1");
				}
			} else {
				LOG_HOGP(1, "ext adv not supported, "
				    "using legacy");
				if (hci_le_set_advertising_params(dev.hci_fd,
				    ADV_INTERVAL_100MS, ADV_INTERVAL_100MS,
				    0x00, own_addr_type, filt) < 0)
					err(1, "set advertising parameters");
				if (hci_le_set_advertising_data(dev.hci_fd,
				    adv_data, (uint8_t)adv_len) < 0)
					err(1, "set advertising data");
				if (hci_le_set_scan_response_data(dev.hci_fd,
				    scan_rsp, (uint8_t)scan_rsp_len) < 0)
					warn("set scan response data");
				if (hci_le_set_advertise_enable(dev.hci_fd,
				    true) < 0)
					err(1, "enable advertising");
			}
			}
		}

		LOG_HOGP(1, "advertising as \"%s\"", blued_peripheral_name);

		/* Create ATT listen socket and register with kqueue */
		listen_fd = peripheral_att_listen();
		if (listen_fd < 0)
			errx(1, "cannot bind ATT listen socket "
			    "(kill any existing blued first)");
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

		/*
		 * Register the adapter's HCI fd with kqueue to receive
		 * asynchronous LE events: LTK Request (subevent 0x05)
		 * and Auth Payload Timeout (event 0x57).  Set the socket
		 * filter to accept LE Meta and Auth Payload events.
		 */
		{
			struct bt_devfilter flt;
			struct kevent kev;

			memset(&flt, 0, sizeof(flt));
			bt_devfilter_pkt_set(&flt, NG_HCI_EVENT_PKT);
			bt_devfilter_evt_set(&flt, NG_HCI_EVENT_LE);
			bt_devfilter_evt_set(&flt, 0x57);
			bt_devfilter(adp->hci_fd, &flt, NULL);

			EV_SET(&kev, adp->hci_fd, EVFILT_READ,
			    EV_ADD | EV_ENABLE, 0, 0, adp);
			if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0)
				warn("kevent HCI events (non-fatal)");
		}

		/* Init control socket */
		if (blued_ctl_init(cfg.ctlsock) < 0)
			warn("control socket init failed (non-fatal)");

		/*
		 * Enter Capsicum sandbox.  All required fds are open:
		 * kqueue, ATT listen socket, HCI adapter, control socket,
		 * bond database, and self-pipe.
		 */
		blued_capsicum_limit_fds();
		blued_audit(AUE_BLUED_START, 0,
		    "daemon entering sandbox (peripheral)");
		if (cap_enter() < 0)
			err(1, "cap_enter (peripheral)");
		LOG_HOGP(1, "entered Capsicum sandbox (peripheral)");

		LOG_HOGP(1, "peripheral mode, entering event loop");
		running = 1;
		blued_event_loop();

		/*
		 * Shutdown: signal threads to exit, then wait briefly.
		 * Detached threads check blued_shutting_down at blocking
		 * steps; closing their fds will unblock any in-progress
		 * recv()/connect().
		 */
		atomic_store(&blued_shutting_down, true);
		{
			struct blued_conn *sc, *sc_tmp;
			bool has_connecting;
			int wait_ms;

			/*
			 * Cancel in-progress connection attempts and close
			 * fds under setup threads to unblock them.
			 */
			hci_le_create_connection_cancel(adp->hci_fd);
			LIST_FOREACH(sc, &blued_g.conns, entries) {
				if (sc->state == BLUED_CONN_CONNECTING) {
					if (sc->att_fd >= 0) {
						close(sc->att_fd);
						sc->att_fd = -1;
					}
					if (sc->att_owned != NULL)
						sc->att_owned->fd = -1;
					if (sc->hogp != NULL) {
						if (sc->hogp->att.fd >= 0) {
							close(sc->hogp->att.fd);
							sc->hogp->att.fd = -1;
						}
						if (sc->hogp->smp.fd >= 0) {
							close(sc->hogp->smp.fd);
							sc->hogp->smp.fd = -1;
						}
					}
				}
			}

			/* Brief wait for threads to observe and exit */
			for (wait_ms = 0; wait_ms < 2000; wait_ms += 50) {
				has_connecting = false;
				LIST_FOREACH(sc, &blued_g.conns, entries) {
					if (sc->state == BLUED_CONN_CONNECTING) {
						has_connecting = true;
						break;
					}
				}
				if (!has_connecting)
					break;
				usleep(50000);
			}

			/*
			 * Send HCI Disconnect to all active connections
			 * so the remote side gets a clean termination
			 * (reason 0x13 = Remote User Terminated).
			 */
			LIST_FOREACH(sc, &blued_g.conns, entries) {
				if (sc->state == BLUED_CONN_ACTIVE &&
				    sc->con_handle != 0 &&
				    sc->adapter != NULL) {
					hci_disconnect(sc->adapter->hci_fd,
					    sc->con_handle, 0x13);
				}
			}
			/* Brief delay for disconnects to be processed */
			usleep(100000);

			/* Free all connections */
			LIST_FOREACH_SAFE(sc, &blued_g.conns, entries, sc_tmp) {
				blued_idle_disarm(sc);
				blued_ind_disarm_timeout(sc);
				/* blued_conn_free closes att_owned->fd */
				blued_conn_free(sc);
			}
		}

		/* Flush bond database to disk */
		if (blued_g.bond_db != NULL)
			smp_bond_db_save(blued_g.bond_db);

		/* Shutdown: disable and remove all advertising sets */
		if (adp->le_features & LE_FEAT_EXT_ADVERTISING) {
			/* Coded PHY set (if active) */
			if (adp->le_features & LE_FEAT_CODED_PHY) {
				hci_le_set_ext_adv_enable(adp->hci_fd, 0, 0x01);
				hci_le_remove_adv_set(adp->hci_fd, 0x01);
			}
			hci_le_set_ext_adv_enable(adp->hci_fd, 0, 0x00);
			hci_le_remove_adv_set(adp->hci_fd, 0x00);
		} else {
			hci_le_set_advertise_enable(adp->hci_fd, false);
		}

		close(listen_fd);
		blued_g.periph_listen_fd = -1;
		blued_ctl_cleanup();

		/* Close self-pipe */
		if (blued_g.setup_pipe[0] >= 0) {
			close(blued_g.setup_pipe[0]);
			blued_g.setup_pipe[0] = -1;
		}
		if (blued_g.setup_pipe[1] >= 0) {
			close(blued_g.setup_pipe[1]);
			blued_g.setup_pipe[1] = -1;
		}

		free(blued_g.bond_db);
		blued_g.bond_db = NULL;
		if (blued_g.bond_fd >= 0) {
			close(blued_g.bond_fd);
			blued_g.bond_fd = -1;
		}

		/* Close adapter HCI fds */
		{
			struct blued_adapter *sa, *sa_tmp;

			LIST_FOREACH_SAFE(sa, &blued_g.adapters, entries,
			    sa_tmp) {
				close(sa->hci_fd);
				LIST_REMOVE(sa, entries);
				free(sa);
			}
		}

		/* Remove pidfile */
		if (blued_pfh != NULL) {
			pidfile_remove(blued_pfh);
			blued_pfh = NULL;
		}

		close(blued_g.kq);
		hci_log_close();
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

	/* 12. Open bond database */
	blued_g.bond_fd = open(cfg.bonddb,
	    O_RDWR | O_CREAT | O_CLOEXEC | O_CLOFORK, 0600);
	if (blued_g.bond_fd < 0)
		err(1, "open %s", cfg.bonddb);
	dev.bond_fd = blued_g.bond_fd;
	smp_bond_db_load(&dev.bond_db, dev.bond_fd);

	/* 13. Load resolving list */
	load_resolving_list(&dev, cfg.rpa_timeout);

	/* Open vhid control */
	blued_g.vhid_ctl_fd = open("/dev/vhid", O_RDWR | O_CLOEXEC | O_CLOFORK);
	if (blued_g.vhid_ctl_fd < 0)
		err(1, "open /dev/vhid");

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
	 * 16c. Central mode: multi-connection kqueue-based path.
	 *
	 * For each target device, heap-allocate a hogp_device, create
	 * a blued_conn, and spawn blued_conn_setup_central() in a
	 * detached thread.  The setup thread performs the blocking ATT
	 * connect, MTU exchange, bond/pair, HOGP discovery, and vhid
	 * setup, then registers the connection with the kqueue event
	 * loop via the self-pipe.  Reconnection is handled by the
	 * event loop's EVFILT_TIMER path.
	 */

	/* Create self-pipe for thread->main signaling */
	if (pipe2(blued_g.setup_pipe, O_CLOEXEC | O_NONBLOCK) < 0)
		err(1, "setup_pipe");
	{
		struct kevent kev;

		EV_SET(&kev, blued_g.setup_pipe[0], EVFILT_READ,
		    EV_ADD | EV_ENABLE, 0, 0, BLUED_KQ_SETUP_PIPE);
		if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0)
			err(1, "kevent setup_pipe");
	}

	/* Pre-allocate global socket pool for Capsicum reconnection */
	blued_g.att_pool_next = 0;
	if (cfg.reconnect) {
		if (pool_create(blued_g.att_pool, blued_g.att_pool_size) < 0)
			warn("ATT socket pool creation failed");
	}

	blued_reconnect_max_delay = cfg.reconnect_max_delay;

	/* Spawn a setup thread for each target device */
	for (i = 0; i < ndevs; i++) {
		struct hogp_device *hdev;
		struct blued_conn *conn;
		pthread_t tid;
		pthread_attr_t pattr;
		int j;

		hdev = calloc(1, sizeof(*hdev));
		if (hdev == NULL)
			err(1, "hogp_device alloc");

		for (j = 0; j < SOCK_POOL_SIZE; j++)
			hdev->att_pool[j] = -1;
		if (pool_create(hdev->att_pool, cfg.socket_pool_size) < 0)
			warn("ATT socket pool for device %d", i);
		hdev->att.fd = -1;
		hdev->smp.fd = -1;
		hdev->bond_fd = blued_g.bond_fd;
		hdev->vhid_ctl_fd = blued_g.vhid_ctl_fd;
		hdev->vhid_fd = -1;
		hdev->hci_fd = adp->hci_fd;
		hdev->adapter = adp->name;
		hdev->le_features = adp->le_features;
		memcpy(hdev->local_addr, &adp->addr, 6);
		hdev->reconnect = cfg.reconnect;
		hdev->debug = (blued_verbose >= 1);
		memcpy(hdev->addr, devs[i].addr, 6);
		hdev->addr_type = devs[i].addr_type;
		smp_bond_db_load(&hdev->bond_db, hdev->bond_fd);

		conn = blued_conn_alloc();
		if (conn == NULL)
			err(1, "blued_conn_alloc");
		conn->hogp = hdev;
		memcpy(&conn->dst, devs[i].addr, sizeof(conn->dst));
		conn->addr_type = devs[i].addr_type;
		conn->adapter = adp;
		conn->role = BLUED_ROLE_CENTRAL;
		conn->reconnect = cfg.reconnect;
		blued_conn_set_state(conn, BLUED_CONN_CONNECTING);

		pthread_attr_init(&pattr);
		pthread_attr_setdetachstate(&pattr,
		    PTHREAD_CREATE_DETACHED);
		if (pthread_create(&tid, &pattr,
		    blued_conn_setup_central, conn) != 0) {
			warn("central setup thread for device %d", i);
			blued_conn_free(conn);
			free(hdev);
		}
		pthread_attr_destroy(&pattr);
	}

	/*
	 * Enter Capsicum sandbox.  All required fds are open:
	 * kqueue, HCI adapter, control socket, bond database,
	 * vhid control, self-pipe, and pre-allocated socket pool.
	 */
	blued_capsicum_limit_fds();
	{
		struct blued_conn *sc;

		LIST_FOREACH(sc, &blued_g.conns, entries) {
			if (sc->hogp != NULL)
				blued_capsicum_limit_dev_pool(sc->hogp);
		}
	}
	blued_audit(AUE_BLUED_START, 0,
	    "daemon entering sandbox (central)");
	if (cap_enter() < 0)
		err(1, "cap_enter (central)");
	LOG_HOGP(1, "entered Capsicum sandbox (central)");

	LOG_HOGP(1, "central mode, entering event loop");
	running = 1;
	blued_event_loop();

	/*
	 * Shutdown: signal threads to exit, then wait briefly.
	 */
	atomic_store(&blued_shutting_down, true);
	{
		struct blued_conn *sc, *sc_tmp;
		bool has_connecting;
		int wait_ms;

		hci_le_create_connection_cancel(adp->hci_fd);
		LIST_FOREACH(sc, &blued_g.conns, entries) {
			if (sc->state == BLUED_CONN_CONNECTING) {
				if (sc->att_fd >= 0) {
					close(sc->att_fd);
					sc->att_fd = -1;
				}
				if (sc->hogp != NULL) {
					if (sc->hogp->att.fd >= 0) {
						close(sc->hogp->att.fd);
						sc->hogp->att.fd = -1;
					}
					if (sc->hogp->smp.fd >= 0) {
						close(sc->hogp->smp.fd);
						sc->hogp->smp.fd = -1;
					}
				}
			}
		}

		for (wait_ms = 0; wait_ms < 2000; wait_ms += 50) {
			has_connecting = false;
			LIST_FOREACH(sc, &blued_g.conns, entries) {
				if (sc->state == BLUED_CONN_CONNECTING) {
					has_connecting = true;
					break;
				}
			}
			if (!has_connecting)
				break;
			usleep(50000);
		}

		/*
		 * Send HCI Disconnect to all active connections
		 * so the remote side gets a clean termination
		 * (reason 0x13 = Remote User Terminated).
		 */
		LIST_FOREACH(sc, &blued_g.conns, entries) {
			if (sc->state == BLUED_CONN_ACTIVE &&
			    sc->con_handle != 0 &&
			    sc->adapter != NULL) {
				hci_disconnect(sc->adapter->hci_fd,
				    sc->con_handle, 0x13);
			}
		}
		/* Brief delay for disconnects to be processed */
		usleep(100000);

		LIST_FOREACH_SAFE(sc, &blued_g.conns, entries, sc_tmp) {
			if (sc->hogp != NULL) {
				att_close(&sc->hogp->att);
				if (sc->hogp->smp.fd >= 0)
					smp_close(&sc->hogp->smp);
				if (sc->hogp->vhid_fd >= 0) {
					close(sc->hogp->vhid_fd);
					sc->hogp->vhid_fd = -1;
				}
				free(sc->hogp->report_map);
				free(sc->hogp);
				sc->hogp = NULL;
			}
			blued_conn_free(sc);
		}
	}

	} /* close devs[] scope */

	/* Final cleanup */
	blued_ctl_cleanup();
	if (blued_g.vhid_ctl_fd >= 0) {
		close(blued_g.vhid_ctl_fd);
		blued_g.vhid_ctl_fd = -1;
	}
	if (blued_g.bond_fd >= 0) {
		close(blued_g.bond_fd);
		blued_g.bond_fd = -1;
	}

	/* Close self-pipe */
	if (blued_g.setup_pipe[0] >= 0) {
		close(blued_g.setup_pipe[0]);
		blued_g.setup_pipe[0] = -1;
	}
	if (blued_g.setup_pipe[1] >= 0) {
		close(blued_g.setup_pipe[1]);
		blued_g.setup_pipe[1] = -1;
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

	if (blued_pfh != NULL) {
		pidfile_remove(blued_pfh);
		blued_pfh = NULL;
	}

	hci_log_close();

#undef cfg
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

		/* Heap-allocate read buffer: Report Maps can be up to
		 * 4KB; too large for the stack in a setup thread. */
		uint8_t *rmbuf;
		size_t total = 0;
		size_t rmbuf_sz = 4096;
		uint16_t handle = disc->chars[i].value_handle;

		rmbuf = malloc(rmbuf_sz);
		if (rmbuf == NULL)
			return (ENOMEM);

		ret = att_read(&dev->att, handle, rmbuf, rmbuf_sz, &len);
		if (ret != 0) {
			warnx("failed to read Report Map");
			free(rmbuf);
			return (ret);
		}
		total = len;

		while (len == (size_t)(dev->att.mtu - 1) &&
		    total < rmbuf_sz) {
			ret = att_read_blob(&dev->att, handle, total,
			    rmbuf + total, rmbuf_sz - total, &len);
			if (ret != 0)
				break;
			total += len;
		}

		if (dev->report_map == NULL) {
			dev->report_map = malloc(total);
			if (dev->report_map == NULL) {
				free(rmbuf);
				return (ENOMEM);
			}
			memcpy(dev->report_map, rmbuf, total);
			dev->report_map_len = total;
		} else {
			/* Concatenate report maps from multiple services */
			uint8_t *p = realloc(dev->report_map,
			    dev->report_map_len + total);
			if (p == NULL) {
				free(rmbuf);
				return (ENOMEM);
			}
			memcpy(p + dev->report_map_len, rmbuf, total);
			dev->report_map = p;
			dev->report_map_len += total;
		}
		free(rmbuf);

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
 * Save discovered HOGP handles to a bond's handle cache.
 * Called after successful full GATT discovery to avoid rediscovery
 * on subsequent reconnects when the GATT Database Hash matches.
 */
static void
hogp_cache_save(struct hogp_device *dev, struct smp_bond *bond)
{
	int i, n;

	if (bond == NULL || dev->nreports == 0)
		return;

	bond->hid_svc_start = dev->hid_disc.service.start_handle;
	bond->hid_svc_end = dev->hid_disc.service.end_handle;
	bond->report_map_handle = 0;
	bond->hid_info_handle = 0;
	bond->protocol_mode_handle = 0;

	for (i = 0; i < dev->hid_disc.nchars; i++) {
		if (dev->hid_disc.chars[i].uuid16 == UUID_REPORT_MAP)
			bond->report_map_handle =
			    dev->hid_disc.chars[i].value_handle;
		else if (dev->hid_disc.chars[i].uuid16 == UUID_HID_INFORMATION)
			bond->hid_info_handle =
			    dev->hid_disc.chars[i].value_handle;
		else if (dev->hid_disc.chars[i].uuid16 == UUID_PROTOCOL_MODE)
			bond->protocol_mode_handle =
			    dev->hid_disc.chars[i].value_handle;
	}

	n = dev->nreports;
	if (n > HOGP_MAX_REPORTS)
		n = HOGP_MAX_REPORTS;
	for (i = 0; i < n; i++) {
		bond->report_handles[i] = dev->reports[i].value_handle;
		bond->report_cccd_handles[i] = dev->reports[i].cccd_handle;
		bond->report_types[i] = dev->reports[i].report_type;
		bond->report_ids[i] = dev->reports[i].report_id;
	}
	bond->num_reports = n;

	/* Battery handles default to 0 (not cached individually) */
	bond->battery_level_handle = 0;
	bond->battery_cccd_handle = 0;
	bond->bat_svc_start = 0;
	bond->bat_svc_end = 0;

	bond->has_handle_cache = true;
	LOG_HOGP(1, "handle cache saved: %d reports, HID svc %04x-%04x",
	    n, bond->hid_svc_start, bond->hid_svc_end);
}

/*
 * Restore HOGP handles from bond cache, skipping full GATT discovery.
 * Must still read Report Map and HID Information from the device since
 * those are value-based (not handles).  Returns 0 on success, nonzero
 * on failure (caller should fall back to full discovery).
 */
static int
hogp_cache_restore(struct hogp_device *dev, struct smp_bond *bond)
{
	int i, ret;
	size_t len;

	if (bond == NULL || !bond->has_handle_cache || bond->num_reports <= 0) {
		LOG_HOGP(1, "handle cache: no valid cache");
		return (-1);
	}

	LOG_HOGP(1, "restoring %d report handles from cache "
	    "(HID svc %04x-%04x)", bond->num_reports,
	    bond->hid_svc_start, bond->hid_svc_end);

	/* Clear state as hogp_discover does */
	free(dev->report_map);
	dev->report_map = NULL;
	dev->report_map_len = 0;
	dev->nreports = 0;
	dev->hid_ctrl_handle = 0;
	dev->hid_bcdHID = 0;
	dev->idVendor = 0;
	dev->idProduct = 0;

	/* Restore report handles from cache */
	for (i = 0; i < bond->num_reports && i < HOGP_MAX_REPORTS; i++) {
		dev->reports[i].value_handle = bond->report_handles[i];
		dev->reports[i].cccd_handle = bond->report_cccd_handles[i];
		dev->reports[i].report_type = bond->report_types[i];
		dev->reports[i].report_id = bond->report_ids[i];
		dev->nreports++;

		LOG_HOGP(1, "cache: Report handle=%04x id=%d type=%d "
		    "cccd=%04x", bond->report_handles[i],
		    bond->report_ids[i], bond->report_types[i],
		    bond->report_cccd_handles[i]);
	}

	/*
	 * Read Report Map from cached handle -- the value is needed
	 * for vhid setup even though the handle is cached.
	 */
	if (bond->report_map_handle != 0) {
		uint8_t *rmbuf;
		size_t total = 0;
		size_t rmbuf_sz = 4096;

		rmbuf = malloc(rmbuf_sz);
		if (rmbuf == NULL)
			return (ENOMEM);

		ret = att_read(&dev->att, bond->report_map_handle,
		    rmbuf, rmbuf_sz, &len);
		if (ret != 0) {
			warnx("cache: failed to read Report Map");
			free(rmbuf);
			return (ret);
		}
		total = len;

		while (len == (size_t)(dev->att.mtu - 1) &&
		    total < rmbuf_sz) {
			ret = att_read_blob(&dev->att,
			    bond->report_map_handle, total,
			    rmbuf + total, rmbuf_sz - total, &len);
			if (ret != 0)
				break;
			total += len;
		}

		dev->report_map = malloc(total);
		if (dev->report_map == NULL) {
			free(rmbuf);
			return (ENOMEM);
		}
		memcpy(dev->report_map, rmbuf, total);
		dev->report_map_len = total;
		free(rmbuf);

		LOG_HOGP(1, "cache: Report Map: %zu bytes", total);
	}

	/*
	 * Read HID Information from cached handle.
	 */
	if (bond->hid_info_handle != 0) {
		uint8_t info[4];

		ret = att_read(&dev->att, bond->hid_info_handle,
		    info, sizeof(info), &len);
		if (ret == 0 && len >= 4) {
			dev->hid_bcdHID = (uint16_t)info[0] |
			    ((uint16_t)info[1] << 8);
			LOG_HOGP(1, "cache: HID Information: bcdHID=%04x",
			    dev->hid_bcdHID);
		}
	}

	/*
	 * Set Protocol Mode to Report Protocol from cached handle.
	 */
	if (bond->protocol_mode_handle != 0) {
		uint8_t mode = HID_PROTOCOL_REPORT;
		att_write_cmd(&dev->att, bond->protocol_mode_handle,
		    &mode, 1);
		LOG_HOGP(1, "cache: set Report Protocol mode");
	}

	/*
	 * Read Device Name from GAP Service (0x2A00) via Read By Type.
	 * This doesn't depend on cached handles.
	 */
	{
		uint8_t val[32];
		size_t vlen = 0;

		if (att_read_by_type(&dev->att, 0x0001, 0xFFFF,
		    UUID_DEVICE_NAME, val, sizeof(val), &vlen) == 0 &&
		    vlen > 0) {
			int nlen = (int)(vlen > 31 ? 31 : vlen);
			memcpy(dev->device_name, val, nlen);
			dev->device_name[nlen] = '\0';
			dev->has_device_name = true;
			LOG_HOGP(1, "cache: device name: %s",
			    dev->device_name);
		}
	}

	/*
	 * Read DIS PnP ID via Read By Type -- handle-independent.
	 */
	{
		uint8_t pnp[7];
		size_t plen = 0;

		if (att_read_by_type(&dev->att, 0x0001, 0xFFFF,
		    UUID_PNP_ID, pnp, sizeof(pnp), &plen) == 0 &&
		    plen >= 7) {
			dev->idVendor = (uint16_t)pnp[1] |
			    ((uint16_t)pnp[2] << 8);
			dev->idProduct = (uint16_t)pnp[3] |
			    ((uint16_t)pnp[4] << 8);
			LOG_HOGP(1, "cache: PnP ID: vendor=%04x product=%04x",
			    dev->idVendor, dev->idProduct);
		}
	}

	if (dev->report_map == NULL) {
		warnx("cache: Report Map not available");
		return (ENOENT);
	}

	LOG_HOGP(1, "handle cache restore complete: %d reports, %zu bytes "
	    "report map", dev->nreports, dev->report_map_len);

	return (0);
}

/*
 * Discover with cache support.
 * If the bond has a valid handle cache and the hash matches, restore
 * from cache.  Otherwise do full discovery.
 */
static int
hogp_discover_cached(struct hogp_device *dev, struct smp_bond *bond,
    bool hash_valid)
{
	/*
	 * Attempt cache restore if hash is valid and cache exists.
	 */
	if (bond != NULL && hash_valid && bond->has_handle_cache) {
		int ret = hogp_cache_restore(dev, bond);
		if (ret == 0) {
			LOG_HOGP(1, "GATT discovery skipped (cached handles)");
			return (0);
		}
		LOG_HOGP(1, "cache restore failed (%d), falling back to "
		    "full discovery", ret);
		bond->has_handle_cache = false;
	}

	return (hogp_discover(dev));
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
 * Handle an Output report from the kernel vhid driver.
 *
 * When an application sets LED state (e.g., Caps Lock, Num Lock),
 * the kernel writes the Output report to the vhid device fd.
 * We read it here and forward it to the BLE device via ATT Write
 * Without Response (Write Command), as required by HOGP v1.0
 * Section 3.3.3.
 *
 * The report from the kernel is in standard HID format:
 *   - If report IDs are in use: [report_id, data...]
 *   - If no report IDs: [data...]
 *
 * We match the report ID to find the correct Output Report
 * characteristic handle and strip the report ID byte before
 * sending over BLE (HOGP sends report data without the ID byte;
 * the ID is implicit in the characteristic handle).
 */
static void
hogp_handle_vhid_output(struct hogp_device *dev)
{
	uint8_t buf[VHID_MAX_REPORT];
	ssize_t n;
	uint8_t report_id;
	uint8_t *report_data;
	size_t report_len;
	int i;

	do {
		n = read(dev->vhid_fd, buf, sizeof(buf));
	} while (n < 0 && errno == EINTR);

	if (n <= 0) {
		if (n < 0 && errno != EAGAIN)
			warn("vhid read");
		return;
	}

	/*
	 * Determine report ID.  If any report in the device has a
	 * non-zero report ID, then the first byte is the report ID.
	 * Otherwise, there is no report ID byte.
	 */
	{
		bool has_report_ids = false;

		for (i = 0; i < dev->nreports; i++) {
			if (dev->reports[i].report_id != 0) {
				has_report_ids = true;
				break;
			}
		}

		if (has_report_ids && n >= 1) {
			report_id = buf[0];
			report_data = buf + 1;
			report_len = (size_t)(n - 1);
		} else {
			report_id = 0;
			report_data = buf;
			report_len = (size_t)n;
		}
	}

	/* Find the Output Report characteristic for this report ID */
	for (i = 0; i < dev->nreports; i++) {
		struct hogp_report *rpt = &dev->reports[i];

		if (rpt->report_type != HID_REPORT_TYPE_OUTPUT)
			continue;
		if (rpt->report_id != report_id)
			continue;

		/*
		 * HOGP v1.0 Section 3.3.3: Output Reports use Write
		 * Without Response (ATT Write Command, opcode 0x52).
		 */
		if (att_write_cmd(&dev->att, rpt->value_handle,
		    report_data, report_len) < 0)
			warn("output report write failed "
			    "(handle=%04x id=%d)",
			    rpt->value_handle, report_id);
		else
			LOG_HOGP(2, "output report sent: id=%d handle=%04x "
			    "len=%zu", report_id, rpt->value_handle,
			    report_len);
		return;
	}

	LOG_HOGP(2, "no output report handle for id=%d, dropped", report_id);
}

/*
 * Find the ATT value handle for a Feature report with the given report ID.
 * Returns 0 if not found.  Used by ctl.c for HOGP_READ/HOGP_WRITE commands.
 */
/*
 * Allocate and initialize a hogp_device for a new central connection.
 * Called from ctl.c CONNECT command.
 */
struct hogp_device *
blued_hogp_alloc(struct blued_adapter *adp, const uint8_t *addr,
    uint8_t addr_type, bool reconnect)
{
	struct hogp_device *hdev;
	int j;

	hdev = calloc(1, sizeof(*hdev));
	if (hdev == NULL)
		return (NULL);

	for (j = 0; j < SOCK_POOL_SIZE; j++)
		hdev->att_pool[j] = -1;
	hdev->att.fd = -1;
	hdev->att.bearer_fd = -1;
	hdev->smp.fd = -1;
	hdev->bond_fd = blued_g.bond_fd;
	hdev->vhid_ctl_fd = blued_g.vhid_ctl_fd;
	hdev->vhid_fd = -1;
	hdev->hci_fd = adp->hci_fd;
	hdev->adapter = adp->name;
	hdev->le_features = adp->le_features;
	memcpy(hdev->local_addr, &adp->addr, 6);
	hdev->debug = (blued_verbose >= 1);
	memcpy(hdev->addr, addr, 6);
	hdev->addr_type = addr_type;
	hdev->reconnect = reconnect;
	smp_bond_db_load(&hdev->bond_db, hdev->bond_fd);

	return (hdev);
}

uint16_t
hogp_find_feature_handle(struct blued_conn *conn, uint8_t report_id)
{
	struct hogp_device *dev;
	int i;

	if (conn == NULL || conn->hogp == NULL)
		return (0);
	dev = conn->hogp;

	for (i = 0; i < dev->nreports; i++) {
		if (dev->reports[i].report_type == HID_REPORT_TYPE_FEATURE &&
		    dev->reports[i].report_id == report_id)
			return (dev->reports[i].value_handle);
	}
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
	uint8_t buf[ATT_PDU_BUF_SIZE];
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

			/* Notify subscribed ctl clients */
			blued_ctl_notify_value(&conn->dst, handle,
			    report_data, (uint16_t)report_len);

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
			uint16_t handle = (uint16_t)buf[1] |
			    ((uint16_t)buf[2] << 8);
			uint8_t *ind_data = buf + 3;
			size_t ind_len = len - 3;

			/* Notify subscribed ctl clients */
			blued_ctl_notify_value(&conn->dst, handle,
			    ind_data, (uint16_t)ind_len);
			att_confirm(&dev->att);
		}
	}
}


/* ----------------------------------------------------------------
 *  Peripheral mode — GATT server
 * ---------------------------------------------------------------- */

/*
 * Send a Service Changed indication to a connected client.
 * Core Spec Vol 3 Part G §2.5.2, §7.1: when the GATT database changes,
 * the server shall indicate the Service Changed characteristic to all
 * bonded clients that have enabled indications via the CCCD.
 *
 * The indication carries the affected handle range [start, end].
 */
static void
gatt_send_service_changed(struct att_conn *ac, struct att_db *db,
    uint16_t start, uint16_t end)
{
	int i;
	uint16_t sc_handle = 0;
	uint16_t cccd_handle = 0;

	/* Find the Service Changed characteristic value handle */
	for (i = 0; i < db->count; i++) {
		if (db->attrs[i].uuid16 == 0x2A05 &&
		    db->attrs[i].is_char_value) {
			sc_handle = db->attrs[i].handle;
			/* The CCCD immediately follows the char value */
			if (i + 1 < db->count &&
			    db->attrs[i + 1].uuid16 == GATT_UUID_CCCD)
				cccd_handle = db->attrs[i + 1].handle;
			break;
		}
	}

	if (sc_handle == 0 || cccd_handle == 0) {
		LOG_GATT(1, "Service Changed: characteristic not found");
		return;
	}

	/* Check if the client has enabled indications via the CCCD */
	{
		bool ind_enabled = false;

		for (i = 0; i < ac->cccd_count; i++) {
			if (ac->cccds[i].handle == cccd_handle &&
			    (ac->cccds[i].value & GATT_CCCD_INDICATE) != 0) {
				ind_enabled = true;
				break;
			}
		}
		if (!ind_enabled) {
			LOG_GATT(1, "Service Changed: indications not "
			    "enabled (cccd_handle=%04x)", cccd_handle);
			return;
		}
	}

	/* Send the indication with the affected handle range */
	{
		uint8_t val[4];

		put_le16(val, start);
		put_le16(val + 2, end);
		if (att_send_indication(ac, sc_handle, val,
		    sizeof(val)) < 0)
			LOG_GATT(1, "Service Changed indication send "
			    "failed");
		else
			LOG_GATT(1, "Service Changed indication sent "
			    "(range %04x-%04x)", start, end);
	}
}

static void
peripheral_build_gattdb(struct att_db *db, struct att_attr *attrs,
    uint8_t *val_buf, size_t val_size, const struct blued_config *cfgp)
{
	static const uint8_t appearance[] = { 0x00, 0x00 }; /* Unknown */

	attdb_init(db, attrs, 64, val_buf, val_size);

	/* GAP Service (required) */
	attdb_add_service(db, UUID_GAP_SERVICE);
	attdb_add_characteristic(db, UUID_DEVICE_NAME,
	    GATT_PROP_READ, ATT_PERM_READ,
	    blued_peripheral_name, strlen(blued_peripheral_name));
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
	 * Config-driven services: register any services defined in
	 * the configuration file's "service" blocks.
	 */
	if (cfgp != NULL) {
		for (int si = 0; si < cfgp->nservices; si++) {
			const struct blued_service_conf *svc;
			uint16_t sh;

			svc = &cfgp->services[si];
			if (svc->uuid16 != 0)
				sh = attdb_add_service(db, svc->uuid16);
			else
				sh = attdb_add_service128(db, svc->uuid128);
			if (sh == 0) {
				LOG_ATT(0, "config service '%s': "
				    "failed to add", svc->name);
				continue;
			}
			LOG_ATT(1, "config service '%s' added at "
			    "handle 0x%04x", svc->name, sh);

			for (int ci = 0; ci < svc->nchars; ci++) {
				const struct blued_char_conf *ch;
				uint16_t ch_handle;

				ch = &svc->chars[ci];
				if (ch->uuid16 != 0) {
					ch_handle =
					    attdb_add_characteristic(db,
					    ch->uuid16, ch->properties,
					    ch->permissions,
					    ch->initial_value_len > 0 ?
					    ch->initial_value : NULL,
					    ch->initial_value_len);
				} else {
					ch_handle =
					    attdb_add_characteristic128(db,
					    ch->uuid128, ch->properties,
					    ch->permissions,
					    ch->initial_value_len > 0 ?
					    ch->initial_value : NULL,
					    ch->initial_value_len);
				}
				if (ch_handle == 0) {
					LOG_ATT(0, "config service '%s': "
					    "failed to add char", svc->name);
					continue;
				}
				if (ch->has_cccd)
					attdb_add_cccd(db);
			}
		}
	}

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
	struct blued_adapter *adp;
	struct sockaddr_l2cap sa;
	int fd;

	adp = LIST_FIRST(&blued_g.adapters);
	if (adp == NULL)
		return (-1);

	fd = socket(PF_BLUETOOTH,
	    SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_CLOFORK,
	    BLUETOOTH_PROTO_L2CAP);
	if (fd < 0)
		return (-1);

	{
		int one = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	}

	memset(&sa, 0, sizeof(sa));
	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;
	sa.l2cap_cid = htole16(NG_L2CAP_ATT_CID);
	sa.l2cap_bdaddr_type = BDADDR_LE_PUBLIC;
	/* Use BDADDR_ANY — the kernel's L2CAP fixed-CID matching does not
	 * reliably deliver incoming LE connections to address-bound sockets. */

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		warn("ATT listen bind (is another blued still running?)");
		close(fd);
		return (-1);
	}

	if (listen(fd, 1) < 0) {
		warn("ATT listen");
		close(fd);
		return (-1);
	}

	{
		char addr_str[18];
		bt_ntoa(&adp->addr, addr_str);
		LOG_ATT(1, "ATT listen socket fd=%d addr=%s cid=0x%04x "
		    "type=%d", fd, addr_str,
		    NG_L2CAP_ATT_CID, sa.l2cap_bdaddr_type);
	}

	return (fd);
}

/* peripheral_run() removed — peripheral mode now uses the unified kqueue
 * event loop with blued_periph_accept() and blued_conn_setup_peripheral(). */
