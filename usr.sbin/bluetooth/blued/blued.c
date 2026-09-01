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

#include "blued_internal.h"
#include "iso.h"
#include "hci_internal.h"	/* hci_set_event_mask_page2 (adapter init) */
#include "hci_util.h"		/* hci_fd_closed (adapter teardown) */
#include "blued_persist.h"	/* operational-state persistence across restart */
#include "blued_devmgr.h"	/* device-manager policy over persisted state */
#include "smp_internal.h"

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <time.h>	/* time(3) for device-cache last_seen (finding 67) */

/* ---- Global state (defined here, declared extern in blued_internal.h) ---- */

atomic_int blued_verbose = 0;
int blued_daemonized = 0;
atomic_bool blued_shutting_down = false;
static int blued_serviced;
/*
 * Points into blued_cfg.peripheral_name — pointer set once during init,
 * string contents updated atomically via strlcpy during SIGHUP reload.
 */
const char *blued_peripheral_name;
struct blued_ctx blued_g;
const int _blued_kq_ctl_tag;	/* sentinel address for BLUED_KQ_CTL_LISTEN */
const int _blued_kq_setup_pipe_tag;
const int _blued_kq_rpa_timer_tag;
const int _blued_kq_rpa_retry_tag;
const int _blued_kq_ctl_accept_retry_tag;	/* finding C-m1 */
const int _blued_kq_ind_timeout_tag;
const int _blued_kq_vhid_output_tag;
const int _blued_kq_acquire_tag;	/* AcquireNotify/Write daemon-side fds */
const int _blued_kq_idle_timeout_tag;
const int _blued_kq_readvertise_tag;

/*
 * Operator runtime pairing gate (the common adapter pairable control); default accept.
 * The SMP responder consults this before answering an incoming Pairing Request.
 */
atomic_bool blued_pairable = true;

_Atomic uintptr_t blued_next_timer_id = 1;

volatile sig_atomic_t running = 1;
struct pidfh *blued_pfh;
const char *blued_config_path;	/* saved for SIGHUP reload */
struct blued_config blued_cfg;	/* current daemon config */

/* Shared GATT database for peripheral mode (built once in main) */
struct att_db periph_gatt_db;
struct att_attr periph_gatt_attrs[64];
uint8_t periph_gatt_val_buf[2048];
/* Shared config reference for reconnect_max_delay */
int blued_reconnect_max_delay = 60;

static int
blued_bond_open(const char *path)
{
	const char *base;
	struct stat sb;
	int fd;

	base = strrchr(path, '/');
	base = base != NULL ? base + 1 : path;
	if (strcmp(path, BLUED_BONDDB_DEFAULT) == 0 &&
	    blued_g.persist_dirfd >= 0)
		fd = openat(blued_g.persist_dirfd, base, O_RDWR | O_CREAT |
		    O_CLOEXEC | O_CLOFORK | O_NOFOLLOW, 0600);
	else
		fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_CLOFORK |
		    O_NOFOLLOW, 0600);
	if (fd < 0)
		return (-1);
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) ||
	    sb.st_uid != geteuid() || fchmod(fd, 0600) != 0) {
		(void)close(fd);
		errno = EPERM;
		return (-1);
	}
	return (fd);
}

static int
blued_bond_set_atomic(struct smp_bond_db *db, const char *path)
{
	char dir[PATH_MAX];
	char lockname[80];
	const char *slash;
	const char *base;
	struct stat sb, dirsb;
	size_t len;
	int dirfd, lockfd, owned_dirfd, r;

	if (db == NULL || path == NULL || path[0] == '\0')
		return (-1);
	slash = strrchr(path, '/');
	base = slash != NULL ? slash + 1 : path;
	r = snprintf(lockname, sizeof(lockname), "%s.lock", base);
	if (base[0] == '\0' || r < 0 || (size_t)r >= sizeof(lockname)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (slash == NULL) {
		strlcpy(dir, ".", sizeof(dir));
	} else if (slash == path) {
		strlcpy(dir, "/", sizeof(dir));
	} else {
		len = (size_t)(slash - path);
		if (len >= sizeof(dir)) {
			errno = ENAMETOOLONG;
			return (-1);
		}
		memcpy(dir, path, len);
		dir[len] = '\0';
	}
	if (strcmp(dir, BLUED_PERSIST_DIR_DEFAULT) == 0 &&
	    blued_g.persist_dirfd >= 0) {
		dirfd = blued_g.persist_dirfd;
		owned_dirfd = 0;
	} else {
		dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_CLOFORK |
		    O_NOFOLLOW);
		if (dirfd < 0)
			return (-1);
		owned_dirfd = 1;
	}
	if (fstat(dirfd, &dirsb) != 0 || !S_ISDIR(dirsb.st_mode) ||
	    dirsb.st_uid != geteuid() || (dirsb.st_mode & 022) != 0) {
		if (owned_dirfd)
			close(dirfd);
		errno = EPERM;
		return (-1);
	}
	lockfd = openat(dirfd, lockname,
	    O_RDWR | O_CREAT | O_CLOEXEC | O_CLOFORK | O_NOFOLLOW, 0600);
	if (lockfd < 0 || fstat(lockfd, &sb) != 0 || !S_ISREG(sb.st_mode) ||
	    sb.st_uid != geteuid() || fchmod(lockfd, 0600) != 0 ||
	    flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
		if (lockfd >= 0)
			close(lockfd);
		if (owned_dirfd)
			close(dirfd);
		return (-1);
	}
	blued_g.bond_dirfd = dirfd;
	blued_g.bond_lockfd = lockfd;
	smp_bond_db_set_atomic(db, dirfd, path);
	if (db->dir_fd >= 0)
		return (0);
	close(lockfd);
	blued_g.bond_lockfd = -1;
	if (owned_dirfd)
		close(dirfd);
	blued_g.bond_dirfd = -1;
	return (-1);
}

/* Persistent local IRK for RPA generation */
uint8_t blued_local_irk[16];
bool blued_has_local_irk;

/*
 * Live device-manager state applied from persisted operational state at
 * startup.  These survive for the daemon lifetime so the loaded device/GATT
 * caches and advertising config are actually consulted at runtime instead of
 * being loaded and dropped.  The resolving-list shadow tracks which peer IRKs
 * are programmed into the controller so bond/unbond stay in sync.
 */
static struct blued_devtable blued_devtable;
static struct blued_persist_gatt_device
    blued_gattcache[BLUED_PERSIST_MAX_GATT_DEVICES];
static uint32_t blued_gattcache_count;
static struct blued_persist_adv_set blued_adv_restore;
static bool blued_adv_restore_valid;
/*
 * Snapshot of the device cache as loaded at startup, retained so metadata the
 * daemon has no live store for (notably GAP Appearance) is carried forward
 * across a restart instead of being wiped on every flush (finding 67).
 */
static struct blued_persist_device
    blued_devcache_snapshot[BLUED_PERSIST_MAX_DEVICES];
static uint32_t blued_devcache_snapshot_count;
static uintptr_t blued_rpa_timer;
uintptr_t blued_rpa_retry_timer;
static void	usage(void) __dead2;

/*
 * BSM audit helper.  Submits an audit record if BSM is enabled.
 * Silently succeeds if audit is not configured or if called from
 * inside the Capsicum sandbox (where /dev/audit is inaccessible).
 */
#ifdef USE_BSM_AUDIT
void
blued_audit(int event, int error, const char *fmt, ...)
{
	char buf[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	(void)audit_submit(event, getuid(), error, error ? 1 : 0, "%s", buf);
}
#endif

static int blued_broker_fd = -1;
static pid_t blued_broker_pid = -1;
static pthread_mutex_t blued_broker_lock = PTHREAD_MUTEX_INITIALIZER;

static int
blued_broker_send_fd(int channel, int fd)
{
	char control[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;
	uint8_t status;

	status = fd < 0 ? 1 : 0;
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &status;
	iov.iov_len = sizeof(status);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (fd >= 0) {
		memset(control, 0, sizeof(control));
		msg.msg_control = control;
		msg.msg_controllen = sizeof(control);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	}
	return (sendmsg(channel, &msg, 0) == (ssize_t)sizeof(status) ? 0 : -1);
}

static void
blued_socket_broker_loop(int channel)
{
	uint8_t command;
	int fd, maxfd;

	maxfd = getdtablesize();
	for (fd = 0; fd < maxfd; fd++)
		if (fd != channel)
			close(fd);
	for (;;) {
		if (recv(channel, &command, sizeof(command), 0) !=
		    (ssize_t)sizeof(command))
			break;
		if (command == 'Q')
			break;
		if (command != 'L')
			continue;
		fd = socket(PF_BLUETOOTH,
		    SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_CLOFORK,
		    BLUETOOTH_PROTO_L2CAP);
		if (blued_broker_send_fd(channel, fd) != 0) {
			if (fd >= 0)
				close(fd);
			break;
		}
		if (fd >= 0)
			close(fd);
	}
	close(channel);
	_exit(0);
}

static int
blued_socket_broker_start(void)
{
	int sv[2];
	pid_t pid;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) != 0)
		return (-1);
	pid = fork();
	if (pid < 0) {
		close(sv[0]);
		close(sv[1]);
		return (-1);
	}
	if (pid == 0) {
		close(sv[0]);
		blued_socket_broker_loop(sv[1]);
	}
	close(sv[1]);
	(void)fcntl(sv[0], F_SETFD, FD_CLOEXEC | FD_CLOFORK);
	blued_broker_fd = sv[0];
	blued_broker_pid = pid;
	return (0);
}

int
blued_socket_broker_take(void)
{
	char control[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;
	cap_rights_t rights;
	uint8_t command = 'L', status = 1;
	int fd = -1;

	pthread_mutex_lock(&blued_broker_lock);
	if (blued_broker_fd < 0 ||
	    send(blued_broker_fd, &command, sizeof(command), 0) !=
	    (ssize_t)sizeof(command))
		goto out;
	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	iov.iov_base = &status;
	iov.iov_len = sizeof(status);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	if (recvmsg(blued_broker_fd, &msg, 0) != (ssize_t)sizeof(status) ||
	    status != 0)
		goto out;
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len != CMSG_LEN(sizeof(fd)))
		goto out;
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	cap_rights_init(&rights, CAP_BIND, CAP_CONNECT, CAP_READ, CAP_WRITE,
	    CAP_EVENT, CAP_SETSOCKOPT, CAP_GETSOCKOPT);
	if (cap_rights_limit(fd, &rights) != 0 && errno != ENOSYS) {
		close(fd);
		fd = -1;
	}
out:
	pthread_mutex_unlock(&blued_broker_lock);
	return (fd);
}

static void
blued_socket_broker_stop(void)
{
	uint8_t command = 'Q';

	if (blued_broker_fd >= 0) {
		(void)send(blued_broker_fd, &command, sizeof(command), 0);
		close(blued_broker_fd);
		blued_broker_fd = -1;
	}
	if (blued_broker_pid > 0) {
		(void)waitpid(blued_broker_pid, NULL, 0);
		blued_broker_pid = -1;
	}
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
void
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
	if (blued_g.bond_lockfd >= 0) {
		cap_rights_init(&rights, CAP_FLOCK, CAP_FSTAT);
		cap_limit_fd_locked(blued_g.bond_lockfd, &rights, "bond_lock");
	}

	/* 3a. Pre-opened config file fd (for SIGHUP reload) */
	if (blued_g.config_fd >= 0) {
		cap_rights_init(&rights, CAP_READ, CAP_SEEK, CAP_FSTAT);
		cap_limit_fd_locked(blued_g.config_fd, &rights, "config");
	}

	/*
	 * 3b. Persist state directory fd.  The atomic saves use openat +
	 * fsync + renameat + unlinkat relative to this fd, so grant lookup,
	 * create/write/read, fsync, and rename/unlink-at rights.
	 */
	if (blued_g.persist_dirfd >= 0) {
		cap_rights_init(&rights, CAP_LOOKUP, CAP_CREATE, CAP_READ,
		    CAP_WRITE, CAP_SEEK, CAP_FSTAT, CAP_FSYNC, CAP_FTRUNCATE,
		    CAP_UNLINKAT, CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET);
		cap_limit_fd_locked(blued_g.persist_dirfd, &rights, "persist");
	}
	if (blued_g.bond_dirfd >= 0 &&
	    blued_g.bond_dirfd != blued_g.persist_dirfd) {
		cap_rights_init(&rights, CAP_LOOKUP, CAP_CREATE, CAP_READ,
		    CAP_WRITE, CAP_SEEK, CAP_FSTAT, CAP_FSYNC, CAP_FTRUNCATE,
		    CAP_UNLINKAT, CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET);
		cap_limit_fd_locked(blued_g.bond_dirfd, &rights, "bond_dir");
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
	if (blued_broker_fd >= 0) {
		cap_rights_init(&rights, CAP_SEND, CAP_RECV);
		cap_limit_fd_locked(blued_broker_fd, &rights, "socket_broker");
	}

	/* 7. Exact-address ATT/EATT listeners owned by each adapter. */
	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		cap_rights_init(&rights, CAP_ACCEPT, CAP_EVENT);
		if (adp->periph_listen_fd >= 0)
			cap_limit_fd_locked(adp->periph_listen_fd, &rights,
			    "periph_listen");
		if (adp->eatt_listen_fd >= 0)
			cap_limit_fd_locked(adp->eatt_listen_fd, &rights,
			    "eatt_listen");
	}

}

/*
 * capprotect shields (ptrace/signal/visibility/ktrace/core dump protection)
 * are applied via the Authority/cap_rt subsystem.  They are not integrated
 * here — add them after authorityd/serviced integration is complete.
 */

/*
 * Apply fd inheritance limits tailored to each fd's security role.
 * Called after fds are created but before threads are spawned.
 *
 * Policy rationale:
 *   HCI raw socket   - clofork+cloexec: raw radio access must not
 *                       leak to children or exec'd processes
 *   Bond database    - clofork+cloexec: contains LTKs, IRKs, CSRKs
 *   Control socket   - cloexec only: listener fd is harmless across
 *                       fork (accept is idempotent) but must not leak
 *                       to exec'd helper processes
 *   SMP socket       - clofork only: active pairing session must not
 *                       be shared with forked children; cloexec is not
 *                       needed since blued never exec's during pairing
 *
 * Note: blued_capsicum_limit_fds() already applies cap_limit_fd_locked()
 * (both cloexec+clofork) to most fds.  The calls here handle fds that
 * need asymmetric policies, and the SMP socket which is created lazily
 * inside setup threads after cap_enter().
 */
static void
blued_harden_fd_inheritance(void)
{
	struct blued_adapter *adp;

	/* HCI adapter raw sockets: clofork + cloexec */
	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (!adp->active || adp->hci_fd < 0)
			continue;
		(void)cap_clofork_limit(adp->hci_fd, CAP_CLOFORK_LOCKED);
		(void)cap_cloexec_limit(adp->hci_fd, CAP_CLOEXEC_LOCKED);
	}

	/* Bond database: clofork + cloexec */
	if (blued_g.bond_fd >= 0) {
		(void)cap_clofork_limit(blued_g.bond_fd, CAP_CLOFORK_LOCKED);
		(void)cap_cloexec_limit(blued_g.bond_fd, CAP_CLOEXEC_LOCKED);
	}
	if (blued_g.bond_lockfd >= 0) {
		(void)cap_clofork_limit(blued_g.bond_lockfd,
		    CAP_CLOFORK_LOCKED);
		(void)cap_cloexec_limit(blued_g.bond_lockfd,
		    CAP_CLOEXEC_LOCKED);
	}

	/* Control socket listener: cloexec only */
	if (blued_g.ctl_fd >= 0)
		(void)cap_cloexec_limit(blued_g.ctl_fd, CAP_CLOEXEC_LOCKED);

	/*
	 * SMP sockets are not hardened here -- they are created lazily
	 * inside blued_conn_setup_central() during pairing.  The SMP
	 * socket fd gets cap_clofork_limit() applied in smp_open().
	 * See smp.c for the clofork hardening of active pairing sessions.
	 */

	LOG_HOGP(2, "fd inheritance limits applied");
}

static void
atexit_cleanup(void)
{
	if (blued_serviced) {
		/*
		 * The provider exists only in central mode (peripheral mode
		 * acquires the context but returns before registering); the
		 * context is released either way.
		 */
		if (blued_g.svc_provider != NULL) {
			service_provider_destroy(blued_g.svc_provider);
			blued_g.svc_provider = NULL;
		}
		if (blued_g.svc_ctx != NULL) {
			service_release(blued_g.svc_ctx);
			blued_g.svc_ctx = NULL;
		}
	}
	/*
	 * ISO streams are live-session-only and never persisted; closing the
	 * HCI socket resets the controller's isochronous state, so a best-effort
	 * free of the registry is all that is needed at exit (no dead-state to
	 * carry across a restart).
	 */
	blued_iso_reset();
	blued_ctl_cleanup();
	if (blued_pfh != NULL)
		pidfile_remove(blued_pfh);
	if (blued_g.vhid_ctl_fd >= 0) {
		close(blued_g.vhid_ctl_fd);
		blued_g.vhid_ctl_fd = -1;
	}
}

/*
 * Check whether a privileged (uid 0) push-events subscriber is connected.
 *
 * Pairing prompts carry security-sensitive material -- the Passkey Entry
 * passkey and the Numeric Comparison value -- and drive a MITM-relevant
 * decision.  The control socket is group-accessible (mode 0660), so a
 * non-root socket-group member must never see a passkey or answer a pairing
 * prompt.  With no registered pairing agent, prompts are delivered only to
 * root subscribers (see ctl_broadcast_event()); this predicate gates whether
 * that path is available before falling back to the local console.
 */
static bool
ctl_priv_event_client_connected(void)
{
	struct blued_ctl_client *c;
	bool found;

	found = false;
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(c, &blued_g.ctl_clients, entries)
		if (c->wants_events && c->peer_known && c->peer_uid == 0) {
			found = true;
			break;
		}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
	return (found);
}

/*
 * Passkey callback for SMP pairing.
 *
 * When ctl clients are connected, sends an event and waits for a reply.
 * Falls back to stderr/stdin when no ctl clients are connected (non-daemon).
 */
int
passkey_display(uint32_t *passkey, bool display, void *arg)
{
	struct blued_conn *conn = arg;
	bdaddr_t null_addr = {{ 0 }};
	const bdaddr_t *addr;

	if (conn != NULL)
		addr = &conn->dst;
	else
		addr = &null_addr;

	if (display) {
		/*
		 * Display mode -- show the passkey to the user.
		 * Send to ctl clients if any are connected.
		 */
		if (ctl_priv_event_client_connected())
			blued_ctl_passkey_display(addr, *passkey);
		else
			fprintf(stderr,
			    "\n*** Enter this passkey on the BLE device: "
			    "%06u ***\n\n", *passkey);
		return (0);
	}

	/* Input mode -- need a passkey from the user */
	if (ctl_priv_event_client_connected()) {
		struct timespec ts;
		int ret;

		if (conn == NULL)
			return (-1);

		/*
		 * Finding 94: ARM the reply slot (status = 0) BEFORE emitting
		 * the PASSKEY_INPUT event.  The replier only accepts a reply
		 * while status == 0; if we emit first, an automated agent's
		 * immediate reply lands in the window before the slot is armed,
		 * is rejected NOT_FOUND, and this thread then blocks the full
		 * 30 s timedwait for an answer that already came.  We must not
		 * hold pairing_lock across the emit (it takes ctl_clients_lock,
		 * the reverse of the dispatch order pairing replies use — an
		 * AB/BA inversion), so arm, unlock, emit, then re-check the
		 * predicate: a reply that raced in between simply sets status
		 * to 1 and the wait loop observes it without sleeping.
		 */
		pthread_mutex_lock(&conn->pairing_lock);
		conn->passkey_reply_status = 0;
		pthread_mutex_unlock(&conn->pairing_lock);

		blued_ctl_passkey_input(addr);

		/* Wait for PASSKEY_REPLY with 30-second timeout */
		pthread_mutex_lock(&conn->pairing_lock);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 30;

		while (conn->passkey_reply_status == 0) {
			ret = pthread_cond_timedwait(&conn->pairing_cond,
			    &conn->pairing_lock, &ts);
			if (ret != 0) {
				conn->passkey_reply_status = -1;
				break;
			}
		}

		if (conn->passkey_reply_status == 1) {
			*passkey = conn->passkey_reply;
			conn->passkey_reply_status = -1;
			pthread_mutex_unlock(&conn->pairing_lock);
			return (0);
		}
		conn->passkey_reply_status = -1;
		pthread_mutex_unlock(&conn->pairing_lock);
		return (-1);
	}

	/* Fallback: stdin (non-daemon mode) */
	fprintf(stderr, "Enter the passkey shown on the BLE device: ");
	if (scanf("%u", passkey) != 1) {
		fprintf(stderr, "Passkey entry cancelled.\n");
		return (-1);
	}
	if (*passkey > 999999) {
		fprintf(stderr, "Passkey out of range (must be 0-999999).\n");
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
int
numcmp_confirm(uint32_t value, void *arg)
{
	struct blued_conn *conn = arg;
	bdaddr_t null_addr = {{ 0 }};
	const bdaddr_t *addr;

	if (conn != NULL)
		addr = &conn->dst;
	else
		addr = &null_addr;

	if (ctl_priv_event_client_connected()) {
		struct timespec ts;
		int ret;

		if (conn == NULL)
			return (-1);

		/*
		 * Finding 94: arm the reply slot before emitting the NUMCMP
		 * event so an immediate reply is not lost (see passkey_display).
		 * pairing_lock is not held across the emit to avoid the
		 * pairing_lock/ctl_clients_lock order inversion.
		 */
		pthread_mutex_lock(&conn->pairing_lock);
		conn->numcmp_reply_status = 0;
		pthread_mutex_unlock(&conn->pairing_lock);

		blued_ctl_numcmp_request(addr, value);

		/* Wait for NUMCMP_REPLY with 30-second timeout */
		pthread_mutex_lock(&conn->pairing_lock);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 30;

		while (conn->numcmp_reply_status == 0) {
			ret = pthread_cond_timedwait(&conn->pairing_cond,
			    &conn->pairing_lock, &ts);
			if (ret != 0) {
				conn->numcmp_reply_status = -1;
				break;
			}
		}

		if (conn->numcmp_reply_status == 1 && conn->numcmp_reply) {
			conn->numcmp_reply_status = -1;
			pthread_mutex_unlock(&conn->pairing_lock);
			return (0);
		}
		conn->numcmp_reply_status = -1;
		pthread_mutex_unlock(&conn->pairing_lock);
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

/*
 * Inbound Keypress Notification callback (Core Spec Vol 3 Part H §3.5.8).
 * Registered on smp_conn so a received keypress (started / digit entered /
 * digit erased / cleared / completed) is surfaced to privileged event clients.
 * 'arg' is the peer bdaddr_t.  Informational only; it never blocks pairing.
 */
void
blued_keypress_notify(uint8_t type, void *arg)
{
	bdaddr_t null_addr = {{ 0 }};
	const bdaddr_t *addr = arg != NULL ? arg : &null_addr;

	if (ctl_priv_event_client_connected())
		blued_ctl_keypress(addr, type);
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
 * Load bonded device IRKs into the controller's resolving list.
 * Enables hardware-level RPA resolution for reconnection with
 * privacy-enabled devices.  Best-effort -- silently ignored if
 * the controller doesn't support it.
 *
 * If a local IRK is available, it's passed to the controller so
 * it can generate RPAs for our advertising address.
 */
static int
blued_local_irk_ensure(void)
{
	uint8_t irk[16];
	uint8_t any = 0;

	if (blued_has_local_irk)
		return (0);
	if (smp_local_irk_get(blued_g.bond_db, irk) != 0)
		return (-1);
	for (size_t i = 0; i < sizeof(irk); i++)
		any |= irk[i];
	if (any == 0) {
		explicit_bzero(irk, sizeof(irk));
		errno = EINVAL;
		return (-1);
	}
	memcpy(blued_local_irk, irk, sizeof(irk));
	explicit_bzero(irk, sizeof(irk));
	blued_has_local_irk = true;
	return (0);
}

static int
blued_rpa_timer_rearm(int timeout_sec)
{
	struct kevent kev;
	uintptr_t old_id, new_id;

	if (blued_g.kq < 0 || !blued_has_local_irk)
		return (0);
	old_id = blued_rpa_timer;
	new_id = blued_next_timer_id++;
	EV_SET(&kev, new_id, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, timeout_sec,
	    BLUED_KQ_RPA_TIMER);
	if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0)
		return (-1);
	if (old_id != 0) {
		EV_SET(&kev, old_id, EVFILT_TIMER, EV_DELETE, 0, 0,
		    BLUED_KQ_RPA_TIMER);
		if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0) {
			EV_SET(&kev, new_id, EVFILT_TIMER, EV_DELETE, 0, 0,
			    BLUED_KQ_RPA_TIMER);
			(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
			return (-1);
		}
	}
	blued_rpa_timer = new_id;
	return (0);
}

int
blued_rpa_retry_arm(void)
{
	struct kevent kev;
	uintptr_t id;

	if (blued_g.kq < 0 || blued_rpa_retry_timer != 0)
		return (0);
	id = blued_next_timer_id++;
	EV_SET(&kev, id, EVFILT_TIMER, EV_ADD | EV_ONESHOT, NOTE_SECONDS, 1,
	    BLUED_KQ_RPA_RETRY);
	if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0)
		return (-1);
	blued_rpa_retry_timer = id;
	return (0);
}

void
blued_rpa_retry_cancel(void)
{
	struct kevent kev;

	if (blued_rpa_retry_timer == 0)
		return;
	if (blued_g.kq >= 0) {
		EV_SET(&kev, blued_rpa_retry_timer, EVFILT_TIMER, EV_DELETE,
		    0, 0, BLUED_KQ_RPA_RETRY);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	}
	blued_rpa_retry_timer = 0;
}

static void
blued_adapter_rpa_clear(struct blued_adapter *adp)
{

	adp->rpa_pending = false;
	adp->rpa_pending_global = false;
	adp->rpa_pending_primary = false;
	adp->rpa_restore_legacy = false;
	adp->rpa_restore_primary = false;
	memset(adp->rpa_pending_ext, 0, sizeof(adp->rpa_pending_ext));
	memset(adp->rpa_restore_ext, 0, sizeof(adp->rpa_restore_ext));
	explicit_bzero(adp->rpa_pending_addr, sizeof(adp->rpa_pending_addr));
	adp->rpa_retry_count = 0;
}

static void
blued_rpa_retry_reconcile(void)
{
	struct blued_adapter *adp;

	LIST_FOREACH(adp, &blued_g.adapters, entries)
		if (adp->active && adp->powered && adp->privacy &&
		    adp->rpa_pending)
			return;
	blued_rpa_retry_cancel();
}

int
blued_set_rpa_timeout(int timeout_sec)
{
	struct blued_adapter *changed[BLUED_MAX_ADAPTERS];
	struct blued_adapter *adp;
	int old_timeout;
	size_t nchanged = 0;

	if (timeout_sec < 1 || timeout_sec > 3600) {
		errno = EINVAL;
		return (-1);
	}
	old_timeout = blued_cfg.rpa_timeout;
	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (!adp->active)
			continue;
		if (hci_le_set_rpa_timeout(adp->hci_fd,
		    (uint16_t)timeout_sec) < 0)
			goto rollback;
		changed[nchanged++] = adp;
	}
	if (blued_rpa_timer_rearm(timeout_sec) < 0)
		goto rollback;
	blued_cfg.rpa_timeout = timeout_sec;
	return (0);
rollback:
	while (nchanged != 0)
		(void)hci_le_set_rpa_timeout(changed[--nchanged]->hci_fd,
		    (uint16_t)old_timeout);
	return (-1);
}

static int
blued_host_rpa_set(int hci_fd, uint8_t rpa[6])
{
	struct blued_adapter *adp;

	if (smp_generate_rpa(blued_local_irk, rpa) != 0)
		return (-1);
	if (hci_le_set_random_address(hci_fd, rpa) != 0) {
		explicit_bzero(rpa, 6);
		return (-1);
	}
	adp = blued_adapter_by_fd(hci_fd);
	if (adp != NULL) {
		memcpy(&adp->random_addr, rpa, 6);
		adp->random_addr_valid = true;
	}
	return (0);
}

/*
 * Runtime resolving-list IRK entries (finding 138).
 *
 * IPC_SECURITY_RESOLV_ADD with a client-supplied IRK for a non-bonded address
 * programs the controller but the shadow (adp->reslist) keeps only the address.
 * The bond database rebuilds the list at init; these non-bond entries would be
 * lost.  Keep a persisted shadow of the (addr, type, irk) and reprogram it in
 * load_resolving_list() alongside the bond-derived entries.  Mutations happen
 * under blued_g.reslist_lock (held by the ctl resolv handler).
 */
static struct blued_persist_resolv_entry
    blued_runtime_resolv[BLUED_PERSIST_MAX_RESOLV];
static uint32_t blued_runtime_resolv_count;

static void
blued_runtime_resolv_persist(void)
{

	if (blued_g.persist_dirfd >= 0)
		(void)blued_persist_resolv_save(blued_g.persist_dirfd,
		    blued_runtime_resolv, blued_runtime_resolv_count);
}

/* Load persisted runtime resolving-list entries into the shadow (init only). */
void
blued_runtime_resolv_load(void)
{
	uint32_t n = 0;

	if (blued_g.persist_dirfd < 0)
		return;
	if (blued_persist_resolv_load(blued_g.persist_dirfd,
	    blued_runtime_resolv, &n) == 0)
		blued_runtime_resolv_count = n;
}

void
blued_runtime_resolv_record(const uint8_t addr[6], uint8_t addr_type,
    const uint8_t irk[16])
{
	uint32_t i;

	for (i = 0; i < blued_runtime_resolv_count; i++) {
		if (blued_runtime_resolv[i].addr_type == addr_type &&
		    memcmp(blued_runtime_resolv[i].addr, addr, 6) == 0) {
			memcpy(blued_runtime_resolv[i].irk, irk, 16);
			blued_runtime_resolv_persist();
			return;
		}
	}
	if (blued_runtime_resolv_count >= BLUED_PERSIST_MAX_RESOLV)
		return;
	i = blued_runtime_resolv_count++;
	memset(&blued_runtime_resolv[i], 0, sizeof(blued_runtime_resolv[i]));
	memcpy(blued_runtime_resolv[i].addr, addr, 6);
	blued_runtime_resolv[i].addr_type = addr_type;
	memcpy(blued_runtime_resolv[i].irk, irk, 16);
	blued_runtime_resolv_persist();
}

void
blued_runtime_resolv_forget(const uint8_t addr[6], uint8_t addr_type)
{
	uint32_t i;

	for (i = 0; i < blued_runtime_resolv_count; i++) {
		if (blued_runtime_resolv[i].addr_type == addr_type &&
		    memcmp(blued_runtime_resolv[i].addr, addr, 6) == 0) {
			explicit_bzero(&blued_runtime_resolv[i],
			    sizeof(blued_runtime_resolv[i]));
			blued_runtime_resolv[i] =
			    blued_runtime_resolv[--blued_runtime_resolv_count];
			explicit_bzero(
			    &blued_runtime_resolv[blued_runtime_resolv_count],
			    sizeof(blued_runtime_resolv[0]));
			blued_runtime_resolv_persist();
			return;
		}
	}
}

void
blued_runtime_resolv_clear(void)
{

	explicit_bzero(blued_runtime_resolv, sizeof(blued_runtime_resolv));
	blued_runtime_resolv_count = 0;
	blued_runtime_resolv_persist();
}

/*
 * Runtime Filter Accept List entries (finding 135).
 *
 * The controller Filter Accept List is otherwise populated only from bonds at
 * init.  Operator-added non-bond entries are held in this persisted shadow; the
 * ctl handler programs/unprograms the controllers, and these helpers keep the
 * shadow + on-disk artifact in sync and reprogram at init.
 */
static struct blued_persist_accept_entry
    blued_acceptlist_shadow[BLUED_PERSIST_MAX_ACCEPT];
static uint32_t blued_acceptlist_shadow_count;

static void
blued_acceptlist_persist(void)
{

	if (blued_g.persist_dirfd >= 0)
		(void)blued_persist_accept_save(blued_g.persist_dirfd,
		    blued_acceptlist_shadow, blued_acceptlist_shadow_count);
}

void
blued_acceptlist_load(void)
{
	uint32_t n = 0;

	if (blued_g.persist_dirfd < 0)
		return;
	if (blued_persist_accept_load(blued_g.persist_dirfd,
	    blued_acceptlist_shadow, &n) == 0)
		blued_acceptlist_shadow_count = n;
}

/* Record a runtime entry; returns 1 if newly added, 0 if present/full. */
int
blued_acceptlist_record(const uint8_t addr[6], uint8_t addr_type)
{
	uint32_t i;

	for (i = 0; i < blued_acceptlist_shadow_count; i++) {
		if (blued_acceptlist_shadow[i].addr_type == addr_type &&
		    memcmp(blued_acceptlist_shadow[i].addr, addr, 6) == 0)
			return (0);
	}
	if (blued_acceptlist_shadow_count >= BLUED_PERSIST_MAX_ACCEPT)
		return (0);
	i = blued_acceptlist_shadow_count++;
	memset(&blued_acceptlist_shadow[i], 0,
	    sizeof(blued_acceptlist_shadow[i]));
	memcpy(blued_acceptlist_shadow[i].addr, addr, 6);
	blued_acceptlist_shadow[i].addr_type = addr_type;
	blued_acceptlist_persist();
	return (1);
}

/* Forget a runtime entry; returns 1 if it was present and removed. */
int
blued_acceptlist_forget(const uint8_t addr[6], uint8_t addr_type)
{
	uint32_t i;

	for (i = 0; i < blued_acceptlist_shadow_count; i++) {
		if (blued_acceptlist_shadow[i].addr_type == addr_type &&
		    memcmp(blued_acceptlist_shadow[i].addr, addr, 6) == 0) {
			blued_acceptlist_shadow[i] =
			    blued_acceptlist_shadow[
			    --blued_acceptlist_shadow_count];
			memset(&blued_acceptlist_shadow[
			    blued_acceptlist_shadow_count], 0,
			    sizeof(blued_acceptlist_shadow[0]));
			blued_acceptlist_persist();
			return (1);
		}
	}
	return (0);
}

void
blued_acceptlist_clear_all(void)
{

	memset(blued_acceptlist_shadow, 0, sizeof(blued_acceptlist_shadow));
	blued_acceptlist_shadow_count = 0;
	blued_acceptlist_persist();
}

uint32_t
blued_acceptlist_snapshot(struct blued_persist_accept_entry *out, uint32_t max)
{
	uint32_t n = blued_acceptlist_shadow_count;

	if (n > max)
		n = max;
	if (n > 0 && out != NULL)
		memcpy(out, blued_acceptlist_shadow, n * sizeof(out[0]));
	return (n);
}

/*
 * Reprogram persisted runtime accept-list entries onto one controller at init,
 * after the bond-derived entries have been loaded.  Best-effort.
 */
void
blued_acceptlist_reprogram(int hci_fd)
{
	uint32_t i;

	if (hci_fd < 0)
		return;
	for (i = 0; i < blued_acceptlist_shadow_count; i++) {
		uint8_t at = (blued_acceptlist_shadow[i].addr_type ==
		    BDADDR_LE_RANDOM) ? 0x01 : 0x00;

		(void)hci_le_add_device_to_filter_accept_list(hci_fd, at,
		    blued_acceptlist_shadow[i].addr);
	}
}

static int
load_resolving_list(struct hogp_device *dev, int rpa_timeout)
{
	struct blued_adapter *adp;
	struct blued_reslist *reslist;
	const uint8_t *local_irk;
	uint8_t host_rpa[6];
	uint8_t rl_size = 0;
	int loaded = 0, rl_cap;

	if (blued_cfg.privacy && blued_local_irk_ensure() != 0)
		return (-1);
	local_irk = blued_local_irk;
	adp = blued_adapter_by_fd(dev->hci_fd);
	if (adp == NULL)
		return (-1);
	reslist = &adp->reslist;

	/*
	 * Finding H-H5: resolving a bonded peer's RPA is independent of hiding
	 * our own address.  Program bonded-peer IRKs into the controller
	 * resolving list and enable address resolution whenever at least one
	 * bonded peer (or a persisted runtime entry) carries an IRK — even with
	 * local privacy off.  Only when there is nothing to resolve AND privacy
	 * is off do we keep the historical best-effort teardown that must not
	 * depend on optional resolving-list support.  Local-address privacy (our
	 * own RPA advertising + RPA rotation) stays gated on blued_cfg.privacy
	 * separately, below.
	 */
	{
		bool have_irks = false;

		if (dev->bond_db != NULL) {
			for (int i = 0; i < dev->bond_db->count; i++)
				if (dev->bond_db->bonds[i].has_irk) {
					have_irks = true;
					break;
				}
		}
		if (blued_runtime_resolv_count > 0)
			have_irks = true;

		if (!blued_cfg.privacy && !have_irks) {
			(void)hci_le_set_addr_resolution_enable(dev->hci_fd, 0);
			if (hci_le_clear_resolving_list(dev->hci_fd) == 0)
				memset(reslist, 0, sizeof(*reslist));
			return (0);
		}
	}

	/*
	 * Disable address resolution before modifying the resolving list.
	 * Core Spec Vol 4 Part E §7.8.38 forbids modification while
	 * address resolution is enabled.  Safe even if resolution was
	 * not previously enabled.
	 */
	if (hci_le_set_addr_resolution_enable(dev->hci_fd, 0) != 0)
		return (-1);

	/* Clear any stale entries; the shadow mirrors the controller list. */
	if (hci_le_clear_resolving_list(dev->hci_fd) != 0)
		return (-1);
	memset(reslist, 0, sizeof(*reslist));

	/*
	 * Controller resolving lists are small (commonly 8).  Program at most
	 * min(controller size, host shadow BLUED_RESLIST_MAX) identities and
	 * leave the rest to host-based resolution: exceeding the list must NOT
	 * be fatal (it previously aborted with err(1) at startup once bonds
	 * outnumbered the list, bricking the daemon).  A 0/unknown size falls
	 * back to the shadow cap.
	 */
	(void)hci_le_read_resolving_list_size(dev->hci_fd, &rl_size);
	rl_cap = (rl_size > 0 && rl_size < BLUED_RESLIST_MAX) ?
	    rl_size : BLUED_RESLIST_MAX;

	if (dev->bond_db == NULL && blued_runtime_resolv_count == 0)
		return (blued_cfg.privacy ? -1 : 0);
	for (int i = 0; dev->bond_db != NULL && i < dev->bond_db->count; i++) {
		struct smp_bond *b = &dev->bond_db->bonds[i];

		if (!b->has_irk)
			continue;
		if (loaded >= rl_cap) {
			LOG_HCI(1, "resolving list full (%d); remaining peers "
			    "use host-based resolution", rl_cap);
			break;
		}

		uint8_t at = (b->addr_type == BDADDR_LE_RANDOM) ? 0x01 : 0x00;

		if (hci_le_add_dev_resolving_list(dev->hci_fd, at,
		    b->addr, b->irk, local_irk) != 0 ||
		    hci_le_set_privacy_mode(dev->hci_fd, at, b->addr,
		    blued_cfg.privacy_mode) != 0)
			goto fail;
		/* Track only the fully programmed controller record. */
		if (!blued_reslist_add(reslist, b->addr, b->addr_type))
			goto fail;
		loaded++;
	}

	/*
	 * Finding 138: reprogram persisted runtime (non-bond) resolving-list
	 * entries in the same resolution-disabled window.  Skip any address a
	 * bond already programmed above (idempotent, avoids a duplicate add).
	 */
	for (uint32_t ri = 0; ri < blued_runtime_resolv_count; ri++) {
		struct blued_persist_resolv_entry *e = &blued_runtime_resolv[ri];
		uint8_t at = (e->addr_type == BDADDR_LE_RANDOM) ? 0x01 : 0x00;

		if (blued_reslist_contains(reslist, e->addr, e->addr_type))
			continue;
		if (loaded >= rl_cap) {
			LOG_HCI(1, "resolving list full (%d); remaining runtime "
			    "entries use host-based resolution", rl_cap);
			break;
		}
		if (hci_le_add_dev_resolving_list(dev->hci_fd, at,
		    e->addr, e->irk, local_irk) != 0 ||
		    hci_le_set_privacy_mode(dev->hci_fd, at, e->addr,
		    blued_cfg.privacy_mode) != 0)
			goto fail;
		if (!blued_reslist_add(reslist, e->addr, e->addr_type))
			goto fail;
		loaded++;
	}

	if (loaded > 0) {
		if (hci_le_set_rpa_timeout(dev->hci_fd, rpa_timeout) != 0 ||
		    hci_le_set_addr_resolution_enable(dev->hci_fd, 1) != 0)
			goto fail;
		LOG_HCI(1, "resolving list: %d device(s) loaded "
		    "(local_irk=%s)", loaded,
		    blued_has_local_irk ? "yes" : "no");

	}
	if (blued_cfg.privacy &&
	    blued_host_rpa_set(dev->hci_fd, host_rpa) != 0)
		goto fail;
	explicit_bzero(host_rpa, sizeof(host_rpa));
	/* Host-based advertising privacy also needs rotation with no bonds. */
	if (blued_cfg.privacy && blued_rpa_timer == 0 &&
	    blued_rpa_timer_rearm(rpa_timeout) != 0)
		goto fail;
	return (0);
fail:
	(void)hci_le_set_addr_resolution_enable(dev->hci_fd, 0);
	(void)hci_le_clear_resolving_list(dev->hci_fd);
	memset(reslist, 0, sizeof(*reslist));
	explicit_bzero(host_rpa, sizeof(host_rpa));
	return (-1);
}

/*
 * Runtime LE privacy toggle (PRIVACY verb).  See blued.h.  Enabling clears and
 * reprograms the controller resolving list from the global bond database (Core
 * Spec Vol 4 Part E §7.8.38 requires resolution off while editing), then sets
 * the RPA timeout, enables address resolution, and switches the scan role's
 * own-address type to Resolvable Private Address (0x02).  Disabling turns
 * resolution off and reverts scanning to the public address (0x00).
 */
static int
blued_privacy_program(int hci_fd, bool on, struct blued_reslist *shadow)
{
	struct smp_bond_db *db = blued_g.bond_db;
	uint8_t host_rpa[6];
	int i, loaded = 0;

	if (hci_fd < 0)
		return (-1);
	/* Never start a privacy controller transaction with an unusable identity. */
	if (on && blued_local_irk_ensure() != 0)
		return (-1);
	if (on && blued_host_rpa_set(hci_fd, host_rpa) != 0)
		return (-1);
	explicit_bzero(host_rpa, sizeof(host_rpa));

	/* Resolution must be disabled before the list can be modified. */
	if (hci_le_set_addr_resolution_enable(hci_fd, 0) != 0)
		return (-1);

	if (!on) {
		struct blued_adapter *adp = blued_adapter_by_fd(hci_fd);

		if (adp != NULL) {
			adp->random_addr_valid = false;
			/*
			 * Peer-RPA resolution is independent of LOCAL privacy: it
			 * must stay enabled whenever the resolving list holds peer
			 * identities (H-H5), or a bonded peer that advertises with
			 * an RPA can no longer be resolved for auto-reconnect.  We
			 * disabled resolution above only so the list could be
			 * modified; here the list is left intact, so restore it.
			 */
			if (adp->reslist.count > 0 &&
			    hci_le_set_addr_resolution_enable(hci_fd, 1) != 0)
				return (-1);
		}
		hci_scan_set_own_address_type(hci_fd, BLUED_HCI_OWN_ADDR_PUBLIC);
		return (0);
	}

	if (hci_le_clear_resolving_list(hci_fd) != 0)
		return (-1);
	memset(shadow, 0, sizeof(*shadow));

	if (db != NULL) {
		pthread_mutex_lock(&blued_g.bond_db_lock);
		for (i = 0; i < db->count; i++) {
			struct smp_bond *b = &db->bonds[i];
			uint8_t at;

			if (!b->has_irk)
				continue;
			at = (b->addr_type == BDADDR_LE_RANDOM) ? 0x01 : 0x00;
			if (hci_le_add_dev_resolving_list(hci_fd, at, b->addr,
			    b->irk, blued_local_irk) != 0 ||
			    hci_le_set_privacy_mode(hci_fd, at, b->addr,
			    blued_cfg.privacy_mode) != 0) {
				pthread_mutex_unlock(&blued_g.bond_db_lock);
				return (-1);
			}
			(void)blued_reslist_add(shadow, b->addr, b->addr_type);
			loaded++;
		}
		pthread_mutex_unlock(&blued_g.bond_db_lock);
	}

	/*
	 * C3-M6: reprogram persisted runtime (non-bond) resolving-list entries
	 * too, mirroring the init-time load path (blued.c ~1317).  The toggle
	 * path previously rebuilt the list from bonds ONLY, silently dropping
	 * every operator RESOLV_ADD IRK on a PRIVACY on->off->on cycle.  Skip
	 * any address a bond already programmed above (idempotent).
	 */
	for (uint32_t ri = 0; ri < blued_runtime_resolv_count; ri++) {
		struct blued_persist_resolv_entry *e = &blued_runtime_resolv[ri];
		uint8_t at = (e->addr_type == BDADDR_LE_RANDOM) ? 0x01 : 0x00;

		if (blued_reslist_contains(shadow, e->addr, e->addr_type))
			continue;
		if (hci_le_add_dev_resolving_list(hci_fd, at, e->addr, e->irk,
		    blued_local_irk) != 0 ||
		    hci_le_set_privacy_mode(hci_fd, at, e->addr,
		    blued_cfg.privacy_mode) != 0)
			return (-1);
		(void)blued_reslist_add(shadow, e->addr, e->addr_type);
		loaded++;
	}

	/*
	 * C3-M6 (H-H5 policy): resolution must be ON whenever any identity is
	 * present, independent of which op last ran.  A PRIVACY on request
	 * always enables resolution; with entries loaded this also resolves
	 * peer RPAs, and with none it still gives host-side advertising privacy.
	 */
	if (hci_le_set_rpa_timeout(hci_fd, (uint16_t)blued_cfg.rpa_timeout) != 0 ||
	    hci_le_set_addr_resolution_enable(hci_fd, 1) != 0)
		return (-1);
	if (blued_rpa_timer == 0 &&
	    blued_rpa_timer_rearm(blued_cfg.rpa_timeout) != 0)
		return (-1);
	hci_scan_set_own_address_type(hci_fd,
	    BLUED_HCI_OWN_ADDR_RPA_RANDOM_FALLBACK);
	LOG_HCI(1, "privacy enabled: %d resolving-list entry(ies)", loaded);
	return (0);
}

int
blued_privacy_set(int hci_fd, bool on)
{
	struct blued_adapter *adp;
	struct blued_reslist *shadow;
	struct blued_reslist next, restored;
	bool old_on;
	int saved_errno;

	if (hci_fd < 0)
		return (-1);
	adp = blued_adapter_by_fd(hci_fd);
	if (adp == NULL) {
		errno = ENODEV;
		return (-1);
	}
	shadow = &adp->reslist;
	/*
	 * C3-M7: serialize the read-modify-write of adp->reslist and the
	 * controller reprogram against concurrent SMP-worker / dispatch
	 * mutations (blued_reslist_sync_add/remove hold this same lock).
	 * Without it, a pairing worker's incremental add could interleave with
	 * this full rebuild and leave the shadow inconsistent with the
	 * controller list.
	 */
	pthread_mutex_lock(&blued_g.reslist_lock);
	old_on = adp->privacy;
	next = *shadow;
	if (blued_privacy_program(hci_fd, on, &next) == 0) {
		*shadow = next;
		pthread_mutex_unlock(&blued_g.reslist_lock);
		return (0);
	}

	/*
	 * Restore the controller policy that was live before this request.  When
	 * the old policy was off, leave a disabled, empty resolving list whose
	 * host shadow exactly matches it; a later enable rebuilds it from bonds.
	 */
	saved_errno = errno;
	if (old_on) {
		restored = *shadow;
		if (blued_privacy_program(hci_fd, true, &restored) == 0)
			*shadow = restored;
	} else {
		(void)hci_le_set_addr_resolution_enable(hci_fd, 0);
		if (hci_le_clear_resolving_list(hci_fd) == 0)
			memset(shadow, 0, sizeof(*shadow));
		hci_scan_set_own_address_type(hci_fd, BLUED_HCI_OWN_ADDR_PUBLIC);
	}
	pthread_mutex_unlock(&blued_g.reslist_lock);
	errno = saved_errno;
	return (-1);
}

static struct blued_ext_adv_set *
blued_ext_adv_set_find(struct blued_adapter *adp, uint8_t handle)
{

	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
		if (adp->ext_adv_sets[i].used &&
		    adp->ext_adv_sets[i].handle == handle)
			return (&adp->ext_adv_sets[i]);
	return (NULL);
}

bool
blued_ext_adv_set_used(const struct blued_adapter *adp, uint8_t handle)
{

	if (adp == NULL)
		return (false);
	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
		if (adp->ext_adv_sets[i].used &&
		    adp->ext_adv_sets[i].handle == handle)
			return (true);
	return (false);
}

int
blued_ext_adv_set_track(struct blued_adapter *adp, uint8_t handle,
    uint16_t event_props, uint32_t interval_min, uint32_t interval_max,
    uint8_t own_addr_type, uint8_t filter_policy, uint8_t primary_phy,
    uint8_t secondary_phy, uint8_t channel_map, int8_t tx_power,
    uint8_t peer_addr_type, const uint8_t *peer_addr)
{
	struct blued_ext_adv_set *set;
	size_t slot;

	if (adp == NULL || handle == 0)
		return (-1);
	set = blued_ext_adv_set_find(adp, handle);
	if (set == NULL) {
		for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
			if (!adp->ext_adv_sets[i].used) {
				set = &adp->ext_adv_sets[i];
				break;
			}
	}
	if (set == NULL) {
		errno = ENOSPC;
		return (-1);
	}
	slot = (size_t)(set - adp->ext_adv_sets);
	/* A registry slot is not a transaction identity across reconfiguration. */
	adp->rpa_pending_ext[slot] = false;
	adp->rpa_restore_ext[slot] = false;
	memset(set, 0, sizeof(*set));
	set->used = true;
	set->configured = true;
	set->handle = handle;
	set->event_props = event_props;
	set->interval_min = interval_min;
	set->interval_max = interval_max;
	set->own_addr_type = own_addr_type;
	set->filter_policy = filter_policy;
	set->primary_phy = primary_phy;
	set->secondary_phy = secondary_phy;
	set->channel_map = channel_map;
	set->tx_power = tx_power;
	set->peer_addr_type = peer_addr_type;
	if (peer_addr != NULL)
		memcpy(set->peer_addr, peer_addr, sizeof(set->peer_addr));
	return (0);
}

void
blued_ext_adv_set_enabled(struct blued_adapter *adp, uint8_t handle,
    bool enabled)
{
	struct blued_ext_adv_set *set;

	if (adp != NULL && (set = blued_ext_adv_set_find(adp, handle)) != NULL) {
		set->enabled = enabled;
		if (!enabled)
			adp->rpa_restore_ext[set - adp->ext_adv_sets] = false;
	}
}

void
blued_ext_adv_set_untrack(struct blued_adapter *adp, uint8_t handle)
{
	struct blued_ext_adv_set *set;

	if (adp != NULL && (set = blued_ext_adv_set_find(adp, handle)) != NULL) {
		adp->rpa_pending_ext[set - adp->ext_adv_sets] = false;
		adp->rpa_restore_ext[set - adp->ext_adv_sets] = false;
		memset(set, 0, sizeof(*set));
	}
}

int
blued_adv_set_privacy_prepare(struct blued_adapter *adp, uint8_t handle)
{
	uint8_t rpa[6];
	int rc;

	if (adp == NULL || handle == 0)
		return (-1);
	if (!adp->privacy)
		return (0);
	if (blued_local_irk_ensure() != 0 ||
	    smp_generate_rpa(blued_local_irk, rpa) != 0)
		return (-1);
	rc = hci_le_set_adv_set_random_address(adp->hci_fd, handle, rpa);
	explicit_bzero(rpa, sizeof(rpa));
	return (rc);
}

static int
blued_ext_adv_set_program(struct blued_adapter *adp,
    const struct blued_ext_adv_set *set, uint8_t own_addr_type)
{

	return (hci_le_set_ext_adv_params_full(adp->hci_fd, set->handle,
	    set->event_props, set->interval_min, set->interval_max, own_addr_type,
	    set->filter_policy, set->primary_phy, set->secondary_phy,
	    set->channel_map, set->tx_power, set->peer_addr_type,
	    set->peer_addr));
}

/* Apply controller privacy and advertising Own_Address_Type as one unit. */
int
blued_adapter_set_privacy(struct blued_adapter *adp, bool on)
{
	struct hci_adv_config oldcfg, newcfg;
	uint8_t adv_rpa[6];
	bool configured, enabled, privacy_changed = false;
	bool primary_reenabled = false, restore_ok = true;
	size_t disabled = 0, reenabled = 0;

	if (adp == NULL)
		return (-1);
	if (on && blued_local_irk_ensure() != 0)
		return (-1);
	configured = adp->adv_configured && adp->adv_config != NULL;
	enabled = adp->adv_enabled;
	if (configured) {
		oldcfg = *adp->adv_config;
		if (enabled && (adp->adv_use_extended ?
		    hci_le_set_ext_adv_enable(adp->hci_fd, 0, 0) :
		    hci_le_set_advertise_enable(adp->hci_fd, false)) < 0)
			return (-1);
	}
	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++) {
		struct blued_ext_adv_set *set = &adp->ext_adv_sets[i];

		if (!set->used || !set->configured || !set->enabled)
			continue;
		if (hci_le_set_ext_adv_enable(adp->hci_fd, 0, set->handle) < 0)
			goto rollback;
		disabled = i + 1;
	}
	if (blued_privacy_set(adp->hci_fd, on) < 0)
		goto rollback;
	privacy_changed = true;
	if (on) {
		if (smp_generate_rpa(blued_local_irk, adv_rpa) != 0)
			goto rollback;
	}
	if (configured) {
		newcfg = oldcfg;
		newcfg.own_addr_type = on ? 0x03 : 0x00;
		if (hci_adv_configure(adp->hci_fd, adp->le_features, &newcfg) < 0)
			goto rollback;
	}
	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++) {
		struct blued_ext_adv_set *set = &adp->ext_adv_sets[i];

		if (set->used && set->configured &&
		    blued_ext_adv_set_program(adp, set, on ? 0x03 : 0x00) < 0)
			goto rollback;
	}
	/* HCI Reset removes all extended advertising sets, so parameters must
	 * create each set before Set Advertising Set Random Address names it. */
	if (on) {
		if (configured && newcfg.used_extended &&
		    hci_le_set_adv_set_random_address(adp->hci_fd, 0,
		    adv_rpa) < 0)
			goto rollback;
		for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++) {
			struct blued_ext_adv_set *set = &adp->ext_adv_sets[i];

			if (set->used && set->configured &&
			    hci_le_set_adv_set_random_address(adp->hci_fd,
			    set->handle, adv_rpa) < 0)
				goto rollback;
		}
		explicit_bzero(adv_rpa, sizeof(adv_rpa));
	}
	if (configured && enabled && (newcfg.used_extended ?
	    hci_le_set_ext_adv_enable(adp->hci_fd, 1, 0) :
	    hci_le_set_advertise_enable(adp->hci_fd, true)) < 0)
		goto rollback;
	primary_reenabled = configured && enabled;
	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++) {
		struct blued_ext_adv_set *set = &adp->ext_adv_sets[i];

		if (set->used && set->configured && set->enabled &&
		    hci_le_set_ext_adv_enable(adp->hci_fd, 1, set->handle) < 0)
			goto rollback;
		if (set->used && set->configured && set->enabled)
			reenabled = i + 1;
	}
	if (configured) {
		*adp->adv_config = newcfg;
		adp->adv_use_extended = newcfg.used_extended;
	}
	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
		if (adp->ext_adv_sets[i].used && adp->ext_adv_sets[i].configured)
			adp->ext_adv_sets[i].own_addr_type = on ? 0x03 : 0x00;
	blued_adapter_rpa_clear(adp);
	blued_rpa_retry_reconcile();
	return (0);

rollback:
	explicit_bzero(adv_rpa, sizeof(adv_rpa));
	/* Re-quiesce anything the enable phase resurrected before reprogramming. */
	if (primary_reenabled && (newcfg.used_extended ?
	    hci_le_set_ext_adv_enable(adp->hci_fd, 0, 0) :
	    hci_le_set_advertise_enable(adp->hci_fd, false)) < 0)
		restore_ok = false;
	for (size_t i = 0; i < reenabled; i++)
		if (adp->ext_adv_sets[i].used &&
		    adp->ext_adv_sets[i].configured &&
		    adp->ext_adv_sets[i].enabled &&
		    hci_le_set_ext_adv_enable(adp->hci_fd, 0,
		    adp->ext_adv_sets[i].handle) < 0)
			restore_ok = false;
	if (privacy_changed && blued_privacy_set(adp->hci_fd,
	    adp->privacy) < 0)
		restore_ok = false;
	if (configured && hci_adv_configure(adp->hci_fd,
	    adp->le_features, &oldcfg) < 0)
		restore_ok = false;
	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++) {
		struct blued_ext_adv_set *set = &adp->ext_adv_sets[i];

		if (set->used && set->configured &&
		    blued_ext_adv_set_program(adp, set,
		    set->own_addr_type) < 0)
			restore_ok = false;
	}
	if (restore_ok && configured && enabled && (oldcfg.used_extended ?
	    hci_le_set_ext_adv_enable(adp->hci_fd, 1, 0) :
	    hci_le_set_advertise_enable(adp->hci_fd, true)) < 0)
		restore_ok = false;
	for (size_t i = 0; restore_ok && i < disabled; i++)
		if (adp->ext_adv_sets[i].used &&
		    adp->ext_adv_sets[i].configured &&
		    adp->ext_adv_sets[i].enabled &&
		    hci_le_set_ext_adv_enable(adp->hci_fd, 1,
		    adp->ext_adv_sets[i].handle) < 0)
			restore_ok = false;
	if (!restore_ok) {
		if (configured)
			(void)(oldcfg.used_extended ?
			    hci_le_set_ext_adv_enable(adp->hci_fd, 0, 0) :
			    hci_le_set_advertise_enable(adp->hci_fd, false));
		adp->adv_enabled = false;
		for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
			if (adp->ext_adv_sets[i].used &&
			    adp->ext_adv_sets[i].configured) {
				(void)hci_le_set_ext_adv_enable(adp->hci_fd, 0,
				    adp->ext_adv_sets[i].handle);
				adp->ext_adv_sets[i].enabled = false;
			}
	}
	return (-1);
}

int
blued_adapter_rotate_rpa(struct blued_adapter *adp, const uint8_t rpa[6])
{
	bool primary_ext, complete;
	const uint8_t *addr;

	if (adp == NULL || rpa == NULL || !adp->active || !adp->powered ||
	    !adp->privacy)
		return (-1);
	primary_ext = adp->adv_configured && adp->adv_use_extended;
	if (!adp->rpa_pending) {
		memcpy(adp->rpa_pending_addr, rpa, 6);
		adp->rpa_pending = true;
		adp->rpa_pending_global = true;
		adp->rpa_pending_primary = primary_ext;
		adp->rpa_retry_count = 0;
		for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
			adp->rpa_pending_ext[i] =
			    adp->ext_adv_sets[i].used &&
			    adp->ext_adv_sets[i].configured;
	}
	addr = adp->rpa_pending_addr;

	/* Global scan/initiation address; legacy advertising shares this domain. */
	if (adp->rpa_pending_global) {
		bool safe = true;
		bool scan_suspended = false;

		if (!primary_ext && adp->adv_enabled && !adp->rpa_restore_legacy) {
			if (hci_le_set_advertise_enable(adp->hci_fd, false) < 0)
				safe = false;
			else
				adp->rpa_restore_legacy = true;
		}
		/*
		 * Finding H-H6: LE Set Random Address (Core Spec Vol 4 Part E
		 * §7.8.4) returns Command Disallowed while scanning or initiating
		 * is enabled.  The mesh bearer keeps an always-on passive scan and
		 * a central may have a create-connection outstanding — either one
		 * makes the address set fail, so the RPA never rotates and becomes
		 * fixed.  Quiesce the mesh scanner and cancel any pending
		 * create-connection across the address set, then resume the
		 * scanner; a cancelled initiation is re-driven by the normal
		 * reconnect path.
		 */
		if (safe && adp->mesh_scan_active) {
			if (hci_le_mesh_scan_set(adp->hci_fd, adp->le_features,
			    false) < 0)
				safe = false;
			else
				scan_suspended = true;
		}
		if (safe) {
			struct blued_conn *iconn;
			bool initiating = false;

			LIST_FOREACH(iconn, &blued_g.conns, entries)
				if (iconn->adapter == adp &&
				    atomic_load(&iconn->state) ==
				    BLUED_CONN_CONNECTING) {
					initiating = true;
					break;
				}
			if (initiating &&
			    hci_le_create_connection_cancel(adp->hci_fd) < 0)
				safe = false;
		}
		if (safe && hci_le_set_random_address(adp->hci_fd, addr) == 0) {
			memcpy(&adp->random_addr, addr, 6);
			adp->random_addr_valid = true;
			adp->rpa_pending_global = false;
		}
		/* Restore the always-on mesh scanner regardless of the outcome. */
		if (scan_suspended)
			(void)hci_le_mesh_scan_set(adp->hci_fd,
			    adp->le_features, true);
	}
	if (adp->rpa_restore_legacy) {
		if (!adp->adv_enabled ||
		    hci_le_set_advertise_enable(adp->hci_fd, true) == 0)
			adp->rpa_restore_legacy = false;
	}

	/* Extended primary set is independent of the global address domain. */
	if (adp->rpa_pending_primary) {
		bool safe = true;

		if (adp->adv_enabled && !adp->rpa_restore_primary) {
			if (hci_le_set_ext_adv_enable(adp->hci_fd, 0, 0) < 0)
				safe = false;
			else
				adp->rpa_restore_primary = true;
		}
		if (safe && hci_le_set_adv_set_random_address(adp->hci_fd, 0,
		    addr) == 0)
			adp->rpa_pending_primary = false;
	}
	if (adp->rpa_restore_primary) {
		if (!adp->adv_enabled ||
		    hci_le_set_ext_adv_enable(adp->hci_fd, 1, 0) == 0)
			adp->rpa_restore_primary = false;
	}

	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++) {
		struct blued_ext_adv_set *set = &adp->ext_adv_sets[i];
		bool safe = true;

		if (!set->used || !set->configured) {
			adp->rpa_pending_ext[i] = false;
			adp->rpa_restore_ext[i] = false;
			continue;
		}
		if (adp->rpa_pending_ext[i]) {
			if (set->enabled && !adp->rpa_restore_ext[i]) {
				if (hci_le_set_ext_adv_enable(adp->hci_fd, 0,
				    set->handle) < 0)
					safe = false;
				else
					adp->rpa_restore_ext[i] = true;
			}
			if (safe && hci_le_set_adv_set_random_address(adp->hci_fd,
			    set->handle, addr) == 0)
				adp->rpa_pending_ext[i] = false;
		}
		if (adp->rpa_restore_ext[i]) {
			if (!set->enabled || hci_le_set_ext_adv_enable(adp->hci_fd,
			    1, set->handle) == 0)
				adp->rpa_restore_ext[i] = false;
		}
	}

	complete = !adp->rpa_pending_global &&
	    !adp->rpa_pending_primary && !adp->rpa_restore_legacy &&
	    !adp->rpa_restore_primary;
	for (size_t i = 0; complete && i < nitems(adp->ext_adv_sets); i++)
		complete = !adp->rpa_pending_ext[i] &&
		    !adp->rpa_restore_ext[i];
	if (complete) {
		adp->rpa_pending = false;
		adp->rpa_retry_count = 0;
		explicit_bzero(adp->rpa_pending_addr,
		    sizeof(adp->rpa_pending_addr));
		return (0);
	}
	return (-1);
}

/*
 * Populate the controller's Filter Accept List with bonded device
 * addresses.  Returns the number of devices loaded.  Used to decide
 * advertising_filter_policy: if > 0, use 0x02 (connection requests
 * only from accept list; §7.8.5); if 0, use 0x00 (allow all for
 * initial pairing).
 *
 * Caller must ensure advertising and scanning are stopped before
 * calling this at runtime (Core Spec Vol 4 Part E §7.8.15).
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

static const uint8_t blued_zero_irk[16];

/*
 * PC8: consult the GATT cache restored from persistent storage.  Returns true
 * when a persisted per-peer entry carries a Database Hash equal to the freshly
 * read one, so cached handles are reusable and rediscovery is skipped
 * (Core Spec Vol 3 Part G §2.5.2).  Lets a restart-restored cache short-circuit
 * discovery even when the in-memory bond blob has not yet re-derived its hash.
 */
bool
blued_persist_gattcache_reuse(const uint8_t addr[6], uint8_t addr_type,
    const uint8_t fresh_hash[16])
{

	return (blued_gattcache_reuse(blued_gattcache, blued_gattcache_count,
	    addr, addr_type, fresh_hash));
}

/*
 * Finding H-H7: resolving-list Add/Remove and Set Address Resolution Enable
 * (Core Spec Vol 4 Part E §7.8.38/§7.8.44) are Command Disallowed while
 * advertising or scanning is enabled.  These helpers quiesce the adapter's
 * advertising and its always-on mesh passive scan around a resolving-list
 * mutation and restore exactly what was suspended afterwards.
 */
void
blued_reslist_quiesce_begin(struct blued_adapter *adp,
    struct blued_reslist_quiesce *q)
{

	memset(q, 0, sizeof(*q));
	if (adp == NULL)
		return;
	if (adp->adv_configured && adp->adv_enabled) {
		if (adp->adv_use_extended) {
			if (hci_le_set_ext_adv_enable(adp->hci_fd, 0, 0) == 0)
				q->ext_primary_adv = true;
		} else if (hci_le_set_advertise_enable(adp->hci_fd, false) == 0)
			q->legacy_adv = true;
	}
	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++) {
		struct blued_ext_adv_set *set = &adp->ext_adv_sets[i];

		if (set->used && set->configured && set->enabled &&
		    hci_le_set_ext_adv_enable(adp->hci_fd, 0, set->handle) == 0)
			q->ext_sets[i] = true;
	}
	if (adp->mesh_scan_active &&
	    hci_le_mesh_scan_set(adp->hci_fd, adp->le_features, false) == 0)
		q->mesh_scan = true;
}

void
blued_reslist_quiesce_end(struct blued_adapter *adp,
    struct blued_reslist_quiesce *q)
{

	if (adp == NULL)
		return;
	if (q->mesh_scan)
		(void)hci_le_mesh_scan_set(adp->hci_fd, adp->le_features, true);
	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
		if (q->ext_sets[i])
			(void)hci_le_set_ext_adv_enable(adp->hci_fd, 1,
			    adp->ext_adv_sets[i].handle);
	if (q->ext_primary_adv)
		(void)hci_le_set_ext_adv_enable(adp->hci_fd, 1, 0);
	if (q->legacy_adv)
		(void)hci_le_set_advertise_enable(adp->hci_fd, true);
}

/*
 * Re-enable address resolution after a resolving-list mutation.  Finding H-H5:
 * resolving bonded peers' RPAs is independent of local-address privacy, so
 * resolution must be on whenever the shadow holds at least one entry, even with
 * privacy off.
 */
void
blued_reslist_restore_resolution(int hci_fd, struct blued_adapter *adp)
{

	(void)hci_le_set_addr_resolution_enable(hci_fd,
	    (blued_cfg.privacy || adp->reslist.count > 0) ? 1 : 0);
}

/*
 * Incrementally add a freshly bonded peer's IRK to the controller resolving
 * list (PC10 add-on-bond).  Idempotent via the shadow and bounded to the
 * controller list depth, so repeated pairings never grow the list past its
 * capacity.  A bond without an IRK is a no-op.  Advertising/scanning are
 * quiesced and address resolution is toggled off around the mutation (Core
 * Spec Vol 4 Part E §7.8.38).
 */
void
blued_reslist_sync_add(int hci_fd, const struct smp_bond *bond)
{
	struct blued_adapter *adp;
	struct blued_reslist_quiesce q;
	const uint8_t *local_irk;
	uint8_t at;

	if (bond == NULL || hci_fd < 0 || !bond->has_irk)
		return;
	adp = blued_adapter_by_fd(hci_fd);
	if (adp == NULL)
		return;
	/* Serialize shadow + controller mutation against dispatch (finding 92). */
	pthread_mutex_lock(&blued_g.reslist_lock);
	if (!blued_reslist_add(&adp->reslist, bond->addr, bond->addr_type)) {
		pthread_mutex_unlock(&blued_g.reslist_lock);
		return;		/* already present or list full */
	}

	local_irk = blued_has_local_irk ? blued_local_irk : blued_zero_irk;
	at = (bond->addr_type == BDADDR_LE_RANDOM) ? 0x01 : 0x00;
	/*
	 * Finding H-H7: quiesce adv/scan first, and check every command's
	 * return.  Ignoring the disable-resolution / Add return let the Add fail
	 * 0x0C (Command Disallowed) while the shadow claimed success — the peer
	 * IRK silently never reached the controller.  On any failure roll the
	 * shadow back so it stays consistent with the controller.
	 */
	blued_reslist_quiesce_begin(adp, &q);
	if (hci_le_set_addr_resolution_enable(hci_fd, 0) != 0 ||
	    hci_le_add_dev_resolving_list(hci_fd, at, bond->addr, bond->irk,
	    local_irk) != 0) {
		(void)blued_reslist_remove(&adp->reslist, bond->addr,
		    bond->addr_type);	/* keep shadow == controller */
		LOG_HCI(1, "resolving-list add failed; peer IRK not programmed");
	} else {
		(void)hci_le_set_privacy_mode(hci_fd, at, bond->addr,
		    blued_cfg.privacy_mode);
	}
	blued_reslist_restore_resolution(hci_fd, adp);
	blued_reslist_quiesce_end(adp, &q);
	pthread_mutex_unlock(&blued_g.reslist_lock);
}

/*
 * Incrementally remove a forgotten peer's IRK from the controller resolving
 * list (PC10 remove-on-unbond).  Idempotent: a no-op if the peer was not
 * programmed.
 */
void
blued_reslist_sync_remove(int hci_fd, const uint8_t addr[6], uint8_t addr_type)
{
	struct blued_adapter *adp;
	struct blued_reslist_quiesce q;
	uint8_t at;

	if (hci_fd < 0)
		return;
	adp = blued_adapter_by_fd(hci_fd);
	if (adp == NULL)
		return;
	/* Serialize shadow + controller mutation against dispatch (finding 92). */
	pthread_mutex_lock(&blued_g.reslist_lock);
	if (!blued_reslist_remove(&adp->reslist, addr, addr_type)) {
		pthread_mutex_unlock(&blued_g.reslist_lock);
		return;		/* not programmed */
	}

	at = (addr_type == BDADDR_LE_RANDOM) ? 0x01 : 0x00;
	/* Finding H-H7: quiesce adv/scan around the disallowed-while-active
	 * mutation (Core Spec Vol 4 Part E §7.8.38). */
	blued_reslist_quiesce_begin(adp, &q);
	(void)hci_le_set_addr_resolution_enable(hci_fd, 0);
	(void)hci_le_remove_dev_resolving_list(hci_fd, at, addr);
	blued_reslist_restore_resolution(hci_fd, adp);
	blued_reslist_quiesce_end(adp, &q);
	pthread_mutex_unlock(&blued_g.reslist_lock);
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
		uint8_t scan_phys = 0x01; /* 1M */
		if (dev->le_features & LE_FEAT_CODED_PHY)
			scan_phys = 0x05; /* 1M + Coded */
		if (hci_le_ext_scan(dev->hci_fd, 5, results,
		    BLE_MAX_SCAN_RESULTS, &nresults, scan_phys) == 0) {
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
 * HCI nodes via SIOC_HCI_RAW_NODE_LIST_NAMES -- no guessing.
 *
 * Skip nodes with all-zero BD_ADDR -- these are phantom netgraph
 * nodes without a real USB transport behind them.
 */
static int
blued_devenum_cb(int s __unused, struct bt_devinfo const *di, void *arg)
{
	int *nfound = arg;
	struct blued_adapter *adp;
	int fd;

	/*
	 * Cap the live adapter set at BLUED_MAX_ADAPTERS.  Several routines
	 * (blued_set_rpa_timeout, the SIGHUP privacy transition) collect
	 * changed adapters into a fixed BLUED_MAX_ADAPTERS-sized stack array
	 * while iterating this list, and the per-fd HCI lock/scan-state tables
	 * are also 8-slot; an unbounded adapter count would overflow them.
	 * (finding 96)
	 */
	if (*nfound >= BLUED_MAX_ADAPTERS) {
		LOG_HCI(0, "ignoring %s: adapter limit (%d) reached",
		    di->devname, BLUED_MAX_ADAPTERS);
		return (0);
	}

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
	adp->periph_listen_fd = -1;
	adp->eatt_listen_fd = -1;
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

			/* Cap the live adapter set (finding 96). */
			if (nfound >= BLUED_MAX_ADAPTERS) {
				warnx("ignoring adapter %s: limit (%d) reached",
				    cfg->adapters[i], BLUED_MAX_ADAPTERS);
				break;
			}

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
			adp->periph_listen_fd = -1;
			adp->eatt_listen_fd = -1;
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
blued_adapter_hci_reset(struct blued_adapter *adp)
{
	uint8_t buf[3 + NG_HCI_EVENT_PKT_SIZE];
	ssize_t n;

	if (hci_reset(adp->hci_fd) < 0)
		return (-1);
	/*
	 * Reset Complete is the boundary between controller incarnations.  Raw
	 * HCI sockets can still contain asynchronous events queued before that
	 * boundary; no post-reset procedure has started yet, so drain them before
	 * publishing the new epoch.
	 */
	do {
		n = recv(adp->hci_fd, buf, sizeof(buf), MSG_DONTWAIT);
	} while (n > 0 || (n < 0 && errno == EINTR));
	/*
	 * controller_epoch / local_ids[] / local_id_next are read by setup
	 * workers under conns_lock (blued_conn_apply_cached_local); publish the
	 * new incarnation under the write lock so a worker cannot observe a torn
	 * epoch or a half-cleared local_ids entry racing this reset.  conns_lock
	 * is the top of the lock hierarchy and no lower lock is held here.
	 */
	pthread_rwlock_wrlock(&blued_g.conns_lock);
	adp->controller_epoch++;
	if (adp->controller_epoch == 0)
		adp->controller_epoch++;
	memset(adp->local_ids, 0, sizeof(adp->local_ids));
	adp->local_id_next = 0;
	pthread_rwlock_unlock(&blued_g.conns_lock);
	return (0);
}

static int
blued_adapter_init(struct blued_adapter *adp)
{

	if (blued_adapter_hci_reset(adp) < 0) {
		warn("reset %s", adp->name);
		return (-1);
	}
	/* HCI Reset destroys controller-resident privacy and role state. */
	adp->powered = false;
	adp->random_addr_valid = false;
	memset(&adp->random_addr, 0, sizeof(adp->random_addr));
	pthread_mutex_lock(&blued_g.reslist_lock);	/* finding 92 */
	memset(&adp->reslist, 0, sizeof(adp->reslist));
	pthread_mutex_unlock(&blued_g.reslist_lock);
	blued_adapter_rpa_clear(adp);
	/*
	 * Post-reset settle time: the kernel's ng_hci Reset Complete
	 * handler clears the INITED flag asynchronously.  Without a
	 * brief delay, subsequent HCI commands can race with the flag
	 * clear.  100ms is empirically sufficient on all tested USB
	 * adapters.
	 */
	usleep(100000); /* 100ms post-reset settle */

	if (hci_get_bdaddr(adp->hci_fd, (uint8_t *)&adp->addr) < 0) {
		warn("read BD_ADDR for %s", adp->name);
		return (-1);
	}

	if (hci_write_le_host_support(adp->hci_fd, 1, 0) < 0 && blued_verbose)
		warn("write LE host support for %s", adp->name);

	if (hci_le_read_local_features(adp->hci_fd, &adp->le_features) < 0)
		adp->le_features = 0;
	adp->adv_configured = false;
	adp->adv_enabled = false;
	adp->primary_adv_data_valid = false;
	adp->primary_scan_rsp_valid = false;
	adp->disc_saved_valid = false;
	adp->adv_use_extended =
	    (adp->le_features & LE_FEAT_EXT_ADVERTISING) != 0;
	adp->privacy = blued_cfg.privacy;

	hci_set_event_mask(adp->hci_fd,
	    NG_HCI_EVENT_MASK_DEFAULT | NG_HCI_EVENT_MASK_LE);

	/*
	 * Enable page-2 Authenticated Payload Timeout Expired (bit 23) and
	 * Encryption Change v2 (bit 25), Core 6.3 Vol 4 Part E §7.3.69.
	 * Without bit 25 the v2 decoder is unreachable on controllers that
	 * select the current event version.
	 */
	hci_set_event_mask_page2(adp->hci_fd,
	    BLUED_HCI_EVENT_MASK_PAGE2_DEFAULT);

	/* Set LE event mask. Feature bits and event-mask bits differ. */
	hci_le_set_event_mask(adp->hci_fd,
	    hci_le_default_event_mask(adp->le_features));

	/*
	 * When LE privacy is enabled, scan with a Resolvable Private
	 * Address (own_address_type 0x03, random-address fallback) so the
	 * Observer/Central roles do not transmit the public identity
	 * address (Core Spec Vol 3 Part C Section 12.4).  Otherwise scan
	 * with the public address (0x00).
	 */
	hci_scan_set_own_address_type(adp->hci_fd,
	    blued_cfg.privacy ? BLUED_HCI_OWN_ADDR_RPA_RANDOM_FALLBACK :
	    BLUED_HCI_OWN_ADDR_PUBLIC);

	/*
	 * Set controller-wide defaults for Data Length Extension and PHY.
	 * These apply to all future connections so they must be set once
	 * at init rather than per-connection.  Best-effort: silently
	 * ignored if the controller doesn't support the feature.
	 */
	if (adp->le_features & LE_FEAT_DATA_LENGTH_EXT)
		hci_le_write_suggested_default_data_length(adp->hci_fd,
		    0x00FB /* 251 octets */, 0x0848 /* 2120 us */);
	if (adp->le_features & LE_FEAT_2M_PHY)
		hci_le_set_default_phy(adp->hci_fd, 0x00 /* no preference */,
		    0x02 /* prefer 2M TX */, 0x02 /* prefer 2M RX */);

	/*
	 * Announce host support for the optional LE procedures the daemon
	 * actually drives, so the controller will permit them (LE Set Host
	 * Feature, Core Vol 4 Part E §7.8.115).  Without these the peer never
	 * sees the corresponding host-support feature bit and rejects/omits
	 * the procedure.  Feature bit numbers per Core Vol 6 Part B Table 4.4:
	 * 32 = Connected Isochronous Stream (Host Support),
	 * 38 = Connection Subrating (Host Support).  Gated on controller
	 * support so an unsupported bit is not toggled.  (finding 143)
	 */
#define HCI_LE_HOSTFEAT_CIS		32
#define HCI_LE_HOSTFEAT_CONN_SUBRATING	38
	if (adp->le_features & (LE_FEAT_CIS_CENTRAL | LE_FEAT_CIS_PERIPH))
		(void)hci_le_set_host_feature(adp->hci_fd,
		    HCI_LE_HOSTFEAT_CIS, 0x01);
	if (adp->le_features & LE_FEAT_CONN_SUBRATING)
		(void)hci_le_set_host_feature(adp->hci_fd,
		    HCI_LE_HOSTFEAT_CONN_SUBRATING, 0x01);
#undef HCI_LE_HOSTFEAT_CIS
#undef HCI_LE_HOSTFEAT_CONN_SUBRATING

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
			LOG_HOGP(1, "%s: %d advertising sets supported",
			    adp->name, num_sets);
		if (hci_le_read_max_adv_data_length(adp->hci_fd,
		    &max_adv_len) == 0)
			LOG_HOGP(1, "%s: max adv data length=%d",
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
	if (hci_node_init(adp->hci_fd) < 0) {
		if (blued_verbose)
			warn("node init for %s", adp->name);
		adp->powered = false;
		return (-1);
	}

	adp->powered = true;	/* controller is up after a successful init */

	if (blued_verbose >= 1) {
		char addr_str[18];
		bt_ntoa(&adp->addr, addr_str);
		LOG_HOGP(1, "adapter %s: address %s, features 0x%llx",
		    adp->name, addr_str,
		    (unsigned long long)adp->le_features);
	}

	return (0);
}

/*
 * Operator runtime adapter settings (common adapter-settings parity): power,
 * device name, and discoverable advertising with an auto-off timer.
 */

static void
blued_disc_timer_disarm(struct blued_adapter *adp)
{
	struct kevent kev;

	if (adp->discoverable_timer == 0 || blued_g.kq < 0) {
		adp->discoverable_timer = 0;
		return;
	}
	EV_SET(&kev, adp->discoverable_timer, EVFILT_TIMER, EV_DELETE, 0, 0,
	    NULL);
	(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	adp->discoverable_timer = 0;
}

#define BLUED_DISC_STOP_RETRY_SEC	1
#define BLUED_DISC_STOP_RETRY_MAX	5

/* Commit the host side of a verified Reset terminal boundary. */
static void
blued_adapter_controller_invalidated(struct blued_adapter *adp)
{
	struct blued_conn *conn, *tmp;

	blued_disc_timer_disarm(adp);
	blued_periph_readvertise_cancel(adp);
	blued_ctl_adapter_reset(adp);
	blued_iso_reset_adapter(adp);
	adp->periodic_adv_enabled = false;
	adp->periodic_sync_pending = false;
	memset(adp->periodic_syncs, 0, sizeof(adp->periodic_syncs));
	adp->adv_configured = false;
	adp->adv_use_extended = false;
	adp->adv_enabled = false;
	memset(adp->ext_adv_sets, 0, sizeof(adp->ext_adv_sets));
	adp->mesh_scan_active = false;
	adp->discoverable = false;
	adp->disc_limited = false;
	adp->discoverable_stop_retries = 0;
	adp->privacy = false;
	adp->random_addr_valid = false;
	memset(&adp->random_addr, 0, sizeof(adp->random_addr));
	pthread_mutex_lock(&blued_g.reslist_lock);	/* finding 92 */
	memset(&adp->reslist, 0, sizeof(adp->reslist));
	pthread_mutex_unlock(&blued_g.reslist_lock);
	blued_adapter_rpa_clear(adp);
	adp->powered = false;
	adp->power_quiescing = false;
	LIST_FOREACH_SAFE(conn, &blued_g.conns, entries, tmp) {
		if (conn->adapter != adp)
			continue;
		conn->reconnect = false;
		blued_conn_disconnect(conn);
	}
	blued_rpa_retry_reconcile();
	/*
	 * If a mesh advertising PDU owned by this adapter was in flight when
	 * the controller was invalidated (power-off, rollback, discoverable
	 * fail-safe), its Advertising Set Terminated event is drained/lost by
	 * the HCI reset and can never arrive.  Recover the one-at-a-time mesh
	 * pacing state here so mesh TX (which shares a process-global in-flight
	 * flag) is not wedged until the next power-on.
	 */
	blued_mesh_adv_reset();
}

void
blued_primary_adv_cache(struct blued_adapter *adp, bool scan_rsp,
    const uint8_t *data, uint8_t len)
{
	uint8_t *dst;
	uint8_t *dstlen;
	bool *valid;

	if (adp == NULL || data == NULL || len > 31)
		return;
	/* While the overlay owns handle 0, client writes update the payload that
	 * will be restored rather than destroying the discoverability deadline. */
	if (adp->disc_saved_valid) {
		dst = scan_rsp ? adp->disc_saved_scan_rsp :
		    adp->disc_saved_adv_data;
		dstlen = scan_rsp ? &adp->disc_saved_scan_rsp_len :
		    &adp->disc_saved_adv_data_len;
		valid = scan_rsp ? &adp->disc_saved_scan_rsp_valid :
		    &adp->disc_saved_adv_data_valid;
	} else {
		dst = scan_rsp ? adp->primary_scan_rsp : adp->primary_adv_data;
		dstlen = scan_rsp ? &adp->primary_scan_rsp_len :
		    &adp->primary_adv_data_len;
		valid = scan_rsp ? &adp->primary_scan_rsp_valid :
		    &adp->primary_adv_data_valid;
	}
	memcpy(dst, data, len);
	*dstlen = len;
	*valid = true;
}

/*
 * A failed discoverability rollback cannot be represented safely: the
 * controller may still be advertising while the requested deadline is gone.
 * Reset is the verified boundary that places every LE role in Standby.  Only
 * after Reset succeeds may controller-backed host mirrors be invalidated.
 */
static int
blued_adapter_discoverable_fail_safe(struct blued_adapter *adp)
{
	if (blued_adapter_hci_reset(adp) < 0)
		return (-1);
	blued_adapter_controller_invalidated(adp);
	/* The reset cleared mesh_scan_active; re-assert the always-on mesh
	 * scan if the host still has subscribers, so mesh RX survives the
	 * fail-safe reset. */
	blued_mesh_scan_reassert();
	/* The reset destroyed the mesh adv set; recover the adv FIFO so a PDU
	 * in flight at reset time cannot wedge mesh TX. */
	blued_mesh_adv_reset();
	return (0);
}

static int
blued_disc_timer_arm(struct blued_adapter *adp, unsigned int timeout_sec)
{
	struct kevent kev;
	uintptr_t id, old_id;

	if (timeout_sec == 0) {
		blued_disc_timer_disarm(adp);
		return (0);
	}
	if (blued_g.kq < 0) {
		errno = ENXIO;
		return (-1);
	}
	old_id = adp->discoverable_timer;
	id = blued_next_timer_id++;
	/* One-shot: auto-off fires once, then the timer is removed. */
	EV_SET(&kev, id, EVFILT_TIMER, EV_ADD | EV_ONESHOT, NOTE_SECONDS,
	    (int64_t)timeout_sec, NULL);
	if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0)
		return (-1);
	if (old_id != 0) {
		EV_SET(&kev, old_id, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
		if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0) {
			EV_SET(&kev, id, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
			(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
			return (-1);
		}
	}
	adp->discoverable_timer = id;
	return (0);
}

static int
blued_discoverable_restore(struct blued_adapter *adp)
{
	bool ext;

	if (!adp->disc_saved_valid)
		return (0);
	ext = adp->adv_use_extended;
	if (adp->adv_enabled && (ext ?
	    hci_le_set_ext_adv_enable(adp->hci_fd, 0, 0) :
	    hci_le_set_advertise_enable(adp->hci_fd, false)) < 0)
		return (1); /* no mutation: overlay remains truthful and retryable */
	adp->adv_enabled = false;
	adp->discoverable = false;
	if (adp->disc_saved_adv_data_valid && (ext ?
	    hci_le_set_ext_adv_data(adp->hci_fd, 0,
	    adp->disc_saved_adv_data, adp->disc_saved_adv_data_len) :
	    hci_le_set_advertising_data(adp->hci_fd,
	    adp->disc_saved_adv_data, adp->disc_saved_adv_data_len)) < 0)
		return (-1);
	if (adp->disc_saved_scan_rsp_valid && (ext ?
	    hci_le_set_ext_scan_response_data(adp->hci_fd, 0,
	    adp->disc_saved_scan_rsp, adp->disc_saved_scan_rsp_len) :
	    hci_le_set_scan_response_data(adp->hci_fd,
	    adp->disc_saved_scan_rsp, adp->disc_saved_scan_rsp_len)) < 0)
		return (-1);
	if (adp->disc_saved_enabled && (ext ?
	    hci_le_set_ext_adv_enable(adp->hci_fd, 1, 0) :
	    hci_le_set_advertise_enable(adp->hci_fd, true)) < 0)
		return (-1);

	adp->adv_configured = adp->disc_saved_configured;
	adp->adv_use_extended = adp->disc_saved_use_extended;
	adp->adv_enabled = adp->disc_saved_enabled;
	memcpy(adp->primary_adv_data, adp->disc_saved_adv_data,
	    sizeof(adp->primary_adv_data));
	adp->primary_adv_data_len = adp->disc_saved_adv_data_len;
	adp->primary_adv_data_valid = adp->disc_saved_adv_data_valid;
	memcpy(adp->primary_scan_rsp, adp->disc_saved_scan_rsp,
	    sizeof(adp->primary_scan_rsp));
	adp->primary_scan_rsp_len = adp->disc_saved_scan_rsp_len;
	adp->primary_scan_rsp_valid = adp->disc_saved_scan_rsp_valid;
	adp->disc_saved_valid = false;
	adp->discoverable = false;
	adp->disc_limited = false;
	adp->discoverable_stop_retries = 0;
	return (0);
}

/*
 * Push connectable + discoverable advertising for an adapter with the requested
 * discoverable flags, or turn it off.  Reuses the existing adv data/param/enable
 * path (Core Spec Vol 3 Part C §9.2.3/§9.2.4 general/limited discoverable mode).
 */
int
blued_adapter_set_discoverable(struct blued_adapter *adp, bool enable,
    bool limited, unsigned int timeout_sec)
{
	uint8_t adv_data[31];
	uint8_t flags;
	int dlen;
	bool ext;

	if (adp == NULL)
		return (-1);
	ext = adp->adv_configured ? adp->adv_use_extended :
	    (adp->le_features & LE_FEAT_EXT_ADVERTISING) != 0;

	if (!enable) {
		int restore_error;

		if (!adp->disc_saved_valid)
			return (0);
		restore_error = blued_discoverable_restore(adp);
		if (restore_error > 0)
			return (-1);
		if (restore_error < 0) {
			if (blued_adapter_discoverable_fail_safe(adp) < 0)
				return (-1);
		}
		blued_disc_timer_disarm(adp);
		return (0);
	}

	flags = AD_FLAG_BREDR_NOT_SUPP |
	    (limited ? AD_FLAG_LIMITED_DISC : AD_FLAG_GENERAL_DISC);
	dlen = ble_build_adv_data_flags(adv_data, sizeof(adv_data), flags,
	    blued_peripheral_name, NULL, 0);
	if (dlen < 0)
		return (-1);

	if (!adp->disc_saved_valid) {
		if (adp->adv_enabled && !adp->primary_adv_data_valid) {
			errno = EBUSY;
			return (-1);
		}
		adp->disc_saved_valid = true;
		adp->disc_saved_configured = adp->adv_configured;
		adp->disc_saved_use_extended = ext;
		adp->disc_saved_enabled = adp->adv_enabled;
		memcpy(adp->disc_saved_adv_data, adp->primary_adv_data,
		    sizeof(adp->disc_saved_adv_data));
		adp->disc_saved_adv_data_len = adp->primary_adv_data_len;
		adp->disc_saved_adv_data_valid = adp->primary_adv_data_valid;
		memcpy(adp->disc_saved_scan_rsp, adp->primary_scan_rsp,
		    sizeof(adp->disc_saved_scan_rsp));
		adp->disc_saved_scan_rsp_len = adp->primary_scan_rsp_len;
		adp->disc_saved_scan_rsp_valid = adp->primary_scan_rsp_valid;
	}
	if (adp->adv_enabled && (ext ?
	    hci_le_set_ext_adv_enable(adp->hci_fd, 0, 0) :
	    hci_le_set_advertise_enable(adp->hci_fd, false)) < 0)
		goto overlay_fail;
	adp->adv_enabled = false;
	if (ext) {
		/*
		 * On extended-advertising controllers the connectable set 0
		 * must be created with Set Extended Advertising Parameters
		 * before Set Extended Advertising Data, otherwise the data
		 * command fails with Unknown Advertising Identifier and
		 * DISCOVERABLE always returns -1.  Issue params for the
		 * connectable+scannable legacy set now (the set is disabled
		 * above, so this is allowed).  (finding 44)
		 */
		if (hci_le_set_ext_adv_params_phy(adp->hci_fd, 0x00,
		    0x0013 /* conn+scan legacy ADV_IND */,
		    ADV_INTERVAL_100MS, ADV_INTERVAL_100MS,
		    adp->privacy ? BLUED_HCI_OWN_ADDR_RPA_RANDOM_FALLBACK :
		    BLUED_HCI_OWN_ADDR_PUBLIC, 0x00 /* no allowlist */,
		    0x01 /* primary PHY 1M */, 0x01 /* secondary PHY 1M */) < 0)
			goto overlay_fail;
		if (hci_le_set_ext_adv_data(adp->hci_fd, 0x00, adv_data,
		    (uint8_t)dlen) < 0)
			goto overlay_fail;
		if (hci_le_set_ext_adv_enable(adp->hci_fd, 1, 0x00) < 0)
			goto overlay_fail;
	} else {
		if (hci_le_set_advertising_data(adp->hci_fd, adv_data,
		    (uint8_t)dlen) < 0)
			goto overlay_fail;
		if (hci_le_set_advertise_enable(adp->hci_fd, true) < 0)
			goto overlay_fail;
	}
	adp->adv_enabled = true;

	if (blued_disc_timer_arm(adp, timeout_sec) < 0) {
		goto overlay_fail;
	}
	adp->discoverable = true;
	adp->discoverable_stop_retries = 0;
	adp->disc_limited = limited;
	adp->adv_configured = true;
	adp->adv_use_extended = ext;
	adp->adv_enabled = true;
	return (0);

overlay_fail:
	if (blued_discoverable_restore(adp) != 0)
		(void)blued_adapter_discoverable_fail_safe(adp);
	return (-1);
}

/*
 * Match and dispatch an adapter-owned discoverable auto-off timer.
 */
bool
blued_discoverable_timer_fired(uintptr_t timer_id)
{
	struct blued_adapter *adp;

	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (adp->discoverable_timer != timer_id)
			continue;
		adp->discoverable_timer = 0;
		if (!adp->discoverable && !adp->disc_saved_valid)
			return (true);
		if (blued_adapter_set_discoverable(adp, false, false, 0) == 0)
			return (true);
		adp->discoverable_stop_retries++;
		if (adp->discoverable_stop_retries < BLUED_DISC_STOP_RETRY_MAX &&
		    blued_disc_timer_arm(adp, BLUED_DISC_STOP_RETRY_SEC) == 0)
			return (true);
		if (blued_adapter_discoverable_fail_safe(adp) < 0) {
			/* Preserve the last verified mirrors.  A partial restore can already
			 * have stopped the overlay; disc_saved_valid keeps that restoration
			 * alive without falsely publishing advertising as enabled. */
			(void)blued_disc_timer_arm(adp,
			    BLUED_DISC_STOP_RETRY_SEC);
		}
		return (true);
	}
	return (false);
}

static void
blued_periph_refresh_adv_data(void)
{
	struct blued_adapter *adp;
	uint16_t uuids[] = { UUID_DIS_SERVICE, UUID_CUSTOM_SERVICE };
	uint8_t adv[31], scan_rsp[31];
	size_t namelen;
	int adv_len, scan_len;
	bool truncated;

	if (!blued_g.periph_active)
		return;
	adv_len = ble_build_adv_data(adv, sizeof(adv), blued_peripheral_name,
	    uuids, nitems(uuids));
	if (adv_len < 0)
		return;
	namelen = strlen(blued_peripheral_name);
	truncated = namelen > 29;
	if (namelen > 29)
		namelen = 29;
	scan_len = 0;
	scan_rsp[scan_len++] = (uint8_t)(1 + namelen);
	scan_rsp[scan_len++] = truncated ? 0x08 : 0x09;
	memcpy(scan_rsp + scan_len, blued_peripheral_name, namelen);
	scan_len += (int)namelen;

	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (!adp->active || !adp->adv_configured)
			continue;
		if (adp->disc_saved_valid) {
			blued_primary_adv_cache(adp, false, adv,
			    (uint8_t)adv_len);
			blued_primary_adv_cache(adp, true, scan_rsp,
			    (uint8_t)scan_len);
			continue;
		}
		if (adp->adv_use_extended) {
			if (hci_le_set_ext_adv_data(adp->hci_fd, 0x00, adv,
			    (uint8_t)adv_len) < 0 ||
			    hci_le_set_ext_scan_response_data(adp->hci_fd, 0x00,
			    scan_rsp, (uint8_t)scan_len) < 0)
				warn("refresh extended advertising data on %s",
				    adp->name);
			else {
				blued_primary_adv_cache(adp, false, adv,
				    (uint8_t)adv_len);
				blued_primary_adv_cache(adp, true, scan_rsp,
				    (uint8_t)scan_len);
			}
		} else if (hci_le_set_advertising_data(adp->hci_fd, adv,
		    (uint8_t)adv_len) < 0 ||
		    hci_le_set_scan_response_data(adp->hci_fd, scan_rsp,
		    (uint8_t)scan_len) < 0) {
			warn("refresh legacy advertising data on %s", adp->name);
		} else {
			blued_primary_adv_cache(adp, false, adv, (uint8_t)adv_len);
			blued_primary_adv_cache(adp, true, scan_rsp,
			    (uint8_t)scan_len);
		}
	}
}

/*
 * Update the local GAP Device Name (0x2A00) attribute and the advertising
 * Local Name.  Bounded by BLUED_GAP_NAME_MAXLEN.  Returns 0 on success, -1 on
 * an empty or over-long name.
 */
int
blued_set_device_name(const char *name)
{
	size_t nl;

	if (name == NULL)
		return (-1);
	nl = strlen(name);
	if (nl == 0 || nl > BLUED_GAP_NAME_MAXLEN)
		return (-1);

	/* Update the persistent name pointer (points into blued_cfg storage). */
	strlcpy(blued_cfg.peripheral_name, name,
	    sizeof(blued_cfg.peripheral_name));
	blued_peripheral_name = blued_cfg.peripheral_name;

	/* Update the served GAP Device Name characteristic value. */
	pthread_mutex_lock(&blued_g.gatt_db_lock);
	(void)attdb_set_char_value(&periph_gatt_db, UUID_DEVICE_NAME, name,
	    (uint16_t)nl);
	pthread_mutex_unlock(&blued_g.gatt_db_lock);

	/* Refresh advertising / scan-response Local Name if advertising. */
	if (blued_g.periph_active) {
		blued_periph_refresh_adv_data();
		blued_periph_readvertise();
	}
	return (0);
}

/*
 * POWER on|off for an adapter (the common adapter power control).  on re-inits the
 * controller via the adapter init path; off quiesces advertising/scanning,
 * drops this adapter's links, and disarms the discoverable timer while keeping
 * the HCI socket open.  Returns 0 on success.
 */
static void
blued_periodic_sync_reset(struct blued_adapter *adp)
{

	if (adp == NULL)
		return;
	adp->periodic_sync_pending = false;
	memset(adp->periodic_syncs, 0, sizeof(adp->periodic_syncs));
}

int
blued_adapter_set_power(struct blued_adapter *adp, bool on)
{
	struct blued_conn *conn;
	bool primary_disabled = false, scan_disabled = false;
	bool periodic_disabled = false;
	bool ext_disabled[BLUED_EXT_ADV_SET_MAX] = { false };
	bool initiating = false;

	if (adp == NULL || adp->hci_fd < 0)
		return (-1);

	if (on) {
		if (adp->powered)
			return (0);
		if (blued_adapter_init(adp) < 0) {
			adp->powered = false;
			return (-1);
		}
		/* Reset already destroyed controller ISO/periodic objects. */
		blued_iso_reset_adapter(adp);
		adp->periodic_adv_enabled = false;
		blued_periodic_sync_reset(adp);
		/* Reset erased advertising payloads.  Invalidate every daemon and
		 * client set rather than exposing a configured set with empty data. */
		blued_ctl_adapter_reset(adp);
		adp->adv_configured = false;
		adp->adv_enabled = false;
		memset(adp->ext_adv_sets, 0, sizeof(adp->ext_adv_sets));
		/* Reset removed RL/timeout/resolution/random-address state. */
		adp->privacy = false;
		if (blued_adapter_set_privacy(adp, blued_cfg.privacy) < 0) {
			adp->powered = false;
			adp->privacy = false;
			adp->random_addr_valid = false;
			pthread_mutex_lock(&blued_g.reslist_lock);	/* 92 */
			memset(&adp->reslist, 0, sizeof(adp->reslist));
			pthread_mutex_unlock(&blued_g.reslist_lock);
			blued_adapter_rpa_clear(adp);
			blued_rpa_retry_reconcile();
			return (-1);
		}
		adp->privacy = blued_cfg.privacy;
		adp->powered = true;
		adp->power_quiescing = false;
		/*
		 * The controller reset on power-down cleared mesh_scan_active,
		 * but the mesh subscription (mesh_subscribers) is host state that
		 * survives.  Re-assert the always-on mesh passive scan so mesh RX
		 * is not silently dead until an UNSUBSCRIBE/SUBSCRIBE cycle.
		 */
		blued_mesh_scan_reassert();
		/* Recover the mesh adv FIFO: a PDU in flight when power was cut
		 * left mesh_adv_inflight stuck, which would wedge mesh TX. */
		blued_mesh_adv_reset();
		return (0);
	}

	/* Power off: stop discoverable advertising and any standing adv. */
	adp->power_quiescing = true;
	if (adp->adv_configured && adp->adv_enabled) {
		if (adp->adv_use_extended)
			primary_disabled = hci_le_set_ext_adv_enable(adp->hci_fd,
			    0, 0x00) == 0;
		else
			primary_disabled = hci_le_set_advertise_enable(adp->hci_fd,
			    false) == 0;
		if (!primary_disabled)
			goto poweroff_rollback;
	}
	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++) {
		struct blued_ext_adv_set *set = &adp->ext_adv_sets[i];

		if (set->used && set->configured && set->enabled) {
			if (hci_le_set_ext_adv_enable(adp->hci_fd, 0,
			    set->handle) < 0)
				goto poweroff_rollback;
			ext_disabled[i] = true;
		}
	}
	/* Stop the actual persistent scan family selected by this controller. */
	if (adp->mesh_scan_active) {
		if (hci_le_mesh_scan_set(adp->hci_fd, adp->le_features,
		    false) < 0)
			goto poweroff_rollback;
		scan_disabled = true;
	}

	LIST_FOREACH(conn, &blued_g.conns, entries)
		if (conn->adapter == adp &&
		    atomic_load(&conn->state) == BLUED_CONN_CONNECTING) {
			initiating = true;
			break;
		}
	if (initiating && hci_le_create_connection_cancel(adp->hci_fd) < 0)
		goto poweroff_rollback;
	if (adp->periodic_adv_enabled) {
		if (hci_le_set_periodic_adv_enable(adp->hci_fd, 0, 0) < 0)
			goto poweroff_rollback;
		periodic_disabled = true;
	}
	/* Disconnect/Terminate BIG report only Command Status; their terminal
	 * events cannot be awaited while this event-loop transaction is running.
	 * Reset completion is the synchronous boundary proving every periodic
	 * sync, CIG/CIS, BIG/BIS, and queued role procedure gone. */
	if (blued_adapter_hci_reset(adp) < 0)
		goto poweroff_rollback;
	blued_adapter_controller_invalidated(adp);
	return (0);

poweroff_rollback:
	{
		bool rollback_ok = true;

	if (scan_disabled &&
	    hci_le_mesh_scan_set(adp->hci_fd, adp->le_features, true) < 0)
		rollback_ok = false;
	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
		if (ext_disabled[i] && hci_le_set_ext_adv_enable(adp->hci_fd, 1,
		    adp->ext_adv_sets[i].handle) < 0)
			rollback_ok = false;
	if (primary_disabled) {
		if (adp->adv_use_extended)
			rollback_ok = hci_le_set_ext_adv_enable(adp->hci_fd, 1,
			    0) == 0 && rollback_ok;
		else
			rollback_ok = hci_le_set_advertise_enable(adp->hci_fd,
			    true) == 0 && rollback_ok;
	}
	if (periodic_disabled &&
	    hci_le_set_periodic_adv_enable(adp->hci_fd, 1, 0) < 0)
		rollback_ok = false;
	if (!rollback_ok && blued_adapter_hci_reset(adp) == 0) {
		/* Reset is the only truthful recovery from a partly restored role
		 * transaction: it drops links, sets, payloads, and privacy state. */
		blued_adapter_controller_invalidated(adp);
		return (0);
	}
	adp->power_quiescing = false;
	return (-1);
	}
}

/*
 * Reload configuration from disk on SIGHUP.
 *
 * Only runtime-changeable settings are applied.  Structural settings
 * (adapters, peripheral_mode, scan_mode, service definitions, pidfile,
 * ctlsock, bonddb paths) require a full restart.
 */
void
blued_reload_config(void)
{
	struct blued_config newcfg;
	struct blued_config *old;

	old = &blued_cfg;

	blued_config_defaults(&newcfg);
	/*
	 * Inside Capsicum sandbox, use the pre-opened config fd.
	 * Fall back to path-based load if no fd is available (e.g.,
	 * running without Capsicum or before cap_enter).
	 */
	if (blued_g.config_fd >= 0) {
		if (blued_config_load_fd(&newcfg, blued_g.config_fd) < 0) {
			LOG_HOGP(1, "SIGHUP: failed to reload config "
			    "from fd, keeping current settings");
			return;
		}
	} else if (blued_config_load(&newcfg, blued_config_path) < 0) {
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
		int old_timeout = old->rpa_timeout;

		LOG_HOGP(1, "config reload: rpa_timeout %d -> %d",
		    old->rpa_timeout, newcfg.rpa_timeout);
		if (blued_set_rpa_timeout(newcfg.rpa_timeout) < 0)
			LOG_HOGP(0, "config reload: RPA timeout transition "
			    "failed; keeping %d", old_timeout);
	}

	/* Security settings */
	if (newcfg.bondable != old->bondable) {
		LOG_HOGP(1, "config reload: bondable %s -> %s",
		    old->bondable ? "yes" : "no",
		    newcfg.bondable ? "yes" : "no");
		old->bondable = newcfg.bondable;
	}
	if (newcfg.sc_mode != old->sc_mode) {
		LOG_HOGP(1, "config reload: sc mode %u -> %u",
		    old->sc_mode, newcfg.sc_mode);
		old->sc_mode = newcfg.sc_mode;
	}
	if (newcfg.mitm != old->mitm) {
		LOG_HOGP(1, "config reload: mitm %s -> %s",
		    old->mitm ? "yes" : "no", newcfg.mitm ? "yes" : "no");
		old->mitm = newcfg.mitm;
	}
	if (newcfg.keypress != old->keypress) {
		LOG_HOGP(1, "config reload: keypress %s -> %s",
		    old->keypress ? "yes" : "no",
		    newcfg.keypress ? "yes" : "no");
		old->keypress = newcfg.keypress;
	}
	if (newcfg.key_dist != old->key_dist) {
		LOG_HOGP(1, "config reload: key_dist 0x%02x -> 0x%02x",
		    old->key_dist, newcfg.key_dist);
		old->key_dist = newcfg.key_dist;
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
	if (newcfg.min_pairing_security != old->min_pairing_security) {
		LOG_HOGP(1, "config reload: min_pairing_security %u -> %u",
		    old->min_pairing_security, newcfg.min_pairing_security);
		old->min_pairing_security = newcfg.min_pairing_security;
	}

	/* Privacy */
	if (newcfg.privacy != old->privacy) {
		struct blued_adapter *changed[BLUED_MAX_ADAPTERS];
		struct blued_adapter *adp;
		size_t nchanged = 0;
		bool old_privacy = old->privacy;

		LOG_HOGP(1, "config reload: privacy %s -> %s",
		    old->privacy ? "on" : "off",
		    newcfg.privacy ? "on" : "off");
		LIST_FOREACH(adp, &blued_g.adapters, entries) {
			if (!adp->active)
				continue;
			if (blued_adapter_set_privacy(adp, newcfg.privacy) < 0) {
				while (nchanged != 0)
					(void)blued_adapter_set_privacy(
					    changed[--nchanged], old_privacy);
				LOG_HOGP(0, "config reload: privacy transition failed; "
				    "keeping %s", old_privacy ? "on" : "off");
				goto privacy_done;
			}
			changed[nchanged++] = adp;
		}
		old->privacy = newcfg.privacy;
		hci_l2cap_set_own_address_type(old->privacy ?
		    BLUED_HCI_OWN_ADDR_RPA_RANDOM_FALLBACK :
		    BLUED_HCI_OWN_ADDR_PUBLIC);
		for (size_t i = 0; i < nchanged; i++) {
			changed[i]->privacy = old->privacy;
			hci_scan_set_own_address_type(changed[i]->hci_fd,
			    old->privacy ?
			    BLUED_HCI_OWN_ADDR_RPA_RANDOM_FALLBACK :
			    BLUED_HCI_OWN_ADDR_PUBLIC);
		}
	privacy_done: ;
	}

	/* Peripheral name */
	if (strcmp(newcfg.peripheral_name, old->peripheral_name) != 0) {
		LOG_HOGP(1, "config reload: peripheral_name '%s' -> '%s'",
		    old->peripheral_name, newcfg.peripheral_name);
		strlcpy(old->peripheral_name, newcfg.peripheral_name,
		    sizeof(old->peripheral_name));
		blued_peripheral_name = old->peripheral_name;
		blued_periph_refresh_adv_data();
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
	/*
	 * privacy_mode (device vs network) is programmed per-bond into the
	 * controller's resolving list at startup; changing it at runtime would
	 * require reprogramming every resolving-list entry, which SIGHUP does
	 * not do.  Emit the same "restart required" diagnostic as the other
	 * non-reloadable keys instead of silently dropping the edit.
	 * (finding 98)
	 */
	if (newcfg.privacy_mode != old->privacy_mode)
		LOG_HOGP(1, "config reload: privacy_mode changed "
		    "(restart required)");
	if (strcmp(newcfg.logfile, old->logfile) != 0)
		LOG_HOGP(1, "config reload: logfile changed "
		    "(restart required)");
	if (newcfg.daemonize != old->daemonize)
		LOG_HOGP(1, "config reload: daemonize changed "
		    "(restart required)");

	LOG_HOGP(1, "configuration reloaded");
}

/* ================================================================
 * Operational-state persistence (blued_persist) integration.
 *
 * The state directory fd is opened before cap_enter() so the atomic
 * openat/renameat writes work inside the Capsicum sandbox.  Settings restore
 * overlays the runtime-mutable adapter state onto the config the daemon inits
 * from, so a value changed at runtime (e.g. the device name) survives a
 * restart and wins over the original blued.conf value.  The device and GATT
 * caches are reconciled against the bond database at save time -- they carry
 * only the non-key metadata, never the keys.
 * ================================================================ */

static void
blued_persist_settings_from_cfg(struct blued_persist_settings *s,
    const struct blued_config *c)
{

	memset(s, 0, sizeof(*s));
	strlcpy(s->name, c->peripheral_name, sizeof(s->name));
	s->privacy = c->privacy ? 1 : 0;
	s->privacy_mode = (uint8_t)c->privacy_mode;
	s->discoverable = c->peripheral_mode ? 1 : 0;
	s->connectable = 1;
	s->io_capability = c->io_capability;
	s->bondable = c->bondable ? 1 : 0;
	s->sc_mode = c->sc_mode;
	s->min_key_size = c->min_key_size;
	s->rpa_timeout = c->rpa_timeout;
	/*
	 * Persist the default connection parameters (finding 67: previously
	 * dead schema) and the runtime preferred ATT MTU (finding 140: had no
	 * persisted field and reverted on restart).  The conn-param defaults
	 * mirror the CONNECT fallback (6/12/4/500).
	 */
	s->conn_interval_min = 6;
	s->conn_interval_max = 12;
	s->conn_latency = 4;
	s->supervision_timeout = 500;
	s->preferred_mtu = blued_g.att_preferred_mtu;
}

static void
blued_persist_settings_to_cfg(const struct blued_persist_settings *s,
    struct blued_config *c)
{

	if (s->name[0] != '\0')
		strlcpy(c->peripheral_name, s->name,
		    sizeof(c->peripheral_name));
	c->privacy = s->privacy != 0;
	if (s->privacy_mode <= 1)
		c->privacy_mode = s->privacy_mode;
	c->io_capability = s->io_capability;
	c->bondable = s->bondable != 0;
	if (s->sc_mode <= BLUED_SC_ONLY)
		c->sc_mode = s->sc_mode;
	if (s->min_key_size >= 7 && s->min_key_size <= 16)
		c->min_key_size = s->min_key_size;
	if (s->rpa_timeout >= 1 && s->rpa_timeout <= 3600)
		c->rpa_timeout = s->rpa_timeout;
	/*
	 * Restore the runtime discoverable state (finding 67: previously saved
	 * but never restored) so a peripheral that was made discoverable comes
	 * back discoverable, and the preferred ATT MTU (finding 140) into the
	 * live global the central MTU-exchange path already consults.
	 */
	if (s->discoverable)
		c->peripheral_mode = true;
	if (s->preferred_mtu >= 23 && s->preferred_mtu <= 517)
		blued_g.att_preferred_mtu = s->preferred_mtu;
}

/*
 * Load persisted state and apply it to the running config.  Called after the
 * config file and CLI overrides are applied, before adapters are initialised.
 */
static void
blued_persist_restore(struct blued_config *cfg)
{
	struct blued_persist_settings s;
	static struct blued_persist_device devs[BLUED_PERSIST_MAX_DEVICES];
	static struct blued_persist_gatt_device gatt[BLUED_PERSIST_MAX_GATT_DEVICES];
	static struct blued_persist_adv_set advs[BLUED_PERSIST_MAX_ADV_SETS];
	uint32_t ndev = 0, ngatt = 0, nadv = 0;

	if (blued_g.persist_dirfd < 0)
		blued_g.persist_dirfd =
		    blued_persist_open_dir(BLUED_PERSIST_DIR_DEFAULT);
	if (blued_g.persist_dirfd < 0) {
		LOG_HOGP(1, "persist: state dir %s unavailable, using defaults",
		    BLUED_PERSIST_DIR_DEFAULT);
		return;
	}

	if (blued_persist_settings_load(blued_g.persist_dirfd, &s) == 0) {
		blued_persist_settings_to_cfg(&s, cfg);
		LOG_HOGP(1, "persist: restored adapter settings (name=\"%s\")",
		    cfg->peripheral_name);
	}
	/*
	 * Apply, not just load.  The persist loader has already rejected a
	 * corrupt/truncated/wrong-version file (CRC + version gate) and clamps
	 * the count, so on a bad load ndev/ngatt/nadv stay 0 and the applies
	 * below are no-ops -- a partial or hostile file can never overwrite
	 * live state with garbage.
	 */
	if (blued_persist_devcache_load(blued_g.persist_dirfd, devs,
	    &ndev) == 0) {
		int applied = blued_devtable_apply(&blued_devtable, devs, ndev);

		/*
		 * Retain the loaded records so fields with no live store (GAP
		 * Appearance) survive the next flush (finding 67).
		 */
		if (ndev > BLUED_PERSIST_MAX_DEVICES)
			ndev = BLUED_PERSIST_MAX_DEVICES;
		memcpy(blued_devcache_snapshot, devs,
		    ndev * sizeof(blued_devcache_snapshot[0]));
		blued_devcache_snapshot_count = ndev;
		LOG_HOGP(1, "persist: applied %d cached device(s) to live "
		    "table", applied);
	}
	if (blued_persist_gattcache_load(blued_g.persist_dirfd, gatt,
	    &ngatt) == 0) {
		/* Keep the loaded GATT cache live so a bonded peer with a
		 * matching Database Hash skips rediscovery on reconnect. */
		if (ngatt > BLUED_PERSIST_MAX_GATT_DEVICES)
			ngatt = BLUED_PERSIST_MAX_GATT_DEVICES;
		memcpy(blued_gattcache, gatt,
		    ngatt * sizeof(blued_gattcache[0]));
		blued_gattcache_count = ngatt;
		LOG_HOGP(1, "persist: restored GATT cache for %u device(s)",
		    ngatt);
	}
	if (blued_persist_advconfig_load(blued_g.persist_dirfd, advs,
	    &nadv) == 0 && nadv > 0) {
		/*
		 * Restore the peripheral advertising configuration so a
		 * peripheral resumes advertising after a restart.  Only the
		 * legacy set (handle 0) is resumed; if it was enabled, force
		 * peripheral mode so the startup adv path re-applies it.
		 *
		 * H-L5: the primary set's real interval/props are now restored
		 * with full 24-bit interval precision (persist v2).  Re-creating
		 * the additional persisted *extended* sets (records 1..nadv-1)
		 * with their individual props/interval/data at adapter init is a
		 * larger piece of plumbing (per-set create+data+enable in the
		 * init path) and is NOT yet done: those records are loaded and
		 * available in advs[] but not re-applied.  Until then a
		 * non-connectable extended set is simply not resurrected (rather
		 * than resurrected with the wrong, connectable, properties).
		 */
		blued_adv_restore = advs[0];
		blued_adv_restore_valid = true;
		if (advs[0].enabled)
			cfg->peripheral_mode = true;
		LOG_HOGP(1, "persist: restored advertising config "
		    "(enabled=%u)", advs[0].enabled);
	}

	/*
	 * Restore the runtime resolving-list IRK entries (finding 138) and the
	 * runtime Filter Accept List entries (finding 135) into their shadows;
	 * they are reprogrammed onto each controller during adapter init.
	 */
	blued_runtime_resolv_load();
	blued_acceptlist_load();
}

/*
 * Harvest current operational state and persist it.  Reconciles the device
 * and GATT caches from the bond database (bonded devices contribute their
 * non-key metadata: name, appearance, HOGP flag, DB hash, cached handles).
 * Safe to call at shutdown; a failure is logged and otherwise ignored.
 */
static int
blued_persist_flush(const struct blued_config *cfg)
{
	struct blued_persist_settings s;
	static struct blued_persist_device devs[BLUED_PERSIST_MAX_DEVICES];
	static struct blued_persist_gatt_device gatt[BLUED_PERSIST_MAX_GATT_DEVICES];
	struct blued_persist_adv_set *adv;
	uint32_t ndev = 0, ngatt = 0;
	int rc = 0;

	if (blued_g.persist_dirfd < 0)
		return (0);

	blued_persist_settings_from_cfg(&s, cfg);
	if (blued_persist_settings_save(blued_g.persist_dirfd, &s) != 0)
		rc = -1;

	if (blued_g.bond_db != NULL) {
		int i;

		pthread_mutex_lock(&blued_g.bond_db_lock);
		for (i = 0; i < blued_g.bond_db->count &&
		    ndev < BLUED_PERSIST_MAX_DEVICES; i++) {
			const struct smp_bond *b = &blued_g.bond_db->bonds[i];
			struct blued_persist_device *pd = &devs[ndev++];

			const struct blued_known_device *kd;
			const struct blued_persist_device *snap;

			memset(pd, 0, sizeof(*pd));
			memcpy(pd->addr, b->addr, 6);
			pd->addr_type = b->addr_type;
			pd->bonded = 1;
			/*
			 * auto_connect reflects the operator reconnect policy
			 * rather than being hardcoded to 1 (finding 67).
			 */
			pd->auto_connect = (cfg->auto_connect &&
			    cfg->reconnect) ? 1 : 0;
			if (b->has_name) {
				pd->has_name = 1;
				strlcpy(pd->name, b->name, sizeof(pd->name));
			}
			pd->is_hogp = b->has_handle_cache ? 1 : 0;
			/*
			 * A bonded peer's stored address is its identity
			 * address when it distributed an IRK; record it so an
			 * RPA-using peer is still recognised after restart
			 * (finding 67).
			 */
			if (b->has_irk) {
				pd->has_identity = 1;
				memcpy(pd->identity_addr, b->addr, 6);
				pd->identity_addr_type = b->addr_type;
			}
			/*
			 * Populate last_seen and the resolved identity from the
			 * live known-device table (finding 67: previously the
			 * save path left these zero, wiping them every restart).
			 */
			kd = blued_devtable_find(&blued_devtable, b->addr,
			    b->addr_type);
			if (kd != NULL) {
				pd->last_seen = kd->last_seen;
				if ((kd->flags & BLUED_KNOWN_IDENTITY) != 0) {
					pd->has_identity = 1;
					memcpy(pd->identity_addr,
					    kd->identity_addr, 6);
					pd->identity_addr_type =
					    kd->identity_addr_type;
				}
				if (!pd->has_name && kd->name[0] != '\0') {
					pd->has_name = 1;
					strlcpy(pd->name, kd->name,
					    sizeof(pd->name));
				}
			}
			if (pd->last_seen == 0)
				pd->last_seen = (int64_t)time(NULL);
			/*
			 * Carry GAP Appearance forward from the loaded snapshot
			 * (the daemon keeps no live Appearance store), finding 67.
			 */
			snap = blued_persist_devcache_find(
			    blued_devcache_snapshot,
			    blued_devcache_snapshot_count, b->addr,
			    b->addr_type);
			if (snap != NULL && snap->has_appearance) {
				pd->has_appearance = 1;
				pd->appearance = snap->appearance;
			}

			if (b->has_db_hash && ngatt < BLUED_PERSIST_MAX_GATT_DEVICES) {
				struct blued_persist_gatt_device *pg =
				    &gatt[ngatt++];

				memset(pg, 0, sizeof(*pg));
				memcpy(pg->addr, b->addr, 6);
				pg->addr_type = b->addr_type;
				pg->has_db_hash = 1;
				memcpy(pg->db_hash, b->db_hash, 16);
			}
		}
		pthread_mutex_unlock(&blued_g.bond_db_lock);
	}

	if (blued_persist_devcache_save(blued_g.persist_dirfd, devs, ndev) != 0)
		rc = -1;
	if (blued_persist_gattcache_save(blued_g.persist_dirfd, gatt, ngatt) != 0)
		rc = -1;

	/*
	 * Persist the peripheral advertising configuration.  Record 0 is the
	 * legacy/primary set; the daemon's primary adv payload and scan
	 * response are captured (finding 141: these fields were reserved but
	 * always written as zeros), and every configured extended advertising
	 * set is persisted rather than only a single hardcoded handle-0 record
	 * (finding 139).
	 */
	{
		struct blued_persist_adv_set advset[BLUED_PERSIST_MAX_ADV_SETS];
		uint32_t nset = 0;
		struct blued_adapter *pa = NULL, *ai;

		LIST_FOREACH(ai, &blued_g.adapters, entries)
			if (ai->active) {
				pa = ai;
				break;
			}

		memset(advset, 0, sizeof(advset));
		adv = &advset[nset++];
		adv->handle = 0;
		adv->enabled = cfg->peripheral_mode ? 1 : 0;
		adv->own_addr_type = cfg->privacy ? 0x03 : 0x00;
		adv->adv_props = 0x0013;	/* conn+scan legacy ADV_IND */
		adv->interval_min = ADV_INTERVAL_100MS;
		adv->interval_max = ADV_INTERVAL_100MS;
		if (pa != NULL && pa->primary_adv_data_valid &&
		    pa->primary_adv_data_len <= sizeof(adv->adv_data)) {
			adv->adv_data_len = pa->primary_adv_data_len;
			memcpy(adv->adv_data, pa->primary_adv_data,
			    pa->primary_adv_data_len);
		}
		if (pa != NULL && pa->primary_scan_rsp_valid &&
		    pa->primary_scan_rsp_len <= sizeof(adv->scan_rsp)) {
			adv->scan_rsp_len = pa->primary_scan_rsp_len;
			memcpy(adv->scan_rsp, pa->primary_scan_rsp,
			    pa->primary_scan_rsp_len);
		}

		/* Persist each configured extended advertising set. */
		if (pa != NULL) {
			int si;

			for (si = 0; si < BLUED_EXT_ADV_SET_MAX &&
			    nset < BLUED_PERSIST_MAX_ADV_SETS; si++) {
				const struct blued_ext_adv_set *es =
				    &pa->ext_adv_sets[si];

				if (!es->used || !es->configured ||
				    es->handle == 0)
					continue;
				adv = &advset[nset++];
				adv->handle = es->handle;
				adv->enabled = es->enabled ? 1 : 0;
				adv->own_addr_type = es->own_addr_type;
				adv->adv_props = es->event_props;
				/* H-L5: interval is 24-bit; no longer truncated. */
				adv->interval_min = es->interval_min;
				adv->interval_max = es->interval_max;
			}
		}

		if (blued_persist_advconfig_save(blued_g.persist_dirfd,
		    advset, nset) != 0)
			rc = -1;
	}

	if (rc == 0)
		LOG_HOGP(1, "persist: flushed state (%u dev, %u gatt)", ndev,
		    ngatt);
	else
		warn("persist: one or more operational state files were not saved");
	return (rc);
}

int
main(int argc, char *argv[])
{
	struct blued_config *cfgp = &blued_cfg;
	struct blued_adapter *adp;
	struct hogp_device dev;
	const char *config_path;
	char managed_config_path[PATH_MAX];
	int ch, i, nfound, exit_status = 0;

	/* Alias for minimal diff with existing code */
#define cfg (*cfgp)

	blued_g.persist_dirfd = -1;

	/* 0. serviced integration: acquire declared authority by role and type. */
	if (getenv("SERVICE_BOOTSTRAP_FD") != NULL) {
		if (service_acquire(&blued_g.svc_ctx) == -1)
			err(1, "initialize serviced channel");
		if (service_authorize_capabilities(blued_g.svc_ctx) == -1)
			err(1, "activate serviced capabilities");
		if (service_capability_open(blued_g.svc_ctx, "storage:state",
		    "directory", &blued_g.persist_dirfd) == -1)
			err(1, "acquire persistent storage");
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
	if (config_path == NULL && getenv(SERVICE_UNIT_DIR_ENV) != NULL) {
		if (snprintf(managed_config_path, sizeof(managed_config_path),
		    "%s/Config/blued.conf", getenv(SERVICE_UNIT_DIR_ENV)) >=
		    (int)sizeof(managed_config_path))
			errx(1, "managed configuration path is too long");
		config_path = managed_config_path;
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
		hci_l2cap_set_own_address_type(cfg.privacy ? 0x03 : 0x00);

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
	pthread_mutex_init(&blued_g.reslist_lock, NULL);
	pthread_mutex_init(&blued_g.att_sec_lock, NULL);
	LIST_INIT(&blued_g.ctl_clients);
	LIST_INIT(&blued_g.ctl_acquires);
	blued_ctl_clients_lock_init(&blued_g.ctl_clients_lock);
	blued_g.kq = -1;
	blued_g.ctl_fd = -1;
	blued_g.bond_fd = -1;
	blued_g.bond_dirfd = -1;
	blued_g.bond_lockfd = -1;
	blued_g.vhid_ctl_fd = -1;
	blued_g.config_fd = -1;
	/* capprotect_fd reserved for future authorityd integration */

	/* Record main thread for conn_by_addr safety assertion */
	blued_g.main_thread = pthread_self();

	/*
	 * Restore persisted operational state and overlay it onto the config
	 * before adapters are initialised from it.  Opens the state dir fd
	 * (kept for the atomic saves at shutdown, sandbox-compatible).
	 */
	blued_persist_restore(&cfg);

	/* 7. Create kqueue */
	blued_g.kq = kqueue();
	if (blued_g.kq < 0)
		err(1, "kqueue");
	if (fcntl(blued_g.kq, F_SETFD, FD_CLOEXEC) < 0)
		err(1, "fcntl kqueue CLOEXEC");

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
				hci_fd_closed(adp->hci_fd);
				close(adp->hci_fd);
				LIST_REMOVE(adp, entries);
				free(adp);
				continue;
			}
		}
	}

	/* Assign stable adapter indices now the surviving set is known. */
	blued_index_adapters();

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
			bt_devfilter_evt_set(&flt, 0x05); /* Disconnection Complete */
			bt_devfilter_evt_set(&flt, 0x08); /* Encryption Change */
			bt_devfilter_evt_set(&flt, 0x30); /* Encryption Key Refresh */
			bt_devfilter_evt_set(&flt, 0x57); /* Auth Payload Timeout */
			bt_devfilter_evt_set(&flt, 0x59); /* Encryption Change v2 */
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

	/* Register atexit cleanup for both peripheral and central modes */
	atexit(atexit_cleanup);

	/*
	 * 16b. Peripheral mode: build GATT DB, open bond file,
	 * start advertising, register ATT listen socket with kqueue,
	 * and fall through to the event loop.
	 */
	blued_peripheral_name = cfg.peripheral_name;

	if (cfg.peripheral_mode) {
		uint8_t adv_data[31];
		int adv_len;
		int nbonded = 0;
		/*
		 * own_address_type for advertising:
		 * 0x00 = public (no privacy)
		 * 0x02 = RPA, fallback to public (privacy enabled)
		 * Core Spec Vol 4 Part E 7.8.53
		 */
		uint8_t own_addr_type = 0x00;

		/* Build the shared GATT database */
		peripheral_build_gattdb(&periph_gatt_db, periph_gatt_attrs,
		    periph_gatt_val_buf, sizeof(periph_gatt_val_buf), &cfg);

		/*
		 * Finding 137: mark the built-in/config base, then replay
		 * runtime-added local GATT services persisted from a previous
		 * run into the freshly built DB.
		 */
		ctl_gatt_set_base_count();
		ctl_gatt_load_persisted_services(blued_g.persist_dirfd);

		/* Open bond database -- heap-allocate so threads can safely
		 * reference blued_g.bond_db without depending on main()'s
		 * stack frame lifetime. */
		blued_g.bond_fd = blued_bond_open(cfg.bonddb);
		if (blued_g.bond_fd >= 0) {
			struct smp_bond_db *bdb;

			bdb = calloc(1, sizeof(*bdb));
			if (bdb == NULL)
				err(1, "bond_db alloc");
			bdb->lock = &blued_g.bond_db_lock;
			blued_g.bond_db = bdb;
			/*
			 * Enable atomic bond-DB writes when the bond file
			 * lives in the persist state directory (the default):
			 * reuse that already capability-scoped dir fd so a crash
			 * mid-save cannot corrupt the previous good bond file.
			 */
			if (blued_bond_set_atomic(bdb, cfg.bonddb) != 0)
				err(1, "open bond database directory");
			if (smp_bond_db_load(bdb, blued_g.bond_fd) != 0)
				err(1, "load bond database");
			/* Bridge into hogp_device for load_resolving_list */
			dev.bond_db = bdb;
			dev.bond_fd = blued_g.bond_fd;

			/*
			 * Use the bond DB's atomic, encrypted local IRK as the sole
			 * identity key for both SMP distribution and controller RPA
			 * generation.  A separate .irk file can diverge from the key
			 * already distributed to peers after a crash or partial write.
			 */
			if (cfg.privacy) {
				if (blued_local_irk_ensure() != 0)
					err(1, "load local privacy identity");
				own_addr_type = 0x03; /* RPA, host-RPA fallback */
			}

			{
				struct blued_adapter *pa;

				LIST_FOREACH(pa, &blued_g.adapters, entries) {
					struct hogp_device pdev = dev;

					if (!pa->active)
						continue;
					pdev.hci_fd = pa->hci_fd;
					pdev.adapter = pa->name;
					pdev.le_features = pa->le_features;
					memcpy(pdev.local_addr, &pa->addr, 6);
					if (load_resolving_list(&pdev,
					    cfg.rpa_timeout) != 0)
						err(1, "program resolving list");
					nbonded = MAX(nbonded,
					    load_filter_accept_list(pa->hci_fd,
					    blued_g.bond_db));
					/* Runtime accept-list entries (135). */
					blued_acceptlist_reprogram(pa->hci_fd);
				}
			}
		}
		if (cfg.privacy && !blued_has_local_irk)
			err(1, "privacy requires persistent bond storage");

		/* Build advertising data */
		{
			uint16_t uuids[] = { UUID_DIS_SERVICE,
			    UUID_CUSTOM_SERVICE };

			/*
			 * Reapply the exact advertising payload persisted from
			 * the previous run when available (finding 141: the
			 * persisted adv_data was previously never reapplied);
			 * otherwise build the default payload.
			 */
			if (blued_adv_restore_valid &&
			    blued_adv_restore.adv_data_len > 0 &&
			    blued_adv_restore.adv_data_len <=
			    sizeof(adv_data)) {
				adv_len = blued_adv_restore.adv_data_len;
				memcpy(adv_data, blued_adv_restore.adv_data,
				    blued_adv_restore.adv_data_len);
			} else {
				adv_len = ble_build_adv_data(adv_data,
				    sizeof(adv_data), blued_peripheral_name,
				    uuids, 2);
				if (adv_len < 0)
					err(1, "build advertising data");
			}
		}

		/*
		 * Build scan response with Complete Local Name.
		 * Ensures active scanners see the full device name.
		 */
		{
			uint8_t scan_rsp[31];
			int scan_rsp_len = 0;
			size_t namelen = strlen(blued_peripheral_name);
			bool name_truncated;

			/*
			 * Cap name to 29 bytes: advertising uses legacy
			 * PDU format (0x0013 includes the legacy bit)
			 * even via extended HCI commands, so scan
			 * response is limited to 31 bytes (1 len + 1
			 * type + 29 name).
			 */
			name_truncated = (namelen > 29);
			if (namelen > 29)
				namelen = 29;
			scan_rsp[scan_rsp_len++] = (uint8_t)(1 + namelen);
			/* CSS Part A §1.2: use Shortened if truncated */
			scan_rsp[scan_rsp_len++] = name_truncated ? 0x08 : 0x09;
			memcpy(scan_rsp + scan_rsp_len,
			    blued_peripheral_name, namelen);
			scan_rsp_len += (int)namelen;

			/*
			 * Clear stale advertising sets from a previous
			 * daemon instance that crashed without cleanup.
			 * Best-effort -- ignored if controller doesn't
			 * support extended advertising.
			 */
			{
			struct blued_adapter *aa;

			LIST_FOREACH(aa, &blued_g.adapters, entries) {
			uint8_t set_rpa[6];
			bool have_set_rpa = false;

			if (!aa->active)
				continue;
			hci_le_clear_adv_sets(aa->hci_fd);
			if (cfg.privacy) {
				if (smp_generate_rpa(blued_local_irk, set_rpa) != 0)
					err(1, "generate advertising RPA");
				have_set_rpa = true;
			}

			/*
			 * Advertising filter policy (Core Spec Vol 4 Part E
			 * §7.8.5 / §7.8.53): if we have bonded devices,
			 * restrict connections to the filter accept list.
			 * Value 0x02 = "process connection requests only from
			 * devices in the Filter Accept List" (scan requests
			 * still processed from all).  Note 0x01 restricts only
			 * SCAN requests, NOT connections, so it would not
			 * enforce the bonded-only policy.  With no bonds use
			 * 0x00 to allow any device to connect for initial
			 * pairing.
			 */
			{
			uint8_t filt = (nbonded > 0) ? 0x02 : 0x00;
			/*
			 * PC8: re-apply the persisted advertising parameters
			 * when a valid advertising config was restored, so a
			 * peripheral resumes with the same interval/props after
			 * a restart.  Fall back to the connectable-scannable
			 * 100ms default otherwise.
			 */
			uint16_t adv_props = 0x0013;	/* conn+scan legacy */
			uint32_t adv_imin = ADV_INTERVAL_100MS;	/* H-L5: 24-bit */
			uint32_t adv_imax = ADV_INTERVAL_100MS;

			if (blued_adv_restore_valid &&
			    blued_adv_restore.enabled) {
				if (blued_adv_restore.adv_props != 0)
					adv_props = blued_adv_restore.adv_props;
				if (blued_adv_restore.interval_min != 0)
					adv_imin =
					    blued_adv_restore.interval_min;
				if (blued_adv_restore.interval_max != 0)
					adv_imax =
					    blued_adv_restore.interval_max;
			}

			/*
			 * Start advertising -- try extended (BT 5.0+) first,
			 * fall back to legacy.
			 */
			if (hci_le_set_ext_adv_params_phy(aa->hci_fd, 0x00,
			    adv_props,
			    adv_imin, adv_imax,
			    own_addr_type, filt, 0x01, 0x01) == 0 &&
			    (!have_set_rpa || hci_le_set_adv_set_random_address(
			    aa->hci_fd, 0x00, set_rpa) == 0) &&
			    hci_le_set_ext_adv_data(aa->hci_fd, 0x00,
			    adv_data, (uint8_t)adv_len) == 0 &&
			    hci_le_set_ext_scan_response_data(aa->hci_fd,
			    0x00, scan_rsp, (uint8_t)scan_rsp_len) == 0 &&
			    hci_le_set_ext_adv_enable(aa->hci_fd, 1,
			    0x00) == 0) {
				LOG_HOGP(1, "using extended advertising "
				    "(filter=%d)", filt);

				/*
				 * If the controller supports Coded PHY,
				 * add a second advertising set on Coded
				 * PHY for long-range discovery.
				 * Non-connectable (connectable uses set 0).
				 */
				aa->adv_configured = true;
				aa->adv_use_extended = true;
				if (aa->le_features &
				    LE_FEAT_CODED_PHY) {
					if (hci_le_set_ext_adv_params_phy(
					    aa->hci_fd, 0x01,
					    0x0000 /* non-conn, non-scan */,
					    ADV_INTERVAL_100MS * 4,
					    ADV_INTERVAL_100MS * 4,
					    own_addr_type, filt,
					    0x03 /* Coded */, 0x03) == 0 &&
					    (!have_set_rpa ||
					    hci_le_set_adv_set_random_address(
					    aa->hci_fd, 0x01, set_rpa) == 0) &&
					    hci_le_set_ext_adv_data(
					    aa->hci_fd, 0x01,
					    adv_data, (uint8_t)adv_len) == 0 &&
					    hci_le_set_ext_adv_enable(
					    aa->hci_fd, 1, 0x01) == 0)
					{
						(void)blued_ext_adv_set_track(aa, 0x01,
						    0x0000, ADV_INTERVAL_100MS * 4,
						    ADV_INTERVAL_100MS * 4, own_addr_type,
						    filt, 0x03, 0x03, 0x07, 0x7f, 0,
						    NULL);
						blued_ext_adv_set_enabled(aa, 0x01, true);
						LOG_HOGP(1, "Coded PHY "
						    "advertising on set 1");
					}
				}
			} else {
				LOG_HOGP(1, "ext adv not supported, "
				    "using legacy");
				if (hci_le_set_advertising_params(aa->hci_fd,
				    adv_imin, adv_imax,
				    0x00, own_addr_type, filt) < 0)
					err(1, "set advertising parameters");
				if (hci_le_set_advertising_data(aa->hci_fd,
				    adv_data, (uint8_t)adv_len) < 0)
					err(1, "set advertising data");
				if (hci_le_set_scan_response_data(aa->hci_fd,
				    scan_rsp, (uint8_t)scan_rsp_len) < 0)
					warn("set scan response data");
				if (hci_le_set_advertise_enable(aa->hci_fd,
				    true) < 0)
					err(1, "enable advertising");
				aa->adv_configured = true;
				aa->adv_use_extended = false;
			}
			aa->adv_enabled = true;
			blued_primary_adv_cache(aa, false, adv_data,
			    (uint8_t)adv_len);
			blued_primary_adv_cache(aa, true, scan_rsp,
			    (uint8_t)scan_rsp_len);
			if (aa->adv_config == NULL)
				aa->adv_config = calloc(1, sizeof(*aa->adv_config));
			if (aa->adv_config != NULL) {
				aa->adv_config->mode = aa->adv_use_extended ?
				    HCI_ADV_MODE_EXTENDED : HCI_ADV_MODE_LEGACY;
				aa->adv_config->kind = HCI_ADV_CONN_UND;
				aa->adv_config->interval_min = adv_imin;
				aa->adv_config->interval_max = adv_imax;
				aa->adv_config->channel_map = 0x07;
				aa->adv_config->tx_power = 0x7f;
				aa->adv_config->own_addr_type = own_addr_type;
				aa->adv_config->filter_policy = filt;
				aa->adv_config->primary_phy = 0x01;
				aa->adv_config->secondary_phy = 0x01;
				aa->adv_config->used_extended = aa->adv_use_extended;
			}
			explicit_bzero(set_rpa, sizeof(set_rpa));
			}
			}
			}
		}

		LOG_HOGP(1, "advertising as \"%s\"", blued_peripheral_name);

		/* Create exact-address ATT/EATT listeners for every adapter. */
		blued_g.periph_active = true;
		{
			struct blued_adapter *pa;
			int nlisteners = 0;

			LIST_FOREACH(pa, &blued_g.adapters, entries) {
				struct kevent kev;
				int efd;

				if (!pa->active)
					continue;
				pa->periph_listen_fd = peripheral_att_listen(pa);
				if (pa->periph_listen_fd < 0) {
					warnx("ATT listener unavailable on %s", pa->name);
					continue;
				}
				EV_SET(&kev, pa->periph_listen_fd, EVFILT_READ,
				    EV_ADD | EV_ENABLE, 0, 0, pa);
				if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0)
					err(1, "kevent periph listen");
				nlisteners++;

				efd = blued_eatt_listen(pa);
				if (efd < 0)
					continue;
				pa->eatt_listen_fd = efd;
				EV_SET(&kev, efd, EVFILT_READ, EV_ADD | EV_ENABLE,
				    0, 0, pa);
				if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0) {
					warn("kevent eatt listen");
					close(efd);
					pa->eatt_listen_fd = -1;
				}
			}
			if (nlisteners == 0)
				errx(1, "cannot bind any ATT listener");
		}

		/*
		 * EATT (Enhanced ATT) server bearer listener.
		 * Core Spec Vol 3 Part G §5.3 / Part F §5.3.2: a peer
		 * establishes Enhanced ATT bearers as L2CAP CoC channels on
		 * the ATT PSM 0x0027.  Bind and listen so incoming EATT
		 * bearers are accepted and multiplexed alongside the fixed
		 * ATT channel (CID 0x0004).  Best-effort: EATT remains
		 * optional, so a bind failure only disables enhanced bearers.
		 */
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

		/*
		 * Pre-open config file for SIGHUP reload inside sandbox.
		 * Capsicum prevents open-by-path; keep an fd with
		 * CAP_READ | CAP_SEEK so blued_config_load_fd() works.
		 */
		if (blued_config_path != NULL) {
			blued_g.config_fd = open(blued_config_path,
			    O_RDONLY | O_CLOEXEC);
			if (blued_g.config_fd < 0)
				warn("pre-open config for SIGHUP");
		}

		/*
		 * Apply fd inheritance hardening before spawning threads.
		 */
		blued_harden_fd_inheritance();

		/*
		 * Enter Capsicum sandbox.  All required fds are open:
		 * kqueue, ATT listen socket, HCI adapter, control socket,
		 * bond database, config file, and self-pipe.
		 *
		 * Peripheral mode only accepts inbound ATT connections, so it
		 * does not need the central mode's descriptor broker.
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
			struct blued_adapter *ca;
			struct blued_conn *sc, *sc_tmp;
			bool has_connecting;
			int wait_ms;

			/*
			 * Cancel in-progress connection attempts and close
			 * fds under setup threads to unblock them.
			 */
			LIST_FOREACH(ca, &blued_g.adapters, entries) {
				if (ca->active)
					hci_le_create_connection_cancel(ca->hci_fd);
			}
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
			while (atomic_load(&blued_g.setup_workers) != 0)
				usleep(10000);

			/*
			 * Send HCI Disconnect to all active connections
			 * so the remote side gets a clean termination
			 * (reason 0x13 = Remote User Terminated).
			 */
			LIST_FOREACH(sc, &blued_g.conns, entries) {
				if (sc->state == BLUED_CONN_ACTIVE &&
				    sc->con_handle_valid &&
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

		/* Flush bond database to disk (detached setup threads may
		 * still be running, so serialize under the bond-DB mutex) */
		if (blued_g.bond_db != NULL) {
			pthread_mutex_lock(&blued_g.bond_db_lock);
			if (smp_bond_db_save(blued_g.bond_db) != 0)
				exit_status = 1;
			pthread_mutex_unlock(&blued_g.bond_db_lock);
		}

		/* Persist operational state (settings, caches, adv config) */
		if (blued_persist_flush(&cfg) != 0)
			exit_status = 1;

		{
			struct blued_adapter *pa;

			LIST_FOREACH(pa, &blued_g.adapters, entries) {
				if (pa->adv_use_extended) {
					if (pa->le_features & LE_FEAT_CODED_PHY) {
						hci_le_set_ext_adv_enable(pa->hci_fd,
						    0, 0x01);
						hci_le_remove_adv_set(pa->hci_fd, 0x01);
					}
					hci_le_set_ext_adv_enable(pa->hci_fd, 0, 0x00);
					hci_le_remove_adv_set(pa->hci_fd, 0x00);
				} else if (pa->adv_configured) {
					hci_le_set_advertise_enable(pa->hci_fd, false);
				}
				if (pa->periph_listen_fd >= 0)
					close(pa->periph_listen_fd);
				if (pa->eatt_listen_fd >= 0)
					close(pa->eatt_listen_fd);
				pa->periph_listen_fd = -1;
				pa->eatt_listen_fd = -1;
			}
		}
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
		if (blued_g.bond_lockfd >= 0) {
			close(blued_g.bond_lockfd);
			blued_g.bond_lockfd = -1;
		}
		if (blued_g.bond_dirfd >= 0 &&
		    blued_g.bond_dirfd != blued_g.persist_dirfd)
			close(blued_g.bond_dirfd);
		blued_g.bond_dirfd = -1;
		if (blued_g.persist_dirfd >= 0) {
			close(blued_g.persist_dirfd);
			blued_g.persist_dirfd = -1;
		}

		/* Close adapter HCI fds */
		{
			struct blued_adapter *sa, *sa_tmp;

			LIST_FOREACH_SAFE(sa, &blued_g.adapters, entries,
			    sa_tmp) {
				hci_fd_closed(sa->hci_fd);
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
		return (exit_status);
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

		/*
		 * PC6: append known devices flagged auto-connect from the
		 * persisted device cache so the daemon reconnects them at
		 * startup without an explicit target.  They flow through the
		 * same connection allocation and setup-thread spawn below;
		 * reconnect (when enabled) then drives the bounded
		 * exponential backoff so a peer that stays down cannot busy-spin
		 * or monopolize setup workers.
		 */
		if (cfg.auto_connect) {
			struct blued_autoconn cand[BLUED_DEVTABLE_MAX];
			int nc, k, m;

			nc = blued_devtable_autoconnect(&blued_devtable, cand,
			    BLUED_DEVTABLE_MAX);
			for (k = 0; k < nc && ndevs < 16; k++) {
				bool dup = false;

				for (m = 0; m < ndevs; m++)
					if (devs[m].addr_type ==
					    cand[k].addr_type &&
					    memcmp(devs[m].addr, cand[k].addr,
					    6) == 0) {
						dup = true;
						break;
					}
				if (dup)
					continue;
				memcpy(devs[ndevs].addr, cand[k].addr, 6);
				devs[ndevs].addr_type = cand[k].addr_type;
				ndevs++;
				LOG_HOGP(1, "auto-connect: queued known "
				    "device at startup");
			}
		}

		if (ndevs == 0)
			usage();

	/* 12. Open bond database */
	blued_g.bond_fd = blued_bond_open(cfg.bonddb);
	if (blued_g.bond_fd < 0)
		err(1, "open %s", cfg.bonddb);
	dev.bond_fd = blued_g.bond_fd;
	blued_g.bond_db = calloc(1, sizeof(*blued_g.bond_db));
	if (blued_g.bond_db == NULL)
		err(1, "bond_db alloc");
	blued_g.bond_db->lock = &blued_g.bond_db_lock;
	if (blued_bond_set_atomic(blued_g.bond_db, cfg.bonddb) != 0)
		err(1, "open bond database directory");
	if (smp_bond_db_load(blued_g.bond_db, dev.bond_fd) != 0)
		err(1, "load bond database");
	dev.bond_db = blued_g.bond_db;
	if (cfg.privacy && blued_local_irk_ensure() != 0)
		err(1, "load local privacy identity");

	/* 13. Load each controller's independent resolving list. */
	{
		struct blued_adapter *ra;
		LIST_FOREACH(ra, &blued_g.adapters, entries) {
			struct hogp_device rdev = dev;
			if (!ra->active)
				continue;
			rdev.hci_fd = ra->hci_fd;
			if (load_resolving_list(&rdev, cfg.rpa_timeout) != 0)
				err(1, "program resolving list");
			/* Runtime accept-list entries (finding 135). */
			blued_acceptlist_reprogram(ra->hci_fd);
		}
	}

	/*
	 * /dev/vhid is provided by the vhid module.  Under serviced, self-serve
	 * the module via sysextd (system.SystemExtension) before opening the
	 * control node: sysextd owns kernel-module loading, so blued declares no
	 * manifest kmod requirement and neither PID 1 nor serviced loads modules
	 * on its behalf.  Standalone (no serviced), the module is expected to be
	 * present already.
	 */
	if (blued_serviced &&
	    service_ensure_extension(blued_g.svc_ctx, "vhid") == -1)
		syslog(LOG_WARNING, "vhid module not loaded at startup "
		    "(ensured on demand): %m");

	/*
	 * Open the vhid control node.  Under serviced the filesystem daemon
	 * (tzfsd) opens it on our behalf via service_open_isolated(3) and hands
	 * back a read/write/ioctl descriptor — its per-label policy authorizes
	 * blued for /dev/vhid*, nothing is declared in the manifest, and a
	 * sandboxed blued never opens the device by path.  Standalone (no
	 * serviced), open it directly.
	 */
	if (blued_serviced) {
		/*
		 * Ask the filesystem daemon for the vhid control node — but do
		 * NOT make it a hard startup dependency: if it is not available
		 * yet, warn and carry on with vhid_ctl_fd == -1.  It is acquired
		 * lazily (hogp_setup_vhid) when the first HID device actually
		 * needs it, so blued never dies because tzfsd is transiently down.
		 */
		if (service_open_isolated(blued_g.svc_ctx, "/dev/vhid",
		    SERVICE_OPEN_READ | SERVICE_OPEN_WRITE | SERVICE_OPEN_IOCTL,
		    0, &blued_g.vhid_ctl_fd) == -1) {
			syslog(LOG_WARNING, "vhid control not available at "
			    "startup (acquired on demand): %m");
			blued_g.vhid_ctl_fd = -1;
		}
	} else {
		blued_g.vhid_ctl_fd = open("/dev/vhid",
		    O_RDWR | O_CLOEXEC | O_CLOFORK);
		if (blued_g.vhid_ctl_fd < 0)
			err(1, "open /dev/vhid");
	}
	if (blued_socket_broker_start() != 0)
		err(1, "start L2CAP socket broker");

	/* 14. Init control socket */
	if (blued_ctl_init(cfg.ctlsock) < 0)
		warn("control socket init failed (non-fatal)");

	/*
	 * 15. serviced: create the provider, expose the name, and watch the
	 * supervisor fd for lifecycle.  Readiness is reported below, after
	 * cap_enter(): the provider API requires the explicit
	 * capability-mode transition before service_provider_ready().
	 */
	if (blued_serviced) {
		int sup_fd;

		/* The daemon chooses its external shield after initialization.
		 * serviced retains stop authority through its procdesc; pdkill
		 * deliberately bypasses ambient signal checks. */
		if (service_provider_create(&blued_g.svc_provider) == -1)
			err(1, "create serviced provider");
		if (service_provider_protect(blued_g.svc_provider,
		    SERVICE_PROTECT_EXTERNAL) == -1)
			err(1, "protect serviced process");
		if (service_provider_expose(blued_g.svc_provider,
		    "system.Bluetooth", &blued_g.svc_listener) == -1)
			err(1, "expose serviced name");
		/*
		 * The supervisor fd (successor to the old service_channel_fd)
		 * becomes readable only when the serviced connection is lost;
		 * the real stop path is SIGTERM/pdkill.  Nothing connects to
		 * the exposed name, so the listener is left dormant.
		 */
		sup_fd = service_supervisor_fd(blued_g.svc_ctx);
		if (sup_fd >= 0) {
			struct kevent kev;

			EV_SET(&kev, sup_fd, EVFILT_READ,
			    EV_ADD | EV_ENABLE, 0, 0, NULL);
			if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0)
				warn("kevent service_supervisor_fd");
		}
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

	blued_reconnect_max_delay = cfg.reconnect_max_delay;

	/*
	 * Allocate devices and connections before entering the sandbox.  Runtime
	 * L2CAP descriptors come from the already-running descriptor broker.
	 */
	for (i = 0; i < ndevs; i++) {
		struct hogp_device *hdev;
		struct blued_conn *conn;

		hdev = calloc(1, sizeof(*hdev));
		if (hdev == NULL)
			err(1, "hogp_device alloc");

		hdev->att.fd = -1;
		hdev->smp.fd = -1;
		hdev->bond_fd = blued_g.bond_fd;
		hdev->bond_db = blued_g.bond_db;
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

		conn = blued_conn_alloc();
		if (conn == NULL)
			err(1, "blued_conn_alloc");
		conn->hogp = hdev;
		memcpy(&conn->dst, devs[i].addr, sizeof(conn->dst));
		conn->addr_type = devs[i].addr_type;
		conn->adapter = adp;
		conn->role = BLUED_ROLE_CENTRAL;
		conn->reconnect = cfg.reconnect;
		conn->local_own_addr_type = adp->privacy ? 0x03 : 0x00;
		blued_conn_reset_local(conn);
		blued_conn_set_state(conn, BLUED_CONN_CONNECTING);
	}

	/*
	 * Pre-open config file for SIGHUP reload inside sandbox.
	 */
	if (blued_config_path != NULL) {
		blued_g.config_fd = open(blued_config_path,
		    O_RDONLY | O_CLOEXEC);
		if (blued_g.config_fd < 0)
			warn("pre-open config for SIGHUP");
	}

	/*
	 * Apply fd inheritance hardening before spawning threads.
	 */
	blued_harden_fd_inheritance();

	/*
	 * Coalition note: blued's central mode uses threads (not fork)
	 * for multi-device connections.  Each target device gets a
	 * detached pthread running blued_conn_setup_central().  Since
	 * threads share the process address space and cannot be
	 * individually enlisted in a coalition (coalitions operate on
	 * process descriptors, not threads), coalition-based group
	 * teardown is not applicable here.  The daemon tears down all
	 * connections via the blued_shutting_down atomic flag and
	 * per-connection fd closure instead.
	 */

	/*
	 * Enter Capsicum sandbox BEFORE spawning setup threads.
	 * All required fds are open: kqueue, HCI adapter, control
	 * socket, bond database, config file, vhid control,
	 * self-pipe, and the capability-limited socket-broker channel.
	 * Setup threads request one narrowly typed L2CAP descriptor from the
	 * broker and use cap_connect() inside the sandbox.
	 */
	blued_capsicum_limit_fds();
	blued_audit(AUE_BLUED_START, 0,
	    "daemon entering sandbox (central)");
	if (cap_enter() < 0)
		err(1, "cap_enter (central)");
	LOG_HOGP(1, "entered Capsicum sandbox (central)");

	/*
	 * Report serviced readiness now that we are in capability mode
	 * (service_provider_ready() requires it).  enter_capability_mode
	 * is idempotent with the cap_enter() above — it observes we are
	 * already sandboxed and only records the transition.
	 */
	if (blued_serviced) {
		if (service_provider_enter_capability_mode(
		    blued_g.svc_provider) == -1)
			err(1, "enter serviced capability mode");
		if (service_provider_ready(blued_g.svc_provider) == -1)
			err(1, "report serviced readiness");
	}

	/* Now spawn setup threads inside the sandbox */
	{
		struct blued_conn *sc;

		LIST_FOREACH(sc, &blued_g.conns, entries) {
			pthread_t tid;
			pthread_attr_t pattr;

			if (sc->role != BLUED_ROLE_CENTRAL ||
			    sc->hogp == NULL)
				continue;

			pthread_attr_init(&pattr);
			pthread_attr_setdetachstate(&pattr,
			    PTHREAD_CREATE_DETACHED);
			/* Reference held by the setup thread for its lifetime. */
			blued_conn_ref(sc);
			blued_setup_worker_start(sc);
			if (pthread_create(&tid, &pattr,
			    blued_conn_setup_central, sc) != 0) {
				warn("central setup thread");
				blued_setup_worker_finish(sc);
				blued_conn_unref(sc);
				blued_conn_set_state(sc,
				    BLUED_CONN_IDLE);
			}
			pthread_attr_destroy(&pattr);
		}
	}

	LOG_HOGP(1, "central mode, entering event loop");
	running = 1;
	blued_event_loop();

	/*
	 * Shutdown: signal threads to exit, then wait briefly.
	 */
	atomic_store(&blued_shutting_down, true);
	{
		struct blued_adapter *ca;
		struct blued_conn *sc, *sc_tmp;
		bool has_connecting;
		int wait_ms;

		LIST_FOREACH(ca, &blued_g.adapters, entries) {
			if (ca->active)
				hci_le_create_connection_cancel(ca->hci_fd);
		}
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
		while (atomic_load(&blued_g.setup_workers) != 0)
			usleep(10000);

		/*
		 * Finding 93: quiesce the GATT worker pool BEFORE freeing any
		 * hogp/att below.  The setup_workers wait above covers only the
		 * connection setup threads, not the GATT workers, which may be
		 * mid-job on conn->att == &hogp->att.  Joining them here closes
		 * the use-after-free window when SIGTERM lands during an
		 * in-flight client GATT operation.
		 */
		blued_ctl_gatt_workers_stop();

		/*
		 * Send HCI Disconnect to all active connections
		 * so the remote side gets a clean termination
		 * (reason 0x13 = Remote User Terminated).
		 */
		LIST_FOREACH(sc, &blued_g.conns, entries) {
			if (sc->state == BLUED_CONN_ACTIVE &&
			    sc->con_handle_valid &&
			    sc->adapter != NULL) {
				hci_disconnect(sc->adapter->hci_fd,
				    sc->con_handle, 0x13);
			}
		}
		/* Brief delay for disconnects to be processed */
		usleep(100000);

		LIST_FOREACH_SAFE(sc, &blued_g.conns, entries, sc_tmp) {
			if (sc->hogp != NULL) {
				/*
				 * Flush bond database to disk before
				 * freeing each device, so any bonds
				 * established during this session are
				 * persisted.  Serialize under the bond-DB
				 * mutex: all saves share blued_g.bond_fd and
				 * a lingering setup thread may save too.
				 */
				pthread_mutex_lock(&blued_g.bond_db_lock);
				if (smp_bond_db_save(blued_g.bond_db) != 0)
					warn("saving bond database");
				pthread_mutex_unlock(&blued_g.bond_db_lock);
				/* Single central teardown (unregister + free). */
				blued_conn_central_teardown(sc);
			}
			blued_conn_free(sc);
		}
	}

	} /* close devs[] scope */

	/* Persist operational state before tearing down. */
	if (blued_persist_flush(&cfg) != 0)
		exit_status = 1;

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
	if (blued_g.bond_lockfd >= 0) {
		close(blued_g.bond_lockfd);
		blued_g.bond_lockfd = -1;
	}
	if (blued_g.bond_dirfd >= 0 &&
	    blued_g.bond_dirfd != blued_g.persist_dirfd)
		close(blued_g.bond_dirfd);
	blued_g.bond_dirfd = -1;
	if (blued_g.persist_dirfd >= 0) {
		close(blued_g.persist_dirfd);
		blued_g.persist_dirfd = -1;
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
		if (blued_rpa_timer != 0) {
			struct kevent kev;
			EV_SET(&kev, blued_rpa_timer, EVFILT_TIMER, EV_DELETE, 0, 0,
			    BLUED_KQ_RPA_TIMER);
			(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
			blued_rpa_timer = 0;
		}
	if (blued_g.kq >= 0 && blued_rpa_retry_timer != 0) {
		struct kevent kev;

		EV_SET(&kev, blued_rpa_retry_timer, EVFILT_TIMER, EV_DELETE,
		    0, 0, BLUED_KQ_RPA_RETRY);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
		blued_rpa_retry_timer = 0;
	}
	if (blued_g.kq >= 0)
		close(blued_g.kq);
	blued_socket_broker_stop();

	/* Close all adapter fds */
	{
		struct blued_adapter *adp_tmp;
		while ((adp_tmp = LIST_FIRST(&blued_g.adapters)) != NULL) {
			blued_periph_readvertise_cancel(adp_tmp);
			LIST_REMOVE(adp_tmp, entries);
			if (adp_tmp->hci_fd >= 0) {
				hci_fd_closed(adp_tmp->hci_fd);
				close(adp_tmp->hci_fd);
			}
			free(adp_tmp->adv_config);
			free(adp_tmp);
		}
	}

	if (blued_pfh != NULL) {
		pidfile_remove(blued_pfh);
		blued_pfh = NULL;
	}

	hci_log_close();

#undef cfg
	return (exit_status);
}
