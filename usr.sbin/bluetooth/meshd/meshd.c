/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * meshd(8) main: the thin glue that binds the node core (meshd_node.c), the
 * configuration parser (meshd_config.c) and the control surface (meshd_ctl.c)
 * to the outside world.  It loads the config, brings the node up, and serves a
 * line-oriented control protocol on a UNIX-domain stream socket.
 *
 * The radio bearer is a privileged client of blued: meshd installs a struct
 * meshd_bearer whose sink is meshd_blued_tx() (outbound mesh adv PDUs become
 * MESH_ADV_SEND commands) and adds blued's control fd to the poll set, where
 * inbound EVENT MESH_ADV push events are pumped into the RX seams.  meshd never
 * opens an HCI socket itself; blued owns the radio.  If blued is absent
 * the node keeps running on libblemesh's mesh_sim(3) engine and the tick loop
 * reconnects with backoff.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "meshd.h"
#include "meshd_bearer_blued.h"
#include "meshd_persist.h"
#include "meshd_probes.h"

#define	MESHD_DEFAULT_CONF	"/etc/bluetooth/meshd.conf"
#define	MESHD_DEFAULT_SOCK	"/var/run/meshd.sock"
#define	MESHD_DEFAULT_STATE	"/var/db/meshd.state"
#define	MESHD_DEFAULT_MGR	"/var/db/meshd.mgr"
#define	MESHD_CTL_ARGV_MAX	16
#define	MESHD_CTL_LINE_MAX	256
/* MESHD_CTL_REPLY_MAX now lives in meshd.h (shared with meshd_ctl.c). */

/* Clock tick cadence: the interval at which the state machines are advanced. */
#define	MESHD_TICK_MS		10

static volatile sig_atomic_t meshd_quit;
static int meshd_listen_token;

/*
 * Bearer events carry the connection generation in udata.  The low-bit tag
 * keeps them distinct from the naturally aligned app-client and listener
 * pointers.  In particular, a stale event returned for a closed connection
 * cannot be mistaken for the new connection when the kernel reuses its fd.
 */
#define	MESHD_BLUED_UDATA_TAG	((uintptr_t)1)

static void *
meshd_blued_udata(uint64_t generation)
{

	return ((void *)((((uintptr_t)generation) << 1) |
	    MESHD_BLUED_UDATA_TAG));
}

static uint64_t
meshd_blued_udata_generation(const void *udata)
{

	return ((uint64_t)((uintptr_t)udata >> 1));
}

static int
meshd_blued_event_current(const struct meshd_blued *bc,
    const struct kevent *ev)
{

	if (bc == NULL || ev == NULL ||
	    ((uintptr_t)ev->udata & MESHD_BLUED_UDATA_TAG) == 0)
		return (0);
	return (meshd_blued_udata_generation(ev->udata) ==
	    meshd_blued_generation(bc) &&
	    ev->ident == (uintptr_t)meshd_blued_fd(bc));
}

static int
meshd_blued_registration_changed(const struct meshd_blued *bc,
    int registered_fd, uint64_t registered_generation)
{

	return (registered_fd != meshd_blued_fd(bc) ||
	    registered_generation != meshd_blued_generation(bc));
}

/* Monotonic wall clock in milliseconds for all runtime state machines. */
static uint64_t
meshd_now(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return (0);
	return ((uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static void
meshd_on_signal(int sig __unused)
{

	meshd_quit = 1;
}

static void
usage(void)
{

	fprintf(stderr,
	    "usage: meshd [-d] [-f config] [-s socket] [-S state] "
	    "[-M mgr-state] [-B blued-socket]\n");
	exit(1);
}

/*
 * Load the manager database (network keys, roster, DevKeys, allocator) from the
 * store, if present, and mark the node's manager active.  A fresh daemon (no
 * store) leaves nd->mgr NULL until create-network mints one.  A corrupt store is
 * a hard error: refusing to boot avoids a duplicate-address split-brain.
 */
static void
meshd_mgr_restore(struct meshd_node *nd, const char *path)
{
	struct mesh_mgr *mgr;
	int r;

	if (nd->mgr_active && nd->mgr != NULL) {
		if (meshd_persist_mgr_save(path, nd->mgr) != 0)
			err(1, "cannot refresh manager mirror %s", path);
		return;
	}

	mgr = calloc(1, sizeof(*mgr));
	if (mgr == NULL)
		err(1, "cannot allocate manager");
	r = meshd_persist_mgr_load(path, mgr);
	if (r == 0) {
		if (timingsafe_bcmp(nd->local_devkey, mgr->self_devkey,
		    sizeof(nd->local_devkey)) != 0) {
			free(mgr);
			errx(1, "manager and node DeviceKeys disagree");
		}
		nd->mgr = mgr;
		nd->mgr_active = 1;
	} else if (r == 1) {
		free(mgr);			/* fresh: no network yet */
	} else {
		free(mgr);
		errx(1, "manager state %s is corrupt", path);
	}
}

/* Persist the manager database when a network is active (best-effort). */
static int
meshd_mgr_persist(const struct meshd_node *nd, const char *path)
{

	if (nd->mgr_active && nd->mgr != NULL)
		return (meshd_persist_mgr_save(path, nd->mgr));
	return (0);
}

static int
meshd_uid_authorized(uid_t peer, uid_t owner)
{

	return (peer == 0 || peer == owner);
}

static int
meshd_peer_authorized(int fd)
{
	uid_t euid;
	gid_t egid;

	if (getpeereid(fd, &euid, &egid) != 0)
		return (0);
	(void)egid;
	return (meshd_uid_authorized(euid, geteuid()));
}

static int
meshd_state_lock(const char *path)
{
	char lock[PATH_MAX];
	struct stat sb;
	int fd;

	if ((size_t)snprintf(lock, sizeof(lock), "%s.lock", path) >= sizeof(lock))
		return (-1);
	fd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0)
		return (-1);
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) ||
	    sb.st_uid != geteuid() || fchmod(fd, 0600) != 0) {
		(void)close(fd);
		errno = EPERM;
		return (-1);
	}
	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		(void)close(fd);
		return (-1);
	}
	return (fd);
}

/* State, manager and socket names must live in a directory an unprivileged
 * process cannot rename entries within.  The lock file alone is insufficient
 * in a writable directory: an attacker can unlink it while flock(2) remains
 * held and start a second writer on a replacement inode. */
static int
meshd_parent_secure(const char *path)
{
	char dir[PATH_MAX];
	const char *slash;
	struct stat sb;
	size_t len;
	int fd;

	if (path == NULL || path[0] == '\0') {
		errno = EINVAL;
		return (-1);
	}
	slash = strrchr(path, '/');
	if (slash == NULL) {
		strlcpy(dir, ".", sizeof(dir));
	} else {
		len = slash == path ? 1 : (size_t)(slash - path);
		if (len >= sizeof(dir)) {
			errno = ENAMETOOLONG;
			return (-1);
		}
		memcpy(dir, path, len);
		dir[len] = '\0';
	}
	fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return (-1);
	if (fstat(fd, &sb) != 0 || !S_ISDIR(sb.st_mode) ||
	    sb.st_uid != geteuid() || (sb.st_mode & 022) != 0) {
		(void)close(fd);
		errno = EPERM;
		return (-1);
	}
	return (close(fd));
}

static int
meshd_unlink_stale_socket(const char *path)
{
	struct sockaddr_un sun;
	struct stat before, after;
	int fd, saved;

	if (lstat(path, &before) != 0)
		return (errno == ENOENT ? 0 : -1);
	if (!S_ISSOCK(before.st_mode) || before.st_uid != geteuid()) {
		errno = EPERM;
		return (-1);
	}
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return (-1);
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == 0) {
		(void)close(fd);
		errno = EADDRINUSE;
		return (-1);
	}
	saved = errno;
	(void)close(fd);
	if (saved == ENOENT)
		return (0);
	if (saved != ECONNREFUSED) {
		errno = EADDRINUSE;
		return (-1);
	}

	/* Do not unlink a pathname that was replaced while it was probed. */
	if (lstat(path, &after) != 0)
		return (errno == ENOENT ? 0 : -1);
	if (before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
	    !S_ISSOCK(after.st_mode) || after.st_uid != geteuid()) {
		errno = EAGAIN;
		return (-1);
	}
	return (unlink(path));
}

static int
meshd_set_nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return (-1);
	return (fcntl(fd, F_SETFL, flags | O_NONBLOCK));
}

static int
meshd_kevent_ctl(int kq, uintptr_t ident, int16_t filter, uint16_t flags,
    void *udata)
{
	struct kevent kev;

	EV_SET(&kev, ident, filter, flags, 0, 0, udata);
	return (kevent(kq, &kev, 1, NULL, 0, NULL));
}

static int
meshd_client_queue_bytes(struct meshd_app_client *cl, const char *buf,
    size_t len)
{

	if (cl == NULL || !cl->active || buf == NULL)
		return (-1);
	if (len > sizeof(cl->txbuf) - cl->txlen)
		return (-1);
	memcpy(cl->txbuf + cl->txlen, buf, len);
	cl->txlen += len;
	return (0);
}

static int
meshd_client_queue_line(struct meshd_app_client *cl, const char *line)
{
	size_t len;

	len = strlen(line);
	if (meshd_client_queue_bytes(cl, line, len) != 0 ||
	    meshd_client_queue_bytes(cl, "\n", 1) != 0)
		return (-1);
	return (0);
}

static int
meshd_format_event(const struct meshd_app_event *ev, char *out, size_t outsz)
{
	static const char hex[] = "0123456789abcdef";
	size_t off, i;
	int n;

	n = snprintf(out, outsz,
	    "EVENT elem=0x%04x model=0x%04x vendor=0x%04x src=0x%04x "
	    "dst=0x%04x opcode=0x%06x params=",
	    ev->elem_addr, ev->id.model_id,
	    ev->id.vendor ? ev->id.company_id : 0, ev->src, ev->dst,
	    ev->opcode);
	if (n < 0 || (size_t)n >= outsz)
		return (-1);
	off = (size_t)n;
	for (i = 0; i < ev->params_len && off + 2 < outsz; i++) {
		out[off++] = hex[ev->params[i] >> 4];
		out[off++] = hex[ev->params[i] & 0x0f];
	}
	if (off >= outsz)
		return (-1);
	out[off] = '\0';
	return (0);
}

static int
meshd_client_queue_events(struct meshd_app_client *cl)
{
	struct meshd_app_event ev;
	char line[MESHD_CTL_REPLY_MAX];
	int queued = 0;

	while (meshd_app_client_event_pop(cl, &ev) > 0) {
		if (meshd_format_event(&ev, line, sizeof(line)) != 0 ||
		    meshd_client_queue_line(cl, line) != 0)
			return (-1);
		MESHD_PROBE_APP_EVENT_SEND(cl->fd, ev.opcode, ev.params_len);
		queued++;
	}
	return (queued);
}

static struct meshd_app_client *
meshd_client_alloc(struct meshd_node *nd, int fd)
{
	size_t i;

	for (i = 0; i < MESHD_MAX_APP_CLIENTS; i++) {
		if (!nd->app_clients[i].active) {
			meshd_app_client_init(&nd->app_clients[i], fd);
			return (&nd->app_clients[i]);
		}
	}
	return (NULL);
}

static void
meshd_client_close(int kq, struct meshd_app_client *cl)
{
	int fd;

	if (cl == NULL || !cl->active)
		return;
	fd = cl->fd;
	(void)meshd_kevent_ctl(kq, (uintptr_t)fd, EVFILT_READ, EV_DELETE, cl);
	(void)meshd_kevent_ctl(kq, (uintptr_t)fd, EVFILT_WRITE, EV_DELETE, cl);
	meshd_app_client_fini(cl);
	close(fd);
}

static int
meshd_client_process_line(struct meshd_node *nd, struct meshd_persist *ps,
    struct meshd_app_client *cl, char *line)
{
	char reply[MESHD_CTL_REPLY_MAX];
	char *argv[MESHD_CTL_ARGV_MAX];
	int argc;

	/*
	 * Ensure the on-disk SEQ high-water leads this line's originations
	 * BEFORE they are transmitted (NB-6).  A single control-socket drain can
	 * execute many lines, each originating a segmented message (up to ~32
	 * SEQ); reserving only once after the whole drain let a batch push the
	 * live SEQ past the persisted mark, so a crash mid-batch resumed at a
	 * lower SEQ and reused (IV,SRC,SEQ).  Reserving per line (a cheap no-op
	 * while headroom remains) keeps the persisted mark ahead of every PDU
	 * that reaches the air.
	 */
	if (ps != NULL && meshd_persist_seq_reserve(ps, nd) < 0) {
		/*
		 * The persisted SEQ high-water could not be advanced (store write
		 * failed): refuse this line rather than originate PDUs whose SEQ
		 * may reach or exceed the stale on-disk mark and reuse (IV,SRC,SEQ)
		 * after a crash.  The main loop observes the same failure after the
		 * drain and quits; here we make sure nothing is transmitted first.
		 * (ps == NULL is the no-persist/test path: skip the reservation.)
		 */
		snprintf(reply, sizeof(reply),
		    "ERR cannot persist SEQ reservation");
		return (meshd_client_queue_line(cl, reply));
	}
	argc = meshd_ctl_tokenize(line, argv, MESHD_CTL_ARGV_MAX);
	(void)meshd_ctl_exec_client(nd, cl, argc, argv, reply, sizeof(reply));
	return (meshd_client_queue_line(cl, reply));
}

static int
meshd_client_read(struct meshd_node *nd, struct meshd_persist *ps,
    struct meshd_app_client *cl)
{
	char buf[256];
	ssize_t n;
	int handled = 0;

	for (;;) {
		n = read(cl->fd, buf, sizeof(buf));
		if (n > 0) {
			size_t off, start;

			if ((size_t)n > sizeof(cl->rxbuf) - cl->rxlen)
				return (-1);
			memcpy(cl->rxbuf + cl->rxlen, buf, (size_t)n);
			cl->rxlen += (size_t)n;
			start = 0;
			for (off = 0; off < cl->rxlen; off++) {
				if (cl->rxbuf[off] != '\n')
					continue;
				cl->rxbuf[off] = '\0';
				if (meshd_client_process_line(nd, ps, cl,
				    cl->rxbuf + start) != 0)
					return (-1);
				handled = 1;
				start = off + 1;
			}
			if (start > 0) {
				memmove(cl->rxbuf, cl->rxbuf + start,
				    cl->rxlen - start);
				cl->rxlen -= start;
			}
			if (cl->rxlen == sizeof(cl->rxbuf))
				return (-1);
			continue;
		}
		if (n == 0)
			return (-1);
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return (handled);
		if (errno == EINTR)
			continue;
		return (-1);
	}
}

static int
meshd_client_write(struct meshd_app_client *cl)
{
	ssize_t n;

	while (cl->txoff < cl->txlen) {
		n = write(cl->fd, cl->txbuf + cl->txoff, cl->txlen - cl->txoff);
		if (n > 0) {
			cl->txoff += (size_t)n;
			continue;
		}
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return (0);
		if (n < 0 && errno == EINTR)
			continue;
		return (-1);
	}
	cl->txoff = 0;
	cl->txlen = 0;
	return (0);
}

static void
meshd_clients_queue_events(struct meshd_node *nd, int kq)
{
	size_t i;

	for (i = 0; i < MESHD_MAX_APP_CLIENTS; i++) {
		struct meshd_app_client *cl = &nd->app_clients[i];

		if (!cl->active)
			continue;
		if (meshd_client_queue_events(cl) < 0) {
			meshd_client_close(kq, cl);
			continue;
		}
		if (cl->txlen > cl->txoff)
			(void)meshd_kevent_ctl(kq, (uintptr_t)cl->fd,
			    EVFILT_WRITE, EV_ADD | EV_ENABLE, cl);
	}
}

int
main(int argc, char *argv[])
{
	struct meshd_config cfg;
	struct meshd_node nd;
	struct meshd_persist ps;
	struct meshd_blued bc;
	struct meshd_bearer bearer;
	struct sockaddr_un sun;
	const char *conf = MESHD_DEFAULT_CONF;
	const char *sockpath = MESHD_DEFAULT_SOCK;
	const char *statepath = MESHD_DEFAULT_STATE;
	const char *mgrpath = MESHD_DEFAULT_MGR;
	const char *bluedpath = NULL;
	int bfd_registered = -1;
	int bfd_write_registered = 0;
	uint64_t bfd_generation_registered = 0;
	int ch, exit_status = 0, fatal_persist = 0, kq, sfd, foreground = 0;
	int state_lock = -1, mgr_lock = -1;

	while ((ch = getopt(argc, argv, "df:s:S:M:B:h")) != -1) {
		switch (ch) {
		case 'd':
			foreground = 1;
			break;
		case 'f':
			conf = optarg;
			break;
		case 's':
			sockpath = optarg;
			break;
		case 'S':
			statepath = optarg;
			break;
		case 'M':
			mgrpath = optarg;
			break;
		case 'B':
			bluedpath = optarg;
			break;
		case 'h':
		default:
			usage();
		}
	}

	if (meshd_config_load(&cfg, conf) != 0)
		errx(1, "cannot load configuration from %s", conf);
	if (meshd_parent_secure(statepath) != 0 ||
	    meshd_parent_secure(mgrpath) != 0 ||
	    meshd_parent_secure(sockpath) != 0)
		err(1, "insecure state, manager, or socket directory");
	if (meshd_node_init(&nd, &cfg) != 0)
		errx(1, "cannot initialise mesh node");
	state_lock = meshd_state_lock(statepath);
	if (state_lock < 0)
		err(1, "cannot lock node state %s", statepath);
	mgr_lock = meshd_state_lock(mgrpath);
	if (mgr_lock < 0)
		err(1, "cannot lock manager state %s", mgrpath);

	/*
	 * Reload persisted runtime state BEFORE joining the network: this resumes
	 * the SEQ above any value previously used and restores the Replay
	 * Protection List, closing the restart replay-protection gap.  A fresh
	 * node (no store) reserves its first SEQ block instead.
	 */
	meshd_persist_init(&ps, statepath, 0);
	switch (meshd_persist_load(&ps, &nd)) {
	case 0:
		break;
	case 1:
		if (meshd_persist_seq_reserve(&ps, &nd) < 0)
			errx(1, "cannot reserve node sequence state in %s", statepath);
		break;
	case -2:
		errx(1, "node state %s was written by an unsupported (older) "
		    "format version; remove it to start fresh", statepath);
		break;
	default:
		errx(1, "node state %s is corrupt", statepath);
	}

	/*
	 * Restore the manager database (the created network's keys, unicast
	 * allocator, node roster and per-node DevKeys) so the network this daemon
	 * manages survives a restart and the Config Client can address its nodes.
	 */
	meshd_mgr_restore(&nd, mgrpath);

	/*
	 * Resume a NetKey key-refresh that was mid-distribution when the daemon
	 * last stopped: the staged key and kr_distributing flag were restored
	 * from the node store, and the per-node kr_state (DISTRIBUTING for nodes
	 * not yet acked) came back with the manager roster, so re-kick the one-
	 * at-a-time NetKey Update pump.  Without this the refresh would stall
	 * silently and a later phase advance would eject the un-acked nodes.
	 */
	if (nd.kr_distributing)
		(void)meshd_kr_send_next(&nd, meshd_now());

	/*
	 * Attach the radio bearer: a privileged client of blued.  The bearer
	 * sink is installed unconditionally so outbound PDUs route through it;
	 * meshd_blued_tx() drops (and counts) sends while the link is down.  The
	 * initial connect is best-effort - if blued is not yet up the node
	 * stays running and the tick loop reconnects with backoff, so daemon
	 * boot order is not load-bearing.
	 */
	meshd_blued_init(&bc, bluedpath != NULL ? bluedpath : cfg.blued_socket);
	meshd_blued_bind_node(&bc, &nd);
	(void)meshd_blued_connect(&bc);
	bearer.tx = meshd_blued_tx;
	bearer.pbgatt_open = meshd_blued_pbgatt_open;
	bearer.proxy_open = meshd_blued_proxy_open;
	bearer.pbgatt_close = meshd_blued_pbgatt_close;
	bearer.pbgatt_timeout = meshd_blued_pbgatt_timeout;
	bearer.proxy_close = meshd_blued_proxy_close;
	bearer.proxy_tx = meshd_blued_proxy_tx;
	bearer.arg = &bc;
	meshd_set_bearer(&nd, &bearer);

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd < 0)
		err(1, "socket");
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, sockpath, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path))
		errx(1, "socket path is too long: %s", sockpath);
	if (meshd_unlink_stale_socket(sockpath) != 0)
		err(1, "cannot remove stale socket %s", sockpath);
	if (bind(sfd, (struct sockaddr *)&sun, sizeof(sun)) < 0)
		err(1, "bind %s", sockpath);
	if (chmod(sockpath, S_IRUSR | S_IWUSR) != 0)
		err(1, "chmod %s", sockpath);
	if (listen(sfd, 5) < 0)
		err(1, "listen");
	if (meshd_set_nonblock(sfd) != 0)
		err(1, "fcntl listener");

	signal(SIGINT, meshd_on_signal);
	signal(SIGTERM, meshd_on_signal);
	signal(SIGPIPE, SIG_IGN);

	if (!foreground && daemon(0, 0) < 0)
		err(1, "daemon");

	kq = kqueue();
	if (kq < 0)
		err(1, "kqueue");
	if (meshd_kevent_ctl(kq, (uintptr_t)sfd, EVFILT_READ, EV_ADD,
	    &meshd_listen_token) != 0)
		err(1, "kevent listener");

	while (!meshd_quit) {
		struct kevent ev[32];
		struct timespec ts;
		uint64_t now;
		int iv_changed = 0;
		uint64_t bfd_generation;
		uint32_t iv_epoch;
		int bfd, i, nev;

		/*
		 * Keep blued's current connection registered.  Descriptor numbers
		 * can be reused immediately after close, so fd equality alone does not
		 * identify a connection.  The generation also becomes the immutable
		 * event token used to reject stale events already returned by kqueue.
		 */
		bfd = meshd_blued_fd(&bc);
		bfd_generation = meshd_blued_generation(&bc);
		if (meshd_blued_registration_changed(&bc, bfd_registered,
		    bfd_generation_registered)) {
			if (bfd_registered >= 0) {
				(void)meshd_kevent_ctl(kq,
				    (uintptr_t)bfd_registered, EVFILT_READ,
				    EV_DELETE, meshd_blued_udata(
				    bfd_generation_registered));
				if (bfd_write_registered)
					(void)meshd_kevent_ctl(kq,
					    (uintptr_t)bfd_registered, EVFILT_WRITE,
					    EV_DELETE, meshd_blued_udata(
					    bfd_generation_registered));
			}
			bfd_registered = -1;
			bfd_write_registered = 0;
			bfd_generation_registered = 0;
			if (bfd >= 0 && meshd_kevent_ctl(kq, (uintptr_t)bfd,
			    EVFILT_READ, EV_ADD,
			    meshd_blued_udata(bfd_generation)) == 0) {
				bfd_registered = bfd;
				bfd_generation_registered = bfd_generation;
			}
		}
		if (bfd_registered >= 0 && meshd_blued_wants_write(&bc) !=
		    bfd_write_registered) {
			if (meshd_kevent_ctl(kq, (uintptr_t)bfd_registered,
			    EVFILT_WRITE, meshd_blued_wants_write(&bc) ? EV_ADD :
			    EV_DELETE, meshd_blued_udata(
			    bfd_generation_registered)) == 0)
				bfd_write_registered = !bfd_write_registered;
		}

		ts.tv_sec = MESHD_TICK_MS / 1000;
		ts.tv_nsec = (MESHD_TICK_MS % 1000) * 1000000L;
		nev = kevent(kq, NULL, 0, ev, nitems(ev), &ts);
		now = meshd_now();
		if (nev < 0) {
			if (errno != EINTR)
				warn("kevent");
			nev = 0;
		}

		/* SEQ-epoch snapshot for beacon-driven IV completion (see tick). */
		iv_epoch = (nd.self != NULL) ? nd.self->iv.iv_index : 0;

		for (i = 0; i < nev; i++) {
			if (ev[i].udata == &meshd_listen_token) {
				for (;;) {
					struct meshd_app_client *cl;
					int cfd;

					cfd = accept(sfd, NULL, NULL);
					if (cfd < 0) {
						if (errno == EAGAIN ||
						    errno == EWOULDBLOCK ||
						    errno == EINTR)
							break;
						warn("accept");
						break;
					}
					if (!meshd_peer_authorized(cfd)) {
						warnx("rejected unauthorized control peer");
						close(cfd);
						continue;
					}
					if (meshd_set_nonblock(cfd) != 0 ||
					    (cl = meshd_client_alloc(&nd,
					    cfd)) == NULL) {
						close(cfd);
						continue;
					}
					if (meshd_kevent_ctl(kq, (uintptr_t)cfd,
					    EVFILT_READ, EV_ADD, cl) != 0) {
						meshd_client_close(kq, cl);
						continue;
					}
				}
				continue;
			}
			if (((uintptr_t)ev[i].udata &
			    MESHD_BLUED_UDATA_TAG) != 0) {
				/* Ignore an event belonging to an earlier connection. */
				if (!meshd_blued_event_current(&bc, &ev[i]))
					continue;
				if (ev[i].filter == EVFILT_WRITE) {
					if (meshd_blued_flush(&bc) != 0) {
						meshd_proxy_gatt_cancel(&nd, NULL, 0,
						    MESHD_ADAPTER_DEFAULT);
						if (!meshd_pbgatt_done(&nd))
							meshd_pbgatt_cancel(&nd);
						meshd_blued_close(&bc);
					}
				} else if (meshd_blued_pump_rx(&bc, &nd, &ps,
				    now) > 0)
					meshd_persist_mark_dirty(&ps, now);
				meshd_clients_queue_events(&nd, kq);
				continue;
			}
			if (ev[i].udata != NULL) {
				struct meshd_app_client *cl = ev[i].udata;

				if ((ev[i].flags & EV_EOF) != 0) {
					meshd_client_close(kq, cl);
					continue;
				}
				if (ev[i].filter == EVFILT_READ) {
					int handled = meshd_client_read(&nd, &ps, cl);

					if (handled < 0) {
						meshd_client_close(kq, cl);
						continue;
					}
					if (handled > 0)
						meshd_persist_mark_dirty(&ps, now);
					if (meshd_persist_seq_reserve(&ps, &nd) < 0) {
						warn("cannot reserve node state %s", statepath);
						fatal_persist = 1;
						meshd_quit = 1;
					}
					if (meshd_mgr_persist(&nd, mgrpath) != 0) {
						warn("cannot persist manager state %s", mgrpath);
						fatal_persist = 1;
						meshd_quit = 1;
					}
				} else if (ev[i].filter == EVFILT_WRITE) {
					if (meshd_client_write(cl) < 0) {
						meshd_client_close(kq, cl);
						continue;
					}
				}
				if (cl->active && cl->txlen > cl->txoff)
					(void)meshd_kevent_ctl(kq,
					    (uintptr_t)cl->fd, EVFILT_WRITE,
					    EV_ADD | EV_ENABLE, cl);
				else if (cl->active)
					(void)meshd_kevent_ctl(kq,
					    (uintptr_t)cl->fd, EVFILT_WRITE,
					    EV_DISABLE, cl);
			}
		}
		if (meshd_quit)
			break;

		/*
		 * Clock tick: advance the time-driven state machines and keep the
		 * SEQ reservation ahead of the live SEQ.  An IV Index change opens
		 * a fresh SEQ epoch, so re-establish the reservation from zero.
		 */
		(void)meshd_node_tick(&nd, now, &iv_changed);
		/*
		 * Reset the persisted SEQ reservation on any IV Index change,
		 * whether observed by the tick (iv_changed) or completed earlier
		 * during event drain by a Secure Network Beacon (which resets the
		 * live SEQ to 0 in the RX pump before the tick sees Normal).  The
		 * beacon path bumps iv.iv_index but leaves iv_changed clear, so
		 * without the epoch comparison the old high-water would be carried
		 * into the new epoch and burn SEQ space.
		 */
		if (iv_changed ||
		    (nd.self != NULL && nd.self->iv.iv_index != iv_epoch))
			ps.reserved = 0;
		if (meshd_persist_seq_reserve(&ps, &nd) < 0) {
			warn("cannot reserve node state %s", statepath);
			fatal_persist = 1;
			meshd_quit = 1;
		}
		if (meshd_persist_flush(&ps, &nd, now, 0) < 0) {
			warn("cannot persist node state %s", statepath);
			fatal_persist = 1;
			meshd_quit = 1;
		}
		if (meshd_quit)
			break;

		/* Drain any due Provisioner PB-ADV output to the bearer. */
		(void)meshd_provisioner_drain(&nd, now);

		/*
		 * A failed provisioning attempt (PB-ADV retransmit budget
		 * exhausted, or a session protocol error) otherwise wedges
		 * provisioning forever and leaks the reserved unicast address.
		 * Tear it down eagerly so a later attempt can proceed; the
		 * failure is retained for the operator's provision-status poll.
		 */
		if (meshd_provision_ota_failed(&nd))
			meshd_provision_ota_abort(&nd, 1);

		/*
		 * Commit an OTA provisioning that has completed since the last
		 * tick, recording the new node + DevKey and persisting the roster.
		 */
		if (nd.prov_target_active && meshd_provisioner_done(&nd)) {
			if (meshd_provision_ota_commit(&nd, now) != NULL) {
				meshd_persist_mark_dirty(&ps, now);
				if (meshd_mgr_persist(&nd, mgrpath) != 0) {
					warn("cannot persist manager state %s", mgrpath);
					fatal_persist = 1;
					meshd_quit = 1;
				}
			}
		}
		if (meshd_quit)
			break;

		/* Retransmit an in-flight Config Client transaction if due. */
		(void)meshd_cfg_client_tick(&nd, now);
		meshd_clients_queue_events(&nd, kq);

		/* Reconnect the bearer (with backoff) if blued dropped. */
		(void)meshd_blued_maintain(&bc, now);
	}

	for (size_t i = 0; i < MESHD_MAX_APP_CLIENTS; i++)
		meshd_client_close(kq, &nd.app_clients[i]);
	meshd_persist_mark_dirty(&ps, meshd_now());
	if (meshd_persist_flush(&ps, &nd, meshd_now(), 1) < 0) {
		warn("cannot persist node state %s during shutdown", statepath);
		exit_status = 1;
	}
	if (meshd_mgr_persist(&nd, mgrpath) != 0) {
		warn("cannot persist manager state %s during shutdown", mgrpath);
		exit_status = 1;
	}
	if (fatal_persist)
		exit_status = 1;
	close(kq);
	meshd_blued_close(&bc);
	close(sfd);
	close(mgr_lock);
	close(state_lock);
	(void)unlink(sockpath);
	meshd_node_fini(&nd);
	return (exit_status);
}
