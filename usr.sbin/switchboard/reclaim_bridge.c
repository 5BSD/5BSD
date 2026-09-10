/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * switchboard label-reclaim UNIX-socket bridge (docs/capability-lifecycle-cleanup.md
 * §5b).
 *
 * ============================================================================
 * THE SOLE DELIBERATE UNIX-DOMAIN SOCKET ON THE CAPABILITY PLANE.
 * ============================================================================
 *
 * switchboard otherwise speaks only over the capability discovery plane (minted
 * libchannel endpoints, authorized by held rights, never by peer uid).  This
 * one socket is a deliberate, documented exception.  Its ONLY function is to
 * let a UNIX (non-plane) context trigger a bundle-label reclaim — specifically
 * a pkg(8) post-deinstall script, which runs in a plain root context with NO
 * inherited ambient discovery channel (pkg preserves SERVICE_LOOKUP_FD in the
 * environment but closes the inherited descriptor), so it cannot reach
 * switchboard's SWITCHBOARD_CONTROL_NAME plane to run the normal `switchboardctl reclaim`.
 *
 * It confers NO NEW AUTHORITY.  Root can already drive `switchboardctl reclaim`
 * over the ambient ADMIN control channel from an admin login session
 * (SCTL_OP_RECLAIM, ADMIN-gated).  This socket is root-gated by getpeereid(2)
 * (euid == 0); the worst thing it enables is a root-only denial of service that
 * reclaims a still-live label — a capability root already holds by other means.
 *
 * It does RECLAIM AND NOTHING ELSE: one fixed request in
 * (struct switchboard_reclaim_req), one fixed reply out
 * (struct switchboard_reclaim_reply), connection closed.  There is no other op.
 *
 * Ownership / gating reasoning: switchboard runs as uid 976
 * (capability:capability), not root, so the socket node is owned by 976 and
 * chmod'd 0600.  root (pkg) can still connect(2) — DAC permission bits never
 * restrict a privileged (uid 0) process — while any other uid is refused at
 * connect(2) by the 0600 mode AND, decisively, by the getpeereid(2) euid == 0
 * gate enforced here.  The mode is defense in depth; the getpeereid gate is the
 * authority.
 *
 * Everything here is best-effort / fail-soft: if the socket cannot be created,
 * a warning is logged and switchboard runs normally (reclaim is simply not
 * reachable over the socket; the ambient control path is unaffected).
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <capability.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "switchboard.h"
#include "switchboard_ctl.h"
#include "reclaim_bridge.h"

/*
 * The single listening socket.  -1 when the bridge is not up (setup failed, or
 * before init / after teardown).
 */
static int reclaim_listen_fd = -1;

/* Bound synchronous I/O so a stalled root client cannot wedge the event loop. */
#define	RECLAIM_IO_TIMEOUT_SEC	5

/*
 * Read exactly n bytes into buf, or fail.  Returns 0 on success, -1 on error or
 * premature EOF (errno set; EPIPE for a short close).
 */
static int
read_full(int fd, void *buf, size_t n)
{
	char *p = buf;
	size_t off = 0;
	ssize_t r;

	while (off < n) {
		r = read(fd, p + off, n - off);
		if (r == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (r == 0) {
			errno = EPIPE;
			return (-1);
		}
		off += (size_t)r;
	}
	return (0);
}

/*
 * Write exactly n bytes from buf, or fail.  Returns 0 on success, -1 on error.
 */
static int
write_full(int fd, const void *buf, size_t n)
{
	const char *p = buf;
	size_t off = 0;
	ssize_t w;

	while (off < n) {
		w = write(fd, p + off, n - off);
		if (w == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (w == 0) {
			errno = EPIPE;
			return (-1);
		}
		off += (size_t)w;
	}
	return (0);
}

int
reclaim_bridge_serve(int connfd, bool peer_authorized,
    reclaim_bridge_action action, void *arg)
{
	struct switchboard_reclaim_req req;
	struct switchboard_reclaim_reply reply;
	int rc = 0;

	memset(&reply, 0, sizeof(reply));

	/*
	 * Authorization precedes all request I/O.  In particular, an
	 * unauthorized peer must not be able to occupy switchboard's event loop
	 * for the receive-timeout interval merely by connecting and withholding
	 * the fixed request.
	 */
	if (!peer_authorized) {
		reply.status = EPERM;
		reply.providers_notified = 0;
	} else if (read_full(connfd, &req, sizeof(req)) == -1) {
		/*
		 * Could not even read a full request.  Try to answer EIO so the
		 * client sees a failure, but the connection may already be gone.
		 */
		reply.status = EIO;
		reply.providers_notified = 0;
		rc = -1;
	} else if (!reclaim_req_valid(&req)) {
		reply.status = EINVAL;
		reply.providers_notified = 0;
	} else {
		reply.status = 0;
		reply.providers_notified =
		    action != NULL ? action(req.label, arg) : 0;
	}

	if (write_full(connfd, &reply, sizeof(reply)) == -1)
		rc = -1;
	(void)close(connfd);
	return (rc);
}

/*
 * Production reclaim action: fan the retirement out to running providers via
 * the existing authorized broadcast.  arg points to the switchboard kqueue fd.
 */
static unsigned
reclaim_do_retire(const char *label, void *arg)
{
	int kq = *(const int *)arg;

	return (svc_retire_label(label, kq));
}

void
reclaim_bridge_accept(int kq)
{
	struct timeval tv;
	uid_t euid;
	gid_t egid;
	bool authorized;
	int connfd;

	if (reclaim_listen_fd < 0)
		return;

	/*
	 * Accept a BLOCKING connection (SOCK_CLOEXEC only, not SOCK_NONBLOCK):
	 * the request/reply are handled synchronously, and SO_RCVTIMEO/SO_SNDTIMEO
	 * below turn the blocking read_full/write_full loops into bounded waits.
	 * A non-blocking accepted socket would instead make read_full fail EAGAIN
	 * if the request bytes had not yet arrived after connect(2).
	 */
	connfd = accept4(reclaim_listen_fd, NULL, NULL, SOCK_CLOEXEC);
	if (connfd == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			syslog(LOG_WARNING, "reclaim bridge: accept: %m");
		return;
	}

	/*
	 * Bound the synchronous request/reply so a misbehaving (root) client
	 * cannot stall switchboard's single-threaded event loop: a receive/send
	 * timeout caps how long the blocking read/write loops can wait.
	 */
	tv.tv_sec = RECLAIM_IO_TIMEOUT_SEC;
	tv.tv_usec = 0;
	if (setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1 ||
	    setsockopt(connfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
		syslog(LOG_WARNING,
		    "reclaim bridge: cannot bound client I/O: %m");
		(void)close(connfd);
		return;
	}

	/*
	 * The authority gate: only a root peer may drive reclaim.  See the file
	 * banner — this is a uid gate on purpose (the caller is a non-plane pkg
	 * context) and grants nothing root cannot already do.
	 */
	if (getpeereid(connfd, &euid, &egid) != 0) {
		syslog(LOG_WARNING, "reclaim bridge: getpeereid: %m");
		(void)close(connfd);
		return;
	}
	authorized = reclaim_peer_is_authorized(euid);
	if (!authorized)
		syslog(LOG_WARNING,
		    "reclaim bridge: rejecting non-root peer euid=%u",
		    (unsigned)euid);

	(void)reclaim_bridge_serve(connfd, authorized, reclaim_do_retire, &kq);
}

bool
reclaim_bridge_is_listener(int fd)
{

	return (reclaim_listen_fd >= 0 && fd == reclaim_listen_fd);
}

int
reclaim_bridge_init(int kq)
{
	struct sockaddr_un sun;
	struct kevent kev;
	int fd, saved;

	if (reclaim_listen_fd >= 0)
		return (0);			/* already up */

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, SWITCHBOARD_RECLAIM_SOCK, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		syslog(LOG_WARNING, "reclaim bridge: socket path too long: %s",
		    SWITCHBOARD_RECLAIM_SOCK);
		return (-1);
	}

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd == -1) {
		syslog(LOG_WARNING, "reclaim bridge: socket: %m");
		return (-1);
	}

	/*
	 * A stale node from a previous boot/crash would make bind(2) fail
	 * EADDRINUSE.  switchboard is the sole binder of this path, so unlinking a
	 * leftover node is safe (mirrors activation.c's AF_UNIX bind path).
	 */
	(void)unlink(SWITCHBOARD_RECLAIM_SOCK);
	if (bind(fd, (struct sockaddr *)&sun,
	    (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
	    strlen(sun.sun_path) + 1)) == -1) {
		syslog(LOG_WARNING, "reclaim bridge: bind %s: %m",
		    SWITCHBOARD_RECLAIM_SOCK);
		(void)close(fd);
		return (-1);
	}

	/*
	 * 0600: owner (uid 976, switchboard) only.  root bypasses DAC and can still
	 * connect; every other uid is refused here as defense in depth, and the
	 * getpeereid euid == 0 gate is the decisive authority.
	 */
	if (chmod(SWITCHBOARD_RECLAIM_SOCK, 0600) == -1)
		syslog(LOG_WARNING, "reclaim bridge: chmod %s: %m (continuing)",
		    SWITCHBOARD_RECLAIM_SOCK);

	if (listen(fd, 8) == -1) {
		syslog(LOG_WARNING, "reclaim bridge: listen: %m");
		saved = errno;
		(void)close(fd);
		(void)unlink(SWITCHBOARD_RECLAIM_SOCK);
		errno = saved;
		return (-1);
	}

	/*
	 * Confine the listener as a switchboard-internal descriptor: it must never
	 * be inherited by a forked service (clofork), leaked via exec (cloexec —
	 * already SOCK_CLOEXEC), or transferred over a channel (xfer none).
	 * Best-effort: a confinement failure is logged but does not disable the
	 * bridge (the fd is still CLOEXEC from the socket() flags).
	 */
	if (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1)
		syslog(LOG_WARNING,
		    "reclaim bridge: fd confinement: %m (continuing)");

	/* udata == NULL: dispatched by fd identity via reclaim_bridge_is_listener(). */
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_WARNING, "reclaim bridge: kevent register: %m");
		saved = errno;
		(void)close(fd);
		(void)unlink(SWITCHBOARD_RECLAIM_SOCK);
		errno = saved;
		return (-1);
	}

	reclaim_listen_fd = fd;
	syslog(LOG_INFO, "reclaim bridge: listening on %s (fd %d)",
	    SWITCHBOARD_RECLAIM_SOCK, fd);
	return (0);
}

void
reclaim_bridge_teardown(void)
{

	if (reclaim_listen_fd < 0)
		return;
	(void)close(reclaim_listen_fd);
	reclaim_listen_fd = -1;
	(void)unlink(SWITCHBOARD_RECLAIM_SOCK);
}
