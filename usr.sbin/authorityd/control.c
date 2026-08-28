/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Control socket for authorityd.
 *
 * Provides a unix domain socket at /var/run/authorityd.sock for
 * administrative commands (status, shutdown, reload).  System
 * operations (kldload, reboot) are here temporarily and will
 * move to separate service programs in Phase 2.
 *
 * Each client connection is one-shot and fully nonblocking:
 * accept → kqueue-driven read of request → dispatch → kqueue-
 * driven write of reply → close.  No client can stall the
 * event loop.
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "authorityd.h"
#include "authorityd_ctl.h"
#include "commands.h"

static int
confine_control_fd(int fd)
{

	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}
#include "probes.h"

/* Module-private state. */
static int control_sock = -1;
static struct timespec start_time;

#define	CTL_CONN_TIMEOUT_SEC	2
#define	CTL_CONN_MAX		16

/*
 * Per-connection nonblocking state machine.
 *
 * Lifecycle: READING_HDR → [READING_PAYLOAD →] dispatch →
 *            WRITING_REPLY → [WRITING_SUMMARY →] DONE.
 */
enum ctl_conn_state {
	CTL_CONN_READING_HDR,
	CTL_CONN_READING_PAYLOAD,
	CTL_CONN_WRITING_REPLY,
	CTL_CONN_WRITING_SUMMARY,
	CTL_CONN_DONE
};

struct ctl_conn {
	TAILQ_ENTRY(ctl_conn)	entry;
	int			fd;
	uid_t			euid;
	enum ctl_conn_state	state;
	size_t			offset;

	struct ctl_request	req;
	char			payload[CTL_MAX_PAYLOAD + 1];

	struct ctl_reply	reply;
	char			summary[CTL_SUMMARY_MAX];
	uint32_t		summary_len;
	int			action;

	uintptr_t		timer_ident;
	struct timespec		accept_ts;	/* monotonic time at accept */
};

static TAILQ_HEAD(, ctl_conn) conn_list = TAILQ_HEAD_INITIALIZER(conn_list);
static unsigned nconns;
static uintptr_t conn_timer_next = 50000;
#define	CTL_CONN_TIMER_BIT	((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 2))

static uint64_t
uptime_usec(void)
{
	struct timespec now;
	uint64_t sec;
	long nsec;

	clock_gettime(CLOCK_MONOTONIC, &now);
	sec = now.tv_sec - start_time.tv_sec;
	nsec = now.tv_nsec - start_time.tv_nsec;
	if (nsec < 0) {
		sec--;
		nsec += 1000000000L;
	}
	return (sec * 1000000 + nsec / 1000);
}

static void
conn_destroy(struct ctl_conn *c)
{
	struct kevent kev;

	/* Remove kqueue filters. */
	EV_SET(&kev, c->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	(void)kevent(event_kq, &kev, 1, NULL, 0, NULL);
	EV_SET(&kev, c->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
	(void)kevent(event_kq, &kev, 1, NULL, 0, NULL);

	if (c->timer_ident != 0) {
		EV_SET(&kev, c->timer_ident, EVFILT_TIMER,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(event_kq, &kev, 1, NULL, 0, NULL);
	}

	close(c->fd);
	TAILQ_REMOVE(&conn_list, c, entry);
	nconns--;
	AUTHORITYD_PROBE_CONN_COUNT(nconns);
	free(c);
}

static void
conn_arm_timeout(struct ctl_conn *c)
{
	struct kevent kev;

	c->timer_ident = CTL_CONN_TIMER_BIT | conn_timer_next++;
	EV_SET(&kev, c->timer_ident, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS, CTL_CONN_TIMEOUT_SEC, c);
	if (kevent(event_kq, &kev, 1, NULL, 0, NULL) == -1)
		syslog(LOG_WARNING, "control: conn timeout: %m");
}

/*
 * Dispatch the command.  Fills reply + summary, transitions to
 * writing, and switches the kqueue filter from read to write.
 */
static void
conn_dispatch(struct ctl_conn *c)
{
	struct ctl_request *req;
	struct ctl_reply *reply;
	struct kevent kev[2];

	req = &c->req;
	reply = &c->reply;
	memset(reply, 0, sizeof(*reply));
	c->summary[0] = '\0';
	c->summary_len = 0;
	c->action = CTL_ACTION_NONE;

	if (req->version != CTL_VERSION) {
		reply->status = ENOTSUP;
		goto write;
	}

	AUTHORITYD_PROBE_CTL_CMD(req->op, c->euid);

	switch (req->op) {
	case CTL_OP_STATUS:
		if (req->datalen != 0) {
			reply->status = EINVAL;
			break;
		}
		cmd_status(uptime_usec(), reply,
		    c->summary, sizeof(c->summary));
		break;
	case CTL_OP_SHUTDOWN:
		if (req->datalen != 0) {
			reply->status = EINVAL;
			break;
		}
		if (cmd_shutdown(c->euid, reply))
			c->action = CTL_ACTION_SHUTDOWN;
		break;
	case CTL_OP_RELOAD:
		if (req->datalen != 0) {
			reply->status = EINVAL;
			break;
		}
		cmd_reload(c->euid, reply,
		    c->summary, sizeof(c->summary));
		break;
	case CTL_OP_REBOOT:
	case CTL_OP_HALT:
	case CTL_OP_POWEROFF:
	case CTL_OP_POWERCYCLE:
	case CTL_OP_SINGLE:
	case CTL_OP_REROOT:
	case CTL_OP_RESCAN:
	case CTL_OP_CATATONIA:
		if (req->datalen != 0) {
			reply->status = EINVAL;
			break;
		}
		if (cmd_lifecycle(c->euid, req->op, reply))
			c->action = CTL_ACTION_LIFECYCLE;
		break;
	default:
		reply->status = ENOTSUP;
		break;
	}

write:
	if ((req->op == CTL_OP_STATUS || req->op == CTL_OP_RELOAD) &&
	    reply->flags > 0)
		c->summary_len = reply->flags;

	c->state = CTL_CONN_WRITING_REPLY;
	c->offset = 0;

	EV_SET(&kev[0], c->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	EV_SET(&kev[1], c->fd, EVFILT_WRITE, EV_ADD, 0, 0, c);
	(void)kevent(event_kq, kev, 2, NULL, 0, NULL);
}

static void
conn_handle_read(struct ctl_conn *c)
{
	char *dst;
	size_t want;
	ssize_t n;

	switch (c->state) {
	case CTL_CONN_READING_HDR:
		dst = (char *)&c->req + c->offset;
		want = sizeof(c->req) - c->offset;
		break;
	case CTL_CONN_READING_PAYLOAD:
		dst = c->payload + c->offset;
		want = c->req.datalen - c->offset;
		break;
	default:
		c->state = CTL_CONN_DONE;
		return;
	}

	n = read(c->fd, dst, want);
	if (n == -1) {
		if (errno == EINTR || errno == EAGAIN)
			return;
		c->state = CTL_CONN_DONE;
		return;
	}
	if (n == 0) {
		c->state = CTL_CONN_DONE;
		return;
	}

	c->offset += (size_t)n;

	if (c->state == CTL_CONN_READING_HDR &&
	    c->offset == sizeof(c->req)) {
		if (c->req.datalen > 0 &&
		    c->req.datalen < sizeof(c->payload)) {
			c->state = CTL_CONN_READING_PAYLOAD;
			c->offset = 0;
		} else {
			conn_dispatch(c);
		}
	} else if (c->state == CTL_CONN_READING_PAYLOAD &&
	    c->offset == c->req.datalen) {
		conn_dispatch(c);
	}
}

static void
conn_handle_write(struct ctl_conn *c)
{
	const char *src;
	size_t total;
	ssize_t n;

	switch (c->state) {
	case CTL_CONN_WRITING_REPLY:
		src = (const char *)&c->reply + c->offset;
		total = sizeof(c->reply);
		break;
	case CTL_CONN_WRITING_SUMMARY:
		src = c->summary + c->offset;
		total = c->summary_len;
		break;
	default:
		c->state = CTL_CONN_DONE;
		return;
	}

	n = write(c->fd, src, total - c->offset);
	if (n == -1) {
		if (errno == EINTR || errno == EAGAIN)
			return;
		c->state = CTL_CONN_DONE;
		return;
	}
	if (n == 0) {
		c->state = CTL_CONN_DONE;
		return;
	}

	c->offset += (size_t)n;

	if (c->state == CTL_CONN_WRITING_REPLY &&
	    c->offset == sizeof(c->reply)) {
		if (c->summary_len > 0) {
			c->state = CTL_CONN_WRITING_SUMMARY;
			c->offset = 0;
		} else {
			c->state = CTL_CONN_DONE;
		}
	} else if (c->state == CTL_CONN_WRITING_SUMMARY &&
	    c->offset == c->summary_len) {
		c->state = CTL_CONN_DONE;
	}
}

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */

int
ctl_setup(void)
{
	struct sockaddr_un un;
	mode_t old_umask;
	int fd;

	clock_gettime(CLOCK_MONOTONIC, &start_time);

	fd = socket(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		syslog(LOG_ERR, "control socket: %m");
		return (-1);
	}

	if (strlen(od.cfg.control_socket) >= sizeof(un.sun_path)) {
		syslog(LOG_ERR, "control socket path too long: %s",
		    od.cfg.control_socket);
		close(fd);
		return (-1);
	}

	(void)unlink(od.cfg.control_socket);

	memset(&un, 0, sizeof(un));
	un.sun_family = AF_LOCAL;
	strlcpy(un.sun_path, od.cfg.control_socket, sizeof(un.sun_path));

	old_umask = umask(~od.cfg.control_socket_mode & 0777);
	if (bind(fd, (struct sockaddr *)&un, sizeof(un)) == -1) {
		syslog(LOG_ERR, "control bind %s: %m",
		    od.cfg.control_socket);
		(void)umask(old_umask);
		close(fd);
		return (-1);
	}
	(void)umask(old_umask);

	if (listen(fd, 5) == -1) {
		syslog(LOG_ERR, "control listen: %m");
		close(fd);
		(void)unlink(od.cfg.control_socket);
		return (-1);
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		syslog(LOG_ERR, "control fcntl: %m");
		close(fd);
		(void)unlink(od.cfg.control_socket);
		return (-1);
	}
	if (confine_control_fd(fd) == -1) {
		syslog(LOG_ERR, "control socket confinement: %m");
		close(fd);
		(void)unlink(od.cfg.control_socket);
		return (-1);
	}

	control_sock = fd;
	syslog(LOG_INFO, "control socket %s", od.cfg.control_socket);
	return (0);
}

void
ctl_teardown(void)
{
	struct ctl_conn *c, *tmp;

	TAILQ_FOREACH_SAFE(c, &conn_list, entry, tmp)
		conn_destroy(c);

	if (control_sock >= 0) {
		close(control_sock);
		control_sock = -1;
		(void)unlink(od.cfg.control_socket);
	}
}

int
ctl_fd(void)
{

	return (control_sock);
}

int
ctl_accept(void)
{
	struct ctl_conn *c;
	struct kevent kev;
	uid_t euid;
	gid_t egid;
	int cfd;

	cfd = accept4(control_sock, NULL, NULL,
	    SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (cfd == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			syslog(LOG_WARNING, "control accept: %m");
		return (CTL_ACTION_NONE);
	}
	if (confine_control_fd(cfd) == -1) {
		syslog(LOG_WARNING, "control client confinement: %m");
		close(cfd);
		return (CTL_ACTION_NONE);
	}

	if (nconns >= CTL_CONN_MAX) {
		syslog(LOG_WARNING,
		    "control: too many connections, rejecting");
		close(cfd);
		return (CTL_ACTION_NONE);
	}

	if (getpeereid(cfd, &euid, &egid) != 0) {
		syslog(LOG_WARNING, "control getpeereid: %m");
		close(cfd);
		return (CTL_ACTION_NONE);
	}

	AUTHORITYD_PROBE_CTL_ACCEPT(euid);

	c = calloc(1, sizeof(*c));
	if (c == NULL) {
		syslog(LOG_ERR, "control: calloc conn: %m");
		close(cfd);
		return (CTL_ACTION_NONE);
	}

	c->fd = cfd;
	c->euid = euid;
	c->state = CTL_CONN_READING_HDR;
	clock_gettime(CLOCK_MONOTONIC, &c->accept_ts);

	TAILQ_INSERT_TAIL(&conn_list, c, entry);
	nconns++;
	AUTHORITYD_PROBE_CONN_COUNT(nconns);

	EV_SET(&kev, cfd, EVFILT_READ, EV_ADD, 0, 0, c);
	if (kevent(event_kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_WARNING, "control: kevent register: %m");
		conn_destroy(c);
		return (CTL_ACTION_NONE);
	}

	conn_arm_timeout(c);
	return (CTL_ACTION_NONE);
}

int
ctl_conn_event(struct kevent *kev)
{
	struct ctl_conn *c;
	int action;

	c = kev->udata;
	action = CTL_ACTION_NONE;

	if (kev->filter == EVFILT_TIMER) {
		syslog(LOG_WARNING, "control: client timeout");
		c->timer_ident = 0;
		conn_destroy(c);
		return (CTL_ACTION_NONE);
	}

	if (kev->flags & EV_EOF &&
	    c->state <= CTL_CONN_READING_PAYLOAD) {
		conn_destroy(c);
		return (CTL_ACTION_NONE);
	}

	if (kev->filter == EVFILT_READ)
		conn_handle_read(c);
	else if (kev->filter == EVFILT_WRITE)
		conn_handle_write(c);

	if (c->state == CTL_CONN_DONE) {
		struct timespec now;
		uint64_t dur;

		clock_gettime(CLOCK_MONOTONIC, &now);
		dur = (uint64_t)(now.tv_sec - c->accept_ts.tv_sec) *
		    1000000000ULL +
		    (uint64_t)(now.tv_nsec - c->accept_ts.tv_nsec);
		AUTHORITYD_PROBE_CTL_CMD_DONE(c->req.op, c->euid,
		    c->reply.status, dur);
		action = c->action;
		/*
		 * Carry the lifecycle opcode out with the action so the
		 * dispatcher applies this connection's request, not one a
		 * concurrent connection may have overwritten.
		 */
		if (action & CTL_ACTION_LIFECYCLE)
			action |= (int)(c->req.op & 0xff) << CTL_ACTION_OP_SHIFT;
		conn_destroy(c);
	}

	return (action);
}

bool
ctl_is_conn_event(struct kevent *kev)
{
	struct ctl_conn *c;

	if (kev->filter == EVFILT_TIMER && kev->udata != NULL &&
	    ((uintptr_t)kev->ident & CTL_CONN_TIMER_BIT) != 0)
		return (true);

	if ((kev->filter == EVFILT_READ || kev->filter == EVFILT_WRITE) &&
	    kev->udata != NULL) {
		TAILQ_FOREACH(c, &conn_list, entry) {
			if (c == kev->udata)
				return (true);
		}
	}
	return (false);
}
