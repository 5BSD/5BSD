/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced control socket.
 *
 * Provides a unix domain socket at /var/run/serviced.sock for
 * administrative commands (status, reload, services).
 *
 * Each client connection is one-shot and fully nonblocking:
 * accept -> kqueue-driven read of request -> dispatch -> kqueue-
 * driven write of reply -> close.  No client can stall the
 * event loop.
 */

#include <sys/types.h>
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

#include "serviced.h"
#include "serviced_ctl.h"
#include "serviced_probes.h"

/* Module-private state. */
static int sctl_sock = -1;
static char sctl_path[PATH_MAX];

#define	SCTL_CONN_TIMEOUT_SEC	2
#define	SCTL_CONN_MAX		16

/*
 * Per-connection nonblocking state machine.
 *
 * Lifecycle: READING_HDR -> [READING_PAYLOAD ->] dispatch ->
 *            WRITING_REPLY -> [WRITING_SUMMARY ->] DONE.
 */
enum sctl_conn_state {
	SCTL_CONN_READING_HDR,
	SCTL_CONN_READING_PAYLOAD,
	SCTL_CONN_WRITING_REPLY,
	SCTL_CONN_WRITING_SUMMARY,
	SCTL_CONN_DONE
};

struct sctl_conn {
	TAILQ_ENTRY(sctl_conn)	entry;
	int			fd;
	uid_t			euid;
	enum sctl_conn_state	state;
	size_t			offset;

	struct sctl_request	req;
	struct sctl_reply	reply;
	char			summary[SERVICED_CTL_SUMMARY_MAX];
	uint32_t		summary_len;

	char			payload[SERVICED_CTL_MAX_PAYLOAD + 1];

	uintptr_t		timer_ident;
	struct timespec		accept_ts;	/* monotonic time at accept */
};

static TAILQ_HEAD(, sctl_conn) conn_list = TAILQ_HEAD_INITIALIZER(conn_list);
static unsigned nconns;
static uintptr_t conn_timer_next = 50000;
#define	SCTL_CONN_TIMER_BIT	((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 3))

/*
 * Format status summary.
 */
static void
sctl_cmd_status(struct sctl_reply *reply, char *summary, size_t sumlen)
{
	size_t off;
	unsigned i, nrunning, nstopped, nstarting, nstopping;
	static const char *state_names[] = {
		"stopped", "starting", "running", "stopping"
	};

	off = 0;
	nrunning = nstopped = nstarting = nstopping = 0;

	if (sd.services != NULL) {
		for (i = 0; i < sd.nservices; i++) {
			switch (sd.services[i].state) {
			case SVC_STATE_RUNNING:  nrunning++;  break;
			case SVC_STATE_STOPPED:  nstopped++;  break;
			case SVC_STATE_STARTING: nstarting++; break;
			case SVC_STATE_STOPPING: nstopping++; break;
			}
		}
	}

	BUF_APPEND(summary, sumlen, &off,
	    "serviced: running\n"
	    "services: %u loaded", sd.nservices);
	if (sd.nservices > 0)
		BUF_APPEND(summary, sumlen, &off,
		    " (%u running, %u stopped, %u starting, %u stopping)",
		    nrunning, nstopped, nstarting, nstopping);
	BUF_APPEND(summary, sumlen, &off, "\n");

	if (sd.nservices > 0) {
		BUF_APPEND(summary, sumlen, &off, "\n");
		for (i = 0; i < sd.nservices; i++) {
			struct svc_runtime *svc = &sd.services[i];
			const char *state;

			if ((unsigned)svc->state < nitems(state_names))
				state = state_names[svc->state];
			else
				state = "unknown";

			BUF_APPEND(summary, sumlen, &off,
			    "  %-20s %-8s", svc->manifest.label, state);

			if (svc->state == SVC_STATE_RUNNING ||
			    svc->state == SVC_STATE_STARTING) {
				if (svc->pid > 0)
					BUF_APPEND(summary, sumlen, &off,
					    " pid %jd", (intmax_t)svc->pid);
			}

			BUF_APPEND(summary, sumlen, &off, " restart=%s",
			    restart_policy_name(svc->manifest.restart));

			if (svc->restart_count > 0)
				BUF_APPEND(summary, sumlen, &off,
				    " restarts=%u", svc->restart_count);

			if (svc->launched_by[0] != '\0')
				BUF_APPEND(summary, sumlen, &off,
				    " by=%s", svc->launched_by);

			if (svc->connection_count > 0)
				BUF_APPEND(summary, sumlen, &off,
				    " conns=%u", svc->connection_count);

			BUF_APPEND(summary, sumlen, &off, "\n");
		}
	}

	reply->status = 0;
	reply->flags = (uint32_t)off;
}

/*
 * Destroy a connection, removing all kqueue registrations.
 */
static void
conn_destroy(struct sctl_conn *c)
{
	struct kevent kev;

	/* Remove kqueue filters. */
	EV_SET(&kev, c->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	(void)kevent(serviced_kq, &kev, 1, NULL, 0, NULL);
	EV_SET(&kev, c->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
	(void)kevent(serviced_kq, &kev, 1, NULL, 0, NULL);

	if (c->timer_ident != 0) {
		EV_SET(&kev, c->timer_ident, EVFILT_TIMER,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(serviced_kq, &kev, 1, NULL, 0, NULL);
	}

	close(c->fd);
	TAILQ_REMOVE(&conn_list, c, entry);
	nconns--;
	SERVICED_PROBE_CONN_CLOSE(nconns);
	free(c);
}

/*
 * Arm a one-shot timeout for a connection.
 */
static void
conn_arm_timeout(struct sctl_conn *c)
{
	struct kevent kev;

	c->timer_ident = SCTL_CONN_TIMER_BIT | conn_timer_next++;
	EV_SET(&kev, c->timer_ident, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS, SCTL_CONN_TIMEOUT_SEC, c);
	if (kevent(serviced_kq, &kev, 1, NULL, 0, NULL) == -1)
		syslog(LOG_WARNING, "sctl: conn timeout: %m");
}

/*
 * Dispatch the command.  Fills reply + summary, transitions to
 * writing, and switches the kqueue filter from read to write.
 */
static void
conn_dispatch(struct sctl_conn *c)
{
	struct sctl_request *req;
	struct sctl_reply *reply;
	struct kevent kev[2];

	req = &c->req;
	reply = &c->reply;
	memset(reply, 0, sizeof(*reply));
	c->summary[0] = '\0';
	c->summary_len = 0;

	if (req->version != SERVICED_CTL_VERSION) {
		reply->status = EPROTONOSUPPORT;
		goto write;
	}

	SERVICED_PROBE_SCTL_CMD(req->op, c->euid);

	switch (req->op) {
	case SCTL_OP_STATUS:
	case SCTL_OP_SERVICES:
	case SCTL_OP_RELOAD:
		/* Reject unexpected payloads on no-payload ops. */
		if (req->datalen != 0) {
			reply->status = EINVAL;
			snprintf(c->summary, sizeof(c->summary),
			    "unexpected payload for op %u", req->op);
			reply->flags = (uint32_t)strlen(c->summary);
			break;
		}
		if (req->op == SCTL_OP_STATUS || req->op == SCTL_OP_SERVICES) {
			sctl_cmd_status(reply, c->summary,
			    sizeof(c->summary));
			break;
		}
		/* SCTL_OP_RELOAD */
		if (c->euid != 0) {
			reply->status = EPERM;
			snprintf(c->summary, sizeof(c->summary),
			    "reload: permission denied");
			reply->flags = (uint32_t)strlen(c->summary);
			syslog(LOG_WARNING,
			    "sctl: reload denied uid %u", c->euid);
			SERVICED_PROBE_SCTL_DENY(req->op, c->euid);
		} else {
			if (supervisor_reload(serviced_kq,
			    c->summary, sizeof(c->summary)) == -1)
				reply->status = (uint32_t)-1;
			else
				reply->status = 0;
			reply->flags = (uint32_t)strlen(c->summary);
		}
		break;
	case SCTL_OP_CHECK:
	case SCTL_OP_LOAD:
		/*
		 * Legacy ops — superseded by bundle-based service
		 * management.  Use 'servicectl install' + 'reload'.
		 */
		reply->status = ENOTSUP;
		snprintf(c->summary, sizeof(c->summary),
		    "%s: use bundle install + reload",
		    req->op == SCTL_OP_CHECK ? "check" : "load");
		reply->flags = (uint32_t)strlen(c->summary);
		break;
	case SCTL_OP_STOP_SVC:
		if (c->euid != 0) {
			reply->status = EPERM;
			snprintf(c->summary, sizeof(c->summary),
			    "stop: permission denied");
			reply->flags = (uint32_t)strlen(c->summary);
			SERVICED_PROBE_SCTL_DENY(req->op, c->euid);
		} else if (req->datalen == 0) {
			reply->status = EINVAL;
			snprintf(c->summary, sizeof(c->summary),
			    "stop: missing service label");
			reply->flags = (uint32_t)strlen(c->summary);
		} else {
			struct svc_runtime *svc;
			unsigned si;

			svc = NULL;
			for (si = 0; si < sd.nservices; si++) {
				if (strcmp(sd.services[si].manifest.label,
				    c->payload) == 0) {
					svc = &sd.services[si];
					break;
				}
			}
			if (svc == NULL) {
				reply->status = ENOENT;
				snprintf(c->summary, sizeof(c->summary),
				    "stop: service \"%s\" not found",
				    c->payload);
			} else if (svc->state == SVC_STATE_STOPPED) {
				reply->status = EALREADY;
				snprintf(c->summary, sizeof(c->summary),
				    "stop: \"%s\" already stopped",
				    c->payload);
			} else if (svc->state == SVC_STATE_STOPPING) {
				reply->status = EALREADY;
				snprintf(c->summary, sizeof(c->summary),
				    "stop: \"%s\" already stopping",
				    c->payload);
			} else {
				svc_graceful_stop(svc, serviced_kq);
				reply->status = 0;
				snprintf(c->summary, sizeof(c->summary),
				    "stop: \"%s\" stopping", c->payload);
			}
			reply->flags = (uint32_t)strlen(c->summary);
		}
		break;
	default:
		reply->status = ENOTSUP;
		snprintf(c->summary, sizeof(c->summary),
		    "unknown op %u", req->op);
		reply->flags = (uint32_t)strlen(c->summary);
		break;
	}

write:
	if (reply->flags > 0)
		c->summary_len = reply->flags;

	c->state = SCTL_CONN_WRITING_REPLY;
	c->offset = 0;

	EV_SET(&kev[0], c->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	EV_SET(&kev[1], c->fd, EVFILT_WRITE, EV_ADD, 0, 0, c);
	(void)kevent(serviced_kq, kev, 2, NULL, 0, NULL);
}

/*
 * Handle partial reads: header first, then payload if needed.
 */
static void
conn_handle_read(struct sctl_conn *c)
{
	char *dst;
	size_t want;
	ssize_t n;

	switch (c->state) {
	case SCTL_CONN_READING_HDR:
		dst = (char *)&c->req + c->offset;
		want = sizeof(c->req) - c->offset;
		break;
	case SCTL_CONN_READING_PAYLOAD:
		dst = c->payload + c->offset;
		want = c->req.datalen - c->offset;
		break;
	default:
		c->state = SCTL_CONN_DONE;
		return;
	}

	n = read(c->fd, dst, want);
	if (n == -1) {
		if (errno == EINTR || errno == EAGAIN)
			return;
		c->state = SCTL_CONN_DONE;
		return;
	}
	if (n == 0) {
		c->state = SCTL_CONN_DONE;
		return;
	}

	c->offset += (size_t)n;

	if (c->state == SCTL_CONN_READING_HDR &&
	    c->offset == sizeof(c->req)) {
		if (c->req.datalen > SERVICED_CTL_MAX_PAYLOAD) {
			/* Reply with error before closing. */
			c->reply.status = EMSGSIZE;
			c->reply.flags = 0;
			c->summary_len = 0;
			c->state = SCTL_CONN_WRITING_REPLY;
			c->offset = 0;
			{
				struct kevent kev[2];

				EV_SET(&kev[0], c->fd, EVFILT_READ,
				    EV_DELETE, 0, 0, NULL);
				EV_SET(&kev[1], c->fd, EVFILT_WRITE,
				    EV_ADD | EV_CLEAR, 0, 0, c);
				kevent(serviced_kq, kev, 2, NULL, 0, NULL);
			}
			return;
		}
		if (c->req.datalen > 0) {
			c->state = SCTL_CONN_READING_PAYLOAD;
			c->offset = 0;
		} else {
			conn_dispatch(c);
		}
	} else if (c->state == SCTL_CONN_READING_PAYLOAD &&
	    c->offset == c->req.datalen) {
		c->payload[c->req.datalen] = '\0';
		conn_dispatch(c);
	}
}

/*
 * Handle partial writes: reply header first, then summary payload.
 */
static void
conn_handle_write(struct sctl_conn *c)
{
	const char *src;
	size_t total;
	ssize_t n;

	switch (c->state) {
	case SCTL_CONN_WRITING_REPLY:
		src = (const char *)&c->reply + c->offset;
		total = sizeof(c->reply);
		break;
	case SCTL_CONN_WRITING_SUMMARY:
		src = c->summary + c->offset;
		total = c->summary_len;
		break;
	default:
		c->state = SCTL_CONN_DONE;
		return;
	}

	n = write(c->fd, src, total - c->offset);
	if (n == -1) {
		if (errno == EINTR || errno == EAGAIN)
			return;
		c->state = SCTL_CONN_DONE;
		return;
	}
	if (n == 0) {
		c->state = SCTL_CONN_DONE;
		return;
	}

	c->offset += (size_t)n;

	if (c->state == SCTL_CONN_WRITING_REPLY &&
	    c->offset == sizeof(c->reply)) {
		if (c->summary_len > 0) {
			c->state = SCTL_CONN_WRITING_SUMMARY;
			c->offset = 0;
		} else {
			c->state = SCTL_CONN_DONE;
		}
	} else if (c->state == SCTL_CONN_WRITING_SUMMARY &&
	    c->offset == c->summary_len) {
		c->state = SCTL_CONN_DONE;
	}
}

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */

int
sctl_setup(void)
{
	struct sockaddr_un un;
	int fd;

	{
		const char *env_path;

		env_path = getenv("SERVICED_CONTROL_SOCKET");
		if (env_path != NULL && env_path[0] != '\0')
			strlcpy(sctl_path, env_path, sizeof(sctl_path));
		else
			strlcpy(sctl_path, SERVICED_CTL_SOCK,
			    sizeof(sctl_path));
	}

	fd = socket(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		syslog(LOG_ERR, "sctl: socket: %m");
		return (-1);
	}

	(void)unlink(sctl_path);

	memset(&un, 0, sizeof(un));
	un.sun_family = AF_LOCAL;
	strlcpy(un.sun_path, sctl_path, sizeof(un.sun_path));

	if (bind(fd, (struct sockaddr *)&un, sizeof(un)) == -1) {
		syslog(LOG_ERR, "sctl: bind %s: %m", sctl_path);
		close(fd);
		return (-1);
	}

	(void)chmod(sctl_path, 0700);

	if (listen(fd, 5) == -1) {
		syslog(LOG_ERR, "sctl: listen: %m");
		close(fd);
		(void)unlink(sctl_path);
		return (-1);
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		syslog(LOG_ERR, "sctl: fcntl: %m");
		close(fd);
		(void)unlink(sctl_path);
		return (-1);
	}

	sctl_sock = fd;
	syslog(LOG_INFO, "control socket: %s", sctl_path);
	return (0);
}

void
sctl_teardown(void)
{
	struct sctl_conn *c, *tmp;

	TAILQ_FOREACH_SAFE(c, &conn_list, entry, tmp)
		conn_destroy(c);

	if (sctl_sock >= 0) {
		close(sctl_sock);
		sctl_sock = -1;
		(void)unlink(sctl_path);
	}
}

int
sctl_fd(void)
{

	return (sctl_sock);
}

void
sctl_accept(void)
{
	struct sctl_conn *c;
	struct kevent kev;
	uid_t euid;
	gid_t egid;
	int cfd;

	cfd = accept4(sctl_sock, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (cfd == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			syslog(LOG_WARNING, "sctl: accept: %m");
		return;
	}

	if (nconns >= SCTL_CONN_MAX) {
		syslog(LOG_WARNING,
		    "sctl: too many connections, rejecting");
		close(cfd);
		return;
	}

	if (getpeereid(cfd, &euid, &egid) != 0) {
		syslog(LOG_WARNING, "sctl: getpeereid: %m");
		close(cfd);
		return;
	}

	c = calloc(1, sizeof(*c));
	if (c == NULL) {
		syslog(LOG_ERR, "sctl: calloc conn: %m");
		close(cfd);
		return;
	}

	c->fd = cfd;
	c->euid = euid;
	c->state = SCTL_CONN_READING_HDR;
	clock_gettime(CLOCK_MONOTONIC, &c->accept_ts);

	TAILQ_INSERT_TAIL(&conn_list, c, entry);
	nconns++;
	SERVICED_PROBE_CONN_ACCEPT(euid, nconns);

	EV_SET(&kev, cfd, EVFILT_READ, EV_ADD, 0, 0, c);
	if (kevent(serviced_kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_WARNING, "sctl: kevent register: %m");
		conn_destroy(c);
		return;
	}

	conn_arm_timeout(c);
}

void
sctl_conn_event(struct kevent *kev)
{
	struct sctl_conn *c;

	c = kev->udata;

	if (kev->filter == EVFILT_TIMER) {
		syslog(LOG_WARNING, "sctl: client timeout");
		c->timer_ident = 0;
		conn_destroy(c);
		return;
	}

	if (kev->flags & EV_EOF &&
	    c->state <= SCTL_CONN_READING_PAYLOAD) {
		conn_destroy(c);
		return;
	}

	if (kev->filter == EVFILT_READ)
		conn_handle_read(c);
	else if (kev->filter == EVFILT_WRITE)
		conn_handle_write(c);

	if (c->state == SCTL_CONN_DONE) {
		struct timespec now;
		uint64_t dur __unused;

		clock_gettime(CLOCK_MONOTONIC, &now);
		dur = (uint64_t)(now.tv_sec - c->accept_ts.tv_sec) *
		    1000000000ULL +
		    (uint64_t)(now.tv_nsec - c->accept_ts.tv_nsec);
		SERVICED_PROBE_SCTL_CMD_DONE(c->req.op, c->euid,
		    c->reply.status, dur);
		conn_destroy(c);
	}
}

bool
sctl_is_conn_event(struct kevent *kev)
{
	struct sctl_conn *c;

	if (kev->filter == EVFILT_TIMER && kev->udata != NULL &&
	    ((uintptr_t)kev->ident & SCTL_CONN_TIMER_BIT) != 0)
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
