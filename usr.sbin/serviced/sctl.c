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
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/mount.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "serviced.h"
#include "serviced_audit.h"
#include "serviced_ctl.h"
#include "serviced_svc_proto.h"
#include "fd_budget.h"
#include "management.h"
#include "serviced_probes.h"

/* Module-private state. */
static int sctl_sock = -1;
static char sctl_path[PATH_MAX];

#define	SCTL_CONN_TIMEOUT_SEC	2
#define	SCTL_CONN_MAX		16

static int
sctl_confine_fd(int fd)
{

	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

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

	/*
	 * A descriptor to attach to the reply header via SCM_RIGHTS (currently
	 * only SCTL_OP_PROVISION_SESSION's minted session channel), or -1 when
	 * the reply carries no descriptor.  fd_passed guards against a double
	 * send/close once the kernel has taken ownership.
	 */
	int			pass_fd;
	bool			fd_passed;

	uintptr_t		timer_ident;
	struct timespec		accept_ts;	/* monotonic time at accept */

	/*
	 * Capability control path (P3).  When is_capability is set this
	 * connection is not a socket stream but a libchannel provider endpoint
	 * that serviced minted for SERVICED_CONTROL_NAME; the socket state
	 * machine (state/offset/req/reply/summary/timer/pass_fd) is unused, and
	 * authorization gates on SVC_RIGHTS_ADMIN in cap_rights instead of euid.
	 */
	bool			is_capability;
	struct channel		*cap_channel;
	uint64_t		cap_rights;
};

static TAILQ_HEAD(, sctl_conn) conn_list = TAILQ_HEAD_INITIALIZER(conn_list);
static unsigned nconns;
static uintptr_t conn_timer_next = 50000;
#define	SCTL_CONN_TIMER_BIT	((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 3))

/*
 * Connection udata tagging.  Heap-allocated sctl_conn pointers are tagged
 * with a high bit so sctl_is_conn_event() can distinguish them from
 * svc_runtime udata in O(1) instead of scanning the connection list.
 */
#define	SCTL_CONN_TAG		((uintptr_t)1 << 63)
#define	SCTL_CONN_PTR(c)	((void *)((uintptr_t)(c) | SCTL_CONN_TAG))
#define	SCTL_IS_CONN(u)		(((uintptr_t)(u) & SCTL_CONN_TAG) != 0)
#define	SCTL_GET_CONN(u)	((struct sctl_conn *)((uintptr_t)(u) & ~SCTL_CONN_TAG))

/*
 * Format status summary.
 */
static void
sctl_cmd_status(struct sctl_reply *reply, char *summary, size_t sumlen)
{
	struct serviced_fd_budget_stats fd_stats;
	size_t off;
	unsigned i, ndone, nrunning, nstopped, nstarting, nstopping;
	static const char *state_names[] = {
		"stopped", "starting", "running", "stopping", "done"
	};

	off = 0;
	ndone = nrunning = nstopped = nstarting = nstopping = 0;

	if (sd.services != NULL) {
		for (i = 0; i < sd.nservices; i++) {
			switch (sd.services[i].state) {
			case SVC_STATE_RUNNING:  nrunning++;  break;
			case SVC_STATE_STOPPED:  nstopped++;  break;
			case SVC_STATE_STARTING: nstarting++; break;
			case SVC_STATE_STOPPING: nstopping++; break;
			case SVC_STATE_DONE:     ndone++;     break;
			}
		}
	}

	BUF_APPEND(summary, sumlen, &off,
	    "serviced: running\n"
	    "services: %u loaded", sd.nservices);
	if (sd.nservices > 0)
		BUF_APPEND(summary, sumlen, &off,
		    " (%u running, %u stopped, %u starting, %u stopping, "
		    "%u done)", nrunning, nstopped, nstarting, nstopping,
		    ndone);
	BUF_APPEND(summary, sumlen, &off, "\n");
	serviced_fd_budget_get_stats(&fd_stats);
	BUF_APPEND(summary, sumlen, &off,
	    "fd-budget: soft=%ju hard=%ju reserve=%zu denied=%ju "
	    "control-shed=%ju\n",
	    (uintmax_t)fd_stats.soft_limit, (uintmax_t)fd_stats.hard_limit,
	    fd_stats.reserve_count,
	    (uintmax_t)fd_stats.admission_denied,
	    (uintmax_t)fd_stats.control_shed);

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

			BUF_APPEND(summary, sumlen, &off, " mgmt=%s",
			    svc_management_name(svc->manifest.management));

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

	/*
	 * Capability control connection: the read/write filters are keyed on the
	 * channel fd, and channel_destroy() closes that fd.  None of the socket
	 * stream state (timer, pass_fd) applies.
	 */
	if (c->is_capability) {
		EV_SET(&kev, c->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		(void)kevent(serviced_kq, &kev, 1, NULL, 0, NULL);
		EV_SET(&kev, c->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
		(void)kevent(serviced_kq, &kev, 1, NULL, 0, NULL);
		if (c->cap_channel != NULL)
			channel_destroy(c->cap_channel);
		TAILQ_REMOVE(&conn_list, c, entry);
		nconns--;
		SERVICED_PROBE_CONN_CLOSE(nconns);
		free(c);
		return;
	}

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

	/*
	 * Drop an unsent minted descriptor.  If the reply's SCM_RIGHTS send
	 * already handed it to the kernel (fd_passed), the kernel owns it and
	 * pass_fd was cleared; otherwise (an aborted or timed-out connection)
	 * close our copy so the minted channel does not leak — serviced's own
	 * end then sees EOF and reaps the lookup-channel registration.
	 */
	if (c->pass_fd >= 0 && !c->fd_passed)
		close(c->pass_fd);

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
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS, SCTL_CONN_TIMEOUT_SEC,
	    SCTL_CONN_PTR(c));
	if (kevent(serviced_kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_WARNING, "sctl: conn timeout: %m");
		/* Timer was not armed; clear the ident so conn_destroy does
		 * not try to delete a nonexistent timer and the connection
		 * state honestly reflects that it has no timeout. */
		c->timer_ident = 0;
	}
}

/*
 * Execute a transport-neutral control operation — the fd-less ops shared by the
 * socket path and the capability control path: STATUS, SERVICES, RELOAD, START,
 * STOP.  is_admin is the caller's already-made authorization decision (the socket
 * path passes peer-euid == 0; the capability path passes SVC_RIGHTS_ADMIN held on
 * the grant); audit_uid is what the audit trail records (the socket peer euid, or
 * (uid_t)-1 for a capability caller whose authority is the held right, not a uid).
 * Fills reply->status and reply->flags (the summary length) and up to summary_cap
 * bytes of summary text.  PROVISION_SESSION (fd-passing) and unknown ops are the
 * caller's responsibility, not handled here.
 */
static void
sctl_execute_op(uint32_t op, const char *payload, uint32_t datalen,
    bool is_admin, uid_t audit_uid, struct sctl_reply *reply,
    char *summary, size_t summary_cap)
{

	summary[0] = '\0';
	reply->status = 0;
	reply->flags = 0;

	switch (op) {
	case SCTL_OP_STATUS:
	case SCTL_OP_SERVICES:
	case SCTL_OP_RELOAD:
		if (datalen != 0) {
			reply->status = EINVAL;
			snprintf(summary, summary_cap,
			    "unexpected payload for op %u", op);
			break;
		}
		if (op == SCTL_OP_STATUS || op == SCTL_OP_SERVICES) {
			sctl_cmd_status(reply, summary, summary_cap);
			break;
		}
		/* SCTL_OP_RELOAD */
		if (!is_admin) {
			reply->status = EPERM;
			snprintf(summary, summary_cap,
			    "reload: permission denied");
			syslog(LOG_WARNING, "sctl: reload denied uid %u",
			    (unsigned)audit_uid);
			SERVICED_PROBE_SCTL_DENY(op, audit_uid);
			serviced_audit(AUE_SERVICED_CTL, audit_uid, EPERM,
			    "reload denied");
		} else if (supervisor_reload(serviced_kq, summary,
		    summary_cap) == -1) {
			reply->status = EIO;
			serviced_audit(AUE_SERVICED_CTL, audit_uid, EIO,
			    "reload failed");
		} else {
			reply->status = 0;
			serviced_audit(AUE_SERVICED_CTL, audit_uid, 0,
			    "reload: %s", summary);
		}
		break;
	case SCTL_OP_START_SVC:
		if (!is_admin) {
			reply->status = EPERM;
			snprintf(summary, summary_cap,
			    "start: permission denied");
			SERVICED_PROBE_SCTL_DENY(op, audit_uid);
			serviced_audit(AUE_SERVICED_CTL, audit_uid, EPERM,
			    "start denied");
		} else if (datalen == 0) {
			reply->status = EINVAL;
			snprintf(summary, summary_cap,
			    "start: missing service label");
		} else {
			struct svc_runtime *svc;
			int error;

			svc = svc_by_label(payload);
			if (svc == NULL) {
				reply->status = ENOENT;
				snprintf(summary, summary_cap,
				    "start: service \"%s\" not found", payload);
			} else if (svc->state != SVC_STATE_STOPPED &&
			    svc->state != SVC_STATE_DONE) {
				reply->status = EALREADY;
				snprintf(summary, summary_cap,
				    "start: \"%s\" is not stopped", payload);
			} else {
				svc_cancel_restart(svc, serviced_kq);
				svc->state = SVC_STATE_STOPPED;
				svc->restart_count = 0;
				svc->lookup_activated = false;
				strlcpy(svc->launched_by, "operator",
				    sizeof(svc->launched_by));
				error = svc_exec(svc, serviced_kq) == -1 ?
				    (errno != 0 ? errno : EIO) : 0;
				reply->status = error;
				if (error == 0)
					snprintf(summary, summary_cap,
					    "start: \"%s\" starting", payload);
				else
					snprintf(summary, summary_cap,
					    "start: \"%s\" failed: %s", payload,
					    strerror(error));
				serviced_audit(AUE_SERVICED_CTL, audit_uid,
				    error, "start svc=%s", payload);
			}
		}
		break;
	case SCTL_OP_STOP_SVC:
		if (!is_admin) {
			reply->status = EPERM;
			snprintf(summary, summary_cap,
			    "stop: permission denied");
			SERVICED_PROBE_SCTL_DENY(op, audit_uid);
			serviced_audit(AUE_SERVICED_CTL, audit_uid, EPERM,
			    "stop denied");
		} else if (datalen == 0) {
			reply->status = EINVAL;
			snprintf(summary, summary_cap,
			    "stop: missing service label");
		} else {
			struct svc_runtime *svc;
			unsigned si;

			svc = NULL;
			for (si = 0; si < sd.nservices; si++) {
				if (strcmp(sd.services[si].manifest.label,
				    payload) == 0) {
					svc = &sd.services[si];
					break;
				}
			}
			if (svc == NULL) {
				reply->status = ENOENT;
				snprintf(summary, summary_cap,
				    "stop: service \"%s\" not found", payload);
			} else if (svc_management_check_op(svc, "stopped") != 0) {
				/*
				 * Absolute management-class rule (§5): a core
				 * unit cannot be stopped at runtime, not even with
				 * the admin right.  svc_management_check_op() has
				 * already logged the refusal.
				 */
				reply->status = EPERM;
				snprintf(summary, summary_cap,
				    "stop: \"%s\" is management class core and "
				    "cannot be stopped at runtime", payload);
				SERVICED_PROBE_SCTL_DENY(op, audit_uid);
				serviced_audit(AUE_SERVICED_CTL, audit_uid, EPERM,
				    "stop denied (core) svc=%s", payload);
			} else if (svc->state == SVC_STATE_STOPPED) {
				reply->status = EALREADY;
				snprintf(summary, summary_cap,
				    "stop: \"%s\" already stopped", payload);
			} else if (svc->state == SVC_STATE_STOPPING) {
				reply->status = EALREADY;
				snprintf(summary, summary_cap,
				    "stop: \"%s\" already stopping", payload);
			} else {
				svc_graceful_stop(svc, serviced_kq);
				reply->status = 0;
				snprintf(summary, summary_cap,
				    "stop: \"%s\" stopping", payload);
				serviced_audit(AUE_SERVICED_CTL, audit_uid, 0,
				    "stop svc=%s", payload);
			}
		}
		break;
	default:
		reply->status = ENOTSUP;
		snprintf(summary, summary_cap, "unknown op %u", op);
		break;
	}

	reply->flags = (uint32_t)strlen(summary);
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
	if (req->flags != 0 ||
	    (req->datalen > 0 && memchr(c->payload, '\0', req->datalen) != NULL)) {
		reply->status = EINVAL;
		snprintf(c->summary, sizeof(c->summary),
		    "invalid control request encoding");
		reply->flags = (uint32_t)strlen(c->summary);
		goto write;
	}

	/*
	 * The privileged ops (reload/start/stop) are gated on the peer euid here
	 * only for socket callers; the capability control path (sctl_cap_request,
	 * SERVICED_CONTROL_NAME) runs the SAME sctl_execute_op() gated on the
	 * SVC_RIGHTS_ADMIN held on its grant, which is the successor authority
	 * (docs/capability-authority-model.md, P3).  PROVISION_SESSION stays
	 * socket-only and kernel-attested until the lifecycle phase (P4).
	 */
	SERVICED_PROBE_SCTL_CMD(req->op, c->euid);

	switch (req->op) {
	case SCTL_OP_STATUS:
	case SCTL_OP_SERVICES:
	case SCTL_OP_RELOAD:
	case SCTL_OP_START_SVC:
	case SCTL_OP_STOP_SVC:
		sctl_execute_op(req->op, c->payload, req->datalen,
		    c->euid == 0, c->euid, reply, c->summary,
		    sizeof(c->summary));
		break;
	case SCTL_OP_PROVISION_SESSION:
		/*
		 * Socket-authenticated session provisioning (§21/§22, item 4).
		 * AUTH (security boundary): the getpeereid(3) peer euid captured
		 * at accept time (c->euid) MUST be root — provisioning speaks for
		 * an arbitrary target uid, so a non-root caller is refused with
		 * EPERM and NO descriptor.  On success the minted channel is
		 * scoped by the TARGET uid (root/wheel -> SYSTEM admin, else USER)
		 * and stashed in c->pass_fd for the reply's SCM_RIGHTS send; after
		 * the send serviced closes its own copy (fd_passed).  A mint
		 * failure is a plain error reply — serviced never crashes.
		 */
		if (c->euid != 0) {
			reply->status = EPERM;
			snprintf(c->summary, sizeof(c->summary),
			    "provision: permission denied");
			SERVICED_PROBE_SCTL_DENY(req->op, c->euid);
			serviced_audit(AUE_SERVICED_CTL, c->euid, EPERM,
			    "provision denied (non-root)");
		} else if (req->datalen == 0) {
			reply->status = EINVAL;
			snprintf(c->summary, sizeof(c->summary),
			    "provision: missing target uid");
		} else {
			char *endp;
			unsigned long val;
			uid_t target;
			int provisioned, perr;

			errno = 0;
			val = strtoul(c->payload, &endp, 10);
			if (endp == c->payload || *endp != '\0' ||
			    (val == ULONG_MAX && errno == ERANGE) ||
			    val > (unsigned long)UID_MAX) {
				reply->status = EINVAL;
				snprintf(c->summary, sizeof(c->summary),
				    "provision: malformed target uid");
			} else {
				target = (uid_t)val;
				provisioned = -1;
				if (domain_provision_session(c->euid, target,
				    &provisioned, serviced_kq) == -1) {
					perr = errno != 0 ? errno : EIO;
					reply->status = perr;
					snprintf(c->summary, sizeof(c->summary),
					    "provision: uid %u failed: %s",
					    (unsigned)target, strerror(perr));
					serviced_audit(AUE_SERVICED_CTL,
					    c->euid, perr,
					    "provision uid=%u failed",
					    (unsigned)target);
				} else {
					c->pass_fd = provisioned;
					reply->status = 0;
					/*
					 * Success carries the fd via SCM_RIGHTS
					 * and no summary text (flags stays 0).
					 */
					c->summary[0] = '\0';
					serviced_audit(AUE_SERVICED_CTL,
					    c->euid, 0,
					    "provision uid=%u", (unsigned)target);
				}
			}
		}
		reply->flags = (uint32_t)strlen(c->summary);
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
	EV_SET(&kev[1], c->fd, EVFILT_WRITE, EV_ADD, 0, 0, SCTL_CONN_PTR(c));
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
				/* Level-triggered, matching the normal reply
				 * path above; the edge-triggered EV_CLEAR could
				 * stall a short reply that hits EAGAIN. */
				EV_SET(&kev[1], c->fd, EVFILT_WRITE,
				    EV_ADD, 0, 0,
				    SCTL_CONN_PTR(c));
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
 * Send the reply header carrying a descriptor via SCM_RIGHTS.  Used only while
 * writing the fixed-size reply of an op that provisions a descriptor
 * (SCTL_OP_PROVISION_SESSION).  The descriptor is delivered with whatever data
 * bytes this single sendmsg(2) transmits — the reply is 8 bytes and goes in one
 * shot on a local stream socket — so the caller marks it passed on the first
 * successful send and any residual reply bytes then go via plain write(2).
 */
static ssize_t
conn_send_reply_fd(struct sctl_conn *c, const char *src, size_t len)
{
	struct msghdr msg;
	struct iovec iov;
	union {
		struct cmsghdr	align;
		char		buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	struct cmsghdr *cmsg;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = __DECONST(void *, src);
	iov.iov_len = len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memset(&cmsgbuf, 0, sizeof(cmsgbuf));
	msg.msg_control = cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &c->pass_fd, sizeof(int));
	msg.msg_controllen = cmsg->cmsg_len;
	return (sendmsg(c->fd, &msg, 0));
}

/*
 * Handle partial writes: reply header first, then summary payload.
 */
static void
conn_handle_write(struct sctl_conn *c)
{
	const char *src;
	size_t total;
	bool sending_fd;
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

	/*
	 * Attach the provisioned descriptor to the very first bytes of the
	 * reply header; every later byte (reply residue or summary) is plain.
	 */
	sending_fd = (c->state == SCTL_CONN_WRITING_REPLY &&
	    c->pass_fd >= 0 && !c->fd_passed);
	if (sending_fd)
		n = conn_send_reply_fd(c, src, total - c->offset);
	else
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

	/*
	 * The descriptor rides the ancillary data of this sendmsg regardless of
	 * how many payload bytes it carried, so once any bytes are out the kernel
	 * owns the fd: mark it passed and drop serviced's copy.  Residual reply
	 * bytes fall through to plain write(2) on the next writable event.
	 */
	if (sending_fd) {
		c->fd_passed = true;
		(void)close(c->pass_fd);
		c->pass_fd = -1;
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
 * Capability control path (P3)
 *
 * serviced self-serves SERVICED_CONTROL_NAME over the discovery plane.  A lookup
 * from an admin login session (see naming_lookup) mints a channel pair whose
 * grant carries SVC_RIGHTS_ADMIN; serviced adopts the provider end here and runs
 * the shared sctl_execute_op() gated on that right — the capability successor to
 * the socket's getpeereid euid.  The request/reply are single libchannel messages
 * (no SCM_RIGHTS): a request is [sctl_request][payload], a reply is
 * [sctl_reply][summary].
 * ---------------------------------------------------------------- */

/*
 * Enable/disable the write filter to match the channel's queued-output state.
 */
static void
sctl_cap_sync_events(struct sctl_conn *c)
{
	struct kevent change;
	int wants;

	if (c->cap_channel == NULL || c->fd < 0)
		return;
	wants = channel_wants_write(c->cap_channel);
	if (wants == -1)
		return;
	EV_SET(&change, c->fd, EVFILT_WRITE,
	    EV_ADD | (wants ? EV_ENABLE : EV_DISABLE), 0, 0, SCTL_CONN_PTR(c));
	(void)kevent(serviced_kq, &change, 1, NULL, 0, NULL);
}

/*
 * libchannel request handler for the capability control channel.
 */
static void
sctl_cap_request(struct channel *ch __unused, struct channel_message *request,
    void *arg)
{
	struct sctl_conn *c = arg;
	const struct sctl_request *req;
	const void *data;
	size_t len;
	struct sctl_reply reply;
	char summary[SERVICED_CTL_SUMMARY_MAX];
	char payload[SERVICED_CTL_MAX_PAYLOAD + 1];
	char out[sizeof(struct sctl_reply) + SERVICED_CTL_SUMMARY_MAX];

	memset(&reply, 0, sizeof(reply));
	summary[0] = '\0';
	data = channel_message_data(request);
	len = channel_message_length(request);

	if (data == NULL || len < sizeof(*req)) {
		reply.status = EINVAL;
	} else {
		req = data;
		if (req->version != SERVICED_CTL_VERSION) {
			reply.status = EPROTONOSUPPORT;
		} else if (req->flags != 0 ||
		    req->datalen > SERVICED_CTL_MAX_PAYLOAD ||
		    len != sizeof(*req) + (size_t)req->datalen ||
		    (req->datalen > 0 &&
		    memchr((const char *)data + sizeof(*req), '\0',
		    req->datalen) != NULL)) {
			reply.status = EINVAL;
			snprintf(summary, sizeof(summary),
			    "invalid control request encoding");
		} else {
			bool is_admin = (c->cap_rights & SVC_RIGHTS_ADMIN) != 0;

			memcpy(payload, (const char *)data + sizeof(*req),
			    req->datalen);
			payload[req->datalen] = '\0';
			SERVICED_PROBE_SCTL_CMD(req->op, (uid_t)-1);
			switch (req->op) {
			case SCTL_OP_STATUS:
			case SCTL_OP_SERVICES:
			case SCTL_OP_RELOAD:
			case SCTL_OP_START_SVC:
			case SCTL_OP_STOP_SVC:
				/*
				 * Authority is the held right, not a uid; the
				 * audit uid is (uid_t)-1 for a capability caller.
				 */
				sctl_execute_op(req->op, payload, req->datalen,
				    is_admin, (uid_t)-1, &reply, summary,
				    sizeof(summary));
				break;
			case SCTL_OP_PROVISION_SESSION:
				/* Kernel-attested, socket-only until P4. */
				reply.status = ENOTSUP;
				snprintf(summary, sizeof(summary),
				    "provision-session is not served over the "
				    "capability control plane");
				break;
			default:
				reply.status = ENOTSUP;
				snprintf(summary, sizeof(summary),
				    "unknown op %u", req->op);
				break;
			}
		}
	}
	reply.flags = (uint32_t)strlen(summary);

	memcpy(out, &reply, sizeof(reply));
	if (reply.flags > 0)
		memcpy(out + sizeof(reply), summary, reply.flags);
	if (channel_send_reply(request,
	    &(struct channel_outgoing){
		.size = sizeof(struct channel_outgoing),
		.data = out,
		.length = sizeof(reply) + reply.flags,
		.fds = NULL,
		.nfds = 0
	    }) == -1)
		syslog(LOG_WARNING, "sctl: capability control reply: %m");
	sctl_cap_sync_events(c);
}

int
sctl_adopt_channel(int provider_fd, uint64_t rights)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct sctl_conn *c;
	struct kevent kev;
	int error;

	if (provider_fd < 0) {
		errno = EINVAL;
		return (-1);
	}
	if (serviced_fd_budget_check(1, "capability control connection") == -1) {
		error = errno;
		close(provider_fd);
		errno = error;
		return (-1);
	}
	if (nconns >= SCTL_CONN_MAX) {
		syslog(LOG_WARNING,
		    "sctl: too many control connections, rejecting capability");
		close(provider_fd);
		errno = ENOSPC;
		return (-1);
	}
	c = calloc(1, sizeof(*c));
	if (c == NULL) {
		error = errno;
		close(provider_fd);
		errno = error;
		return (-1);
	}
	options.max_pending_requests = 8;
	options.max_queued_messages = 32;
	options.max_queued_bytes = 256 * 1024;
	options.max_queued_fds = 0;
	if (channel_create(provider_fd, &options, &c->cap_channel) == -1) {
		error = errno;
		free(c);
		close(provider_fd);
		errno = error;
		return (-1);
	}
	c->is_capability = true;
	c->cap_rights = rights;
	c->pass_fd = -1;
	c->fd = channel_fd(c->cap_channel);
	if (channel_set_request_handler(c->cap_channel, sctl_cap_request,
	    c) == -1) {
		error = errno;
		channel_destroy(c->cap_channel);
		free(c);
		errno = error;
		return (-1);
	}
	TAILQ_INSERT_TAIL(&conn_list, c, entry);
	nconns++;
	EV_SET(&kev, c->fd, EVFILT_READ, EV_ADD, 0, 0, SCTL_CONN_PTR(c));
	if (kevent(serviced_kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_WARNING, "sctl: capability kevent register: %m");
		conn_destroy(c);
		return (-1);
	}
	SERVICED_PROBE_CONN_ACCEPT((uid_t)-1, nconns);
	syslog(LOG_INFO,
	    "capability control connection adopted (%s)",
	    (rights & SVC_RIGHTS_ADMIN) != 0 ? "admin" : "unprivileged");
	return (0);
}

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */

/*
 * Back serviced's control-socket directory with a private tmpfs, so the socket
 * node is memory-resident: no ZFS snapshot or `zfs send -R` backup can capture
 * it, and a reboot leaves no stale node to fight the next bind.  Idempotent and
 * best-effort — if the mount fails serviced still binds on the plain directory.
 * Only used for the default path; a SERVICED_CONTROL_SOCKET override (tests)
 * is left exactly where the caller put it.
 */
static void
ensure_socket_home(const char *sockpath)
{
	struct statfs sfs;
	struct iovec iov[4];
	char dir[PATH_MAX], *slash;

	if (strlcpy(dir, sockpath, sizeof(dir)) >= sizeof(dir))
		return;
	slash = strrchr(dir, '/');
	if (slash == NULL || slash == dir)
		return;
	*slash = '\0';
	if (mkdir(dir, 0755) == -1 && errno != EEXIST) {
		syslog(LOG_WARNING, "sctl: mkdir %s: %m", dir);
		return;
	}
	/* Already our tmpfs? (serviced restart) — nothing to do. */
	if (statfs(dir, &sfs) == 0 &&
	    strcmp(sfs.f_fstypename, "tmpfs") == 0 &&
	    strcmp(sfs.f_mntonname, dir) == 0)
		return;
	iov[0].iov_base = __DECONST(void *, "fstype");
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = __DECONST(void *, "tmpfs");
	iov[1].iov_len = sizeof("tmpfs");
	iov[2].iov_base = __DECONST(void *, "fspath");
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = dir;
	iov[3].iov_len = strlen(dir) + 1;
	if (nmount(iov, 4, 0) == -1)
		syslog(LOG_WARNING,
		    "sctl: tmpfs on %s: %m (binding on plain dir)", dir);
}

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
		else {
			strlcpy(sctl_path, SERVICED_CTL_SOCK,
			    sizeof(sctl_path));
			ensure_socket_home(sctl_path);
		}
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

	(void)chmod(sctl_path, 0770);

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
	if (sctl_confine_fd(fd) == -1) {
		syslog(LOG_ERR, "sctl: socket confinement: %m");
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

	if (serviced_fd_budget_check(1, "control connection") == -1) {
		serviced_fd_budget_shed_control(sctl_sock);
		return;
	}
	cfd = accept4(sctl_sock, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (cfd == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			syslog(LOG_WARNING, "sctl: accept: %m");
		return;
	}
	if (sctl_confine_fd(cfd) == -1) {
		syslog(LOG_WARNING, "sctl: client confinement: %m");
		close(cfd);
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
	c->pass_fd = -1;	/* calloc gives 0, a valid fd; force "none" */
	c->fd_passed = false;
	clock_gettime(CLOCK_MONOTONIC, &c->accept_ts);

	TAILQ_INSERT_TAIL(&conn_list, c, entry);
	nconns++;
	SERVICED_PROBE_CONN_ACCEPT(euid, nconns);

	EV_SET(&kev, cfd, EVFILT_READ, EV_ADD, 0, 0, SCTL_CONN_PTR(c));
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

	c = SCTL_GET_CONN(kev->udata);

	/*
	 * Capability control connection: driven by libchannel, not the socket
	 * stream state machine.  A read dispatches queued requests (invoking
	 * sctl_cap_request); a write flushes queued replies; EOF tears it down.
	 */
	if (c->is_capability) {
		if (kev->flags & EV_EOF) {
			conn_destroy(c);
			return;
		}
		if (kev->filter == EVFILT_WRITE) {
			if (channel_flush(c->cap_channel) == -1) {
				conn_destroy(c);
				return;
			}
		} else if (kev->filter == EVFILT_READ) {
			if (channel_dispatch(c->cap_channel) == -1) {
				conn_destroy(c);
				return;
			}
		}
		sctl_cap_sync_events(c);
		return;
	}

	if (kev->filter == EVFILT_TIMER) {
		syslog(LOG_WARNING, "sctl: client timeout");
		c->timer_ident = 0;
		conn_destroy(c);
		return;
	}

	if (kev->flags & EV_EOF &&
	    c->state <= SCTL_CONN_READING_PAYLOAD) {
		/*
		 * The peer half-closed while we are still reading its request.
		 * kqueue can deliver EV_EOF in the same event as buffered
		 * readable data (kev->data > 0) — a well-behaved one-shot
		 * client may write() its request and immediately
		 * shutdown(SHUT_WR)/close().  Drain the buffered bytes so a
		 * fully-arrived request is dispatched rather than silently
		 * dropped with no reply.  conn_handle_read() consumes one
		 * segment (header, then payload) per call, so loop until it
		 * stops making progress.
		 */
		if (kev->filter == EVFILT_READ && kev->data > 0) {
			enum sctl_conn_state prev_state;
			size_t prev_off;

			do {
				prev_state = c->state;
				prev_off = c->offset;
				conn_handle_read(c);
			} while (c->state <= SCTL_CONN_READING_PAYLOAD &&
			    (c->state != prev_state || c->offset != prev_off));
		}
		if (c->state <= SCTL_CONN_READING_PAYLOAD ||
		    c->state == SCTL_CONN_DONE) {
			/* No complete request arrived (or it errored). */
			conn_destroy(c);
			return;
		}
		/*
		 * A complete request was assembled and dispatched;
		 * conn_dispatch() armed the write filter.  The reply is sent
		 * when the socket is writable (the peer's SHUT_WR closed only
		 * its write side), and CMD_DONE + destroy fire then.
		 */
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

	if (kev->udata == NULL)
		return (false);

	/*
	 * Connection udata is tagged with SCTL_CONN_TAG, allowing O(1)
	 * discrimination from svc_runtime pointers.  Timer events also
	 * use tagged udata, but we check ident-based SCTL_CONN_TIMER_BIT
	 * for backward compatibility with any untagged timer idents.
	 */
	if (kev->filter == EVFILT_TIMER &&
	    ((uintptr_t)kev->ident & SCTL_CONN_TIMER_BIT) != 0)
		return (true);

	return (SCTL_IS_CONN(kev->udata));
}
