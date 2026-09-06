/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced capability control plane.
 *
 * serviced self-serves the "system.serviced" (control) and "system.lifecycle"
 * discovery names over the ambient plane; an admin login session's lookup
 * mints a channel whose grant carries SVC_RIGHTS_ADMIN, and serviced adopts the
 * provider end here (sctl_adopt_channel).  Administrative commands (status,
 * reload, services, start, stop) arrive as single libchannel request/reply
 * messages and are authorized by the held ADMIN right — never a peer uid.  The
 * getpeereid(2) unix-domain control socket this file used to bind was retired
 * (docs/capability-authority-model.md).
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
#include "authorityd_ctl.h"
#include "fd_budget.h"
#include "management.h"
#include "serviced_probes.h"

/* Module-private state. */

#define	SCTL_CONN_MAX		16

/*
 * A control connection.  Since the getpeereid(2) control socket was retired
 * (docs/capability-authority-model.md), every control connection is a libchannel
 * provider endpoint serviced minted for SERVICED_CONTROL_NAME (system.serviced)
 * or SERVICED_LIFECYCLE_NAME (system.lifecycle).  Authority is the held
 * SVC_RIGHTS_ADMIN right on cap_rights (P3), never a peer uid.
 */
struct sctl_conn {
	TAILQ_ENTRY(sctl_conn)	entry;
	int			fd;		/* the channel fd (kqueue key) */
	struct channel		*cap_channel;
	uint64_t		cap_rights;
};

static TAILQ_HEAD(, sctl_conn) conn_list = TAILQ_HEAD_INITIALIZER(conn_list);
static unsigned nconns;

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
	 * The read/write filters are keyed on the channel fd, and
	 * channel_destroy() closes that fd.
	 */
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
	case SCTL_OP_RECLAIM:
		/*
		 * Retire an uninstalled bundle label
		 * (docs/capability-lifecycle-cleanup.md): broadcast a best-effort
		 * SVC_OP_RECLAIM_LABEL to every running provider so any that holds
		 * persistent per-label state drops it.  The pkg deinstall hook is
		 * the only intended caller; it runs as root over the ADMIN control
		 * plane.  ADMIN-gated exactly like start/stop.
		 */
		if (!is_admin) {
			reply->status = EPERM;
			snprintf(summary, summary_cap,
			    "reclaim: permission denied");
			SERVICED_PROBE_SCTL_DENY(op, audit_uid);
			serviced_audit(AUE_SERVICED_CTL, audit_uid, EPERM,
			    "reclaim denied");
		} else if (datalen == 0) {
			reply->status = EINVAL;
			snprintf(summary, summary_cap,
			    "reclaim: missing bundle label");
		} else if (datalen > sizeof(((struct svc_reclaim_label_msg *)
		    0)->label) - 1) {
			/* Must fit the reclaim message's label[64] with its NUL. */
			reply->status = EINVAL;
			snprintf(summary, summary_cap,
			    "reclaim: bundle label too long");
		} else {
			unsigned sent;

			sent = svc_retire_label(payload, serviced_kq);
			reply->status = 0;
			snprintf(summary, summary_cap,
			    "reclaim %s: broadcast to %u providers\n",
			    payload, sent);
			serviced_audit(AUE_SERVICED_CTL, audit_uid, 0,
			    "reclaim %s", payload);
		}
		break;
	default:
		reply->status = ENOTSUP;
		snprintf(summary, summary_cap, "unknown op %u", op);
		break;
	}

	reply->flags = (uint32_t)strlen(summary);
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
			case SCTL_OP_RECLAIM:
				/*
				 * Authority is the held right, not a uid; the
				 * audit uid is (uid_t)-1 for a capability caller.
				 */
				sctl_execute_op(req->op, payload, req->datalen,
				    is_admin, (uid_t)-1, &reply, summary,
				    sizeof(summary));
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

/*
 * Request handler for a system.lifecycle capability connection (P4b): relay an
 * authorized lifecycle op to authorityd.  authorityctl(8) speaks the same
 * ctl_request/CTL_OP_* protocol the legacy authorityd socket used, now carried
 * over an ADMIN-gated capability channel and forwarded to the spine.
 */
static void
sctl_authority_request(struct channel *ch __unused,
    struct channel_message *request, void *arg)
{
	struct sctl_conn *c = arg;
	const struct ctl_request *req;
	struct ctl_reply reply;
	char summary[SERVICED_CTL_SUMMARY_MAX];
	char out[sizeof(struct ctl_reply) + SERVICED_CTL_SUMMARY_MAX];
	const void *data;
	size_t len;
	int status;

	memset(&reply, 0, sizeof(reply));
	summary[0] = '\0';
	data = channel_message_data(request);
	len = channel_message_length(request);

	if (data == NULL || len != sizeof(*req)) {
		reply.status = EINVAL;
	} else {
		req = data;
		if (req->version != CTL_VERSION || req->flags != 0 ||
		    req->datalen != 0) {
			reply.status = EINVAL;
		} else if ((c->cap_rights & SVC_RIGHTS_ADMIN) == 0) {
			reply.status = EPERM;
		} else {
			switch (req->op) {
			case CTL_OP_REBOOT:
			case CTL_OP_HALT:
			case CTL_OP_POWEROFF:
			case CTL_OP_POWERCYCLE:
			case CTL_OP_SINGLE:
			case CTL_OP_REROOT:
			case CTL_OP_RESCAN:
			case CTL_OP_CATATONIA:
				status = authority_lifecycle(sd.authority_channel_fd,
				    req->op);
				reply.status = (status < 0) ? EIO :
				    (uint32_t)status;
				if (reply.status == 0)
					syslog(LOG_NOTICE, "sctl: relayed "
					    "lifecycle op %u to authority",
					    req->op);
				break;
			case CTL_OP_RELOAD:
				status = authority_reload(sd.authority_channel_fd);
				reply.status = (status < 0) ? EIO :
				    (uint32_t)status;
				if (reply.status == 0)
					snprintf(summary, sizeof(summary),
					    "authority claims reloaded\n");
				break;
			case CTL_OP_STATUS:
				/*
				 * Synthesized from what serviced already tracks:
				 * the authority is PID 1 and reachable over the
				 * authority channel.  mac_capability policy detail
				 * lives in the mac_capability(4) device.
				 */
				snprintf(summary, sizeof(summary),
				    "authority: %s (spine, PID 1)\n"
				    "control plane: capability "
				    "(system.lifecycle)\n"
				    "services loaded: %u\n",
				    sd.authority_channel_fd >= 0 ? "reachable" :
				    "unreachable", sd.nservices);
				reply.status = 0;
				break;
			default:
				reply.status = ENOTSUP;
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
		syslog(LOG_WARNING, "sctl: authority control reply: %m");
	sctl_cap_sync_events(c);
}

int
sctl_adopt_channel(int provider_fd, uint64_t rights, bool authority_relay)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	channel_request_handler handler;
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
	c->cap_rights = rights;
	c->fd = channel_fd(c->cap_channel);
	/*
	 * system.serviced connections run the serviced control dispatch;
	 * system.lifecycle connections relay to authorityd (P4b).  Both share the
	 * adopt/kqueue/channel machinery — only the request handler differs.
	 */
	handler = authority_relay ? sctl_authority_request : sctl_cap_request;
	if (channel_set_request_handler(c->cap_channel, handler, c) == -1) {
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


void
sctl_teardown(void)
{
	struct sctl_conn *c, *tmp;

	TAILQ_FOREACH_SAFE(c, &conn_list, entry, tmp)
		conn_destroy(c);
}


void
sctl_conn_event(struct kevent *kev)
{
	struct sctl_conn *c;

	c = SCTL_GET_CONN(kev->udata);

	/*
	 * A control connection is driven by libchannel: a read dispatches queued
	 * requests (invoking sctl_cap_request / sctl_authority_request), a write
	 * flushes queued replies, and EOF tears it down.
	 */
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
}

bool
sctl_is_conn_event(struct kevent *kev)
{

	if (kev->udata == NULL)
		return (false);

	/*
	 * Connection udata is tagged with SCTL_CONN_TAG, allowing O(1)
	 * discrimination from svc_runtime pointers.
	 */
	return (SCTL_IS_CONN(kev->udata));
}
