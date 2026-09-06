/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <channel.h>
#include <libcapbundle.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "serviced.h"
#include "fd_budget.h"
#include "serviced_audit.h"
#include "serviced_probes.h"
#include "serviced_svc_proto.h"

/*
 * Deliver a control reply, optionally attaching descriptors.  cap_xfer is true
 * for every delivery except a sendable session endpoint: each attached fd is
 * limited to CAP_XFER_ONCE so the single delivery send consumes it to
 * CAP_XFER_NONE at the receiver (non-forwardable).  A sendable session is left
 * at the transfer state naming_lookup() chose (CAP_XFER_UNLIMITED), so the
 * consumer may re-send it.
 */
static int
svc_channel_reply_ex(struct svc_runtime *svc, struct channel_message *request,
    uint32_t op, int status, int *fds, size_t nfds, bool cap_xfer)
{
	struct svc_reply reply;
	size_t i;

	reply.status = status;
	for (i = 0; cap_xfer && i < nfds; i++) {
		if (cap_xfer_limit(fds[i], CAP_XFER_ONCE) == -1) {
			reply.status = errno;
			fds = NULL;
			nfds = 0;
			break;
		}
	}
	if (channel_send_reply(request,
	    &(struct channel_outgoing){
		.size = sizeof(struct channel_outgoing),
		.data = &reply,
		.length = sizeof(reply),
		.fds = fds,
		.nfds = nfds
	    }) == -1) {
		int error;

		error = errno;
		syslog(LOG_WARNING, "service %s: channel reply: %m",
		    svc->manifest.label);
		SERVICED_PROBE_ERROR("svc_proto", "channel reply failed");
		/*
		 * A control reply that cannot be queued is not recoverable:
		 * the peer is waiting on this exact token.  Revoke the control
		 * channel so every waiter observes peer death instead of
		 * hanging behind a silently lost acknowledgement.
		 */
		naming_remove_owner(svc);
		svc_channel_close(svc);
		errno = error;
		return (-1);
	}
	SERVICED_PROBE_IPC_REPLY(svc->manifest.label, op, reply.status);
	svc_channel_sync_events(svc, serviced_kq);
	return (0);
}

static int
svc_channel_reply(struct svc_runtime *svc, struct channel_message *request,
    uint32_t op, int status, int *fds, size_t nfds)
{

	return (svc_channel_reply_ex(svc, request, op, status, fds, nfds, true));
}

void
svc_channel_sync_events(struct svc_runtime *svc, int kq)
{
	struct kevent change;
	int wants;

	if (svc == NULL || svc->control_channel == NULL ||
	    svc->channel_fd < 0)
		return;
	wants = channel_wants_write(svc->control_channel);
	if (wants == -1)
		return;
	EV_SET(&change, svc->channel_fd, EVFILT_WRITE,
	    EV_ADD | (wants ? EV_ENABLE : EV_DISABLE), 0, 0, svc);
	if (kevent(kq, &change, 1, NULL, 0, NULL) == -1)
		syslog(LOG_WARNING, "service %s: update channel write event: %m",
		    svc->manifest.label);
}

int
svc_channel_send_event(struct svc_runtime *svc, const void *data,
    size_t length,
    const int *fds, size_t nfds, int kq)
{

	if (svc == NULL || svc->control_channel == NULL) {
		errno = ECONNRESET;
		return (-1);
	}
	if (channel_send_event(svc->control_channel,
	    &(struct channel_outgoing){
		.size = sizeof(struct channel_outgoing),
		.data = data,
		.length = length,
		.fds = fds,
		.nfds = nfds
	    }) == -1) {
		int error;

		error = errno;
		if (channel_error(svc->control_channel) == -1) {
			naming_remove_owner(svc);
			svc_channel_close(svc);
		}
		errno = error;
		return (-1);
	}
	svc_channel_sync_events(svc, kq);
	return (0);
}

static void
handle_ready(struct svc_runtime *svc, struct channel_message *request)
{
	int error;

	error = 0;
	if (svc->state == SVC_STATE_STARTING ||
	    svc->state == SVC_STATE_RUNNING) {
		if (svc->protocol_ready)
			error = EALREADY;
		else if (!on_demand_all_names_claimed(svc))
			error = EPROTO;
		else {
			svc->protocol_ready = true;
			/*
			 * A privileged provider never enters capability mode, so
			 * the NOTE_CAPMODE boundary that normally moves the unit
			 * to RUNNING (supervisor.c) will never fire.  For such a
			 * unit its own SVC_OP_READY IS the readiness boundary:
			 * promote it to RUNNING here.  Its authority is the held
			 * system capability, not the sandbox, so no kernel-
			 * observed capability-mode entry is expected.
			 */
			if (svc->state == SVC_STATE_STARTING &&
			    svc->manifest.privileged)
				svc->state = SVC_STATE_RUNNING;
			syslog(LOG_INFO,
			    "service %s: application reported ready%s",
			    svc->manifest.label,
			    svc->state == SVC_STATE_RUNNING ?
			    (svc->manifest.privileged ?
			    " (privileged, no sandbox)" : " after sandbox entry") :
			    "");
			if (svc->state == SVC_STATE_RUNNING)
				on_demand_check_ready(svc, serviced_kq);
		}
	} else
		error = EBUSY;
	if (error != 0)
		syslog(LOG_WARNING,
		    "service %s: readiness rejected: %s",
		    svc->manifest.label, strerror(error));
	(void)svc_channel_reply(svc, request, SVC_OP_READY, error, NULL, 0);
}

static void
handle_quiesce_result(struct svc_runtime *svc,
    struct channel_message *request)
{
	const struct svc_quiesce_result_req *req;
	int error;

	error = 0;
	if (channel_message_length(request) != sizeof(*req))
		error = EINVAL;
	else {
		req = channel_message_data(request);
		if (req->status < 0)
			error = EINVAL;
		else if (svc->state != SVC_STATE_STOPPING ||
		    !svc->quiesce_pending)
			error = EBUSY;
	}
	(void)svc_channel_reply(svc, request, SVC_OP_QUIESCE_RESULT, error,
	    NULL, 0);
	if (error == 0)
		svc_quiesce_complete(svc, req->status, serviced_kq);
}

static void
handle_idle(struct svc_runtime *svc, struct channel_message *request)
{
	const struct svc_idle_req *req;
	int error;

	error = 0;
	if (channel_message_length(request) != sizeof(*req))
		error = EINVAL;
	else if (svc->state != SVC_STATE_RUNNING || !svc->protocol_ready)
		error = EBUSY;
	else {
		req = channel_message_data(request);
		svc->idle_timeout_sec = req->seconds;
		if (req->seconds > 0)
			arm_idle_timer(svc, serviced_kq);
		else
			cancel_idle_timer(svc, serviced_kq);
	}
	(void)svc_channel_reply(svc, request, SVC_OP_IDLE, error, NULL, 0);
}

static void
handle_worker_channel(struct svc_runtime *svc,
    struct channel_message *request)
{
	int endpoints[2], error;

	endpoints[0] = endpoints[1] = -1;
	error = 0;
	/* Two endpoints and their two in-flight reply attachments. */
	if (serviced_fd_budget_check(4, "private worker channel") == -1)
		error = errno;
	else if (mac_cap_create_channel(&endpoints[0], &endpoints[1]) == -1)
		error = errno != 0 ? errno : EIO;
	SERVICED_PROBE_WORKER_CHANNEL(svc->manifest.label, error);
	serviced_audit(AUE_SERVICED_COMPONENT, getuid(), error,
	    "private worker channel svc=%s", svc->manifest.label);
	(void)svc_channel_reply(svc, request, SVC_OP_WORKER_CHANNEL, error,
	    error == 0 ? endpoints : NULL, error == 0 ? nitems(endpoints) : 0);
	if (endpoints[0] >= 0)
		close(endpoints[0]);
	if (endpoints[1] >= 0)
		close(endpoints[1]);
}

static void
handle_name_claim(struct svc_runtime *svc, struct channel_message *request)
{
	const struct svc_name_claim_req *req;
	int error;

	if (channel_message_length(request) != sizeof(*req)) {
		(void)svc_channel_reply(svc, request, SVC_OP_NAME_CLAIM,
		    EINVAL, NULL, 0);
		return;
	}
	req = channel_message_data(request);
	if ((req->flags & ~SVC_NAME_CLAIM_SENDABLE) != 0 ||
	    strnlen(req->name, sizeof(req->name)) >= sizeof(req->name)) {
		(void)svc_channel_reply(svc, request, SVC_OP_NAME_CLAIM,
		    EINVAL, NULL, 0);
		return;
	}
	error = on_demand_name_claim(svc, req->name,
	    (req->flags & SVC_NAME_CLAIM_SENDABLE) != 0);
	SERVICED_PROBE_ENDPOINT_CLAIM(svc->manifest.label, req->name, error);
	serviced_audit(AUE_SERVICED_ONDEMAND, getuid(), error,
	    "endpoint claim svc=%s name=%s", svc->manifest.label, req->name);
	if (svc_channel_reply(svc, request, SVC_OP_NAME_CLAIM, error,
	    NULL, 0) == 0 && error == 0 &&
	    svc->state == SVC_STATE_RUNNING && svc->protocol_ready)
		on_demand_check_ready(svc, serviced_kq);
}

static void
handle_name_result(struct svc_runtime *svc, struct channel_message *request)
{
	const struct svc_name_result_req *req;
	int error;

	if (channel_message_length(request) != sizeof(*req)) {
		(void)svc_channel_reply(svc, request, SVC_OP_NAME_RESULT,
		    EINVAL, NULL, 0);
		return;
	}
	req = channel_message_data(request);
	if (req->flags != 0 || req->reserved != 0 || req->status < 0 ||
	    req->status > ELAST) {
		(void)svc_channel_reply(svc, request, SVC_OP_NAME_RESULT,
		    EINVAL, NULL, 0);
		return;
	}
	if (strnlen(req->name, sizeof(req->name)) >= sizeof(req->name)) {
		(void)svc_channel_reply(svc, request, SVC_OP_NAME_RESULT,
		    ENAMETOOLONG, NULL, 0);
		return;
	}
	if (!on_demand_name_activating(svc, req->name)) {
		(void)svc_channel_reply(svc, request, SVC_OP_NAME_RESULT,
		    EPROTO, NULL, 0);
		return;
	}
	if (req->status == 0) {
		error = naming_register(req->name, svc,
		    on_demand_name_sendable(svc, req->name));
		if (error == 0) {
			/*
			 * Queue the publication acknowledgement before releasing
			 * client sessions.  Channel FIFO ordering then guarantees
			 * the provider observes NAME_RESULT completion before any
			 * NEW_CLIENT event for the newly active endpoint.
			 */
			if (svc_channel_reply(svc, request,
			    SVC_OP_NAME_RESULT, 0, NULL, 0) == 0) {
				on_demand_name_ready(svc, req->name,
				    serviced_kq);
				return;
			}
			(void)naming_unregister(req->name, svc);
			on_demand_name_failed(svc, req->name, ECONNRESET,
			    serviced_kq);
			return;
		} else
			on_demand_name_failed(svc, req->name, error,
			    serviced_kq);
	} else {
		/*
		 * Acknowledge the provider before reporting failure to
		 * unrelated requester channels.  The provider channel order
		 * remains independent from each requester's reply stream.
		 */
		error = svc_channel_reply(svc, request, SVC_OP_NAME_RESULT,
		    0, NULL, 0);
		if (error == -1)
			return;
		(void)naming_unregister(req->name, svc);
		on_demand_name_failed(svc, req->name, req->status,
		    serviced_kq);
		return;
	}
	(void)svc_channel_reply(svc, request, SVC_OP_NAME_RESULT, error,
	    NULL, 0);
}

static void
handle_name_withdraw(struct svc_runtime *svc,
    struct channel_message *request)
{
	const struct svc_name_withdraw_req *req;
	int error;

	if (channel_message_length(request) != sizeof(*req)) {
		(void)svc_channel_reply(svc, request, SVC_OP_NAME_WITHDRAW,
		    EINVAL, NULL, 0);
		return;
	}
	req = channel_message_data(request);
	if (req->flags != 0) {
		(void)svc_channel_reply(svc, request, SVC_OP_NAME_WITHDRAW,
		    EINVAL, NULL, 0);
		return;
	}
	if (strnlen(req->name, sizeof(req->name)) >= sizeof(req->name)) {
		(void)svc_channel_reply(svc, request, SVC_OP_NAME_WITHDRAW,
		    ENAMETOOLONG, NULL, 0);
		return;
	}
	error = on_demand_name_withdraw(svc, req->name, serviced_kq);
	SERVICED_PROBE_ENDPOINT_WITHDRAW(svc->manifest.label, req->name,
	    error);
	serviced_audit(AUE_SERVICED_ONDEMAND, getuid(), error,
	    "endpoint withdraw svc=%s name=%s", svc->manifest.label,
	    req->name);
	if (error == 0)
		syslog(LOG_INFO, "service %s: endpoint %s withdrawn",
		    svc->manifest.label, req->name);
	(void)svc_channel_reply(svc, request, SVC_OP_NAME_WITHDRAW, error,
	    NULL, 0);
}

/* Returns true when on-demand state retained the request. */
static bool
handle_lookup(struct svc_runtime *svc, struct channel_message *request)
{
	const struct svc_lookup_req *req;
	bool sendable;
	int client_fd, error;

	if (channel_message_length(request) != sizeof(*req)) {
		(void)svc_channel_reply(svc, request, SVC_OP_LOOKUP, EINVAL,
		    NULL, 0);
		return (false);
	}
	req = channel_message_data(request);
	if (req->flags != 0) {
		(void)svc_channel_reply(svc, request, SVC_OP_LOOKUP, EINVAL,
		    NULL, 0);
		return (false);
	}
	if (strnlen(req->name, sizeof(req->name)) >= sizeof(req->name)) {
		(void)svc_channel_reply(svc, request, SVC_OP_LOOKUP,
		    ENAMETOOLONG, NULL, 0);
		return (false);
	}
	/*
	 * The reserved "helper." namespace is private to a bundle: it is
	 * reachable only through SVC_OP_HELPER_OPEN, never global lookup.
	 */
	if (strncmp(req->name, "helper.", 7) == 0) {
		(void)svc_channel_reply(svc, request, SVC_OP_LOOKUP, EACCES,
		    NULL, 0);
		return (false);
	}
	sendable = false;
	client_fd = naming_lookup(req->name, svc, &svc->domain, &error,
	    &sendable);
	if (client_fd < 0) {
		if (error == ENOENT) {
			if (on_demand_launch(req->name, svc, request,
			    serviced_kq) == 0)
				return (true);
			if (errno == EDEADLK)
				error = EDEADLK;
		} else if (error == EACCES) {
			/* Out of scope: fail fast, indistinguishable from
			 * unregistered on the wire. */
			error = ENOENT;
		}
		(void)svc_channel_reply(svc, request, SVC_OP_LOOKUP, error,
		    NULL, 0);
		return (false);
	}
	(void)svc_channel_reply_ex(svc, request, SVC_OP_LOOKUP, 0,
	    &client_fd, 1, !sendable);
	close(client_fd);
	return (false);
}

/*
 * SVC_OP_HELPER_OPEN — launch and connect a private helper declared in the
 * caller's own bundle.  The helper is reached through the on-demand provider
 * machinery under a synthetic bundle-local name "helper.<bundle-id>.<unit>"
 * that global lookup rejects, so it is invisible outside its bundle.  Returns
 * true when on-demand state retained the request (reply comes later).
 */
static bool
handle_helper_open(struct svc_runtime *svc, struct channel_message *request)
{
	const struct svc_helper_req *req;
	char synthetic[SERVICED_NAME_MAX + 1];
	const char *slash;
	bool sendable;
	int client_fd, error;
	size_t blen;

	if (channel_message_length(request) != sizeof(*req)) {
		(void)svc_channel_reply(svc, request, SVC_OP_HELPER_OPEN, EINVAL,
		    NULL, 0);
		return (false);
	}
	req = channel_message_data(request);
	if (req->flags != 0 ||
	    strnlen(req->name, sizeof(req->name)) >= sizeof(req->name) ||
	    req->name[0] == '\0' || strchr(req->name, '/') != NULL ||
	    strchr(req->name, '.') != NULL || strchr(req->name, ':') != NULL) {
		(void)svc_channel_reply(svc, request, SVC_OP_HELPER_OPEN, EINVAL,
		    NULL, 0);
		return (false);
	}
	/* The caller's bundle id is the part of its label before '/'. */
	slash = strchr(svc->manifest.label, '/');
	if (slash == NULL) {
		(void)svc_channel_reply(svc, request, SVC_OP_HELPER_OPEN, EINVAL,
		    NULL, 0);
		return (false);
	}
	blen = (size_t)(slash - svc->manifest.label);
	if (snprintf(synthetic, sizeof(synthetic), "helper.%.*s.%s",
	    (int)blen, svc->manifest.label, req->name) >= (int)sizeof(synthetic)) {
		(void)svc_channel_reply(svc, request, SVC_OP_HELPER_OPEN,
		    ENAMETOOLONG, NULL, 0);
		return (false);
	}
	client_fd = naming_lookup(synthetic, svc, &svc->domain, &error,
	    &sendable);
	if (client_fd < 0) {
		if (error == ENOENT) {
			if (on_demand_launch(synthetic, svc, request,
			    serviced_kq) == 0)
				return (true);
			if (errno == EDEADLK)
				error = EDEADLK;
		} else if (error == EACCES) {
			/* Out of scope: fail fast, indistinguishable from
			 * unregistered on the wire. */
			error = ENOENT;
		}
		(void)svc_channel_reply(svc, request, SVC_OP_HELPER_OPEN, error,
		    NULL, 0);
		return (false);
	}
	(void)svc_channel_reply_ex(svc, request, SVC_OP_HELPER_OPEN, 0,
	    &client_fd, 1, !sendable);
	close(client_fd);
	return (false);
}

/*
 * SVC_OP_MINT_DOMAIN — mint a session lookup channel and return the caller's
 * endpoint.  The request's `domain` field selects USER (per-uid, scoped) or
 * SYSTEM (full-discovery admin).  Only a SYSTEM-domain caller may mint at all:
 * a request on an already-narrowed channel is refused, because domains only
 * narrow and never broaden.  Additionally, minting a SYSTEM channel is a
 * privilege escalation, so it is refused unless the requesting channel is
 * itself SYSTEM (§6).  The returned descriptor is ambient (survives fork and
 * exec, usable in capability mode); serviced retains the other end, scoped to
 * the minted domain, and dispatches lookups on it in domain.c.
 */
static void
handle_mint_domain(struct svc_runtime *svc, struct channel_message *request)
{
	const struct svc_mint_domain_req *req;
	enum svc_domain_kind kind;
	int minted_fd, error;
	bool resend;

	minted_fd = -1;
	if (channel_message_length(request) != sizeof(*req)) {
		(void)svc_channel_reply(svc, request, SVC_OP_MINT_DOMAIN,
		    EINVAL, NULL, 0);
		return;
	}
	req = channel_message_data(request);
	if ((req->flags & ~SVC_MINT_FLAG_RESEND) != 0) {
		(void)svc_channel_reply(svc, request, SVC_OP_MINT_DOMAIN,
		    EINVAL, NULL, 0);
		return;
	}
	/*
	 * SVC_MINT_FLAG_RESEND: deliver the endpoint transferable (default
	 * CAP_XFER_UNLIMITED, skipping the CAP_XFER_ONCE attenuation) so a broker
	 * that forwards it over one more SCM_RIGHTS hop before it is installed —
	 * the auth-agent minting a session for a login program — is not left
	 * holding an exhausted descriptor.  See docs/auth-agent-design.md.
	 */
	resend = (req->flags & SVC_MINT_FLAG_RESEND) != 0;
	/*
	 * The mint boundary is the auth-agent alone (domain.c, docs/
	 * auth-agent-design.md): it is the single component that translates an
	 * authenticated identity into a session lookup channel.  Gate on the
	 * caller's unforgeable channel LABEL, not its domain — every
	 * serviced-launched unit's domain is SVC_DOMAIN_SYSTEM (zero-initialized),
	 * so svc_domain_may_mint()/svc_mint_domain_kind() below cannot tell the
	 * auth-agent from any other unit.  Without this check any unit could mint a
	 * SYSTEM channel and, because a minted channel's lookups carry
	 * requester == NULL (domain.c), obtain the ADMIN bypass — the
	 * authority-relay control connection to authorityd (reboot/halt/lifecycle)
	 * and third-party *.Control planes — that it can never get on its own
	 * control channel.  Only the auth-agent legitimately calls this op
	 * (usr.sbin/authagentd); login/su/sshd receive the minted channel from it.
	 */
	if (strcmp(svc->manifest.label, SVC_MINT_PRINCIPAL_LABEL) != 0) {
		serviced_audit(AUE_SERVICED_COMPONENT, getuid(), EPERM,
		    "mint domain refused: %s is not the mint boundary",
		    svc->manifest.label);
		(void)svc_channel_reply(svc, request, SVC_OP_MINT_DOMAIN,
		    EPERM, NULL, 0);
		return;
	}
	/* Domains only narrow: a non-system caller may not mint at all. */
	if (!svc_domain_may_mint(&svc->domain)) {
		(void)svc_channel_reply(svc, request, SVC_OP_MINT_DOMAIN,
		    EPERM, NULL, 0);
		return;
	}
	/*
	 * Escalation guard (§6): resolve the requested kind and refuse a SYSTEM
	 * mint unless this channel is itself SYSTEM.  The may_mint gate above
	 * already limits minting to SYSTEM channels; this explicit re-check is
	 * the privilege boundary that must hold even if that policy widens.
	 */
	if (svc_mint_domain_kind(&svc->domain, req->domain, &kind) == -1) {
		(void)svc_channel_reply(svc, request, SVC_OP_MINT_DOMAIN,
		    errno != 0 ? errno : EPERM, NULL, 0);
		return;
	}
	if (domain_mint_session_channel(kind, (uid_t)req->uid, &minted_fd,
	    serviced_kq) == -1)
		error = errno != 0 ? errno : EIO;
	else
		error = 0;
	serviced_audit(AUE_SERVICED_COMPONENT, getuid(), error,
	    "mint %s-domain channel svc=%s uid=%u",
	    kind == SVC_DOMAIN_SYSTEM ? "system" :
	    kind == SVC_DOMAIN_CONTROL ? "control" : "user",
	    svc->manifest.label, (unsigned)req->uid);
	(void)svc_channel_reply_ex(svc, request, SVC_OP_MINT_DOMAIN, error,
	    error == 0 ? &minted_fd : NULL, error == 0 ? 1 : 0,
	    /*cap_xfer=*/!resend);
	if (minted_fd >= 0)
		close(minted_fd);
}

/*
 * SVC_OP_LABEL_IS_LIVE — a pure, read-only liveness query for the involuntary-
 * cleanup pull path (docs/capability-lifecycle-cleanup.md).  A provider's
 * reconciliation sweep asks whether a bundle label it still holds persistent
 * state for is currently installed.  Reply status 0 == live (a currently-
 * installed bundle carries that manifest label), ENOENT == not live (retired or
 * never installed).  This op NEVER mutates serviced state and NEVER retires a
 * label: retirement is driven only by serviced's own bundle-removal detection
 * (svc_retire_label from reload), never by a service request.  Any launched
 * service may ask — the answer reveals only installed/not, no privileged data.
 */
static void
handle_label_is_live(struct svc_runtime *svc, struct channel_message *request)
{
	const struct svc_label_query_req *req;
	int status;

	if (channel_message_length(request) != sizeof(*req)) {
		(void)svc_channel_reply(svc, request, SVC_OP_LABEL_IS_LIVE,
		    EINVAL, NULL, 0);
		return;
	}
	req = channel_message_data(request);
	if (req->flags != 0 ||
	    strnlen(req->label, sizeof(req->label)) >= sizeof(req->label)) {
		(void)svc_channel_reply(svc, request, SVC_OP_LABEL_IS_LIVE,
		    EINVAL, NULL, 0);
		return;
	}
	status = bundle_registry_label_installed(req->label) ? 0 : ENOENT;
	(void)svc_channel_reply(svc, request, SVC_OP_LABEL_IS_LIVE, status,
	    NULL, 0);
}

static void
svc_request(struct channel *channel, struct channel_message *request,
    void *context)
{
	struct svc_runtime *svc;
	const uint32_t *opp;
	uint32_t op;
	bool retained;

	(void)channel;
	svc = context;
	retained = false;
	if (channel_message_fd_count(request) != 0 ||
	    channel_message_length(request) < sizeof(op)) {
		(void)svc_channel_reply(svc, request, 0, EINVAL, NULL, 0);
		goto out;
	}
	opp = channel_message_data(request);
	memcpy(&op, opp, sizeof(op));
	SERVICED_PROBE_IPC_RECV(svc->manifest.label, op);
	switch (op) {
	case SVC_OP_READY:
		if (channel_message_length(request) != sizeof(struct svc_req_hdr))
			(void)svc_channel_reply(svc, request, op, EINVAL,
			    NULL, 0);
		else
			handle_ready(svc, request);
		break;
	case SVC_OP_NAME_RESULT:
		handle_name_result(svc, request);
		break;
	case SVC_OP_NAME_WITHDRAW:
		handle_name_withdraw(svc, request);
		break;
	case SVC_OP_NAME_CLAIM:
		handle_name_claim(svc, request);
		break;
	case SVC_OP_QUIESCE_RESULT:
		handle_quiesce_result(svc, request);
		break;
	case SVC_OP_IDLE:
		handle_idle(svc, request);
		break;
	case SVC_OP_LOOKUP:
		retained = handle_lookup(svc, request);
		break;
	case SVC_OP_HELPER_OPEN:
		retained = handle_helper_open(svc, request);
		break;
	case SVC_OP_WORKER_CHANNEL:
		if (channel_message_length(request) != sizeof(struct svc_req_hdr))
			(void)svc_channel_reply(svc, request, op, EINVAL,
			    NULL, 0);
		else
			handle_worker_channel(svc, request);
		break;
	case SVC_OP_MINT_DOMAIN:
		handle_mint_domain(svc, request);
		break;
	case SVC_OP_LABEL_IS_LIVE:
		handle_label_is_live(svc, request);
		break;
	default:
		syslog(LOG_WARNING, "service %s: unknown channel op %u",
		    svc->manifest.label, op);
		(void)svc_channel_reply(svc, request, op, ENOTSUP, NULL, 0);
		break;
	}
out:
	if (!retained)
		channel_message_free(request);
}

int
svc_channel_attach(struct svc_runtime *svc, int fd)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);

	if (svc == NULL || fd < 0) {
		errno = EINVAL;
		return (-1);
	}
	options.max_pending_requests = 64;
	options.max_queued_messages = 256;
	options.max_queued_bytes = 1024 * 1024;
	options.max_queued_fds = 256;
	if (channel_create(fd, &options, &svc->control_channel) == -1) {
		int error;

		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	svc->channel_fd = channel_fd(svc->control_channel);
	if (channel_set_request_handler(svc->control_channel, svc_request,
	    svc) == -1) {
		channel_destroy(svc->control_channel);
		svc->control_channel = NULL;
		svc->channel_fd = -1;
		return (-1);
	}
	return (0);
}

int
svc_channel_rebind(struct svc_runtime *svc)
{

	if (svc == NULL || svc->control_channel == NULL) {
		errno = EINVAL;
		return (-1);
	}
	return (channel_set_request_handler(svc->control_channel, svc_request,
	    svc));
}

void
svc_channel_close(struct svc_runtime *svc)
{

	if (svc == NULL)
		return;
	if (svc->control_channel != NULL)
		channel_destroy(svc->control_channel);
	else if (svc->channel_fd >= 0)
		close(svc->channel_fd);
	svc->control_channel = NULL;
	svc->channel_fd = -1;
}

void
supervisor_handle_channel(struct kevent *event)
{
	struct mac_capability_recvmsg_args receive;
	struct svc_runtime *svc;
	char buffer[64];

	svc = event->udata;
	if ((int)event->ident == svc->coalition_fd) {
		memset(&receive, 0, sizeof(receive));
		receive.payload = buffer;
		receive.payload_len = sizeof(buffer);
		(void)ioctl(svc->coalition_fd, MAC_CAPABILITY_RECVMSG,
		    &receive);
		return;
	}
	if (svc->control_channel == NULL)
		return;
	if (event->flags & EV_EOF) {
		/* The peer hung up; errno is stale here and must not leak
		 * into the diagnostic. */
		errno = ECONNRESET;
		goto dead;
	}
	if (event->filter == EVFILT_WRITE) {
		if (channel_flush(svc->control_channel) == -1)
			goto dead;
	} else if (event->filter == EVFILT_READ) {
		if (channel_dispatch(svc->control_channel) == -1)
			goto dead;
	}
	svc_channel_sync_events(svc, serviced_kq);
	return;
dead:
	syslog(LOG_INFO, "service %s: channel closed: %s",
	    svc->manifest.label, strerror(errno != 0 ? errno : ECONNRESET));
	naming_remove_owner(svc);
	svc_channel_close(svc);
}
