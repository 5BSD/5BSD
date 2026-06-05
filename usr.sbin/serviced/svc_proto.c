/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Service pair protocol dispatch for serviced.
 *
 * Handles messages received on a service's pair channel:
 * ready notification, name registration, unregistration, and
 * service lookup.
 */

#include <sys/ioctl.h>

#include <dev/cap_rt/cap_rt_ioctl.h>

#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "serviced.h"
#include "serviced_probes.h"
#include "serviced_svc_proto.h"

/*
 * Send a reply to a service on its pair channel.
 */
static void
svc_pair_reply(struct svc_runtime *svc, int status,
    uint64_t reply_token, int *fds, int nfds)
{
	struct cap_rt_sendmsg_args sa;
	struct svc_reply rpl;

	if (svc->pair_fd < 0)
		return;

	rpl.status = status;

	memset(&sa, 0, sizeof(sa));
	sa.payload = &rpl;
	sa.payload_len = sizeof(rpl);
	sa.reply_token = reply_token;
	if (nfds > 0 && fds != NULL) {
		sa.fds = fds;
		sa.nfds = (uint32_t)nfds;
	}

	if (ioctl(svc->pair_fd, CAP_RT_SENDMSG, &sa) == -1) {
		syslog(LOG_WARNING, "service %s: pair reply: %m",
		    svc->manifest.label);
		SERVICED_PROBE_ERROR("svc_proto", "pair reply failed");
	} else
		SERVICED_PROBE_IPC_REPLY(svc->manifest.label, 0, status);
}

static void
handle_svc_ready(struct svc_runtime *svc, uint64_t reply_token)
{

	if (svc->state == SVC_STATE_STARTING ||
	    svc->state == SVC_STATE_RUNNING) {
		svc->state = SVC_STATE_RUNNING;
		syslog(LOG_INFO, "service %s: reported ready",
		    svc->manifest.label);
	}
	svc_pair_reply(svc, 0, reply_token, NULL, 0);
}

static void
handle_svc_register(struct svc_runtime *svc, const void *payload,
    uint32_t len, uint64_t reply_token)
{
	const struct svc_register_req *req;
	int error;

	if (len < sizeof(*req)) {
		svc_pair_reply(svc, EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;

	if (strnlen(req->name, sizeof(req->name)) >= sizeof(req->name)) {
		svc_pair_reply(svc, ENAMETOOLONG, reply_token, NULL, 0);
		return;
	}

	error = naming_register(req->name, svc);
	svc_pair_reply(svc, error, reply_token, NULL, 0);
}

static void
handle_svc_unregister(struct svc_runtime *svc, const void *payload,
    uint32_t len, uint64_t reply_token)
{
	const struct svc_unregister_req *req;
	int error;

	if (len < sizeof(*req)) {
		svc_pair_reply(svc, EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;

	if (strnlen(req->name, sizeof(req->name)) >= sizeof(req->name)) {
		svc_pair_reply(svc, ENAMETOOLONG, reply_token, NULL, 0);
		return;
	}

	error = naming_unregister(req->name, svc);
	svc_pair_reply(svc, error, reply_token, NULL, 0);
}

static void
handle_svc_lookup(struct svc_runtime *svc, const void *payload,
    uint32_t len, uint64_t reply_token)
{
	const struct svc_lookup_req *req;
	int client_fd, error;

	if (len < sizeof(*req)) {
		svc_pair_reply(svc, EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;

	if (strnlen(req->name, sizeof(req->name)) >= sizeof(req->name)) {
		svc_pair_reply(svc, ENAMETOOLONG, reply_token, NULL, 0);
		return;
	}

	client_fd = naming_lookup(req->name, svc, &error);
	if (client_fd < 0) {
		svc_pair_reply(svc, error, reply_token, NULL, 0);
		return;
	}

	svc_pair_reply(svc, 0, reply_token, &client_fd, 1);
	close(client_fd);
}

void
supervisor_handle_pair(struct kevent *kev)
{
	struct cap_rt_recvmsg_args ra;
	struct svc_runtime *svc;
	char buf[sizeof(struct svc_register_req)];
	uint32_t op;

	svc = kev->udata;

	/* Coalition events — drain the message to prevent busy-loop. */
	if ((int)kev->ident == svc->coalition_fd) {
		struct cap_rt_recvmsg_args cra;
		char cbuf[64];

		memset(&cra, 0, sizeof(cra));
		cra.payload = cbuf;
		cra.payload_len = sizeof(cbuf);
		(void)ioctl(svc->coalition_fd, CAP_RT_RECVMSG, &cra);
		return;
	}

	if (kev->flags & EV_EOF) {
		syslog(LOG_INFO, "service %s: pair channel closed",
		    svc->manifest.label);
		close(svc->pair_fd);
		svc->pair_fd = -1;
		return;
	}

	/* Read the message from the service's pair channel. */
	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);

	if (ioctl(svc->pair_fd, CAP_RT_RECVMSG, &ra) == -1) {
		if (errno != EAGAIN)
			syslog(LOG_WARNING, "service %s: pair recvmsg: %m",
			    svc->manifest.label);
		return;
	}

	if (ra.payload_len < sizeof(uint32_t)) {
		syslog(LOG_WARNING, "service %s: short pair message",
		    svc->manifest.label);
		return;
	}

	memcpy(&op, buf, sizeof(op));
	SERVICED_PROBE_IPC_RECV(svc->manifest.label, op);

	switch (op) {
	case SVC_OP_READY:
		handle_svc_ready(svc, ra.reply_token);
		break;
	case SVC_OP_REGISTER:
		handle_svc_register(svc, buf, ra.payload_len, ra.reply_token);
		break;
	case SVC_OP_UNREGISTER:
		handle_svc_unregister(svc, buf, ra.payload_len,
		    ra.reply_token);
		break;
	case SVC_OP_LOOKUP:
		handle_svc_lookup(svc, buf, ra.payload_len, ra.reply_token);
		break;
	default:
		syslog(LOG_WARNING, "service %s: unknown pair op %u",
		    svc->manifest.label, op);
		svc_pair_reply(svc, ENOTSUP, ra.reply_token, NULL, 0);
		break;
	}
}
