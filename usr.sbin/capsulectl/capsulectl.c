/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * capsulectl -- capability-native control CLI for Capsule (the PID 1
 * spine), the parallel of switchboardctl(8) for switchboard.  It presents a lifecycle
 * op over the ADMIN-gated system.lifecycle capability, which switchboard relays to
 * capsule (docs/book/src/plane/capsule.md, P4b).
 *
 * This is the capability path.  The everyday reboot(8)/halt(8)/shutdown(8) keep
 * their stock BSD signal-to-init behaviour; capsulectl sits beside them for a
 * capability-native shutdown (and for automation that already holds the plane).
 */

#include <sys/param.h>
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <libservice.h>

#include "capsule_ctl.h"
#include "switchboard_ctl.h"

static const struct {
	const char	*verb;
	uint32_t	 op;
	bool		 show;	/* print the reply summary (query/admin ops) */
} verbs[] = {
	{ "reboot",	CTL_OP_REBOOT,		false },
	{ "halt",	CTL_OP_HALT,		false },
	{ "poweroff",	CTL_OP_POWEROFF,	false },
	{ "powercycle",	CTL_OP_POWERCYCLE,	false },
	{ "single",	CTL_OP_SINGLE,		false },
	{ "reroot",	CTL_OP_REROOT,		false },
	{ "rescan",	CTL_OP_RESCAN,		false },
	{ "catatonia",	CTL_OP_CATATONIA,	false },
	{ "status",	CTL_OP_STATUS,		true },
	{ "reload",	CTL_OP_RELOAD,		true },
};

static void __dead2
usage(void)
{

	fprintf(stderr, "usage: capsulectl "
	    "reboot|halt|poweroff|powercycle|single|reroot|rescan|catatonia|"
	    "status|reload\n");
	exit(EX_USAGE);
}

/*
 * Resolve system.lifecycle over the ambient discovery plane and present the op,
 * which switchboard relays to Capsule (the PID 1 spine).  When show is set,
 * print the reply summary (status/reload).  Returns Capsule's status.
 */
static int
capsulectl_call(uint32_t op, bool show)
{
	struct service_session *session;
	struct service_message message;
	struct service_reply reply;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct ctl_request req;
	char rbuf[sizeof(struct ctl_reply) + SWITCHBOARD_CTL_SUMMARY_MAX];
	struct ctl_reply rpl;
	int fd;

	if (service_open(SWITCHBOARD_LIFECYCLE_NAME, &fd) != 0)
		err(EX_UNAVAILABLE,
		    "cannot reach Capsule control capability");
	if (service_session_create(fd, &session) != 0) {
		(void)close(fd);
		err(EX_UNAVAILABLE, "Capsule session");
	}

	memset(&req, 0, sizeof(req));
	req.version = CTL_VERSION;
	req.op = op;

	memset(&message, 0, sizeof(message));
	message.size = sizeof(message);
	message.data = &req;
	message.length = sizeof(req);

	memset(&reply, 0, sizeof(reply));
	reply.size = sizeof(reply);
	reply.data = rbuf;
	reply.capacity = sizeof(rbuf);
	options.timeout_ms = 30000;

	if (service_session_call(session, &message, &reply, &options) != 0) {
		service_session_close(session);
		err(EX_UNAVAILABLE, "Capsule request");
	}
	if (reply.length < sizeof(rpl)) {
		service_session_close(session);
		errx(EX_PROTOCOL, "short Capsule reply");
	}
	memcpy(&rpl, rbuf, sizeof(rpl));
	if (rpl.flags > SWITCHBOARD_CTL_SUMMARY_MAX ||
	    reply.length != sizeof(rpl) + (size_t)rpl.flags ||
	    rpl.status > ELAST) {
		service_session_close(session);
		errx(EX_PROTOCOL, "malformed Capsule reply");
	}
	if (show && rpl.flags > 0)
		(void)fwrite(rbuf + sizeof(rpl), 1, rpl.flags, stdout);

	service_session_close(session);
	return ((int)rpl.status);
}

int
main(int argc, char **argv)
{
	unsigned i;
	int status;

	if (argc != 2)
		usage();

	for (i = 0; i < nitems(verbs); i++) {
		if (strcmp(argv[1], verbs[i].verb) != 0)
			continue;
		status = capsulectl_call(verbs[i].op, verbs[i].show);
		if (status != 0) {
			warnc(status, "%s", argv[1]);
			return (1);
		}
		return (0);
	}

	warnx("unknown command: %s", argv[1]);
	usage();
}
