/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * authorityctl -- capability-native control CLI for the authority (the PID 1
 * spine), the parallel of servicectl(8) for serviced.  It presents a lifecycle
 * op over the ADMIN-gated system.lifecycle capability, which serviced relays to
 * authorityd (docs/lifecycle-capability-design.md, P4b).
 *
 * This is the capability path.  The everyday reboot(8)/halt(8)/shutdown(8) keep
 * their stock BSD signal-to-init behaviour; authorityctl sits beside them for a
 * capability-native shutdown (and for automation that already holds the plane).
 */

#include <sys/param.h>
#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <libservice.h>

#include "authorityd_ctl.h"
#include "serviced_ctl.h"

static const struct {
	const char	*verb;
	uint32_t	 op;
} verbs[] = {
	{ "reboot",	CTL_OP_REBOOT },
	{ "halt",	CTL_OP_HALT },
	{ "poweroff",	CTL_OP_POWEROFF },
	{ "powercycle",	CTL_OP_POWERCYCLE },
	{ "single",	CTL_OP_SINGLE },
	{ "reroot",	CTL_OP_REROOT },
	{ "rescan",	CTL_OP_RESCAN },
	{ "catatonia",	CTL_OP_CATATONIA },
};

static void __dead2
usage(void)
{

	fprintf(stderr, "usage: authorityctl "
	    "reboot|halt|poweroff|powercycle|single|reroot|rescan|catatonia\n");
	exit(EX_USAGE);
}

/*
 * Resolve system.lifecycle over the ambient discovery plane and present the op.
 * Returns the authority's status (0 = accepted).
 */
static int
authctl_lifecycle(uint32_t op)
{
	struct service_session *session;
	struct service_message message;
	struct service_reply reply;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct ctl_request req;
	struct ctl_reply rpl;
	int fd;

	if (service_open(SERVICED_LIFECYCLE_NAME, &fd) != 0)
		err(EX_UNAVAILABLE,
		    "cannot reach the system lifecycle capability");
	if (service_session_create(fd, &session) != 0) {
		(void)close(fd);
		err(EX_UNAVAILABLE, "lifecycle session");
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
	reply.data = &rpl;
	reply.capacity = sizeof(rpl);
	options.timeout_ms = 30000;

	if (service_session_call(session, &message, &reply, &options) != 0) {
		service_session_close(session);
		err(EX_UNAVAILABLE, "lifecycle request");
	}
	if (reply.length != sizeof(rpl)) {
		service_session_close(session);
		errx(EX_PROTOCOL, "short lifecycle reply");
	}
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
		status = authctl_lifecycle(verbs[i].op);
		if (status != 0) {
			warnc(status, "%s", argv[1]);
			return (1);
		}
		/* Accepted: the machine is going down; nothing more to print. */
		return (0);
	}

	warnx("unknown command: %s", argv[1]);
	usage();
}
