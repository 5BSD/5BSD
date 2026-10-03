/* SPDX-License-Identifier: BSD-2-Clause */
/* Guest-only endpoint, authentication and control probe. */
#include <sys/types.h>
#include <sys/stat.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>
#include <service_bootstrap.h>
#include "switchboard_ctl.h"

static int
request(struct service_session *session, unsigned op, const char *label)
{
	struct { struct sctl_request header; char payload[1024]; } req;
	struct { struct sctl_reply header; char payload[16384]; } response;
	struct service_message message = { .size = sizeof(message) };
	struct service_reply reply = { .size = sizeof(reply) };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;

	memset(&req, 0, sizeof(req));
	req.header.op = op;
	req.header.datalen = strlen(label);
	if (req.header.datalen >= sizeof(req.payload))
		errx(1, "label too long");
	memcpy(req.payload, label, req.header.datalen);
	message.data = &req;
	message.length = sizeof(req.header) + req.header.datalen;
	reply.data = &response;
	reply.capacity = sizeof(response);
	options.timeout_ms = 30000;
	if (service_session_call(session, &message, &reply, &options) != 0)
		err(1, "control call");
	if (reply.length < sizeof(response.header))
		errx(1, "short reply");
	return (response.header.status);
}

int
main(int argc, char **argv)
{
	struct service_session *session;
	int fd, status, expected;
	unsigned op, attempt;

	if (argc != 4)
		errx(1, "usage: probe start|stop|reload|open|mint label expected-status");
	if (strcmp(argv[1], "mint") == 0) {
		fd = -1;
		status = service_mint_session_via_agent(service_ambient_lookup_fd(),
		    (uid_t)strtoul(argv[2], NULL, 10), 0, 10000, &fd);
		status = status == 0 ? 0 : errno;
		if (fd >= 0) close(fd);
		if (status != atoi(argv[3]))
			errx(1, "mint status %d expected %s", status, argv[3]);
		puts("SESSION_MINT_BOUNDARY_PASS");
		return (0);
	}
	if (strcmp(argv[1], "open") == 0) {
		if (service_ambient_lookup_fd() < 0)
			errx(1, "missing ambient session channel");
		status = service_open(argv[2], &fd) == 0 ? 0 : errno;
		if (status != atoi(argv[3]))
			errx(1, "open %s: errno %d expected %s", argv[2], status, argv[3]);
		if (status == 0)
			close(fd);
		printf("CAPABILITY_REACH uid=%u endpoint=%s errno=%d PASS\n",
		    getuid(), argv[2], status);
		return (0);
	}
	op = strcmp(argv[1], "start") == 0 ? SCTL_OP_START_SVC :
	    strcmp(argv[1], "reload") == 0 ? SCTL_OP_RELOAD : SCTL_OP_STOP_SVC;
	expected = atoi(argv[3]);
	if (service_open(SWITCHBOARD_CONTROL_NAME, &fd) != 0 ||
	    service_session_create(fd, &session) != 0)
		err(1, "open control");
	status = request(session, op, argv[2]);
	/* Stop is asynchronous; wait for its shutdown grace period to finish. */
	for (attempt = 0; op == SCTL_OP_START_SVC && expected == 0 &&
	    status == EALREADY && attempt < 300; attempt++) {
		usleep(100000);
		status = request(session, op, argv[2]);
	}
	if (status != expected)
		errx(1, "%s %s: status %d expected %d", argv[1], argv[2], status, expected);

	service_session_close(session);
	printf("POLICY_PROBE uid=%u op=%s target=%s PASS\n", getuid(), argv[1], argv[2]);
	return (0);
}
