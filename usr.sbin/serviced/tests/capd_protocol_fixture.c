/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Purpose-built protocol peer for capability-daemon integration tests.
 * Keeping malformed-wire behavior here makes it part of the normal build, with
 * the same headers and compiler policy as the daemons.
 *
 * The serviced control plane is the "system.serviced" capability discovery name
 * reached over the session's ambient lookup channel (SERVICE_LOOKUP_FD); the
 * getpeereid control socket this fixture used to dial was retired.  Each verb
 * crafts a deliberately malformed sctl_request, sends it over the capability
 * channel, and prints the reply status so the test can assert the rejection.
 * If there is no ambient control channel here (not a live plane), it exits 2 so
 * the caller can skip.
 */

#include <sys/types.h>

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <serviced_ctl.h>

/* Distinct exit code meaning "no ambient control channel here" (test skips). */
#define	EX_NO_CHANNEL	2

/*
 * Send one raw sctl_request (already assembled, possibly malformed) over the
 * system.serviced capability channel and print "status=<n>" from the reply.
 * datalen is the value placed in the wire header; paylen is how many payload
 * bytes actually follow it (they may deliberately disagree).
 */
static int
control_send(uint32_t version, uint32_t op, uint32_t flags, uint32_t datalen,
    const void *payload, size_t paylen)
{
	struct service_session *session;
	struct service_message message;
	struct service_reply reply;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct sctl_request *req;
	const struct sctl_reply *rhdr;
	char reqbuf[sizeof(struct sctl_request) + SERVICED_CTL_MAX_PAYLOAD + 16];
	char rplbuf[sizeof(struct sctl_reply) + SERVICED_CTL_SUMMARY_MAX];
	int fd;

	if (paylen > SERVICED_CTL_MAX_PAYLOAD + 16)
		errx(1, "payload too large for fixture buffer");

	if (service_open(SERVICED_CONTROL_NAME, &fd) != 0) {
		fprintf(stderr, "no ambient control channel\n");
		return (EX_NO_CHANNEL);
	}
	if (service_session_create(fd, &session) != 0) {
		(void)close(fd);
		err(1, "service_session_create");
	}

	req = (struct sctl_request *)reqbuf;
	memset(req, 0, sizeof(*req));
	req->version = version;
	req->op = op;
	req->flags = flags;
	req->datalen = datalen;
	if (payload != NULL && paylen > 0)
		memcpy(reqbuf + sizeof(*req), payload, paylen);

	memset(&message, 0, sizeof(message));
	message.size = sizeof(message);
	message.data = reqbuf;
	message.length = sizeof(*req) + paylen;

	memset(&reply, 0, sizeof(reply));
	reply.size = sizeof(reply);
	reply.data = rplbuf;
	reply.capacity = sizeof(rplbuf);
	options.timeout_ms = 30000;

	if (service_session_call(session, &message, &reply, &options) != 0) {
		service_session_close(session);
		err(1, "service_session_call");
	}
	if (reply.length < sizeof(struct sctl_reply)) {
		service_session_close(session);
		errx(1, "short control reply: %zu", reply.length);
	}
	rhdr = (const struct sctl_reply *)rplbuf;
	printf("status=%u\n", rhdr->status);
	service_session_close(session);
	return (0);
}

/*
 * control-oversized: a request whose declared datalen exceeds the protocol
 * maximum (and does not match the bytes actually sent).  serviced must reject
 * it (EINVAL) without reading past the buffer.
 */
static int
control_oversized(void)
{

	return (control_send(SERVICED_CTL_VERSION, SCTL_OP_START_SVC, 0,
	    SERVICED_CTL_MAX_PAYLOAD + 1, NULL, 0));
}

/*
 * control-invalid flags|nul: a well-sized request that violates an encoding
 * rule — a nonzero reserved flags field, or an embedded NUL in the text
 * payload.  Both must be rejected (EINVAL).
 */
static int
control_invalid(const char *kind)
{
	static const char embedded_nul[] = { 'u', '\0', 'n', 'i', 't' };

	if (strcmp(kind, "flags") == 0)
		return (control_send(SERVICED_CTL_VERSION, SCTL_OP_START_SVC,
		    1, 0, NULL, 0));
	if (strcmp(kind, "nul") == 0)
		return (control_send(SERVICED_CTL_VERSION, SCTL_OP_START_SVC,
		    0, (uint32_t)sizeof(embedded_nul), embedded_nul,
		    sizeof(embedded_nul)));
	errx(2, "unknown invalid request kind: %s", kind);
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: capd_protocol_fixture control-oversized\n"
	    "       capd_protocol_fixture control-invalid flags|nul\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "control-oversized") == 0)
		return (control_oversized());
	if (argc == 3 && strcmp(argv[1], "control-invalid") == 0)
		return (control_invalid(argv[2]));
	usage();
}
