/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "switchboard_ctl.h"

struct service_session {
	int fd;
};

static struct service_session fake_session;

static bool
fail_at(const char *stage)
{
	const char *requested;

	requested = getenv("SCTL_FAIL");
	return (requested != NULL && strcmp(requested, stage) == 0);
}

int
service_open(const char *name, int *fdp)
{
	int fd;

	if (name == NULL || fdp == NULL ||
	    strcmp(name, SWITCHBOARD_CONTROL_NAME) != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (fail_at("open")) {
		errno = ENOENT;
		return (-1);
	}
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return (-1);
	*fdp = fd;
	return (0);
}

int
service_session_create(int fd, struct service_session **sessionp)
{
	if (sessionp == NULL || fd < 0) {
		errno = EINVAL;
		return (-1);
	}
	if (fail_at("session")) {
		errno = EIO;
		return (-1);
	}
	fake_session.fd = fd;
	*sessionp = &fake_session;
	return (0);
}

void
service_session_close(struct service_session *session)
{
	if (session == &fake_session && session->fd >= 0) {
		(void)close(session->fd);
		session->fd = -1;
		if (getenv("SCTL_TRACE_CLOSE") != NULL)
			fprintf(stderr, "session-closed\n");
	}
}

int
service_session_call(struct service_session *session,
    const struct service_message *message, struct service_reply *reply,
    const struct service_call_options *options)
{
	const struct sctl_request *req;
	struct sctl_reply rpl;
	const char *mode, *summary;
	char *end;
	unsigned long expected;
	size_t summary_len;

	if (session != &fake_session || session->fd < 0 || message == NULL ||
	    message->size != sizeof(*message) ||
	    message->length != sizeof(*req) || message->data == NULL ||
	    message->nfds != 0 || reply == NULL ||
	    reply->size != sizeof(*reply) || reply->data == NULL ||
	    reply->capacity < sizeof(rpl) || options == NULL ||
	    options->size != sizeof(*options) || options->timeout_ms != 30000) {
		errno = EINVAL;
		return (-1);
	}
	if (fail_at("call")) {
		errno = EIO;
		return (-1);
	}
	req = message->data;
	if (req->version != SWITCHBOARD_CTL_VERSION || req->flags != 0 ||
	    req->datalen != 0) {
		errno = EPROTO;
		return (-1);
	}
	mode = getenv("SCTL_EXPECT_OP");
	if (mode != NULL) {
		errno = 0;
		expected = strtoul(mode, &end, 10);
		if (errno != 0 || *mode == '\0' || *end != '\0' ||
		    expected != req->op) {
			errno = EPROTO;
			return (-1);
		}
	}

	memset(&rpl, 0, sizeof(rpl));
	summary = "switchboard-ready\n";
	summary_len = strlen(summary);
	mode = getenv("SCTL_REPLY");
	if (mode != NULL && strcmp(mode, "status") == 0)
		rpl.status = EBUSY;
	else if (mode != NULL && strcmp(mode, "badstatus") == 0)
		rpl.status = ELAST + 1U;
	else if (mode == NULL || strcmp(mode, "nosummary") != 0)
		rpl.flags = (uint32_t)summary_len;
	if (mode != NULL && strcmp(mode, "oversize") == 0)
		rpl.flags = SWITCHBOARD_CTL_SUMMARY_MAX + 1U;

	memcpy(reply->data, &rpl, sizeof(rpl));
	if (rpl.flags == summary_len)
		memcpy((char *)reply->data + sizeof(rpl), summary, summary_len);
	reply->length = sizeof(rpl) +
	    (rpl.flags == summary_len ? summary_len : 0);
	if (mode != NULL && strcmp(mode, "short") == 0)
		reply->length = sizeof(rpl) - 1;
	else if (mode != NULL && strcmp(mode, "trailing") == 0) {
		rpl.flags = 0;
		memcpy(reply->data, &rpl, sizeof(rpl));
		reply->length = sizeof(rpl) + 1;
	}
	return (0);
}
