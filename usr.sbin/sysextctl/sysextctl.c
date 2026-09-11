/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <libservice.h>
#include <sysext_proto.h>

static void __dead2
usage(void)
{
	fprintf(stderr, "usage: sysextctl list | status module | load module\n");
	exit(EX_USAGE);
}

static int
valid_name(const char *name)
{
	return (memchr(name, '\0', SYSEXT_NAME_MAX) != NULL &&
	    name[0] != '\0' && strcmp(name, ".") != 0 &&
	    strcmp(name, "..") != 0 && strchr(name, '/') == NULL);
}

int
main(int argc, char **argv)
{
	struct service_session *session;
	struct service_message message = { .size = sizeof(message) };
	struct service_reply reply = { .size = sizeof(reply) };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct sysext_request request = {0};
	union {
		struct sysext_reply basic;
		struct sysext_stat_reply stat;
		struct sysext_list_reply list;
	} response = {0};
	size_t i, expected;
	int fd, error;

	if (argc == 2 && strcmp(argv[1], "list") == 0)
		request.op = SYSEXT_OP_LIST;
	else if (argc == 3 && strcmp(argv[1], "status") == 0)
		request.op = SYSEXT_OP_STAT;
	else if (argc == 3 && strcmp(argv[1], "load") == 0)
		request.op = SYSEXT_OP_ENSURE;
	else
		usage();
	if (request.op != SYSEXT_OP_LIST) {
		if (strlcpy(request.name, argv[2], sizeof(request.name)) >=
		    sizeof(request.name) || !valid_name(request.name))
			errx(EX_USAGE, "module must be a single safe name, without a path");
	}
	if (service_open(SYSEXT_SERVICE_NAME, &fd) == -1)
		err(EX_UNAVAILABLE, "cannot reach SystemExtension capability");
	if (service_session_create(fd, &session) == -1) {
		error = errno;
		close(fd);
		errno = error;
		err(EX_UNAVAILABLE, "SystemExtension session");
	}
	message.data = &request;
	message.length = sizeof(request);
	reply.data = &response;
	reply.capacity = sizeof(response);
	options.timeout_ms = 30000;
	if (service_session_call(session, &message, &reply, &options) == -1) {
		error = errno;
		service_session_close(session);
		errno = error;
		err(EX_UNAVAILABLE, "SystemExtension request");
	}
	service_session_close(session);
	if (reply.nfds != 0 || reply.length < sizeof(response.basic) ||
	    response.basic.status < 0 || response.basic.status > ELAST)
		errx(EX_PROTOCOL, "malformed SystemExtension reply");
	if (response.basic.status != 0) {
		errno = response.basic.status;
		err(EX_UNAVAILABLE, "SystemExtension %s", argv[1]);
	}
	expected = request.op == SYSEXT_OP_LIST ?
	    sizeof(response.list) : sizeof(response.basic);
	if (reply.length != expected)
		errx(EX_PROTOCOL, "wrong SystemExtension reply size");
	switch (request.op) {
	case SYSEXT_OP_LIST:
		if (response.list.count > SYSEXT_LIST_MAX)
			errx(EX_PROTOCOL, "invalid module count");
		/* Validate the entire reply before printing any of it. */
		for (i = 0; i < response.list.count; i++)
			if (!valid_name(response.list.names[i]))
				errx(EX_PROTOCOL, "invalid module name in reply");
		for (i = 0; i < response.list.count; i++)
			puts(response.list.names[i]);
		break;
	case SYSEXT_OP_STAT:
		if (response.stat.loaded != 0 && response.stat.loaded != 1)
			errx(EX_PROTOCOL, "invalid loaded state");
		printf("%s: %s\n", request.name,
		    response.stat.loaded ? "loaded" : "not loaded");
		return (response.stat.loaded ? 0 : 1);
	case SYSEXT_OP_ENSURE:
		if (response.basic._reserved != 0)
			errx(EX_PROTOCOL, "invalid reserved field");
		printf("%s: loaded\n", request.name);
		break;
	}
	return (0);
}
