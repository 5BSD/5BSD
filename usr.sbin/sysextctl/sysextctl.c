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

static void __dead2
usage(void)
{
	fprintf(stderr, "usage: sysextctl list | status module | load module | reload\n");
	exit(EX_USAGE);
}

int
main(int argc, char **argv)
{
	struct service_session *session;
	char names[SERVICE_EXTENSION_LIST_MAX][SERVICE_EXTENSION_NAME_MAX];
	size_t count, i;
	int fd, error, result, loaded, operation;

	if (argc == 2 && strcmp(argv[1], "list") == 0)
		operation = 0;
	else if (argc == 3 && strcmp(argv[1], "status") == 0)
		operation = 1;
	else if (argc == 3 && strcmp(argv[1], "load") == 0)
		operation = 2;
	else if (argc == 2 && strcmp(argv[1], "reload") == 0)
		operation = 3;
	else
		usage();
	if (service_open("system.SystemExtension", &fd) == -1)
		err(EX_UNAVAILABLE, "cannot reach SystemExtension capability");
	if (service_session_create(fd, &session) == -1) {
		error = errno;
		close(fd);
		errno = error;
		err(EX_UNAVAILABLE, "SystemExtension session");
	}
	switch (operation) {
	case 0:
		result = service_session_extension_list(session, names,
		    SERVICE_EXTENSION_LIST_MAX, &count);
		break;
	case 1:
		result = service_session_extension_stat(session, argv[2], &loaded);
		break;
	case 2:
		result = service_session_extension_load(session, argv[2]);
		break;
	default:
		result = service_session_extension_reload(session);
		break;
	}
	error = errno;
	service_session_close(session);
	if (result == -1) {
		errno = error;
		if (operation != 3 && (error == EINVAL || error == ENAMETOOLONG))
			err(EX_USAGE, "invalid module name or request");
		err(error == EPROTO ? EX_PROTOCOL : EX_UNAVAILABLE,
		    "SystemExtension %s", argv[1]);
	}
	if (operation == 3) {
		puts("SystemExtension policy reloaded");
	} else if (operation == 0) {
		for (i = 0; i < count; i++)
			puts(names[i]);
	} else {
		printf("%s: %s\n", argv[2],
		    operation == 2 || loaded ? "loaded" : "not loaded");
		if (operation == 1 && !loaded)
			return (1);
	}
	return (0);
}
