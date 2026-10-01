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
	fprintf(stderr, "usage: sysextctl list | config | reload | restore\n"
	    "       sysextctl status|load|allow|deny|reset|enable|disable module\n");
	exit(EX_USAGE);
}

static void
print_info(const struct service_extension_info *info)
{
	printf("%s: %s, boot=%s, loaded=%s, policy=%s%s\n", info->name,
	    info->allowed ? "allowed" : "denied",
	    info->enabled ? (info->allowed ? "enabled" : "blocked") : "disabled",
	    info->allowed ? (info->loaded ? "yes" : "no") : "undisclosed",
	    info->overridden ? "override" : "default",
	    info->ready ? "" : " (bootstrap; persistent policy not ready)");
}

int
main(int argc, char **argv)
{
	struct service_session *session;
	struct service_extension_info info;
	enum service_extension_action action = SERVICE_EXTENSION_RESTORE;
	char cursor[SERVICE_EXTENSION_NAME_MAX] = "";
	const char *verb, *name = NULL;
	int fd, error, result = 0, operation;

	if (argc < 2)
		usage();
	verb = argv[1];
	if (argc == 2 && strcmp(verb, "list") == 0)
		operation = 0;
	else if (argc == 2 && strcmp(verb, "config") == 0)
		operation = 1;
	else if (argc == 3 && strcmp(verb, "status") == 0)
		operation = 2;
	else if (argc == 3 && strcmp(verb, "load") == 0)
		operation = 3;
	else if (argc == 2 && strcmp(verb, "reload") == 0)
		operation = 4;
	else {
		operation = 5;
		if (argc == 2 && strcmp(verb, "restore") == 0)
			action = SERVICE_EXTENSION_RESTORE;
		else if (argc != 3)
			usage();
		else if (strcmp(verb, "allow") == 0)
			action = SERVICE_EXTENSION_ALLOW;
		else if (strcmp(verb, "deny") == 0)
			action = SERVICE_EXTENSION_DENY;
		else if (strcmp(verb, "reset") == 0)
			action = SERVICE_EXTENSION_RESET;
		else if (strcmp(verb, "enable") == 0)
			action = SERVICE_EXTENSION_ENABLE;
		else if (strcmp(verb, "disable") == 0)
			action = SERVICE_EXTENSION_DISABLE;
		else
			usage();
	}
	if (argc == 3)
		name = argv[2];
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
	case 1:
		while ((result = service_session_extension_info(session, cursor, 1,
		    &info)) == 0) {
			if (operation == 1)
				print_info(&info);
			else if (info.allowed)
				puts(info.name);
			strlcpy(cursor, info.name, sizeof(cursor));
		}
		if (errno == ENOENT)
			result = 0;
		break;
	case 2:
		result = service_session_extension_info(session, name, 0, &info);
		if (result == 0)
			print_info(&info);
		break;
	case 3:
		result = service_session_extension_load(session, name);
		break;
	case 4:
		result = service_session_extension_reload(session);
		break;
	default:
		result = service_session_extension_manage(session, action, name);
		break;
	}
	error = errno;
	service_session_close(session);
	if (result == -1) {
		errno = error;
		if (error == EINVAL || error == ENAMETOOLONG)
			err(EX_USAGE, "invalid module name or request");
		err(error == EPROTO ? EX_PROTOCOL :
		    error == EAGAIN ? EX_TEMPFAIL : EX_UNAVAILABLE,
		    "SystemExtension %s", verb);
	}
	if (operation == 3)
		printf("%s: loaded\n", name);
	else if (operation == 4)
		puts("SystemExtension defaults reloaded; administrator overrides preserved");
	else if (operation == 5) {
		if (action == SERVICE_EXTENSION_RESTORE)
			puts("SystemExtension boot activations restored");
		else
			printf("%s: %s saved; existing loads remain until reboot\n", name, verb);
	}
	if (operation == 2 && (!info.allowed || !info.loaded))
		return (1);
	return (0);
}
