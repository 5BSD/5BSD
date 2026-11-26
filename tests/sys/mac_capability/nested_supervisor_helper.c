/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The child program of nested_supervisor_test.
 *
 *   lookup NAME TAG  (NR1) send TAG on the MAC_CAP_PROCESS_GET descriptor,
 *		then service_open(NAME) the way a base program looks a name up,
 *		and send NSH_NR1_SESSION on the session it gets.
 *   noroute	(NR6) the route is cleared before this exec: INFO reports
 *		none, GET and service_open answer ENOENT.
 *
 * The exit status names the step that did not behave as pinned
 * (nested_supervisor.h).
 */

#include <sys/types.h>
#include <sys/cap_process.h>
#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "nested_supervisor.h"

static int
send_on(int fd, const char *text)
{
	struct mac_capability_sendmsg_args sa;

	memset(&sa, 0, sizeof(sa));
	sa.payload = text;
	sa.payload_len = strlen(text);
	return (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa));
}

static int
mode_lookup(const char *name, const char *tag)
{
	int fd, session;

	fd = cap_process(MAC_CAP_PROCESS_GET, -1, 0, NULL);
	if (fd == -1) {
		warn("MAC_CAP_PROCESS_GET");
		return (NSH_EXIT_GET);
	}
	if (send_on(fd, tag) == -1) {
		warn("send on the GET descriptor");
		return (NSH_EXIT_SEND);
	}
	(void)close(fd);
	session = -1;
	if (service_open(name, &session) == -1) {
		warn("service_open(%s)", name);
		return (NSH_EXIT_LOOKUP);
	}
	if (send_on(session, NSH_NR1_SESSION) == -1) {
		warn("send on the session");
		return (NSH_EXIT_SESSION);
	}
	(void)close(session);
	return (NSH_EXIT_OK);
}

static int
mode_noroute(void)
{
	struct mac_cap_process_info info;
	int fd;

	memset(&info, 0, sizeof(info));
	if (cap_process(MAC_CAP_PROCESS_INFO, -1, 0, &info) == -1)
		return (NSH_EXIT_INFO);
	if (info.present != 0)
		return (NSH_EXIT_PRESENT);
	if (cap_process(MAC_CAP_PROCESS_GET, -1, 0, NULL) != -1 ||
	    errno != ENOENT)
		return (NSH_EXIT_GET);
	fd = -1;
	if (service_open("system.Notify", &fd) != -1 || errno != ENOENT)
		return (NSH_EXIT_LOOKUP);
	return (NSH_EXIT_OK);
}

int
main(int argc, char **argv)
{

	if (argc == 4 && strcmp(argv[1], NSH_MODE_LOOKUP) == 0)
		return (mode_lookup(argv[2], argv[3]));
	if (argc == 2 && strcmp(argv[1], NSH_MODE_NOROUTE) == 0)
		return (mode_noroute());
	fprintf(stderr, "usage: nested_supervisor_helper lookup name tag | "
	    "noroute\n");
	return (NSH_EXIT_USAGE);
}
