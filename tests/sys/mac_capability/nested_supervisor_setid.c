/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * NR8's set-uid root program (installed mode 4555).  nested_supervisor_test
 * runs it from an unprivileged process whose parent installed a route; it
 * reports what the set-id exec left of that route over the route itself,
 * so the report reaches the parent only if the route survived.  It links
 * nothing but libc.
 */

#include <sys/types.h>
#include <sys/cap_process.h>
#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "nested_supervisor.h"

int
main(void)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_cap_process_info info;
	struct nsh_setid_report report;
	int fd;

	memset(&report, 0, sizeof(report));
	report.issetugid = issetugid();
	report.ruid = getuid();
	report.euid = geteuid();
	/*
	 * Nothing below needs root: drop it, keeping the set-id mark
	 * (P_SUGID stays until the next exec).  The route is per process
	 * and GET checks only the prison, so the pin loses nothing.
	 */
	if (setuid(getuid()) == -1)
		return (NSH_EXIT_SETUID);
	memset(&info, 0, sizeof(info));
	report.info_err = cap_process(MAC_CAP_PROCESS_INFO, -1, 0, &info) ==
	    -1 ? errno : 0;
	report.present = info.present;
	report.generation = info.generation;
	fd = cap_process(MAC_CAP_PROCESS_GET, -1, 0, NULL);
	report.get_err = fd == -1 ? errno : 0;
	if (fd == -1)
		return (NSH_EXIT_GET);
	memset(&sa, 0, sizeof(sa));
	sa.payload = &report;
	sa.payload_len = sizeof(report);
	if (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1)
		return (NSH_EXIT_SEND);
	return (NSH_EXIT_OK);
}
