/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * service_probe <service-name> -- integration-test helper.
 *
 * Resolves a named capability service the way an ordinary CLI does: over the
 * ambient lookup channel a login session inherits (SERVICE_LOOKUP_FD), via
 * service_open().  This is the exact path a shell-run tool (networkcmpctl,
 * notifyctl, ...) takes, so a successful probe proves the service is
 * registered and reachable/activatable from a login session -- including the
 * on-demand activation that a lookup must trigger.
 *
 * Prints one line to stdout and exits:
 *   0  "OK <name> fd=<n>"          resolved + connected
 *   1  "FAIL <name> errno=<e> <s>" not reachable (ENOENT/EBADF/ETIMEDOUT/...)
 *   2  usage / no ambient channel in this environment (test should skip)
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "service_bootstrap.h"

int
main(int argc, char **argv)
{
	int fd, rv;

	if (argc != 2) {
		fprintf(stderr, "usage: service_probe <service-name>\n");
		return (2);
	}

	/*
	 * No ambient lookup channel means this is not a plane login session
	 * (e.g. run on the host, off the plane): the caller should skip rather
	 * than fail.  Exit 2 is the distinct "not applicable here" signal.
	 */
	if (service_ambient_lookup_fd() < 0) {
		printf("SKIP %s no-ambient-channel\n", argv[1]);
		return (2);
	}

	fd = -1;
	rv = service_open(argv[1], &fd);
	if (rv == 0 && fd >= 0) {
		printf("OK %s fd=%d\n", argv[1], fd);
		(void)close(fd);
		return (0);
	}
	printf("FAIL %s errno=%d %s\n", argv[1], errno, strerror(errno));
	return (1);
}
