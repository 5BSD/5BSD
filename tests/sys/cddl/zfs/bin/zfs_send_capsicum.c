/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#include <sys/types.h>
#include <sys/capsicum.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libzfs_core.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
usage(void)
{
	fprintf(stderr, "usage: zfs_send_capsicum snapshot output "
	    "write|none\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	cap_rights_t rights;
	bool writable;
	int error, fd;

	if (argc != 4)
		usage();
	if (strcmp(argv[3], "write") == 0)
		writable = true;
	else if (strcmp(argv[3], "none") == 0)
		writable = false;
	else
		usage();

	error = libzfs_core_init();
	if (error != 0)
		errc(1, error, "libzfs_core_init");

	fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		err(1, "open(%s)", argv[2]);

	if (writable)
		cap_rights_init(&rights, CAP_WRITE);
	else
		cap_rights_init(&rights);
	if (cap_rights_limit(fd, &rights) == -1)
		err(1, "cap_rights_limit");

	error = lzc_send(argv[1], NULL, fd, 0);
	if (close(fd) == -1)
		err(1, "close");
	libzfs_core_fini();

	if (writable && error != 0)
		errc(1, error, "lzc_send with CAP_WRITE");
	if (!writable) {
		if (error == 0)
			errx(1, "lzc_send succeeded without CAP_WRITE");
		if (error != ENOTCAPABLE)
			errc(1, error, "lzc_send without CAP_WRITE: expected %d",
			    ENOTCAPABLE);
	}

	return (0);
}
