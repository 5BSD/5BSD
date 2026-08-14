/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>
#include <sys/nvpair.h>

#include <err.h>
#include <libzfs_core.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
usage(void)
{
	fprintf(stderr, "usage: zfs_destroy_snaps legacy snapshot\n"
	    "       zfs_destroy_snaps batch snapshot ...\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	nvlist_t *errors, *snaps;
	int error, i;

	if (argc < 3)
		usage();
	if (strcmp(argv[1], "legacy") == 0 && argc != 3)
		usage();
	if (strcmp(argv[1], "legacy") != 0 &&
	    strcmp(argv[1], "batch") != 0)
		usage();

	error = libzfs_core_init();
	if (error != 0)
		errc(1, error, "libzfs_core_init");

	errors = NULL;
	snaps = NULL;
	if (strcmp(argv[1], "legacy") == 0) {
		error = lzc_destroy(argv[2]);
	} else {
		snaps = fnvlist_alloc();
		for (i = 2; i < argc; i++)
			fnvlist_add_boolean(snaps, argv[i]);
		error = lzc_destroy_snaps(snaps, B_FALSE, &errors);
	}

	nvlist_free(errors);
	nvlist_free(snaps);
	libzfs_core_fini();
	if (error != 0)
		errc(1, error, "%s destroy", argv[1]);
	return (0);
}
