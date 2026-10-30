/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

static inline int
open_progdir(const char *prog)
{
	char pdir[PATH_MAX], *resolved;
	int dfd;

	resolved = realpath(prog, &pdir[0]);
	assert(resolved != NULL);

	resolved = dirname(&pdir[0]);
	assert(resolved != NULL);

	dfd = open(resolved, O_DIRECTORY);
	assert(dfd != -1);

	return (dfd);
}

/* Optional explicit fixture path supports out-of-tree test runners. */
static inline int
open_test_fixture(int argc, char *argv[], const char *name)
{
	int dfd, fd;

	assert(argc == 1 || argc == 2);
	if (argc == 2)
		return (open(argv[1], O_RDONLY));
	dfd = open_progdir(argv[0]);
	fd = openat(dfd, name, O_RDONLY);
	close(dfd);
	return (fd);
}
