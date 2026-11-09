/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * paths_statburst: stat(2) one path count times; the process
 * paths_fast_test traces with dtrace -c.
 *
 * usage: paths_statburst path count [capmode]
 *
 * With "capmode", the parent directory is opened, the process enters
 * capability mode and the burst is fstatat(dirfd, basename): lockless
 * lookup always declines in capability mode, which gives the test the
 * decline site to compare with.  Exit status 0 when every call succeeded.
 */

#include <sys/capsicum.h>
#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct stat sb;
	char *dcopy, *bcopy, *dir, *base;
	long count, i;
	int dfd, bad;

	if (argc < 3)
		errx(2, "usage: paths_statburst path count [capmode]");
	count = strtol(argv[2], NULL, 10);
	bad = 0;
	if (argc > 3 && strcmp(argv[3], "capmode") == 0) {
		dcopy = strdup(argv[1]);
		bcopy = strdup(argv[1]);
		if (dcopy == NULL || bcopy == NULL)
			err(2, "strdup");
		dir = dirname(dcopy);
		base = basename(bcopy);
		dfd = open(dir, O_DIRECTORY | O_RDONLY);
		if (dfd < 0)
			err(2, "open %s", dir);
		if (cap_enter() != 0)
			err(2, "cap_enter");
		for (i = 0; i < count; i++)
			if (fstatat(dfd, base, &sb, 0) != 0)
				bad++;
	} else {
		for (i = 0; i < count; i++)
			if (stat(argv[1], &sb) != 0)
				bad++;
	}
	return (bad == 0 ? 0 : 1);
}
