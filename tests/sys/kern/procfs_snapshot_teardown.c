/* SPDX-License-Identifier: BSD-2-Clause */
/* Native lifetime coverage for the Starnix-derived uptime snapshot adapter. */
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	char mountpath[PATH_MAX], path[PATH_MAX], byte;
	int fds[32], failed = 0;
	int mounted = 0;

	if (argc != 2 || realpath(argv[1], mountpath) == NULL)
		return (1);
	if (snprintf(path, sizeof(path), "%s/uptime", mountpath) >=
	    (int)sizeof(path))
		return (2);
	struct iovec args[] = {
		{ .iov_base = (void *)"fstype", .iov_len = sizeof("fstype") },
		{ .iov_base = (void *)"linprocfs", .iov_len = sizeof("linprocfs") },
		{ .iov_base = (void *)"fspath", .iov_len = sizeof("fspath") },
		{ .iov_base = mountpath, .iov_len = strlen(mountpath) + 1 },
	};
	for (unsigned round = 0; round < 16; round++) {
		for (unsigned i = 0; i < nitems(fds); i++)
			fds[i] = -1;
		if (nmount(args, nitems(args), 0) != 0) {
			perror("nmount");
			return (3);
		}
		mounted = 1;
		for (unsigned i = 0; i < nitems(fds); i++) {
			fds[i] = open(path, O_RDONLY);
			if (fds[i] < 0 || read(fds[i], &byte, 1) != 1) {
				perror("open/read snapshot");
				failed = 4;
				goto cleanup;
			}
		}
		if (unmount(mountpath, MNT_FORCE) != 0) {
			perror("forced unmount");
			failed = 5;
			goto cleanup;
		}
		mounted = 0;
		for (unsigned i = 0; i < nitems(fds); i++) {
			errno = 0;
			if (read(fds[i], &byte, 1) != -1 || errno != ENXIO) {
				fprintf(stderr, "dead snapshot %u errno %d\n", i, errno);
				failed = 6;
				goto cleanup;
			}
		}
cleanup:
		for (unsigned i = 0; i < nitems(fds); i++) {
			if (fds[i] >= 0 && close(fds[i]) != 0 && failed == 0)
				failed = 7;
		}
		if (mounted && unmount(mountpath, MNT_FORCE) != 0)
			perror("cleanup unmount");
		if (failed != 0)
			return (failed);
	}
	puts("PROCFS_SNAPSHOT_TEARDOWN PASS 16 mounts 512 descriptors");
	return (0);
}
