/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	int fd, jailed = 0;
	size_t size = sizeof(jailed);
	pid_t child;
	char fstype[] = "fstype", tmpfs[] = "tmpfs", fspath[] = "fspath",
	    root[] = "/";
	struct iovec iov[] = {
	    { .iov_base = fstype, .iov_len = 7 },
	    { .iov_base = tmpfs, .iov_len = 6 },
	    { .iov_base = fspath, .iov_len = 7 },
	    { .iov_base = root, .iov_len = 2 }
	};

	if (argc != 3)
		err(1, "arguments");
	if (sysctlbyname("security.jail.jailed", &jailed, &size, NULL, 0) != 0 || jailed != 1)
		errx(1, "not jailed");
	if (access(argv[2], F_OK) == 0 || errno != ENOENT)
		errx(1, "outside file visible");
	for (fd = 3; fd < getdtablesize(); fd++)
		if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
			errx(1, "inherited descriptor %d", fd);
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd != -1 || errno != EPROTONOSUPPORT)
		err(1, "IPv4 socket restriction");
	if (nmount(iov, 4, 0) != -1 || errno != EPERM)
		err(1, "mount restriction");
	if (chflags("/input", SF_IMMUTABLE) != -1 || errno != EPERM)
		err(1, "file flag restriction");
	if (strcmp(argv[1], "timeout") == 0)
		for (;;)
			pause();
	fd = open("/output", O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd == -1 || write(fd, "checked\n", 8) != 8 || close(fd) != 0)
		err(1, "output");
	if (strcmp(argv[1], "metadata") == 0) {
		if (chflags("/input", UF_NODUMP) != 0)
			err(1, "user flag change");
		return (0);
	}
	child = fork();
	if (child == -1)
		err(1, "fork");
	if (child == 0) {
		if (setsid() == -1)
			err(1, "setsid");
		for (;;)
			pause();
	}
	printf("DESCENDANT %d\n", child);
	return (0);
}
