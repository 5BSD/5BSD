/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Run an explicitly selected generator with stdout bound to its declared
 * output and, with -i, stdin bound to a declared input (the "sh gen <
 * input > output" recipes of maintained Make, without a shell pipeline).
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int
bind_fd(const char *path, int flags, int fd)
{
	int f;

	f = open(path, flags, 0666);
	if (f < 0 || dup2(f, fd) < 0) {
		perror(path);
		return (-1);
	}
	if (f != fd)
		close(f);
	return (0);
}

int
main(int argc, char **argv)
{

	if (argc >= 3 && strcmp(argv[1], "-i") == 0) {
		if (bind_fd(argv[2], O_RDONLY, STDIN_FILENO) != 0)
			return (1);
		argc -= 2;
		argv += 2;
	}
	if (argc < 3) {
		fprintf(stderr, "usage: stdout_redirect [-i input] output executable "
		    "[arguments ...]\n");
		return (1);
	}
	if (bind_fd(argv[1], O_WRONLY | O_CREAT | O_TRUNC, STDOUT_FILENO) != 0)
		return (1);
	execv(argv[2], argv + 2);
	perror(argv[2]);
	return (1);
}
