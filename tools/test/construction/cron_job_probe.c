/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int
main(void)
{
	char input[64];
	ssize_t count;
	int leaked;

	leaked = fcntl(199, F_GETFD) != -1 || errno != EBADF;
	count = read(STDIN_FILENO, input, sizeof(input) - 1);
	if (count < 0)
		return (2);
	input[count] = '\0';
	printf("uid=%u gid=%u leaked=%d input=%s", (unsigned)getuid(),
	    (unsigned)getgid(), leaked, input);
	fprintf(stderr, "cron-job-stderr\n");
	return (leaked ? 1 : 0);
}
