/* SPDX-License-Identifier: BSD-2-Clause */
/* Run an explicitly selected generator with stdout bound to its declared output. */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	int output;

	if (argc < 3) {
		fprintf(stderr, "usage: stdout_redirect output executable [arguments ...]\n");
		return (1);
	}
	output = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0 || dup2(output, STDOUT_FILENO) < 0) {
		perror(argv[1]);
		return (1);
	}
	if (output != STDOUT_FILENO)
		close(output);
	execv(argv[2], argv + 2);
	perror(argv[2]);
	return (1);
}
