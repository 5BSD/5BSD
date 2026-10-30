/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Run an explicitly selected generator with declared standard streams:
 * stdout bound to its declared output and, with -i or --stdin, stdin bound
 * to a declared input (the "sh gen < input > output" recipes of maintained
 * Make, without a shell pipeline); --executable makes the output mode 0755.
 */
#include <sys/stat.h>

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
	const char *input_path = NULL;
	int executable = 0, arg = 1;

	while (arg < argc) {
		if (strcmp(argv[arg], "--executable") == 0 && !executable) {
			executable = 1;
			arg++;
		} else if ((strcmp(argv[arg], "--stdin") == 0 ||
		    strcmp(argv[arg], "-i") == 0) &&
		    input_path == NULL && arg + 1 < argc) {
			input_path = argv[arg + 1];
			arg += 2;
		} else {
			break;
		}
	}
	if (argc - arg < 2) {
		fprintf(stderr, "usage: stdout_redirect [--executable] "
		    "[-i | --stdin input] output executable [arguments ...]\n");
		return (1);
	}
	if (input_path != NULL &&
	    bind_fd(input_path, O_RDONLY, STDIN_FILENO) != 0)
		return (1);
	if (bind_fd(argv[arg], O_WRONLY | O_CREAT | O_TRUNC,
	    STDOUT_FILENO) != 0)
		return (1);
	if (executable && fchmod(STDOUT_FILENO, 0755) < 0) {
		perror(argv[arg]);
		return (1);
	}
	execv(argv[arg + 1], argv + arg + 1);
	perror(argv[arg + 1]);
	return (1);
}
