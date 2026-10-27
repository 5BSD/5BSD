/* SPDX-License-Identifier: BSD-2-Clause */
/* Run an explicitly selected generator with declared standard streams. */
#include <sys/stat.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	const char *input_path = NULL;
	int input, output, executable = 0, arg = 1;

	while (arg < argc) {
		if (strcmp(argv[arg], "--executable") == 0 && !executable) {
			executable = 1;
			arg++;
		} else if (strcmp(argv[arg], "--stdin") == 0 &&
		    input_path == NULL && arg + 1 < argc) {
			input_path = argv[arg + 1];
			arg += 2;
		} else {
			break;
		}
	}
	if (argc - arg < 2) {
		fprintf(stderr, "usage: stdout_redirect [--executable] "
		    "[--stdin input] output executable [arguments ...]\n");
		return (1);
	}
	if (input_path != NULL) {
		input = open(input_path, O_RDONLY);
		if (input < 0 || dup2(input, STDIN_FILENO) < 0) {
			perror(input_path);
			return (1);
		}
		if (input != STDIN_FILENO)
			close(input);
	}
	output = open(argv[arg], O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0 || dup2(output, STDOUT_FILENO) < 0) {
		perror(argv[arg]);
		return (1);
	}
	if (executable && fchmod(output, 0755) < 0) {
		perror(argv[arg]);
		return (1);
	}
	if (output != STDOUT_FILENO)
		close(output);
	execv(argv[arg + 1], argv + arg + 1);
	perror(argv[arg + 1]);
	return (1);
}
