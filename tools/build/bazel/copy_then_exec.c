/* SPDX-License-Identifier: BSD-2-Clause */
/* Copy declared inputs to fresh outputs before running a mutating generator. */
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int
copy_file(const char *source, const char *target, mode_t mode)
{
	char buffer[65536];
	ssize_t count, written, offset;
	int input, output, error = 0;

	input = open(source, O_RDONLY);
	if (input == -1) {
		perror(source);
		return (1);
	}
	/* Never truncate an existing output or an alias of the original input. */
	output = open(target, O_WRONLY | O_CREAT | O_EXCL, mode);
	if (output == -1) {
		perror(target);
		close(input);
		return (1);
	}
	for (;;) {
		count = read(input, buffer, sizeof(buffer));
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0) {
			if (count < 0) {
				perror(source);
				error = 1;
			}
			break;
		}
		for (offset = 0; offset < count; offset += written) {
			written = write(output, buffer + offset, count - offset);
			if (written < 0 && errno == EINTR) {
				written = 0;
				continue;
			}
			if (written <= 0) {
				perror(target);
				error = 1;
				goto done;
			}
		}
	}
 done:
	if (close(output) != 0) {
		perror(target);
		error = 1;
	}
	close(input);
	return (error);
}

int
main(int argc, char **argv)
{
	int arg = 1;

	while (arg + 2 < argc && (strcmp(argv[arg], "--copy") == 0 ||
	    strcmp(argv[arg], "--copy-executable") == 0)) {
		if (copy_file(argv[arg + 1], argv[arg + 2],
		    strcmp(argv[arg], "--copy-executable") == 0 ? 0700 : 0600) != 0)
			return (1);
		arg += 3;
	}
	if (arg + 1 >= argc || strcmp(argv[arg], "--") != 0) {
		fprintf(stderr, "usage: copy_then_exec [--copy|--copy-executable input output ...] "
		    "-- executable [arguments ...]\n");
		return (1);
	}
	execv(argv[arg + 1], argv + arg + 1);
	perror(argv[arg + 1]);
	return (1);
}
