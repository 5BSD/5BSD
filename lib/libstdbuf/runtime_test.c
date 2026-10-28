/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Exit without stdio flushing: only constructor-selected buffering can
 * determine whether the parent receives the line. */
int
main(int argc, char **argv)
{
	char self[PATH_MAX], library[PATH_MAX], output[16];
	const char *modes[] = { "0", "L", "B", "4k" };
	const char *streams[] = { "_STDBUF_O", "_STDBUF_E" };
	int fd[2], status = -1;
	pid_t child;
	ssize_t n, total;

	if (argc == 2 && strcmp(argv[1], "child-out") == 0) {
		fputs("x\n", stdout);
		_exit(0);
	}
	if (argc == 2 && strcmp(argv[1], "child-err") == 0) {
		fputs("x\n", stderr);
		_exit(0);
	}
	if (argc != 2 || getenv("TEST_SRCDIR") == NULL ||
	    realpath(argv[0], self) == NULL)
		return (1);
	if (snprintf(library, sizeof(library), "%s/%s",
	    getenv("TEST_SRCDIR"), argv[1]) >= (int)sizeof(library))
		return (1);
	for (size_t s = 0; s < 2; s++) {
		for (size_t m = 0; m < 4; m++) {
			if (pipe(fd) < 0 || (child = fork()) < 0)
				return (1);
			if (child == 0) {
				close(fd[0]);
				if (dup2(fd[1], s == 0 ? STDOUT_FILENO : STDERR_FILENO) < 0)
					_exit(2);
				close(fd[1]);
				unsetenv("_STDBUF_I");
				unsetenv("_STDBUF_O");
				unsetenv("_STDBUF_E");
				if (setenv("LD_PRELOAD", library, 1) != 0 ||
				    setenv(streams[s], modes[m], 1) != 0)
					_exit(2);
				execl(self, self, s == 0 ? "child-out" : "child-err", NULL);
				_exit(2);
			}
			close(fd[1]);
			total = 0;
			while ((n = read(fd[0], output + total, sizeof(output) - total)) != 0) {
				if (n < 0) {
					if (errno == EINTR)
						continue;
					return (1);
				}
				total += n;
				if (total == sizeof(output))
					return (1);
			}
			close(fd[0]);
			if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
			    WEXITSTATUS(status) != 0 || total != (m < 2 ? 2 : 0) ||
			    (total == 2 && memcmp(output, "x\n", 2) != 0)) {
				fprintf(stderr, "%s=%s: bytes=%zd status=%d\n", streams[s], modes[m], total, status);
				return (1);
			}
		}
	}
	return (0);
}
