/* SPDX-License-Identifier: BSD-2-Clause */
/* Give a Linux exec child native pipe endpoints in a disposable guest. */
#include <sys/types.h>
#include <sys/wait.h>
#include <err.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	int p[2], ready[2], status;
	char go;
	pid_t child;

	if (argc != 4)
		errx(2, "usage: native-pipe-parent linux-probe case root|unprivileged");
	alarm(45);
	if (strcmp(argv[3], "unprivileged") == 0) {
		if (setgid(65534) != 0 || setuid(65534) != 0)
			err(1, "drop credentials before creating pipe");
	} else if (strcmp(argv[3], "root") != 0)
		errx(2, "invalid credential mode");
	if (pipe(p) != 0 || pipe(ready) != 0)
		err(1, "native pipe");
	child = fork();
	if (child == -1)
		err(1, "fork");
	if (child == 0) {
		/* Fresh launcher: neither pipe descriptor overlaps 10 or 11. */
		if (p[0] >= 10 || p[1] >= 10)
			errx(1, "unexpected inherited descriptors");
		if (dup2(p[0], 10) != 10 || dup2(p[1], 11) != 11)
			err(1, "dup2");
		close(p[0]);
		close(p[1]);
		close(ready[1]);
		if (read(ready[0], &go, 1) != 1)
			err(1, "parent synchronization");
		close(ready[0]);
		execl(argv[1], argv[1], argv[2], (char *)NULL);
		err(1, "exec Linux probe");
	}
	close(p[0]);
	close(p[1]);
	close(ready[0]);
	if (write(ready[1], "g", 1) != 1)
		err(1, "child synchronization");
	close(ready[1]);
	if (waitpid(child, &status, 0) != child)
		err(1, "waitpid");
	if (!WIFEXITED(status))
		errx(1, "probe did not exit normally: %#x", status);
	return (WEXITSTATUS(status));
}
