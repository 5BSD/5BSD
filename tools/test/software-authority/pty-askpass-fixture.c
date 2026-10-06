/*-
 * pty_askpass PASSWORD CMD [ARG ...] -- run CMD on a pseudo-terminal, wait
 * for its password prompt, then type PASSWORD once.
 *
 * anoint(1) reads its password with readpassphrase(3) and RPP_REQUIRE_TTY --
 * the same tty-only rule sudo and doas use -- and readpassphrase calls
 * tcsetattr(TCSAFLUSH), which DISCARDS any input typed before the prompt.  So
 * a plain `printf pw | script cmd` races and usually loses: the byte is
 * flushed and the child blocks forever, or an empty line is read.  This helper
 * drives a real pty and sends the password only after the prompt appears, the
 * way an interactive user would, so the elevation integration test is
 * deterministic.  It streams the child's output through and exits with the
 * child's status.
 */
#include <sys/types.h>
#include <sys/wait.h>

#include <err.h>
#include <libutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct winsize ws = { .ws_row = 24, .ws_col = 80 };
	char buf[4096], acc[8192];
	size_t al = 0;
	ssize_t n;
	int master, status, sent = 0;
	pid_t pid;

	if (argc < 3)
		errx(2, "usage: pty_askpass PASSWORD CMD [ARG ...]");
	pid = forkpty(&master, NULL, NULL, &ws);
	if (pid == -1)
		err(2, "forkpty");
	if (pid == 0) {
		execvp(argv[2], &argv[2]);
		err(127, "exec %s", argv[2]);
	}
	memset(acc, 0, sizeof(acc));
	while ((n = read(master, buf, sizeof(buf))) > 0) {
		(void)fwrite(buf, 1, (size_t)n, stdout);
		(void)fflush(stdout);
		if (al + (size_t)n < sizeof(acc)) {
			memcpy(acc + al, buf, (size_t)n);
			al += (size_t)n;
		}
		if (!sent && strstr(acc, "assword") != NULL) {
			usleep(150000);		/* let tcsetattr settle */
			(void)write(master, argv[1], strlen(argv[1]));
			(void)write(master, "\n", 1);
			sent = 1;
		}
	}
	if (waitpid(pid, &status, 0) == -1)
		err(2, "waitpid");
	return (WIFEXITED(status) ? WEXITSTATUS(status) : 1);
}
