/* Raw, receive-only console capture for a private L2 null-modem endpoint. */
#include <sys/types.h>
#include <sys/stat.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct termios t;
	char buf[4096];
	ssize_t n, off, written;
	int fd, ready, flags;

	if (argc != 3)
		errx(2, "usage: l2-console device ready-file");
	/* Do not wait for carrier before the loader opens the other endpoint. */
	fd = open(argv[1], O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd == -1)
		err(1, "open %s", argv[1]);
	if (tcgetattr(fd, &t) == -1)
		err(1, "tcgetattr");
	cfmakeraw(&t);
	t.c_cflag |= CLOCAL;
	t.c_cflag &= ~(CCTS_OFLOW | CRTS_IFLOW | CDTR_IFLOW | CDSR_OFLOW);
	if (tcsetattr(fd, TCSANOW, &t) == -1)
		err(1, "tcsetattr");
	flags = fcntl(fd, F_GETFL);
	if (flags == -1 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1)
		err(1, "fcntl");
	/* Keep this fd open: closing/reopening an nmdm pair resets termios. */
	ready = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (ready == -1)
		err(1, "ready file");
	close(ready);
	for (;;) {
		n = read(fd, buf, sizeof(buf));
		if (n == -1) {
			if (errno == EINTR)
				continue;
			err(1, "console read");
		}
		if (n == 0) {
			/* Loader and bhyve open the peer in separate processes. */
			usleep(100000);
			continue;
		}
		for (off = 0; off < n; off += written) {
			written = write(STDOUT_FILENO, buf + off, n - off);
			if (written == -1) {
				if (errno == EINTR) { written = 0; continue; }
				err(1, "console output");
			}
		}
	}
}
