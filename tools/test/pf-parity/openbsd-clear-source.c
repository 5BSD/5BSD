/* SPDX-License-Identifier: BSD-2-Clause */
/* Reference-only workaround: pinned OpenBSD pfctl leaves rdomain uninitialized. */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>
#include <arpa/inet.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct pfioc_source_kill ioc = {0};
	int fd;

	if (argc != 2 || access("/root/pf-parity-disposable", F_OK) != 0)
		errx(1, "requires disposable guest marker and one address");
	ioc.id = 1;
	ioc.rdomain = 0;
	ioc.af = AF_INET;
	if (inet_pton(AF_INET, argv[1], &ioc.addr.v4) != 1) {
		ioc.af = AF_INET6;
		if (inet_pton(AF_INET6, argv[1], &ioc.addr.v6) != 1)
			errx(1, "invalid address");
	}
	if ((fd = open("/dev/pf", O_RDWR)) == -1)
		err(1, "open pf");
	if (ioctl(fd, DIOCCLRSOURCE, &ioc) == -1)
		err(1, "clear source");
	close(fd);
	return (0);
}
