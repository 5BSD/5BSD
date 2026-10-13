/* SPDX-License-Identifier: BSD-2-Clause */
/* Change only the shared packet-delay limit; never reload root PF policy. */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>
#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct pfioc_limit limit = { .index = PF_LIMIT_PKTDELAY_PKTS };
	const char *error;
	int fd;

	if (argc > 2)
		errx(1, "usage: delay_pool_limit [limit]");
	if (argc == 2) {
		limit.limit = strtonum(argv[1], 0, UINT_MAX, &error);
		if (error != NULL)
			errx(1, "limit: %s", error);
	}
	fd = open("/dev/pf", argc == 2 ? O_RDWR : O_RDONLY);
	if (fd == -1)
		err(1, "/dev/pf");
	if (ioctl(fd, argc == 2 ? DIOCSETLIMIT : DIOCGETLIMIT, &limit) == -1)
		err(1, "packet-delay limit");
	if (argc == 1)
		printf("%u\n", limit.limit);
	close(fd);
	return (0);
}
