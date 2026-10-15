/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * Issue single /dev/pf ioctls for the seam tests (securelevel.sh) and
 * print the result as "<ioctl>=<ok|errno name>".  pfctl(8) wraps rule
 * loads in a DIOCXBEGIN transaction, so the ether-rule check of
 * DIOCADDETHRULE (pf_ether.c) is only reachable with a direct ioctl.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *
errname(int e)
{
	switch (e) {
	case 0:		return ("ok");
	case EPERM:	return ("EPERM");
	case EACCES:	return ("EACCES");
	case EBUSY:	return ("EBUSY");
	case EINVAL:	return ("EINVAL");
	case ENOENT:	return ("ENOENT");
	default:	return (strerror(e));
	}
}

static void
usage(void)
{
	fprintf(stderr, "usage: pfiochelper ethadd|getstatus|start\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	struct pfioc_eth_rule er;
	struct pf_status st;
	int dev, e;

	if (argc != 2)
		usage();
	dev = open("/dev/pf", O_RDWR);
	if (dev == -1)
		err(1, "/dev/pf");
	if (strcmp(argv[1], "ethadd") == 0) {
		/*
		 * A zeroed request: below securelevel 2 the ticket check
		 * refuses it (EBUSY/EINVAL); at securelevel 2 the
		 * securelevel check refuses it first (EPERM).
		 */
		memset(&er, 0, sizeof(er));
		e = ioctl(dev, DIOCADDETHRULE, &er) == -1 ? errno : 0;
		printf("DIOCADDETHRULE=%s\n", errname(e));
	} else if (strcmp(argv[1], "getstatus") == 0) {
		memset(&st, 0, sizeof(st));
		e = ioctl(dev, DIOCGETSTATUS, &st) == -1 ? errno : 0;
		printf("DIOCGETSTATUS=%s running=%d\n", errname(e),
		    e == 0 ? st.running : -1);
	} else if (strcmp(argv[1], "start") == 0) {
		e = ioctl(dev, DIOCSTART) == -1 ? errno : 0;
		printf("DIOCSTART=%s\n", errname(e));
	} else
		usage();
	close(dev);
	return (0);
}
