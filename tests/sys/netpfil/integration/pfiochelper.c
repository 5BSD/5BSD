/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * Issue single /dev/pf ioctls for the seam tests (securelevel.sh,
 * quotas.sh) and print the result as "<ioctl>=<ok|errno name>".  pfctl(8)
 * wraps rule loads in a DIOCXBEGIN transaction, so the ether-rule check of
 * DIOCADDETHRULE (pf_ether.c) is only reachable with a direct ioctl.
 *
 *   pfiochelper addstate COUNT NET
 *	Add up to COUNT UDP states with DIOCADDSTATE (as pfsync would),
 *	10.NET.x.y:1000 -> 10.NET.x.y:2000 on lo0, without traffic or rules.
 *	Prints "DIOCADDSTATE=<ok|errno name> added=N": the first error stops.
 */

#include <sys/types.h>
#include <sys/endian.h>
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
	case ENOMEM:	return ("ENOMEM");
	default:	return (strerror(e));
	}
}

static void
usage(void)
{
	fprintf(stderr, "usage: pfiochelper ethadd|getstatus|start\n"
	    "       pfiochelper addstate count net\n");
	exit(2);
}

/* DIOCADDSTATE count UDP states in 10.net.0.0/16; the first error stops. */
static void
addstates(int dev, long count, long net)
{
	struct pfioc_state ps;
	struct pfsync_state *sp = &ps.state;
	long i;
	int e = 0;

	for (i = 0; i < count; i++) {
		memset(&ps, 0, sizeof(ps));
		sp->id = htobe64(((uint64_t)net << 32) | (uint64_t)(i + 1));
		strlcpy(sp->ifname, "lo0", sizeof(sp->ifname));
		sp->af = AF_INET;
		sp->proto = IPPROTO_UDP;
		sp->direction = PF_IN;
		sp->timeout = PFTM_UDP_MULTIPLE;
		sp->creatorid = htonl(0x5bfd);
		sp->rule = htonl(-1);
		sp->anchor = htonl(-1);
		sp->nat_rule = htonl(-1);
		sp->rtableid[0] = sp->rtableid[1] = (int32_t)htonl((uint32_t)-1);
		sp->key[0].af = sp->key[1].af = AF_INET;
		sp->key[0].addr[0].v4.s_addr = htonl(0x0a000000 |
		    ((net & 0xff) << 16) | (i & 0xffff));
		sp->key[0].addr[1] = sp->key[0].addr[0];
		sp->key[0].port[0] = htons(1000);
		sp->key[0].port[1] = htons(2000);
		sp->key[1] = sp->key[0];
		if (ioctl(dev, DIOCADDSTATE, &ps) == -1) {
			e = errno;
			break;
		}
	}
	printf("DIOCADDSTATE=%s added=%ld\n", errname(e), i);
}

int
main(int argc, char **argv)
{
	struct pfioc_eth_rule er;
	struct pf_status st;
	int dev, e;

	if (argc != 2 && !(argc == 4 && strcmp(argv[1], "addstate") == 0))
		usage();
	dev = open("/dev/pf", O_RDWR);
	if (dev == -1)
		err(1, "/dev/pf");
	if (strcmp(argv[1], "addstate") == 0) {
		addstates(dev, strtol(argv[2], NULL, 10),
		    strtol(argv[3], NULL, 10));
	} else if (strcmp(argv[1], "ethadd") == 0) {
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
