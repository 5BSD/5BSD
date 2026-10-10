/*-
 * Copyright (c) 2002-2003 Luigi Rizzo
 * Copyright (c) 1996 Alex Nash, Paul Traina, Poul-Henning Kamp
 * Copyright (c) 1994 Ugen J.S.Antsilevich
 *
 * Idea and grammar partially left from:
 * Copyright (c) 1993 Daniel Boulet
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 *
 * NEW command line interface for IP firewall facility
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_dn_flow.h>
#include <netinet/ip_dummynet.h>
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include "dnctl.h"

/* The standalone tool can issue only Dummynet control requests. */
int
do_cmd(int optname, void *optval, uintptr_t optlen)
{
	static int fd = -1;

	if (optname != IP_DUMMYNET3 && optname != -IP_DUMMYNET3) {
		errno = EINVAL;
		return (-1);
	}
	if (g_co.test_only)
		return (0);
	if (fd == -1)
		fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (fd == -1)
		err(EX_UNAVAILABLE, "socket");
	if (optname < 0)
		return (getsockopt(fd, IPPROTO_IP, -optname, optval,
		    (socklen_t *)optlen));
	return (setsockopt(fd, IPPROTO_IP, optname, optval, optlen));
}
