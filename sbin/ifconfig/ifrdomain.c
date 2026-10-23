/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * Routing domains (rdomain(4)) in OpenBSD ifconfig(8) syntax:
 * "rdomain N", "-rdomain" and the " rdomain N" field of the status line,
 * and OpenBSD's implicit creation of a cloneable interface that is
 * configured before it exists.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/route.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ifconfig.h"

static void
setifrdomain(if_ctx *ctx, const char *val, int dummy __unused)
{
	struct ifreq ifr = {};
	const char *errstr;
	int rdomain;

	rdomain = strtonum(val, 0, RT_TABLEID_MAX, &errstr);
	if (errstr != NULL)
		errx(1, "rdomain %s: %s", val, errstr);
	ifr.ifr_rdomainid = rdomain;
	if (ioctl_ctx_ifr(ctx, SIOCSIFRDOMAIN, &ifr) < 0)
		warn("SIOCSIFRDOMAIN");
}

static void
unsetifrdomain(if_ctx *ctx, const char *val __unused, int dummy __unused)
{
	struct ifreq ifr = {};

	ifr.ifr_rdomainid = 0;
	if (ioctl_ctx_ifr(ctx, SIOCSIFRDOMAIN, &ifr) < 0)
		warn("SIOCSIFRDOMAIN");
}

/* Routing domain of the interface, or -1. */
int
get_rdomain(if_ctx *ctx)
{
	struct ifreq ifr = {};

	if (ioctl_ctx_ifr(ctx, SIOCGIFRDOMAIN, &ifr) < 0)
		return (-1);
	return (ifr.ifr_rdomainid);
}

/* The " rdomain N" field of the status line (OpenBSD). */
void
print_rdomain(if_ctx *ctx)
{
	int rdomain;

	if ((rdomain = get_rdomain(ctx)) > 0)
		printf(" rdomain %d", rdomain);
}

/*
 * OpenBSD creates a cloneable interface that does not exist yet when it is
 * configured ("ifconfig vether0 10.0.0.1/24", "ifconfig lo5 rdomain 5").
 * Returns true when name has been created.
 */
bool
ifautocreate(const char *name, const char *arg)
{
	struct ifreq ifr = {};
	int s;
	bool created = false;

	if (arg == NULL || strcmp(arg, "destroy") == 0 ||
	    strcmp(arg, "create") == 0 || strcmp(arg, "plumb") == 0 ||
	    strcmp(arg, "-vnet") == 0 || strlen(name) >= sizeof(ifr.ifr_name))
		return (false);
	if ((s = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0)
		return (false);
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCIFCREATE2, &ifr) == 0) {
		if (strcmp(ifr.ifr_name, name) == 0)
			created = true;
		else
			(void)ioctl(s, SIOCIFDESTROY, &ifr);
	}
	close(s);
	return (created);
}

static struct cmd rdomain_cmds[] = {
	DEF_CMD_ARG("rdomain", setifrdomain),
	DEF_CMD("-rdomain", 0, unsetifrdomain),
};

static __constructor void
rdomain_ctor(void)
{
	for (size_t i = 0; i < nitems(rdomain_cmds); i++)
		cmd_register(&rdomain_cmds[i]);
}
