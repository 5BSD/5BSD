/*-
 * SPDX-License-Identifier: ISC
 *
 * pfsync(4) and pflow(4) configuration, from OpenBSD sbin/ifconfig/ifconfig.c
 * (revision facc8d7ec5d1, see contrib/openbsd-pf/README.5BSD), adapted to
 * the 5BSD ifconfig module interface.  Interface ioctls are OpenBSD's
 * (SIOC[GS]ETPFSYNC, SIOC[GS]ETPFLOW).
 *
 * Copyright (c) 1983, 1993 The Regents of the University of California.
 * Copyright (c) 1997, 1998, 2000 The NetBSD Foundation, Inc.
 * (OpenBSD ifconfig.c copyright notice applies.)
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "openbsd_compat.h"
#include <net/pfvar.h>
#include <net/if_pfsync.h>
#include <net/if_pflow.h>

#include <err.h>
#include <limits.h>

#ifndef HOST_NAME_MAX
#define	HOST_NAME_MAX	_POSIX_HOST_NAME_MAX
#endif
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ifconfig.h"

#ifndef ifr_data
#define	ifr_data	ifr_ifru.ifru_data
#endif

static void
setpfsync_syncdev(if_ctx *ctx, const char *val, int d)
{
	struct ifreq ifr = {};
	struct pfsyncreq preq;

	bzero(&preq, sizeof(struct pfsyncreq));
	ifr.ifr_data = (caddr_t)&preq;

	if (ioctl_ctx_ifr(ctx, SIOCGETPFSYNC, &ifr) == -1)
		err(1, "%s: SIOCGETPFSYNC", ifr.ifr_name);

	strlcpy(preq.pfsyncr_syncdev, val, sizeof(preq.pfsyncr_syncdev));

	if (ioctl_ctx_ifr(ctx, SIOCSETPFSYNC, &ifr) == -1)
		err(1, "%s: SIOCSETPFSYNC", ifr.ifr_name);
}

static void
unsetpfsync_syncdev(if_ctx *ctx, const char *val, int d)
{
	struct ifreq ifr = {};
	struct pfsyncreq preq;

	bzero(&preq, sizeof(struct pfsyncreq));
	ifr.ifr_data = (caddr_t)&preq;

	if (ioctl_ctx_ifr(ctx, SIOCGETPFSYNC, &ifr) == -1)
		err(1, "%s: SIOCGETPFSYNC", ifr.ifr_name);

	bzero(&preq.pfsyncr_syncdev, sizeof(preq.pfsyncr_syncdev));

	if (ioctl_ctx_ifr(ctx, SIOCSETPFSYNC, &ifr) == -1)
		err(1, "%s: SIOCSETPFSYNC", ifr.ifr_name);
}

static void
setpfsync_syncpeer(if_ctx *ctx, const char *val, int d)
{
	struct ifreq ifr = {};
	struct pfsyncreq preq;
	struct addrinfo hints, *peerres;
	int ecode;

	bzero(&preq, sizeof(struct pfsyncreq));
	ifr.ifr_data = (caddr_t)&preq;

	if (ioctl_ctx_ifr(ctx, SIOCGETPFSYNC, &ifr) == -1)
		err(1, "%s: SIOCGETPFSYNC", ifr.ifr_name);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/

	if ((ecode = getaddrinfo(val, NULL, &hints, &peerres)) != 0)
		errx(1, "error in parsing address string: %s",
		    gai_strerror(ecode));

	if (peerres->ai_addr->sa_family != AF_INET)
		errx(1, "only IPv4 addresses supported for the syncpeer");

	preq.pfsyncr_syncpeer.s_addr = ((struct sockaddr_in *)
	    peerres->ai_addr)->sin_addr.s_addr;

	if (ioctl_ctx_ifr(ctx, SIOCSETPFSYNC, &ifr) == -1)
		err(1, "%s: SIOCSETPFSYNC", ifr.ifr_name);

	freeaddrinfo(peerres);
}

static void
unsetpfsync_syncpeer(if_ctx *ctx, const char *val, int d)
{
	struct ifreq ifr = {};
	struct pfsyncreq preq;

	bzero(&preq, sizeof(struct pfsyncreq));
	ifr.ifr_data = (caddr_t)&preq;

	if (ioctl_ctx_ifr(ctx, SIOCGETPFSYNC, &ifr) == -1)
		err(1, "%s: SIOCGETPFSYNC", ifr.ifr_name);

	preq.pfsyncr_syncpeer.s_addr = 0;

	if (ioctl_ctx_ifr(ctx, SIOCSETPFSYNC, &ifr) == -1)
		err(1, "%s: SIOCSETPFSYNC", ifr.ifr_name);
}

static void
setpfsync_maxupd(if_ctx *ctx, const char *val, int d)
{
	struct ifreq ifr = {};
	const char *errmsg = NULL;
	struct pfsyncreq preq;
	int maxupdates;

	maxupdates = strtonum(val, 0, 255, &errmsg);
	if (errmsg)
		errx(1, "maxupd %s: %s", val, errmsg);

	bzero(&preq, sizeof(struct pfsyncreq));
	ifr.ifr_data = (caddr_t)&preq;

	if (ioctl_ctx_ifr(ctx, SIOCGETPFSYNC, &ifr) == -1)
		err(1, "%s: SIOCGETPFSYNC", ifr.ifr_name);

	preq.pfsyncr_maxupdates = maxupdates;

	if (ioctl_ctx_ifr(ctx, SIOCSETPFSYNC, &ifr) == -1)
		err(1, "%s: SIOCSETPFSYNC", ifr.ifr_name);
}

static void
setpfsync_defer(if_ctx *ctx, const char *val, int d)
{
	struct ifreq ifr = {};
	struct pfsyncreq preq;

	bzero(&preq, sizeof(struct pfsyncreq));
	ifr.ifr_data = (caddr_t)&preq;

	if (ioctl_ctx_ifr(ctx, SIOCGETPFSYNC, &ifr) == -1)
		err(1, "%s: SIOCGETPFSYNC", ifr.ifr_name);

	preq.pfsyncr_defer = d;
	if (ioctl_ctx_ifr(ctx, SIOCSETPFSYNC, &ifr) == -1)
		err(1, "%s: SIOCSETPFSYNC", ifr.ifr_name);
}

static void
pfsync_status(if_ctx *ctx)
{
	struct ifreq ifr = {};
	struct pfsyncreq preq;

	bzero(&preq, sizeof(struct pfsyncreq));
	ifr.ifr_data = (caddr_t)&preq;

	if (ioctl_ctx_ifr(ctx, SIOCGETPFSYNC, &ifr) == -1)
		return;

	if (preq.pfsyncr_syncdev[0] != '\0') {
		printf("\tpfsync: syncdev: %s ", preq.pfsyncr_syncdev);
		if (preq.pfsyncr_syncpeer.s_addr != htonl(INADDR_PFSYNC_GROUP))
			printf("syncpeer: %s ",
			    inet_ntoa(preq.pfsyncr_syncpeer));
		printf("maxupd: %d ", preq.pfsyncr_maxupdates);
		printf("defer: %s\n", preq.pfsyncr_defer ? "on" : "off");
	}
}

static void
pflow_status(if_ctx *ctx)
{
	struct ifreq ifr = {};
	struct pflowreq		 preq;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	int			 error;
	char			 buf[INET6_ADDRSTRLEN];

	bzero(&preq, sizeof(struct pflowreq));
	ifr.ifr_data = (caddr_t)&preq;

	if (ioctl_ctx_ifr(ctx, SIOCGETPFLOW, &ifr) == -1)
		 return;

	if (preq.flowsrc.ss_family == AF_INET || preq.flowsrc.ss_family ==
	    AF_INET6) {
		error = getnameinfo((struct sockaddr*)&preq.flowsrc,
		    preq.flowsrc.ss_len, buf, sizeof(buf), NULL, 0,
		    NI_NUMERICHOST);
		if (error)
			err(1, "sender: %s", gai_strerror(error));
	}

	printf("\tpflow: ");
	switch (preq.flowsrc.ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in*) &preq.flowsrc;
		if (sin->sin_addr.s_addr != INADDR_ANY) {
			printf("sender: %s", buf);
			if (sin->sin_port != 0)
				printf(":%u", ntohs(sin->sin_port));
			printf(" ");
		}
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6*) &preq.flowsrc;
		if (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
			printf("sender: [%s]", buf);
			if (sin6->sin6_port != 0)
				printf(":%u", ntohs(sin6->sin6_port));
			printf(" ");
		}
	default:
		break;
	}
	if (preq.flowdst.ss_family == AF_INET || preq.flowdst.ss_family ==
	    AF_INET6) {
		error = getnameinfo((struct sockaddr*)&preq.flowdst,
		    preq.flowdst.ss_len, buf, sizeof(buf), NULL, 0,
		    NI_NUMERICHOST);
		if (error)
			err(1, "receiver: %s", gai_strerror(error));
	}
	switch (preq.flowdst.ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in*)&preq.flowdst;
		printf("receiver: %s:", sin->sin_addr.s_addr != INADDR_ANY ?
		    buf : "INVALID");
		if (sin->sin_port == 0)
			printf("%s ", "INVALID");
		else
			printf("%u ", ntohs(sin->sin_port));
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6*) &preq.flowdst;
		printf("receiver: [%s]:",
		    !IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) ? buf :
		    "INVALID");
		if (sin6->sin6_port == 0)
			printf("%s ", "INVALID");
		else
			printf("%u ", ntohs(sin6->sin6_port));
		break;
	default:
		printf("receiver: INVALID:INVALID ");
		break;
	}
	printf("version: %d\n", preq.version);
}

static void
pflow_addr(const char *val, struct sockaddr_storage *ss)
{
	struct addrinfo hints, *res0;
	int error, flag;
	char *cp, *ip, *port, buf[HOST_NAME_MAX+1 + sizeof (":65535")];

	if (strlcpy(buf, val, sizeof(buf)) >= sizeof(buf))
		errx(1, "%s bad value", val);

	port = NULL;
	cp = buf;
	if (*cp == '[')
		flag = 1;
	else
		flag = 0;

	for(; *cp; ++cp) {
		if (*cp == ']' && *(cp + 1) == ':' && flag) {
			*cp = '\0';
			*(cp + 1) = '\0';
			port = cp + 2;
			break;
		}
		if (*cp == ']' && *(cp + 1) == '\0' && flag) {
			*cp = '\0';
			port = NULL;
			break;
		}
		if (*cp == ':' && !flag) {
			*cp = '\0';
			port = cp + 1;
			break;
		}
	}

	ip = buf;
	if (flag)
		ip++;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM; /*dummy*/
	hints.ai_flags = AI_NUMERICHOST;

	if ((error = getaddrinfo(ip, port, &hints, &res0)) != 0)
		errx(1, "error in parsing address string: %s",
		    gai_strerror(error));

	memcpy(ss, res0->ai_addr, res0->ai_addr->sa_len);
	freeaddrinfo(res0);
}

static void
setpflow_sender(if_ctx *ctx, const char *val, int d)
{
	struct ifreq ifr = {};
	struct pflowreq preq;

	bzero(&preq, sizeof(struct pflowreq));
	ifr.ifr_data = (caddr_t)&preq;
	preq.addrmask |= PFLOW_MASK_SRCIP;
	pflow_addr(val, &preq.flowsrc);

	if (ioctl_ctx_ifr(ctx, SIOCSETPFLOW, &ifr) == -1)
		err(1, "%s: SIOCSETPFLOW", ifr.ifr_name);
}

static void
unsetpflow_sender(if_ctx *ctx, const char *val, int d)
{
	struct ifreq ifr = {};
	struct pflowreq preq;

	bzero(&preq, sizeof(struct pflowreq));
	preq.addrmask |= PFLOW_MASK_SRCIP;
	ifr.ifr_data = (caddr_t)&preq;
	if (ioctl_ctx_ifr(ctx, SIOCSETPFLOW, &ifr) == -1)
		err(1, "%s: SIOCSETPFLOW", ifr.ifr_name);
}

static void
setpflow_receiver(if_ctx *ctx, const char *val, int d)
{
	struct ifreq ifr = {};
	struct pflowreq preq;

	bzero(&preq, sizeof(struct pflowreq));
	ifr.ifr_data = (caddr_t)&preq;
	preq.addrmask |= PFLOW_MASK_DSTIP;
	pflow_addr(val, &preq.flowdst);

	if (ioctl_ctx_ifr(ctx, SIOCSETPFLOW, &ifr) == -1)
		err(1, "%s: SIOCSETPFLOW", ifr.ifr_name);
}

static void
unsetpflow_receiver(if_ctx *ctx, const char *val, int d)
{
	struct ifreq ifr = {};
	struct pflowreq preq;

	bzero(&preq, sizeof(struct pflowreq));
	ifr.ifr_data = (caddr_t)&preq;
	preq.addrmask |= PFLOW_MASK_DSTIP;
	if (ioctl_ctx_ifr(ctx, SIOCSETPFLOW, &ifr) == -1)
		err(1, "%s: SIOCSETPFLOW", ifr.ifr_name);
}

/* PFLOWPROTO XXX */
static void
setpflowproto(if_ctx *ctx, const char *val, int d)
{
	struct ifreq ifr = {};
	struct pflow_protos ppr[] = PFLOW_PROTOS;
	struct pflowreq preq;
	int i;

	bzero(&preq, sizeof(preq));
	preq.version = PFLOW_PROTO_MAX;

	for (i = 0; i < (sizeof(ppr) / sizeof(ppr[0])); i++) {
		if (strcmp(val, ppr[i].ppr_name) == 0) {
			preq.version = ppr[i].ppr_proto;
			break;
		}
	}
	if (preq.version == PFLOW_PROTO_MAX)
		errx(1, "Invalid pflow protocol: %s", val);

	preq.addrmask |= PFLOW_MASK_VERSION;

	ifr.ifr_data = (caddr_t)&preq;

	if (ioctl_ctx_ifr(ctx, SIOCSETPFLOW, &ifr) == -1)
		err(1, "%s: SIOCSETPFLOW", ifr.ifr_name);
}

static struct cmd pf_cmds[] = {
	DEF_CMD_ARG("syncdev",		setpfsync_syncdev),
	DEF_CMD("-syncdev",	1,	unsetpfsync_syncdev),
	DEF_CMD_ARG("syncif",		setpfsync_syncdev),
	DEF_CMD("-syncif",	1,	unsetpfsync_syncdev),
	DEF_CMD_ARG("syncpeer",		setpfsync_syncpeer),
	DEF_CMD("-syncpeer",	1,	unsetpfsync_syncpeer),
	DEF_CMD_ARG("maxupd",		setpfsync_maxupd),
	DEF_CMD("defer",	1,	setpfsync_defer),
	DEF_CMD("-defer",	0,	setpfsync_defer),
	DEF_CMD_ARG("flowsrc",		setpflow_sender),
	DEF_CMD("-flowsrc",	1,	unsetpflow_sender),
	DEF_CMD_ARG("flowdst",		setpflow_receiver),
	DEF_CMD("-flowdst",	1,	unsetpflow_receiver),
	DEF_CMD_ARG("pflowproto",	setpflowproto),
};

static void
pf_status(if_ctx *ctx)
{
	pfsync_status(ctx);
	pflow_status(ctx);
}

static struct afswtch af_pf = {
	.af_name	= "af_pf",
	.af_af		= AF_UNSPEC,
	.af_other_status = pf_status,
};

static __constructor void
pf_ctor(void)
{
	for (size_t i = 0; i < nitems(pf_cmds);  i++)
		cmd_register(&pf_cmds[i]);
	af_register(&af_pf);
}
