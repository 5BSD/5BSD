/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * "route show": print a routing table in the OpenBSD route(8) layout
 * (Destination, Gateway, Flags, Refs, Use, Mtu, Prio, Iface).
 *
 * 5BSD keeps FreeBSD's routing table, so OpenBSD's view is derived:
 *  - a local address is a host route through a loopback interface whose
 *    gateway names the interface owning the address: flags "l" (local)
 *    and "L" (link layer) or "h", priority 1, that interface as Iface and
 *    its link-layer address (or the address itself) as gateway;
 *  - a connected network (interface route, no gateway) is shown with flags
 *    "C" and "n", priority 4 and the interface's address as gateway;
 *  - other routes have priority 8 (static).
 * Entries are sorted by address and prefix length like OpenBSD's ART.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "show.h"

#define	PRIO_LOCAL	1
#define	PRIO_CONNECTED	4
#define	PRIO_STATIC	8

struct rtshow {
	int			 af;
	struct sockaddr_storage	 dst;
	int			 plen;		/* -1: host */
	char			 gw[INET6_ADDRSTRLEN + IF_NAMESIZE + 8];
	char			 flags[24];
	u_long			 use;
	u_long			 mtu;
	bool			 mtulock;
	int			 prio;
	char			 ifname[IF_NAMESIZE];
	bool			 gwfamily;	/* gateway of the dst family */
};

static struct ifaddrs *ifap;

static const struct {
	int	mask;
	char	c;
} rtflagbits[] = {
	{ RTF_UP,	 'U' },
	{ RTF_GATEWAY,	 'G' },
	{ RTF_HOST,	 'H' },
	{ RTF_REJECT,	 'R' },
	{ RTF_DYNAMIC,	 'D' },
	{ RTF_MODIFIED,	 'M' },
	{ RTF_STATIC,	 'S' },
	{ RTF_BLACKHOLE, 'B' },
	{ RTF_PROTO3,	 '3' },
	{ RTF_PROTO2,	 '2' },
	{ RTF_PROTO1,	 '1' },
};

static int
sa_plen(const struct sockaddr *mask, int af)
{
	const u_char *p;
	int len, i, bits = 0;

	if (mask == NULL)
		return (af == AF_INET ? 32 : 128);
	if (af == AF_INET) {
		p = (const u_char *)&((const struct sockaddr_in *)mask)->sin_addr;
		len = mask->sa_len - offsetof(struct sockaddr_in, sin_addr);
		if (len > 4)
			len = 4;
	} else {
		p = (const u_char *)
		    &((const struct sockaddr_in6 *)mask)->sin6_addr;
		len = mask->sa_len - offsetof(struct sockaddr_in6, sin6_addr);
		if (len > 16)
			len = 16;
	}
	for (i = 0; i < len; i++) {
		u_char b = p[i];

		while (b & 0x80) {
			bits++;
			b <<= 1;
		}
		if (p[i] != 0xff)
			break;
	}
	return (bits);
}

static const char *
name_ifindex(u_int idx, char *buf)
{
	if (idx == 0 || if_indextoname(idx, buf) == NULL)
		strlcpy(buf, "-", IF_NAMESIZE);
	return (buf);
}

/* Address of interface ifname in family af (in prefix dst/plen if >= 0). */
static const struct sockaddr *
if_address(const char *ifname, int af, const struct sockaddr *dst, int plen)
{
	struct ifaddrs *ifa;

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != af ||
		    strcmp(ifa->ifa_name, ifname) != 0)
			continue;
		if (dst == NULL)
			return (ifa->ifa_addr);
		if (af == AF_INET) {
			uint32_t a, d, m;

			a = ntohl(((struct sockaddr_in *)ifa->ifa_addr)->
			    sin_addr.s_addr);
			d = ntohl(((const struct sockaddr_in *)dst)->
			    sin_addr.s_addr);
			m = plen <= 0 ? 0 : 0xffffffffU << (32 - plen);
			if ((a & m) == (d & m))
				return (ifa->ifa_addr);
		} else {
			const u_char *a, *d;
			int i;

			a = (u_char *)&((struct sockaddr_in6 *)ifa->ifa_addr)->
			    sin6_addr;
			d = (const u_char *)&((const struct sockaddr_in6 *)dst)->
			    sin6_addr;
			for (i = 0; i < plen / 8; i++)
				if (a[i] != d[i])
					break;
			if (i == plen / 8 && (plen % 8 == 0 ||
			    ((a[i] ^ d[i]) & (0xff << (8 - plen % 8))) == 0))
				return (ifa->ifa_addr);
		}
	}
	return (NULL);
}

static void
addr_str(const struct sockaddr *sa, char *buf, size_t len)
{
	struct sockaddr_in6 sin6;

	switch (sa->sa_family) {
	case AF_INET:
		if (!nflag &&
		    getnameinfo(sa, sa->sa_len, buf, len, NULL, 0, 0) == 0)
			return;
		inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr,
		    buf, len);
		break;
	case AF_INET6:
		memcpy(&sin6, sa, sizeof(sin6));
		/* KAME embedded scope */
		if ((IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(&sin6.sin6_addr)) &&
		    sin6.sin6_scope_id == 0) {
			sin6.sin6_scope_id = ntohs(*(u_int16_t *)
			    &sin6.sin6_addr.s6_addr[2]);
			sin6.sin6_addr.s6_addr[2] = 0;
			sin6.sin6_addr.s6_addr[3] = 0;
		}
		if (getnameinfo((struct sockaddr *)&sin6, sizeof(sin6), buf,
		    len, NULL, 0, nflag ? NI_NUMERICHOST : NI_NOFQDN) != 0)
			strlcpy(buf, "invalid", len);
		break;
	case AF_LINK: {
		const struct sockaddr_dl *sdl = (const struct sockaddr_dl *)sa;
		const u_char *lla = (const u_char *)LLADDR(sdl);
		size_t o = 0;

		if (sdl->sdl_alen == 0) {
			snprintf(buf, len, "link#%d", sdl->sdl_index);
			break;
		}
		buf[0] = '\0';
		for (int i = 0; i < sdl->sdl_alen && o + 4 < len; i++)
			o += snprintf(buf + o, len - o, "%s%02x",
			    i > 0 ? ":" : "", lla[i]);
		break;
	}
	default:
		snprintf(buf, len, "(%d)", sa->sa_family);
		break;
	}
}

/* OpenBSD's short network names: 10/8, 10.0/16, 10.8.1/24. */
static void
net_str(const struct sockaddr *sa, int plen, char *buf, size_t len)
{
	char host[NI_MAXHOST];

	if (sa->sa_family == AF_INET) {
		uint32_t a = ntohl(((const struct sockaddr_in *)sa)->
		    sin_addr.s_addr);

		if (a == 0 && plen == 0)
			strlcpy(buf, "default", len);
		else if (plen < 9)
			snprintf(buf, len, "%u/%d", a >> 24, plen);
		else if (plen < 17)
			snprintf(buf, len, "%u.%u/%d", a >> 24,
			    (a >> 16) & 0xff, plen);
		else if (plen < 25)
			snprintf(buf, len, "%u.%u.%u/%d", a >> 24,
			    (a >> 16) & 0xff, (a >> 8) & 0xff, plen);
		else
			snprintf(buf, len, "%u.%u.%u.%u/%d", a >> 24,
			    (a >> 16) & 0xff, (a >> 8) & 0xff, a & 0xff, plen);
		return;
	}
	if (plen == 0 && IN6_IS_ADDR_UNSPECIFIED(
	    &((const struct sockaddr_in6 *)sa)->sin6_addr)) {
		strlcpy(buf, "default", len);
		return;
	}
	addr_str(sa, host, sizeof(host));
	snprintf(buf, len, "%s/%d", host, plen);
}

static int
rtshow_cmp(const void *a, const void *b)
{
	const struct rtshow *x = a, *y = b;
	int c;

	if (x->af != y->af)
		return (x->af == AF_INET ? -1 : 1);
	if (x->af == AF_INET)
		c = memcmp(&((const struct sockaddr_in *)&x->dst)->sin_addr,
		    &((const struct sockaddr_in *)&y->dst)->sin_addr, 4);
	else
		c = memcmp(&((const struct sockaddr_in6 *)&x->dst)->sin6_addr,
		    &((const struct sockaddr_in6 *)&y->dst)->sin6_addr, 16);
	if (c != 0)
		return (c);
	return ((x->plen < 0 ? 129 : x->plen) - (y->plen < 0 ? 129 : y->plen));
}

static bool
rtshow_entry(struct rt_msghdr *rtm, struct rtshow *e)
{
	struct sockaddr *sa, *rti[RTAX_MAX];
	const struct sockaddr *a;
	struct sockaddr_dl *gwdl = NULL;
	char ifn[IF_NAMESIZE], gwif[IF_NAMESIZE];
	bool local = false, connected = false;
	size_t o = 0;
	int i;

	sa = (struct sockaddr *)(rtm + 1);
	for (i = 0; i < RTAX_MAX; i++) {
		if (rtm->rtm_addrs & (1 << i)) {
			rti[i] = sa;
			sa = (struct sockaddr *)((char *)sa + SA_SIZE(sa));
		} else
			rti[i] = NULL;
	}
	if (rti[RTAX_DST] == NULL || rti[RTAX_GATEWAY] == NULL)
		return (false);
	memset(e, 0, sizeof(*e));
	e->af = rti[RTAX_DST]->sa_family;
	if (e->af != AF_INET && e->af != AF_INET6)
		return (false);
	memcpy(&e->dst, rti[RTAX_DST], MIN(rti[RTAX_DST]->sa_len,
	    sizeof(e->dst)));
	e->plen = (rtm->rtm_flags & RTF_HOST) ? -1 :
	    sa_plen(rti[RTAX_NETMASK], e->af);
	name_ifindex(rtm->rtm_index, ifn);
	if (rti[RTAX_GATEWAY]->sa_family == AF_LINK)
		gwdl = (struct sockaddr_dl *)rti[RTAX_GATEWAY];

	if (gwdl != NULL && (rtm->rtm_flags & RTF_HOST) &&
	    (rtm->rtm_flags & RTF_GATEWAY) == 0 && gwdl->sdl_index != 0 &&
	    strncmp(ifn, "lo", 2) == 0 &&
	    if_address(name_ifindex(gwdl->sdl_index, gwif), e->af,
	    rti[RTAX_DST], e->af == AF_INET ? 32 : 128) != NULL)
		local = true;
	else if (gwdl != NULL && (rtm->rtm_flags & (RTF_HOST | RTF_GATEWAY))
	    == 0)
		connected = true;

	for (i = 0; i < (int)nitems(rtflagbits); i++) {
		if (rtm->rtm_flags & rtflagbits[i].mask)
			e->flags[o++] = rtflagbits[i].c;
		if (rtflagbits[i].mask == RTF_MODIFIED && connected)
			e->flags[o++] = 'C';
	}
	if (local) {
		/* OpenBSD local route: no "S", link layer or cached + local */
		char *s = strchr(e->flags, 'S');

		if (s != NULL)
			memmove(s, s + 1, strlen(s));
		o = strlen(e->flags);
		e->flags[o++] = gwdl->sdl_type == IFT_ETHER ||
		    gwdl->sdl_alen != 0 ? 'L' : 'h';
		e->flags[o++] = 'l';
	}
	if (connected)
		e->flags[o++] = 'n';
	e->flags[o] = '\0';
	e->gwfamily = rti[RTAX_GATEWAY]->sa_family == e->af;

	if (local) {
		strlcpy(e->ifname, gwif, sizeof(e->ifname));
		e->prio = PRIO_LOCAL;
		if (gwdl->sdl_alen != 0)
			addr_str(rti[RTAX_GATEWAY], e->gw, sizeof(e->gw));
		else
			addr_str(rti[RTAX_DST], e->gw, sizeof(e->gw));
	} else if (connected) {
		name_ifindex(gwdl->sdl_index != 0 ? gwdl->sdl_index :
		    rtm->rtm_index, e->ifname);
		e->prio = PRIO_CONNECTED;
		a = if_address(e->ifname, e->af, rti[RTAX_DST], e->plen);
		if (a == NULL && rti[RTAX_IFA] != NULL &&
		    rti[RTAX_IFA]->sa_family == e->af)
			a = rti[RTAX_IFA];
		if (a != NULL)
			addr_str(a, e->gw, sizeof(e->gw));
		else
			addr_str(rti[RTAX_GATEWAY], e->gw, sizeof(e->gw));
	} else {
		strlcpy(e->ifname, ifn, sizeof(e->ifname));
		e->prio = PRIO_STATIC;
		addr_str(rti[RTAX_GATEWAY], e->gw, sizeof(e->gw));
	}
	e->use = rtm->rtm_rmx.rmx_pksent;
	e->mtu = rtm->rtm_rmx.rmx_mtu;
	e->mtulock = (rtm->rtm_rmx.rmx_locks & RTV_MTU) != 0;
	return (true);
}

static void
rtshow_print(const struct rtshow *e)
{
	char dst[NI_MAXHOST + 8];
	int wd = e->af == AF_INET6 ? 43 : 18, wg = e->af == AF_INET6 ? 39 : 18;

	if (e->plen < 0)
		addr_str((const struct sockaddr *)&e->dst, dst, sizeof(dst));
	else
		net_str((const struct sockaddr *)&e->dst, e->plen, dst,
		    sizeof(dst));
	if (nflag)
		printf("%-*s %-*s ", wd, dst, wg, e->gw);
	else
		printf("%-*.*s %-*.*s ", wd, wd, dst, wg, wg, e->gw);
	printf("%-6.6s %5u %8lu ", e->flags, 0, e->use);
	if (e->mtu != 0)
		printf("%5lu ", e->mtu);
	else
		printf("%5s ", "-");
	putchar(e->mtulock ? 'L' : ' ');
	printf("  %2d %-5.16s\n", e->prio, e->ifname);
}

/*
 * route [-T table] [-n] show [-inet | -inet6] [-gateway]
 * Returns -1 when the arguments are not a table dump (legacy "show dst").
 */
int
show(int argc, char **argv, int fib)
{
	struct rtshow *ent = NULL;
	struct rt_msghdr *rtm;
	char *buf = NULL, *next, *lim;
	size_t needed, n = 0, cap = 0;
	int mib[7], af = AF_UNSPEC, i, last_af = -1;
	bool gwonly = false;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-inet") == 0)
			af = AF_INET;
		else if (strcmp(argv[i], "-inet6") == 0)
			af = AF_INET6;
		else if (strcmp(argv[i], "-gateway") == 0)
			gwonly = true;
		else if (strcmp(argv[i], "-priority") == 0 ||
		    strcmp(argv[i], "-label") == 0) {
			if (++i >= argc)
				errx(1, "missing argument");
		} else
			return (-1);
	}

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = af;
	mib[4] = NET_RT_DUMP;
	mib[5] = 0;
	mib[6] = fib;
	for (;;) {
		if (sysctl(mib, nitems(mib), NULL, &needed, NULL, 0) < 0)
			err(1, "routing table %d", fib);
		if ((buf = realloc(buf, needed + 1)) == NULL)
			err(1, NULL);
		if (sysctl(mib, nitems(mib), buf, &needed, NULL, 0) == 0)
			break;
		if (errno != ENOMEM)
			err(1, "routing table %d", fib);
	}
	if (getifaddrs(&ifap) != 0)
		ifap = NULL;

	lim = buf + needed;
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		if (rtm->rtm_msglen == 0)
			break;
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		if (n == cap) {
			cap = cap ? cap * 2 : 64;
			if ((ent = reallocarray(ent, cap, sizeof(*ent))) ==
			    NULL)
				err(1, NULL);
		}
		if (!rtshow_entry(rtm, &ent[n]))
			continue;
		if (gwonly && !ent[n].gwfamily)
			continue;
		n++;
	}
	qsort(ent, n, sizeof(*ent), rtshow_cmp);

	printf("Routing tables\n");
	for (size_t k = 0; k < n; k++) {
		int wd, wg;

		if (ent[k].af != last_af) {
			last_af = ent[k].af;
			wd = last_af == AF_INET6 ? 43 : 18;
			wg = last_af == AF_INET6 ? 39 : 18;
			printf("\n%s:\n", last_af == AF_INET ? "Internet" :
			    "Internet6");
			printf("%-*.*s %-*.*s %-6.6s %5.5s %8.8s %5.5s  "
			    "%4.4s %s\n", wd, wd, "Destination", wg, wg,
			    "Gateway", "Flags", "Refs", "Use", "Mtu", "Prio",
			    "Iface");
		}
		rtshow_print(&ent[k]);
	}
	if (ifap != NULL)
		freeifaddrs(ifap);
	free(ent);
	free(buf);
	return (0);
}
