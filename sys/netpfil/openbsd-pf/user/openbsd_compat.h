/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * Userland compatibility for OpenBSD pfctl(8) on 5BSD.  Force-included
 * before every pfctl source file.
 */
#ifndef _PFCTL_OPENBSD_COMPAT_H_
#define _PFCTL_OPENBSD_COMPAT_H_

#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/endian.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* sys/socket.h protocol family that collides with pf's PF_DIVERT action */
#undef	PF_DIVERT

/* OpenBSD sys/queue.h SIMPLEQ (FreeBSD calls it STAILQ). */
#define	SIMPLEQ_HEAD		STAILQ_HEAD
#define	SIMPLEQ_HEAD_INITIALIZER STAILQ_HEAD_INITIALIZER
#define	SIMPLEQ_ENTRY		STAILQ_ENTRY
#define	SIMPLEQ_FIRST		STAILQ_FIRST
#define	SIMPLEQ_END(head)	NULL
#define	SIMPLEQ_EMPTY		STAILQ_EMPTY
#define	SIMPLEQ_NEXT		STAILQ_NEXT
#define	SIMPLEQ_FOREACH		STAILQ_FOREACH
#define	SIMPLEQ_FOREACH_SAFE	STAILQ_FOREACH_SAFE
#define	SIMPLEQ_INIT		STAILQ_INIT
#define	SIMPLEQ_INSERT_HEAD	STAILQ_INSERT_HEAD
#define	SIMPLEQ_INSERT_TAIL	STAILQ_INSERT_TAIL
#define	SIMPLEQ_INSERT_AFTER	STAILQ_INSERT_AFTER
#define	SIMPLEQ_REMOVE_HEAD	STAILQ_REMOVE_HEAD
#define	SIMPLEQ_CONCAT		STAILQ_CONCAT

#define	RT_TABLEID_MAX		255

#define	__dead			__dead2
#define	betoh16(x)		be16toh(x)
#define	betoh32(x)		be32toh(x)
#define	betoh64(x)		be64toh(x)
#define	HTONL(x)		((x) = htonl((x)))
#define	HTONS(x)		((x) = htons((x)))
#define	NTOHL(x)		((x) = ntohl((x)))
#define	NTOHS(x)		((x) = ntohs((x)))

static inline void
freezero(void *p, size_t sz)
{
	if (p == NULL)
		return;
	explicit_bzero(p, sz);
	free(p);
}

#define	IFQ_MAXPRIO		7

/*
 * OpenBSD getaddrinfo(3) parses AI_NUMERICHOST strings with inet_pton(3);
 * 5BSD's also accepts inet_aton(3) shorthands ("10" as 0.0.0.10), which
 * changes pf.conf's "10/8" meaning.  Reject what inet_pton rejects.
 */
#include <netdb.h>
#include <arpa/inet.h>
static inline int
obsd_getaddrinfo(const char *host, const char *serv,
    const struct addrinfo *hints, struct addrinfo **res)
{
	if (host != NULL && hints != NULL &&
	    (hints->ai_flags & AI_NUMERICHOST) &&
	    (hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET) &&
	    strchr(host, ':') == NULL) {
		struct in_addr a;

		if (inet_pton(AF_INET, host, &a) != 1)
			return (EAI_NONAME);
	}
	return (getaddrinfo(host, serv, hints, res));
}
#define	getaddrinfo(h, s, hi, r)	obsd_getaddrinfo((h), (s), (hi), (r))

#include <netinet/in.h>
#ifndef _SOCKADDR_UNION_DEFINED
#define	_SOCKADDR_UNION_DEFINED
union sockaddr_union {
	struct sockaddr		sa;
	struct sockaddr_in	sin;
	struct sockaddr_in6	sin6;
};
#endif
#define	LOGIN_NAME_MAX		MAXLOGNAME

/* OpenBSD strnvis(dst, src, dstsize, flag); 5BSD orders (dst, dstsize, src). */
#include <vis.h>
#define	strnvis(d, s, l, f)	strnvis((d), (l), (s), (f))
#define	SEGSIZE_MAX		65464	/* arpa/tftp.h */

/*
 * pledge(2)/unveil(2) do not exist on 5BSD; programs are confined by the
 * capability plane instead.
 */
#define	pledge(promises, execpromises)	0
#define	unveil(path, permissions)	0

/* Routing domains (rdomain(4)) map onto FIBs. */
#include <netinet/in.h>
#ifndef SO_RTABLE
#define	SO_RTABLE		SO_SETFIB
#endif
static inline int
getrtable(void)
{
	int fib = 0;
	size_t len = sizeof(fib);

	(void)sysctlbyname("net.my_fibnum", &fib, &len, NULL, 0);
	return (fib);
}

/* SO_BINDANY is a native 5BSD socket option (sys/socket.h). */

/* 5BSD pf rule option "jail" (pfctl_jail.c). */
struct pf_rule_jail;
void	pfctl_print_jail(const struct pf_rule_jail *);

/* Routing table information (struct rt_tableinfo, NET_RT_TABLE) is native. */
#include <net/route.h>

/* OpenBSD sysctl MIBs read by pfctl, mapped onto 5BSD names. */
#define	KERN_MAXCLUSTERS	(-0x5f01)
#define	HW_PHYSMEM64		(-0x5f02)
static inline int
obsd_sysctl(const int *mib, u_int n, void *o, size_t *ol, const void *nw,
    size_t nl)
{
	if (n == 2 && mib[0] == CTL_KERN && mib[1] == KERN_MAXCLUSTERS)
		return (sysctlbyname("kern.ipc.nmbclusters", o, ol, nw, nl));
	if (n == 2 && mib[0] == CTL_HW && mib[1] == HW_PHYSMEM64) {
		unsigned long pm;
		size_t sz = sizeof(pm);

		if (sysctlbyname("hw.physmem", &pm, &sz, NULL, 0) == -1)
			return (-1);
		if (*ol < sizeof(int64_t))
			return (-1);
		*(int64_t *)o = (int64_t)pm;
		*ol = sizeof(int64_t);
		return (0);
	}
	return (sysctl(mib, n, o, ol, nw, nl));
}
#define	sysctl(m, n, o, ol, nw, nl)	obsd_sysctl((m), (n), (o), (ol), (nw), (nl))

/* OpenBSD typed red-black trees (RBT_*) on top of sys/tree.h RB_*. */
#include <sys/tree.h>
#define	RBT_HEAD(name, type)		RB_HEAD(name, type)
#define	RBT_ENTRY(type)			RB_ENTRY(type)
#define	RBT_INITIALIZER(head)		RB_INITIALIZER(head)
#define	RBT_PROTOTYPE(name, type, field, cmp)	RB_PROTOTYPE(name, type, field, cmp)
#define	RBT_GENERATE(name, type, field, cmp)	RB_GENERATE(name, type, field, cmp)
#define	RBT_INIT(name, head)		RB_INIT(head)
#define	RBT_INSERT(name, head, elm)	RB_INSERT(name, head, elm)
#define	RBT_REMOVE(name, head, elm)	RB_REMOVE(name, head, elm)
#define	RBT_FIND(name, head, key)	RB_FIND(name, head, key)
#define	RBT_NFIND(name, head, key)	RB_NFIND(name, head, key)
#define	RBT_ROOT(name, head)		RB_ROOT(head)
#define	RBT_EMPTY(name, head)		RB_EMPTY(head)
#define	RBT_MIN(name, head)		RB_MIN(name, head)
#define	RBT_MAX(name, head)		RB_MAX(name, head)
#define	RBT_NEXT(name, elm)		RB_NEXT(name, NULL, elm)
#define	RBT_PREV(name, elm)		RB_PREV(name, NULL, elm)
#define	RBT_FOREACH(var, name, head)	RB_FOREACH(var, name, head)
#define	RBT_FOREACH_SAFE(var, name, head, tvar)	RB_FOREACH_SAFE(var, name, head, tvar)

#endif /* _PFCTL_OPENBSD_COMPAT_H_ */
