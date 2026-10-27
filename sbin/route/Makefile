.include <src.opts.mk>

PACKAGE=runtime
PROG=	route
MAN=	route.8
SRCS=	route.c show.c keywords.h
WARNS?=	3
CLEANFILES+=keywords.h

CFLAGS+= -DNS
.if ${MK_INET_SUPPORT} != "no"
CFLAGS+= -DINET
.endif
.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+= -DINET6
.endif
CFLAGS+= -I.

.if ${MK_NETLINK_SUPPORT} != "no"
SRCS+= route_netlink.c
.else
CFLAGS+=-DWITHOUT_NETLINK
.endif

.if ${MK_JAIL} != "no" && !defined(RESCUE)
CFLAGS+= -DJAIL
LIBADD+= jail
.endif

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

keywords.h: keywords keywords.awk
	LC_ALL=C awk -f ${.CURDIR}/keywords.awk ${.CURDIR}/keywords > ${.TARGET} || (rm -f ${.TARGET}; false)

.include <bsd.prog.mk>
