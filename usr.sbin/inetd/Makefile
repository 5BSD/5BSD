.include <src.opts.mk>

CONFS=	inetd.conf
PROG=	inetd
PACKAGE=	inetd
MAN=	inetd.8
MLINKS=	inetd.8 inetd.conf.5
SRCS=	inetd.c builtins.c

CFLAGS+= -DLOGIN_CAP

.if ${MK_DTRACE} != "no"
SRCS+=	inetd_provider.d
CFLAGS+= -DWITH_DTRACE
.endif
#CFLAGS+= -DSANITY_CHECK

.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+= -DINET6
.endif

LIBADD=	util

.if ${MK_TCP_WRAPPERS} != "no"
CFLAGS+=	-DLIBWRAP
LIBADD+=	wrap
.endif

CFLAGS+= -DIPSEC
LIBADD+=	ipsec

.include <bsd.prog.mk>
