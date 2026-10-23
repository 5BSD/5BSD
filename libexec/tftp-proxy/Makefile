# tftp-proxy(8) from OpenBSD (contrib/openbsd-pf/usr.sbin/tftp-proxy).

.PATH:	${SRCTOP}/contrib/openbsd-pf/usr.sbin/tftp-proxy

PACKAGE= pf
PROG=	tftp-proxy
SRCS=	tftp-proxy.c filter.c
MAN=	tftp-proxy.8

CFLAGS+= -I${SRCTOP}/sys/netpfil/openbsd-pf/user
CFLAGS+= -include ${SRCTOP}/sys/netpfil/openbsd-pf/user/openbsd_compat.h
CFLAGS+= -I${SRCTOP}/contrib/pf/libevent
NO_WFORMAT=
# 5BSD runs the proxies as the "proxy" user (OpenBSD: _ftp_proxy, _tftp_proxy).
CFLAGS+= -DNOPRIV_USER=\"proxy\"

LIBADD=	event1

WARNS?=	3

.include <bsd.prog.mk>
