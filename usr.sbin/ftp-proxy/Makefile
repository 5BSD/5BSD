# ftp-proxy(8) from OpenBSD (contrib/openbsd-pf/usr.sbin/ftp-proxy).

.PATH:	${SRCTOP}/contrib/openbsd-pf/usr.sbin/ftp-proxy

PACKAGE=	pf
PROG=	ftp-proxy
MAN=	ftp-proxy.8

SRCS=	ftp-proxy.c filter.c

CFLAGS+= -I${SRCTOP}/sys/netpfil/openbsd-pf/user
CFLAGS+= -include ${SRCTOP}/sys/netpfil/openbsd-pf/user/openbsd_compat.h
CFLAGS+= -I${SRCTOP}/contrib/pf/libevent
NO_WFORMAT=
CWARNFLAGS+= -Wno-sign-compare -Wno-incompatible-pointer-types-discards-qualifiers

LIBADD=	event1

WARNS?=	2

.include <bsd.prog.mk>
