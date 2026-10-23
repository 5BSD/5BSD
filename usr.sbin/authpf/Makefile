# authpf(8) from OpenBSD (contrib/openbsd-pf/usr.sbin/authpf).

.PATH:	${SRCTOP}/contrib/openbsd-pf/usr.sbin/authpf

PACKAGE=pf
PROG=	authpf
MAN=	authpf.8
BINOWN=	root
BINGRP= authpf
BINMODE= 6555

SRCS=   authpf.c

CFLAGS+= -I${SRCTOP}/sys/netpfil/openbsd-pf/user
CFLAGS+= -include ${SRCTOP}/sys/netpfil/openbsd-pf/user/openbsd_compat.h
NO_WFORMAT=
CWARNFLAGS+= -Wno-sign-compare -Wno-incompatible-pointer-types-discards-qualifiers

LIBADD=	m util

WARNS?=	3

LINKS=	${BINDIR}/authpf ${BINDIR}/authpf-noip
MLINKS=	authpf.8 authpf-noip.8

.include <bsd.prog.mk>
