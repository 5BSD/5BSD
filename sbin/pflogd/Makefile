# pflogd(8) from OpenBSD (contrib/openbsd-pf/sbin/pflogd), built on the
# base libpcap.  5BSD glue: pflogd_5bsd.h (force-included), pflogd_5bsd.c
# and the edits marked "5BSD" in the vendor sources (contrib/openbsd-pf/
# README.5BSD).

.PATH:	${SRCTOP}/contrib/openbsd-pf/sbin/pflogd

PACKAGE=pf
PROG=	pflogd
SRCS= 	pflogd.c privsep.c privsep_fdpass.c pflogd_5bsd.c
MAN=	pflogd.8

CFLAGS+=-include ${.CURDIR}/pflogd_5bsd.h
CFLAGS+=-I${.CURDIR} -I${SRCTOP}/contrib/openbsd-pf/sbin/pflogd
# util.h (OpenBSD libutil) and pcap-int.h (pcap_t's private fields)
CFLAGS+=-I${SRCTOP}/sys/netpfil/openbsd-pf/user
CFLAGS+=-include ${SRCTOP}/lib/libpcap/config.h
CFLAGS+=-I${SRCTOP}/contrib/libpcap

LIBADD=	pcap

WARNS?=	2

.include <bsd.prog.mk>
