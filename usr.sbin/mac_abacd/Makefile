.include <src.opts.mk>

PACKAGE=	mac-abac
PROG=		mac_abacd
SRCS=		mac_abacd.c parse_line.c parse_ucl.c
MAN=
CONFS=		mac_abac.conf

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=	ucl util

.if ${MK_DTRACE} != "no"
SRCS+= diagnostics_provider.d
CFLAGS+= -DWITH_DTRACE
.endif

.include <bsd.prog.mk>
