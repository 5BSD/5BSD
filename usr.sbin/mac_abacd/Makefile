.include <src.opts.mk>

PACKAGE=	mac-abac
PROG=		mac_abacd
SRCS=		mac_abacd.c parse_line.c parse_ucl.c
MAN=
CONFS=		mac_abac.conf

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=	ucl util

.include <bsd.prog.mk>
