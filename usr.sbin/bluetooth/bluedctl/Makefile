.include <src.opts.mk>

PROG=	bluedctl
SRCS=	bluedctl.c

PACKAGE=	bluetooth

CFLAGS+=	-I${SRCTOP}/lib/libble

LIBADD=	ble

MAN=	bluedctl.8

WARNS?=	6

.include <bsd.prog.mk>
