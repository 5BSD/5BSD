PROG=	btled
SRCS=	btled.c att.c gatt.c hci_util.c smp.c

CFLAGS+=	-I${SRCTOP}/sys

LIBADD=	bluetooth crypto

MAN=	btled.8

WARNS?=	6

.include <bsd.prog.mk>
