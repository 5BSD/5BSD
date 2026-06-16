PROG=	btled
SRCS=	btled.c att.c att_server.c gatt.c hci_util.c hci_log.c smp.c

CFLAGS+=	-I${SRCTOP}/sys

LIBADD=	bluetooth crypto util

MAN=	btled.8

WARNS?=	6

.include <bsd.prog.mk>
