.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	notifycmp
SHLIB_MAJOR=	1
MAN=	libnotifycmp.3
MLINKS+=libnotifycmp.3 notifycmp_client_open.3
MLINKS+=libnotifycmp.3 notifycmp_subscribe.3
MLINKS+=libnotifycmp.3 notifycmp_unsubscribe.3
MLINKS+=libnotifycmp.3 notifycmp_publish.3
MLINKS+=libnotifycmp.3 notifycmp_next.3
MLINKS+=libnotifycmp.3 notifycmp_timer_add.3
MLINKS+=libnotifycmp.3 notifycmp_timer_cancel.3
MLINKS+=libnotifycmp.3 notifycmp_stats.3
MLINKS+=libnotifycmp.3 notifycmp_client_close.3

SRCS=	notifycmp.c
INCS=	notifycmp.h notifycmp_protocol.h
LIBADD=	pthread service
CFLAGS+=	-I${SRCTOP}/lib/libservice

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	notifycmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.lib.mk>
