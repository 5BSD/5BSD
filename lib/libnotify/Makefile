.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	notify
SHLIB_MAJOR=	1
MAN=	libnotify.3
MLINKS+=libnotify.3 notify_client_open.3
MLINKS+=libnotify.3 notify_subscribe.3
MLINKS+=libnotify.3 notify_unsubscribe.3
MLINKS+=libnotify.3 notify_publish.3
MLINKS+=libnotify.3 notify_next.3
MLINKS+=libnotify.3 notify_timer_add.3
MLINKS+=libnotify.3 notify_timer_cancel.3
MLINKS+=libnotify.3 notify_stats.3
MLINKS+=libnotify.3 notify_list_subscriptions.3
MLINKS+=libnotify.3 notify_list_timers.3
MLINKS+=libnotify.3 notify_client_close.3

SRCS=	notify.c
INCS=	notify.h notify_protocol.h notify_server.h
LIBADD=	pthread service
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	notify_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.lib.mk>
