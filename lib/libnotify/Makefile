.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	notify
SHLIB_MAJOR=	1
MAN=	libnotify.3 notify_watch.3
MLINKS+=libnotify.3 notify_client_open.3
MLINKS+=libnotify.3 notify_subscribe.3
MLINKS+=libnotify.3 notify_unsubscribe.3
MLINKS+=libnotify.3 notify_publish.3
MLINKS+=libnotify.3 notify_next.3
MLINKS+=libnotify.3 notify_state_watch.3
MLINKS+=libnotify.3 notify_timer_add.3
MLINKS+=libnotify.3 notify_timer_cancel.3
MLINKS+=libnotify.3 notify_stats.3
MLINKS+=libnotify.3 notify_list_subscriptions.3
MLINKS+=libnotify.3 notify_list_timers.3
MLINKS+=libnotify.3 notify_client_close.3

SRCS=	notify.c notify_legacy.c notify_watch.c \
	${FIDLGEN_SRCS.notify}
CXXSTD= c++20
WARNS?= 0
CFLAGS+= -I${FIDLGEN.notify}
.include "../libfidl/runtime-includes.mk"
FILESGROUPS+= NOTIFY_SCHEMA
NOTIFY_SCHEMA= notify.fidl
NOTIFY_SCHEMADIR= /usr/share/fidl
NOTIFY_SCHEMAPACKAGE= libnotify-dev
FILESGROUPS+= NOTIFY_NOTICE
NOTIFY_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
NOTIFY_NOTICEDIR= /usr/share/licenses/libnotify/fuchsia
INCS=	notify.h notify_protocol.h notify_server.h notify_watch.h notify_pressure.h
LIBADD=	pthread service fidl_bsd cplusplus
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	notify_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	notify
FIDL_SCHEMAS.notify=	lib/libnotify/notify.fidl
FIDL_LIBRARY.notify=	bsd.notify.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.lib.mk>
