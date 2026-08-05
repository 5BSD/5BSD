.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	logcmp
SHLIB_MAJOR=	1
MAN=	liblogcmp.3
MLINKS+=liblogcmp.3 logcmp_client_open.3
MLINKS+=liblogcmp.3 logcmp_logger_create.3
MLINKS+=liblogcmp.3 logcmp_logger_destroy.3
MLINKS+=liblogcmp.3 logcmp_emit.3
MLINKS+=liblogcmp.3 logcmp_flush.3
MLINKS+=liblogcmp.3 logcmp_stats.3
MLINKS+=liblogcmp.3 logcmp_client_close.3

SRCS=	logcmp.c logcmp_wakeup.c
INCS=	logcmp.h logcmp_protocol.h logcmp_server.h

LIBADD=	pthread service shmring
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libshmring
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	logcmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.lib.mk>
