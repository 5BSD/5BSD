.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	tracecmp
SHLIB_MAJOR=	1
MAN=	libtracecmp.3
MLINKS+=libtracecmp.3 tracecmp_open.3
MLINKS+=libtracecmp.3 tracecmp_stats.3
MLINKS+=libtracecmp.3 tracecmp_dtrace_open.3

SRCS=	tracecmp.c
INCS=	tracecmp.h tracecmp_protocol.h tracecmp_server.h
LIBADD=	dtrace service
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/cddl/contrib/opensolaris/lib/libdtrace/common
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	tracecmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.lib.mk>
