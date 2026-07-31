.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	tracecmp
SHLIB_MAJOR=	1
MAN=	libtracecmp.3
MLINKS+=libtracecmp.3 tracecmp_open.3

SRCS=	tracecmp.c
INCS=	tracecmp.h tracecmp_protocol.h
LIBADD=	service
CFLAGS+=	-I${SRCTOP}/lib/libservice

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	tracecmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.lib.mk>
