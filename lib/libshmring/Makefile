.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	shmring
SHLIB_MAJOR=	1
MAN=	libshmring.3

SRCS=	shmring.c
INCS=	shmring.h

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	shmring_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.lib.mk>
