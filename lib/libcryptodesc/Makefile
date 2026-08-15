.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	cryptodesc
SHLIB_MAJOR=	1
SRCS=	cryptodesc.c
INCS=	cryptodesc.h

CFLAGS+=	-I${SRCTOP}/sys

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
