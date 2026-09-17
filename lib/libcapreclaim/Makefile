.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	capreclaim
SHLIB_MAJOR=	2

SRCS=	capreclaim.c
INCS=	capreclaim.h

WARNS?=	6

.if ${MK_TESTS} != "no"
SUBDIR+=	tests
.endif

.include <bsd.lib.mk>
