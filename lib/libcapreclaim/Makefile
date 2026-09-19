.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	capreclaim
SHLIB_MAJOR=	3

SRCS=	capreclaim.c
INCS=	capreclaim.h
MAN=	capreclaim.3
MLINKS=	capreclaim.3 capreclaim_run.3 capreclaim.3 capreclaim_fini.3

WARNS?=	6

.if ${MK_TESTS} != "no"
SUBDIR+=	tests
.endif

.include <bsd.lib.mk>
