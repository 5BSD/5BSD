.include <src.opts.mk>

PACKAGE=	runtime
PROG=	env
SRCS=	env.c envopts.c

LIBADD=	util

HAS_TESTS=
SUBDIR.${MK_TESTS}=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	envdir_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
