.include <src.opts.mk>

PROG=	timeout

SYMLINKS=	../..${BINDIR}/timeout /usr/bin/timeout

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.if ${MK_DTRACE} != "no"
SRCS+=	timeout.c timeoutsig_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
