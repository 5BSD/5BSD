.include <src.opts.mk>

PROG=	stat

LINKS=	${BINDIR}/stat ${BINDIR}/readlink \
	${BINDIR}/stat ${BINDIR}/mountpoint
MLINKS=	stat.1 readlink.1 stat.1 mountpoint.1

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	stat.c filestat_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
