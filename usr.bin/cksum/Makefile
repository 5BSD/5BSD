.include <src.opts.mk>

PROG=	cksum
SRCS=	cksum.c crc.c print.c sum1.c sum2.c crc32.c
LINKS=	${BINDIR}/cksum ${BINDIR}/sum
MLINKS=	cksum.1 sum.1

.if ${MK_DTRACE} != "no" && !defined(RESCUE) && !defined(BOOTSTRAPPING)
SRCS+=	checksumtool_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
