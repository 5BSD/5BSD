.include <src.opts.mk>

PROG=	vmstat
MAN=	vmstat.8
LIBADD=	devstat kvm memstat xo util

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

SRCS=	vmstat.c

.if ${MK_DTRACE} != "no" && !defined(RESCUE) && !defined(BOOTSTRAPPING)
SRCS+=	vmquery_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
