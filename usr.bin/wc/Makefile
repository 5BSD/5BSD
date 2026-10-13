.include <src.opts.mk>

PROG=	wc
LIBADD=	xo

.if ${MK_CASPER} != "no"
LIBADD+=        casper
LIBADD+=        cap_fileargs
CFLAGS+=-DWITH_CASPER
.endif

HAS_TESTS=
SUBDIR.${MK_TESTS}=	tests

SRCS=	wc.c

.if ${MK_DTRACE} != "no" && !defined(RESCUE) && !defined(BOOTSTRAPPING)
SRCS+=	wordcountio_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
