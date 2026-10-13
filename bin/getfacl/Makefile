.include <src.opts.mk>

PACKAGE=runtime
PROG=	getfacl

SRCS=	getfacl.c

.if ${MK_DTRACE} != "no" && !defined(RESCUE) && !defined(BOOTSTRAPPING)
SRCS+=	aclread_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
