.include <src.opts.mk>

PACKAGE=runtime
PROG=	setfacl
SRCS=	file.c mask.c merge.c remove.c setfacl.c util.c

.if ${MK_DTRACE} != "no" && !defined(RESCUE) && !defined(BOOTSTRAPPING)
SRCS+=	aclwrite_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
