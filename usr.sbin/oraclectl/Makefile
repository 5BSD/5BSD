.include <src.opts.mk>

PACKAGE=runtime
PROG=	oraclectl
MAN=	oraclectl.8

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/lib/liboraclectl
LIBADD=		oraclectl

.include <bsd.prog.mk>
