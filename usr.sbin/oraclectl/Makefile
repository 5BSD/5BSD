.include <src.opts.mk>

PACKAGE=oracled
PROG=	oraclectl
MAN=	oraclectl.8

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/lib/liboraclectl
CFLAGS+=	-I${SRCTOP}/usr.sbin/oracled
LIBADD=		oraclectl

.include <bsd.prog.mk>
