.include <src.opts.mk>

PACKAGE=runtime
PROG=	oraclectl
MAN=	oraclectl.8

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/usr.sbin/oracled

.include <bsd.prog.mk>
