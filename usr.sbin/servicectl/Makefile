.include <src.opts.mk>

PACKAGE=servicectl
PROG=	servicectl
MAN=	servicectl.8

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/usr.sbin/serviced

.include <bsd.prog.mk>
