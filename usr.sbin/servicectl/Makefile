.include <src.opts.mk>

PACKAGE=servicectl
PROG=	servicectl
SRCS=	servicectl.c install.c verify.c
MAN=	servicectl.8

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/usr.sbin/serviced
CFLAGS+=	-I${SRCTOP}/lib/libappbundle
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		appbundle ucl

.include <bsd.prog.mk>
