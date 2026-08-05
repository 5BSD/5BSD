.include <src.opts.mk>

PACKAGE=	rebootd
PROG=	rebootctl
MAN=	rebootctl.8
SRCS=	rebootctl.c rebootd_policy.c
CFLAGS+=	-I${SRCTOP}/lib/librebootctl
CFLAGS+=	-I${SRCTOP}/usr.sbin/rebootd
LIBADD=	rebootctl
.PATH:	${SRCTOP}/usr.sbin/rebootd
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.include <bsd.prog.mk>
