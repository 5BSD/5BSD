.include <src.opts.mk>

PACKAGE=	traced
PROG=	tracectl
MAN=	tracectl.8
SRCS=	tracectl.c tracecmp_policy.c
CFLAGS+=	-I${SRCTOP}/usr.sbin/traced
.PATH:	${SRCTOP}/usr.sbin/traced
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.include <bsd.prog.mk>
