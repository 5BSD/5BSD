.include <src.opts.mk>

PACKAGE=	bsdtrace-provider
PROG=	tracectl
MAN=	tracectl.8
SRCS=	tracectl.c tracecmp_policy.c
CFLAGS+=	-I${SRCTOP}/usr.sbin/BSDTrace
.PATH:	${SRCTOP}/usr.sbin/BSDTrace
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.include <bsd.prog.mk>
