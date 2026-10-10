.include <src.opts.mk>

PACKAGE=	runtime
PROG=		BSDPowerctl
MAN=		BSDPowerctl.8

CFLAGS+=	-I${SRCTOP}/lib/libpowercmp
CFLAGS+= -I${SRCTOP}/lib/libservice
LIBADD=		powercmp service
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
