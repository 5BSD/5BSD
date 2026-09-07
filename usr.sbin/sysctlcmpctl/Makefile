.include <src.opts.mk>

PACKAGE=	runtime
PROG=		sysctlcmpctl
MAN=		sysctlcmpctl.8

CFLAGS+=	-I${SRCTOP}/lib/libsysctlcmp
LIBADD=		sysctlcmp

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
