.include <src.opts.mk>

PACKAGE=	runtime
PROG=		tzfsctl
MAN=		tzfsctl.8

CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libbsdfilesystem
CFLAGS+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS+=	-I${SRCTOP}/sys

LIBADD=		bsdfilesystem trustedzfs

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
