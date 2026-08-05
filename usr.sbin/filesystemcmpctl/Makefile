.include <src.opts.mk>

PACKAGE=	localfilesystem
PROG=		filesystemcmpctl
MAN=		filesystemcmpctl.8

CFLAGS+=	-I${SRCTOP}/lib/libfilesystemcmp
LIBADD=		filesystemcmp

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>
