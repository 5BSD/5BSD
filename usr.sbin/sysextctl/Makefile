.include <src.opts.mk>
PACKAGE=	sysextctl
PROG=	sysextctl
MAN=	sysextctl.8
CFLAGS+=	-I${SRCTOP}/lib/libservice -I${SRCTOP}/lib/libcapsulert
LIBADD=	service
HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests
.include <bsd.prog.mk>
