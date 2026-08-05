.include <src.opts.mk>

PACKAGE=	logd
PROG=		logctl
MAN=		logctl.8
SRCS=		logctl.c config.c

.PATH:		${SRCTOP}/usr.sbin/logd
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${SRCTOP}/usr.sbin/logd
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		logcmp ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>
