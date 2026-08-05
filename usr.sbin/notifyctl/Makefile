.include <src.opts.mk>

PACKAGE=	bsdnotify
PROG=		notifyctl
MAN=		notifyctl.8
SRCS=		notifyctl.c policy.c

.PATH:		${SRCTOP}/usr.sbin/bsdnotify
CFLAGS+=	-I${SRCTOP}/lib/libnotifycmp
CFLAGS+=	-I${SRCTOP}/usr.sbin/bsdnotify
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		notifycmp ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>
