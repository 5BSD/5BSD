.include <src.opts.mk>

PACKAGE=	kldmgrd
PROG=	kldmgrctl
MAN=	kldmgrctl.8
SRCS=	kldmgrctl.c kldmgrd_policy.c
CFLAGS+=	-I${SRCTOP}/lib/libkldmgr
CFLAGS+=	-I${SRCTOP}/usr.sbin/kldmgrd
LIBADD=	kldmgr
.PATH:	${SRCTOP}/usr.sbin/kldmgrd
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.include <bsd.prog.mk>
