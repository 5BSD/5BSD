.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	appbundle
SHLIB_MAJOR=	1
MAN=	libappbundle.3

SRCS=	libappbundle.c claim_parse.c
INCS=	libappbundle.h

.PATH:	${SRCTOP}/usr.sbin/oracled

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/usr.sbin/serviced
CFLAGS+=	-I${SRCTOP}/usr.sbin/oracled
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		ucl

.include <bsd.lib.mk>
