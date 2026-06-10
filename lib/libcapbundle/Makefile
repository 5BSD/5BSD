.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	capbundle
SHLIB_MAJOR=	1
MAN=	libcapbundle.3

SRCS=	libcapbundle.c libcapbundle_parse.c libcapbundle_verify.c
INCS=	libcapbundle.h

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/liboraclert
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		oraclert ucl

.include <bsd.lib.mk>
