.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	oraclert
SHLIB_MAJOR=	1

SRCS=	claim_parse.c
INCS=	oraclert.h claim_parse.h oracled_ctl.h \
	serviced_ctl.h oracled_svc_proto.h serviced_svc_proto.h \
	tzfsd_proto.h

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
