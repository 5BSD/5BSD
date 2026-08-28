.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	authorityrt
SHLIB_MAJOR=	2

SRCS=	claim_parse.c
INCS=	authorityrt.h claim_parse.h authorityd_ctl.h \
	serviced_ctl.h authorityd_svc_proto.h serviced_svc_proto.h \
	tzfsd_proto.h

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
