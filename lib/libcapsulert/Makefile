.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	capsulert
SHLIB_MAJOR=	2

SRCS=	claim_parse.c switchboard_lifecycle.c switchboard_history.c switchboard_reclamation.c
INCS=	switchboard_reclamation.h switchboard_lifecycle.h capsulert.h claim_parse.h capsule_ctl.h \
	switchboard_ctl.h capsule_svc_proto.h switchboard_svc_proto.h \
	tzfsd_proto.h

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
