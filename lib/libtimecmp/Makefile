.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	timecmp
SHLIB_MAJOR=	1
MAN=	libtimecmp.3
MLINKS+=	libtimecmp.3 timecmp_client_open.3 \
		libtimecmp.3 timecmp_client_close.3 \
		libtimecmp.3 timecmp_get.3 \
		libtimecmp.3 timecmp_set.3 \
		libtimecmp.3 timecmp_adjust.3
SRCS=	timecmp.c
INCS=	timecmp.h timecmp_protocol.h
LIBADD=	service
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
