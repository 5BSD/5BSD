.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	authorityctl
SRCS=	authorityctl.c
INCS=	authorityctl.h
MAN=	libauthorityctl.3

MLINKS+=	libauthorityctl.3 authorityctl_open.3
MLINKS+=	libauthorityctl.3 authorityctl_status.3
MLINKS+=	libauthorityctl.3 authorityctl_reload.3
MLINKS+=	libauthorityctl.3 authorityctl_shutdown.3

SHLIB_MAJOR=	1

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt

.include <bsd.lib.mk>
