.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	capability
SHLIB_MAJOR=	1
MAN=	libcapability.3
MLINKS+=	libcapability.3 capability_get_info.3
MLINKS+=	libcapability.3 capability_kernel_call.3

SRCS=	capability.c
INCS=	capability.h

CFLAGS+=	-I${SRCTOP}/sys

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
