PACKAGE=lib${LIB}
LIB=	vmmapi
SHLIB_MAJOR=	7
SRCS=	vmmapi.c vmmapi_dirty_log.c vmmapi_memory.c
INCS=	vmmapi.h

CFLAGS+= -I${.CURDIR} -I${SRCTOP}/sys

.PATH:	${.CURDIR}/${MACHINE_CPUARCH}

.include "${MACHINE_CPUARCH}/Makefile.inc"

LIBADD=	util

.include <bsd.lib.mk>
