.include <src.opts.mk>

LIB=		dtotel
INTERNALLIB=

SRCS=		dtotel.c \
		dtotel_agg.c

WARNS?=		3

CFLAGS+=	-DIN_BASE
CFLAGS+=	-DSKIP_SPL_SYS_CONDVAR_H
CFLAGS+=	-I${ZFSTOP}/include
CFLAGS+=	-I${ZFSTOP}/lib/libspl/include/
CFLAGS+=	-I${ZFSTOP}/lib/libspl/include/os/freebsd
CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+=	-I${SRCTOP}/sys/cddl/compat/opensolaris \
		-I${SRCTOP}/cddl/compat/opensolaris/include \
		-I${OPENSOLARIS_USR_DISTDIR}/head \
		-I${OPENSOLARIS_USR_DISTDIR}/lib/libdtrace/common \
		-I${OPENSOLARIS_USR_DISTDIR}/lib/libproc/common \
		-I${OPENSOLARIS_SYS_DISTDIR}/uts/common \
		-I${OPENSOLARIS_SYS_DISTDIR}/compat
CFLAGS+=	-DHAVE_ISSETUGID
CFLAGS+=	-I${SRCTOP}/lib/libotelexport

LIBADD=		dtrace jail otelexport

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
