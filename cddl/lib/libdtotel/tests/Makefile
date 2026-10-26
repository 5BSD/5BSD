.include <src.opts.mk>

PACKAGE=	libotelexport-tests

ATF_TESTS_C=	dtotel_test
SRCS.dtotel_test=	dtotel_test.c dtrace_stub.c

CFLAGS+=	-DIN_BASE
CFLAGS+=	-DSKIP_SPL_SYS_CONDVAR_H
CFLAGS+=	-I${ZFSTOP}/include
CFLAGS+=	-I${ZFSTOP}/lib/libspl/include/
CFLAGS+=	-I${ZFSTOP}/lib/libspl/include/os/freebsd
CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+=	-I${SRCTOP}/sys/cddl/compat/opensolaris \
		-I${SRCTOP}/cddl/compat/opensolaris/include \
		-I${SRCTOP}/cddl/contrib/opensolaris/head \
		-I${SRCTOP}/cddl/contrib/opensolaris/lib/libdtrace/common \
		-I${SRCTOP}/cddl/contrib/opensolaris/lib/libproc/common \
		-I${SRCTOP}/sys/cddl/contrib/opensolaris/uts/common \
		-I${SRCTOP}/sys/cddl/contrib/opensolaris/compat
CFLAGS+=	-DHAVE_ISSETUGID
CFLAGS+=	-DNEED_SOLARIS_BOOLEAN -DHAVE_STRLCAT -DHAVE_STRLCPY
CFLAGS+=	-I${SRCTOP}/lib/libotelexport
CFLAGS+=	-I${SRCTOP}/lib/libotelexport/tests
CFLAGS+=	-I${.CURDIR:H}
.PATH:		${SRCTOP}/lib/libotelexport/tests
SRCS.dtotel_test+=	otlp_validate.c

# dtrace_stub.c stands in for the libdtrace entry points libdtotel
# uses, so the bridge is tested without a DTrace device.
LIBADD.dtotel_test+=	dtotel otelexport z ssl crypto pthread m

.include <bsd.test.mk>
