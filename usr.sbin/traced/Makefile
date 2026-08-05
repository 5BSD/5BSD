.include <src.opts.mk>

PACKAGE=	traced
PROG=	traced
MAN=	traced.8
SRCS=	tracecmp.c tracecmp_policy.c
LIBADD=	bsm channel tracecmp service
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libtracecmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys

DIRS+=	TRACECMP_CAP TRACECMP_CAP_BIN TRACECMP_CAP_ETC
TRACECMP_CAP=	/Capabilities/System/Trace.cap
TRACECMP_CAPPACKAGE=	traced
TRACECMP_CAP_BIN=	/Capabilities/System/Trace.cap/bin
TRACECMP_CAP_BINPACKAGE=	traced
TRACECMP_CAP_ETC=	/Capabilities/System/Trace.cap/etc
TRACECMP_CAP_ETCPACKAGE=	traced

BINDIR=	${TRACECMP_CAP_BIN}

FILESGROUPS+=	TRACECMP_MANIFEST
TRACECMP_MANIFEST=	capbundle/traced.ucl
TRACECMP_MANIFESTDIR=	${TRACECMP_CAP_ETC}
TRACECMP_MANIFESTNAME=	traced.ucl
TRACECMP_MANIFESTMODE=	0444

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	traced_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-TRACECMP_CAP_BIN
