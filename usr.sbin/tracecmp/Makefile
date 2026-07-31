.include <src.opts.mk>

PACKAGE=	tracecmp
PROG=	tracecmp
MAN=	tracecmp.8
SRCS=	tracecmp.c
LIBADD=	bsm channel tracecmp service
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libtracecmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys

DIRS+=	TRACECMP_CAP TRACECMP_CAP_BIN TRACECMP_CAP_ETC
TRACECMP_CAP=	/Capabilities/System/TraceCmp.cap
TRACECMP_CAPPACKAGE=	tracecmp
TRACECMP_CAP_BIN=	/Capabilities/System/TraceCmp.cap/bin
TRACECMP_CAP_BINPACKAGE=	tracecmp
TRACECMP_CAP_ETC=	/Capabilities/System/TraceCmp.cap/etc
TRACECMP_CAP_ETCPACKAGE=	tracecmp

BINDIR=	${TRACECMP_CAP_BIN}

FILESGROUPS+=	TRACECMP_MANIFEST
TRACECMP_MANIFEST=	capbundle/tracecmp.ucl
TRACECMP_MANIFESTDIR=	${TRACECMP_CAP_ETC}
TRACECMP_MANIFESTNAME=	tracecmp.ucl
TRACECMP_MANIFESTMODE=	0444

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	tracecmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-TRACECMP_CAP_BIN
