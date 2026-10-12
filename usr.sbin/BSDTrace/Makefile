.include <src.opts.mk>

PACKAGE=	bsdtrace-provider
PROG=	BSDTrace
MAN=	BSDTrace.8
SRCS=	tracecmp.c tracecmp_policy.c
LIBADD=	bsm channel tracecmp service logcmp fidl_bsd
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${FIDLGEN.tracecmp}
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libtracecmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys

DIRS+=	TRACECMP_CAP TRACECMP_CAP_UNITS TRACECMP_CAP_UNIT TRACECMP_CAP_BIN
TRACECMP_CAP=	/Capabilities/System/Trace.cap
TRACECMP_CAPPACKAGE=	bsdtrace-provider
TRACECMP_CAP_UNITS=	${TRACECMP_CAP}/Units
TRACECMP_CAP_UNIT=	${TRACECMP_CAP_UNITS}/bsdtrace.unit
TRACECMP_CAP_BIN=	${TRACECMP_CAP_UNIT}/bin
TRACECMP_CAP_BINPACKAGE=	bsdtrace-provider
TRACECMP_CAP_UNITSPACKAGE=	bsdtrace-provider
TRACECMP_CAP_UNITPACKAGE=	bsdtrace-provider
BINDIR=	${TRACECMP_CAP_BIN}

FILESGROUPS+=	TRACECMP_BUNDLE TRACECMP_UNIT
TRACECMP_BUNDLE=	capbundle/Bundle.ucl
TRACECMP_BUNDLEDIR=	${TRACECMP_CAP}
TRACECMP_BUNDLEMODE=	0444
TRACECMP_UNIT=	capbundle/bsdtrace.ucl
TRACECMP_UNITDIR=	${TRACECMP_CAP_UNIT}
TRACECMP_UNITNAME=	Unit.ucl
TRACECMP_UNITMODE=	0444

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	bsdtrace_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

CAPIMAGE_MANIFEST= ${TRACECMP_UNIT}

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	tracecmp
FIDL_SCHEMAS.tracecmp=	lib/libfidl/tests/zx.fidl \
	lib/libtracecmp/tracecmp.fidl
FIDL_LIBRARY.tracecmp=	bsd.trace.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.prog.mk>

_proginstall: installdirs-TRACECMP_CAP_BIN
