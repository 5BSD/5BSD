.include <src.opts.mk>

PACKAGE=bsdcrypto
PROG=	BSDCrypto
MAN=BSDCrypto.8
SRCS=bsdcrypto.c policy.c
CFLAGS+=-I${SRCTOP}/lib/libauditcmp -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libcryptocmp -I${SRCTOP}/lib/libcryptodesc -I${SRCTOP}/lib/liblogcmp -I${SRCTOP}/lib/libservice -I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/libextensioncmp
CFLAGS+=	-I${SRCTOP}/lib/libcapreclaim
CFLAGS+=	-I${FIDLGEN.cryptocmp} -I${SRCTOP}/lib/libfidl/include
LIBADD=auditcmp channel cryptocmp cryptodesc extensioncmp service logcmp capreclaim fidl_bsd
DIRS+=CRYPTOCMP_CAP CRYPTOCMP_CAP_UNITS CRYPTOCMP_CAP_UNIT CRYPTOCMP_CAP_BIN
CRYPTOCMP_CAP=/Capabilities/System/Crypto.cap
CRYPTOCMP_CAPPACKAGE=bsdcrypto
CRYPTOCMP_CAP_UNITS=${CRYPTOCMP_CAP}/Units
CRYPTOCMP_CAP_UNIT=${CRYPTOCMP_CAP_UNITS}/bsdcrypto.unit
CRYPTOCMP_CAP_BIN=${CRYPTOCMP_CAP_UNIT}/bin
CRYPTOCMP_CAP_BINPACKAGE=bsdcrypto
CRYPTOCMP_CAP_UNITSPACKAGE=bsdcrypto
CRYPTOCMP_CAP_UNITPACKAGE=bsdcrypto
BINDIR=${CRYPTOCMP_CAP_BIN}
FILESGROUPS+=CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=capbundle/Bundle.ucl
CAP_BUNDLEDIR=${CRYPTOCMP_CAP}
CAP_BUNDLEMODE=0444
CAP_UNIT=capbundle/crypto.ucl
CAP_UNITDIR=${CRYPTOCMP_CAP_UNIT}
CAP_UNITNAME=Unit.ucl
CAP_UNITMODE=0444
HAS_TESTS=
SUBDIR.${MK_TESTS}+=tests

.if ${MK_DTRACE} != "no"
SRCS+=		crypto_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	cryptocmp
FIDL_SCHEMAS.cryptocmp=	lib/libfidl/tests/zx.fidl \
	lib/libcryptocmp/cryptocmp.fidl
FIDL_LIBRARY.cryptocmp=	bsd.crypto.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.prog.mk>

_proginstall: installdirs-CRYPTOCMP_CAP_BIN
