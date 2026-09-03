.include <src.opts.mk>

PACKAGE=localcrypto
PROG=localcrypto
PROGNAME=	Crypto
MAN=
MAN=localcrypto.8
SRCS=localcrypto.c policy.c
CFLAGS+=-I${SRCTOP}/lib/libauditcmp -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libcryptocmp -I${SRCTOP}/lib/libcryptodesc -I${SRCTOP}/lib/libservice -I${SRCTOP}/sys
LIBADD=auditcmp channel cryptocmp cryptodesc service
DIRS+=CRYPTOCMP_CAP CRYPTOCMP_CAP_UNITS CRYPTOCMP_CAP_UNIT CRYPTOCMP_CAP_BIN
CRYPTOCMP_CAP=/Capabilities/System/Crypto.cap
CRYPTOCMP_CAPPACKAGE=localcrypto
CRYPTOCMP_CAP_UNITS=${CRYPTOCMP_CAP}/Units
CRYPTOCMP_CAP_UNIT=${CRYPTOCMP_CAP_UNITS}/localcrypto.unit
CRYPTOCMP_CAP_BIN=${CRYPTOCMP_CAP_UNIT}/bin
CRYPTOCMP_CAP_BINPACKAGE=localcrypto
CRYPTOCMP_CAP_UNITSPACKAGE=localcrypto
CRYPTOCMP_CAP_UNITPACKAGE=localcrypto
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
.include <bsd.prog.mk>

_proginstall: installdirs-CRYPTOCMP_CAP_BIN
