.include <src.opts.mk>

PACKAGE=localcrypto
PROG=localcrypto
MAN=
SRCS=localcrypto.c policy.c
CFLAGS+=-I${SRCTOP}/lib/libauditcmp -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libcryptocmp -I${SRCTOP}/lib/libcryptodesc -I${SRCTOP}/lib/libservice -I${SRCTOP}/sys
LIBADD=auditcmp channel cryptocmp cryptodesc service
DIRS+=CRYPTOCMP_CAP CRYPTOCMP_CAP_BIN CRYPTOCMP_CAP_ETC
CRYPTOCMP_CAP=/Capabilities/System/Crypto.cap
CRYPTOCMP_CAPPACKAGE=localcrypto
CRYPTOCMP_CAP_BIN=${CRYPTOCMP_CAP}/bin
CRYPTOCMP_CAP_BINPACKAGE=localcrypto
CRYPTOCMP_CAP_ETC=${CRYPTOCMP_CAP}/etc
CRYPTOCMP_CAP_ETCPACKAGE=localcrypto
BINDIR=${CRYPTOCMP_CAP_BIN}
FILESGROUPS+=SERVICES
SERVICES=capbundle/crypto.ucl
SERVICESDIR=${CRYPTOCMP_CAP_ETC}
SERVICESNAME_capbundle/crypto.ucl=crypto.ucl
SERVICESMODE=0444
HAS_TESTS=
SUBDIR.${MK_TESTS}+=tests
.include <bsd.prog.mk>

_proginstall: installdirs-CRYPTOCMP_CAP_BIN
