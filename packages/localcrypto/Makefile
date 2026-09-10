WORLDPACKAGE=localcrypto
PKG_SETS=minimal
SUBPACKAGES=dbg
PKG_LICENSES=BSD2CLAUSE
UCLSRC=${SRCTOP}/release/packages/ucl/localcrypto-all.ucl
UCLSRC.localcrypto=localcrypto.ucl

PKG_DEPS.localcrypto+=auditbrokerd
PKG_DEPS.localcrypto+=libauditcmp
PKG_DEPS.localcrypto+=libchannel
PKG_DEPS.localcrypto+=libcryptocmp
PKG_DEPS.localcrypto+=libcryptodesc
PKG_DEPS.localcrypto+=libservice
PKG_DEPS.localcrypto+=switchboard
PKG_DEPS.localcrypto+=switchboardctl

.include <bsd.pkg.mk>
