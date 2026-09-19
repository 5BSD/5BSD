WORLDPACKAGE=bsdcrypto
PKG_SETS=minimal
SUBPACKAGES=dbg
PKG_LICENSES=BSD2CLAUSE
UCLSRC=${SRCTOP}/release/packages/ucl/bsdcrypto-all.ucl
UCLSRC.bsdcrypto=bsdcrypto.ucl

PKG_DEPS.bsdcrypto+=bsdaudit
PKG_DEPS.bsdcrypto+=libauditcmp
PKG_DEPS.bsdcrypto+=libchannel
PKG_DEPS.bsdcrypto+=libcryptocmp
PKG_DEPS.bsdcrypto+=libcryptodesc
PKG_DEPS.bsdcrypto+=libservice
PKG_DEPS.bsdcrypto+=switchboard
PKG_DEPS.bsdcrypto+=switchboardctl

.include <bsd.pkg.mk>
