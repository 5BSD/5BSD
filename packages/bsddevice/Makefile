WORLDPACKAGE=bsddevice
PKG_SETS=minimal
SUBPACKAGES=dbg
PKG_LICENSES=BSD2CLAUSE
UCLSRC=${SRCTOP}/release/packages/ucl/bsddevice-all.ucl
UCLSRC.bsddevice=bsddevice.ucl

PKG_DEPS.bsddevice+=libchannel
PKG_DEPS.bsddevice+=libdevicecmp
PKG_DEPS.bsddevice+=libservice
PKG_DEPS.bsddevice+=switchboard
PKG_DEPS.bsddevice+=switchboardctl

.include <bsd.pkg.mk>
