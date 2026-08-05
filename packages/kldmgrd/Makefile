WORLDPACKAGE=	kldmgrd
PKG_SETS=	minimal
SUBPACKAGES=	dbg man

PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/kldmgrd-all.ucl

PKG_DEPS.kldmgrd+=	audit
PKG_DEPS.kldmgrd+=	libchannel
PKG_DEPS.kldmgrd+=	libkldmgr
PKG_DEPS.kldmgrd+=	libservice
PKG_DEPS.kldmgrd+=	serviced

.include <bsd.pkg.mk>
