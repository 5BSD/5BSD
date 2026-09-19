WORLDPACKAGE=	bsdnetwork
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/bsdnetwork-all.ucl
UCLSRC.bsdnetwork=	bsdnetwork.ucl

PKG_DEPS.bsdnetwork+=	bsdaudit
PKG_DEPS.bsdnetwork+=	libauditcmp
PKG_DEPS.bsdnetwork+=	libcasper
PKG_DEPS.bsdnetwork+=	libchannel
PKG_DEPS.bsdnetwork+=	libnetworkcmp
PKG_DEPS.bsdnetwork+=	libservice
PKG_DEPS.bsdnetwork+=	switchboard
PKG_DEPS.bsdnetwork+=	switchboardctl

.include <bsd.pkg.mk>
