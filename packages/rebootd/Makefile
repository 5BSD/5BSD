WORLDPACKAGE=	rebootd
PKG_SETS=	minimal
SUBPACKAGES=	dbg man

PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/rebootd-all.ucl

PKG_DEPS.rebootd+=	audit
PKG_DEPS.rebootd+=	libchannel
PKG_DEPS.rebootd+=	localfilesystem
PKG_DEPS.rebootd+=	libfilesystemcmp
PKG_DEPS.rebootd+=	libnotifycmp
PKG_DEPS.rebootd+=	librebootctl
PKG_DEPS.rebootd+=	libservice
PKG_DEPS.rebootd+=	bsdnotify
PKG_DEPS.rebootd+=	serviced

.include <bsd.pkg.mk>
