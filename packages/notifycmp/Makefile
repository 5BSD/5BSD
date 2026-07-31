WORLDPACKAGE=	notifycmp
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/notifycmp-all.ucl

PKG_DEPS.notifycmp+=	audit
PKG_DEPS.notifycmp+=	libchannel
PKG_DEPS.notifycmp+=	libnotifycmp
PKG_DEPS.notifycmp+=	libservice
PKG_DEPS.notifycmp+=	libucl
PKG_DEPS.notifycmp+=	serviced

.include <bsd.pkg.mk>
