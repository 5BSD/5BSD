WORLDPACKAGE=	logd
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/logd-all.ucl

PKG_DEPS.logd+=	auditbrokerd
PKG_DEPS.logd+=	libauditcmp
PKG_DEPS.logd+=	libcasper
PKG_DEPS.logd+=	libchannel
PKG_DEPS.logd+=	liblogcmp
PKG_DEPS.logd+=	libservice
PKG_DEPS.logd+=	libucl
PKG_DEPS.logd+=	libshmring
PKG_DEPS.logd+=	serviced

.include <bsd.pkg.mk>
