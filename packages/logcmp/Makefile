WORLDPACKAGE=	logcmp
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/logcmp-all.ucl

PKG_DEPS.logcmp+=	audit
PKG_DEPS.logcmp+=	libcasper
PKG_DEPS.logcmp+=	libchannel
PKG_DEPS.logcmp+=	liblogcmp
PKG_DEPS.logcmp+=	libservice
PKG_DEPS.logcmp+=	libshmring
PKG_DEPS.logcmp+=	serviced

.include <bsd.pkg.mk>
