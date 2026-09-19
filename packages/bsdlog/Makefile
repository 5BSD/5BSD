WORLDPACKAGE=	bsdlog
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/bsdlog-all.ucl
UCLSRC.bsdlog=	bsdlog.ucl

PKG_DEPS.bsdlog+=	bsdaudit
PKG_DEPS.bsdlog+=	libauditcmp
PKG_DEPS.bsdlog+=	libcasper
PKG_DEPS.bsdlog+=	libchannel
PKG_DEPS.bsdlog+=	liblogcmp
PKG_DEPS.bsdlog+=	libservice
PKG_DEPS.bsdlog+=	libucl
PKG_DEPS.bsdlog+=	libshmring
PKG_DEPS.bsdlog+=	switchboard
PKG_DEPS.bsdlog+=	switchboardctl

.include <bsd.pkg.mk>
