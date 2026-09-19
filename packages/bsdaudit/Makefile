WORLDPACKAGE=	bsdaudit
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/bsdaudit-all.ucl
UCLSRC.bsdaudit=	bsdaudit.ucl

PKG_DEPS.bsdaudit+=	audit
PKG_DEPS.bsdaudit+=	libauditcmp
PKG_DEPS.bsdaudit+=	libchannel
PKG_DEPS.bsdaudit+=	libservice
PKG_DEPS.bsdaudit+=	switchboard
PKG_DEPS.bsdaudit+=	switchboardctl

.include <bsd.pkg.mk>
