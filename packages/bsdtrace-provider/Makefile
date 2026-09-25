WORLDPACKAGE=	bsdtrace-provider
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/bsdtrace-provider-all.ucl
UCLSRC.bsdtrace-provider=	bsdtrace-provider.ucl

PKG_DEPS.bsdtrace-provider+=	audit
PKG_DEPS.bsdtrace-provider+=	libchannel
PKG_DEPS.bsdtrace-provider+=	libservice
PKG_DEPS.bsdtrace-provider+=	libtracecmp
PKG_DEPS.bsdtrace-provider+=	switchboard
PKG_DEPS.bsdtrace-provider+=	switchboardctl

.include <bsd.pkg.mk>
