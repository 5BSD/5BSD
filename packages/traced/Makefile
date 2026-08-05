WORLDPACKAGE=	traced
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/traced-all.ucl

PKG_DEPS.traced+=	audit
PKG_DEPS.traced+=	libchannel
PKG_DEPS.traced+=	libservice
PKG_DEPS.traced+=	libtracecmp
PKG_DEPS.traced+=	serviced

.include <bsd.pkg.mk>
