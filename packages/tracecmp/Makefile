WORLDPACKAGE=	tracecmp
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/tracecmp-all.ucl

PKG_DEPS.tracecmp+=	audit
PKG_DEPS.tracecmp+=	libchannel
PKG_DEPS.tracecmp+=	libservice
PKG_DEPS.tracecmp+=	libtracecmp
PKG_DEPS.tracecmp+=	serviced

.include <bsd.pkg.mk>
