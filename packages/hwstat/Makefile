WORLDPACKAGE=	hwstat
PKG_SETS=	optional
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=		${SRCTOP}/release/packages/ucl/hwstat-all.ucl
# libotelexport's OTLP/gRPC transport.
PKG_DEPS.hwstat+=	libnghttp2

.include <bsd.pkg.mk>
