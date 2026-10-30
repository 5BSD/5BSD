WORLDPACKAGE=	dtrace
SUBPACKAGES=	dbg dev man
COMPAT_PKG=	yes
COMPAT_PKGS=	dbg dev

# DTrace doesn't work in a jail.
PKG_SETS=	optional
# libotelexport's OTLP/gRPC transport.
PKG_DEPS.dtrace+=	libnghttp2

.include <bsd.pkg.mk>
