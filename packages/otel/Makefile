WORLDPACKAGE=	otel
PKG_SETS=	optional
SUBPACKAGES=	dbg man
# Programs here statically link libotelexport, with the OTLP bindings
# generated from opentelemetry-proto (Apache-2.0,
# /usr/share/licenses/opentelemetry-proto) and the upb runtime (BSD-3-Clause,
# its utf8_range MIT; /usr/share/licenses/upb), both installed by utilities.
PKG_LICENSES=	BSD2CLAUSE BSD3CLAUSE MIT APACHE20
PKG_LICENSELOGIC= multi
# libotelexport's OTLP/gRPC transport.
PKG_DEPS.otel+=	libnghttp2

.include <bsd.pkg.mk>
