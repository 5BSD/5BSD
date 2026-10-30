WORLDPACKAGE=	otel-tests
SUBPACKAGES=	dbg
PKG_SETS=	tests
# Programs here statically link libotelexport, with the OTLP bindings
# generated from opentelemetry-proto (Apache-2.0,
# /usr/share/licenses/opentelemetry-proto) and the upb runtime (BSD-3-Clause,
# its utf8_range MIT; /usr/share/licenses/upb), both installed by utilities.
PKG_LICENSES=	BSD2CLAUSE BSD3CLAUSE MIT APACHE20
PKG_LICENSELOGIC= multi

PKG_DEPS.otel-tests+=	atf
PKG_DEPS.otel-tests+=	kyua
PKG_DEPS.otel-tests+=	otel
PKG_DEPS.otel-tests+=	set-base

.include <bsd.pkg.mk>
