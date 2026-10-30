WORLDPACKAGE=	dtrace
SUBPACKAGES=	dbg dev man
COMPAT_PKG=	yes
COMPAT_PKGS=	dbg dev

# dtrace(1) and libdtotel statically link libotelexport, with the OTLP bindings
# generated from opentelemetry-proto (Apache-2.0,
# /usr/share/licenses/opentelemetry-proto) and the upb runtime (BSD-3-Clause,
# its utf8_range MIT; /usr/share/licenses/upb), both installed by utilities.
PKG_LICENSES=	CDDL-1.0 BSD2CLAUSE BSD3CLAUSE MIT APACHE20
PKG_LICENSELOGIC= multi

# DTrace doesn't work in a jail.
PKG_SETS=	optional
# libotelexport's OTLP/gRPC transport.
PKG_DEPS.dtrace+=	libnghttp2

.include <bsd.pkg.mk>
