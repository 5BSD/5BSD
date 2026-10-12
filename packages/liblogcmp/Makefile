WORLDPACKAGE=	liblogcmp
PKG_SETS=	minimal minimal-jail
SUBPACKAGES=	dbg dev man
COMPAT_PKGS=	dbg dev lib
PKG_LICENSES=	BSD2CLAUSE
PKG_LICENSELOGIC= multi
UCLSRC=	${SRCTOP}/release/packages/ucl/liblogcmp-all.ucl

PKG_DEPS.liblogcmp+=	libservice
PKG_DEPS.liblogcmp+=	libshmring
PKG_DEPS.liblogcmp+=	libfidl
PKG_DEPS.liblogcmp+=	clibs

PKG_DEPS.liblogcmp-dev+= libservice-dev libfidl-dev clibs-dev

.include <bsd.pkg.mk>
