WORLDPACKAGE=	libpowercmp
PKG_SETS=	minimal minimal-jail
SUBPACKAGES=	dbg dev man
COMPAT_PKGS=	dbg dev lib
PKG_LICENSES=	BSD2CLAUSE
PKG_LICENSELOGIC= multi
UCLSRC=	${SRCTOP}/release/packages/ucl/libpowercmp-all.ucl

PKG_DEPS.libpowercmp+=	libservice libfidl clibs

PKG_DEPS.libpowercmp-dev+= libservice-dev libfidl-dev clibs-dev

.include <bsd.pkg.mk>
