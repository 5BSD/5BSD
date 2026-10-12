WORLDPACKAGE=	libfilesystemcmp
PKG_SETS=	minimal minimal-jail
SUBPACKAGES=	dbg dev man
COMPAT_PKGS=	dbg dev lib
PKG_LICENSES=	BSD2CLAUSE
PKG_LICENSELOGIC= multi
UCLSRC=	${SRCTOP}/release/packages/ucl/libfilesystemcmp-all.ucl

PKG_DEPS.libfilesystemcmp+=	libservice libfidl clibs
PKG_DEPS.libfilesystemcmp-dev+= libservice-dev libfidl-dev clibs-dev

.include <bsd.pkg.mk>
