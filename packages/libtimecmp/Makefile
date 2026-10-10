WORLDPACKAGE=	libtimecmp
PKG_SETS=	minimal minimal-jail
SUBPACKAGES=	dbg dev man
COMPAT_PKGS=	dbg dev lib
PKG_LICENSES=	BSD2CLAUSE
PKG_LICENSELOGIC= multi
UCLSRC=	${SRCTOP}/release/packages/ucl/libtimecmp-all.ucl

PKG_DEPS.libtimecmp+=	libservice libfidl clibs

PKG_DEPS.libtimecmp-dev+= libservice-dev libfidl-dev clibs-dev

.include <bsd.pkg.mk>
