WORLDPACKAGE=	libfilesystemcmp
PKG_SETS=	minimal minimal-jail
SUBPACKAGES=	dbg dev man
COMPAT_PKGS=	dbg dev lib
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/libfilesystemcmp-all.ucl

PKG_DEPS.libfilesystemcmp+=	libservice clibs
PKG_DEPS.libfilesystemcmp-dev+= libservice-dev clibs-dev

.include <bsd.pkg.mk>
