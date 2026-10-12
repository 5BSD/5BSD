WORLDPACKAGE=	libextensioncmp
PKG_SETS=	minimal minimal-jail
SUBPACKAGES=	dbg dev man
COMPAT_PKGS=	dbg dev lib
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/libextensioncmp-all.ucl

PKG_DEPS.libextensioncmp+=	libservice clibs
PKG_DEPS.libextensioncmp-dev+= libservice-dev clibs-dev

.include <bsd.pkg.mk>
