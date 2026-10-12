WORLDPACKAGE=	libvmcmp
PKG_SETS=	minimal minimal-jail
SUBPACKAGES=	dbg dev man
COMPAT_PKGS=	dbg dev lib
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/libvmcmp-all.ucl

PKG_DEPS.libvmcmp+=	libservice clibs
PKG_DEPS.libvmcmp-dev+= libservice-dev clibs-dev

.include <bsd.pkg.mk>
