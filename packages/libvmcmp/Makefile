WORLDPACKAGE=	libvmcmp
PKG_SETS=	minimal minimal-jail
SUBPACKAGES=	dbg dev man
COMPAT_PKGS=	dbg dev lib
PKG_LICENSES=	BSD2CLAUSE
PKG_LICENSELOGIC= multi
UCLSRC=	${SRCTOP}/release/packages/ucl/libvmcmp-all.ucl

PKG_DEPS.libvmcmp+=	libservice libfidl clibs
PKG_DEPS.libvmcmp-dev+= libservice-dev libfidl-dev clibs-dev

.include <bsd.pkg.mk>
