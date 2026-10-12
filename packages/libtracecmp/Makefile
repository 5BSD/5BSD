WORLDPACKAGE=	libtracecmp
PKG_SETS=	minimal minimal-jail
SUBPACKAGES=	dbg dev man
COMPAT_PKGS=	dbg dev lib
PKG_LICENSES=	BSD2CLAUSE
PKG_LICENSELOGIC= multi
UCLSRC=	${SRCTOP}/release/packages/ucl/libtracecmp-all.ucl

PKG_DEPS.libtracecmp+=	libservice
PKG_DEPS.libtracecmp+=	dtrace
PKG_DEPS.libtracecmp+=	libfidl clibs

PKG_DEPS.libtracecmp-dev+= libservice-dev libfidl-dev clibs-dev

.include <bsd.pkg.mk>
