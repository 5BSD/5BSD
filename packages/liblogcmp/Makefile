WORLDPACKAGE=	liblogcmp
PKG_SETS=	minimal minimal-jail
SUBPACKAGES=	dbg dev man
COMPAT_PKGS=	dbg dev lib
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/liblogcmp-all.ucl

PKG_DEPS.liblogcmp+=	libservice
PKG_DEPS.liblogcmp+=	libshmring

.include <bsd.pkg.mk>
