WORLDPACKAGE=	libnetworkcmp
PKG_SETS=	minimal minimal-jail
SUBPACKAGES=	dbg dev man
COMPAT_PKGS=	dbg dev lib
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/libnetworkcmp-all.ucl

PKG_DEPS.libnetworkcmp+=	libservice
PKG_DEPS.libnetworkcmp+=	libshmring

.include <bsd.pkg.mk>
