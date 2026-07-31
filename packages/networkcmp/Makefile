WORLDPACKAGE=	networkcmp
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/networkcmp-all.ucl

PKG_DEPS.networkcmp+=	audit
PKG_DEPS.networkcmp+=	libcasper
PKG_DEPS.networkcmp+=	libchannel
PKG_DEPS.networkcmp+=	libnetworkcmp
PKG_DEPS.networkcmp+=	libservice
PKG_DEPS.networkcmp+=	serviced

.include <bsd.pkg.mk>
