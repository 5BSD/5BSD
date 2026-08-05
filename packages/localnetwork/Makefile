WORLDPACKAGE=	localnetwork
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/localnetwork-all.ucl

PKG_DEPS.localnetwork+=	auditbrokerd
PKG_DEPS.localnetwork+=	libauditcmp
PKG_DEPS.localnetwork+=	libcasper
PKG_DEPS.localnetwork+=	libchannel
PKG_DEPS.localnetwork+=	libnetworkcmp
PKG_DEPS.localnetwork+=	libservice
PKG_DEPS.localnetwork+=	serviced

.include <bsd.pkg.mk>
