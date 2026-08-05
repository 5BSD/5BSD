WORLDPACKAGE=	localfilesystem
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/localfilesystem-all.ucl

PKG_DEPS.localfilesystem+=	auditbrokerd
PKG_DEPS.localfilesystem+=	libauditcmp
PKG_DEPS.localfilesystem+=	libchannel
PKG_DEPS.localfilesystem+=	libfilesystemcmp
PKG_DEPS.localfilesystem+=	libservice
PKG_DEPS.localfilesystem+=	serviced

.include <bsd.pkg.mk>
