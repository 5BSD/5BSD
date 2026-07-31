WORLDPACKAGE=	filesystemcmp
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/filesystemcmp-all.ucl

PKG_DEPS.filesystemcmp+=	audit
PKG_DEPS.filesystemcmp+=	libchannel
PKG_DEPS.filesystemcmp+=	libfilesystemcmp
PKG_DEPS.filesystemcmp+=	libservice
PKG_DEPS.filesystemcmp+=	serviced

.include <bsd.pkg.mk>
