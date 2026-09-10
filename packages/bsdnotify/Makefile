WORLDPACKAGE=	bsdnotify
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/bsdnotify-all.ucl
UCLSRC.bsdnotify=	bsdnotify.ucl

PKG_DEPS.bsdnotify+=	auditbrokerd
PKG_DEPS.bsdnotify+=	libauditcmp
PKG_DEPS.bsdnotify+=	libchannel
PKG_DEPS.bsdnotify+=	libnotify
PKG_DEPS.bsdnotify+=	libservice
PKG_DEPS.bsdnotify+=	libucl
PKG_DEPS.bsdnotify+=	switchboard
PKG_DEPS.bsdnotify+=	switchboardctl

.include <bsd.pkg.mk>
