WORLDPACKAGE=	auditbrokerd
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/auditbrokerd-all.ucl

PKG_DEPS.auditbrokerd+=	audit
PKG_DEPS.auditbrokerd+=	libauditcmp
PKG_DEPS.auditbrokerd+=	libchannel
PKG_DEPS.auditbrokerd+=	libservice
PKG_DEPS.auditbrokerd+=	serviced

.include <bsd.pkg.mk>
