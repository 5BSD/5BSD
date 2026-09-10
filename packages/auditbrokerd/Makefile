WORLDPACKAGE=	auditbrokerd
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/auditbrokerd-all.ucl
UCLSRC.auditbrokerd=	auditbrokerd.ucl

PKG_DEPS.auditbrokerd+=	audit
PKG_DEPS.auditbrokerd+=	libauditcmp
PKG_DEPS.auditbrokerd+=	libchannel
PKG_DEPS.auditbrokerd+=	libservice
PKG_DEPS.auditbrokerd+=	switchboard
PKG_DEPS.auditbrokerd+=	switchboardctl

.include <bsd.pkg.mk>
