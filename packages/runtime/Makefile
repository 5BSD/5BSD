WORLDPACKAGE=	runtime
SUBPACKAGES=	dbg dev man
COMPAT_PKGS=	dbg dev lib

.include <bsd.endian.mk>
PKG_UCLVARS+=	CAP_MKDB_ENDIAN "${CAP_MKDB_ENDIAN}"

PKG_SETS=	minimal minimal-jail
PKG_VITAL.runtime=
PKG_DEPS.runtime+=	switchboardctl
# BSDTime links its C client, FIDL transport and policy parser directly.
PKG_DEPS.runtime+=	libtimecmp libfidl libservice libchannel libucl

UCLSRC=		common.ucl
UCLSRC.runtime=	runtime.ucl

.include <bsd.pkg.mk>
