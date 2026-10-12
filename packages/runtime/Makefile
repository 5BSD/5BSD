WORLDPACKAGE=	runtime
SUBPACKAGES=	dbg dev man
COMPAT_PKGS=	dbg dev lib

.include <bsd.endian.mk>
PKG_UCLVARS+=	CAP_MKDB_ENDIAN "${CAP_MKDB_ENDIAN}"

PKG_SETS=	minimal minimal-jail
PKG_VITAL.runtime=
PKG_DEPS.runtime+=	switchboardctl
# BSDTime, BSDPower and BSDSysctl link their C clients, FIDL transport and
# policy parsers directly.
PKG_DEPS.runtime+=	libtimecmp libpowercmp libsysctlcmp libfidl libservice \
	libchannel libucl

UCLSRC=		common.ucl
UCLSRC.runtime=	runtime.ucl

# Provider clients moved out of libservice.
PKG_DEPS.runtime+=	libfilesystemcmp

.include <bsd.pkg.mk>
