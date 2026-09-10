WORLDPACKAGE=	bluetooth
SUBPACKAGES=	dbg dev lib man
COMPAT_PKGS=	dbg dev lib

# Bluetooth isn't applicable to jails.
PKG_SETS=	optional
UCLSRC=	bluetooth.ucl
UCLSRC.bluetooth=	bluetooth-base.ucl

# rfcomm_pppd(8) uses ppp(8)
PKG_DEPS.bluetooth+=	ppp
# blued(8) supports switchboard(8) lifecycle and capability activation.
PKG_DEPS.bluetooth+=	libservice
PKG_DEPS.bluetooth+=	switchboard
PKG_DEPS.bluetooth+=	switchboardctl

.include <bsd.pkg.mk>
