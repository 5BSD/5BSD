WORLDPACKAGE=	bluetooth
SUBPACKAGES=	dbg dev lib man
COMPAT_PKGS=	dbg dev lib

# Bluetooth isn't applicable to jails.
PKG_SETS=	optional

# rfcomm_pppd(8) uses ppp(8)
PKG_DEPS.bluetooth+=	ppp
# blued(8) supports serviced(8) lifecycle and capability activation.
PKG_DEPS.bluetooth+=	libservice

.include <bsd.pkg.mk>
