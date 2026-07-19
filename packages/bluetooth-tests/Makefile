WORLDPACKAGE=	bluetooth-tests
SUBPACKAGES=	dbg

PKG_SETS=	tests

# The suite is an ATF/Kyua test set.
PKG_DEPS.bluetooth-tests+=	atf
PKG_DEPS.bluetooth-tests+=	kyua

# The tests exercise the base blued daemon, libble, and the netgraph
# Bluetooth stack, so the base system must be installed.
PKG_DEPS.bluetooth-tests+=	set-base

.include <bsd.pkg.mk>
