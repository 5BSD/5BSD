WORLDPACKAGE=	vsock-tests
SUBPACKAGES=	dbg

PKG_SETS=	tests

# The device harness is an ATF/Kyua test; the e2e suite is driven by scripts.
PKG_DEPS.vsock-tests+=	atf
PKG_DEPS.vsock-tests+=	kyua

# The tests exercise the base system (AF_VSOCK domain, virtio-vsock guest
# transport, bhyve host device), so the base system must be installed.
PKG_DEPS.vsock-tests+=	set-base

.include <bsd.pkg.mk>
