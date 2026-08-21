WORLDPACKAGE=	waspnest-tests
SUBPACKAGES=	dbg

PKG_SETS=	tests

# WASPNest is the single bhyve/VMM qualification package.  It owns the VMM,
# AF_VSOCK, VirtIO model, live guest, checkpoint, and nested-VMX test payloads
# directly; only external framework and runtime packages remain dependencies.
PKG_DEPS.waspnest-tests+=	atf
PKG_DEPS.waspnest-tests+=	kyua
PKG_DEPS.waspnest-tests+=	mac-capability-tests
PKG_DEPS.waspnest-tests+=	bhyve
PKG_DEPS.waspnest-tests+=	libvmmapi
PKG_DEPS.waspnest-tests+=	flua
PKG_DEPS.waspnest-tests+=	toolchain
PKG_DEPS.waspnest-tests+=	set-base

.include <bsd.pkg.mk>
