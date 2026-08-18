WORLDPACKAGE=	waspnest-tests
SUBPACKAGES=

PKG_SETS=	tests

# WASPNest is the complete bhyve/VMM qualification package.  The existing
# vsock-tests payload owns the large VirtIO model and guest-lab corpus, while
# tests owns the kernel VMM ATF corpus.  This package supplies the fail-closed
# aggregate runner and makes those inputs an installable unit.
PKG_DEPS.waspnest-tests+=	atf
PKG_DEPS.waspnest-tests+=	kyua
PKG_DEPS.waspnest-tests+=	tests
PKG_DEPS.waspnest-tests+=	vsock-tests
PKG_DEPS.waspnest-tests+=	bhyve
PKG_DEPS.waspnest-tests+=	libvmmapi
PKG_DEPS.waspnest-tests+=	flua
PKG_DEPS.waspnest-tests+=	toolchain
PKG_DEPS.waspnest-tests+=	set-base

.include <bsd.pkg.mk>
