# Test-only service for tests/sys/mac_capability: the unload and cleanup
# cases load and unload it themselves.  It travels with the test suite in the
# mac-capability-tests package, never with the kernel; see
# tests/sys/mac_capability/fixtures/README.
PACKAGE=	mac-capability-tests

.PATH: ${SRCTOP}/tests/sys/mac_capability/fixtures/cleanup

KMOD=	mac_capability_test_cleanup
SRCS=	cleanup_fixture.c

CFLAGS+=	-I${SRCTOP}/sys/dev/mac_capability

.include <bsd.kmod.mk>
