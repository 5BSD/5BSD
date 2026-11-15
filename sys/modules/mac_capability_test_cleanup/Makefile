# Test-only service for tests/sys/mac_capability: the unload and cleanup
# cases load and unload it themselves; see
# tests/sys/mac_capability/fixtures/README.
.include "${SRCTOP}/tests/sys/mac_capability/fixtures/Makefile.fixture"

.PATH: ${SRCTOP}/tests/sys/mac_capability/fixtures/cleanup

KMOD=	mac_capability_test_cleanup
SRCS=	cleanup_fixture.c

.include <bsd.kmod.mk>
