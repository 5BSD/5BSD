# Test-only service for tests/sys/mac_capability; see
# tests/sys/mac_capability/fixtures/README.
.include "${SRCTOP}/tests/sys/mac_capability/fixtures/Makefile.fixture"

.PATH: ${SRCTOP}/tests/sys/mac_capability/fixtures/keystore

KMOD=	mac_capability_test_keystore
SRCS=	mac_capability_test_keystore.c

.include <bsd.kmod.mk>
