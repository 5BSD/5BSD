# Test-only service for tests/sys/mac_capability; see
# tests/sys/mac_capability/fixtures/README.
.include "${SRCTOP}/tests/sys/mac_capability/fixtures/Makefile.fixture"

.PATH: ${SRCTOP}/tests/sys/mac_capability/fixtures/kernelstore

KMOD=	mac_capability_test_kernelstore
SRCS=	mac_capability_test_kernelstore.c

.include <bsd.kmod.mk>
