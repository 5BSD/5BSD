# Test-only service for tests/sys/mac_capability.  It travels with the test
# suite in the mac-capability-tests package, never with the kernel; see
# tests/sys/mac_capability/fixtures/README.
PACKAGE=	mac-capability-tests

.PATH: ${SRCTOP}/tests/sys/mac_capability/fixtures/kernelstore

KMOD=	mac_capability_test_kernelstore
SRCS=	mac_capability_test_kernelstore.c

CFLAGS+=	-I${SRCTOP}/sys/dev/mac_capability \
		-I${SRCTOP}/tests/sys/mac_capability/fixtures/include

.include <bsd.kmod.mk>
