# Isolated VM fixture; never install or load this module on the host.  The
# source lives with the capability tests, which ship the same module in the
# mac-capability-tests package (sys/modules/mac_capability_test_cleanup);
# run-vm.py --cleanup-lifecycle builds it here for its own staging.
.PATH: ${SRCTOP}/tests/sys/mac_capability/fixtures/cleanup
KMOD= mac_capability_test_cleanup
SRCS= cleanup_fixture.c
CFLAGS+= -I${SRCTOP}/sys/dev/mac_capability
.include <bsd.kmod.mk>
