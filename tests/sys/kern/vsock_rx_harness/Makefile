# Guest-side ATF harness for the AF_VSOCK RX state machine.  The test includes
# the real sys/kern/uipc_vsock.c and shadows its kernel headers with the small
# userspace environment in this directory.  Copy the DUT into ${.OBJDIR} so
# its quote include resolves to the generated object-tree file.

PACKAGE=	vsock-tests
TESTSDIR=	${TESTSBASE}/sys/kern/vsock_rx_harness

ATF_TESTS_C+=	vsock_rx_test
SRCS.vsock_rx_test=	vsock_rx_test.c glue.c
CFLAGS.vsock_rx_test+=	-I${.CURDIR} -I${.OBJDIR}

# The included kernel source has intentional sockaddr casts, a local variable
# named ticks, and sysctl handlers unused by this userspace harness.
CWARNFLAGS.vsock_rx_test.c+=	-Wno-cast-align \
				-Wno-shadow \
				-Wno-unused-function \
				-Wno-macro-redefined
CWARNFLAGS.glue.c+=		-Wno-macro-redefined

CLEANFILES+=	uipc_vsock.c

beforedepend: uipc_vsock.c
uipc_vsock.c: ${SRCTOP}/sys/kern/uipc_vsock.c
	cp ${.ALLSRC} ${.TARGET}

.include <bsd.test.mk>
