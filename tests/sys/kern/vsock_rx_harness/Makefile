# Guest-side ATF harnesses for the AF_VSOCK RX state machine and VirtIO
# transport.  The tests include the real kernel sources and shadow their
# kernel headers with the small userspace environment in this directory.
# Copy each DUT into ${.OBJDIR} so quote includes resolve in the object tree.

PACKAGE=	waspnest-tests
TESTSDIR=	${TESTSBASE}/sys/kern/vsock_rx_harness

ATF_TESTS_C+=	vsock_rx_test
SRCS.vsock_rx_test=	vsock_rx_test.c glue.c
CFLAGS.vsock_rx_test+=	-I${.CURDIR} -I${.OBJDIR}

ATF_TESTS_C+=	virtio_vsock_transport_test
SRCS.virtio_vsock_transport_test=	virtio_vsock_transport_test.c
CFLAGS.virtio_vsock_transport_test+=	-I${.CURDIR} -I${.OBJDIR} \
					-I${SRCTOP}/sys
LIBADD.virtio_vsock_transport_test+=	pthread

# The included kernel source has intentional sockaddr casts, a local variable
# named ticks, and sysctl handlers unused by this userspace harness.
CWARNFLAGS.vsock_rx_test.c+=	-Wno-cast-align \
				-Wno-shadow \
				-Wno-unused-function \
				-Wno-macro-redefined
CWARNFLAGS.glue.c+=		-Wno-macro-redefined
CWARNFLAGS.virtio_vsock_transport_test.c+=	-Wno-unused-function \
					-Wno-unused-variable \
					-Wno-thread-safety-analysis \
					-Wno-macro-redefined

CLEANFILES+=	uipc_vsock.c virtio_vsock.c

beforedepend: uipc_vsock.c virtio_vsock.c
uipc_vsock.c: ${SRCTOP}/sys/kern/uipc_vsock.c
	cp ${.ALLSRC} ${.TARGET}
virtio_vsock.c: ${SRCTOP}/sys/dev/virtio/vsock/virtio_vsock.c
	cp ${.ALLSRC} ${.TARGET}

.include <bsd.test.mk>
