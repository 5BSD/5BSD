# Device-level ATF harness for the bhyve virtio-vsock host device.  It #includes
# the real pci_virtio_vsock.c and shadows its bhyve headers with the mocks in
# this directory; host-socket syscalls are intercepted with ld --wrap.  See
# README.md.  The DUT sources are copied into ${.OBJDIR} so their quote-includes
# resolve to the mocks here (via -I) rather than the real bhyve headers.
#
# Packaged in vsock-tests (not the base tests package) so it can be installed on
# its own.  run.sh runs the device/transport tests under sanitizers without
# ATF.

PACKAGE=	vsock-tests
TESTSDIR=	${TESTSBASE}/sys/kern/vsock_device_harness

ATF_TESTS_C+=	vsock_device_test
ATF_TESTS_C+=	virtio_modern_test
ATF_TESTS_C+=	virtio_input_test
ATF_TESTS_C+=	virtio_rnd_test
ATF_TESTS_C+=	virtio_rnd_interrupt_test
ATF_TESTS_C+=	virtio_core_test
CFLAGS.vsock_device_test+=	-DWITHOUT_CAPSICUM \
				-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/sys
CFLAGS.virtio_modern_test+=	-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin \
				-I${SRCTOP}/sys
CFLAGS.virtio_input_test+=	-DWITHOUT_CAPSICUM \
				-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/sys
CFLAGS.virtio_rnd_test+=	-DWITHOUT_CAPSICUM \
				-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/sys
CFLAGS.virtio_rnd_interrupt_test+= -DWITHOUT_CAPSICUM -ffunction-sections \
				-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin \
				-I${SRCTOP}/sys
CFLAGS.virtio_core_test+=	-DWITHOUT_CAPSICUM -ffunction-sections \
				-I${.CURDIR} -I${.OBJDIR} \
				-I${SRCTOP}/usr.sbin \
				-I${SRCTOP}/sys
# The mock-included device source and the ld --wrap interceptors (non-static so
# the linker binds them, tripping -Wmissing-prototypes) warn; keep non-fatal.
# Must be CWARNFLAGS.<src> (appended after -Werror) -- CFLAGS.<prog> is emitted
# before -Werror and would have no effect.
CWARNFLAGS.vsock_device_test.c+=	-Wno-error
CWARNFLAGS.virtio_modern_test.c+=	-Wno-cast-align \
					-Wno-thread-safety-analysis
CWARNFLAGS.virtio_input_test.c+=	-Wno-error \
					-Wno-thread-safety-analysis
CWARNFLAGS.virtio_rnd_test.c+=	-Wno-error \
					-Wno-thread-safety-analysis
CWARNFLAGS.virtio_rnd_interrupt_test.c+= -Wno-error \
					-Wno-thread-safety-analysis
CWARNFLAGS.virtio_core_test.c+=	-Wno-error \
					-Wno-thread-safety-analysis
LDFLAGS.vsock_device_test+=	-Wl,--wrap=socket -Wl,--wrap=connectat \
	-Wl,--wrap=send -Wl,--wrap=recv -Wl,--wrap=sendmsg -Wl,--wrap=shutdown \
	-Wl,--wrap=poll -Wl,--wrap=close -Wl,--wrap=accept \
	-Wl,--wrap=socketpair -Wl,--wrap=fcntl -Wl,--wrap=setsockopt \
	-Wl,--wrap=getsockopt -Wl,--wrap=recvmsg -Wl,--wrap=ioctl \
	-Wl,--wrap=realloc
LDFLAGS.virtio_core_test+=	-Wl,--gc-sections
LDFLAGS.virtio_rnd_interrupt_test+= -Wl,--gc-sections
LIBADD.vsock_device_test+=	pthread
LIBADD.virtio_modern_test+=	pthread
LIBADD.virtio_input_test+=	pthread
LIBADD.virtio_rnd_test+=	pthread
LIBADD.virtio_rnd_interrupt_test+= pthread
LIBADD.virtio_core_test+=	pthread
CLEANFILES+=	pci_virtio_vsock.c pci_virtio_vsock_iov.h \
		pci_virtio_vsock_probes.h virtio_pci_modern.c \
		virtio_pci_modern_probes.h pci_virtio_input.c pci_virtio_rnd.c \
		virtio.c

# Copy the DUT sources into ${.OBJDIR} at beforedepend (not as an .o prerequisite:
# ATF builds a PIE object, so an .o-only prerequisite never fires and a stale
# copy would be compiled).  Re-copies whenever the bhyve sources change.
beforedepend:	pci_virtio_vsock.c pci_virtio_vsock_iov.h \
		pci_virtio_vsock_probes.h virtio_pci_modern.c \
		virtio_pci_modern_probes.h pci_virtio_input.c pci_virtio_rnd.c \
		virtio.c
pci_virtio_vsock.c:	${SRCTOP}/usr.sbin/bhyve/pci_virtio_vsock.c
	cp ${.ALLSRC} ${.TARGET}
pci_virtio_vsock_iov.h:	${SRCTOP}/usr.sbin/bhyve/pci_virtio_vsock_iov.h
	cp ${.ALLSRC} ${.TARGET}
# No -DWITH_DTRACE here, so every VSOCK_PROBE_* resolves to a no-op.
pci_virtio_vsock_probes.h:	${SRCTOP}/usr.sbin/bhyve/pci_virtio_vsock_probes.h
	cp ${.ALLSRC} ${.TARGET}
virtio_pci_modern.c:	${SRCTOP}/usr.sbin/bhyve/virtio_pci_modern.c
	cp ${.ALLSRC} ${.TARGET}
virtio_pci_modern_probes.h: ${SRCTOP}/usr.sbin/bhyve/virtio_pci_modern_probes.h
	cp ${.ALLSRC} ${.TARGET}
pci_virtio_input.c:	${SRCTOP}/usr.sbin/bhyve/pci_virtio_input.c
	cp ${.ALLSRC} ${.TARGET}
pci_virtio_rnd.c:	${SRCTOP}/usr.sbin/bhyve/pci_virtio_rnd.c
	cp ${.ALLSRC} ${.TARGET}
virtio.c:	${SRCTOP}/usr.sbin/bhyve/virtio.c
	cp ${.ALLSRC} ${.TARGET}

.include <bsd.test.mk>
