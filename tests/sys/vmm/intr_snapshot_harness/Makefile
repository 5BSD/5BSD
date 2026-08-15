# Rootless model tests for the kernel vmm interrupt/timer snapshot codecs.
# The tests compile the real sys/amd64/vmm/io device sources against the
# small userspace kernel-header environment in this directory (see the
# vsock_rx_harness for the same pattern).  Uptime and callouts are mocked so
# restore can be exercised on a destination whose uptime differs arbitrarily
# from the source.

PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/vmm/intr_snapshot_harness

ATF_TESTS_C+=	vatpit_snapshot_test
ATF_TESTS_C+=	vioapic_snapshot_test
ATF_TESTS_C+=	vrtc_snapshot_test

CFLAGS.vatpit_snapshot_test+=	-I${.CURDIR}
# vioapic.c quote-includes "vmm_lapic.h" from sys/amd64/vmm.
CFLAGS.vioapic_snapshot_test+=	-I${.CURDIR} -I${SRCTOP}/sys/amd64/vmm
# vrtc.c declares its VM_CTR tracing argument ('vm') only under #ifdef KTR;
# the shadow vmm_ktr.h still references it, so compile with KTR defined.
CFLAGS.vrtc_snapshot_test+=	-I${.CURDIR} -DKTR

# The included kernel sources carry prototypes hidden behind _KERNEL,
# functions unused by a given harness, and kernel-style loop index types.
KMOCK_CWARNFLAGS=	-Wno-unused-function \
			-Wno-missing-prototypes \
			-Wno-unused-parameter \
			-Wno-sign-compare
CWARNFLAGS.vatpit_snapshot_test.c+=	${KMOCK_CWARNFLAGS}
CWARNFLAGS.vioapic_snapshot_test.c+=	${KMOCK_CWARNFLAGS}
CWARNFLAGS.vrtc_snapshot_test.c+=	${KMOCK_CWARNFLAGS}

.include <bsd.test.mk>
