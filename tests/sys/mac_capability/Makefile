# Run the suite in disposable QEMU guests with
# tools/build/fuchsia/vm-provider.sh (plane-on tier, and PLANE_OFF=1 for the
# enforced tier; docs/book/src/develop/testing.md).  The fixture services the
# keystore/kernelstore cases require are built from sys/modules and shipped in
# this package; see fixtures/README.
.include <src.opts.mk>

PACKAGE=	mac-capability-tests
TESTSDIR=	${TESTSBASE}/sys/mac_capability
SCRIPTSDIR=	${TESTSDIR}

ATF_TESTS_C+=	mac_capability_test
ATF_TESTS_C+=	mac_capability_coalition_test
NO_SHARED.mac_capability_coalition_test= yes
ATF_TESTS_C+=	mac_capability_isolation_test
ATF_TESTS_C+=	mac_capability_identity_test
ATF_TESTS_C+=	mac_capability_node_test
ATF_TESTS_C+=	mac_capability_accounting_test
ATF_TESTS_C+=	mac_capability_accounting_racct_test
ATF_TESTS_C+=	mac_capability_jail_lock_order_test
LIBADD.mac_capability_jail_lock_order_test+=	jail
TEST_METADATA.mac_capability_jail_lock_order_test+=	is_exclusive="true"
ATF_TESTS_C+=	mac_capability_procdesc_test
ATF_TESTS_C+=	authority_test_issuer_test
# Base exclusion (oes-core-exemption.md): pins and mechanics.  Its issuer
# cases need the stack tier (test issuers); its PID 1 and switchboard cases
# run on every tier.
ATF_TESTS_C+=	cap_exclusion_test
TEST_METADATA.cap_exclusion_test+=	is_exclusive="true"
LIBADD.cap_exclusion_test+=	util dq
CFLAGS.cap_exclusion_test+=	-I${SRCTOP}/lib/libdq
PROGS+=		cap_exclusion_helper
NO_SHARED.cap_exclusion_helper=	yes
ATF_TESTS_C+=	authority_test_issuer_anchor_test
LIBADD.authority_test_issuer_anchor_test+=	pthread
ATF_TESTS_C+=	authority_issuer_probe_test
PROGS+=		authority_issuer_helper
ATF_TESTS_C+=	mac_capability_mount_test
ATF_TESTS_C+=	mac_capability_system_test
ATF_TESTS_C+=	mac_ntpd_delegate_test
# These programs change or assert on global state, so run each alone (ATF
# test cases cannot carry is_exclusive; it is program metadata):
# - system: SYSCTL/SETTIME/KLDLOAD gate claims deny every other nonce;
# - mac_ntpd_delegate: probes the live clock gate and mac_ntpd sysctls;
# - channel: ordering_mixed_paths toggles kern.mac_capability.direct_delivery;
# - coalition: cases assert on kern.mac_capability_coalition.count;
# - isolation: wildcard and overlapping net/vsock claims fail with EBUSY
#   across nonces.
TEST_METADATA.mac_capability_system_test+=	is_exclusive="true"
TEST_METADATA.mac_ntpd_delegate_test+=	is_exclusive="true"
TEST_METADATA.mac_capability_channel_test+=	is_exclusive="true"
TEST_METADATA.mac_capability_coalition_test+=	is_exclusive="true"
TEST_METADATA.mac_capability_isolation_test+=	is_exclusive="true"
ATF_TESTS_C+=	mac_capability_channel_test
PROGS+=		mac_capability_exec_helper
PROGS+=		mac_capability_channel_helper
PROGS+=		mac_capability_isolation_helper
PROGS+=		mac_capability_shield_helper
# Debug and inspect answers for protected processes, and DTrace against
# them (dtrace-under-shield-minimal design).  The fixture carries a USDT
# provider; the agent plays the protector, prober and tracer as a separate
# process; the ADDDOF helper registers DOF for another process, and the
# fasttrap helper makes pid-provider probes without libdtrace.  The DTrace
# cases need dtraceall preloaded: the plane refuses a late kldload.
ATF_TESTS_C+=	capprotect_debug_pins_test
TEST_METADATA.capprotect_debug_pins_test+=	is_exclusive="true"
CFLAGS.capprotect_debug_pins_test+=	-I${SRCTOP}/tests/sys/security/oes
LIBADD.capprotect_debug_pins_test+=	jail
ATF_TESTS_SH+=	capprotect_dtrace_test
TEST_METADATA.capprotect_dtrace_test+=	is_exclusive="true"
ATF_TESTS_SH+=	capprotect_live_plane_test
TEST_METADATA.capprotect_live_plane_test+=	is_exclusive="true"
PROGS+=		capprotect_usdt_helper capprotect_protector_helper \
		capprotect_adddof_helper capprotect_fasttrap_helper
SRCS.capprotect_usdt_helper=	capprotect_usdt_helper.c
.if ${MK_DTRACE} != "no"
SRCS.capprotect_usdt_helper+=	capprotect_usdt_helper_provider.d
CFLAGS.capprotect_usdt_helper+=	-DWITH_DTRACE
LIBADD.capprotect_usdt_helper+=	elf
LIBADD.capprotect_usdt_helper+=	pthread
.endif
ATF_TESTS_SH+=	process_context_test
PROGS+=		process_context_helper process_context_edge_helper \
		process_context_ipc_helper
.for helper in process_context_helper process_context_edge_helper process_context_ipc_helper
CFLAGS.${helper}+=	-I${SRCTOP}/sys -I${SRCTOP}/lib/libchannel
LIBADD.${helper}+=	channel capability pthread
.endfor
# authority_boot_helper runs only as PID 1 in an isolated VM image.
PROGS+= authority_boot_helper authority_session_helper
PROGS+= authority_loader_helper
FILES+= authority-inject.so
FILESDIR= ${TESTSDIR}
CLEANFILES+= authority-inject.so
authority-inject.so: ${.CURDIR}/authority_preload_helper.c
	${CC} ${CFLAGS} ${LDFLAGS} -shared -fPIC -o ${.TARGET} ${.ALLSRC}
all: authority-inject.so
CFLAGS.authority_boot_helper+= -I${SRCTOP}/sys -I${SRCTOP}/lib/libchannel -I${SRCTOP}/lib/libcapability
LIBADD.authority_boot_helper+= channel capability pthread
NO_SHARED.authority_boot_helper= yes
.PATH: ${SRCTOP}/usr.sbin/switchboard ${SRCTOP}/usr.sbin/switchboard/nss-helper
SRCS.authority_boot_helper= authority_boot_helper.c nss_exchange.c nss_child.c nss_protocol.c
CFLAGS.authority_boot_helper+= -I${SRCTOP}/usr.sbin/switchboard

CFLAGS.authority_session_helper+= -I${SRCTOP}/sys -I${SRCTOP}/lib/libservice
CFLAGS.authority_session_helper+= -I${SRCTOP}/lib/libcapsulert
LIBADD.authority_session_helper+= service
BINDIR=		${TESTSDIR}

CFLAGS+=	-I${SRCTOP}/sys -I${SRCTOP}/sys/dev/mac_capability
CFLAGS+=	-I${.CURDIR}/fixtures/include
LIBADD.mac_capability_test+=	jail
LIBADD.mac_capability_test+=	util
LIBADD.mac_capability_coalition_test+=	jail pthread
LIBADD.mac_capability_isolation_test+=	jail
LIBADD.mac_capability_isolation_helper+=	jail

SUBDIR+=	usdtlib

.include <bsd.test.mk>
