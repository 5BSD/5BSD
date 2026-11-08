#
# DescriptorQueue (dq) test suite.
#
# Integration tests: each program opens /dev/dq as a controller and forks
# requesters, so they need the dq(4) device and root.  A program skips when
# the device is absent.
#
PACKAGE=	dq-tests
TESTSDIR=	${TESTSBASE}/sys/dq

ATF_TESTS_C+=	dq_identity_test
ATF_TESTS_C+=	dq_read_test
ATF_TESTS_C+=	dq_stage1a_test
ATF_TESTS_C+=	dq_lifecycle_test
ATF_TESTS_C+=	dq_concurrency_test
ATF_TESTS_C+=	dq_deadline_test
ATF_TESTS_C+=	dq_observer_test
ATF_TESTS_C+=	dq_observe_test
ATF_TESTS_C+=	dq_negative_test
ATF_TESTS_C+=	dq_oes_test
ATF_TESTS_C+=	dq_write_test
ATF_TESTS_C+=	dq_setattr_test
ATF_TESTS_C+=	dq_fsync_test
ATF_TESTS_C+=	dq_lock_test
ATF_TESTS_C+=	dq_ioctl_test
ATF_TESTS_C+=	dq_note_test
ATF_TESTS_C+=	dq_mac_test
ATF_TESTS_C+=	dq_mmap_test
ATF_TESTS_C+=	dq_sendfile_test
ATF_TESTS_C+=	dq_cache_test
ATF_TESTS_C+=	dq_async_test
ATF_TESTS_C+=	dq_attach_test
ATF_TESTS_C+=	dq_resolve_test
ATF_TESTS_C+=	dq_socket_test
ATF_TESTS_C+=	dq_served_test
ATF_TESTS_SH+=	dq_dtrace_test
ATF_TESTS_SH+=	dq_oracle_test

# Every program is a controller: the shared harness is part of each.
.for _t in ${ATF_TESTS_C}
SRCS.${_t}=	${_t}.c dq_test.c
.endfor

# ABI header <dev/dq/dq.h> and the library's own header.
CFLAGS+=	-I${SRCTOP}/sys -I${SRCTOP}/lib/libdq

# The OES client side of dq_oes_test (<security/oes/oes.h>, liboes.h).
CFLAGS.dq_oes_test+=	-I${SRCTOP}/lib/liboes
LIBADD.dq_oes_test+=	oes

# jail_setv(3) for the I5 jail_attach row.
LIBADD.dq_resolve_test+=	jail
# jail_setv(3) for the address-family row.
LIBADD.dq_socket_test+=	jail

# The controller thread, the harness's kinfo_getfile(3) oracle.
LIBADD+=	dq pthread util

# Changes kern.dq.max_inflight_per_object: run alone.
TEST_METADATA.dq_concurrency_test+=	is_exclusive="true"
# Attaches a global OES client, as the OES suite does: run alone.
TEST_METADATA.dq_oes_test+=	is_exclusive="true"
# Switches mac_abac to enforcing for one rule, and traces with dtrace: alone.
TEST_METADATA.dq_mac_test+=	is_exclusive="true"
# Changes kern.dq.max_inflight_bytes and stalls page write-back: run alone.
TEST_METADATA.dq_async_test+=	is_exclusive="true"
# Changes kern.dq.default_deadline_ms and creates a jail: run alone.
TEST_METADATA.dq_resolve_test+=	is_exclusive="true"
# Creates a jail, sets kern.dq.default_deadline_ms and
# net.inet.tcp.udp_tunneling_port, traces with dtrace: run alone.
TEST_METADATA.dq_socket_test+=	is_exclusive="true"
TEST_METADATA.dq_served_test+=	is_exclusive="true"
# Runs whole suites twice under kyua: alone, and with time.
TEST_METADATA.dq_oracle_test+=	is_exclusive="true" timeout="3600"

# dqpass (share/examples/dq): the pass-everything controller the oracle
# test runs suites under, and the differences it expects (M9).
.PATH:		${SRCTOP}/share/examples/dq
PROGS+=		dqpass
SRCS.dqpass=	dqpass.c
LIBADD.dqpass=	dq
MAN.dqpass=
BINDIR.dqpass=	${TESTSDIR}
${PACKAGE}FILES+=	dqpass.expected

# The socket commands the oracle runs (stage 1c-ii).
PROGS+=		dq_sockprog
SRCS.dq_sockprog=	dq_sockprog.c
MAN.dq_sockprog=
BINDIR.dq_sockprog=	${TESTSDIR}

WARNS?=		6

.include <bsd.test.mk>
