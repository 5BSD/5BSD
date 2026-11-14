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
ATF_TESTS_C+=	dq_start_test
ATF_TESTS_C+=	dq_tree_oracle_test
ATF_TESTS_C+=	dq_cwd_test
ATF_TESTS_C+=	dq_getcwd_test
ATF_TESTS_C+=	dq_kclass_test
ATF_TESTS_C+=	dq_exec_test
ATF_TESTS_C+=	dq_launch_test
ATF_TESTS_C+=	dq_bootstrap_test
ATF_TESTS_C+=	dq_legitimacy_test
ATF_TESTS_C+=	dq_owner_test
ATF_TESTS_C+=	dq_swap_test
ATF_TESTS_SH+=	dq_dtrace_test
ATF_TESTS_SH+=	dq_testopen_test
ATF_TESTS_SH+=	dq_oracle_test
ATF_TESTS_SH+=	dq_tree_suites_test

# Every program is a controller: the shared harness is part of each.
.for _t in ${ATF_TESTS_C}
SRCS.${_t}=	${_t}.c dq_test.c
.endfor

# ABI header <dev/dq/dq.h> and the library's own header.
CFLAGS+=	-I${SRCTOP}/sys -I${SRCTOP}/lib/libdq

# The OES client side of dq_oes_test (<security/oes/oes.h>, liboes.h).
CFLAGS.dq_oes_test+=	-I${SRCTOP}/lib/liboes
LIBADD.dq_oes_test+=	oes

# BS-0: service_open(3) and the three base clients it pins.
CFLAGS.dq_bootstrap_test+=	-I${SRCTOP}/lib/libservice \
				-I${SRCTOP}/lib/libcapsulert \
				-I${SRCTOP}/lib/libnotify \
				-I${SRCTOP}/lib/liblogcmp \
				-I${SRCTOP}/lib/libsysctlcmp
LIBADD.dq_bootstrap_test+=	notify logcmp sysctlcmp service

# jail_setv(3) for the I5 jail_attach row.
LIBADD.dq_resolve_test+=	jail
# jail_setv(3) for the address-family row.
LIBADD.dq_socket_test+=	jail

# jail_setv(3) for the jailed rows; capability_service_connect(3) on a
# device descriptor the caller did not open.
LIBADD.dq_legitimacy_test+=	jail capability
CFLAGS.dq_legitimacy_test+=	-I${SRCTOP}/lib/libcapability

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
# Changes the mode of /dev/dq and security.bsd.unprivileged_proc_debug,
# creates jails: run alone.
TEST_METADATA.dq_legitimacy_test+=	is_exclusive="true"
# Counts the queues that exist, sets vfs.aio.enable_unsafe: run alone.
TEST_METADATA.dq_owner_test+=	is_exclusive="true"
# Sets vfs.lookup_cap_dotdot: run alone.
TEST_METADATA.dq_start_test+=	is_exclusive="true"
# Set kern.chroot_allow_open_directories, mount linprocfs, call acct(2),
# ktrace(2), swapon(2) and kldload(2): run alone (1c-iii-c).
TEST_METADATA.dq_cwd_test+=	is_exclusive="true"
TEST_METADATA.dq_getcwd_test+=	is_exclusive="true"
TEST_METADATA.dq_kclass_test+=	is_exclusive="true"
# Runs whole suites in a served root and in chroot(8): alone, with time.
TEST_METADATA.dq_tree_suites_test+=	is_exclusive="true" timeout="7200"
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

# The served-root controller the suites oracle runs kyua under, and the
# differences from chroot(8) it expects (stage 1c-iii-c).
PROGS+=		dqtree
SRCS.dqtree=	dqtree.c
MAN.dqtree=
BINDIR.dqtree=	${TESTSDIR}
${PACKAGE}FILES+=	dqtree.expected

# dq_exec_test's dynamic image (copied into a served tree).
PROGS+=		dq_exec_helper
SRCS.dq_exec_helper=	dq_exec_helper.c
MAN.dq_exec_helper=
BINDIR.dq_exec_helper=	${TESTSDIR}

# dq_served_test's Linux program for the O_PATH rows, built by the test.
${PACKAGE}FILES+=	dq_opath_linux.c

# dq_owner_test's exec'd image and its Linux program, built by the test.
PROGS+=		dq_owner_helper
SRCS.dq_owner_helper=	dq_owner_helper.c
MAN.dq_owner_helper=
BINDIR.dq_owner_helper=	${TESTSDIR}
${PACKAGE}FILES+=	dq_owner_linux.c

# dq_legitimacy_test's parent of an attach target, and its Linux
# and 32-bit programs, built by the test.
PROGS+=		dq_legitimacy_helper
SRCS.dq_legitimacy_helper=	dq_legitimacy_helper.c
MAN.dq_legitimacy_helper=
BINDIR.dq_legitimacy_helper=	${TESTSDIR}
${PACKAGE}FILES+=	dq_legitimacy_linux.c
${PACKAGE}FILES+=	dq_legitimacy_ilp32.c

# The socket commands the oracle runs (stage 1c-ii).
PROGS+=		dq_sockprog
SRCS.dq_sockprog=	dq_sockprog.c
MAN.dq_sockprog=
BINDIR.dq_sockprog=	${TESTSDIR}

WARNS?=		6

.include <bsd.test.mk>
