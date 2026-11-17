#
# DescriptorQueue (dq) test suite.
#
# Integration tests: each program opens /dev/dq as a controller and forks
# requesters, so they need the dq(4) device and root.  One skip policy (see
# libdqtest/dq_test.h): a missing device, module, program or other
# prerequisite of the plane-on test guest is a failure, not a skip; the
# skips left are by architecture (require.arch), a race a one-CPU machine
# cannot run, and a case deferred by name to another VM tier
# (DEFERRED_DEVICE_TIER in dq_bootstrap_test: never in the plane-on test
# tier, where kern.mac_capability_isolation.enforce is 0).
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
ATF_TESTS_C+=	dq_restricted_test
ATF_TESTS_SH+=	dq_dtrace_test
ATF_TESTS_SH+=	dq_testopen_test
ATF_TESTS_SH+=	dq_oracle_test
ATF_TESTS_SH+=	dq_tree_suites_test
ATF_TESTS_SH+=	dq_tree_hang_loop
ATF_TESTS_SH+=	dq_dqswap_test

# Every program is a controller: each links the support library
# (libdqtest), which the libdqtest subdirectory builds first.
SUBDIR=		libdqtest
.for _t in ${ATF_TESTS_C}
LIBADD.${_t}+=	dqtest
.endfor

# ABI header <dev/dq/dq.h>, the library's own header and the support
# library's.
CFLAGS+=	-I${SRCTOP}/sys -I${SRCTOP}/lib/libdq -I${.CURDIR}/libdqtest

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
# jail_setv(3) and jail_remove(2) for the jailed supervisor.
LIBADD.dq_restricted_test+=	jail

# jail_setv(3) for the jailed rows; capability_service_connect(3) on a
# device descriptor the caller did not open.
LIBADD.dq_legitimacy_test+=	jail capability
CFLAGS.dq_legitimacy_test+=	-I${SRCTOP}/lib/libcapability

# The controller thread, the harness's kinfo_getfile(3) oracle.
LIBADD+=	dq pthread util

# Changes kern.dq.max_inflight_per_object: run alone.
TEST_METADATA.dq_concurrency_test+=	is_exclusive="true"
# Changes kern.dq.max_inflight_per_object and _per_requester: run alone.
TEST_METADATA.dq_deadline_test+=	is_exclusive="true"
# Attaches a global OES client, as the OES suite does: run alone.
TEST_METADATA.dq_oes_test+=	is_exclusive="true"
# Switches mac_abac to enforcing for one rule, and traces with dtrace: alone.
TEST_METADATA.dq_mac_test+=	is_exclusive="true"
# Changes kern.dq.max_inflight_bytes and stalls page write-back: run alone.
TEST_METADATA.dq_async_test+=	is_exclusive="true"
# Changes kern.dq.default_deadline_ms and creates a jail: run alone.
TEST_METADATA.dq_resolve_test+=	is_exclusive="true"
# debug.dq.delay_reply_notify acts on every queue.
TEST_METADATA.dq_lock_test+=	is_exclusive="true"
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
# Creates jails: run alone.
TEST_METADATA.dq_restricted_test+=	is_exclusive="true"
# Runs dqswap, which attaches its command: run alone.
TEST_METADATA.dq_dqswap_test+=	is_exclusive="true"
# Set kern.chroot_allow_open_directories, mount linprocfs, call acct(2),
# ktrace(2), swapon(2) and kldload(2): run alone (1c-iii-c).
TEST_METADATA.dq_cwd_test+=	is_exclusive="true"
TEST_METADATA.dq_getcwd_test+=	is_exclusive="true"
TEST_METADATA.dq_kclass_test+=	is_exclusive="true"
# Runs whole suites in a served root and in chroot(8): alone, with time.
TEST_METADATA.dq_tree_suites_test+=	is_exclusive="true" timeout="7200"
# Runs one served-root case 200 times beside CPU burners; only with
# test_suites.FreeBSD.dq_hang_loop set: alone.
TEST_METADATA.dq_tree_hang_loop+=	is_exclusive="true"
# Runs whole suites twice under kyua: alone, and with time.  670 to 1440 s
# on an idle host; more than 3600 s on a loaded one (host load 25-40).
TEST_METADATA.dq_oracle_test+=	is_exclusive="true" timeout="7200"

# dqpass (share/examples/dq): the pass-everything controller the oracle
# test runs suites under, and the differences it expects (M9).
.PATH:		${SRCTOP}/share/examples/dq
PROGS+=		dqpass
SRCS.dqpass=	dqpass.c
LIBADD.dqpass=	dq
MAN.dqpass=
BINDIR.dqpass=	${TESTSDIR}
${PACKAGE}FILES+=	dqpass.expected
# The shell functions dq_oracle_test and dq_tree_suites_test share, and
# the hang capture of the served-root runs (T-R11, T-R12).
${PACKAGE}FILES+=	dq_suites.subr
${PACKAGE}FILES+=	dq_hang.subr

# dqswap (share/examples/dq): the example supervisor that gives up root
# after the attach; dq_dqswap_test runs it.
PROGS+=		dqswap
SRCS.dqswap=	dqswap.c
LIBADD.dqswap=	dq jail
MAN.dqswap=
BINDIR.dqswap=	${TESTSDIR}

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

# dq_owner_test's exec'd image.
PROGS+=		dq_owner_helper
SRCS.dq_owner_helper=	dq_owner_helper.c
MAN.dq_owner_helper=
BINDIR.dq_owner_helper=	${TESTSDIR}

# dq_legitimacy_test's parent of an attach target.
PROGS+=		dq_legitimacy_helper
SRCS.dq_legitimacy_helper=	dq_legitimacy_helper.c
LIBADD.dq_legitimacy_helper=	dqtest
MAN.dq_legitimacy_helper=
BINDIR.dq_legitimacy_helper=	${TESTSDIR}

# The foreign-ABI programs: freestanding amd64 Linux programs for the
# Linux rows of dq_owner_test, dq_served_test, dq_swap_test and
# dq_legitimacy_test, and the i386 FreeBSD and Linux images of
# dq_legitimacy_test's ilp32_no_abi.  No libc and no headers but
# dq_linux.h: they are built here with the cross compiler for their own
# target and installed beside the tests, which run them.  x86 assembly:
# amd64 only, as are the rows (require.arch).  Cross targets take clang
# and lld; with another compiler or linker (an external GCC toolchain,
# WITHOUT_CLANG, WITHOUT_LLD) the programs are not built and the rows
# fail, as they do for any missing prerequisite.
.include <bsd.compiler.mk>
.include <bsd.linker.mk>
.if ${MACHINE_ARCH} == "amd64" && ${COMPILER_TYPE} == "clang" && \
    ${LINKER_TYPE} == "lld"
DQ_FOREIGN_CC=	${CC:N-target:N--target=*:N*-unknown-freebsd*:N--sysroot=*}
DQ_FOREIGN_CFLAGS= -fuse-ld=lld -nostdlib -static -fno-stack-protector \
		-fno-builtin -O2 -Wall -Wextra
.if ${MK_WERROR} != "no"
DQ_FOREIGN_CFLAGS+= -Werror
.endif
DQ_LINUX=	dq_owner_linux dq_opath_linux dq_swap_linux dq_legitimacy_linux
DQ_ILP32=	dq_legitimacy_ilp32_freebsd dq_legitimacy_ilp32_linux
.for _p in ${DQ_LINUX}
DQ_TARGET.${_p}=	x86_64-unknown-linux-gnu
DQ_SRC.${_p}=		${_p}.c
.endfor
DQ_TARGET.dq_legitimacy_ilp32_freebsd=	i386-unknown-freebsd
DQ_TARGET.dq_legitimacy_ilp32_linux=	i386-unknown-linux-gnu
DQ_SRC.dq_legitimacy_ilp32_freebsd=	dq_legitimacy_ilp32.c
DQ_SRC.dq_legitimacy_ilp32_linux=	dq_legitimacy_ilp32.c
.for _p in ${DQ_LINUX} ${DQ_ILP32}
${_p}: ${.CURDIR}/${DQ_SRC.${_p}} ${.CURDIR}/dq_linux.h
	${DQ_FOREIGN_CC} --target=${DQ_TARGET.${_p}} ${DQ_FOREIGN_CFLAGS} \
	    -o ${.TARGET} ${.CURDIR}/${DQ_SRC.${_p}}
${PACKAGE}FILES+=	${_p}
${PACKAGE}FILESMODE_${_p}=	0555
CLEANFILES+=	${_p}
.endfor
.endif

# The socket commands the oracle runs (stage 1c-ii).
PROGS+=		dq_sockprog
SRCS.dq_sockprog=	dq_sockprog.c
MAN.dq_sockprog=
BINDIR.dq_sockprog=	${TESTSDIR}

WARNS?=		6

.include <bsd.test.mk>

# The programs link libdqtest.a: build the subdirectory before them.
.for _t in ${ATF_TESTS_C} dq_legitimacy_helper
.ORDER: all_subdir_${DIRPRFX}libdqtest ${_t}
.endfor
