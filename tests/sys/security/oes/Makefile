#
# OpenEndpointSecurity (oes) test suite.
#
# These are integration tests: they open /dev/oes and therefore require the
# oes(4) module loaded and root privilege.  The shared harness (test_common.h)
# now reports a non-zero exit status on any failed assertion, so they are valid
# plain tests: exit 0 == pass, non-zero == fail.
#
PACKAGE=	oes-tests
TESTSDIR=	${TESTSBASE}/sys/security/oes

# ABI header: <security/oes/oes.h>.
CFLAGS+=	-I${SRCTOP}/sys -I${SRCTOP}/lib/liboes

# Several tests spawn client threads (multi-client auth/notify, stress).
LIBADD+=	pthread

# Most of these tests attach a global OES client: they observe, mute or answer
# every process on the system, and several assert on the exact event stream.
# Run them alone so they neither perturb nor are perturbed by concurrent test
# programs (kyua parallelism > 1).  Clients that deny, leave AUTH events
# unanswered or run fail-closed are additionally descendants-scoped
# (test_set_descendants_scope()), because even an exclusive test must not
# deny the rest of the guest, kyua included.
TEST_METADATA+=	is_exclusive="true"

# Unit-ish coverage that exercises the wire ABI and harness without the module
# is still a plain test; module-dependent tests fail fast if /dev/oes is absent.
# Base exclusion (cap_process(2) BASE EXCLUSION); the stack tier runs it.
ATF_TESTS_C+=	cap_exclusion_oes_test
# A client and its own processes' events (oes-no-self-events.md).
ATF_TESTS_C+=	self_events_test
# A cache add racing the first one waits for the gate (test kernels only).
ATF_TESTS_C+=	cache_gate_test
# The deferred queue's byte bound, per-uid share and lost marker (hold).
ATF_TESTS_C+=	defer_bound_test
# T0a pins (kernel-identity-and-coalitions.md 2.4): the execution id over
# fork and exec, readers per process and execution, mutes per process
# (oes_mute_pid_reuse lowers kern.pid_max to drive pid reuse).
ATF_TESTS_C+=	identity_semantics_test
PROGS+=		oes_join_helper
BINDIR=		${TESTSDIR}

PLAIN_TESTS_C=	\
	test_close_event \
	test_multi_process_clients \
	test_event_abi \
	test_event_reader \
	test_liboes_reader \
	test_oeslogger_output \
	test_descendants_client \
	test_nested_descendants \
	test_jail_pins \
	test_jail_scope \
	test_oeslogger_jail \
	test_vnode_events \
	test_process_events \
	test_multi_client_auth \
	test_multi_client_notify \
	test_auth_responses \
	test_auth_timeout \
	test_decision_cache \
	test_mute \
	test_path_mute \
	test_per_event_muting \
	test_default_muting \
	test_mute_inversion \
	test_uid_gid_mute \
	test_query_muted \
	test_unmute_all \
	test_flags_response \
	test_unmount_event \
	test_kldunload_event \
	test_signal_events \
	test_socket_events \
	test_extattr_acl_events \
	test_mmap_mprotect_events \
	test_chdir_chroot_events \
	test_exec_args \
	test_process_info \
	test_event_metadata \
	test_path_metadata \
	test_hook_coverage \
	test_event_delivery \
	test_mode_timeout_api \
	test_timeout_deadlines \
	test_fd_handling \
	test_bad_ioctls \
	test_error_conditions \
	test_edge_cases \
	test_passive_mode \
	test_memory_pressure \
	test_idle_pins \
	test_idle_gate \
	test_idle_storm \
	test_identity_pins \
	test_stress \
	rename_concurrent \
	signal_concurrent

# Mounts and unmounts a tmpfs in its work directory.
TEST_METADATA.test_unmount_event+=	required_user="root"

ATF_TESTS_C+=	test_contract_matrix
ATF_TESTS_SH+=	test_unsupported_32bit

# Exercise the library's internal batch state without requiring /dev/oes.
.PATH:	${SRCTOP}/lib/liboes
SRCS.test_liboes_reader=	test_liboes_reader.c liboes.c
SRCS.test_oeslogger_output=	test_oeslogger_output.c liboes.c
SRCS.test_descendants_client=	test_descendants_client.c liboes.c
SRCS.test_nested_descendants=	test_nested_descendants.c liboes.c

# The served-descriptor events need a dq(4) controller: libdq mints a
# writable object and dq_serve_file() answers it from a backing file.
CFLAGS.test_hook_coverage+=	-I${SRCTOP}/lib/libdq
LIBADD.test_hook_coverage+=	dq

# libmemstat(3) counts the allocations an idle OES must not make.
LIBADD.test_idle_pins+=	memstat

# jail_setv(3) for the jailed subjects.
LIBADD.test_jail_pins+=	jail
LIBADD.test_jail_scope+=	jail
LIBADD.test_oeslogger_jail+=	jail
LIBADD.defer_bound_test+=	jail

.include <bsd.test.mk>
