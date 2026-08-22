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

# Unit-ish coverage that exercises the wire ABI and harness without the module
# is still a plain test; module-dependent tests fail fast if /dev/oes is absent.
PLAIN_TESTS_C=	\
	test_close_event \
	test_multi_process_clients \
	test_event_abi \
	test_event_reader \
	test_liboes_reader \
	test_oeslogger_output \
	test_descendants_client \
	test_nested_descendants \
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
	test_stress

ATF_TESTS_C+=	test_contract_matrix
ATF_TESTS_SH+=	test_unsupported_32bit

# Exercise the library's internal batch state without requiring /dev/oes.
.PATH:	${SRCTOP}/lib/liboes
SRCS.test_liboes_reader=	test_liboes_reader.c liboes.c
SRCS.test_oeslogger_output=	test_oeslogger_output.c liboes.c
SRCS.test_descendants_client=	test_descendants_client.c liboes.c
SRCS.test_nested_descendants=	test_nested_descendants.c liboes.c

.include <bsd.test.mk>
