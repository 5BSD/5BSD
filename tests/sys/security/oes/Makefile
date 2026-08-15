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
CFLAGS+=	-I${SRCTOP}/sys

# Unit-ish coverage that exercises the wire ABI and harness without the module
# is still a plain test; module-dependent tests fail fast if /dev/oes is absent.
PLAIN_TESTS_C=	\
	test_close_event \
	test_multi_process_clients \
	test_event_abi \
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

.include <bsd.test.mk>
