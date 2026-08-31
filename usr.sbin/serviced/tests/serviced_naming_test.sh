#
# SPDX-License-Identifier: BSD-2-Clause
#
# Full-stack naming contracts for serviced.  Managed programs come from the
# build-time capd_service_fixture; naming.c state-machine unit tests belong in
# the component layer.
#

. "$(atf_get_srcdir)/test_helpers.sh"

install_naming_fixture()
{
	local extra label

	label=$1
	extra=$2
	find_capd_service_fixture
	make_svc_bin system "$label" "$extra" "$capd_service_fixture" >/dev/null
}

wait_naming_result()
{
	if ! wait_for_file "$1"; then
		capd_dump_diagnostics
		atf_fail "naming fixture did not produce $1"
	fi
}

finish_naming_stack()
{
	stop_stack || atf_fail "Authority stack did not stop cleanly"
}

atf_test_case service_ready_protocol cleanup
service_ready_protocol_head()
{
	atf_set "descr" "service READY transitions its serviced state to running"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
service_ready_protocol_body()
{
	prepare_paths
	install_naming_fixture ready-test \
	    'arguments = ["ready", "ready.result"];'
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${APPS_DIR}/ready-test.cap/Units/ready-test.unit/Unit.ucl"
	start_stack
	wait_naming_result ready.result
	atf_check -s exit:0 -o match:'event=ready channel_fd=[0-9]+$' cat ready.result
	atf_check -s exit:0 -o ignore \
	    grep -E 'ready-test.*reported ready' "$logfile"
	finish_naming_stack
}
service_ready_protocol_cleanup()
{
	cleanup_common
}

atf_test_case naming_register_and_lookup cleanup
naming_register_and_lookup_head()
{
	atf_set "descr" "declared provider and client labels complete a brokered exchange"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
naming_register_and_lookup_body()
{
	require_ambient_control
	prepare_paths
	install_naming_fixture org.test.ls-provider \
	    'activation { ipc = ["org.test.ls-provider"]; }
arguments = ["provider", "provider-registered.result", "provider.result"];'
	install_naming_fixture org.test.ls-client \
	    'arguments = ["client", "client.result"];'
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${APPS_DIR}/org.test.ls-client.cap/Units/ls-client.unit/Unit.ucl"
	start_stack
	wait_naming_result provider-registered.result
	wait_naming_result client.result
	wait_naming_result provider.result
	atf_check -s exit:0 -o match:'greeting=hello confined=yes$' cat client.result
	atf_check -s exit:0 \
	    -o match:'client_label=org.test.ls-client/[^ ]* message=world confined=yes$' \
	    cat provider.result
	servicectl status > naming-status.result
	atf_check -s exit:0 -o match:'org.test.ls-provider.*conns=1' \
	    cat naming-status.result
	atf_check -s exit:0 -o not-match:'org.test.ls-client/ls-client running.*conns=[1-9]' \
	    cat naming-status.result
	finish_naming_stack
}
naming_register_and_lookup_cleanup()
{
	cleanup_common
}

atf_test_case naming_lookup_nonexistent cleanup
naming_lookup_nonexistent_head()
{
	atf_set "descr" "lookup of an unregistered name returns ENOENT"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
naming_lookup_nonexistent_body()
{
	prepare_paths
	install_naming_fixture lookup-client \
	    'arguments = ["lookup-missing", "lookup.result"];'
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${APPS_DIR}/lookup-client.cap/Units/lookup-client.unit/Unit.ucl"
	start_stack
	wait_naming_result lookup.result
	atf_check -s exit:0 -o match:'event=lookup fd=-1 errno=2$' cat lookup.result
	finish_naming_stack
}
naming_lookup_nonexistent_cleanup()
{
	cleanup_common
}

atf_test_case naming_auto_unregister_on_exit cleanup
naming_auto_unregister_on_exit_head()
{
	atf_set "descr" "service exit removes every name owned by that service"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
naming_auto_unregister_on_exit_body()
{
	require_ambient_control
	local provider_pid

	prepare_paths
	# A name is registered only once a consumer lookup activates the
	# provider (demand model): a lone provider's declared endpoint stays an
	# unactivated reservation, not a live registration.  So drive a real
	# registration with a client, then kill the provider and confirm the
	# now-live name is auto-unregistered on its owner's exit.
	install_naming_fixture org.test.ls-provider \
	    'restart = "never"; activation { ipc = ["org.test.ls-provider"]; }
arguments = ["provider", "provider-registered.result", "provider.result"];'
	install_naming_fixture org.test.ls-client \
	    'arguments = ["client", "client.result"];'
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${APPS_DIR}/org.test.ls-client.cap/Units/ls-client.unit/Unit.ucl"
	start_stack
	wait_naming_result provider.result
	provider_pid=$(servicectl status |
	    sed -n 's/.*org.test.ls-provider\/ls-provider running  *pid \([0-9][0-9]*\).*/\1/p')
	case "$provider_pid" in
	''|*[!0-9]*) atf_fail "could not determine the provider PID" ;;
	esac
	kill "$provider_pid" || atf_fail "could not terminate the provider"
	if ! wait_for_log 'auto-unregistered.*org.test.ls-provider'; then
		capd_dump_diagnostics
		atf_fail "serviced did not auto-unregister the exited provider"
	fi
	finish_naming_stack
}
naming_auto_unregister_on_exit_cleanup()
{
	cleanup_common
}

atf_test_case naming_unauthorized_name_rejected cleanup
naming_unauthorized_name_rejected_head()
{
	atf_set "descr" "service cannot register a name absent from its manifest"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
naming_unauthorized_name_rejected_body()
{
	prepare_paths
	install_naming_fixture squat-test \
	    'activation { boot = true; ipc = ["org.test.allowed"]; }
arguments = ["register", "com.evil.hijack", "squat.result"];'
	start_stack
	wait_naming_result squat.result
	atf_check -s exit:0 -o match:'event=register .* rc=-1 errno=13$' cat squat.result
	finish_naming_stack
}
naming_unauthorized_name_rejected_cleanup()
{
	cleanup_common
}

atf_test_case naming_self_lookup_eloop cleanup
naming_self_lookup_eloop_head()
{
	atf_set "descr" "a service looking up its own registered name receives ELOOP"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
naming_self_lookup_eloop_body()
{
	prepare_paths
	install_naming_fixture selfloop.test \
	    'activation { boot = true; ipc = ["selfloop.test"]; }
arguments = ["self-lookup", "selfloop.test", "selfloop.result"];'
	start_stack
	wait_naming_result selfloop.result
	atf_check -s exit:0 -o match:'event=self-lookup fd=-1 errno=62$' \
	    cat selfloop.result
	finish_naming_stack
}
naming_self_lookup_eloop_cleanup()
{
	cleanup_common
}

atf_init_test_cases()
{
	atf_add_test_case service_ready_protocol
	atf_add_test_case naming_register_and_lookup
	atf_add_test_case naming_lookup_nonexistent
	atf_add_test_case naming_auto_unregister_on_exit
	atf_add_test_case naming_unauthorized_name_rejected
	atf_add_test_case naming_self_lookup_eloop
}
