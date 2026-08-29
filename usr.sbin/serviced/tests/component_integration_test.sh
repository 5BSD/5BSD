#!/usr/libexec/atf-sh
#
# SPDX-License-Identifier: BSD-2-Clause

helpers="$(dirname "$0")/test_helpers.sh"
if [ ! -r "${helpers}" ]; then
	helpers="@SRCTOP@/usr.sbin/serviced/tests/test_helpers.sh"
fi
. "${helpers}"

component_fixture=

find_component_fixture()
{
	local candidate srcdir

	if [ -n "${component_fixture}" ] && [ -x "${component_fixture}" ]; then
		return
	fi
	srcdir=$(atf_get_srcdir)
	for candidate in "${COMPONENT_FIXTURE:-}" "${srcdir}/component_fixture"; do
		if [ -n "${candidate}" ] && [ -x "${candidate}" ]; then
			component_fixture="${candidate}"
			return
		fi
	done
	atf_fail "component_fixture is unavailable"
}

make_boot_consumer()
{
	local label="$1" arguments="$2" descriptors="$3" bundle

	bundle=$(make_svc_bin system "${label}" \
	    "arguments = ${arguments};
restart = \"never\";
${descriptors}" "${component_fixture}")
}

install_local_factory()
{
	local kind="$1" binary="$2" endpoint="$3" bundle

	test -x "${binary}" || atf_skip "${kind} provider is unavailable"
	# Descriptor factories must exist before any consumer launches:
	# component delegation resolves them with a plain lookup and no
	# on-demand fallback, exactly like the installed base bundles.
	bundle=$(make_svc_bin system "${kind}-factory" \
	    "activation { boot = true; ipc = [\"${endpoint}\"]; }" "${binary}")
	sed -i '' \
	    "s/^bundle_id = .*/bundle_id = \"${endpoint}\";/" \
	    "${bundle}/Bundle.ucl"
}

install_global_service()
{
	local label="$1" binary="$2" endpoint="$3" identity="${4:-$3}"
	local extra="${5:-}" bundle

	local daemon conf unit

	test -x "${binary}" || atf_skip "${label} provider is unavailable"
	bundle=$(make_svc_bin system "${label}" \
	    "activation { ipc = [\"${endpoint}\"]; }
restart = \"on-failure\";
${extra}" "${binary}")
	sed -i '' \
	    "s/^bundle_id = .*/bundle_id = \"${identity}\";/" \
	    "${bundle}/Bundle.ucl"
	# Providers load a managed policy from their unit Config directory and
	# fail closed without it.  make_svc_bin builds a bare bundle, so stage the
	# provider's default config (<daemon>.conf) alongside the copied binary.
	daemon=$(basename "${binary}")
	unit="${label##*.}"
	conf="/usr/src/usr.sbin/${daemon}/capbundle/${daemon}.conf"
	if [ -f "${conf}" ]; then
		mkdir -p "${bundle}/Units/${unit}.unit/Config"
		cp "${conf}" "${bundle}/Units/${unit}.unit/Config/"
	fi
}

install_audit_service()
{
	local binary bundle

	binary="@OBJTOP@/usr.sbin/auditbrokerd/auditbrokerd"
	test -x "${binary}" || atf_skip "AuditCmp provider is unavailable"
	bundle=$(make_svc_bin system audit-service \
	    'activation { ipc = ["system.Audit"]; }
restart = "on-failure";
user = "root";' "${binary}")
	sed -i '' \
	    's/^bundle_id = .*/bundle_id = "system.Audit";/' \
	    "${bundle}/Bundle.ucl"
}

local_component_test_head()
{
	atf_set "require.user" "root"
	require_authority_stack_kmods
	atf_set "timeout" "60"
}

atf_test_case filesystem_local_end_to_end cleanup
filesystem_local_end_to_end_head()
{
	atf_set "descr" \
	    "filesystem declaration injects private scratch, persistent, and bundle namespaces"
	local_component_test_head
}
filesystem_local_end_to_end_body()
{
	require_mac_capability
	find_component_fixture
	start_stack
	install_audit_service
	install_local_factory filesystem \
	    "@OBJTOP@/usr.sbin/localfilesystem/localfilesystem" \
	    "system.Filesystem"
	make_boot_consumer filesystem-consumer \
	    "[\"filesystem-consumer\", \"${WORK}/filesystem-result.out\"]" \
	    'storage = [{ name = "local"; scope = "unit"; rights = "mount"; }];
protect = ["ptrace", "signal", "visible", "wait"];
descriptors { filesystem { storage = "local"; } }'
	reload_stack
	wait_for_file filesystem-result.out 15 ||
	    atf_fail "filesystem consumer did not complete"
	for result in scratch persistent bundle bundle_readonly durable_sync \
	    logical_cwd multi_open concurrent close_reopen raw_storage_hidden; do
		atf_check -s exit:0 -o match:"${result}=ok" \
		    grep "${result}=ok" filesystem-result.out
	done
	atf_check -s exit:1 -o empty -e empty test -e \
	    /var/db/serviced/storage/filesystem-consumer
	atf_check -s exit:0 -o ignore \
	    grep 'component=filesystem.*phase=delegate' "${logfile}"
	stop_stack
}
filesystem_local_end_to_end_cleanup()
{
	cleanup_common
	rm -f filesystem-result.out
}

atf_test_case network_local_end_to_end cleanup
network_local_end_to_end_head()
{
	atf_set "descr" \
	    "network declaration injects one private nonblocking networking service"
	local_component_test_head
}
network_local_end_to_end_body()
{
	require_mac_capability
	find_component_fixture
	start_stack
	install_audit_service
	install_local_factory network \
	    "@OBJTOP@/usr.sbin/localnetwork/localnetwork" \
	    "system.Network"
	make_boot_consumer network-consumer \
	    "[\"network-consumer\", \"${WORK}/network-result.out\"]" \
	    'descriptors { network {} }'
	reload_stack
	wait_for_file network-result.out 15 ||
	    atf_fail "network consumer did not complete"
	for result in network connect_broker rights_limited connect_only \
	    provider_owned_sockets multi_session concurrent close_reopen; do
		atf_check -s exit:0 -o match:"${result}=ok" \
		    grep "${result}=ok" network-result.out
	done
	atf_check -s exit:0 -o ignore \
	    grep 'component=network.*phase=delegate' "${logfile}"
	stop_stack
}
network_local_end_to_end_cleanup()
{
	cleanup_common
	rm -f network-result.out
}

atf_test_case log_global_on_demand cleanup
log_global_on_demand_head()
{
	atf_set "descr" \
	    "liblogcmp connects to the on-demand global log service without a component declaration"
	local_component_test_head
}
log_global_on_demand_body()
{
	require_mac_capability
	find_component_fixture
	start_stack
	install_audit_service
	install_global_service log-service \
	    "@OBJTOP@/usr.sbin/logd/logd" "system.Log" \
	    "system.Log" \
	    'storage = [{ name = "state"; scope = "unit"; flavor = "empty";
            lifetime = "persistent"; rights = "mount"; }];'
	make_boot_consumer log-consumer \
	    "[\"log-consumer\", \"${WORK}/log-result.out\"]" ""
	reload_stack
	wait_for_file log-result.out 15 ||
	    atf_fail "log consumer did not complete"
	for result in logging multi_open concurrent reopen fork_isolated; do
		atf_check -s exit:0 -o match:"${result}=ok" \
		    grep "${result}=ok" log-result.out
	done
	atf_check -s exit:0 -o match:'accepted=102' \
	    grep 'accepted=102' log-result.out
	atf_check -s exit:1 -o empty -e empty \
	    grep 'local component: logging' "${logfile}"
	stop_stack
}
log_global_on_demand_cleanup()
{
	cleanup_common
	rm -f log-result.out
}

atf_test_case notify_global_sessions cleanup
notify_global_sessions_head()
{
	atf_set "descr" \
	    "libnotify opens independent global sessions with safe default-deny policy"
	local_component_test_head
}
notify_global_sessions_body()
{
	require_mac_capability
	find_component_fixture
	start_stack
	install_audit_service
	install_global_service notify-service \
	    "@OBJTOP@/usr.sbin/bsdnotify/bsdnotify" "system.Notify" \
	    "system.Notify"
	make_boot_consumer notify-consumer \
	    "[\"notify-subscriber\", \"${WORK}/notify-result.out\"]" ""
	reload_stack
	wait_for_file notify-result.out 15 ||
	    atf_fail "notify consumer did not complete"
	for result in notification default_deny multi_open concurrent \
	    close_reopen fork_isolated; do
		atf_check -s exit:0 -o match:"${result}=ok" \
		    grep "${result}=ok" notify-result.out
	done
	stop_stack
}
notify_global_sessions_cleanup()
{
	cleanup_common
	rm -f notify-result.out
}

atf_test_case trace_global_safe_api cleanup
trace_global_safe_api_head()
{
	atf_set "descr" \
	    "libtracecmp reaches the global service while raw DTrace delegation remains unavailable"
	local_component_test_head
}
trace_global_safe_api_body()
{
	require_mac_capability
	find_component_fixture
	start_stack
	install_global_service trace-service \
	    "@OBJTOP@/usr.sbin/traced/traced" "system.Trace"
	make_boot_consumer trace-consumer \
	    "[\"trace-consumer\", \"${WORK}/trace-result.out\"]" ""
	reload_stack
	wait_for_file trace-result.out 15 ||
	    atf_fail "trace consumer did not complete"
	atf_check -s exit:0 -o match:'trace=ok' cat trace-result.out
	atf_check -s exit:0 -o match:'raw_descriptor=denied' \
	    cat trace-result.out
	stop_stack
}
trace_global_safe_api_cleanup()
{
	cleanup_common
	rm -f trace-result.out
}

atf_init_test_cases()
{
	atf_add_test_case filesystem_local_end_to_end
	atf_add_test_case network_local_end_to_end
	atf_add_test_case log_global_on_demand
	atf_add_test_case notify_global_sessions
	atf_add_test_case trace_global_safe_api
}
