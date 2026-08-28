#
# SPDX-License-Identifier: BSD-2-Clause
#
# Full-stack contracts for libservice(3).  Pure API validation lives in
# libservice_api_test.c; managed service behavior uses capd_service_fixture.
#

. "$(atf_get_srcdir)/capd_test_harness.sh"

service_fixture=

find_service_fixture()
{
	local candidate srcdir

	if [ -n "$service_fixture" ] && [ -x "$service_fixture" ]; then
		return 0
	fi
	srcdir=$(atf_get_srcdir)
	for candidate in \
	    "${CAPD_SERVICE_FIXTURE:-}" \
	    "${srcdir}/capd_service_fixture" \
	    "$(command -v capd_service_fixture 2>/dev/null)"
	do
		if [ -n "$candidate" ] && [ -x "$candidate" ]; then
			service_fixture=$candidate
			return 0
		fi
	done
	atf_fail "capd_service_fixture is unavailable"
}

install_fixture()
{
	local label extra dir unit

	label=$1
	extra=$2
	unit=service
	dir="${CAPD_APPS_SYSTEM}/${label}.cap"
	mkdir -p "${dir}/Units/${unit}.unit/bin"
	cp "$service_fixture" "${dir}/Units/${unit}.unit/bin/${unit}"
	chmod 0555 "${dir}/Units/${unit}.unit/bin/${unit}"
	cat >"${dir}/Bundle.ucl" <<EOF
schema = "org.5bsd.capability-bundle";
schema_version = 1;
bundle_id = "${label}";
version = "1.0.0";
sequence = 1;
author = "test";
publisher = "org.test";
units = ["${unit}"];
EOF
	cat >"${dir}/Units/${unit}.unit/Unit.ucl" <<EOF
activation { boot = true; ipc = ["${label}"]; }
${extra}
EOF
}

wait_for_result()
{
	local i path

	path=$1
	i=0
	while [ ! -s "$path" ] && [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -s "$path" ]; then
		capd_dump_diagnostics
		atf_fail "fixture did not produce $(basename "$path")"
	fi
}

cleanup_case()
{
	if ! capd_cleanup_stack; then
		atf_fail "guardian could not clean the Authority stack"
	fi
	rm -f ./*.result
}

atf_test_case ready_reports_channel cleanup
ready_reports_channel_head()
{
	atf_set "descr" "service_init and service_ready reach serviced over the confined channel"
	atf_set "require.user" "root"
	capd_require_stack_kmods
}
ready_reports_channel_body()
{
	local result

	find_service_fixture
	capd_stack_prepare
	result="$(pwd)/ready.result"
	install_fixture org.test.ls-ready \
	    "arguments = [\"ready\", \"${result}\"];"
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${CAPD_APPS_SYSTEM}/org.test.ls-ready.cap/Units/service.unit/Unit.ucl"
	capd_start_stack
	wait_for_result "$result"
	atf_check -s exit:0 -o match:'^CAPD-TEST/1 event=ready channel_fd=[0-9]+$' \
	    cat "$result"
	atf_check -s exit:0 -o ignore \
	    grep -E 'service org.test.ls-ready/service:.*reported ready' "$CAPD_LOG"
	capd_stop_stack || atf_fail "Authority stack did not stop cleanly"
}
ready_reports_channel_cleanup()
{
	cleanup_case
}

atf_test_case naming_exchange_confines_endpoints cleanup
naming_exchange_confines_endpoints_head()
{
	atf_set "descr" \
	    "named global discovery and concurrent accept/RPC use confined independent endpoints"
	atf_set "require.user" "root"
	capd_require_stack_kmods
}
naming_exchange_confines_endpoints_body()
{
	local client provider registered

	find_service_fixture
	capd_stack_prepare
	registered="$(pwd)/provider-registered.result"
	provider="$(pwd)/provider.result"
	client="$(pwd)/client.result"
	install_fixture org.test.ls-provider \
	    "arguments = [\"provider\", \"${registered}\", \"${provider}\"];"
	install_fixture org.test.ls-client \
	    "arguments = [\"client\", \"${client}\"];"
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${CAPD_APPS_SYSTEM}/org.test.ls-client.cap/Units/service.unit/Unit.ucl"
	capd_start_stack
	wait_for_result "$registered"
	atf_check -s exit:0 -o match:'concurrent_lookup_errno=2$' \
	    cat "$registered"
	wait_for_result "$client"
	wait_for_result "$provider"
	atf_check -s exit:0 \
	    -o match:'event=exchange greeting=hello confined=yes$' cat "$client"
	atf_check -s exit:0 \
	    -o match:'event=exchange client_label=org.test.ls-client/[^ ]* message=world confined=yes$' \
	    cat "$provider"
	capd_stop_stack || atf_fail "Authority stack did not stop cleanly"
}
naming_exchange_confines_endpoints_cleanup()
{
	cleanup_case
}

atf_test_case multiplexed_transport_correlates_reordered_replies cleanup
multiplexed_transport_correlates_reordered_replies_head()
{
	atf_set "descr" \
	    "one managed channel correlates concurrent reordered replies, separates events, and reports peer death"
	atf_set "require.user" "root"
	capd_require_stack_kmods
}
multiplexed_transport_correlates_reordered_replies_body()
{
	local client provider

	find_service_fixture
	capd_stack_prepare
	provider="$(pwd)/mux-provider.result"
	client="$(pwd)/mux-client.result"
	install_fixture org.test.transport-mux \
	    "arguments = [\"mux-provider\", \"${provider}\"];"
	install_fixture org.test.transport-client \
	    "arguments = [\"mux-client\", \"${client}\"];"
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${CAPD_APPS_SYSTEM}/org.test.transport-client.cap/Units/service.unit/Unit.ucl"
	capd_start_stack
	wait_for_result "$provider"
	wait_for_result "$client"
	atf_check -s exit:0 -o match:'replies=reordered' cat "$provider"
	atf_check -s exit:0 -o match:'correlated=yes' cat "$client"
	atf_check -s exit:0 -o match:'event=event' cat "$client"
	atf_check -s exit:0 -o match:'peer_death_errno=' cat "$client"
	capd_stop_stack || atf_fail "Authority stack did not stop cleanly"
}
multiplexed_transport_correlates_reordered_replies_cleanup()
{
	cleanup_case
}

atf_test_case multiple_provides_route_independently cleanup
multiple_provides_route_independently_head()
{
	atf_set "descr" \
	    "one provider exposes multiple names with independent listeners and exact routing"
	atf_set "require.user" "root"
	capd_require_stack_kmods
}
multiple_provides_route_independently_body()
{
	local first second provider registered result

	find_service_fixture
	capd_stack_prepare
	registered="$(pwd)/multi-registered.result"
	result="$(pwd)/multi-provider.result"
	first="$(pwd)/multi-first.result"
	second="$(pwd)/multi-second.result"
	install_fixture org.test.multi-provider \
	    "arguments = [\"multi-provider\", \"org.test.multi.first\", \"org.test.multi.second\", \"${registered}\", \"${result}\"];"
	sed -i '' \
	    's/ipc = \["org.test.multi-provider"\]/ipc = ["org.test.multi.first", "org.test.multi.second"]/' \
	    "${CAPD_APPS_SYSTEM}/org.test.multi-provider.cap/Units/service.unit/Unit.ucl"
	install_fixture org.test.multi-client-first \
	    "arguments = [\"named-client\", \"org.test.multi.first\", \"${first}\"];"
	install_fixture org.test.multi-client-second \
	    "arguments = [\"named-client\", \"org.test.multi.second\", \"${second}\"];"
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${CAPD_APPS_SYSTEM}/org.test.multi-client-first.cap/Units/service.unit/Unit.ucl" \
	    "${CAPD_APPS_SYSTEM}/org.test.multi-client-second.cap/Units/service.unit/Unit.ucl"
	capd_start_stack
	wait_for_result "$registered"
	wait_for_result "$result"
	wait_for_result "$first"
	wait_for_result "$second"
	atf_check -s exit:0 -o match:'listener_fds_distinct=1' cat "$registered"
	atf_check -s exit:0 -o match:'first=org.test.multi.first' cat "$result"
	atf_check -s exit:0 -o match:'second=org.test.multi.second' cat "$result"
	atf_check -s exit:0 -o match:'routed=org.test.multi.first' cat "$first"
	atf_check -s exit:0 -o match:'routed=org.test.multi.second' cat "$second"
	capd_stop_stack || atf_fail "Authority stack did not stop cleanly"
}
multiple_provides_route_independently_cleanup()
{
	cleanup_case
}

atf_test_case lookup_missing_returns_enoent cleanup
lookup_missing_returns_enoent_head()
{
	atf_set "descr" "typed global discovery of an unregistered service returns ENOENT"
	atf_set "require.user" "root"
	capd_require_stack_kmods
}
lookup_missing_returns_enoent_body()
{
	local result

	find_service_fixture
	capd_stack_prepare
	result="$(pwd)/lookup.result"
	install_fixture org.test.ls-lookup \
	    "arguments = [\"lookup-missing\", \"${result}\"];"
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${CAPD_APPS_SYSTEM}/org.test.ls-lookup.cap/Units/service.unit/Unit.ucl"
	capd_start_stack
	wait_for_result "$result"
	atf_check -s exit:0 \
	    -o match:'^CAPD-TEST/1 event=lookup fd=-1 errno=2$' cat "$result"
	capd_stop_stack || atf_fail "Authority stack did not stop cleanly"
}
lookup_missing_returns_enoent_cleanup()
{
	cleanup_case
}

atf_test_case protection_denies_ktrace cleanup
protection_denies_ktrace_head()
{
	atf_set "descr" "service_protect denies tracing while procdesc supervision remains effective"
	atf_set "require.user" "root"
	atf_set "require.progs" "ktrace"
	capd_require_stack_kmods
}
protection_denies_ktrace_body()
{
	local result service_pid

	find_service_fixture
	capd_stack_prepare
	result="$(pwd)/protect.result"
	install_fixture org.test.ls-protect \
	    "arguments = [\"protect\", \"${result}\"];"
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${CAPD_APPS_SYSTEM}/org.test.ls-protect.cap/Units/service.unit/Unit.ucl"
	capd_start_stack
	wait_for_result "$result"
	atf_check -s exit:0 -o match:'protected=yes$' cat "$result"
	service_pid=$(sed -n 's/.* pid=\([0-9][0-9]*\) .*/\1/p' "$result")
	case "$service_pid" in
	''|*[!0-9]*) atf_fail "fixture returned an invalid service PID" ;;
	esac
	atf_check -s not-exit:0 -e ignore ktrace -p "$service_pid"
	capd_stop_stack || atf_fail "procdesc supervision could not stop protected service"
}
protection_denies_ktrace_cleanup()
{
	cleanup_case
}

atf_test_case supervisor_death_is_observable cleanup
supervisor_death_is_observable_head()
{
	atf_set "descr" \
	    "a managed process receives a pollable terminal event when serviced dies"
	atf_set "require.user" "root"
	capd_require_stack_kmods
	atf_set "timeout" "45"
}
supervisor_death_is_observable_body()
{
	local i ready result serviced_pid

	find_service_fixture
	# This test alone induces a manager crash to prove supervisor loss is
	# observable; drop the shield's ambient-SIGKILL denial for it only, so
	# procdesc_is_only_signal_authority still verifies the default shield.
	export SERVICED_TEST_SHIELD_NO_SIGKILL=1
	capd_stack_prepare
	ready="$(pwd)/supervisor-monitor.ready.result"
	result="$(pwd)/supervisor-monitor.result"
	install_fixture org.test.supervisor-monitor \
	    "arguments = [\"supervisor-monitor\", \"${ready}\", \"${result}\"];"
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "${CAPD_APPS_SYSTEM}/org.test.supervisor-monitor.cap/Units/service.unit/Unit.ucl"
	capd_start_stack
	wait_for_result "$ready"
	atf_check -s exit:0 -o match:'monitor_ready=1' cat "$ready"

	serviced_pid=
	i=0
	while [ -z "$serviced_pid" ] && [ "$i" -lt 100 ]; do
		serviced_pid=$(sed -n \
		    's/.*bootstrap: started serviced pid \([0-9][0-9]*\).*/\1/p' \
		    "$CAPD_LOG" | tail -n 1)
		i=$((i + 1))
		[ -n "$serviced_pid" ] || sleep 0.1
	done
	case "$serviced_pid" in
	''|*[!0-9]*) atf_fail "could not identify the supervised serviced PID" ;;
	esac
	kill -KILL "$serviced_pid" ||
	    atf_fail "could not terminate serviced"
	wait_for_result "$result"
	atf_check -s exit:0 -o match:'supervisor_lost=1' cat "$result"
	atf_check -s exit:0 -o match:'errno=[1-9][0-9]*' cat "$result"
}
supervisor_death_is_observable_cleanup()
{
	cleanup_case
}

atf_init_test_cases()
{
	atf_add_test_case ready_reports_channel
	atf_add_test_case naming_exchange_confines_endpoints
	atf_add_test_case multiplexed_transport_correlates_reordered_replies
	atf_add_test_case multiple_provides_route_independently
	atf_add_test_case lookup_missing_returns_enoent
	atf_add_test_case protection_denies_ktrace
	atf_add_test_case supervisor_death_is_observable
}
