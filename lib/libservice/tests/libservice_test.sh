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
	local label extra dir

	label=$1
	extra=$2
	dir="${CAPD_APPS_SYSTEM}/${label}.cap"
	mkdir -p "${dir}/etc" "${dir}/bin"
	cp "$service_fixture" "${dir}/bin/${label}"
	chmod 0555 "${dir}/bin/${label}"
	cat >"${dir}/etc/${label}.ucl" <<EOF
bundle_id = "${label}.fixture";
version = "1.0";
author = "test";
program = "${label}";
provides = ["${label}"];
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
		atf_fail "guardian could not clean the Oracle stack"
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
	capd_start_stack
	wait_for_result "$result"
	atf_check -s exit:0 -o match:'^CAPD-TEST/1 event=ready channel_fd=3$' \
	    cat "$result"
	atf_check -s exit:0 -o ignore \
	    grep 'service org.test.ls-ready: reported ready' "$CAPD_LOG"
	capd_stop_stack || atf_fail "Oracle stack did not stop cleanly"
}
ready_reports_channel_cleanup()
{
	cleanup_case
}

atf_test_case naming_exchange_confines_endpoints cleanup
naming_exchange_confines_endpoints_head()
{
	atf_set "descr" "declared naming performs an authenticated exchange over transfer-confined endpoints"
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
	    "requires = [\"org.test.ls-provider\"]; arguments = [\"client\", \"${client}\"];"
	capd_start_stack
	wait_for_result "$registered"
	wait_for_result "$client"
	wait_for_result "$provider"
	atf_check -s exit:0 \
	    -o match:'event=exchange greeting=hello confined=yes$' cat "$client"
	atf_check -s exit:0 \
	    -o match:'event=exchange client_label=org.test.ls-client message=world confined=yes$' \
	    cat "$provider"
	capd_stop_stack || atf_fail "Oracle stack did not stop cleanly"
}
naming_exchange_confines_endpoints_cleanup()
{
	cleanup_case
}

atf_test_case lookup_missing_returns_enoent cleanup
lookup_missing_returns_enoent_head()
{
	atf_set "descr" "lookup of an unregistered service returns ENOENT"
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
	capd_start_stack
	wait_for_result "$result"
	atf_check -s exit:0 \
	    -o match:'^CAPD-TEST/1 event=lookup fd=-1 errno=2$' cat "$result"
	capd_stop_stack || atf_fail "Oracle stack did not stop cleanly"
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

atf_init_test_cases()
{
	atf_add_test_case ready_reports_channel
	atf_add_test_case naming_exchange_confines_endpoints
	atf_add_test_case lookup_missing_returns_enoent
	atf_add_test_case protection_denies_ktrace
}
