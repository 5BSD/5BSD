# SPDX-License-Identifier: BSD-2-Clause

atf_test_case configtest
configtest_head()
{
	atf_set "descr" "logctl uses the daemon's strict configuration parser"
}
configtest_body()
{
	logctl="$(atf_get_srcdir)/logctl_test_bin"
	atf_check -s exit:0 -o match:'ring_size=1048576 fallback_drain_ms=25' \
	    "$logctl" configtest "$(atf_get_srcdir)/valid.conf"
	atf_check -s exit:0 -o match:'segment_size=16777216' \
	    "$logctl" configtest "$(atf_get_srcdir)/valid.conf"
	atf_check -s exit:0 -o match:'max_segments=64' \
	    "$logctl" configtest "$(atf_get_srcdir)/valid.conf"
	atf_check -s exit:65 -e match:invalid.conf \
	    "$logctl" configtest "$(atf_get_srcdir)/invalid.conf"
}

atf_test_case config_errors
config_errors_head()
{
	atf_set "descr" "missing, unknown, duplicate, and mistyped configuration is rejected"
}
config_errors_body()
{
	logctl="$(atf_get_srcdir)/logctl_test_bin"
	atf_check -s exit:65 -e match:missing.conf \
	    "$logctl" configtest missing.conf
	printf '%s\n' 'unknown = 1;' > bad.conf
	atf_check -s exit:65 -e match:bad.conf "$logctl" configtest bad.conf
	printf '%s\n' 'segment_size = "16777216";' > bad.conf
	atf_check -s exit:65 -e match:bad.conf "$logctl" configtest bad.conf
	printf '%s\n' 'max_segments = 0;' > bad.conf
	atf_check -s exit:65 -e match:bad.conf "$logctl" configtest bad.conf
	printf '%s\n' 'ring_size = 262144; ring_size = 524288;' > bad.conf
	atf_check -s exit:65 -e match:bad.conf "$logctl" configtest bad.conf
}

atf_test_case arguments
arguments_head()
{
	atf_set "descr" "invalid commands and severities fail as usage errors"
}
arguments_body()
{
	logctl="$(atf_get_srcdir)/logctl_test_bin"
	atf_check -s exit:64 -e match:'usage: logctl' "$logctl"
	atf_check -s exit:64 -e match:'invalid severity' \
	    "$logctl" emit test subsystem nonsense message
	for command in 'configtest a b' 'emit a b info' 'emit a b info c d' \
	    'show info extra' \
	    'flush extra' 'stats extra' unknown; do
		atf_check -s exit:64 -e match:'usage: logctl' \
		    "$logctl" $command
	done
}

atf_test_case show
show_body()
{
	logctl="$(atf_get_srcdir)/logctl_success_bin"
	atf_check -s exit:0 -o match:'timestamp_ns=1234 receive_timestamp_ns=0 receive_monotonic_ns=0 sequence=42 severity=info' \
	    -o match:'subsystem=tests.logctl category=show message=stored message' \
	    "$logctl" show
	atf_check -s exit:0 -o empty "$logctl" show error
	atf_check -s exit:64 -e match:'invalid severity' "$logctl" show bogus
}

atf_test_case severity_names
severity_names_head()
{
	atf_set "descr" "all documented severity names pass parsing"
}
severity_names_body()
{
	logctl="$(atf_get_srcdir)/logctl_test_bin"
	for severity in trace debug info warn error fatal; do
		atf_check -s exit:69 -e match:'open system.Log' \
		    "$logctl" emit tests tool "$severity" message
	done
}

atf_test_case unavailable
unavailable_head()
{
	atf_set "descr" "live commands report an unavailable service cleanly"
}

atf_test_case successful_commands
successful_commands_head()
{
	atf_set "descr" "live commands use the typed LogCmp API and render replies"
}
successful_commands_body()
{
	logctl="$(atf_get_srcdir)/logctl_success_bin"
	atf_check -s exit:0 -o empty -e empty \
	    "$logctl" emit tests.tool success warn hello
	atf_check -s exit:0 -o empty -e empty "$logctl" flush
	atf_check -s exit:0 -o match:'accepted=11 rejected=2 client_dropped=3 provider_filtered=4 provider_rate_limited=5 last_sequence=17' \
	    -o match:'client_dropped.severity.17=3' \
	    -o match:'provider_rate_limited.severity.13=5' -e empty "$logctl" stats
}

atf_test_case operation_failures
operation_failures_head()
{
	atf_set "descr" "typed operation failures retain stable exit contracts"
}
operation_failures_body()
{
	logctl="$(atf_get_srcdir)/logctl_success_bin"
	atf_check -s exit:65 -e match:'logger: Input/output error' \
	    -e match:'client-closed' env CMP_TEST_FAIL=logger \
	    CMP_TEST_TRACE_CLOSE=1 "$logctl" emit tests.tool success warn hello
	atf_check -s exit:69 -e match:'emit: Input/output error' \
	    -e match:'logger-destroyed' -e match:'client-closed' \
	    env CMP_TEST_FAIL=emit CMP_TEST_TRACE_CLOSE=1 \
	    "$logctl" emit tests.tool success warn hello
	atf_check -s exit:69 -e match:'flush: Input/output error' \
	    -e match:'client-closed' env CMP_TEST_FAIL=flush \
	    CMP_TEST_TRACE_CLOSE=1 "$logctl" flush
	atf_check -s exit:69 -e match:'stats: Input/output error' \
	    -e match:'client-closed' env CMP_TEST_FAIL=stats \
	    CMP_TEST_TRACE_CLOSE=1 "$logctl" stats
	atf_check -s exit:69 -e match:'query system.Log: Input/output error' \
	    -e match:'client-closed' env CMP_TEST_FAIL=query \
	    CMP_TEST_TRACE_CLOSE=1 "$logctl" show
}
unavailable_body()
{
	logctl="$(atf_get_srcdir)/logctl_test_bin"
	atf_check -s exit:69 -e match:'open system.Log' "$logctl" stats
	atf_check -s exit:69 -e match:'open system.Log' "$logctl" flush
	atf_check -s exit:69 -e match:'open system.Log' \
	    "$logctl" emit tests tool info message
}

atf_init_test_cases()
{
	atf_add_test_case configtest
	atf_add_test_case show
	atf_add_test_case config_errors
	atf_add_test_case arguments
	atf_add_test_case severity_names
	atf_add_test_case unavailable
	atf_add_test_case successful_commands
	atf_add_test_case operation_failures
}
