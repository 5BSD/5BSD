# SPDX-License-Identifier: BSD-2-Clause

atf_test_case configtest
configtest_head()
{
	atf_set "descr" "notifyctl uses the daemon policy parser"
}

atf_test_case config_errors
config_errors_head()
{
	atf_set "descr" "missing and malformed policy files are rejected"
}
config_errors_body()
{
	notifyctl="$(atf_get_srcdir)/notifyctl_test_bin"
	atf_check -s exit:65 -e match:missing.conf \
	    "$notifyctl" configtest missing.conf
	printf '%s\n' 'unknown = true;' > bad.conf
	atf_check -s exit:65 -e match:bad.conf "$notifyctl" configtest bad.conf
	printf '%s\n' 'clients = [];' > bad.conf
	atf_check -s exit:65 -e match:bad.conf "$notifyctl" configtest bad.conf
	printf '%s\n' 'clients = { "bad label" = {}; };' > bad.conf
	atf_check -s exit:65 -e match:bad.conf "$notifyctl" configtest bad.conf
}
configtest_body()
{
	notifyctl="$(atf_get_srcdir)/notifyctl_test_bin"
	cp "$(atf_get_srcdir)/valid.conf" valid.conf
	cp "$(atf_get_srcdir)/invalid.conf" invalid.conf
	atf_check -s exit:0 -o match:'valid \(1 client\)' \
	    "$notifyctl" configtest valid.conf
	atf_check -s exit:65 -e match:invalid.conf \
	    "$notifyctl" configtest invalid.conf
}

atf_test_case arguments
arguments_head()
{
	atf_set "descr" "invalid commands and integers fail as usage errors"
}
arguments_body()
{
	notifyctl="$(atf_get_srcdir)/notifyctl_test_bin"
	atf_check -s exit:64 -e match:'usage: notifyctl' "$notifyctl"
	atf_check -s exit:64 -e match:'invalid state' \
	    "$notifyctl" state-set org.5bsd.test.changed nope
	atf_check -s exit:64 -e match:'timeout exceeds' \
	    "$notifyctl" watch org.5bsd.test.changed 4294967296
	atf_check -s exit:64 -e match:'invalid timeout' \
	    "$notifyctl" watch org.5bsd.test.changed invalid
	atf_check -s exit:64 -e match:'invalid timer id' \
	    "$notifyctl" timer invalid 10
	atf_check -s exit:64 -e match:'timer id must be nonzero' \
	    "$notifyctl" timer 0 10
	atf_check -s exit:64 -e match:'interval must be between' \
	    "$notifyctl" timer 1 0
	atf_check -s exit:64 -e match:'interval must be between' \
	    "$notifyctl" timer 1 86400001
	atf_check -s exit:64 -e match:'invalid interval' \
	    "$notifyctl" timer 1 invalid
	atf_check -s exit:64 -e match:'count must be between' \
	    "$notifyctl" timer 1 10 0
	atf_check -s exit:64 -e match:'count must be between' \
	    "$notifyctl" timer 1 10 4294967296
	atf_check -s exit:64 -e match:'invalid count' \
	    "$notifyctl" timer 1 10 invalid
	atf_check -s exit:64 -e match:'timeout exceeds' \
	    "$notifyctl" timer 1 10 1 4294967296
	atf_check -s exit:64 -e match:'invalid timeout' \
	    "$notifyctl" timer 1 10 1 invalid
	for command in 'configtest a b' 'publish' 'publish a b c' 'state-get' \
	    'state-set a' 'state-set a b c' 'watch' 'watch a b c' \
	    'timer' 'timer 1' 'timer 1 2 3 4 5' 'stats extra' unknown; do
		atf_check -s exit:64 -e match:'usage: notifyctl' \
		    "$notifyctl" $command
	done
}

atf_test_case payload_limit
payload_limit_head()
{
	atf_set "descr" "payload limits are enforced before service discovery"
}
payload_limit_body()
{
	notifyctl="$(atf_get_srcdir)/notifyctl_test_bin"
	payload="$(jot -b x -s '' 2049)"
	atf_check -s exit:65 -e match:'payload exceeds 2048 bytes' \
	    "$notifyctl" publish org.5bsd.test.changed "$payload"
}

atf_test_case unavailable
unavailable_head()
{
	atf_set "descr" "live commands report an unavailable broker cleanly"
}

atf_test_case successful_commands
successful_commands_head()
{
	atf_set "descr" "all live commands use the typed Notify API and render data"
}
successful_commands_body()
{
	notifyctl="$(atf_get_srcdir)/notifyctl_success_bin"
	topic=org.5bsd.test.changed
	atf_check -s exit:0 -o empty -e empty \
	    "$notifyctl" publish "$topic" payload
	atf_check -s exit:0 -o inline:'epoch=7 generation=8 state=42\n' \
	    -e empty "$notifyctl" state-get "$topic"
	atf_check -s exit:0 -o empty -e empty \
	    "$notifyctl" state-set "$topic" 42
	atf_check -s exit:0 -o match:'type=1 flags=0x00000000 epoch=7 sequence=9' \
	    -o match:'timer_id=0 generation=8 state=42' \
	    -o match:'publisher=org.5bsd.provider/service topic=org.5bsd.test.changed payload_length=12' \
	    -o match:'payload-data' -e empty "$notifyctl" watch "$topic" 25
	atf_check -s exit:0 -o match:'type=2.*timer_id=99' \
	    -o match:'timestamp_ns=123456789' -o match:'sequence=3' -e empty \
	    "$notifyctl" timer 99 10 3 25
	atf_check -s exit:0 -o match:'type=2.*sequence=1.*timer_id=99' \
	    -e empty "$notifyctl" timer 99 10
	atf_check -s exit:0 \
	    -o inline:'published=1 delivered=2 dropped=3 rejected=4 timer_events=5\n' \
	    -e empty "$notifyctl" stats
}

atf_test_case operation_failures
operation_failures_head()
{
	atf_set "descr" "typed operation failures retain stable exit contracts"
}
operation_failures_body()
{
	notifyctl="$(atf_get_srcdir)/notifyctl_success_bin"
	topic=org.5bsd.test.changed
	for operation in publish state-get state-set stats; do
		case "$operation" in
		publish) arguments="publish $topic payload" ;;
		state-get) arguments="state-get $topic" ;;
		state-set) arguments="state-set $topic 42" ;;
		stats) arguments=stats ;;
		esac
		atf_check -s exit:69 -e match:'Input/output error' \
		    -e match:'client-closed' env CMP_TEST_FAIL="$operation" \
		    CMP_TEST_TRACE_CLOSE=1 "$notifyctl" $arguments
	done
	atf_check -s exit:69 -e match:'subscribe.*Input/output error' \
	    -e match:'client-closed' env CMP_TEST_FAIL=subscribe \
	    CMP_TEST_TRACE_CLOSE=1 "$notifyctl" watch "$topic" 25
	atf_check -s exit:69 -e match:'receive.*Input/output error' \
	    -e match:'unsubscribed' -e match:'client-closed' \
	    env CMP_TEST_FAIL=next CMP_TEST_TRACE_UNSUBSCRIBE=1 \
	    CMP_TEST_TRACE_CLOSE=1 "$notifyctl" watch "$topic" 25
	atf_check -s exit:69 -e match:'unsubscribe.*Input/output error' \
	    -e match:'client-closed' env CMP_TEST_FAIL=unsubscribe \
	    CMP_TEST_TRACE_CLOSE=1 "$notifyctl" watch "$topic" 25
	atf_check -s exit:69 -e match:'timer-add.*Input/output error' \
	    -e match:'client-closed' env CMP_TEST_FAIL=timer-add \
	    CMP_TEST_TRACE_CLOSE=1 "$notifyctl" timer 99 10 3 25
	atf_check -s exit:69 -e match:'receive timer.*Input/output error' \
	    -e match:'timer-canceled' -e match:'client-closed' \
	    env CMP_TEST_FAIL=next CMP_TEST_TRACE_TIMER_CANCEL=1 \
	    CMP_TEST_TRACE_CLOSE=1 "$notifyctl" timer 99 10 3 25
	atf_check -s exit:75 -e match:'receive timer.*timed out' \
	    -e match:'timer-canceled' -e match:'client-closed' \
	    env CMP_TEST_TIMEOUT=1 CMP_TEST_TRACE_TIMER_CANCEL=1 \
	    CMP_TEST_TRACE_CLOSE=1 "$notifyctl" timer 99 10 3 25
	atf_check -s exit:76 -e match:'receive timer.*Protocol error' \
	    -e match:'timer-canceled' -e match:'client-closed' \
	    env CMP_TEST_BAD_TIMER_EVENT=1 CMP_TEST_TRACE_TIMER_CANCEL=1 \
	    CMP_TEST_TRACE_CLOSE=1 "$notifyctl" timer 99 10 3 25
	atf_check -s exit:69 -o match:'timer_id=99' \
	    -e match:'timer-cancel.*Input/output error' \
	    -e match:'client-closed' env CMP_TEST_FAIL=timer-cancel \
	    CMP_TEST_TRACE_CLOSE=1 "$notifyctl" timer 99 10 3 25
}
unavailable_body()
{
	notifyctl="$(atf_get_srcdir)/notifyctl_test_bin"
	atf_check -s exit:69 -e match:'open system.Notify' "$notifyctl" stats
	for command in 'publish org.5bsd.test.changed value' \
	    'state-get org.5bsd.test.changed' \
	    'state-set org.5bsd.test.changed 18446744073709551615' \
	    'timer 99 10 3 25' \
	    'watch org.5bsd.test.changed 1'; do
		atf_check -s exit:69 -e match:'open system.Notify' \
		    "$notifyctl" $command
	done
}

atf_init_test_cases()
{
	atf_add_test_case configtest
	atf_add_test_case config_errors
	atf_add_test_case arguments
	atf_add_test_case payload_limit
	atf_add_test_case unavailable
	atf_add_test_case successful_commands
	atf_add_test_case operation_failures
}
