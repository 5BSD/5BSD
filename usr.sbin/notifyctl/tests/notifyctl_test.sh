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
	printf '%s\n' 'default = [];' > bad.conf
	atf_check -s exit:65 -e match:bad.conf "$notifyctl" configtest bad.conf
	printf '%s\n' 'default { publish = [ "*.x" ]; }' > bad.conf
	atf_check -s exit:65 -e match:bad.conf "$notifyctl" configtest bad.conf
	printf '%s\n' 'system_default { unknown = true; }' > bad.conf
	atf_check -s exit:65 -e match:bad.conf "$notifyctl" configtest bad.conf
}
configtest_body()
{
	notifyctl="$(atf_get_srcdir)/notifyctl_test_bin"
	cp "$(atf_get_srcdir)/valid.conf" valid.conf
	cp "$(atf_get_srcdir)/invalid.conf" invalid.conf
	atf_check -s exit:0 \
	    -o match:'valid \(1 client, default builtin, system_default builtin\)' \
	    "$notifyctl" configtest valid.conf
	printf '%s\n' 'default { publish = [ "user.*" ]; }' \
	    'system_default { publish = [ "*" ]; timers = true; }' > tiers.conf
	atf_check -s exit:0 \
	    -o match:'valid \(0 clients, default explicit, system_default explicit\)' \
	    "$notifyctl" configtest tiers.conf
	: > empty.conf
	atf_check -s exit:0 -o match:'valid \(0 clients, default builtin' \
	    "$notifyctl" configtest empty.conf
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
	    'timer' 'timer 1' 'timer 1 2 3 4 5' 'stats extra' unknown \
	    '-s' '-x stats' '-s configtest' '-s configtest valid.conf' \
	    '-s stats extra' '-s publish' 'stats -s'; do
		atf_check -s exit:64 -e match:'usage: notifyctl' \
		    env -u SERVICE_LOOKUP_FD "$notifyctl" $command 3>&-
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

atf_test_case tier_option
tier_option_head()
{
	atf_set "descr" "-s opens the gated system.Notify.System tier; default is the open tier"
}
tier_option_body()
{
	notifyctl="$(atf_get_srcdir)/notifyctl_success_bin"
	topic=org.5bsd.test.changed
	atf_check -s exit:0 -o empty -e inline:'client-open system.Notify\n' \
	    env CMP_TEST_TRACE_OPEN=1 "$notifyctl" publish "$topic" payload
	atf_check -s exit:0 -o empty \
	    -e inline:'client-open system.Notify.System\n' \
	    env CMP_TEST_TRACE_OPEN=1 "$notifyctl" -s publish "$topic" payload
	atf_check -s exit:0 -o inline:'epoch=7 generation=8 state=42\n' \
	    -e inline:'client-open system.Notify.System\n' \
	    env CMP_TEST_TRACE_OPEN=1 "$notifyctl" -s state-get "$topic"
	atf_check -s exit:0 -o empty \
	    -e inline:'client-open system.Notify.System\n' \
	    env CMP_TEST_TRACE_OPEN=1 "$notifyctl" -s state-set "$topic" 42
	atf_check -s exit:0 -o match:'payload-data' \
	    -e inline:'client-open system.Notify.System\n' \
	    env CMP_TEST_TRACE_OPEN=1 "$notifyctl" -s watch "$topic" 25
	atf_check -s exit:0 -o match:'type=2.*timer_id=99' \
	    -e inline:'client-open system.Notify.System\n' \
	    env CMP_TEST_TRACE_OPEN=1 "$notifyctl" -s timer 99 10
	atf_check -s exit:0 -o match:'published=1' \
	    -e inline:'client-open system.Notify.System\n' \
	    env CMP_TEST_TRACE_OPEN=1 "$notifyctl" -s stats
	# -s changes only the endpoint; every failure contract is unchanged.
	atf_check -s exit:69 -e match:'publish.*Input/output error' \
	    env CMP_TEST_FAIL=publish "$notifyctl" -s publish "$topic" payload
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
	atf_check -s exit:69 -e match:'open system.Notify:' \
	    env -u SERVICE_LOOKUP_FD "$notifyctl" stats 3>&-
	atf_check -s exit:69 -e match:'open system.Notify.System:' \
	    env -u SERVICE_LOOKUP_FD "$notifyctl" -s stats 3>&-
	atf_check -s exit:69 -e match:'open system.Notify.System:' \
	    env -u SERVICE_LOOKUP_FD "$notifyctl" -s publish user.x v 3>&-
	for command in 'publish org.5bsd.test.changed value' \
	    'state-get org.5bsd.test.changed' \
	    'state-set org.5bsd.test.changed 18446744073709551615' \
	    'timer 99 10 3 25' \
	    'watch org.5bsd.test.changed 1'; do
		atf_check -s exit:69 -e match:'open system.Notify' \
		    env -u SERVICE_LOOKUP_FD "$notifyctl" $command 3>&-
	done
}

atf_test_case tier_option_usage
tier_option_usage_head()
{
	atf_set "descr" "-s is parsed before the command; usage errors never open a client"
}
tier_option_usage_body()
{
	notifyctl="$(atf_get_srcdir)/notifyctl_test_bin"
	success="$(atf_get_srcdir)/notifyctl_success_bin"
	cp "$(atf_get_srcdir)/valid.conf" valid.conf
	topic=org.5bsd.test.changed
	# -s with an unknown or missing subcommand is a usage error, exit 64,
	# and it must fail before any endpoint is looked up (no lookup fd here).
	for command in '-s' '-s unknown' '-s UNKNOWN' '-s Stats' '-s -x stats' \
	    '-s publish' '-s state-get' '-s state-set a' '-s watch' \
	    '-s timer' '-s timer 1' '-s stats extra' '-s watch a b c' \
	    '-x' '-x -s stats' '-sx stats' '-s -' '- stats' '-s -- -s stats'; do
		atf_check -s exit:64 -o empty -e match:'usage: notifyctl' \
		    env -u SERVICE_LOOKUP_FD "$notifyctl" $command 3>&-
	done
	# configtest never connects, so -s is meaningless there: usage.
	atf_check -s exit:64 -o empty -e match:'usage: notifyctl' \
	    "$notifyctl" -s configtest
	atf_check -s exit:64 -o empty -e match:'usage: notifyctl' \
	    "$notifyctl" -s configtest valid.conf
	atf_check -s exit:64 -o empty -e match:'usage: notifyctl' \
	    "$notifyctl" -s configtest missing.conf
	# and the usage exit happens before the file is even opened
	atf_check -s exit:64 -o empty -e not-match:missing.conf \
	    "$notifyctl" -s configtest missing.conf
	# without -s configtest still works: the flag, not the file, is at fault
	atf_check -s exit:0 -o match:'valid \(1 client' \
	    "$notifyctl" configtest valid.conf
	# a usage error never opens a client, even when a broker is reachable
	for command in '-s' '-s unknown' '-s configtest' \
	    '-s configtest valid.conf' '-s stats extra' '-s -- -s stats'; do
		atf_check -s exit:64 -o empty -e not-match:'client-open' \
		    -e match:'usage: notifyctl' \
		    env CMP_TEST_TRACE_OPEN=1 "$success" $command
	done
	# the flag may be repeated or bundled; it is still the system tier
	atf_check -s exit:0 -o match:'published=1' \
	    -e inline:'client-open system.Notify.System\n' \
	    env CMP_TEST_TRACE_OPEN=1 "$success" -s -s stats
	atf_check -s exit:0 -o match:'published=1' \
	    -e inline:'client-open system.Notify.System\n' \
	    env CMP_TEST_TRACE_OPEN=1 "$success" -ss stats
	# the flag only counts before the command word (getopt stops there)
	atf_check -s exit:64 -o empty -e match:'usage: notifyctl' \
	    env CMP_TEST_TRACE_OPEN=1 "$success" stats -s
	atf_check -s exit:64 -o empty -e match:'usage: notifyctl' \
	    env CMP_TEST_TRACE_OPEN=1 "$success" publish -s "$topic" payload
}

atf_test_case double_dash
double_dash_head()
{
	atf_set "descr" "-- ends option parsing; the command word follows it"
}
double_dash_body()
{
	notifyctl="$(atf_get_srcdir)/notifyctl_test_bin"
	success="$(atf_get_srcdir)/notifyctl_success_bin"
	cp "$(atf_get_srcdir)/valid.conf" valid.conf
	topic=org.5bsd.test.changed
	# "-- command" is the command on the open tier
	atf_check -s exit:0 -o match:'published=1' \
	    -e inline:'client-open system.Notify\n' \
	    env CMP_TEST_TRACE_OPEN=1 "$success" -- stats
	atf_check -s exit:0 -o empty -e inline:'client-open system.Notify\n' \
	    env CMP_TEST_TRACE_OPEN=1 "$success" -- publish "$topic" payload
	# "-s -- command" is the command on the system tier
	atf_check -s exit:0 -o match:'published=1' \
	    -e inline:'client-open system.Notify.System\n' \
	    env CMP_TEST_TRACE_OPEN=1 "$success" -s -- stats
	atf_check -s exit:0 -o inline:'epoch=7 generation=8 state=42\n' \
	    -e inline:'client-open system.Notify.System\n' \
	    env CMP_TEST_TRACE_OPEN=1 "$success" -s -- state-get "$topic"
	# "--" alone, or "-- -s": nothing (or a non-command) follows: usage
	atf_check -s exit:64 -o empty -e match:'usage: notifyctl' \
	    env CMP_TEST_TRACE_OPEN=1 "$success" --
	atf_check -s exit:64 -o empty -e match:'usage: notifyctl' \
	    -e not-match:'client-open' \
	    env CMP_TEST_TRACE_OPEN=1 "$success" -- -s stats
	atf_check -s exit:64 -o empty -e match:'usage: notifyctl' \
	    env CMP_TEST_TRACE_OPEN=1 "$success" -- -- stats
	# "--" after the command word is an ordinary argument
	atf_check -s exit:64 -o empty -e match:'usage: notifyctl' \
	    env CMP_TEST_TRACE_OPEN=1 "$success" stats --
	# ... which for publish means the topic is literally "--": the client
	# is opened and the library refuses the topic; no usage error
	atf_check -s exit:69 -o empty -e match:'publish --' \
	    -e match:'client-open system.Notify' \
	    env CMP_TEST_TRACE_OPEN=1 "$success" publish -- payload
	atf_check -s exit:69 -o empty -e match:'publish --' \
	    -e match:'client-open system.Notify.System' \
	    env CMP_TEST_TRACE_OPEN=1 "$success" -s publish -- payload
	# configtest behind "--" still works and still refuses -s
	atf_check -s exit:0 -o match:'valid \(1 client' \
	    "$notifyctl" -- configtest valid.conf
	atf_check -s exit:64 -o empty -e match:'usage: notifyctl' \
	    "$notifyctl" -s -- configtest valid.conf
	# a payload that looks like an option is fine after the command word
	atf_check -s exit:64 -o empty -e match:'usage: notifyctl' \
	    env CMP_TEST_TRACE_OPEN=1 "$success" -s publish "$topic" -- payload
}

atf_init_test_cases()
{
	atf_add_test_case configtest
	atf_add_test_case config_errors
	atf_add_test_case arguments
	atf_add_test_case payload_limit
	atf_add_test_case unavailable
	atf_add_test_case successful_commands
	atf_add_test_case tier_option
	atf_add_test_case operation_failures
	atf_add_test_case tier_option_usage
	atf_add_test_case double_dash
}
