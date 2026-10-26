#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# CLI tests for bsdinstruments that need no DTrace privileges:
# profile loading/shadowing, rendering (params, predicates, stacks,
# duration), and the list/generate surfaces.
#

make_profile()
{
	# $1 = directory, $2 = name
	mkdir -p "$1"
	cat > "$1/$2.d" <<'EOF'
/*
 * Test profile: counts ${what} syscalls.
 */
syscall::${what}:entry
/* @bsdinstruments-predicate */
{
	printf("%s[%d]: fired\n", execname, pid);
	/* @bsdinstruments-stack */
	/* @bsdinstruments-ustack */
	@calls[execname, pid] = count();
}
EOF
}

make_predicate_and_profile()
{
	mkdir -p "$1"
	cat > "$1/$2.d" <<'EOF'
/*
 * Predicate-and test profile.
 */
syscall:::entry
/errno != 0 /* @bsdinstruments-predicate-and */ /
{
	printf("%d\n", errno);
}
EOF
}

atf_test_case list_basic
list_basic_head()
{
	atf_set descr "list finds user profiles and reports origin"
}
list_basic_body()
{
	export HOME="$(pwd)/home"
	make_profile "$HOME/.bsdinstruments/profiles" test-trace
	atf_check -o match:"test-trace" -o match:"user" \
	    -o match:"Test profile: counts" bsdinstruments list
}

atf_test_case list_json
list_json_head()
{
	atf_set descr "list --json emits one JSONL record per profile"
}
list_json_body()
{
	export HOME="$(pwd)/home"
	make_profile "$HOME/.bsdinstruments/profiles" test-trace
	atf_check -o save:out.json bsdinstruments list --json
	atf_check -o match:'"name":"test-trace"' cat out.json
	atf_check -o match:'"origin":"user"' cat out.json
}

atf_test_case generate_render
generate_render_head()
{
	atf_set descr "generate applies params, filters, stacks, duration"
}
generate_render_body()
{
	export HOME="$(pwd)/home"
	make_profile "$HOME/.bsdinstruments/profiles" test-trace
	atf_check -o save:out.d bsdinstruments generate test-trace \
	    --param what=open --execname nginx --pid 42 \
	    --with-stack --with-ustack --duration 2.5
	atf_check -o match:'syscall::open:entry' cat out.d
	atf_check -o match:'/pid == 42 && execname == "nginx"/' cat out.d
	atf_check -o match:'stack\(\);' cat out.d
	atf_check -o match:'__BSDINSTRUMENTS_USTACK__' cat out.d
	atf_check -o match:'tick-2500000000ns \{ exit\(0\); \}' cat out.d
	# Markers must be gone from the rendered output.
	atf_check -s exit:1 grep -q '@bsdinstruments-' out.d
}

atf_test_case generate_no_filters
generate_no_filters_head()
{
	atf_set descr "without filter flags the predicate marker vanishes"
}
generate_no_filters_body()
{
	export HOME="$(pwd)/home"
	make_profile "$HOME/.bsdinstruments/profiles" test-trace
	atf_check -o save:out.d bsdinstruments generate test-trace \
	    --param what=read
	atf_check -s exit:1 grep -q '@bsdinstruments-predicate' out.d
	atf_check -s exit:1 grep -q 'stack();' out.d
	atf_check -s exit:1 grep -q 'tick-' out.d
}

atf_test_case generate_predicate_and
generate_predicate_and_head()
{
	atf_set descr "predicate-and marker composes into existing predicate"
}
generate_predicate_and_body()
{
	export HOME="$(pwd)/home"
	make_predicate_and_profile "$HOME/.bsdinstruments/profiles" errno-t
	atf_check -o save:out.d bsdinstruments generate errno-t --uid 80
	atf_check -o match:'errno != 0  && uid == 80 /' cat out.d
}

atf_test_case generate_missing_param
generate_missing_param_head()
{
	atf_set descr "an unsatisfied \${param} is a hard error"
}
generate_missing_param_body()
{
	export HOME="$(pwd)/home"
	make_profile "$HOME/.bsdinstruments/profiles" test-trace
	atf_check -s exit:1 -e match:"requires --param what" \
	    bsdinstruments generate test-trace
}

atf_test_case generate_explicit_file
generate_explicit_file_head()
{
	atf_set descr "-f renders an explicit .d file, bypassing the catalog"
}
generate_explicit_file_body()
{
	make_profile "$(pwd)/x" solo
	atf_check -o match:'syscall::close:entry' \
	    bsdinstruments generate -f "$(pwd)/x/solo.d" --param what=close
}

atf_test_case shadowing_warning
shadowing_warning_head()
{
	atf_set descr "user profile shadows a lower-precedence one with warning"
}
shadowing_warning_body()
{
	[ -d /usr/share/bsdinstruments/profiles ] || \
	    atf_skip "base profile catalog not installed"
	name=$(ls /usr/share/bsdinstruments/profiles | head -1 | sed 's/\.d$//')
	[ -n "$name" ] || atf_skip "base profile catalog empty"
	export HOME="$(pwd)/home"
	make_profile "$HOME/.bsdinstruments/profiles" "$name"
	atf_check -o ignore -e match:"shadows" bsdinstruments list
}

atf_test_case watch_conflicting_args
watch_conflicting_args_head()
{
	atf_set descr "watch rejects bad argument combinations"
}

atf_test_case profiles_compile
profiles_compile_head()
{
	atf_set descr "profiles with optional providers compile with zdefs"
	atf_set require.progs dtrace
	atf_set require.user root
}
profiles_compile_body()
{
	profiles="capability-services component-ipc shmring-traffic"
	profiles="${profiles} loader-libraries loader-summary script-exec image-verification"
	profiles="${profiles} bsdlog-performance biosnoop mac-socket"
	profiles="${profiles} sctp-state-change sctp tcplife"
	for profile in $profiles; do
		path="/usr/share/bsdinstruments/profiles/$profile.d"
		[ -f "$path" ] || atf_fail "missing installed profile: $path"
		atf_check -s exit:0 -o empty -e empty \
		    dtrace -Z -e -s "$path"
	done
}
watch_conflicting_args_body()
{
	atf_check -s exit:2 -e match:"profile name or -f" \
	    bsdinstruments watch
	atf_check -s exit:2 -e match:"not both" \
	    bsdinstruments watch foo -f bar.d
	atf_check -s exit:2 -e match:"collapsed requires" \
	    bsdinstruments watch foo --format collapsed
	atf_check -s exit:2 -e match:"key=value" \
	    bsdinstruments watch foo --param broken
}

atf_test_case pf_profiles_compile
pf_profiles_compile_head()
{
	atf_set descr "pf profiles and pf-observe compile against the live pf provider"
	atf_set require.progs dtrace
	atf_set require.user root
}
pf_profiles_compile_body()
{
	kldstat -q -m pf || atf_skip "pf is not loaded"
	for profile in pf-audit pf-drops pf-frags pf-latency \
	    pf-limiter-decisions pf-nat pf-pfsync pf-queues pf-rules \
	    pf-states pf-table-cookie-events pf-tables \
	    pfsync-recovery-events; do
		path="/usr/share/bsdinstruments/profiles/$profile.d"
		[ -f "$path" ] || atf_fail "missing installed profile: $path"
		# No -Z: every pf probe named by the profile must exist.
		atf_check -s exit:0 -o empty -e empty dtrace -e -s "$path"
	done
	atf_check -s exit:0 -o empty -e empty \
	    dtrace -e -s /usr/share/dtrace/pf-observe
}

atf_test_case capability_services_live_probes
capability_services_live_probes_head()
{
	atf_set descr "capability-services traces no retired probes"
}
capability_services_live_probes_body()
{
	# profiles_compile uses -Z, which accepts descriptions no provider
	# defines, so a clause for a retired probe would compile silently.
	# The auth agent (BSDAuth) and session-mint anointments were retired
	# on 2026-10-05; switchboard keeps mint-anoint only as a declaration,
	# and the crypto/bsdnamespace providers fire reclaim-pass/reclaim_pass,
	# never a bare "reclaim".
	path="/usr/share/bsdinstruments/profiles/capability-services.d"
	[ -f "$path" ] || atf_fail "missing installed profile: $path"
	atf_check -s exit:1 -o empty grep -E \
	    '^(authagent\*|service_ambient\*:::elevate-|switchboard\*:::mint-|(crypto|bsdnamespace)\*:::reclaim$)' \
	    "$path"
	for probe in 'service_ambient*:::reg-result' \
	    'switchboard*:::anoint-allow' 'switchboard*:::anoint-deny' \
	    'bsdsysctl*:::request-done' 'bsdnotify*:::session-admit'; do
		atf_check -s exit:0 -o ignore grep -Fx "$probe" "$path"
	done
}

atf_test_case broker_no_fallback
broker_no_fallback_head()
{
    atf_set descr 'Explicit BSDTrace mode never falls back to ambient DTrace access'
    atf_set require.progs 'cc bsdinstruments'
}
broker_no_fallback_body()
{
    cat > broker.c <<'SRC'
#include <dtrace.h>
#include <errno.h>
#include <stdio.h>
dtrace_hdl_t *tracecmp_dtrace_open(int flags, int *error)
{
    (void)flags;
    fputs("BROKER_REQUEST_DENIED\n", stderr);
    *error = EACCES;
    return NULL;
}
dtrace_hdl_t *dtrace_open(int version, int flags, int *error)
{
    (void)version; (void)flags;
    fputs("AMBIENT_DEVICE_ATTEMPT\n", stderr);
    *error = EIO;
    return NULL;
}
SRC
    atf_check -s exit:0 -o empty -e empty cc -Wall -Wextra -Werror -shared -fPIC broker.c -o broker.so
    printf 'dtrace:::BEGIN { exit(0); }\n' > profile.d
    atf_check -s exit:1 -o empty -e save:probes-error env LD_PRELOAD="$PWD/broker.so" \
        bsdinstruments probes --broker
    atf_check -s exit:1 -o empty -e save:watch-error env LD_PRELOAD="$PWD/broker.so" \
        bsdinstruments watch --broker -f profile.d
    for output in probes-error watch-error; do
        atf_check -s exit:0 -o ignore grep -F BROKER_REQUEST_DENIED "$output"
        atf_check -s exit:0 -o ignore grep -F 'BSDTrace delegation failed' "$output"
        atf_check -s exit:1 -o empty grep -F AMBIENT_DEVICE_ATTEMPT "$output"
    done
    atf_check -s exit:2 -o empty -e match:usage \
        bsdinstruments generate --broker -f profile.d
    # Local mode remains explicit and does not unexpectedly request a broker.
    atf_check -s exit:1 -o empty -e save:local-error env LD_PRELOAD="$PWD/broker.so" \
        bsdinstruments probes
    atf_check -s exit:0 -o ignore grep -F AMBIENT_DEVICE_ATTEMPT local-error
    atf_check -s exit:1 -o empty grep -F BROKER_REQUEST_DENIED local-error
}

# ------------------------------------------------------------------
# Mocked libdtrace runs.  mockdtrace.c is a scripted libdtrace (see
# its header); it is preloaded into the installed binary, or already
# linked in when $BI_MOCK_LINKED is set (the coverage harness).

mock_setup()
{
	if [ -z "${BI_MOCK_LINKED}" ]; then
		[ -f /usr/include/dtrace.h ] || atf_skip "dtrace.h not installed"
		atf_check -s exit:0 -o empty -e empty cc -shared -fPIC -w \
		    -o mockdtrace.so "$(atf_get_srcdir)/mockdtrace.c"
		export LD_PRELOAD="$PWD/mockdtrace.so"
	fi
	export BI_MOCK="$PWD/script"
	export BI_MOCK_LOG="$PWD/mock.log"
	: > script
	export HOME="$PWD/home"
	mkdir -p "$HOME/.bsdinstruments/profiles"
	cat > "$HOME/.bsdinstruments/profiles/mock-prof.d" <<'EOF'
/*
 * Mock profile.
 */
syscall::read:entry
/* @bsdinstruments-predicate */
{
	printf("%s[%d]: read\n", execname, pid);
	/* @bsdinstruments-stack */
	@reads[execname] = count();
}
EOF
}

validator()
{
	v=${OTLP_VALIDATE:-/usr/tests/lib/libotelexport/otlp_validate}
	[ -x "$v" ] || atf_skip "otlp_validate not installed"
	echo "$v"
}

collector()
{
	c=${OTLP_COLLECTOR:-/usr/tests/lib/libotelexport/otlp_collector}
	[ -x "$c" ] || atf_skip "otlp_collector not installed"
	echo "$c"
}

# A clock anchor at hrtime 1000 = 2023-11-14T22:13:20Z, then events.
anchored_script()
{
	cat >> script <<'EOF'
chunk 0 1000 1 \037otel.clock\037wall=1700000000000000000\037ts=1000\n
chunk 0 5000 2 nginx[42]: read\n
chunk 0 5000 2               kernel`vn_read+0x10\n
work
chunk 1 9000 2 sshd[7]: read\n
work
agg reads 3
EOF
}

atf_test_case watch_json_probe_time
watch_json_probe_time_head()
{
	atf_set descr "json events carry the probe's wall time and the observed time"
	atf_set require.progs cc
}
watch_json_probe_time_body()
{
	mock_setup
	anchored_script
	atf_check -s exit:0 -o save:out.json -e empty \
	    bsdinstruments watch mock-prof --format json
	atf_check -o match:'"time":"2023-11-14T22:13:20.000Z","observed":"' \
	    -o match:'"body":"nginx\[42\]: read"' \
	    -o match:'"probe":"syscall:freebsd:read:entry"' \
	    -o match:'"stack":\["kernel`vn_read\+0x10"\]' cat out.json
	atf_check -o inline:"2\n" sh -c 'wc -l < out.json | tr -d " "'
	# The clock program is compiled first, then the profile.
	atf_check -o match:'otel.clock' awk '/^compile/ { n++ } n == 1' mock.log
	atf_check -o match:'execname, pid' awk '/^compile/ { n++ } n == 2' \
	    mock.log
	atf_check -o match:'^setopt bufsize=16m' cat mock.log
}

atf_test_case watch_text_output_file
watch_text_output_file_head()
{
	atf_set descr "text output goes to --output, rotated by size, plain (no color)"
	atf_set require.progs cc
}
watch_text_output_file_body()
{
	mock_setup
	cat >> script <<'EOF'
chunk 0 1 1 first line of text output\n
sleep 1100
work
chunk 0 2 1 second line\n
sleep 1100
work
agg reads 3
EOF
	atf_check -s exit:0 -o empty -e empty bsdinstruments watch mock-prof \
	    --output out.txt --rotate-size 10 --rotate-keep 2
	atf_check -o inline:"first line of text output\n" cat out.txt.2
	atf_check -o inline:"second line\n" cat out.txt.1
	atf_check -o match:'reads +3' cat out.txt
	atf_check -s exit:1 grep -q "$(printf '\033')" out.txt
	# The text path never compiles the clock program.
	atf_check -s exit:1 grep -q otel.clock mock.log
	atf_check -o match:'^setopt bufsize=4m' cat mock.log
}

atf_test_case watch_otlpjson_file
watch_otlpjson_file_head()
{
	atf_set descr "otlp-json writes valid OTLP JSON Lines with probe timestamps"
	atf_set require.progs cc
}
watch_otlpjson_file_body()
{
	mock_setup
	anchored_script
	v=$(validator)
	atf_check -s exit:0 -o empty -e empty bsdinstruments watch mock-prof \
	    --format otlp-json --output out.jsonl --rotate-time 1h
	atf_check -o match:'requests=2 logs=2 metrics=1' "$v" out.jsonl
	atf_check -o match:'"timeUnixNano":"1700000000000004000"' \
	    -o match:'"timeUnixNano":"1700000000000008000"' \
	    head -1 out.jsonl
	# To standard output when --output is absent.
	atf_check -s exit:0 -o save:stdout.jsonl -e empty \
	    bsdinstruments watch mock-prof --format otlp-json
	atf_check -o match:'requests=2' "$v" stdout.jsonl
}

atf_test_case watch_collapsed_file
watch_collapsed_file_head()
{
	atf_set descr "collapsed stacks to a file, including stack-only firings"
	atf_set require.progs cc
}
watch_collapsed_file_body()
{
	mock_setup
	cat >> script <<'EOF'
chunk 0 5 1 nginx[1]: x\n
chunk 0 5 1               kernel`a+0x1\n
chunk 1 6 1               kernel`b+0x2\n
work
EOF
	atf_check -s exit:0 -o empty -e empty bsdinstruments watch mock-prof \
	    --format collapsed --with-stack --output folded.txt
	atf_check -o inline:';kernel`b+0x2 1\nnginx;kernel`a+0x1 1\n' \
	    cat folded.txt
}

atf_test_case watch_otel_spool
watch_otel_spool_head()
{
	atf_set descr "otel to an unreachable collector spools; a later run resends"
	atf_set require.progs cc
	atf_set timeout 120
}
watch_otel_spool_body()
{
	mock_setup
	anchored_script
	v=$(validator)
	c=$(collector)
	# Port 9 (discard) on loopback is not listening: refused.
	atf_check -s exit:0 -o empty -e match:'spooled /v1/logs' \
	    bsdinstruments watch mock-prof --format otel \
	    --endpoint http://127.0.0.1:9 --spool spool.jsonl --spool-max 1m
	atf_check -o match:'requests=2 logs=2 metrics=1' "$v" spool.jsonl
	mkdir coll
	"$c" -o coll -n 4 -t 60 &
	cpid=$!
	while [ ! -s coll/port ]; do sleep 0.1; done
	export OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:$(cat coll/port)"
	export OTEL_EXPORTER_OTLP_COMPRESSION=none
	atf_check -s exit:0 -o empty -e match:'resent 2 spooled batches' \
	    bsdinstruments watch mock-prof --format otel --spool spool.jsonl
	wait $cpid
	atf_check -o empty cat spool.jsonl
	for f in coll/*.json; do
		atf_check -o match:'requests=1' "$v" "$f"
	done
	atf_check -o match:'v1/metrics' cat coll/1.path coll/2.path \
	    coll/3.path coll/4.path
}

atf_test_case watch_output_errors
watch_output_errors_head()
{
	atf_set descr "output problems are clear errors, before tracing starts"
	atf_set require.progs cc
	atf_set require.user unprivileged
}
watch_output_errors_body()
{
	mock_setup
	anchored_script
	atf_check -s exit:1 -o empty -e match:'nodir/out.json: open failed' \
	    bsdinstruments watch mock-prof --format json --output nodir/out.json
	# Nothing reached libdtrace.
	atf_check -s exit:0 test ! -e mock.log
	mkdir ro && chmod 555 ro
	atf_check -s exit:1 -o empty -e match:'Permission denied' \
	    bsdinstruments watch mock-prof --format otlp-json --output ro/x
	atf_check -s exit:1 -o empty -e match:'spool .*open failed' \
	    bsdinstruments watch mock-prof --format otel --spool ro/s
	# Disk full while writing (RLIMIT_FSIZE, SIGXFSZ ignored).
	i=0
	while [ $i -lt 40 ]; do
		echo 'chunk 0 5000 2 nginx[42]: a long line to fill the file up\n'
		i=$((i + 1))
	done >> script
	atf_check -s exit:1 -o empty -e match:'File too large' \
	    sh -c 'trap "" XFSZ; ulimit -f 1; exec bsdinstruments watch \
	    mock-prof --format json --output big.json'
}

atf_test_case watch_usage_errors
watch_usage_errors_head()
{
	atf_set descr "watch rejects inconsistent output options"
}
watch_usage_errors_body()
{
	export HOME="$PWD/home"
	atf_check -s exit:2 -e match:'rotation options need --output' \
	    bsdinstruments watch -f x.d --rotate-size 1m
	atf_check -s exit:2 -e match:'otlp-json to write OTLP to a file' \
	    bsdinstruments watch -f x.d --format otel --output f
	atf_check -s exit:2 -e match:'apply to --format otel only' \
	    bsdinstruments watch -f x.d --spool s
	atf_check -s exit:2 -e match:'apply to --format otel only' \
	    bsdinstruments watch -f x.d --format json --endpoint http://h
	atf_check -s exit:2 -e match:'needs --spool' \
	    bsdinstruments watch -f x.d --format otel --spool-max 1m
	atf_check -s exit:2 -e match:'positive number' \
	    bsdinstruments watch -f x.d --output f --rotate-size 0
	atf_check -s exit:2 -e match:'positive number' \
	    bsdinstruments watch -f x.d --output f --rotate-size 5x
	atf_check -s exit:2 -e match:'positive number' \
	    bsdinstruments watch -f x.d --output f --rotate-size 99999999999g
	atf_check -s exit:2 -e match:'positive number' \
	    bsdinstruments watch -f x.d --output f --rotate-time 1mm
	atf_check -s exit:2 -e match:'positive number' \
	    bsdinstruments watch -f x.d --output f --rotate-time -5
	atf_check -s exit:2 -e match:'positive number' \
	    bsdinstruments watch -f x.d --output f --rotate-time 99999999999999999999
	atf_check -s exit:2 -e match:'between 1 and 999' \
	    bsdinstruments watch -f x.d --output f --rotate-keep 1000
	atf_check -s exit:2 -e match:'needs a file name' \
	    bsdinstruments watch -f x.d --output ''
	atf_check -s exit:2 -e match:'needs a value' \
	    bsdinstruments watch -f x.d --format otel --endpoint ''
	atf_check -s exit:2 -e match:'otlp-json, or collapsed' \
	    bsdinstruments watch -f x.d --format xml
	atf_check -s exit:2 -e match:usage \
	    bsdinstruments generate -f x.d --output f
	atf_check -s exit:2 -e match:usage \
	    bsdinstruments generate -f x.d --rotate-time 1s
	atf_check -s exit:2 -e match:usage \
	    bsdinstruments generate -f x.d --rotate-keep 2
	atf_check -s exit:2 -e match:usage \
	    bsdinstruments generate -f x.d --spool-max 1k
}

atf_test_case watch_libdtrace_failures
watch_libdtrace_failures_head()
{
	atf_set descr "every libdtrace failure point exits 1 with a message"
	atf_set require.progs cc
}
watch_libdtrace_failures_body()
{
	mock_setup
	for f in open setopt:bufsize setopt:aggsize setopt:switchrate \
	    setopt:quiet handle_drop handle_buffered compile:1 compile:2 \
	    exec go; do
		echo "fail $f" > script
		atf_check -s exit:1 -o ignore -e not-empty \
		    bsdinstruments watch mock-prof --format json
	done
	echo "fail compile:1" > script
	atf_check -s exit:1 -o empty -e match:"profile 'mock-prof' failed" \
	    bsdinstruments watch mock-prof
	echo "fail go" > script
	atf_check -s exit:1 -o empty -e match:'failed to start trace' \
	    bsdinstruments watch mock-prof
	echo "fail open" > script
	atf_check -s exit:1 -o empty -e match:'local DTrace open failed' \
	    bsdinstruments watch mock-prof --format otlp-json
	# work() failure, and aggregation failures, still exit cleanly.
	printf 'fail work\n' > script
	atf_check -s exit:0 -o ignore -e match:'work\(\) failed' \
	    bsdinstruments watch mock-prof --format json
	: > script
	anchored_script
	printf 'fail snap\n' >> script
	atf_check -s exit:0 -o ignore -e match:'snapshot failed' \
	    bsdinstruments watch mock-prof
	atf_check -s exit:0 -o ignore -e match:'snapshot failed' \
	    bsdinstruments watch mock-prof --format json
	: > script
	anchored_script
	printf 'fail aggprint\nfail walk\n' >> script
	atf_check -s exit:0 -o ignore -e match:'print failed' \
	    bsdinstruments watch mock-prof
	atf_check -s exit:0 -o ignore -e match:'walk failed' \
	    bsdinstruments watch mock-prof --format json
}

atf_test_case watch_drops_and_signals
watch_drops_and_signals_head()
{
	atf_set descr "drops are reported; SIGINT stops and the last pass drains"
	atf_set require.progs cc
}
watch_drops_and_signals_body()
{
	mock_setup
	v=$(validator)
	cat > script <<'EOF'
chunk 0 1 1 a[1]: x\n
drop 5
work
signal
work
chunk 0 2 1 drained[2]: y\n
work
chunk 0 3 1 unread[3]: z\n
work
EOF
	atf_check -s exit:0 -o save:out.jsonl -e match:'dropped 5 record' \
	    bsdinstruments watch mock-prof --format otlp-json
	# The loop stops at the signal; the post-stop pass still drains
	# what the kernel buffered, as dtrace(1) does.
	atf_check -o match:'requests=1 logs=2' "$v" out.jsonl
	atf_check -s exit:0 -o ignore grep drained out.jsonl
	atf_check -s exit:1 grep -q unread out.jsonl
	atf_check -s exit:0 -o ignore -e match:'dropped 5 record' \
	    bsdinstruments watch mock-prof
}

atf_test_case probes_mock
probes_mock_head()
{
	atf_set descr "probes lists, filters, and reports failures"
	atf_set require.progs cc
}
probes_mock_body()
{
	mock_setup
	cat > script <<'EOF'
probe syscall:freebsd:read:entry
probe syscall:freebsd:write:entry
probe fbt:kernel:vn_open:entry
EOF
	atf_check -s exit:0 -o match:'fbt:kernel:vn_open:entry' \
	    -e match:'3 probes' bsdinstruments probes
	atf_check -s exit:0 -o inline:'syscall:freebsd:write:entry\n' \
	    -e match:'1 probe$' bsdinstruments probes --regex 'wr.te'
	atf_check -s exit:0 -o match:'"fullName":"syscall:freebsd:read:entry"' \
	    -o match:'"id":1,' -e empty bsdinstruments probes --json \
	    --provider syscall --pid 1
	atf_check -s exit:2 -e match:'invalid --regex' \
	    bsdinstruments probes --regex '('
	atf_check -s exit:2 -e match:usage bsdinstruments probes extra
	echo 'fail str2desc' >> script
	atf_check -s exit:1 -e match:'invalid provider' \
	    bsdinstruments probes --provider x --regex .
	sed -i '' '/fail/d' script
	echo 'fail grab' >> script
	atf_check -s exit:1 -e match:'failed to grab pid 9' \
	    bsdinstruments probes --pid 9
	sed -i '' '/fail/d' script
	echo 'fail iter' >> script
	atf_check -s exit:1 -e match:'listing failed' bsdinstruments probes
	echo 'fail open' >> script
	atf_check -s exit:1 -e match:'local DTrace open failed' \
	    bsdinstruments probes --regex x
}

make_span_profile()
{
	mkdir -p "$1"
	cat > "$1/$2.d" <<'EOF'
/*
 * Span marker test profile.
 */
syscall::read:entry { self->ts = timestamp; }
syscall::read:return
/self->ts/
{
	printf("%s[%d]: read\n", execname, pid);
	/* @bsdinstruments-span(name="read \"x\"", kind=server,
	    start=self->ts, error=errno, int.fd=(int)arg0,
	    str.op=probefunc == "read" ? "r, w" : "(w)",
	    parent=self->p[1], span=self->ts, trace=1, thread=tid,
	    pid=pid, execname=execname, end=timestamp) */
	self->ts = 0;
}
EOF
}

atf_test_case generate_span_markers
generate_span_markers_head()
{
	atf_set descr "span markers render to record printfs, or vanish in text"
}
generate_span_markers_body()
{
	export HOME="$(pwd)/home"
	make_span_profile "$HOME/.bsdinstruments/profiles" spans
	atf_check -o save:text.d bsdinstruments generate spans
	atf_check -s exit:1 grep -q 'otel.span' text.d
	atf_check -s exit:1 grep -q '@bsdinstruments-span' text.d
	atf_check -o save:json.d bsdinstruments generate spans --format json
	atf_check -s exit:1 grep -q '@bsdinstruments-span' json.d
	atf_check -o match:'printf\("\\037otel.span\\037name=%s\\037start=%d\\037end=%d\\037thread=%d\\037pid=%d\\037execname=%s\\037error=%d\\037a.i.fd=%d\\037a.s.op=%s\\037parent=%d\\037span=%d\\037trace=%d\\037kind=server\\n", "read \\"x\\"", \(int64_t\)\(self->ts\), \(int64_t\)\(timestamp\), \(int64_t\)\(tid\), \(int64_t\)\(pid\), execname, \(int64_t\)\(errno\), \(int64_t\)\(\(int\)arg0\), probefunc == "read" \? "r, w" : "\(w\)", \(int64_t\)\(self->p\[1\]\), \(int64_t\)\(self->ts\), \(int64_t\)\(1\)\);' \
	    cat json.d
	# Defaults: end=timestamp, thread=tid, pid, execname.
	cat > min.d <<'EOF'
BEGIN { /* @bsdinstruments-span(name="m", start=1) */ }
EOF
	atf_check -o match:'"m", \(int64_t\)\(1\), \(int64_t\)\(timestamp\), \(int64_t\)\(tid\), \(int64_t\)\(pid\), execname\);' \
	    bsdinstruments generate -f min.d --format otlp-json
}

atf_test_case generate_span_marker_errors
generate_span_marker_errors_head()
{
	atf_set descr "malformed span markers are rendering errors"
}
generate_span_marker_errors_body()
{
	check_bad()
	{
		printf '%s\n' "$1" > bad.d
		atf_check -s exit:1 -o empty -e match:"$2" \
		    bsdinstruments generate -f bad.d --format json
	}
	check_bad '/* @bsdinstruments-span(start=1) */' 'needs name= and start='
	check_bad '/* @bsdinstruments-span(name="x") */' 'needs name= and start='
	check_bad '/* @bsdinstruments-span(name="x", start=1, bogus=2) */' \
	    "unknown span marker key 'bogus'"
	check_bad '/* @bsdinstruments-span(name="x", start=1, kind=rpc) */' \
	    'span kind must be'
	check_bad '/* @bsdinstruments-span(name="x", start) */' \
	    "argument 'start' is not key=value"
	check_bad '/* @bsdinstruments-span(name="x", start=) */' \
	    "key 'start' has no value"
	check_bad '/* @bsdinstruments-span(name="x", start=1 */' \
	    'malformed span marker'
	check_bad '/* @bsdinstruments-span(name="x, start=1) */' \
	    'malformed span marker'
	check_bad '/* @bsdinstruments-span(name="x", start=1) x */' \
	    'malformed span marker'
	check_bad '/* @bsdinstruments-span(name=f(a, start=1) */' \
	    'malformed span marker'
	many='name="x", start=1'
	i=0
	while [ $i -lt 40 ]; do many="$many, int.k$i=$i"; i=$((i + 1)); done
	check_bad "/* @bsdinstruments-span($many) */" 'too many span marker'
	# Text rendering ignores the arguments but still needs the shape.
	printf '%s\n' '/* @bsdinstruments-span(name="x", start=1 */' > bad.d
	atf_check -s exit:1 -o empty -e match:'malformed span marker' \
	    bsdinstruments generate -f bad.d
	printf '%s\n' "/* @bsdinstruments-span(name='x', start=a[1]) */" > ok.d
	atf_check -o match:"'x'" bsdinstruments generate -f ok.d --format json
}

atf_test_case watch_spans
watch_spans_head()
{
	atf_set descr "span records export as OTLP spans (file and json) with parent links"
	atf_set require.progs cc
}
watch_spans_body()
{
	mock_setup
	v=$(validator)
	cat >> script <<'EOF'
chunk 0 1000 1 \037otel.clock\037wall=1700000000000000000\037ts=1000\n
chunk 1 3500 9 \037otel.span\037name=block io\037start=3000\037end=3500\037thread=77\037parent=2000\037pid=5\037execname=sh\037error=5\037a.i.disk.io.bytes=4096\n
chunk 0 9000 8 \037otel.span\037name=read\037start=2000\037end=9000\037thread=77\037kind=server\037pid=5\037execname=sh\n
chunk 0 9000 8 sh[5]: read\n
work
EOF
	atf_check -s exit:0 -o empty -e empty bsdinstruments watch mock-prof \
	    --format otlp-json --output out.jsonl
	atf_check -o match:'requests=2 logs=1 metrics=0 datapoints=0 spans=2' \
	    "$v" out.jsonl
	atf_check -o match:'"startTimeUnixNano":"1700000000000002000","endTimeUnixNano":"1700000000000002500"' \
	    -o match:'"status":\{"code":2,"message":"error 5"\}' \
	    -o match:'"parentSpanId":"[0-9a-f]{16}"' \
	    -o match:'"key":"disk.io.bytes","value":\{"intValue":"4096"\}' \
	    grep resourceSpans out.jsonl
	# The child's parentSpanId is the parent's spanId.
	parent=$(grep -o '"parentSpanId":"[0-9a-f]*"' out.jsonl | cut -d'"' -f4)
	atf_check -o match:"\"spanId\":\"$parent\",\"name\":\"read\"" \
	    cat out.jsonl
	atf_check -s exit:0 -o save:out.json -e empty \
	    bsdinstruments watch mock-prof --format json
	atf_check -o match:'"type":"span".*"name":"block io".*"duration_ns":500,"kind":"internal","status":"error"' \
	    cat out.json
	atf_check -o match:'"kind":"server","status":"unset"' cat out.json
}

atf_init_test_cases()
{
	atf_add_test_case list_basic
	atf_add_test_case list_json
	atf_add_test_case generate_render
	atf_add_test_case generate_no_filters
	atf_add_test_case generate_predicate_and
	atf_add_test_case generate_missing_param
	atf_add_test_case generate_explicit_file
	atf_add_test_case shadowing_warning
	atf_add_test_case watch_conflicting_args
	atf_add_test_case broker_no_fallback
	atf_add_test_case profiles_compile
	atf_add_test_case pf_profiles_compile
	atf_add_test_case capability_services_live_probes
	atf_add_test_case watch_json_probe_time
	atf_add_test_case watch_text_output_file
	atf_add_test_case watch_otlpjson_file
	atf_add_test_case watch_collapsed_file
	atf_add_test_case watch_otel_spool
	atf_add_test_case watch_output_errors
	atf_add_test_case watch_usage_errors
	atf_add_test_case watch_libdtrace_failures
	atf_add_test_case watch_drops_and_signals
	atf_add_test_case probes_mock
	atf_add_test_case generate_span_markers
	atf_add_test_case generate_span_marker_errors
	atf_add_test_case watch_spans
}
