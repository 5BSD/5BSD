#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# CLI tests for bsdinstruments that need no DTrace privileges:
# profile loading/shadowing, rendering (params, predicates, stacks,
# duration), and the list/generate surfaces.
#

# --format otel reads otel.conf(5); keep the cases independent of the
# system's (otelconf's otel_emitters_test covers the system layer).
export OTELCONF_DEFAULTS= OTELCONF_FILE=
# The loopback collector (otlp_collector) reads OTLP/HTTP JSON; the
# protobuf transports are tested in lib/libotelexport/tests/otlppb_test.
export OTEL_EXPORTER_OTLP_PROTOCOL=http/json

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
	# Built-in otel.conf defaults, but never the system spool.
	echo "spool { directory = \"$PWD/no-spool\"; }" > otel-test.conf
	export OTELCONF_FILE="$PWD/otel-test.conf"
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
	# Two events and the aggregation, as a "type":"metric" line.
	atf_check -o inline:"3\n" sh -c 'wc -l < out.json | tr -d " "'
	atf_check -o match:'^\{"type":"metric",.*"name":"reads","kind":"count","points":\[\{"attributes":\{"[^"]*":"k"\},"value":3\}\]\}$' \
	    tail -1 out.json
	# An aggregation-only trace still exports its aggregation.
	cat > script <<'EOF'
chunk 0 1000 1 \037otel.clock\037wall=1700000000000000000\037ts=1000\n
work
agg reads 5
EOF
	atf_check -s exit:0 -o match:'"type":"metric".*"value":5' -e empty \
	    bsdinstruments watch mock-prof --format json
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
	# --protocol beats OTEL_EXPORTER_OTLP_PROTOCOL; the collector reads JSON.
	export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
	atf_check -s exit:0 -o empty -e match:'resent 2 spooled batches' \
	    bsdinstruments watch mock-prof --format otel --spool spool.jsonl \
	    --protocol http/json
	wait $cpid
	atf_check -o empty cat spool.jsonl
	for f in coll/*.json; do
		atf_check -o match:'requests=1' "$v" "$f"
	done
	atf_check -o match:'v1/metrics' cat coll/1.path coll/2.path \
	    coll/3.path coll/4.path
}

atf_test_case watch_interval
watch_interval_head()
{
	atf_set descr "--interval exports cumulative aggregation snapshots while running"
	atf_set require.progs cc
	atf_set timeout 120
}
watch_interval_body()
{
	mock_setup
	anchored_script
	cat >> script <<'EOF'
sleep 1100
work
sleep 1100
work
done
EOF
	v=$(validator)
	atf_check -s exit:0 -o empty -e empty bsdinstruments watch mock-prof \
	    --format otlp-json --output out.jsonl --interval 1
	# At least two snapshots while running, plus the final one, all
	# starting at the same time (cumulative, never reset).
	atf_check -o match:'metrics=[3-9]' "$v" out.jsonl
	atf_check -o inline:"1\n" -x \
	    "grep -o '\"startTimeUnixNano\":\"[0-9]*\"' out.jsonl | sort -u | wc -l | tr -d ' '"
	# A failing snapshot ends the run with an error.
	echo "fail snap" >> script
	atf_check -s exit:1 -o empty -e match:'aggregation snapshot failed' \
	    bsdinstruments watch mock-prof --format otlp-json \
	    --output out2.jsonl --interval 1
	# An invalid otel.conf stops --format otel before tracing starts.
	echo 'endpoint = 5;' > bad.conf
	atf_check -s exit:1 -o empty -e match:'bsdinstruments: .*bad.conf' \
	    env OTELCONF_FILE="$PWD/bad.conf" bsdinstruments watch mock-prof \
	    --format otel
	# Text and collapsed output have no snapshots to export.
	atf_check -s exit:2 -e match:'--interval needs --format' \
	    bsdinstruments watch mock-prof --interval 1
	atf_check -s exit:2 -e match:'--interval needs --format' \
	    bsdinstruments watch mock-prof --with-stack --format collapsed \
	    --interval 1
	atf_check -s exit:2 -e match:'--interval' \
	    bsdinstruments watch mock-prof --format json --interval 0
	atf_check -s exit:2 -e match:'usage' \
	    bsdinstruments generate mock-prof --interval 5
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
	atf_check -s exit:2 -e match:'--protocol expects grpc, http/protobuf or http/json' \
	    bsdinstruments watch -f x.d --format otel --protocol grpcs
	atf_check -s exit:2 -e match:'apply to --format otel only' \
	    bsdinstruments watch -f x.d --format json --protocol grpc
	atf_check -s exit:2 -e match:usage \
	    bsdinstruments generate -f x.d --protocol grpc
	atf_check -s exit:2 -e match:usage \
	    bsdinstruments generate -f x.d --output f
	atf_check -s exit:2 -e match:usage \
	    bsdinstruments generate -f x.d --rotate-time 1s
	atf_check -s exit:2 -e match:usage \
	    bsdinstruments generate -f x.d --rotate-keep 2
	atf_check -s exit:2 -e match:usage \
	    bsdinstruments generate -f x.d --spool-max 1k
	atf_check -s exit:2 -e match:'--profiles needs --format otel or otlp-json' \
	    bsdinstruments watch -f x.d --format json --profiles
	atf_check -s exit:2 -e match:usage \
	    bsdinstruments generate -f x.d --profiles
}

atf_test_case watch_profiles
watch_profiles_head()
{
	atf_set descr "--profiles: stack-only firings become an OTLP profile"
	atf_set require.progs cc
}
watch_profiles_body()
{
	mock_setup
	anchored_script
	v=$(validator)
	cat >> script <<'EOF'
chunk 0 11000 3               kernel`spin+0x1\n
chunk 0 12000 3               kernel`spin+0x2\n
chunk 1 13000 3               kernel`other+0x2\n
work
EOF
	atf_check -s exit:0 -o empty -e empty bsdinstruments watch mock-prof \
	    --format otlp-json --profiles --output out.jsonl
	atf_check -o match:'profiles=1 samples=2' "$v" out.jsonl
	atf_check -o match:'"stringValue":"syscall:freebsd:read:entry"' \
	    grep resourceProfiles out.jsonl
	# Without --profiles the same firings are no profile.
	atf_check -s exit:0 -o empty -e empty bsdinstruments watch mock-prof \
	    --format otlp-json --output plain.jsonl
	atf_check -s exit:1 grep -q resourceProfiles plain.jsonl
	# Profiles are never sent over http/json.
	atf_check -s not-exit:0 \
	    -e match:'profiles are sent with the http/protobuf or grpc protocol only' \
	    bsdinstruments watch mock-prof --format otel --profiles \
	    --endpoint http://127.0.0.1:9 --protocol http/json
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
drop 2 2
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
	# what the kernel buffered, as dtrace(1) does.  The drops are a
	# cumulative counter by kind (2 is DTRACEDROP_DYNAMIC).
	atf_check -o match:'requests=2 logs=2 metrics=1' "$v" out.jsonl
	atf_check -o match:'"name":"bsdinstruments.drops","description":"Records DTrace dropped, by kind","unit":"\{record\}","sum"' \
	    -o match:'"asInt":"5","attributes":\[\{"key":"dtrace.drop.kind","value":\{"stringValue":"principal"\}\}\]' \
	    -o match:'"asInt":"2","attributes":\[\{"key":"dtrace.drop.kind","value":\{"stringValue":"dynamic"\}\}\]' \
	    -o match:'"isMonotonic":true' cat out.jsonl
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
	atf_check -o match:'"m", \(int64_t\)\(1\), \(int64_t\)\(timestamp\), \(int64_t\)\(tid\), \(int64_t\)\(pid\), execname, ppid, uid, curpsinfo->pr_uid, gid, curpsinfo->pr_gid, curpsinfo->pr_jailid\);' \
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

atf_test_case generate_context_markers
generate_context_markers_head()
{
	atf_set descr "structured rendering records the context at the stack and context markers"
}
generate_context_markers_body()
{
	export HOME="$(pwd)/home"
	make_profile "$HOME/.bsdinstruments/profiles" test-trace
	ctx='printf\("\\037otel.ctx\\037pid=%d\\037ppid=%d\\037tid=%d\\037uid=%d\\037ruid=%d\\037gid=%d\\037rgid=%d\\037jid=%d\\037execname=%s\\n", pid, ppid, tid, uid, curpsinfo->pr_uid, gid, curpsinfo->pr_gid, curpsinfo->pr_jailid, execname\);'
	atf_check -o save:s.d bsdinstruments generate test-trace \
	    --param what=open --format json
	atf_check -o match:"^	$ctx$" cat s.d
	atf_check -o save:k.d bsdinstruments generate test-trace \
	    --param what=open --format otel --with-stack
	atf_check -o match:"^	$ctx stack\(\);$" cat k.d
	# Text output is untouched.
	atf_check -o save:t.d bsdinstruments generate test-trace \
	    --param what=open --with-stack
	atf_check -s exit:1 grep -q otel.ctx t.d
	printf 'BEGIN { /* @bsdinstruments-context */ }\n' > c.d
	atf_check -o match:"$ctx" bsdinstruments generate -f c.d \
	    --format collapsed
	atf_check -o inline:'BEGIN {  }\n\n' bsdinstruments generate -f c.d
	# A span of the probe's own process carries the process context.
	printf 'BEGIN { /* @bsdinstruments-span(name="m", start=1) */ }\n' > m.d
	atf_check -o match:'\\037execname=%s\\037ppid=%d\\037uid=%d\\037ruid=%d\\037gid=%d\\037rgid=%d\\037jid=%d\\n", "m", .*, execname, ppid, uid, curpsinfo->pr_uid, gid, curpsinfo->pr_gid, curpsinfo->pr_jailid\);' \
	    bsdinstruments generate -f m.d --format json
}

atf_test_case watch_semconv
watch_semconv_head()
{
	atf_set descr "records carry semantic-convention context and resource attributes"
	atf_set require.progs cc
}
watch_semconv_body()
{
	mock_setup
	v=$(validator)
	cat >> script <<'EOF'
chunk 0 1000 1 \037otel.clock\037wall=1700000000000000000\037ts=1000\n
chunk 2 5000 2 nginx[42]: read\n
chunk 2 5000 2 \037otel.ctx\037pid=42\037ppid=1\037tid=100123\037uid=80\037ruid=1001\037gid=80\037rgid=1001\037jid=0\037execname=nginx\n
work
agg reads 3
EOF
	export OTEL_RESOURCE_ATTRIBUTES='host.name=override,service.name=fromattrs,team=a'
	atf_check -s exit:0 -o empty -e empty bsdinstruments watch mock-prof \
	    --format otlp-json --output out.jsonl
	atf_check -o match:'requests=2 logs=1 metrics=1' "$v" out.jsonl
	line=$(head -1 out.jsonl)
	for kv in '"process.pid","value":{"intValue":"42"}' \
	    '"process.parent_pid","value":{"intValue":"1"}' \
	    '"process.executable.name","value":{"stringValue":"nginx"}' \
	    '"process.user.id","value":{"intValue":"80"}' \
	    '"process.real_user.id","value":{"intValue":"1001"}' \
	    '"thread.id","value":{"intValue":"100123"}' \
	    '"cpu.logical_number","value":{"intValue":"2"}' \
	    '"service.name","value":{"stringValue":"fromattrs"}' \
	    '"host.name","value":{"stringValue":"override"}' \
	    '"service.instance.id","value":{"stringValue":"' \
	    '"os.type","value":{"stringValue":"freebsd"}' \
	    '"team","value":{"stringValue":"a"}'; do
		echo "$line" | grep -qF "$kv" || atf_fail "missing $kv"
	done
	# No container for the host (jid 0), one host.name only.
	echo "$line" | grep -q container && atf_fail "host reported as a jail"
	[ $(echo "$line" | grep -o '"host.name"' | wc -l) -eq 1 ] || \
	    atf_fail "duplicate host.name"
	# The metric dimension uses the same name as the log attribute.
	atf_check -o match:'"key":"process.executable.name","value":\{"stringValue":"k"\}' \
	    sed -n 2p out.jsonl
	# The scope is the tool, whatever the service is called.
	atf_check -o match:'"scope":\{"name":"bsdinstruments","version":"[^"]*"\}' \
	    -o match:'"key":"bsdinstruments.profile"' head -1 out.jsonl
	# OTEL_SERVICE_NAME beats the attribute.
	export OTEL_SERVICE_NAME=explicit
	atf_check -s exit:0 -o save:o2.jsonl -e empty \
	    bsdinstruments watch mock-prof --format otlp-json
	unset OTEL_SERVICE_NAME
	atf_check -o match:'"service.name","value":\{"stringValue":"explicit"\}' \
	    head -1 o2.jsonl
	unset OTEL_RESOURCE_ATTRIBUTES
	atf_check -s exit:0 -o save:o3.json -e empty \
	    bsdinstruments watch mock-prof --format json
	atf_check -o match:'"attributes":\{"process.pid":42,"process.parent_pid":1,"process.executable.name":"nginx","process.user.id":80' \
	    cat o3.json
}

atf_test_case cli_usage_edges
cli_usage_edges_head()
{
	atf_set descr "usage, version, and argument validation"
}
cli_usage_edges_body()
{
	export HOME="$(pwd)/home"
	make_profile "$HOME/.bsdinstruments/profiles" test-trace
	atf_check -s exit:2 -e match:'^usage: bsdinstruments <subcommand>' \
	    bsdinstruments
	atf_check -s exit:2 -e match:'^usage: bsdinstruments <subcommand>' \
	    bsdinstruments frobnicate
	atf_check -o inline:'0.1.0\n' bsdinstruments --version
	atf_check -s exit:2 -e match:'usage: bsdinstruments list' \
	    bsdinstruments list --bogus
	atf_check -s exit:2 -e match:'usage: bsdinstruments list' \
	    bsdinstruments list extra
	atf_check -s exit:2 -e match:'usage: bsdinstruments probes' \
	    bsdinstruments probes --bogus
	atf_check -s exit:2 -e match:'usage: bsdinstruments generate' \
	    bsdinstruments generate test-trace extra
	atf_check -s exit:2 -e match:'usage: bsdinstruments generate' \
	    bsdinstruments generate test-trace --bogus
	atf_check -s exit:2 -e match:'usage: bsdinstruments watch' \
	    bsdinstruments watch test-trace --bogus
	for o in --broker "--bufsize 1m" "--switchrate 1s"; do
		atf_check -s exit:2 -e match:'usage: bsdinstruments generate' \
		    bsdinstruments generate test-trace $o
	done
	atf_check -s exit:2 -e match:'--bufsize needs a value' \
	    bsdinstruments watch test-trace --bufsize ''
	atf_check -s exit:2 -e match:'--switchrate needs a value' \
	    bsdinstruments watch test-trace --switchrate ''
	for v in abc 5x 99999999999999999999 -1; do
		atf_check -s exit:2 -e match:'--pid expects an integer' \
		    bsdinstruments generate test-trace --param what=x --pid "$v"
	done
	atf_check -s exit:2 -e match:'--uid expects an integer' \
	    bsdinstruments generate test-trace --uid 4294967296
	atf_check -s exit:2 -e match:'--gid expects an integer' \
	    bsdinstruments generate test-trace --gid x
	atf_check -s exit:2 -e match:'--jail expects an integer' \
	    bsdinstruments generate test-trace --jail -2
	for v in abc 1x inf nan 0 -1 1e9; do
		atf_check -s exit:2 -e match:'--duration must be a positive' \
		    bsdinstruments generate test-trace --duration "$v"
	done
	atf_check -s exit:2 -e match:'--param expects key=value' \
	    bsdinstruments generate test-trace --param noequals
	atf_check -s exit:2 -e match:'rotation options need --output' \
	    bsdinstruments watch test-trace --rotate-time 1h
	atf_check -s exit:2 -e match:'rotation options need --output' \
	    bsdinstruments watch test-trace --rotate-keep 2
	atf_check -s exit:2 -e match:'apply to --format otel only' \
	    bsdinstruments watch test-trace --format json --spool-max 1k
	atf_check -s exit:2 -e match:'positive number' \
	    bsdinstruments watch test-trace --output f --rotate-size abc
	atf_check -s exit:2 -e match:'--spool needs a file name' \
	    bsdinstruments watch test-trace --format otel --spool ''
	atf_check -o match:'syscall::c:entry' bsdinstruments generate \
	    test-trace --param other=1 --param what=b --param what=c
	atf_check -s exit:2 -e match:'provide a profile name' \
	    bsdinstruments generate
	atf_check -s exit:1 -e match:"unknown profile 'nosuch'" \
	    bsdinstruments generate nosuch
}

atf_test_case generate_all_filters
generate_all_filters_head()
{
	atf_set descr "every filter flag renders; repeated params take the last"
}
generate_all_filters_body()
{
	export HOME="$(pwd)/home"
	make_profile "$HOME/.bsdinstruments/profiles" test-trace
	atf_check -o save:out.d bsdinstruments generate test-trace \
	    --param what=open --param what=close --uid 3 --gid 4 --jail 5 \
	    --where 'arg0 > 1' --format text
	atf_check -o match:'syscall::close:entry' cat out.d
	atf_check -o match:'/uid == 3 && gid == 4 && curproc->p_ucred->cr_prison->pr_id == 5 && \(arg0 > 1\)/' \
	    cat out.d
}

atf_test_case watch_mock_options
watch_mock_options_head()
{
	atf_set descr "broker mode, buffer options, collapsed user stacks, env endpoint"
	atf_set require.progs cc
}
watch_mock_options_body()
{
	mock_setup
	anchored_script
	atf_check -s exit:0 -o match:'nginx' -e empty \
	    bsdinstruments watch mock-prof --broker --bufsize 2m \
	    --switchrate 10ms
	atf_check -o match:'bufsize=2m' -o match:'switchrate=10ms' cat mock.log
	echo "fail open" > script
	atf_check -s exit:1 -o empty -e match:'BSDTrace delegation failed' \
	    bsdinstruments watch mock-prof --broker
	atf_check -s exit:1 -o empty -e match:'BSDTrace delegation failed' \
	    bsdinstruments probes --broker
	: > script
	anchored_script
	atf_check -s exit:0 -o ignore -e empty \
	    bsdinstruments watch mock-prof --format collapsed --with-ustack
	# The default endpoint (nothing listens on it here): spooled.
	export OTEL_EXPORTER_OTLP_TIMEOUT=200
	atf_check -s exit:0 -o empty -e match:'spooled' \
	    bsdinstruments watch mock-prof --format otel --spool s1.jsonl
	export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:9
	atf_check -s exit:0 -o empty -e match:'spooled' \
	    bsdinstruments watch mock-prof --format otel --spool s2.jsonl
}

atf_test_case watch_tty_color
watch_tty_color_head()
{
	atf_set descr "text output on a terminal is colored; failures reset it"
	atf_set require.progs cc script
}
watch_tty_color_body()
{
	mock_setup
	anchored_script
	atf_check -s exit:0 -o ignore -e ignore \
	    script -q tty.out bsdinstruments watch mock-prof < /dev/null
	atf_check -o match:"$(printf '\033')\[36m" -o match:'nginx' \
	    -o match:"$(printf '\033')\[35m" cat tty.out
	echo "fail go" > script
	atf_check -s exit:1 -o ignore -e ignore \
	    script -q go.out bsdinstruments watch mock-prof < /dev/null
	atf_check -o match:"$(printf '\033')\[0m" \
	    -o match:'failed to start trace' cat go.out
}

atf_test_case watch_write_failures
watch_write_failures_head()
{
	atf_set descr "write failures while tracing stop the run with status 1"
	atf_set require.progs cc
}
watch_write_failures_body()
{
	mock_setup
	{
		echo 'chunk 0 1000 1 \037otel.clock\037wall=1700000000000000000\037ts=1000\n'
		pad=$(printf '%04096d' 0)
		i=0
		while [ $i -lt 80 ]; do
			echo "chunk 0 $((5000 + i)) 2 nginx[42]: $pad\n"
			i=$((i + 1))
		done
		echo work
		echo 'sleep 1100'
		echo work
		echo 'chunk 0 90000 2 nginx[42]: again\n'
		echo work
	} > script
	# The file size limit (RLIMIT_FSIZE, SIGXFSZ ignored; 128k, room
	# for a coverage profile) is hit while tracing.
	for f in text json otlp-json; do
		atf_check -s exit:1 -o empty -e match:'File too large' \
		    sh -c "trap '' XFSZ; ulimit -f 256; exec bsdinstruments watch \
		    mock-prof --format $f --output out.$f"
	done
}

atf_test_case watch_text_rotation_failure
watch_text_rotation_failure_head()
{
	atf_set descr "a failed rotation of text output ends the run with status 1"
	atf_set require.progs cc
}
watch_text_rotation_failure_body()
{
	mock_setup
	cat > script <<'EOF'
chunk 0 5000 2 nginx[42]: a line long enough to need rotating soon\n
work
sleep 1100
work
EOF
	# The slot rotation must clear is a non-empty directory.
	mkdir -p out.txt.1/keep
	atf_check -s exit:1 -o empty -e match:'out.txt: rotate failed' \
	    bsdinstruments watch mock-prof --output out.txt --rotate-size 10 \
	    --rotate-keep 1
	# Standard output gets the periodic check too, without a flush.
	atf_check -s exit:0 -o match:'nginx' -e empty \
	    bsdinstruments watch mock-prof
}

atf_test_case watch_otel_file_target
watch_otel_file_target_head()
{
	atf_set descr "--format otel writes otel.conf's file target and follows rotation"
	atf_set require.progs cc
	atf_set timeout 120
}
watch_otel_file_target_body()
{
	mock_setup
	anchored_script
	cat >> script <<'EOF'
sleep 1500
chunk 0 20000 2 late[9]: read\n
work
sleep 1500
work
done
EOF
	v=$(validator)
	mkdir logs
	printf 'spool { directory = "%s/no-spool"; }\nexport { target = "file"; directory = "%s/logs"; }\n' \
	    "$PWD" "$PWD" > otel-test.conf
	umask 022
	bsdinstruments watch mock-prof --format otel > bi.out 2> bi.err &
	pid=$!
	i=0
	while [ ! -s logs/bsdinstruments.jsonl ] && [ $i -lt 100 ]; do
		sleep 0.05; i=$((i + 1))
	done
	atf_check -o inline:"640\n" stat -f %Lp logs/bsdinstruments.jsonl
	# newsyslog: rename, new file, SIGHUP to the service's process.
	mv logs/bsdinstruments.jsonl logs/bsdinstruments.jsonl.0
	: > logs/new; chmod 0640 logs/new; mv logs/new logs/bsdinstruments.jsonl
	kill -HUP $pid
	wait $pid || atf_fail "bsdinstruments failed: $(cat bi.err)"
	atf_check -o match:'requests=[1-9]' "$v" logs/bsdinstruments.jsonl.0
	atf_check -o match:'requests=[1-9]' "$v" logs/bsdinstruments.jsonl
	# Every record exactly once across the two files.
	for r in 'nginx\[42\]' 'sshd\[7\]' 'late\[9\]'; do
		atf_check -o inline:"1\n" -x \
		    "cat logs/bsdinstruments.jsonl* | grep -o '$r' | wc -l | tr -d ' '"
	done
	# The final snapshot of the run is in the new file.
	atf_check -o match:'resourceMetrics' cat logs/bsdinstruments.jsonl
	# An endpoint on the command line wins (port 9 refuses: spooled).
	atf_check -s exit:0 -o empty -e match:'spooled' \
	    bsdinstruments watch mock-prof --format otel \
	    --endpoint http://127.0.0.1:9 --spool sp.jsonl
	# An unwritable target fails before tracing starts.
	printf 'export { target = "file"; directory = "%s/none"; }\n' "$PWD" \
	    > otel-test.conf
	atf_check -s exit:1 -o empty -e match:'none/bsdinstruments.jsonl' \
	    bsdinstruments watch mock-prof --format otel
}

atf_test_case watch_errors_and_exit
watch_errors_and_exit_head()
{
	atf_set descr "runtime errors and exit() become log events and a counter"
	atf_set require.progs cc
}
watch_errors_and_exit_body()
{
	mock_setup
	v=$(validator)
	cat > script <<'EOF'
chunk 0 1 1 a[1]: x\n
error 1 0x1000
error 4 0
exit 3
work
done
EOF
	atf_check -s exit:0 -o save:out.jsonl -e match:'bsdinstruments: error on enabled probe ID 1' \
	    bsdinstruments watch mock-prof --format otlp-json
	atf_check -o match:'requests=2 logs=4 metrics=1' "$v" out.jsonl
	# ERROR records with the fault, its address, the action.
	atf_check -o match:'"severityNumber":17,"severityText":"ERROR"' \
	    -o match:'"key":"dtrace.fault","value":\{"stringValue":"badaddr"\}' \
	    -o match:'"key":"dtrace.fault.address","value":\{"intValue":"4096"\}' \
	    -o match:'"key":"dtrace.fault","value":\{"stringValue":"divzero"\}' \
	    -o match:'"eventName":"dtrace.error"' \
	    -o match:'"key":"dtrace.exit.status","value":\{"intValue":"3"\}' \
	    -o match:'"eventName":"dtrace.exit"' \
	    -o match:'"name":"bsdinstruments.errors"' cat out.jsonl
	# Text output reports errors on standard error only.
	atf_check -s exit:0 -o not-match:'dtrace.error' -e match:'mock fault' \
	    bsdinstruments watch mock-prof
	echo "fail handle_err" >> script
	atf_check -s exit:1 -e match:'failed to install drop handler' \
	    bsdinstruments watch mock-prof
}

atf_init_test_cases()
{
	atf_add_test_case watch_otel_file_target
	atf_add_test_case watch_errors_and_exit
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
	atf_add_test_case watch_interval
	atf_add_test_case watch_output_errors
	atf_add_test_case watch_usage_errors
	atf_add_test_case watch_profiles
	atf_add_test_case watch_libdtrace_failures
	atf_add_test_case watch_drops_and_signals
	atf_add_test_case probes_mock
	atf_add_test_case generate_span_markers
	atf_add_test_case generate_span_marker_errors
	atf_add_test_case watch_spans
	atf_add_test_case generate_context_markers
	atf_add_test_case watch_semconv
	atf_add_test_case cli_usage_edges
	atf_add_test_case generate_all_filters
	atf_add_test_case watch_mock_options
	atf_add_test_case watch_tty_color
	atf_add_test_case watch_write_failures
	atf_add_test_case watch_text_rotation_failure
}
