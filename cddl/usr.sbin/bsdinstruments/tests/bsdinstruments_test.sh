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
	atf_add_test_case capability_services_live_probes
}
