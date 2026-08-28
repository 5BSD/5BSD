#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Integration tests for bundle-based service management.
# Tests startup, on-demand launch, reload, stop, and attribution.
#

. $(atf_get_srcdir)/test_helpers.sh

DTRACE_PID=

# ---------------------------------------------------------------
# Test: System bundle boot-start
# ---------------------------------------------------------------
atf_test_case system_bundle_startup cleanup
system_bundle_startup_head() {
	atf_set "descr" "System bundle services start at boot"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
system_bundle_startup_body() {
	local bundle

	prepare_paths
	bundle=$(create_system_bundle "BootTest" "org.test.boot" "bootd" \
	    "org.test.boot.svc")
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/bootd.unit/Unit.ucl"

	start_stack
	wait_for_file "${WORK}/bootd.ready" 5

	# A manifest without provides is an eager boot task.  Runtime identity is
	# bundle_id/program and remains independent from public endpoint names.
	atf_check -s exit:0 -o match:"org.test.boot/bootd.*running" \
	    servicectl -s "${CTL_SOCK}" status

	# Attribution should show "system"
	atf_check -s exit:0 -o match:"by=system" \
	    servicectl -s "${CTL_SOCK}" status
}
system_bundle_startup_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: On-demand service launch
# ---------------------------------------------------------------
atf_test_case on_demand_launch cleanup
on_demand_launch_head() {
	atf_set "descr" "On-demand service launches on first lookup"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
on_demand_launch_body() {
	prepare_paths
	build_lookup_client
	create_user_bundle "LazyApp" "org.test.lazy" "lazyd" \
	    "org.test.lazy.svc" ""

	start_stack

	# The endpoint is reserved, but its bundle_id/program runtime is absent.
	atf_check -s exit:0 -o not-match:"org.test.lazy/lazyd.*running" \
	    servicectl -s "${CTL_SOCK}" status

	# Trigger lookup from a client
	run_lookup_client "org.test.lazy.svc"

	# Now it should be running
	wait_for_file "${WORK}/lazyd.ready" 10
	atf_check -s exit:0 -o match:"org.test.lazy/lazyd.*running" \
	    servicectl -s "${CTL_SOCK}" status
}
on_demand_launch_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: On-demand timeout
# ---------------------------------------------------------------
atf_test_case on_demand_timeout cleanup
on_demand_timeout_head() {
	atf_set "descr" "On-demand launch times out if service never reports ready"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
on_demand_timeout_body() {
	prepare_paths
	build_lookup_client
	# Create a service that never calls service_ready()
	create_user_bundle_custom "Hang" "hangd" \
	    'activation { ipc = ["org.test.hang.svc"]; }'

	start_stack

	# Lookup should fail with timeout.  run_lookup_client is a shell
	# function, so it must be called directly (atf_check execs a binary,
	# not the shell, and would just get ENOENT).
	if run_lookup_client "org.test.hang.svc" 15; then
		atf_fail "on-demand lookup unexpectedly succeeded (no ready timeout)"
	fi
}
on_demand_timeout_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: servicectl stop
# ---------------------------------------------------------------
atf_test_case stop_service cleanup
stop_service_head() {
	atf_set "descr" "Stop a running service via servicectl stop"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
stop_service_body() {
	local bundle

	prepare_paths
	bundle=$(create_system_bundle "StopMe" "org.test.stop" "stopd" \
	    "org.test.stop.svc" "stop_timeout = 1;")
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/stopd.unit/Unit.ucl"

	start_stack
	wait_for_file "${WORK}/stopd.ready" 5

	# Stop it
	atf_check -s exit:0 -o match:"stopping" \
	    servicectl -s "${CTL_SOCK}" stop "org.test.stop/stopd"

	# The compat-ready fixture blocks and does not answer QUIESCE, so it
	# exits only when the stop_timeout SIGKILL fires (1s here).  Poll for the
	# terminal stopped state rather than assuming a fixed settle time.
	i=0
	while [ "$i" -lt 60 ]; do
		if servicectl -s "${CTL_SOCK}" status |
		    grep -q "org.test.stop/stopd.*stopped"; then
			break
		fi
		i=$((i + 1))
		sleep 0.2
	done
	atf_check -s exit:0 -o match:"org.test.stop/stopd.*stopped" \
	    servicectl -s "${CTL_SOCK}" status

	# A stopped unit can be explicitly started again; a second start is
	# rejected while it is active.
	rm -f "${WORK}/stopd.ready"
	atf_check -s exit:0 -o match:"starting" \
	    servicectl -s "${CTL_SOCK}" start "org.test.stop/stopd"
	wait_for_file "${WORK}/stopd.ready" 5 ||
	    atf_fail "explicitly started service did not become ready"
	atf_check -s exit:1 -e match:"not stopped" \
	    servicectl -s "${CTL_SOCK}" start "org.test.stop/stopd"
}
stop_service_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Stop non-existent service
# ---------------------------------------------------------------
atf_test_case stop_nonexistent cleanup
stop_nonexistent_head() {
	atf_set "descr" "Stop returns ENOENT for unknown service label"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
stop_nonexistent_body() {
	prepare_paths
	start_stack

	atf_check -s exit:1 -e match:"not found" \
	    servicectl -s "${CTL_SOCK}" stop "org.fake.service"
}
stop_nonexistent_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Reload adds new services
# ---------------------------------------------------------------
atf_test_case reload_new_service cleanup
reload_new_service_head() {
	atf_set "descr" "Reload detects and launches newly added bundle services"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
reload_new_service_body() {
	local bundle

	prepare_paths
	start_stack

	# Initially no user services
	atf_check -s exit:0 -o not-match:"newbie" \
	    servicectl -s "${CTL_SOCK}" status

	# Add a new bundle
	bundle=$(create_user_bundle "NewApp" "org.test.new" "newbie" \
	    "org.test.new.svc")
	sed -i '' -e 's/ipc = \[[^]]*\];/boot = true;/' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/newbie.unit/Unit.ucl"

	# Reload.  The reply summary is "reload: N bundles, M new, ..."
	# (supervisor_reload); one new service means "1 new".
	atf_check -s exit:0 -o match:"1 new" \
	    servicectl -s "${CTL_SOCK}" reload

	wait_for_file "${WORK}/newbie.ready" 5
	atf_check -s exit:0 -o match:"org.test.new/newbie.*running" \
	    servicectl -s "${CTL_SOCK}" status
}
reload_new_service_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Reload removes deleted services
# ---------------------------------------------------------------
atf_test_case reload_remove_service cleanup
reload_remove_service_head() {
	atf_set "descr" "Reload stops services whose bundle was removed"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
reload_remove_service_body() {
	local bundle

	prepare_paths
	bundle=$(create_user_bundle "Removable" "org.test.rm" "rmd" \
	    "org.test.rm.svc")
	sed -i '' -e 's/ipc = \[[^]]*\];/boot = true;/' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/rmd.unit/Unit.ucl"

	start_stack
	wait_for_file "${WORK}/rmd.ready" 5

	# Remove the bundle (user bundle lives in USER_APPS_DIR)
	rm -rf "${USER_APPS_DIR}/Removable.cap"

	# Reload.  servicectl prints a summary to stdout, so -o ignore is
	# required (atf_check defaults to -o empty).
	atf_check -s exit:0 -o ignore \
	    servicectl -s "${CTL_SOCK}" reload

	# The runtime is no longer running.
	sleep 1
	atf_check -s exit:0 -o not-match:"org.test.rm/rmd.*running" \
	    servicectl -s "${CTL_SOCK}" status
}
reload_remove_service_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Missing system bundle directory is optional
# ---------------------------------------------------------------
atf_test_case missing_system_bundle_optional cleanup
missing_system_bundle_optional_head() {
	atf_set "descr" "Missing /Capabilities/System is optional"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
missing_system_bundle_optional_body() {
	prepare_paths
	# Remove the system dir
	rmdir "${APPS_DIR}" 2>/dev/null || true

	start_stack
	atf_check -s exit:0 -o match:"serviced: running" \
	    servicectl -s "${CTL_SOCK}" status
}
missing_system_bundle_optional_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: servicectl bundles command
# ---------------------------------------------------------------
atf_test_case bundles_list cleanup
bundles_list_head() {
	atf_set "descr" "servicectl bundles lists registered bundles"
}
bundles_list_body() {
	# This doesn't need a running serviced — it scans directories directly.
	# Scratch space must live in the kyua work directory: the source
	# directory may be a read-only medium.
	TMPDIR=${PWD}/work.$$
	mkdir -p "${TMPDIR}"

	atf_check -s exit:0 -o match:"System bundles" \
	    servicectl bundles
}
bundles_list_cleanup() {
	rm -rf "${PWD}"/work.*
}

# ---------------------------------------------------------------
# Test: DTrace probes fire
# ---------------------------------------------------------------
atf_test_case dtrace_probes cleanup
dtrace_probes_head() {
	atf_set "descr" "DTrace startup schema is registered and capability orchestration probes fire"
	atf_set "require.user" "root"
	atf_set "require.progs" "dtrace"
	require_authority_stack_kmods mac_capability_identity
	atf_set "timeout" "60"
}
dtrace_probes_body() {
	local bundle i serviced_pid

	prepare_paths
	printf 'probe target\n' > "${WORK}/dtrace-token-target"

	# USDT -Z accepts an initially unmatched description but does not attach
	# it retroactively when a provider registers.  Start an empty stack first,
	# then bind to the exact live provider PIDs.  The startup probes have
	# already fired, so validate their registered schema with dtrace -l; the
	# capability probes below are exercised by a subsequent reload.
	start_stack
	serviced_pid=
	i=0
	while [ -z "$serviced_pid" ] && [ "$i" -lt 100 ]; do
		serviced_pid=$(sed -n \
		    's/.*bootstrap: started serviced pid \([0-9][0-9]*\).*/\1/p' \
		    "$logfile" 2>/dev/null | tail -1)
		if [ -n "$serviced_pid" ] &&
		    ! kill -0 "$serviced_pid" 2>/dev/null; then
			serviced_pid=
		fi
		i=$((i + 1))
		[ -n "$serviced_pid" ] || sleep 0.1
	done
	if [ -z "$serviced_pid" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "could not identify the live serviced provider"
	fi
	atf_check -s exit:0 -o match:'startup-begin' \
	    dtrace -l -n "serviced${serviced_pid}:::startup-begin"
	atf_check -s exit:0 -o match:'startup-done' \
	    dtrace -l -n "serviced${serviced_pid}:::startup-done"

	dtrace -n 'BEGIN { printf("CONSUMER_READY\n"); }' \
	    -n "serviced${serviced_pid}:::cap-service { printf(\"SVC_CAP %s %s %d\\n\", copyinstr(arg0), copyinstr(arg1), arg2); }" \
	    -n "authorityd${daemon_pid}:::mint-file { printf(\"FILE %s 0x%x %d\\n\", copyinstr(arg0), arg1, arg2); }" \
	    -n "authorityd${daemon_pid}:::service-delegate { printf(\"SERVICE %s %d\\n\", copyinstr(arg0), arg1); }" \
	    -o "${WORK}/dtrace.out" 2>"${WORK}/dtrace.err" &
	DTRACE_PID=$!
	printf '%s\n' "$DTRACE_PID" > "${WORK}/dtrace.pid"
	i=0
	while ! grep -q 'CONSUMER_READY' "${WORK}/dtrace.out" 2>/dev/null &&
	    kill -0 "${DTRACE_PID}" 2>/dev/null && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if ! grep -q 'CONSUMER_READY' "${WORK}/dtrace.out" 2>/dev/null; then
		wait "${DTRACE_PID}" 2>/dev/null || true
		cat "${WORK}/dtrace.err" >&2
		atf_fail "DTrace consumer did not become ready"
	fi

	bundle=$(create_system_bundle "Traced" "org.test.trace" "traced" \
	    "org.test.trace.svc" \
	    "capabilities { files = [ { path = \"${WORK}/dtrace-token-target\"; actions = [\"read\"]; } ]; services = [\"identity\"]; }")
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/traced.unit/Unit.ucl"
	atf_check -s exit:0 -o ignore \
	    servicectl -s "${CTL_SOCK}" reload
	if ! wait_for_file "${WORK}/traced.ready" 5; then
		cat "$logfile" 2>/dev/null
		atf_fail "traced service did not become ready"
	fi

	# Wait until every expected probe record is visible, or until the
	# consumer exits.  This provides a bounded, event-based completion point.
	i=0
	while [ "$i" -lt 100 ]; do
		if grep -q 'FILE.*dtrace-token-target' "${WORK}/dtrace.out" 2>/dev/null &&
		    grep -q 'SERVICE identity 0' "${WORK}/dtrace.out" 2>/dev/null &&
	    grep -q 'SVC_CAP org.test.trace/traced identity 0' \
		    "${WORK}/dtrace.out" 2>/dev/null; then
			break
		fi
		kill -0 "${DTRACE_PID}" 2>/dev/null || break
		i=$((i + 1))
		sleep 0.1
	done
	if ! grep -q 'FILE.*dtrace-token-target' "${WORK}/dtrace.out" 2>/dev/null ||
	    ! grep -q 'SERVICE identity 0' "${WORK}/dtrace.out" 2>/dev/null ||
	    ! grep -q 'SVC_CAP org.test.trace/traced identity 0' \
	    "${WORK}/dtrace.out" 2>/dev/null; then
		cat "${WORK}/dtrace.err" >&2
		cat "${WORK}/dtrace.out" >&2
		atf_fail "capability orchestration probes did not all fire"
	fi
	kill -INT "${DTRACE_PID}" 2>/dev/null || true
	wait "${DTRACE_PID}" 2>/dev/null || true
	DTRACE_PID=
	rm -f "${WORK}/dtrace.pid"

	atf_check -s exit:0 -o match:"FILE.*dtrace-token-target" \
	    cat "${WORK}/dtrace.out"
	atf_check -s exit:0 -o match:"SERVICE identity 0" \
	    cat "${WORK}/dtrace.out"
	atf_check -s exit:0 -o match:"SVC_CAP org.test.trace/traced identity 0" \
	    cat "${WORK}/dtrace.out"
}
dtrace_probes_cleanup() {
	local dtrace_pid i

	if [ -r "${WORK}/dtrace.pid" ]; then
		read -r dtrace_pid < "${WORK}/dtrace.pid" || dtrace_pid=
		case "$dtrace_pid" in
		''|*[!0-9]*) ;;
		*)
			if [ "$(ps -p "$dtrace_pid" -o comm= 2>/dev/null)" =
			    "dtrace" ]; then
				kill -INT "$dtrace_pid" 2>/dev/null || true
				i=0
				while kill -0 "$dtrace_pid" 2>/dev/null &&
				    [ "$i" -lt 20 ]; do
					i=$((i + 1))
					sleep 0.1
				done
				kill -KILL "$dtrace_pid" 2>/dev/null || true
			fi
			;;
		esac
		rm -f "${WORK}/dtrace.pid"
	fi
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Changed bundle triggers service restart
# ---------------------------------------------------------------
atf_test_case reload_changed_bundle cleanup
reload_changed_bundle_head() {
	atf_set "descr" "Reload restarts service when bundle manifest changes"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
reload_changed_bundle_body() {
	local bundle

	prepare_paths
	bundle=$(create_system_bundle "Morph" "org.test.morph" "morphd" \
	    "org.test.morph.svc" 'restart = "never";')
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/morphd.unit/Unit.ucl"

	start_stack
	wait_for_file "${WORK}/morphd.ready" 5

	# Change restart policy
	cat > "${APPS_DIR}/Morph.cap/Units/morphd.unit/Unit.ucl" <<UCL
activation { boot = true; ipc = ["org.test.morph.svc"]; }
restart = "always";
UCL

	atf_check -s exit:0 -o ignore \
	    servicectl -s "${CTL_SOCK}" reload

	sleep 1

	# Should see the change detection.  reload.c logs "restarting changed
	# service '<label>'" and "reload: N services changed".
	atf_check -s exit:0 -o ignore \
	    grep "restarting changed service\|1 services changed" "${logfile}"
}
reload_changed_bundle_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Stop already-stopped service returns EALREADY
# ---------------------------------------------------------------
atf_test_case stop_already_stopped cleanup
stop_already_stopped_head() {
	atf_set "descr" "Stop on already-stopped service returns error"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
stop_already_stopped_body() {
	local bundle

	prepare_paths
	bundle=$(create_system_bundle "Brief" "org.test.brief" "briefd" \
	    "org.test.brief.svc")
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/briefd.unit/Unit.ucl"

	start_stack
	wait_for_file "${WORK}/briefd.ready" 5

	# Stop it once (servicectl prints "stop: ... stopping" -> -o ignore).
	atf_check -s exit:0 -o ignore \
	    servicectl -s "${CTL_SOCK}" stop "org.test.brief/briefd"

	sleep 1

	# Stop it again — should fail
	atf_check -s not-exit:0 -o ignore -e ignore \
	    servicectl -s "${CTL_SOCK}" stop "org.test.brief/briefd"
}
stop_already_stopped_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Coalition kill on stop timeout
# ---------------------------------------------------------------
atf_test_case coalition_kill_on_timeout cleanup
coalition_kill_on_timeout_head() {
	atf_set "descr" "Service ignoring SIGTERM is killed via coalition after stop_timeout"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
coalition_kill_on_timeout_body() {
	prepare_paths

	# Create a stubborn service that ignores SIGTERM
	local stubdir="${APPS_DIR}/Stubborn.cap"
	write_test_bundle "$stubdir" org.test.stubborn stubbornd \
	    'stop_timeout = 2;' 'activation { boot = true; }'

	# UNQUOTED heredoc: ${WORK} is expanded at write time so the absolute
	# path bakes into the script (services run with a minimal env and do not
	# inherit WORK).  \$\$ stays a runtime shell variable.
	cat > "${stubdir}/Units/stubbornd.unit/bin/stubbornd" <<SVCEOF
#!/bin/sh
trap "" TERM
echo \$\$ > "${WORK}/stubbornd.pid"
while :; do sleep 1; done
SVCEOF
	chmod 755 "${stubdir}/Units/stubbornd.unit/bin/stubbornd"

	start_stack
	wait_for_file "${WORK}/stubbornd.pid" 5

	# Stop the service — it will ignore SIGTERM
	servicectl -s "${CTL_SOCK}" stop "org.test.stubborn/stubbornd"

	# Wait for stop_timeout + SIGKILL + coalition terminate
	sleep 4

	# Service should be dead
	if [ -f "${WORK}/stubbornd.pid" ]; then
		atf_check -s not-exit:0 -e ignore \
		    kill -0 "$(cat ${WORK}/stubbornd.pid)"
	fi

	# Log should show the escalation.  With a coalition the kernel escalates
	# SIGTERM->SIGKILL after stop_timeout and serviced logs the exit as
	# "killed by signal 9"; without one, serviced's own stop-kill timer logs
	# "stop timeout, sending SIGKILL" (svc_graceful_stop only arms that timer
	# in the non-coalition fallback path).
	atf_check -s exit:0 -o ignore \
	    grep "stop timeout.*SIGKILL\|killed by signal 9" "${logfile}"
}
coalition_kill_on_timeout_cleanup() {
	if [ -f "${WORK}/stubbornd.pid" ]; then
		kill -KILL "$(cat ${WORK}/stubbornd.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

# ---------------------------------------------------------------
# Test: On-demand service crash and relaunch
# ---------------------------------------------------------------
atf_test_case on_demand_crash_relaunch cleanup
on_demand_crash_relaunch_head() {
	atf_set "descr" "On-demand service that crashes is relaunched on next lookup"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
on_demand_crash_relaunch_body() {
	prepare_paths
	build_lookup_client
	build_ready_svc

	# Create a custom on-demand bundle whose service crashes on
	# first invocation and runs normally on subsequent ones.
	local dir="${APPS_DIR}/Crasher.cap"
	write_test_bundle "$dir" org.test.crash crashd \
	    'activation { ipc = ["org.test.crash.svc"]; }
restart = "on-failure";' 'activation { boot = true; }'

	# Install the libservice ready helper directly as the service program.
	# Its crash-once scenario exits non-zero on the first invocation and
	# reports ready (writing crashd.ready) on every later one.  This is a
	# single exec from serviced, so the CAP_CLOEXEC_ONCE bootstrap
	# descriptor — which only survives one exec — reaches the helper; a
	# wrapper script that re-exec'd a helper would lose it.
	cp ready_svc "${dir}/Units/crashd.unit/bin/crashd"
	chmod 755 "${dir}/Units/crashd.unit/bin/crashd"
	printf '%s\n' \
	    "arguments = [\"crash-once\", \"${WORK}/crashd.invocations\", \"crashd\", \"org.test.crash.svc\"];" \
	    >> "${dir}/Units/crashd.unit/Unit.ucl"

	start_stack

	# Service should not have a running bundle_id/program runtime yet.
	atf_check -s exit:0 -o not-match:"org.test.crash/crashd.*running" \
	    servicectl -s "${CTL_SOCK}" status

	# First lookup triggers launch -> service crashes -> restart.
	run_lookup_client "org.test.crash.svc" 15 || true

	# Wait for the restarted instance to come up.
	if ! wait_for_file "${WORK}/crashd.ready" 15; then
		cat "${logfile}" 2>/dev/null
		atf_fail "service did not relaunch after crash"
	fi

	# Verify the service crashed and was relaunched.
	atf_check -s exit:0 -o ignore \
	    grep "exited status 1\|crashed.*crashd" "${logfile}"

	# The relaunched runtime is now running.
	atf_check -s exit:0 -o match:"org.test.crash/crashd.*running" \
	    servicectl -s "${CTL_SOCK}" status

	# State file should show at least 2 invocations.
	atf_check -s exit:0 -o not-match:"^1$" \
	    cat "${WORK}/crashd.invocations"
}
on_demand_crash_relaunch_cleanup() {
	rm -f "${WORK}/crashd.invocations"
	cleanup_common
}

# ---------------------------------------------------------------
# Test: one bundle can contain eager and on-demand binaries
# ---------------------------------------------------------------
atf_test_case multi_binary_bundle_activation cleanup
multi_binary_bundle_activation_head() {
	atf_set "descr" \
	    "One bundle parses two manifests, starts its eager binary, and activates its named binary on lookup"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
multi_binary_bundle_activation_body() {
	local bundle endpoint

	prepare_paths
	find_capd_service_fixture
	build_lookup_client
	endpoint="org.test.multibin.lazy"
	bundle="${USER_APPS_DIR}/MultiBinary.cap"
	mkdir -p "${bundle}/Units/eagerd.unit/bin" \
	    "${bundle}/Units/lazyd.unit/bin"
	cat > "$bundle/Bundle.ucl" <<'UCL'
schema = "org.5bsd.capability-bundle";
schema_version = 1;
bundle_id = "org.test.multibin";
version = "1.0.0";
sequence = 1;
author = "test";
publisher = "org.test";
units = ["eagerd", "lazyd"];
UCL
	cp "${capd_service_fixture}" "${bundle}/Units/eagerd.unit/bin/eagerd"
	cp "${capd_service_fixture}" "${bundle}/Units/lazyd.unit/bin/lazyd"
	chmod 0555 "${bundle}/Units/eagerd.unit/bin/eagerd" \
	    "${bundle}/Units/lazyd.unit/bin/lazyd"
	cat > "${bundle}/Units/eagerd.unit/Unit.ucl" <<'UCL'
activation { boot = true; }
arguments = ["compat-ready"];
UCL
	cat > "${bundle}/Units/lazyd.unit/Unit.ucl" <<UCL
activation { ipc = ["${endpoint}"]; }
arguments = ["compat-ready", "${endpoint}"];
UCL

	start_stack
	wait_for_file "${WORK}/eagerd.ready" 10 ||
	    atf_fail "eager binary in multi-binary bundle did not start"
	test ! -e "${WORK}/lazyd.ready" ||
	    atf_fail "named binary started before lookup"
	atf_check -s exit:0 -o match:'org.test.multibin/eagerd.*running' \
	    servicectl -s "${CTL_SOCK}" status
	atf_check -s exit:0 -o not-match:'org.test.multibin/lazyd.*running' \
	    servicectl -s "${CTL_SOCK}" status

	run_lookup_client "${endpoint}" 15 ||
	    atf_fail "lookup did not activate named binary"
	wait_for_file "${WORK}/lazyd.ready" 10 ||
	    atf_fail "named binary did not report ready"
	atf_check -s exit:0 -o match:'org.test.multibin/lazyd.*running' \
	    servicectl -s "${CTL_SOCK}" status
}
multi_binary_bundle_activation_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: all local factory names are boot-only and not globally connectable
# ---------------------------------------------------------------
atf_test_case component_factory_names_are_internal cleanup
component_factory_names_are_internal_head() {
	atf_set "descr" \
	    "Filesystem, network, and crypto factories boot eagerly but reject ordinary named lookup"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
component_factory_names_are_internal_body() {
	local endpoint kind

	prepare_paths
	find_capd_service_fixture
	build_lookup_client
	for kind in filesystem network crypto; do
		case "${kind}" in
		filesystem) endpoint="org.5bsd.FileSystemCmp" ;;
		network) endpoint="org.5bsd.NetworkCmp" ;;
		crypto) endpoint="org.5bsd.CryptoCmp" ;;
		esac
		make_svc_bin system "${kind}-factory" \
		    "activation { boot = true; ipc = [\"${endpoint}\"]; }
arguments = [\"compat-ready\", \"${endpoint}\"];" \
		    "${capd_service_fixture}" >/dev/null
	done

	start_stack
	for kind in filesystem network crypto; do
		wait_for_file "${WORK}/${kind}-factory.ready" 10 ||
		    atf_fail "${kind} factory did not start at boot"
	done
	for endpoint in org.5bsd.FileSystemCmp org.5bsd.NetworkCmp \
	    org.5bsd.CryptoCmp
	do
		if run_lookup_client "${endpoint}" 3; then
			atf_fail "internal factory ${endpoint} was globally connectable"
		fi
	done
}
component_factory_names_are_internal_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
atf_init_test_cases() {
	atf_add_test_case system_bundle_startup
	atf_add_test_case on_demand_launch
	atf_add_test_case on_demand_timeout
	atf_add_test_case stop_service
	atf_add_test_case stop_nonexistent
	atf_add_test_case stop_already_stopped
	atf_add_test_case reload_new_service
	atf_add_test_case reload_remove_service
	atf_add_test_case reload_changed_bundle
	atf_add_test_case missing_system_bundle_optional
	atf_add_test_case coalition_kill_on_timeout
	atf_add_test_case bundles_list
	atf_add_test_case dtrace_probes
	atf_add_test_case on_demand_concurrent_lookup
	atf_add_test_case multiple_provides_secondary_activation
	atf_add_test_case multiple_provides_failure_isolated
	atf_add_test_case requester_crash_cancels_pending_lookup
	atf_add_test_case on_demand_crash_relaunch
	atf_add_test_case reload_noop
	atf_add_test_case reload_attribution
	atf_add_test_case multi_binary_bundle_activation
	atf_add_test_case component_factory_names_are_internal
}

# ---------------------------------------------------------------
# Test: Concurrent on-demand lookups coalesce into one launch
# ---------------------------------------------------------------
atf_test_case on_demand_concurrent_lookup cleanup
on_demand_concurrent_lookup_head() {
	atf_set "descr" "Multiple concurrent lookups for same on-demand service produce one launch"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
on_demand_concurrent_lookup_body() {
	prepare_paths
	build_lookup_client
	create_user_bundle "Shared" "org.test.shared" "sharedd" \
	    "org.test.shared.svc" ""

	start_stack

	# Fire two lookups concurrently
	run_lookup_client "org.test.shared.svc" &
	LK1=$!
	run_lookup_client "org.test.shared.svc" &
	LK2=$!

	wait_for_file "${WORK}/sharedd.ready" 10

	# Both lookups should resolve
	wait $LK1 2>/dev/null || true
	wait $LK2 2>/dev/null || true

	# Verify only one service instance launched (not two)
	count=$(grep -c "launched.*sharedd\|svc_exec.*org.test.shared" \
	    "${logfile}" 2>/dev/null || echo 0)
	if [ "$count" -gt 1 ]; then
		cat "${logfile}"
		atf_fail "on-demand service launched $count times (expected 1)"
	fi
}
on_demand_concurrent_lookup_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: any provided name activates the same multi-endpoint process
# ---------------------------------------------------------------
atf_test_case multiple_provides_secondary_activation cleanup
multiple_provides_secondary_activation_head() {
	atf_set "descr" \
	    "Concurrent lookups of two provided names launch one process and route each endpoint"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
multiple_provides_secondary_activation_body() {
	local bundle first second p1 p2

	prepare_paths
	build_lookup_client
	find_capd_service_fixture
	first="org.test.multi.primary"
	second="org.test.multi.secondary"
	bundle=$(make_svc_bin user multi-provider \
	    "activation { ipc = [\"${first}\", \"${second}\"]; }
arguments = [\"multi-provider\", \"${first}\", \"${second}\",
		    \"${WORK}/multi-registered.out\", \"${WORK}/multi-routed.out\"];
restart = \"on-failure\";" "${capd_service_fixture}")

	start_stack
	run_lookup_client "${second}" &
	p2=$!
	run_lookup_client "${first}" &
	p1=$!
	wait "${p1}" || atf_fail "primary-name lookup failed"
	wait "${p2}" || atf_fail "secondary-name lookup failed"
	wait_for_file "${WORK}/multi-routed.out" 10 ||
	    atf_fail "multi-name provider did not route both endpoints"
	atf_check -s exit:0 -o match:"first=${first}" \
	    grep "first=${first}" "${WORK}/multi-routed.out"
	atf_check -s exit:0 -o match:"second=${second}" \
	    grep "second=${second}" "${WORK}/multi-routed.out"
	atf_check -s exit:0 -o match:'first_activations=1' \
	    grep first_activations "${WORK}/multi-routed.out"
	atf_check -s exit:0 -o match:'second_activations=1' \
	    grep second_activations "${WORK}/multi-routed.out"
	atf_check -s exit:0 -o match:'publication_ack_before_accept=yes' \
	    grep publication_ack_before_accept "${WORK}/multi-routed.out"
	atf_check -s exit:0 \
	    -o match:'org.test.multi-provider.*conns=2' \
	    servicectl -s "${CTL_SOCK}" status
	count=$(grep -c "on_demand: launching 'org.test.multi-provider/multi-provider'" \
	    "${logfile}" 2>/dev/null || true)
	[ "${count}" -eq 1 ] ||
	    atf_fail "multi-name service launched ${count} times"
	stop_stack
}
multiple_provides_secondary_activation_cleanup() {
	cleanup_common
	rm -f multi-registered.out multi-routed.out
}

# ---------------------------------------------------------------
# Test: readiness rejects a partially claimed provides set
# ---------------------------------------------------------------
atf_test_case multiple_provides_failure_isolated cleanup
multiple_provides_failure_isolated_head() {
	atf_set "descr" \
	    "a provider cannot become ready until every declared name has a listener"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
multiple_provides_failure_isolated_body() {
	local bundle first second

	prepare_paths
	build_lookup_client
	find_capd_service_fixture
	first="org.test.partial.primary"
	second="org.test.partial.secondary"
	bundle=$(make_svc_bin user partial-provider \
	    "activation { ipc = [\"${first}\", \"${second}\"]; }
arguments = [\"partial-provider\", \"${first}\",
		    \"${WORK}/partial-ready.out\"];
restart = \"never\";" "${capd_service_fixture}")

	start_stack
	wait_for_file "${WORK}/partial-ready.out" 5 ||
	    atf_fail "provider did not report its rejected readiness"
	atf_check -s exit:0 -o match:'process_ready=0' \
	    grep process_ready "${WORK}/partial-ready.out"
	atf_check -s exit:0 -o match:'ready_errno=71' \
	    grep ready_errno "${WORK}/partial-ready.out"
	atf_check -s exit:0 -o match:'readiness rejected' \
	    grep "readiness rejected" "${logfile}"
	if run_lookup_client "${first}" 2; then
		atf_fail "partially claimed provider published its first endpoint"
	fi
	if run_lookup_client "${second}" 2; then
		atf_fail "partially claimed provider published its missing endpoint"
	fi
	stop_stack
}
multiple_provides_failure_isolated_cleanup() {
	cleanup_common
	rm -f partial-ready.out
}

# ---------------------------------------------------------------
# Test: pending lookup ownership follows one exact requester incarnation
# ---------------------------------------------------------------
atf_test_case requester_crash_cancels_pending_lookup cleanup
requester_crash_cancels_pending_lookup_head() {
	atf_set "descr" \
	    "a crashed requester loses its pending token and its restarted incarnation receives only its own reply"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
requester_crash_cancels_pending_lookup_body() {
	local client_bundle first_pid i provider_bundle service_name

	prepare_paths
	find_capd_service_fixture
	service_name="org.test.lifecycle.delayed"
	provider_bundle=$(make_svc_bin user delayed-provider \
	    "activation { ipc = [\"${service_name}\"]; }
restart = \"on-failure\";
arguments = [\"delayed-provider\", \"${service_name}\", \"5000\",
    \"${WORK}/delayed-provider.started\",
    \"${WORK}/delayed-provider.result\"];" "${capd_service_fixture}")
	client_bundle=$(make_svc_bin system restart-client \
	    "restart = \"on-failure\";
arguments = [\"crash-client\", \"${service_name}\",
    \"${WORK}/restart-client.started\",
    \"${WORK}/restart-client.result\"];" "${capd_service_fixture}")

	start_stack
	wait_for_file "${WORK}/restart-client.started" 5 ||
	    atf_fail "first requester did not begin its lookup"
	wait_for_file "${WORK}/delayed-provider.started" 5 ||
	    atf_fail "lookup did not activate the delayed provider"
	first_pid=$(sed -n 's/^pid=\([0-9][0-9]*\).*/\1/p' \
	    "${WORK}/restart-client.started")
	case "${first_pid}" in
	''|*[!0-9]*) atf_fail "requester fixture returned an invalid PID" ;;
	esac
	kill -KILL "${first_pid}" ||
	    atf_fail "could not crash the first requester"

	i=0
	while ! grep -q "canceled 1 pending lookup.*restart-client" \
	    "${logfile}" 2>/dev/null && [ "${i}" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	[ "${i}" -lt 100 ] || {
		cat "${logfile}" 2>/dev/null
		atf_fail "serviced did not cancel the crashed requester's token"
	}
	wait_for_file "${WORK}/restart-client.result" 15 || {
		cat "${logfile}" 2>/dev/null
		atf_fail "restarted requester did not receive a fresh session"
	}
	atf_check -s exit:0 -o match:'connected=1' \
	    grep connected "${WORK}/restart-client.result"
	atf_check -s exit:0 -o match:"reply=${service_name}" \
	    grep reply "${WORK}/restart-client.result"
	wait_for_file "${WORK}/delayed-provider.result" 5 ||
	    atf_fail "provider did not record the replacement session"
	atf_check -s exit:0 -o match:'accepted=org.test.lifecycle.delayed' \
	    grep accepted "${WORK}/delayed-provider.result"
	stop_stack
}
requester_crash_cancels_pending_lookup_cleanup() {
	cleanup_common
	rm -f delayed-provider.started delayed-provider.result \
	    restart-client.started restart-client.result
}

# ---------------------------------------------------------------
# Test: Reload with no on-disk changes is a no-op
# ---------------------------------------------------------------
atf_test_case reload_noop cleanup
reload_noop_head() {
	atf_set "descr" "Reload with no bundle changes reports zero deltas and leaves services running"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
reload_noop_body() {
	local bundle

	prepare_paths
	bundle=$(create_system_bundle "Steady" "org.test.steady" "steadyd" \
	    "org.test.steady.svc")
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/steadyd.unit/Unit.ucl"

	start_stack
	wait_for_file "${WORK}/steadyd.ready" 5

	# Nothing changed on disk — reload's summary should report all zeros
	# (supervisor_reload: "reload: N bundles, 0 new, 0 changed, 0 removed").
	atf_check -s exit:0 -o match:"0 new, 0 changed, 0 removed" \
	    servicectl -s "${CTL_SOCK}" reload

	# The already-running service is untouched by the no-op reload.
	atf_check -s exit:0 -o match:"org.test.steady/steadyd.*running" \
	    servicectl -s "${CTL_SOCK}" status
}
reload_noop_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Reload-added service is attributed by=reload
# ---------------------------------------------------------------
atf_test_case reload_attribution cleanup
reload_attribution_head() {
	atf_set "descr" "A service launched by reload is attributed by=reload in status"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
reload_attribution_body() {
	local bundle

	prepare_paths
	start_stack

	# Add a user bundle after startup, then reload to launch it.
	bundle=$(create_user_bundle "Late" "org.test.late" "lated" \
	    "org.test.late.svc")
	sed -i '' -e 's/ipc = \[[^]]*\];/boot = true;/' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/lated.unit/Unit.ucl"

	atf_check -s exit:0 -o match:"1 new" \
	    servicectl -s "${CTL_SOCK}" reload

	wait_for_file "${WORK}/lated.ready" 5

	# reload.c stamps launched_by="reload"; status shows it as by=reload.
	atf_check -s exit:0 -o match:"org.test.late/lated.*by=reload" \
	    servicectl -s "${CTL_SOCK}" status
}
reload_attribution_cleanup() {
	cleanup_common
}
