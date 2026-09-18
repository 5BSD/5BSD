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

# Installed tests exercise the installed control utility.  Raw object-tree
# runs (including developer `kyua test` before install) use the matching build
# instead of failing because /usr/sbin/switchboardctl is not installed yet.
if [ -x /usr/sbin/switchboardctl ]; then
	SWITCHBOARDCTL=/usr/sbin/switchboardctl
else
	SWITCHBOARDCTL="@OBJTOP@/usr.sbin/switchboardctl/switchboardctl"
fi
PATH="${SWITCHBOARDCTL%/*}:${PATH}"
export PATH

# ---------------------------------------------------------------
# Test: System bundle boot-start
# ---------------------------------------------------------------
atf_test_case system_bundle_startup cleanup
system_bundle_startup_head() {
	atf_set "descr" "System bundle services start at boot"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
system_bundle_startup_body() {
	require_ambient_control
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
	    switchboardctl status

	# Attribution should show "system"
	atf_check -s exit:0 -o match:"by=system" \
	    switchboardctl status
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
	require_capsule_stack_kmods
}
on_demand_launch_body() {
	require_ambient_control
	prepare_paths
	build_lookup_client
	create_user_bundle "LazyApp" "org.test.lazy" "lazyd" \
	    "org.test.lazy.svc" ""

	start_stack

	# The endpoint is reserved, but its bundle_id/program runtime is absent.
	atf_check -s exit:0 -o not-match:"org.test.lazy/lazyd.*running" \
	    switchboardctl status

	# Trigger lookup from a client
	run_lookup_client "org.test.lazy.svc"

	# Now it should be running
	wait_for_file "${WORK}/lazyd.ready" 10
	atf_check -s exit:0 -o match:"org.test.lazy/lazyd.*running" \
	    switchboardctl status
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
	require_capsule_stack_kmods
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
# Test: switchboardctl stop
# ---------------------------------------------------------------
atf_test_case stop_service cleanup
stop_service_head() {
	atf_set "descr" "Stop a running service via switchboardctl stop"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
stop_service_body() {
	require_ambient_control
	local bundle

	prepare_paths
	bundle=$(create_system_bundle "StopMe" "org.test.stop" "stopd" \
	    "org.test.stop.svc" "stop_timeout = 1;")
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/stopd.unit/Unit.ucl"

	start_stack
	wait_for_file "${WORK}/stopd.ready" 5

	# Stop it
	atf_check -s exit:0 -o match:"stopping" \
	    switchboardctl stop "org.test.stop/stopd"

	# The compat-ready fixture blocks and does not answer QUIESCE, so it
	# exits only when the stop_timeout SIGKILL fires (1s here).  Poll for the
	# terminal stopped state rather than assuming a fixed settle time.
	i=0
	while [ "$i" -lt 60 ]; do
		if switchboardctl status |
		    grep -q "org.test.stop/stopd.*stopped"; then
			break
		fi
		i=$((i + 1))
		sleep 0.2
	done
	atf_check -s exit:0 -o match:"org.test.stop/stopd.*stopped" \
	    switchboardctl status

	# A stopped unit can be explicitly started again; a second start is
	# rejected while it is active.
	rm -f "${WORK}/stopd.ready"
	atf_check -s exit:0 -o match:"starting" \
	    switchboardctl start "org.test.stop/stopd"
	wait_for_file "${WORK}/stopd.ready" 5 ||
	    atf_fail "explicitly started service did not become ready"
	atf_check -s exit:1 -e match:"not stopped" \
	    switchboardctl start "org.test.stop/stopd"
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
	require_capsule_stack_kmods
}
stop_nonexistent_body() {
	require_ambient_control
	prepare_paths
	start_stack

	atf_check -s exit:1 -e match:"not found" \
	    switchboardctl stop "org.fake.service"
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
	require_capsule_stack_kmods
}
reload_new_service_body() {
	require_ambient_control
	local bundle

	prepare_paths
	start_stack

	# Initially no user services
	atf_check -s exit:0 -o not-match:"newbie" \
	    switchboardctl status

	# Add a new bundle
	bundle=$(create_user_bundle "NewApp" "org.test.new" "newbie" \
	    "org.test.new.svc")
	sed -i '' -e 's/ipc = \[[^]]*\];/boot = true;/' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/newbie.unit/Unit.ucl"

	# Reload.  The reply summary is "reload: N bundles, M new, ..."
	# (supervisor_reload); one new service means "1 new".
	atf_check -s exit:0 -o match:"1 new" \
	    switchboardctl reload

	wait_for_file "${WORK}/newbie.ready" 5
	atf_check -s exit:0 -o match:"org.test.new/newbie.*running" \
	    switchboardctl status
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
	require_capsule_stack_kmods
}
reload_remove_service_body() {
	require_ambient_control
	local bundle

	prepare_paths
	bundle=$(create_user_bundle "Removable" "org.test.rm" "rmd" \
	    "org.test.rm.svc")
	sed -i '' -e 's/ipc = \[[^]]*\];/boot = true;/' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/rmd.unit/Unit.ucl"

	start_stack
	wait_for_file "${WORK}/rmd.ready" 5

	# Remove the bundle (user bundle lives in USER_APPS_DIR)
	rm -rf "${USER_APPS_DIR}/Removable.cap"

	# Reload.  switchboardctl prints a summary to stdout, so -o ignore is
	# required (atf_check defaults to -o empty).
	atf_check -s exit:0 -o ignore \
	    switchboardctl reload

	# The runtime is no longer running.
	sleep 1
	atf_check -s exit:0 -o not-match:"org.test.rm/rmd.*running" \
	    switchboardctl status
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
	require_capsule_stack_kmods
}
missing_system_bundle_optional_body() {
	require_ambient_control
	prepare_paths
	# Remove the system dir
	rmdir "${APPS_DIR}" 2>/dev/null || true

	start_stack
	atf_check -s exit:0 -o match:"switchboard: running" \
	    switchboardctl status
}
missing_system_bundle_optional_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: switchboardctl bundles command
# ---------------------------------------------------------------
atf_test_case bundles_list cleanup
bundles_list_head() {
	atf_set "descr" "switchboardctl bundles lists registered bundles"
}
bundles_list_body() {
	# This doesn't need a running switchboard — it scans directories directly.
	# Scratch space must live in the kyua work directory: the source
	# directory may be a read-only medium.
	TMPDIR=${PWD}/work.$$
	mkdir -p "${TMPDIR}"

	atf_check -s exit:0 -o match:"System bundles" \
	    switchboardctl bundles
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
	require_capsule_stack_kmods mac_capability_identity
	atf_set "timeout" "60"
}
dtrace_probes_body() {
	require_ambient_control
	local bundle i switchboard_pid

	prepare_paths

	# USDT -Z accepts an initially unmatched description but does not attach
	# it retroactively when a provider registers.  Start an empty stack first,
	# then bind to the exact live provider PIDs.  The startup probes have
	# already fired, so validate their registered schema with dtrace -l; the
	# capability probes below are exercised by a subsequent reload.
	start_stack
	switchboard_pid=
	i=0
	while [ -z "$switchboard_pid" ] && [ "$i" -lt 100 ]; do
		switchboard_pid=$(sed -n \
		    's/.*bootstrap: started switchboard pid \([0-9][0-9]*\).*/\1/p' \
		    "$logfile" 2>/dev/null | tail -1)
		if [ -n "$switchboard_pid" ] &&
		    ! kill -0 "$switchboard_pid" 2>/dev/null; then
			switchboard_pid=
		fi
		i=$((i + 1))
		[ -n "$switchboard_pid" ] || sleep 0.1
	done
	if [ -z "$switchboard_pid" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "could not identify the live switchboard provider"
	fi
	atf_check -s exit:0 -o match:'startup-begin' \
	    dtrace -l -n "switchboard${switchboard_pid}:::startup-begin"
	atf_check -s exit:0 -o match:'startup-done' \
	    dtrace -l -n "switchboard${switchboard_pid}:::startup-done"

	dtrace -n 'BEGIN { printf("CONSUMER_READY\n"); }' \
	    -n "switchboard${switchboard_pid}:::cap-mint { printf(\"SVC_CAP %s %s %d\\n\", copyinstr(arg0), copyinstr(arg1), arg2); }" \
	    -n "capsule${daemon_pid}:::mint-system { printf(\"SYSTEM 0x%x %d\\n\", arg0, arg1); }" \
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
	    "capabilities { system = [\"kldload\"]; }")
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/traced.unit/Unit.ucl"
	atf_check -s exit:0 -o ignore \
	    switchboardctl reload
	if ! wait_for_file "${WORK}/traced.ready" 5; then
		cat "$logfile" 2>/dev/null
		atf_fail "traced service did not become ready"
	fi

	# Wait until every expected probe record is visible, or until the
	# consumer exits.  This provides a bounded, event-based completion point.
	i=0
	while [ "$i" -lt 100 ]; do
		if grep -q 'SYSTEM 0x1 0' "${WORK}/dtrace.out" 2>/dev/null &&
		    grep -q 'SVC_CAP org.test.trace/traced system 0' \
		    "${WORK}/dtrace.out" 2>/dev/null; then
			break
		fi
		kill -0 "${DTRACE_PID}" 2>/dev/null || break
		i=$((i + 1))
		sleep 0.1
	done
	if ! grep -q 'SYSTEM 0x1 0' "${WORK}/dtrace.out" 2>/dev/null ||
	    ! grep -q 'SVC_CAP org.test.trace/traced system 0' \
	    "${WORK}/dtrace.out" 2>/dev/null; then
		cat "${WORK}/dtrace.err" >&2
		cat "${WORK}/dtrace.out" >&2
		atf_fail "capability orchestration probes did not all fire"
	fi
	kill -INT "${DTRACE_PID}" 2>/dev/null || true
	wait "${DTRACE_PID}" 2>/dev/null || true
	DTRACE_PID=
	rm -f "${WORK}/dtrace.pid"

	atf_check -s exit:0 -o match:"SYSTEM 0x1 0" \
	    cat "${WORK}/dtrace.out"
	atf_check -s exit:0 -o match:"SVC_CAP org.test.trace/traced system 0" \
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
	require_capsule_stack_kmods
}
reload_changed_bundle_body() {
	require_ambient_control
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
	    switchboardctl reload

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
# Test: Reload refuses to replace a core unit
# ---------------------------------------------------------------
atf_test_case reload_changed_core_refused cleanup
reload_changed_core_refused_head() {
	atf_set "descr" "Reload leaves a running core unit unchanged"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
reload_changed_core_refused_body() {
	require_ambient_control
	local bundle unit

	prepare_paths
	bundle=$(create_system_bundle "CoreMorph" "org.test.core-morph" \
	    "coremorphd" "org.test.core-morph.svc" \
	    'management = "core"; restart = "never";')
	unit="${bundle}/Units/coremorphd.unit/Unit.ucl"
	sed -i '' -e 's/ipc = \[[^]]*\]; //' \
	    -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' \
	    "$unit"

	start_stack
	wait_for_file "${WORK}/coremorphd.ready" 5

	# Change launch policy on disk.  The registry sees the new manifest, but
	# a running core unit belongs to the booted system generation and must not
	# be restarted or have its in-memory manifest replaced.
	cat >"$unit" <<UCL
directories = ["${WORK}"];
activation { boot = true; }
management = "core";
restart = "always";
arguments = ["compat-ready"];
UCL

	atf_check -s exit:0 -o match:"0 changed" \
	    switchboardctl reload
	atf_check -s exit:0 -o ignore grep -F \
	    "management class core: org.test.core-morph/coremorphd cannot be changed at runtime" \
	    "$logfile"
	if grep -Fq \
	    "restarting changed service 'org.test.core-morph/coremorphd'" \
	    "$logfile"; then
		atf_fail "reload restarted a core service"
	fi
	atf_check -s exit:0 \
	    -o match:"org.test.core-morph/coremorphd.*running" \
	    switchboardctl status
}
reload_changed_core_refused_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Stop already-stopped service returns EALREADY
# ---------------------------------------------------------------
atf_test_case stop_already_stopped cleanup
stop_already_stopped_head() {
	atf_set "descr" "Stop on already-stopped service returns error"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
stop_already_stopped_body() {
	require_ambient_control
	local bundle

	prepare_paths
	bundle=$(create_system_bundle "Brief" "org.test.brief" "briefd" \
	    "org.test.brief.svc")
	sed -i '' -e 's/ipc = \[[^]]*\]; //' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/briefd.unit/Unit.ucl"

	start_stack
	wait_for_file "${WORK}/briefd.ready" 5

	# Stop it once (switchboardctl prints "stop: ... stopping" -> -o ignore).
	atf_check -s exit:0 -o ignore \
	    switchboardctl stop "org.test.brief/briefd"

	sleep 1

	# Stop it again — should fail
	atf_check -s not-exit:0 -o ignore -e ignore \
	    switchboardctl stop "org.test.brief/briefd"
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
	require_capsule_stack_kmods
}
coalition_kill_on_timeout_body() {
	require_ambient_control
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
	switchboardctl stop "org.test.stubborn/stubbornd"

	# Wait for stop_timeout + SIGKILL + coalition terminate
	sleep 4

	# Service should be dead
	if [ -f "${WORK}/stubbornd.pid" ]; then
		atf_check -s not-exit:0 -e ignore \
		    kill -0 "$(cat ${WORK}/stubbornd.pid)"
	fi

	# Log should show the escalation.  With a coalition the kernel escalates
	# SIGTERM->SIGKILL after stop_timeout and switchboard logs the exit as
	# "killed by signal 9"; without one, switchboard's own stop-kill timer logs
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
	require_capsule_stack_kmods
}
on_demand_crash_relaunch_body() {
	require_ambient_control
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
	# single exec from switchboard, so the CAP_CLOEXEC_ONCE bootstrap
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
	    switchboardctl status

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
	    switchboardctl status

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
	require_capsule_stack_kmods
}
multi_binary_bundle_activation_body() {
	require_ambient_control
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
	    switchboardctl status
	atf_check -s exit:0 -o not-match:'org.test.multibin/lazyd.*running' \
	    switchboardctl status

	run_lookup_client "${endpoint}" 15 ||
	    atf_fail "lookup did not activate named binary"
	wait_for_file "${WORK}/lazyd.ready" 10 ||
	    atf_fail "named binary did not report ready"
	atf_check -s exit:0 -o match:'org.test.multibin/lazyd.*running' \
	    switchboardctl status
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
	require_capsule_stack_kmods
}
component_factory_names_are_internal_body() {
	local endpoint kind

	prepare_paths
	find_capd_service_fixture
	build_lookup_client
	for kind in filesystem network crypto; do
		case "${kind}" in
		filesystem) endpoint="system.Filesystem" ;;
		network) endpoint="system.Network" ;;
		crypto) endpoint="system.Crypto" ;;
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
	for endpoint in system.Filesystem system.Network \
	    system.Crypto
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
	atf_add_test_case reload_changed_core_refused
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
	atf_add_test_case folder_watch_loads_and_unloads
	atf_add_test_case folder_watch_coalesces_bursts
	atf_add_test_case run_live_markers_follow_units
	atf_add_test_case run_groups_markers_follow_membership
	atf_add_test_case partial_system_install_is_admitted_when_complete
	atf_add_test_case broken_new_system_bundle_does_not_block_installs
	atf_add_test_case registered_system_bundle_survives_half_written_upgrade
	atf_add_test_case registered_apps_bundle_survives_half_written_upgrade
	atf_add_test_case conflicting_user_bundle_is_quarantined_not_fatal
	atf_add_test_case vanished_system_root_retains_registry
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
	require_capsule_stack_kmods
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
	require_capsule_stack_kmods
}
multiple_provides_secondary_activation_body() {
	require_ambient_control
	local bundle first lookup_pid second p1 p2

	prepare_paths
	build_lookup_client
	find_capd_service_fixture
	first="org.test.multi.primary"
	second="org.test.multi.secondary"
	bundle=$(make_svc_bin user multi-provider \
	    "activation { ipc = [\"${first}\", \"${second}\"]; }
resolvable_by = [\"user\"];
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
	    switchboardctl status
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
	require_capsule_stack_kmods
}
multiple_provides_failure_isolated_body() {
	local bundle first lookup_pid second

	prepare_paths
	build_lookup_client
	find_capd_service_fixture
	first="org.test.partial.primary"
	second="org.test.partial.secondary"
	bundle=$(make_svc_bin user partial-provider \
	    "activation { ipc = [\"${first}\", \"${second}\"]; }
resolvable_by = [\"user\"];
arguments = [\"partial-provider\", \"${first}\",
		    \"${WORK}/partial-ready.out\"];
restart = \"never\";" "${capd_service_fixture}")

	start_stack
	# ipc activation is demand-driven; trigger the primary name before waiting
	# for the provider to run and reject its incomplete provides set.
	run_lookup_client "${first}" 10 &
	lookup_pid=$!
	wait_for_file "${WORK}/partial-ready.out" 5 ||
	    atf_fail "provider did not report its rejected readiness"
	wait "${lookup_pid}" || true
	atf_check -s exit:0 -o match:'process_ready=0' \
	    grep process_ready "${WORK}/partial-ready.out"
	atf_check -s exit:0 -o match:'ready_errno=92' \
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
	require_capsule_stack_kmods
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
		atf_fail "switchboard did not cancel the crashed requester's token"
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
	require_capsule_stack_kmods
}
reload_noop_body() {
	require_ambient_control
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
	    switchboardctl reload

	# The already-running service is untouched by the no-op reload.
	atf_check -s exit:0 -o match:"org.test.steady/steadyd.*running" \
	    switchboardctl status
}
reload_noop_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Reload-added service is attributed by=reload
# ---------------------------------------------------------------
# Stage a boot-activated SYSTEM bundle OUTSIDE the install roots, so a test
# can install it piecemeal the way pkg(8) extracts: directory first, files
# after.  Prints the staged bundle directory.
stage_system_bundle()
{
	local name="$1" bid="$2" prog="$3" dir

	dir="${WORK}/stage/${name}.cap"
	mkdir -p "${WORK}/stage"
	write_test_bundle "$dir" "$bid" "$prog" "" \
	    "activation { boot = true; }"
	build_ready_svc
	cp ready_svc "${dir}/Units/${prog}.unit/bin/${prog}"
	chmod 755 "${dir}/Units/${prog}.unit/bin/${prog}"
	printf 'arguments = ["compat-ready"];\n' >> \
	    "$dir/Units/$prog.unit/Unit.ucl"
	echo "$dir"
}

# A SYSTEM bundle caught half extracted (its directory and Bundle.ucl exist,
# its units do not) must not fail the rescan for good: it is quarantined and
# the settled retry admits it once whole -- with no further folder event and
# no explicit reload.  Files below Units/ are two levels down and invisible to
# the watch, so only the retry can admit them.
atf_test_case partial_system_install_is_admitted_when_complete cleanup
partial_system_install_is_admitted_when_complete_head() {
	atf_set "descr" "A System bundle caught mid-extraction is quarantined, retried, and admitted once its units arrive (no explicit reload)"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
partial_system_install_is_admitted_when_complete_body() {
	local stage dst

	prepare_paths
	export SWITCHBOARD_REGISTRY_WATCH_SETTLE=1
	start_stack
	wait_for_log 'registry: watching install folder' ||
	    atf_fail "install folders are not being watched"
	stage=$(stage_system_bundle "Slow" "org.test.slow" "slowd")
	dst="${APPS_DIR}/Slow.cap"

	# Step 1: directory + Bundle.ucl + an EMPTY Units/ (root and bundle-dir
	# events fire; the scan finds no unit and rejects the bundle).
	mkdir "$dst"; cp "$stage/Bundle.ucl" "$dst/"; mkdir "$dst/Units"
	wait_for_log "bundle_registry: SYSTEM bundle '${dst}' invalid" ||
	    atf_fail "the half-written bundle was not rejected"
	wait_for_log "bundle_registry: quarantined SYSTEM bundle '${dst}'" ||
	    atf_fail "a NEW system bundle was not quarantined (it failed the whole scan)"
	wait_for_log 'registry: 1 bundle\(s\) quarantined; rescanning in 1s \(retry 1/' ||
	    atf_fail "no settled retry was armed for the quarantined bundle"
	grep -q 'rescan failed' "$logfile" &&
	    atf_fail "a new System bundle failed the whole rescan"
	pgrep -f '[/ ]slowd( |$)' >/dev/null && atf_fail "slowd ran from a half-written bundle"

	# Step 2: the units arrive BELOW Units/ -- no watched directory changes.
	cp -R "$stage/Units/slowd.unit" "$dst/Units/"
	wait_for_file "${WORK}/slowd.ready" 12 ||
	    atf_fail "the completed bundle was not admitted by the settled retry"
	pgrep -f '[/ ]slowd( |$)' >/dev/null || atf_fail "slowd is not running"
	[ -e "${WORK}/Run/live/Slow" ] || atf_fail "no Run/live marker for the admitted bundle"
	# The admission came from the retry, not from an explicit reload.
	grep -q "reload: .*switchboardctl" "$logfile" && atf_fail "an explicit reload happened"
	wait_for_log "bundle_registry: loaded 'Slow.cap'" || atf_fail "no load record for Slow"
}
partial_system_install_is_admitted_when_complete_cleanup() {
	cleanup_common
}

# A permanently broken NEW System bundle is quarantined with a bounded retry
# budget; it never blocks a later install of a valid bundle, and the retries
# stop at the budget instead of rescanning forever.
atf_test_case broken_new_system_bundle_does_not_block_installs cleanup
broken_new_system_bundle_does_not_block_installs_head() {
	atf_set "descr" "A malformed new System bundle is quarantined (bounded retries) and does not block other installs"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
broken_new_system_bundle_does_not_block_installs_body() {
	local bad bundle i

	prepare_paths
	export SWITCHBOARD_REGISTRY_WATCH_SETTLE=1
	start_stack
	wait_for_log 'registry: watching install folder' ||
	    atf_fail "install folders are not being watched"
	bad="${APPS_DIR}/Broken.cap"
	mkdir "$bad"; printf 'this is not ucl {{{\n' > "$bad/Bundle.ucl"
	wait_for_log "bundle_registry: quarantined SYSTEM bundle '${bad}'" ||
	    atf_fail "the broken new system bundle was not quarantined"
	# A valid user bundle dropped in now must load despite the broken one.
	bundle=$(create_user_bundle "Fine" "org.test.fine" "fined" "org.test.fine.svc")
	sed -i '' -e 's/ipc = \[[^]]*\];/boot = true;/' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/fined.unit/Unit.ucl"
	wait_for_file "${WORK}/fined.ready" 12 ||
	    atf_fail "a valid install was blocked by an unrelated broken System bundle"
	[ -e "${WORK}/Run/live/Fine" ] || atf_fail "no Run/live marker for Fine"
	[ -e "${WORK}/Run/live/Broken" ] && atf_fail "a quarantined bundle got a Run/live marker"
	# The retry budget is bounded: the last retry is logged, no further one.
	i=0; while ! grep -q 'retry 8/8' "$logfile" && [ $i -lt 200 ]; do i=$((i+1)); sleep 0.1; done
	grep -q 'retry 8/8' "$logfile" || atf_fail "the retry budget was never exhausted (no 8/8)"
	sleep 3
	grep -q 'retry 9/8' "$logfile" && atf_fail "retries continued past the budget"
	pgrep -f '[/ ]fined( |$)' >/dev/null || atf_fail "fined is not running"
}
broken_new_system_bundle_does_not_block_installs_cleanup() {
	cleanup_common
}

# An already-registered SYSTEM bundle caught half written (an in-place upgrade
# in progress) must NOT be stopped: the rescan fails, the previous registry and
# the running unit are retained, and the settled retry picks up the completed
# upgrade with no further folder event.
atf_test_case registered_system_bundle_survives_half_written_upgrade cleanup
registered_system_bundle_survives_half_written_upgrade_head() {
	atf_set "descr" "A registered System bundle caught mid-upgrade keeps running; the retry admits the finished upgrade"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
registered_system_bundle_survives_half_written_upgrade_body() {
	local bundle pid unit loads0 i

	prepare_paths
	export SWITCHBOARD_REGISTRY_WATCH_SETTLE=1
	bundle=$(create_system_bundle "Keep" "org.test.keep" "keepd" "org.test.keep.svc")
	sed -i '' -e 's/ipc = \[[^]]*\];//' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/keepd.unit/Unit.ucl"
	start_stack
	wait_for_file "${WORK}/keepd.ready" 10 || atf_fail "keepd did not start"
	pid=$(pgrep -f '[/ ]keepd( |$)' | head -1)
	[ -n "$pid" ] || atf_fail "cannot find keepd pid"
	unit="${bundle}/Units/keepd.unit"

	# Half-written upgrade: the unit manifest is momentarily gone (below the
	# watched level), and a bundle-directory write triggers the rescan.
	loads0=$(grep -c 'bundle_registry: [0-9]* bundles loaded' "$logfile")
	mv "$unit/Unit.ucl" "$unit/Unit.ucl.upgrading"
	touch "$bundle/.upgrade"; rm -f "$bundle/.upgrade"
	wait_for_log "bundle_registry: SYSTEM bundle '${bundle}' invalid" ||
	    atf_fail "the half-written registered bundle was not detected"
	wait_for_log "SYSTEM bundle '${bundle}' unreadable mid-rescan; previous registration retained" ||
	    atf_fail "the half-written registered System bundle was not retained"
	wait_for_log 'registry: 1 bundle\(s\) quarantined; rescanning in 1s \(retry 1/' ||
	    atf_fail "no settled retry was armed for the stale registration"
	grep -q "quarantined SYSTEM bundle '${bundle}'" "$logfile" &&
	    atf_fail "a REGISTERED system bundle was quarantined (its unit would be stopped)"
	grep -q "reload: stopping removed service 'org.test.keep/keepd'" "$logfile" &&
	    atf_fail "the unit was stopped during its own upgrade"
	kill -0 "$pid" 2>/dev/null || atf_fail "keepd was stopped by a half-written upgrade"
	[ -e "${WORK}/Run/live/Keep" ] || atf_fail "Run/live marker lost during the upgrade"

	# The upgrade completes below the watched level: only the retry sees it
	# (the stale registration reads whole again: loaded without [stale]).
	mv "$unit/Unit.ucl.upgrading" "$unit/Unit.ucl"
	i=0; while ! grep -q "loaded 'Keep.cap' (1 services) \[system\]$" "$logfile" && [ $i -lt 120 ]; do i=$((i+1)); sleep 0.1; done
	grep -q "loaded 'Keep.cap' (1 services) \[system\]$" "$logfile" ||
	    atf_fail "the completed upgrade was never read whole by the settled retry"
	sleep 2
	grep -q 'retry 8/8' "$logfile" && atf_fail "retries ran to the budget although the upgrade completed"
	kill -0 "$pid" 2>/dev/null || atf_fail "keepd was restarted/stopped by the completed upgrade"
	[ -e "${WORK}/Run/live/Keep" ] || atf_fail "Run/live marker lost after the upgrade"
	grep -q "bundle_registry: loaded 'Keep.cap'" "$logfile" || atf_fail "Keep never (re)loaded"
}
registered_system_bundle_survives_half_written_upgrade_cleanup() {
	cleanup_common
}

# A registered APPS bundle caught half written keeps its previous
# registration (stale) exactly like a System one: its unit keeps running with
# the same pid, its Run/live marker stays, and the settled retry admits the
# finished upgrade.  (Before: quarantined -> unit stopped, marker dropped.)
atf_test_case registered_apps_bundle_survives_half_written_upgrade cleanup
registered_apps_bundle_survives_half_written_upgrade_head() {
	atf_set "descr" "A registered Apps bundle caught mid-upgrade keeps running on its stale registration; the retry admits the finished upgrade"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
registered_apps_bundle_survives_half_written_upgrade_body() {
	local bundle pid unit loads0 i

	prepare_paths
	export SWITCHBOARD_REGISTRY_WATCH_SETTLE=1
	bundle=$(create_user_bundle "Keepu" "org.test.keepu" "keepud" "org.test.keepu.svc")
	sed -i '' -e 's/ipc = \[[^]]*\];/boot = true;/' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/keepud.unit/Unit.ucl"
	start_stack
	wait_for_file "${WORK}/keepud.ready" 10 || atf_fail "keepud did not start"
	pid=$(pgrep -f '[/ ]keepud( |$)' | head -1)
	[ -n "$pid" ] || atf_fail "cannot find keepud pid"
	unit="${bundle}/Units/keepud.unit"
	loads0=$(grep -c 'bundle_registry: [0-9]* bundles loaded' "$logfile")

	mv "$unit/Unit.ucl" "$unit/Unit.ucl.upgrading"
	touch "$bundle/.upgrade"; rm -f "$bundle/.upgrade"
	wait_for_log "bundle '${bundle}' unreadable mid-rescan; previous registration retained" ||
	    atf_fail "the half-written registered Apps bundle was not retained"
	grep -q "quarantined bundle '${bundle}'" "$logfile" &&
	    atf_fail "a REGISTERED Apps bundle was quarantined (its unit would be stopped)"
	grep -q "reload: stopping removed service 'org.test.keepu/keepud'" "$logfile" &&
	    atf_fail "the unit was stopped during its own upgrade"
	kill -0 "$pid" 2>/dev/null || atf_fail "keepud was stopped by a half-written upgrade"
	[ -e "${WORK}/Run/live/Keepu" ] || atf_fail "Run/live marker lost during the upgrade"
	wait_for_log 'registry: 1 bundle\(s\) quarantined; rescanning in 1s \(retry 1/' ||
	    atf_fail "no settled retry was armed for the stale registration"

	mv "$unit/Unit.ucl.upgrading" "$unit/Unit.ucl"
	i=0; while ! grep -q "loaded 'Keepu.cap' (1 services)$" "$logfile" && [ $i -lt 120 ]; do i=$((i+1)); sleep 0.1; done
	grep -q "loaded 'Keepu.cap' (1 services)$" "$logfile" ||
	    atf_fail "the completed upgrade was never read whole by the retry"
	sleep 1
	kill -0 "$pid" 2>/dev/null || atf_fail "keepud was restarted by an unchanged manifest"
	[ -e "${WORK}/Run/live/Keepu" ] || atf_fail "Run/live marker lost after the upgrade"
}
registered_apps_bundle_survives_half_written_upgrade_cleanup() {
	cleanup_common
}

# A user bundle that conflicts with the registry (here: it provides a name a
# System bundle already provides) is quarantined, never fatal: the plane
# boots, the System unit runs, the user bundle is left out with the reason
# logged.  (Before: the scan failed and boot aborted.)
atf_test_case conflicting_user_bundle_is_quarantined_not_fatal cleanup
conflicting_user_bundle_is_quarantined_not_fatal_head() {
	atf_set "descr" "A user bundle whose provided name collides with a System bundle is quarantined at boot instead of aborting switchboard"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
conflicting_user_bundle_is_quarantined_not_fatal_body() {
	local sysb usrb

	prepare_paths
	sysb=$(create_system_bundle "Owner" "org.test.owner" "ownerd" "org.test.contended.svc")
	usrb=$(create_user_bundle "Squatter" "org.test.squatter" "squatterd" "org.test.contended.svc")
	start_stack
	wait_for_file "${WORK}/ownerd.ready" 10 || atf_fail "the System unit did not start (boot aborted?)"
	wait_for_log "quarantined bundle '${usrb}'" ||
	    { grep -E "bundle_registry|Squatter" "$logfile" | head -20; atf_fail "the conflicting user bundle was not quarantined"; }
	grep -q "quarantined bundle '${usrb}' (duplicate provided name)" "$logfile" ||
	    { grep -E "Squatter" "$logfile" | head -10; atf_fail "quarantined for a reason other than the duplicate provided name"; }
	grep -q "bundle registry init failed" "$logfile" && atf_fail "boot was aborted by a user bundle"
	sleep 2
	pgrep -f '[/ ]squatterd( |$)' >/dev/null && atf_fail "the quarantined bundle's unit ran"
	[ -e "${WORK}/Run/live/Squatter" ] && atf_fail "a quarantined bundle got a Run/live marker"
	[ -e "${WORK}/Run/live/Owner" ] || atf_fail "the System unit has no marker"
}
conflicting_user_bundle_is_quarantined_not_fatal_cleanup() {
	cleanup_common
}

# The System root disappearing under a running plane (renamed away) must not
# be read as "no System bundles": the rescan is retained, units keep running,
# and the root's return is picked up.
atf_test_case vanished_system_root_retains_registry cleanup
vanished_system_root_retains_registry_head() {
	atf_set "descr" "A System install root that vanishes at runtime retains the previous registry instead of unloading every System unit"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
vanished_system_root_retains_registry_body() {
	local bundle pid

	prepare_paths
	export SWITCHBOARD_REGISTRY_WATCH_SETTLE=1
	bundle=$(create_system_bundle "Rooted" "org.test.rooted" "rootedd" "org.test.rooted.svc")
	sed -i '' -e 's/ipc = \[[^]]*\];//' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/rootedd.unit/Unit.ucl"
	start_stack
	wait_for_file "${WORK}/rootedd.ready" 10 || atf_fail "rootedd did not start"
	pid=$(pgrep -f '[/ ]rootedd( |$)' | head -1)
	[ -n "$pid" ] || atf_fail "cannot find rootedd pid"

	mv "${APPS_DIR}" "${APPS_DIR}.gone"
	wait_for_log "disappeared; previous registry retained" ||
	    atf_fail "the vanished System root was not treated as a retained rescan"
	kill -0 "$pid" 2>/dev/null || atf_fail "a System unit was stopped because its root vanished"
	grep -q "reload: stopping removed service 'org.test.rooted/rootedd'" "$logfile" &&
	    atf_fail "the unit was marked removed"

	mv "${APPS_DIR}.gone" "${APPS_DIR}"
	wait_for_log 'registry: install folders changed; reloading' || true
	sleep 3
	kill -0 "$pid" 2>/dev/null || atf_fail "rootedd was restarted when the root returned"
	[ -e "${WORK}/Run/live/Rooted" ] || atf_fail "Run/live marker missing after the root returned"
}
vanished_system_root_retains_registry_cleanup() {
	mv "${APPS_DIR}.gone" "${APPS_DIR}" 2>/dev/null || true
	cleanup_common
}

atf_test_case folder_watch_loads_and_unloads cleanup
folder_watch_loads_and_unloads_head() {
	atf_set "descr" "The install-folder watch loads a dropped-in bundle and unloads a removed one with no explicit reload (container model)"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
folder_watch_loads_and_unloads_body() {
	local bundle

	prepare_paths
	# Short quiescence so the test does not wait on the production settle.
	export SWITCHBOARD_REGISTRY_WATCH_SETTLE=1
	start_stack
	wait_for_log 'registry: watching install folder' ||
	    atf_fail "install folders are not being watched"

	# Drop a bundle into the user install root: NO switchboardctl reload.
	bundle=$(create_user_bundle "Auto" "org.test.auto" "autod" \
	    "org.test.auto.svc")
	sed -i '' -e 's/ipc = \[[^]]*\];/boot = true;/' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/autod.unit/Unit.ucl"
	wait_for_log 'registry: install folders changed; reloading' ||
	    atf_fail "the folder watch did not trigger a reload"
	wait_for_file "${WORK}/autod.ready" 10
	# Units run as "ld-elf.so.1 -f <fd> <program>": match the command line.
	pgrep -f '[/ ]autod( |$)' >/dev/null || atf_fail "autod is not running after the watch-triggered load"
	[ -e "${WORK}/Run/live/Auto" ] || atf_fail "no Run/live marker for the loaded bundle"

	# Remove the bundle: the watch must unload the unit, again with no reload.
	rm -rf "${bundle}"
	wait_for_log "reload: stopping removed service 'org.test.auto/autod'" ||
	    atf_fail "the removed bundle was not unloaded by the folder watch"
	wait_for_log 'reload: 1 services marked for removal' ||
	    atf_fail "removal was not completed"
	i=0; while pgrep -f '[/ ]autod( |$)' >/dev/null && [ $i -lt 100 ]; do i=$((i+1)); sleep 0.1; done
	pgrep -f '[/ ]autod( |$)' >/dev/null && atf_fail "autod still running after its bundle was removed"
	sleep 1
	[ ! -e "${WORK}/Run/live/Auto" ] || atf_fail "Run/live marker survived removal"
}
folder_watch_loads_and_unloads_cleanup() {
	cleanup_common
}

# A burst of root writes (several bundles dropped in quick succession) settles
# into ONE reload, and a write during the settle window extends it.
atf_test_case folder_watch_coalesces_bursts cleanup
folder_watch_coalesces_bursts_head() {
	atf_set "descr" "A burst of install-root changes coalesces into a single settled reload"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
folder_watch_coalesces_bursts_body() {
	local u x n

	prepare_paths
	export SWITCHBOARD_REGISTRY_WATCH_SETTLE=2
	start_stack
	wait_for_log 'registry: watching install folder' ||
	    atf_fail "install folders are not being watched"
	for x in a b c; do
		u=$(create_user_bundle "Burst$x" "org.test.burst$x" "${x}d" "org.test.burst$x.svc")
		sed -i '' -e 's/ipc = \[[^]]*\];/boot = true;/' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${u}/Units/${x}d.unit/Unit.ucl"
	done
	wait_for_log 'registry: install folders changed; reloading' ||
	    atf_fail "the folder watch did not trigger a reload"
	sleep 3
	n=$(grep -c 'registry: install folders changed; reloading' "$logfile" 2>/dev/null || echo 0)
	[ "$n" -eq 1 ] || atf_fail "expected exactly one settled reload for the burst, saw $n"
	# That single reload loaded all three bundles: every unit reports ready.
	for x in a b c; do
		wait_for_file "${WORK}/${x}d.ready" 10
		[ -e "${WORK}/${x}d.ready" ] || atf_fail "unit ${x}d of the burst never came up"
	done
}
folder_watch_coalesces_bursts_cleanup() {
	cleanup_common
}

# The Run/live markers (the "running" half of the reconcile's live set) follow a
# unit through load, an asynchronous relaunch, and removal.
atf_test_case run_live_markers_follow_units cleanup
run_live_markers_follow_units_head() {
	atf_set "descr" "Run/live markers appear on load, survive a relaunch, and vanish on removal"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
run_live_markers_follow_units_body() {
	local bundle pid i

	prepare_paths
	export SWITCHBOARD_REGISTRY_WATCH_SETTLE=1
	start_stack
	i=0; while [ ! -d "${WORK}/Run/live" ] && [ $i -lt 50 ]; do i=$((i+1)); sleep 0.1; done
	if [ ! -d "${WORK}/Run/live" ]; then
		echo "--- diagnostics: WORK=${WORK}"; ls -la "${WORK}" "${WORK}/Run" 2>&1
		echo "--- fixture log (startup/registry/reclaim lines):"
		grep -aE 'startup:|registry:|reclaim:|SWITCHBOARD_RUN_DIR|switchboard started' "$logfile" 2>&1 | head -20
		echo "--- env seen by the harness:"; env | grep -E '^SWITCHBOARD_' 
		atf_fail "Run/live was not prepared at startup"
	fi
	bundle=$(create_user_bundle "Mark" "org.test.mark" "markd" "org.test.mark.svc")
	sed -i '' -e 's/ipc = \[[^]]*\];/boot = true;/' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' -e '/^restart = /d' "${bundle}/Units/markd.unit/Unit.ucl"
	# Relaunch on any exit, and no signal shield so the test may kill it.
	printf 'restart = "always";\nprotect = [];\n' >> "${bundle}/Units/markd.unit/Unit.ucl"
	wait_for_file "${WORK}/markd.ready" 10
	[ -e "${WORK}/Run/live/Mark" ] || atf_fail "no marker for the loaded bundle"
	# Kill the unit: restart=always relaunches it asynchronously; the marker
	# must be re-published for the relaunched unit, not lost.
	pid=$(pgrep -f '[/ ]markd( |$)' | head -1)
	[ -n "$pid" ] || atf_fail "cannot find markd pid"
	rm -f "${WORK}/markd.ready"
	kill -KILL "$pid" || atf_fail "kill -KILL $pid denied (shield?): rc=$?"
	# restart=always relaunches it: a NEW pid reports ready again.
	wait_for_file "${WORK}/markd.ready" 10
	i=0; while [ $i -lt 100 ]; do
		new=$(pgrep -f '[/ ]markd( |$)' | head -1)
		[ -n "$new" ] && [ "$new" != "$pid" ] && break
		i=$((i+1)); sleep 0.1
	done
	if [ -z "${new:-}" ] || [ "$new" = "$pid" ]; then
		echo "--- diagnostics: old pid $pid, new '${new:-}'"; ps -o pid,stat,command -p "$pid" 2>&1
		grep -aE 'markd|restart' "$logfile" | tail -12
		atf_fail "markd was not relaunched"
	fi
	sleep 1
	[ -e "${WORK}/Run/live/Mark" ] || atf_fail "marker lost across the relaunch"
	# Remove the bundle: the watch unloads it and the marker goes with it.
	rm -rf "${bundle}"
	wait_for_log "reload: stopping removed service 'org.test.mark/markd'" ||
	    atf_fail "the removed bundle was not unloaded"
	sleep 2
	[ ! -e "${WORK}/Run/live/Mark" ] || atf_fail "marker survived removal"
}
run_live_markers_follow_units_cleanup() {
	cleanup_common
}

# Run/groups markers publish the INSTALLED-claimed group containers: a marker
# exists while any installed bundle declares the group, and goes when the last
# member is removed (the reconcile's live view for Data/Shared/<group>/).
atf_test_case run_groups_markers_follow_membership cleanup
run_groups_markers_follow_membership_head() {
	atf_set "descr" "Run/groups/<group> exists while any installed bundle claims the group"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
run_groups_markers_follow_membership_body() {
	local a b i

	prepare_paths
	export SWITCHBOARD_REGISTRY_WATCH_SETTLE=1
	start_stack
	i=0; while [ ! -d "${WORK}/Run/groups" ] && [ $i -lt 50 ]; do i=$((i+1)); sleep 0.1; done
	[ -d "${WORK}/Run/groups" ] || atf_fail "Run/groups was not prepared at startup"
	[ ! -e "${WORK}/Run/groups/test.shared" ] || atf_fail "marker for an unclaimed group"
	a=$(create_user_bundle "GroupA" "org.test.groupa" "gad" "org.test.groupa.svc")
	printf 'groups = ["test.shared"];\n' >> "${a}/Bundle.ucl"
	b=$(create_user_bundle "GroupB" "org.test.groupb" "gbd" "org.test.groupb.svc")
	printf 'groups = ["test.shared", "other.group"];\n' >> "${b}/Bundle.ucl"
	wait_for_log 'registry: install folders changed; reloading' ||
	    atf_fail "the folder watch did not trigger a reload"
	sleep 2
	[ -e "${WORK}/Run/groups/test.shared" ] || atf_fail "no marker for a claimed group"
	[ -e "${WORK}/Run/groups/other.group" ] || atf_fail "no marker for B's second group"
	rm -rf "${b}"
	# B's unit is ipc-activated (never ran), so the only observable effect of
	# its removal is the republished marker set after the settled reload.
	i=0; while [ -e "${WORK}/Run/groups/other.group" ] && [ $i -lt 100 ]; do i=$((i+1)); sleep 0.1; done
	[ ! -e "${WORK}/Run/groups/other.group" ] || atf_fail "marker survived its last member"
	[ -e "${WORK}/Run/groups/test.shared" ] || atf_fail "marker lost while A still claims the group"
	rm -rf "${a}"
	i=0; while [ -e "${WORK}/Run/groups/test.shared" ] && [ $i -lt 100 ]; do i=$((i+1)); sleep 0.1; done
	[ ! -e "${WORK}/Run/groups/test.shared" ] || atf_fail "marker survived the last member"
}
run_groups_markers_follow_membership_cleanup() {
	cleanup_common
}

atf_test_case reload_attribution cleanup
reload_attribution_head() {
	atf_set "descr" "A service launched by reload is attributed by=reload in status"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
reload_attribution_body() {
	require_ambient_control
	local bundle

	prepare_paths
	start_stack

	# Add a user bundle after startup, then reload to launch it.
	bundle=$(create_user_bundle "Late" "org.test.late" "lated" \
	    "org.test.late.svc")
	sed -i '' -e 's/ipc = \[[^]]*\];/boot = true;/' -e 's/arguments = \["compat-ready", "[^"]*"\];/arguments = ["compat-ready"];/' "${bundle}/Units/lated.unit/Unit.ucl"

	atf_check -s exit:0 -o match:"1 new" \
	    switchboardctl reload

	wait_for_file "${WORK}/lated.ready" 5

	# reload.c stamps launched_by="reload"; status shows it as by=reload.
	atf_check -s exit:0 -o match:"org.test.late/lated.*by=reload" \
	    switchboardctl status
}
reload_attribution_cleanup() {
	cleanup_common
}
