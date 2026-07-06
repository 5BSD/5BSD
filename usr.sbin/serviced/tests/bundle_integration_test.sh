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

# ---------------------------------------------------------------
# Test: System bundle boot-start
# ---------------------------------------------------------------
atf_test_case system_bundle_startup cleanup
system_bundle_startup_head() {
	atf_set "descr" "System bundle services start at boot"
	atf_set "require.user" "root"
}
system_bundle_startup_body() {
	prepare_paths
	create_system_bundle "BootTest" "org.test.boot" "bootd" \
	    "org.test.boot.svc"

	start_stack
	wait_for_file "${WORK}/bootd.ready" 5

	# Service should be running.  serviced identifies services by label,
	# which is provides[0] (libcapbundle_parse.c), not the program name.
	atf_check -s exit:0 -o match:"org.test.boot.svc.*running" \
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
}
on_demand_launch_body() {
	prepare_paths
	build_lookup_client
	create_user_bundle "LazyApp" "org.test.lazy" "lazyd" \
	    "org.test.lazy.svc" 'on_demand = true;'

	start_stack

	# Service should NOT be running yet (labelled by provides[0]).
	atf_check -s exit:0 -o not-match:"org.test.lazy.svc.*running" \
	    servicectl -s "${CTL_SOCK}" status

	# Trigger lookup from a client
	run_lookup_client "org.test.lazy.svc"

	# Now it should be running
	wait_for_file "${WORK}/lazyd.ready" 10
	atf_check -s exit:0 -o match:"org.test.lazy.svc.*running" \
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
}
on_demand_timeout_body() {
	prepare_paths
	build_lookup_client
	# Create a service that never calls service_ready()
	create_user_bundle_custom "Hang" "hangd" \
	    'bundle_id = "org.test.hang";
version = "1.0";
author = "test";
program = "hangd";
provides = ["org.test.hang.svc"];
on_demand = true;'

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
# Test: Tier-based parallel startup
# ---------------------------------------------------------------
atf_test_case tiered_startup cleanup
tiered_startup_head() {
	atf_set "descr" "Services launch in dependency order via tiers"
	atf_set "require.user" "root"
}
tiered_startup_body() {
	prepare_paths

	# Create two services: B depends on A
	create_system_bundle "Base" "org.test.base" "based" \
	    "org.test.base.svc"
	create_system_bundle_with_requires "Dep" "org.test.dep" "depd" \
	    "org.test.dep.svc" "org.test.base.svc"

	start_stack
	wait_for_file "${WORK}/based.ready" 5
	wait_for_file "${WORK}/depd.ready" 10

	# Both should be running (labelled by provides[0]).
	atf_check -s exit:0 -o match:"org.test.base.svc.*running" \
	    servicectl -s "${CTL_SOCK}" status
	atf_check -s exit:0 -o match:"org.test.dep.svc.*running" \
	    servicectl -s "${CTL_SOCK}" status

	# Base should have started before dep (check timestamps in log)
	atf_check -s exit:0 -o match:"tier 0.*launched 1" \
	    grep "tier 0" "${logfile}"
}
tiered_startup_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: servicectl stop
# ---------------------------------------------------------------
atf_test_case stop_service cleanup
stop_service_head() {
	atf_set "descr" "Stop a running service via servicectl stop"
	atf_set "require.user" "root"
}
stop_service_body() {
	prepare_paths
	create_system_bundle "StopMe" "org.test.stop" "stopd" \
	    "org.test.stop.svc"

	start_stack
	wait_for_file "${WORK}/stopd.ready" 5

	# Stop it
	atf_check -s exit:0 -o match:"stopping" \
	    servicectl -s "${CTL_SOCK}" stop "org.test.stop.svc"

	# Wait for it to actually stop
	sleep 1
	atf_check -s exit:0 -o match:"org.test.stop.svc.*stopped" \
	    servicectl -s "${CTL_SOCK}" status
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
}
reload_new_service_body() {
	prepare_paths
	start_stack

	# Initially no user services
	atf_check -s exit:0 -o not-match:"newbie" \
	    servicectl -s "${CTL_SOCK}" status

	# Add a new bundle
	create_user_bundle "NewApp" "org.test.new" "newbie" \
	    "org.test.new.svc"

	# Reload.  The reply summary is "reload: N bundles, M new, ..."
	# (supervisor_reload); one new service means "1 new".
	atf_check -s exit:0 -o match:"1 new" \
	    servicectl -s "${CTL_SOCK}" reload

	wait_for_file "${WORK}/newbie.ready" 5
	atf_check -s exit:0 -o match:"org.test.new.svc.*running" \
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
}
reload_remove_service_body() {
	prepare_paths
	create_user_bundle "Removable" "org.test.rm" "rmd" \
	    "org.test.rm.svc"

	start_stack
	wait_for_file "${WORK}/rmd.ready" 5

	# Remove the bundle (user bundle lives in USER_APPS_DIR)
	rm -rf "${USER_APPS_DIR}/Removable.cap"

	# Reload.  servicectl prints a summary to stdout, so -o ignore is
	# required (atf_check defaults to -o empty).
	atf_check -s exit:0 -o ignore \
	    servicectl -s "${CTL_SOCK}" reload

	# Service should be stopping/stopped (labelled by provides[0]).
	sleep 1
	atf_check -s exit:0 -o not-match:"org.test.rm.svc.*running" \
	    servicectl -s "${CTL_SOCK}" status
}
reload_remove_service_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Circular dependency blocked at startup
# ---------------------------------------------------------------
atf_test_case circular_dep_fatal cleanup
circular_dep_fatal_head() {
	atf_set "descr" "Circular dependency aborts serviced startup"
	atf_set "require.user" "root"
}
circular_dep_fatal_body() {
	prepare_paths

	# Create circular: A requires B, B requires A.  Distinct bundle_ids so
	# the registry keeps both bundles (and the cycle actually forms).
	create_system_bundle_with_requires "CycA" "org.test.cyc.a" "cyca" \
	    "org.test.cyc.a" "org.test.cyc.b"
	create_system_bundle_with_requires "CycB" "org.test.cyc.b" "cycb" \
	    "org.test.cyc.b" "org.test.cyc.a"

	# serviced should refuse to start (depgraph detects cycle)
	start_stack_expect_failure
	atf_check -s exit:0 -o match:"cycle detected" \
	    grep "cycle detected" "${logfile}"
}
circular_dep_fatal_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Missing system bundle directory is optional
# ---------------------------------------------------------------
atf_test_case missing_system_bundle_optional cleanup
missing_system_bundle_optional_head() {
	atf_set "descr" "Missing /Capabilities/System is optional"
	atf_set "require.user" "root"
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
	# This doesn't need a running serviced — it scans directories directly
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}"

	atf_check -s exit:0 -o match:"System bundles" \
	    servicectl bundles
}
bundles_list_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: DTrace probes fire
# ---------------------------------------------------------------
atf_test_case dtrace_probes cleanup
dtrace_probes_head() {
	atf_set "descr" "DTrace probes fire during startup and on-demand"
	atf_set "require.user" "root"
	atf_set "require.progs" "dtrace"
}
dtrace_probes_body() {
	prepare_paths
	create_system_bundle "Traced" "org.test.trace" "traced" \
	    "org.test.trace.svc"

	# Start dtrace in background
	dtrace -n 'serviced:::startup-begin { printf("BEGIN %d\n", arg0); }' \
	    -n 'serviced:::startup-done { printf("DONE %llu\n", arg0); exit(0); }' \
	    -o "${WORK}/dtrace.out" &
	DTRACE_PID=$!
	sleep 1

	start_stack
	wait_for_file "${WORK}/traced.ready" 5

	# Wait for dtrace to collect
	sleep 2
	kill ${DTRACE_PID} 2>/dev/null
	wait ${DTRACE_PID} 2>/dev/null

	atf_check -s exit:0 -o match:"BEGIN" \
	    cat "${WORK}/dtrace.out"
}
dtrace_probes_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Reload rejects cyclic dependency among new services
# ---------------------------------------------------------------
atf_test_case reload_cycle_rejected cleanup
reload_cycle_rejected_head() {
	atf_set "descr" "Reload rejects new bundles that form a dependency cycle"
	atf_set "require.user" "root"
}
reload_cycle_rejected_body() {
	prepare_paths
	start_stack

	# Add two user bundles that form a cycle: A requires B, B requires A
	create_user_bundle_custom "CycX" "cycd_x" \
	    'bundle_id = "org.test.cyc.x";
version = "1.0";
author = "test";
program = "cycd_x";
provides = ["org.test.cyc.x"];
requires = ["org.test.cyc.y"];'

	create_user_bundle_custom "CycY" "cycd_y" \
	    'bundle_id = "org.test.cyc.y";
version = "1.0";
author = "test";
program = "cycd_y";
provides = ["org.test.cyc.y"];
requires = ["org.test.cyc.x"];'

	atf_check -s exit:0 -o ignore \
	    servicectl -s "${CTL_SOCK}" reload

	# Cycle should be detected — check log
	atf_check -s exit:0 -o ignore \
	    grep "cycle detected\|dependency sort failed" "${logfile}"
}
reload_cycle_rejected_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Reload launches new services in dependency order
# ---------------------------------------------------------------
atf_test_case reload_dependency_order cleanup
reload_dependency_order_head() {
	atf_set "descr" "Reload sorts new services by dependency before launch"
	atf_set "require.user" "root"
}
reload_dependency_order_body() {
	prepare_paths
	start_stack

	# Add provider and consumer — consumer requires provider
	create_system_bundle "Provider" "org.test.prov" "provd" \
	    "org.test.prov.svc"
	create_system_bundle_with_requires "Consumer" "org.test.cons" "consd" \
	    "org.test.cons.svc" "org.test.prov.svc"

	atf_check -s exit:0 -o ignore \
	    servicectl -s "${CTL_SOCK}" reload

	sleep 1

	# Both should have been launched (reload logs "reload: launched '<label>'"
	# where label is provides[0]).
	atf_check -s exit:0 -o ignore \
	    grep "launched.*org.test.prov" "${logfile}"
	atf_check -s exit:0 -o ignore \
	    grep "launched.*org.test.cons" "${logfile}"
}
reload_dependency_order_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Changed bundle triggers service restart
# ---------------------------------------------------------------
atf_test_case reload_changed_bundle cleanup
reload_changed_bundle_head() {
	atf_set "descr" "Reload restarts service when bundle manifest changes"
	atf_set "require.user" "root"
}
reload_changed_bundle_body() {
	prepare_paths
	create_system_bundle "Morph" "org.test.morph" "morphd" \
	    "org.test.morph.svc" 'restart = "never";'

	start_stack
	wait_for_file "${WORK}/morphd.ready" 5

	# Change restart policy
	cat > "${APPS_DIR}/Morph.cap/etc/morphd.ucl" <<UCL
bundle_id = "org.test.morph";
version = "1.0";
author = "test";
program = "morphd";
provides = ["org.test.morph.svc"];
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
}
stop_already_stopped_body() {
	prepare_paths
	create_system_bundle "Brief" "org.test.brief" "briefd" \
	    "org.test.brief.svc"

	start_stack
	wait_for_file "${WORK}/briefd.ready" 5

	# Stop it once (servicectl prints "stop: ... stopping" -> -o ignore).
	atf_check -s exit:0 -o ignore \
	    servicectl -s "${CTL_SOCK}" stop "org.test.brief.svc"

	sleep 1

	# Stop it again — should fail
	atf_check -s not-exit:0 -o ignore -e ignore \
	    servicectl -s "${CTL_SOCK}" stop "org.test.brief.svc"
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
}
coalition_kill_on_timeout_body() {
	prepare_paths

	# Create a stubborn service that ignores SIGTERM
	local stubdir="${APPS_DIR}/Stubborn.cap"
	mkdir -p "${stubdir}/etc"
	mkdir -p "${stubdir}/bin"

	# UNQUOTED heredoc: ${WORK} is expanded at write time so the absolute
	# path bakes into the script (services run with a minimal env and do not
	# inherit WORK).  \$\$ stays a runtime shell variable.
	cat > "${stubdir}/bin/stubbornd" <<SVCEOF
#!/bin/sh
trap "" TERM
echo \$\$ > "${WORK}/stubbornd.pid"
while :; do sleep 1; done
SVCEOF
	chmod 755 "${stubdir}/bin/stubbornd"

	cat > "${stubdir}/etc/stubbornd.ucl" <<UCL
bundle_id = "org.test.stubborn";
version = "1.0";
author = "test";
program = "stubbornd";
provides = ["org.test.stubborn.svc"];
stop_timeout = 2;
UCL

	start_stack
	wait_for_file "${WORK}/stubbornd.pid" 5

	# Stop the service — it will ignore SIGTERM
	servicectl -s "${CTL_SOCK}" stop "org.test.stubborn.svc"

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
}
on_demand_crash_relaunch_body() {
	prepare_paths
	build_lookup_client
	build_ready_svc

	# Create a custom on-demand bundle whose service crashes on
	# first invocation and runs normally on subsequent ones.
	local dir="${APPS_DIR}/Crasher.cap"
	mkdir -p "${dir}/etc"
	mkdir -p "${dir}/bin"

	# UNQUOTED heredoc: ${WORK} bakes in at write time; the service's own
	# runtime shell variables ($statefile, $count, command substitutions)
	# are escaped so they stay literal in the written script.
	cat > "${dir}/bin/crashd" <<SVCEOF
#!/bin/sh
statefile="${WORK}/crashd.invocations"
count=0
if [ -f "\$statefile" ]; then
	count=\$(cat "\$statefile")
fi
count=\$((count + 1))
echo "\$count" > "\$statefile"

if [ "\$count" -eq 1 ]; then
	# First invocation: crash immediately.
	exit 1
fi
# Subsequent invocations: hand off to the libservice ready helper so the
# relaunched instance reports ready (reaches RUNNING) and writes crashd.ready.
exec "${WORK}/ready_svc" crashd
SVCEOF
	chmod 755 "${dir}/bin/crashd"

	cat > "${dir}/etc/crashd.ucl" <<-UCL
	bundle_id = "org.test.crash";
	version = "1.0";
	author = "test";
	program = "crashd";
	provides = ["org.test.crash.svc"];
	on_demand = true;
	restart = "on-failure";
	UCL

	start_stack

	# Service should NOT be running yet (on-demand; labelled by provides[0]).
	atf_check -s exit:0 -o not-match:"org.test.crash.svc.*running" \
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

	# Service should now be running (labelled by provides[0]).
	atf_check -s exit:0 -o match:"org.test.crash.svc.*running" \
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
atf_init_test_cases() {
	atf_add_test_case system_bundle_startup
	atf_add_test_case on_demand_launch
	atf_add_test_case on_demand_timeout
	atf_add_test_case tiered_startup
	atf_add_test_case stop_service
	atf_add_test_case stop_nonexistent
	atf_add_test_case stop_already_stopped
	atf_add_test_case reload_new_service
	atf_add_test_case reload_remove_service
	atf_add_test_case reload_cycle_rejected
	atf_add_test_case reload_dependency_order
	atf_add_test_case reload_changed_bundle
	atf_add_test_case circular_dep_fatal
	atf_add_test_case missing_system_bundle_optional
	atf_add_test_case coalition_kill_on_timeout
	atf_add_test_case bundles_list
	atf_add_test_case dtrace_probes
	atf_add_test_case on_demand_concurrent_lookup
	atf_add_test_case on_demand_crash_relaunch
	atf_add_test_case reload_noop
	atf_add_test_case reload_attribution
}

# ---------------------------------------------------------------
# Test: Concurrent on-demand lookups coalesce into one launch
# ---------------------------------------------------------------
atf_test_case on_demand_concurrent_lookup cleanup
on_demand_concurrent_lookup_head() {
	atf_set "descr" "Multiple concurrent lookups for same on-demand service produce one launch"
	atf_set "require.user" "root"
}
on_demand_concurrent_lookup_body() {
	prepare_paths
	build_lookup_client
	create_user_bundle "Shared" "org.test.shared" "sharedd" \
	    "org.test.shared.svc" 'on_demand = true;'

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
# Test: Reload with no on-disk changes is a no-op
# ---------------------------------------------------------------
atf_test_case reload_noop cleanup
reload_noop_head() {
	atf_set "descr" "Reload with no bundle changes reports zero deltas and leaves services running"
	atf_set "require.user" "root"
}
reload_noop_body() {
	prepare_paths
	create_system_bundle "Steady" "org.test.steady" "steadyd" \
	    "org.test.steady.svc"

	start_stack
	wait_for_file "${WORK}/steadyd.ready" 5

	# Nothing changed on disk — reload's summary should report all zeros
	# (supervisor_reload: "reload: N bundles, 0 new, 0 changed, 0 removed").
	atf_check -s exit:0 -o match:"0 new, 0 changed, 0 removed" \
	    servicectl -s "${CTL_SOCK}" reload

	# The already-running service is untouched by the no-op reload.
	atf_check -s exit:0 -o match:"org.test.steady.svc.*running" \
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
}
reload_attribution_body() {
	prepare_paths
	start_stack

	# Add a user bundle after startup, then reload to launch it.
	create_user_bundle "Late" "org.test.late" "lated" \
	    "org.test.late.svc"

	atf_check -s exit:0 -o match:"1 new" \
	    servicectl -s "${CTL_SOCK}" reload

	wait_for_file "${WORK}/lated.ready" 5

	# reload.c stamps launched_by="reload"; status shows it as by=reload.
	atf_check -s exit:0 -o match:"org.test.late.svc.*by=reload" \
	    servicectl -s "${CTL_SOCK}" status
}
reload_attribution_cleanup() {
	cleanup_common
}
