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

	# Service should be running
	atf_check -s exit:0 -o match:"bootd.*running" \
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
	create_user_bundle "LazyApp" "org.test.lazy" "lazyd" \
	    "org.test.lazy.svc" 'on_demand = true;'

	start_stack

	# Service should NOT be running yet
	atf_check -s exit:0 -o not-match:"lazyd.*running" \
	    servicectl -s "${CTL_SOCK}" status

	# Trigger lookup from a client
	run_lookup_client "org.test.lazy.svc"

	# Now it should be running
	wait_for_file "${WORK}/lazyd.ready" 10
	atf_check -s exit:0 -o match:"lazyd.*running" \
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
	# Create a service that never calls service_ready()
	create_user_bundle_custom "Hang" "hangd" \
	    'bundle_id = "org.test.hang";
version = "1.0";
author = "test";
program = "hangd";
provides = ["org.test.hang.svc"];
on_demand = true;'

	start_stack

	# Lookup should fail with timeout
	atf_check -s exit:1 \
	    run_lookup_client "org.test.hang.svc" 15
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

	# Both should be running
	atf_check -s exit:0 -o match:"based.*running" \
	    servicectl -s "${CTL_SOCK}" status
	atf_check -s exit:0 -o match:"depd.*running" \
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
	sleep 2
	atf_check -s exit:0 -o match:"stopd.*stopped" \
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

	# Reload
	atf_check -s exit:0 -o match:"new launched" \
	    servicectl -s "${CTL_SOCK}" reload

	wait_for_file "${WORK}/newbie.ready" 5
	atf_check -s exit:0 -o match:"newbie.*running" \
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

	# Remove the bundle
	rm -rf "${APPS_DIR}/Removable.app"

	# Reload
	atf_check -s exit:0 \
	    servicectl -s "${CTL_SOCK}" reload

	# Service should be stopping/stopped
	sleep 3
	atf_check -s exit:0 -o not-match:"rmd.*running" \
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

	# Create circular: A requires B, B requires A
	create_system_bundle_with_requires "CycA" "org.test.cyc" "cyca" \
	    "org.test.cyc.a" "org.test.cyc.b"
	create_system_bundle_with_requires "CycB" "org.test.cyc" "cycb" \
	    "org.test.cyc.b" "org.test.cyc.a"

	# serviced should refuse to start
	start_stack_expect_failure
	atf_check -s exit:0 -o match:"circular dependency" \
	    grep "circular" "${logfile}"
}
circular_dep_fatal_cleanup() {
	cleanup_common
}

# ---------------------------------------------------------------
# Test: Missing system bundle directory is optional
# ---------------------------------------------------------------
atf_test_case missing_system_bundle_optional cleanup
missing_system_bundle_optional_head() {
	atf_set "descr" "Missing /System/Applications is optional"
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
atf_init_test_cases() {
	atf_add_test_case system_bundle_startup
	atf_add_test_case on_demand_launch
	atf_add_test_case on_demand_timeout
	atf_add_test_case tiered_startup
	atf_add_test_case stop_service
	atf_add_test_case stop_nonexistent
	atf_add_test_case reload_new_service
	atf_add_test_case reload_remove_service
	atf_add_test_case circular_dep_fatal
	atf_add_test_case missing_system_bundle_optional
	atf_add_test_case bundles_list
	atf_add_test_case dtrace_probes
}
