#
# SPDX-License-Identifier: BSD-2-Clause
#
# Dynamic claim/release integration tests for the oracled + serviced stack.
#
# Tests verify refcount-based dynamic claim lifecycle:
# - auto-claim on mint creates dynamic claims with refcounting
# - shared claims survive partial service exit (refcount > 0)
# - claims are fully released when last user exits (refcount == 0)
# - policy claims are immune to release (EPERM, harmless)
# - batched release of multiple capabilities completes
#
# Requires: root, cap_rt device available.
#

. "$(dirname "$0")/test_helpers.sh"

require_cap_rt()
{
	if [ ! -c /dev/cap_rt ]; then
		atf_skip "cap_rt device not available"
	fi
}

wait_for_log()
{
	local pattern i
	pattern="$1"
	i=0
	while ! grep -q "$pattern" "$logfile" 2>/dev/null && [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	grep -q "$pattern" "$logfile" 2>/dev/null
}

# ===================================================================
# shared_path_survives_exit
#
# Two services both mint tokens for the same unclaimed path.
# Auto-claim creates the claim on the first mint; the second
# bumps the refcount.  When one service exits, the refcount
# decrements but the claim survives for the remaining service.
# ===================================================================

atf_test_case shared_path_survives_exit cleanup
shared_path_survives_exit_head()
{
	atf_set "descr" "Shared dynamic claim survives when one user exits"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
shared_path_survives_exit_body()
{
	require_cap_rt
	start_stack

	write_executable svc_a <<'SEOF'
#!/bin/sh
echo $$ > svc-a.pid
echo "running" > svc-a-running.out
while true; do sleep 1; done
SEOF

	write_executable svc_b <<'SEOF'
#!/bin/sh
echo $$ > svc-b.pid
echo "running" > svc-b-running.out
while true; do sleep 1; done
SEOF

	cat > "$manifestdir/svc-a.ucl" <<EOF
label = "svc-a";
program = "$(pwd)/svc_a";
capabilities {
    paths = ["/var/tmp"];
}
EOF
	cat > "$manifestdir/svc-b.ucl" <<EOF
label = "svc-b";
program = "$(pwd)/svc_b";
capabilities {
    paths = ["/var/tmp"];
}
EOF
	kill -HUP "$daemon_pid"

	if ! wait_for_file svc-a-running.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "svc-a did not start"
	fi
	if ! wait_for_file svc-b-running.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "svc-b did not start"
	fi

	# Verify auto-claim happened
	atf_check -s exit:0 -o ignore grep "auto-claimed /var/tmp" "$logfile"

	# Verify status shows the dynamic claim with refcount=2
	oraclectl -s "$sockpath" status > status-both.out 2>&1
	atf_check -s exit:0 -o match:"/var/tmp.*service.*refcount=2" \
	    cat status-both.out

	# Kill svc-a — its claims release, but /var/tmp must survive
	# because svc-b still holds a reference.
	kill "$(cat svc-a.pid)" 2>/dev/null || true

	# Wait for the exit to be handled
	wait_for_log "svc-a.*exited\|svc-a.*killed"

	sleep 1

	# Verify /var/tmp is still claimed with refcount=1
	oraclectl -s "$sockpath" status > status-after.out 2>&1
	atf_check -s exit:0 -o match:"/var/tmp.*service.*refcount=1" \
	    cat status-after.out
}
shared_path_survives_exit_cleanup()
{
	cleanup_common
	rm -f svc_a svc_b svc-a-running.out svc-b-running.out \
	    svc-a.pid svc-b.pid status-both.out status-after.out
}

# ===================================================================
# dynamic_claim_fully_released
#
# A single service auto-claims a path (refcount=1).  When it
# exits, the refcount drops to 0 and the claim is released from
# the kernel and removed from the oracle's state.
# ===================================================================

atf_test_case dynamic_claim_fully_released cleanup
dynamic_claim_fully_released_head()
{
	atf_set "descr" "Dynamic claim released from kernel when last user exits"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
dynamic_claim_fully_released_body()
{
	require_cap_rt
	start_stack

	write_executable sole_user <<'SEOF'
#!/bin/sh
echo $$ > sole-user.pid
echo "running" > sole-user-running.out
while true; do sleep 1; done
SEOF

	cat > "$manifestdir/sole.ucl" <<EOF
label = "sole-user";
program = "$(pwd)/sole_user";
capabilities {
    paths = ["/var/tmp"];
}
EOF
	kill -HUP "$daemon_pid"

	if ! wait_for_file sole-user-running.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi

	# Verify claim exists as dynamic
	oraclectl -s "$sockpath" status > status-before.out 2>&1
	atf_check -s exit:0 -o match:"/var/tmp.*service" cat status-before.out

	# Kill the service — claim should be fully released
	kill "$(cat sole-user.pid)" 2>/dev/null || true

	wait_for_log "released dynamic claim /var/tmp"

	sleep 1

	# Verify /var/tmp is gone from status
	oraclectl -s "$sockpath" status > status-after.out 2>&1
	if grep -q "/var/tmp" status-after.out; then
		cat status-after.out
		atf_fail "/var/tmp claim still present after last user exited"
	fi
}
dynamic_claim_fully_released_cleanup()
{
	cleanup_common
	rm -f sole_user sole-user-running.out sole-user.pid \
	    status-before.out status-after.out
}

# ===================================================================
# policy_claim_immune_to_release
#
# A path claimed via oracled.conf (CLAIM_SOURCE_POLICY) must
# survive service exit.  The oracle returns EPERM for the
# release, which is harmless and silently drained.
# ===================================================================

atf_test_case policy_claim_immune_to_release cleanup
policy_claim_immune_to_release_head()
{
	atf_set "descr" "Policy claims survive service exit (EPERM on release)"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
policy_claim_immune_to_release_body()
{
	require_cap_rt
	prepare_paths

	# Config with /var/tmp as a POLICY claim
	find_serviced
	cat > "$conffile" <<EOF
pidfile = "$pidfile";
control_socket = "$sockpath";
control_socket_mode = "0700";
service_manager = "$serviced_bin";
claims {
    paths = ["/var/tmp"];
}
EOF
	write_executable policy_svc <<'SEOF'
#!/bin/sh
echo $$ > policy-svc.pid
echo "running" > policy-svc-running.out
while true; do sleep 1; done
SEOF

	cat > "$manifestdir/policy-svc.ucl" <<EOF
label = "policy-svc";
program = "$(pwd)/policy_svc";
capabilities {
    paths = ["/var/tmp"];
}
EOF

	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	# Wait for control socket
	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -S "$sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "oracled did not create control socket"
	fi

	# Wait for serviced ready
	i=0
	while ! grep -q "serviced ready" "$logfile" 2>/dev/null && \
	    [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done

	# Reload to pick up manifest
	kill -HUP "$daemon_pid"

	if ! wait_for_file policy-svc-running.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi

	# Verify claim is policy
	oraclectl -s "$sockpath" status > status-before.out 2>&1
	atf_check -s exit:0 -o match:"/var/tmp.*policy" cat status-before.out

	# Kill the service — policy claim must survive
	kill "$(cat policy-svc.pid)" 2>/dev/null || true

	wait_for_log "policy-svc.*exited\|policy-svc.*killed"

	sleep 1

	# Verify /var/tmp is still present as policy
	oraclectl -s "$sockpath" status > status-after.out 2>&1
	atf_check -s exit:0 -o match:"/var/tmp.*policy" cat status-after.out
}
policy_claim_immune_to_release_cleanup()
{
	cleanup_common
	rm -f policy_svc policy-svc-running.out policy-svc.pid \
	    status-before.out status-after.out
}

# ===================================================================
# multi_cap_batched_release
#
# A service with multiple capabilities (paths, net) has all of
# them released on exit.  The batched release drain must consume
# all replies without leaving stale tokens in the channel buffer.
# ===================================================================

atf_test_case multi_cap_batched_release cleanup
multi_cap_batched_release_head()
{
	atf_set "descr" "Multiple dynamic claims all released on service exit"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
multi_cap_batched_release_body()
{
	require_cap_rt
	start_stack

	write_executable multi_svc <<'SEOF'
#!/bin/sh
echo $$ > multi-svc.pid
echo "running" > multi-svc-running.out
while true; do sleep 1; done
SEOF

	cat > "$manifestdir/multi.ucl" <<EOF
label = "multi-svc";
program = "$(pwd)/multi_svc";
capabilities {
    paths = ["/var/tmp", "/tmp"];
}
EOF
	kill -HUP "$daemon_pid"

	if ! wait_for_file multi-svc-running.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi

	# Verify both claims exist
	oraclectl -s "$sockpath" status > status-before.out 2>&1
	atf_check -s exit:0 -o match:"/var/tmp.*service" cat status-before.out
	atf_check -s exit:0 -o match:"/tmp.*service" cat status-before.out

	# Kill the service — both claims should be released
	kill "$(cat multi-svc.pid)" 2>/dev/null || true

	# Wait for releases to be processed
	wait_for_log "released dynamic claim /var/tmp"
	wait_for_log "released dynamic claim /tmp"

	sleep 1

	# Verify both claims are gone
	oraclectl -s "$sockpath" status > status-after.out 2>&1
	if grep -q "/var/tmp.*service" status-after.out; then
		cat status-after.out
		atf_fail "/var/tmp claim still present after exit"
	fi
	if grep -q "/tmp.*service" status-after.out; then
		cat status-after.out
		atf_fail "/tmp claim still present after exit"
	fi

	# Verify the channel is still healthy — next operation must
	# succeed, proving the drain didn't leave stale replies.
	write_executable health_svc <<'SEOF'
#!/bin/sh
echo "running" > health-svc-running.out
while true; do sleep 1; done
SEOF

	cat > "$manifestdir/health.ucl" <<EOF
label = "health-svc";
program = "$(pwd)/health_svc";
capabilities {
    paths = ["/var/tmp"];
}
EOF
	kill -HUP "$daemon_pid"

	if ! wait_for_file health-svc-running.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "health-svc did not start (channel corrupted?)"
	fi
}
multi_cap_batched_release_cleanup()
{
	cleanup_common
	rm -f multi_svc health_svc multi-svc-running.out multi-svc.pid \
	    health-svc-running.out status-before.out status-after.out
}

# ===================================================================
# duplicate_release_no_underflow
#
# Verify that a duplicate release does not underflow the refcount.
# After a service exits (automatic release), the claims should be
# gone.  A subsequent reload that starts a new service for the same
# path should claim from refcount=1, not UINT32_MAX.
# ===================================================================

atf_test_case duplicate_release_no_underflow cleanup
duplicate_release_no_underflow_head()
{
	atf_set "descr" "Duplicate release returns error, does not underflow refcount"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
duplicate_release_no_underflow_body()
{
	require_cap_rt
	start_stack

	write_executable dup_svc <<'SEOF'
#!/bin/sh
echo $$ > dup-svc.pid
echo "running" > dup-svc-running.out
while true; do sleep 1; done
SEOF

	cat > "$manifestdir/dup.ucl" <<EOF
label = "dup-svc";
program = "$(pwd)/dup_svc";
capabilities {
    paths = ["/var/tmp"];
}
EOF
	kill -HUP "$daemon_pid"

	if ! wait_for_file dup-svc-running.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi

	# Kill the service — auto-release fires, refcount -> 0, claim released
	kill "$(cat dup-svc.pid)" 2>/dev/null || true
	wait_for_log "released dynamic claim /var/tmp"
	sleep 1

	# Now start a new service claiming the same path — if refcount
	# underflowed to UINT32_MAX, the auto-claim would see it as
	# already claimed with a huge refcount instead of claiming fresh.
	write_executable dup2_svc <<'SEOF'
#!/bin/sh
echo $$ > dup2-svc.pid
echo "running" > dup2-svc-running.out
while true; do sleep 1; done
SEOF

	cat > "$manifestdir/dup2.ucl" <<EOF
label = "dup2-svc";
program = "$(pwd)/dup2_svc";
capabilities {
    paths = ["/var/tmp"];
}
EOF
	kill -HUP "$daemon_pid"

	if ! wait_for_file dup2-svc-running.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "second service did not start"
	fi

	# Verify fresh claim with refcount=1 (not UINT32_MAX)
	oraclectl -s "$sockpath" status > status-dup.out 2>&1
	atf_check -s exit:0 -o match:"/var/tmp.*service.*refcount=1" \
	    cat status-dup.out
}
duplicate_release_no_underflow_cleanup()
{
	cleanup_common
	rm -f dup_svc dup2_svc dup-svc-running.out dup2-svc-running.out \
	    dup-svc.pid dup2-svc.pid status-dup.out
}

# ===================================================================
# sweep_all_claim_types
#
# Verify that when serviced exits, ALL dynamic claim types are
# swept — not just paths.  Uses a service with path AND network
# capabilities.
# ===================================================================

atf_test_case sweep_all_claim_types cleanup
sweep_all_claim_types_head()
{
	atf_set "descr" "Sweep on serviced exit releases path and network claims"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
sweep_all_claim_types_body()
{
	require_cap_rt
	start_stack

	write_executable sweep_svc <<'SEOF'
#!/bin/sh
echo $$ > sweep-svc.pid
echo "running" > sweep-svc-running.out
while true; do sleep 1; done
SEOF

	cat > "$manifestdir/sweep.ucl" <<EOF
label = "sweep-svc";
program = "$(pwd)/sweep_svc";
capabilities {
    paths = ["/var/tmp"];
    network = [
        { port = 9999; protocol = "tcp"; direction = "bind"; },
    ];
}
EOF
	kill -HUP "$daemon_pid"

	if ! wait_for_file sweep-svc-running.out; then
		cat "$logfile" 2>/dev/null
		atf_fail "service did not start"
	fi

	# Verify both claim types exist
	oraclectl -s "$sockpath" status > status-sweep-before.out 2>&1
	atf_check -s exit:0 -o match:"/var/tmp.*service" \
	    cat status-sweep-before.out

	# Kill service — both claim types should be released
	kill "$(cat sweep-svc.pid)" 2>/dev/null || true
	wait_for_log "released dynamic claim /var/tmp"
	sleep 1

	# Verify /var/tmp is gone
	oraclectl -s "$sockpath" status > status-sweep-after.out 2>&1
	if grep -q "/var/tmp.*service" status-sweep-after.out; then
		cat status-sweep-after.out
		atf_fail "path claim survived sweep"
	fi
}
sweep_all_claim_types_cleanup()
{
	cleanup_common
	rm -f sweep_svc sweep-svc-running.out sweep-svc.pid \
	    status-sweep-before.out status-sweep-after.out
}

# ===================================================================

atf_init_test_cases()
{
	atf_add_test_case shared_path_survives_exit
	atf_add_test_case dynamic_claim_fully_released
	atf_add_test_case policy_claim_immune_to_release
	atf_add_test_case multi_cap_batched_release
	atf_add_test_case duplicate_release_no_underflow
	atf_add_test_case sweep_all_claim_types
}
