#
# SPDX-License-Identifier: BSD-2-Clause
#
# Service manifest and dependency tests for serviced (via oracled).
#
# These test manifest parsing, dependency sorting, and reload via
# the full oracled + serviced stack.  Requires root and cap_rt.
#

# --- helpers ---

daemon_pid=
pidfile=
conffile=
manifestdir=
sockpath=
logfile=
serviced_bin=

find_serviced()
{
	local p
	for p in \
	    "$(command -v serviced 2>/dev/null)" \
	    /usr/sbin/serviced \
	    /usr/libexec/oracled/serviced \
	    /usr/obj/usr/src/arm64.aarch64/usr.sbin/serviced/serviced
	do
		if [ -n "$p" ] && [ -x "$p" ]; then
			serviced_bin="$p"
			return
		fi
	done
	atf_skip "serviced binary not found"
}

require_cap_rt()
{
	if ! sh -c 'exec 3</dev/cap_rt' 2>/dev/null; then
		atf_skip "/dev/cap_rt not available (oracled may be running)"
	fi
}

prepare_paths()
{
	pidfile="$(pwd)/oracled.pid"
	conffile="$(pwd)/oracled.conf"
	manifestdir="$(pwd)/oracled.d"
	sockpath="$(pwd)/oracled.sock"
	logfile="$(pwd)/oracled.log"
	mkdir -p "$manifestdir"
}

write_config()
{
	find_serviced
	cat > "$conffile" <<EOF
pidfile = "$pidfile";
control_socket = "$sockpath";
control_socket_mode = "0700";
manifest_dir = "$manifestdir";
service_manager = "$serviced_bin";
EOF
}

start_oracled()
{
	prepare_paths
	write_config

	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	# Wait for oracled control socket.
	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -S "$sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "oracled did not create control socket"
	fi

	# Wait for serviced to be ready.
	i=0
	while ! grep -q "serviced ready\|serviced started" "$logfile" 2>/dev/null && [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done
}

stop_oracled()
{
	if [ -n "$daemon_pid" ]; then
		kill -TERM "$daemon_pid" 2>/dev/null || true
		wait "$daemon_pid" 2>/dev/null || true
	fi
}

cleanup_common()
{
	stop_oracled
	pkill -9 -f "oracled.d" 2>/dev/null || true
	sleep 0.2
	rm -rf oracled.pid oracled.conf oracled.d oracled.sock \
	    oracled.log oracled2.d
}

# --- manifest parsing ---

atf_test_case manifest_empty_dir cleanup
manifest_empty_dir_head()
{
	atf_set "descr" "serviced starts with empty manifest directory"
	atf_set "require.user" "root"
}
manifest_empty_dir_body()
{
	require_cap_rt
	start_oracled
	# Wait for serviced to process manifests.
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'no services to start' '$logfile'"
	stop_oracled
}
manifest_empty_dir_cleanup()
{
	cleanup_common
}

atf_test_case manifest_missing_dir cleanup
manifest_missing_dir_head()
{
	atf_set "descr" "serviced starts when manifest directory does not exist"
	atf_set "require.user" "root"
}
manifest_missing_dir_body()
{
	require_cap_rt
	find_serviced
	pidfile="$(pwd)/oracled.pid"
	conffile="$(pwd)/oracled.conf"
	sockpath="$(pwd)/oracled.sock"
	logfile="$(pwd)/oracled.log"

	cat > "$conffile" <<EOF
pidfile = "$pidfile";
control_socket = "$sockpath";
control_socket_mode = "0700";
manifest_dir = "$(pwd)/nonexistent.d";
service_manager = "$serviced_bin";
EOF
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'not found' '$logfile'"
	stop_oracled
}
manifest_missing_dir_cleanup()
{
	cleanup_common
}

atf_test_case manifest_invalid_skipped cleanup
manifest_invalid_skipped_head()
{
	atf_set "descr" "invalid manifest files are skipped"
	atf_set "require.user" "root"
}
manifest_invalid_skipped_body()
{
	require_cap_rt
	prepare_paths

	# Missing label — should be skipped.
	cat > "$manifestdir/bad.ucl" <<EOF
program = "/usr/bin/true";
EOF

	# Valid manifest.
	cat > "$manifestdir/good.ucl" <<EOF
label = "test-good";
program = "/usr/bin/true";
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'missing or empty label' '$logfile'"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded test-good' '$logfile'"
	# Only 1 service should have loaded.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep '1 services loaded' '$logfile'"
	stop_oracled
}
manifest_invalid_skipped_cleanup()
{
	cleanup_common
}

atf_test_case manifest_missing_program cleanup
manifest_missing_program_head()
{
	atf_set "descr" "manifest without program is rejected"
	atf_set "require.user" "root"
}
manifest_missing_program_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/noprog.ucl" <<EOF
label = "noprog";
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'missing program' '$logfile'"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep '0 services loaded' '$logfile'"
	stop_oracled
}
manifest_missing_program_cleanup()
{
	cleanup_common
}

atf_test_case manifest_relative_program cleanup
manifest_relative_program_head()
{
	atf_set "descr" "manifest with relative program path is rejected"
	atf_set "require.user" "root"
}
manifest_relative_program_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/rel.ucl" <<EOF
label = "relative";
program = "bin/true";
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'must be absolute' '$logfile'"
	stop_oracled
}
manifest_relative_program_cleanup()
{
	cleanup_common
}

atf_test_case manifest_non_ucl_ignored cleanup
manifest_non_ucl_ignored_head()
{
	atf_set "descr" "non-.ucl files in manifest dir are ignored"
	atf_set "require.user" "root"
}
manifest_non_ucl_ignored_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/readme.txt" <<EOF
This is not a manifest.
EOF
	cat > "$manifestdir/good.ucl" <<EOF
label = "test-svc";
program = "/usr/bin/true";
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep '1 services loaded' '$logfile'"
	stop_oracled
}
manifest_non_ucl_ignored_cleanup()
{
	cleanup_common
}

atf_test_case manifest_restart_policies cleanup
manifest_restart_policies_head()
{
	atf_set "descr" "manifest restart policies are parsed correctly"
	atf_set "require.user" "root"
}
manifest_restart_policies_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/always.ucl" <<EOF
label = "svc-always";
program = "/usr/bin/true";
restart = "always";
EOF
	cat > "$manifestdir/failure.ucl" <<EOF
label = "svc-failure";
program = "/usr/bin/true";
restart = "on-failure";
EOF
	cat > "$manifestdir/never.ucl" <<EOF
label = "svc-never";
program = "/usr/bin/true";
restart = "never";
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'svc-always.*restart=always' '$logfile'"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'svc-failure.*restart=on-failure' '$logfile'"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'svc-never.*restart=never' '$logfile'"
	stop_oracled
}
manifest_restart_policies_cleanup()
{
	cleanup_common
}

atf_test_case manifest_capabilities cleanup
manifest_capabilities_head()
{
	atf_set "descr" "manifest capability sections are parsed"
	atf_set "require.user" "root"
}
manifest_capabilities_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/caps.ucl" <<EOF
label = "svc-caps";
program = "/usr/bin/true";
capabilities {
    paths = ["/dev/cap_rt", "/etc/oracled.conf"];
    system = ["kldload", "reboot"];
}
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'capabilities: paths=2 network=0 system=0x9' '$logfile'"
	stop_oracled
}
manifest_capabilities_cleanup()
{
	cleanup_common
}

# --- dependency graph ---

atf_test_case depgraph_order cleanup
depgraph_order_head()
{
	atf_set "descr" "services are sorted by dependency order"
	atf_set "require.user" "root"
}
depgraph_order_body()
{
	require_cap_rt
	prepare_paths

	# B requires A.  Even though b.ucl sorts before a.ucl,
	# A should appear first in the sorted order.
	cat > "$manifestdir/b-svc.ucl" <<EOF
label = "svc-b";
program = "/usr/bin/true";
provides = ["B"];
requires = ["A"];
EOF
	cat > "$manifestdir/a-svc.ucl" <<EOF
label = "svc-a";
program = "/usr/bin/true";
provides = ["A"];
requires = ["ORACLED"];
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	# In the log, svc-a should appear before svc-b.
	a_line=$(grep -n 'service: svc-a' "$logfile" | head -1 | cut -d: -f1)
	b_line=$(grep -n 'service: svc-b' "$logfile" | head -1 | cut -d: -f1)
	if [ -z "$a_line" ] || [ -z "$b_line" ]; then
		cat "$logfile"
		atf_fail "could not find service log lines"
	fi
	if [ "$a_line" -ge "$b_line" ]; then
		cat "$logfile"
		atf_fail "svc-a (line $a_line) should appear before svc-b (line $b_line)"
	fi
	stop_oracled
}
depgraph_order_cleanup()
{
	cleanup_common
}

atf_test_case depgraph_cycle cleanup
depgraph_cycle_head()
{
	atf_set "descr" "circular dependencies are detected and refused"
	atf_set "require.user" "root"
}
depgraph_cycle_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/x.ucl" <<EOF
label = "svc-x";
program = "/usr/bin/true";
provides = ["X"];
requires = ["Y"];
EOF
	cat > "$manifestdir/y.ucl" <<EOF
label = "svc-y";
program = "/usr/bin/true";
provides = ["Y"];
requires = ["X"];
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'cycle detected' '$logfile'"
	stop_oracled
}
depgraph_cycle_cleanup()
{
	cleanup_common
}

atf_test_case depgraph_unknown_provider cleanup
depgraph_unknown_provider_head()
{
	atf_set "descr" "unknown provider in requires is warned but not fatal"
	atf_set "require.user" "root"
}
depgraph_unknown_provider_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/lonely.ucl" <<EOF
label = "svc-lonely";
program = "/usr/bin/true";
requires = ["nonexistent"];
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'unknown provider.*nonexistent' '$logfile'"
	# Service should still be loaded and sorted.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'sorted 1 services' '$logfile'"
	stop_oracled
}
depgraph_unknown_provider_cleanup()
{
	cleanup_common
}

atf_test_case depgraph_duplicate_label cleanup
depgraph_duplicate_label_head()
{
	atf_set "descr" "duplicate labels produce a warning"
	atf_set "require.user" "root"
}
depgraph_duplicate_label_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/dup1.ucl" <<EOF
label = "same-name";
program = "/usr/bin/true";
EOF
	cat > "$manifestdir/dup2.ucl" <<EOF
label = "same-name";
program = "/usr/bin/true";
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'duplicate label.*same-name' '$logfile'"
	stop_oracled
}
depgraph_duplicate_label_cleanup()
{
	cleanup_common
}

atf_test_case depgraph_duplicate_provides cleanup
depgraph_duplicate_provides_head()
{
	atf_set "descr" "duplicate provides names produce a warning"
	atf_set "require.user" "root"
}
depgraph_duplicate_provides_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/p1.ucl" <<EOF
label = "svc-p1";
program = "/usr/bin/true";
provides = ["shared"];
EOF
	cat > "$manifestdir/p2.ucl" <<EOF
label = "svc-p2";
program = "/usr/bin/true";
provides = ["shared"];
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'both provide.*shared' '$logfile'"
	stop_oracled
}
depgraph_duplicate_provides_cleanup()
{
	cleanup_common
}

atf_test_case depgraph_oracled_implicit cleanup
depgraph_oracled_implicit_head()
{
	atf_set "descr" "ORACLED is always satisfied as a dependency"
	atf_set "require.user" "root"
}
depgraph_oracled_implicit_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/needs-oracle.ucl" <<EOF
label = "svc-needs-oracle";
program = "/usr/bin/true";
requires = ["ORACLED"];
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	# Should sort without warning about unknown provider.
	atf_check -s not-exit:0 sh -c \
	    "grep 'unknown provider.*ORACLED' '$logfile'"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'sorted 1 services' '$logfile'"
	stop_oracled
}
depgraph_oracled_implicit_cleanup()
{
	cleanup_common
}

# --- bad manifest inputs ---

atf_test_case manifest_bad_ucl_syntax cleanup
manifest_bad_ucl_syntax_head()
{
	atf_set "descr" "UCL syntax error in manifest is skipped"
	atf_set "require.user" "root"
}
manifest_bad_ucl_syntax_body()
{
	require_cap_rt
	prepare_paths

	# Invalid UCL — unclosed brace.
	cat > "$manifestdir/broken.ucl" <<EOF
label = "broken";
program = "/usr/bin/true";
capabilities {
    system = ["kldload"
EOF

	# Valid one to confirm it still loads.
	cat > "$manifestdir/valid.ucl" <<EOF
label = "valid-svc";
program = "/usr/bin/true";
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	# broken.ucl should produce a parse error.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep -i 'broken.ucl' '$logfile'"
	# valid-svc should still load.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded valid-svc' '$logfile'"
	stop_oracled
}
manifest_bad_ucl_syntax_cleanup()
{
	cleanup_common
}

atf_test_case manifest_bad_restart_value cleanup
manifest_bad_restart_value_head()
{
	atf_set "descr" "unknown restart value is warned and defaults to never"
	atf_set "require.user" "root"
}
manifest_bad_restart_value_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/bad-restart.ucl" <<EOF
label = "bad-restart";
program = "/usr/bin/true";
restart = "whenever";
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'unknown restart policy.*whenever' '$logfile'"
	# Should default to never.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'bad-restart.*restart=never' '$logfile'"
	stop_oracled
}
manifest_bad_restart_value_cleanup()
{
	cleanup_common
}

atf_test_case manifest_empty_label cleanup
manifest_empty_label_head()
{
	atf_set "descr" "manifest with empty label string is rejected"
	atf_set "require.user" "root"
}
manifest_empty_label_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/empty-label.ucl" <<EOF
label = "";
program = "/usr/bin/true";
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'missing or empty label' '$logfile'"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep '0 services loaded' '$logfile'"
	stop_oracled
}
manifest_empty_label_cleanup()
{
	cleanup_common
}

atf_test_case manifest_bad_cap_path cleanup
manifest_bad_cap_path_head()
{
	atf_set "descr" "relative capability path is warned"
	atf_set "require.user" "root"
}
manifest_bad_cap_path_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/relcap.ucl" <<EOF
label = "relcap-svc";
program = "/usr/bin/true";
capabilities {
    paths = ["relative/path"];
}
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'must be absolute.*relative/path' '$logfile'"
	# Service still loads, just without that cap path.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded relcap-svc' '$logfile'"
	stop_oracled
}
manifest_bad_cap_path_cleanup()
{
	cleanup_common
}

atf_test_case manifest_bad_system_gate cleanup
manifest_bad_system_gate_head()
{
	atf_set "descr" "unknown system gate name is warned"
	atf_set "require.user" "root"
}
manifest_bad_system_gate_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/badgate.ucl" <<EOF
label = "badgate-svc";
program = "/usr/bin/true";
capabilities {
    system = ["kldload", "fakegate"];
}
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'unknown system gate.*fakegate' '$logfile'"
	# kldload should still be parsed (0x1).
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'capabilities: paths=0 network=0 system=0x1' '$logfile'"
	stop_oracled
}
manifest_bad_system_gate_cleanup()
{
	cleanup_common
}

atf_test_case manifest_unknown_field_ignored cleanup
manifest_unknown_field_ignored_head()
{
	atf_set "descr" "unknown UCL fields are silently ignored"
	atf_set "require.user" "root"
}
manifest_unknown_field_ignored_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/extra.ucl" <<EOF
label = "extra-svc";
program = "/usr/bin/true";
jail = "net-agent";
custom_thing = "hello";
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	# Service should load despite unknown fields.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded extra-svc' '$logfile'"
	stop_oracled
}
manifest_unknown_field_ignored_cleanup()
{
	cleanup_common
}

atf_test_case manifest_cap_network cleanup
manifest_cap_network_head()
{
	atf_set "descr" "capabilities.network section is parsed"
	atf_set "require.user" "root"
}
manifest_cap_network_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/netcap.ucl" <<EOF
label = "net-svc";
program = "/usr/bin/true";
capabilities {
    network = [
        { port = 443; protocol = "tcp"; direction = "bind"; },
        { port = 80; protocol = "tcp"; direction = "bind"; },
    ];
}
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'capabilities: paths=0 network=2 system=0x0' '$logfile'"
	stop_oracled
}
manifest_cap_network_cleanup()
{
	cleanup_common
}

atf_test_case manifest_all_fields cleanup
manifest_all_fields_head()
{
	atf_set "descr" "manifest with all fields parses correctly"
	atf_set "require.user" "root"
}
manifest_all_fields_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/full.ucl" <<EOF
label = "full-svc";
description = "A complete manifest";
program = "/usr/bin/true";
user = "root";
group = "wheel";
provides = ["fulltest"];
requires = ["ORACLED"];
restart = "on-failure";
capabilities {
    paths = ["/dev/null"];
    network = [
        { port = 8080; protocol = "tcp"; direction = "bind"; },
    ];
    system = ["sysctl"];
}
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'full-svc.*restart=on-failure' '$logfile'"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'provides: fulltest' '$logfile'"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'requires: ORACLED' '$logfile'"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'capabilities: paths=1 network=1 system=0x40' '$logfile'"
	stop_oracled
}
manifest_all_fields_cleanup()
{
	cleanup_common
}

atf_test_case depgraph_three_level cleanup
depgraph_three_level_head()
{
	atf_set "descr" "three-level dependency chain sorts correctly"
	atf_set "require.user" "root"
}
depgraph_three_level_body()
{
	require_cap_rt
	prepare_paths

	# C requires B requires A.
	cat > "$manifestdir/c-svc.ucl" <<EOF
label = "svc-c";
program = "/usr/bin/true";
provides = ["C"];
requires = ["B"];
EOF
	cat > "$manifestdir/b-svc.ucl" <<EOF
label = "svc-b";
program = "/usr/bin/true";
provides = ["B"];
requires = ["A"];
EOF
	cat > "$manifestdir/a-svc.ucl" <<EOF
label = "svc-a";
program = "/usr/bin/true";
provides = ["A"];
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	a_line=$(grep -n 'service: svc-a' "$logfile" | head -1 | cut -d: -f1)
	b_line=$(grep -n 'service: svc-b' "$logfile" | head -1 | cut -d: -f1)
	c_line=$(grep -n 'service: svc-c' "$logfile" | head -1 | cut -d: -f1)
	if [ -z "$a_line" ] || [ -z "$b_line" ] || [ -z "$c_line" ]; then
		cat "$logfile"
		atf_fail "could not find all service log lines"
	fi
	if [ "$a_line" -ge "$b_line" ] || [ "$b_line" -ge "$c_line" ]; then
		cat "$logfile"
		atf_fail "expected order A < B < C, got A=$a_line B=$b_line C=$c_line"
	fi
	stop_oracled
}
depgraph_three_level_cleanup()
{
	cleanup_common
}

atf_test_case depgraph_independent cleanup
depgraph_independent_head()
{
	atf_set "descr" "independent services all sort successfully"
	atf_set "require.user" "root"
}
depgraph_independent_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/alpha.ucl" <<EOF
label = "svc-alpha";
program = "/usr/bin/true";
EOF
	cat > "$manifestdir/beta.ucl" <<EOF
label = "svc-beta";
program = "/usr/bin/true";
EOF
	cat > "$manifestdir/gamma.ucl" <<EOF
label = "svc-gamma";
program = "/usr/bin/true";
EOF

	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'sorted 3 services' '$logfile'"
	stop_oracled
}
depgraph_independent_cleanup()
{
	cleanup_common
}

# --- reload ---

atf_test_case reload_add_service cleanup
reload_add_service_head()
{
	atf_set "descr" "reload detects and starts a new service"
	atf_set "require.user" "root"
}
reload_add_service_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/original.ucl" <<EOF
label = "original";
program = "/usr/bin/true";
EOF
	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded original' '$logfile'"

	# Add a new manifest and send SIGHUP.
	cat > "$manifestdir/added.ucl" <<EOF
label = "added-svc";
program = "/usr/bin/true";
EOF
	kill -HUP "$daemon_pid"
	sleep 2
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'reload:.*1 new' '$logfile'"
	stop_oracled
}
reload_add_service_cleanup()
{
	cleanup_common
}

atf_test_case reload_remove_service cleanup
reload_remove_service_head()
{
	atf_set "descr" "reload detects and stops a removed service"
	atf_set "require.user" "root"
}
reload_remove_service_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/keeper.ucl" <<EOF
label = "keeper";
program = "/usr/bin/true";
EOF
	cat > "$manifestdir/doomed.ucl" <<EOF
label = "doomed";
program = "/usr/bin/true";
EOF
	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded doomed' '$logfile'"

	# Remove manifest and reload.
	rm -f "$manifestdir/doomed.ucl"
	kill -HUP "$daemon_pid"
	sleep 2
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'removing.*doomed' '$logfile'"
	stop_oracled
}
reload_remove_service_cleanup()
{
	cleanup_common
}

atf_test_case reload_change_manifest cleanup
reload_change_manifest_head()
{
	atf_set "descr" "reload detects changed manifest and restarts service"
	atf_set "require.user" "root"
}
reload_change_manifest_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/morph.ucl" <<EOF
label = "morph";
program = "/usr/bin/true";
restart = "never";
EOF
	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded morph' '$logfile'"

	# Change the manifest and reload.
	cat > "$manifestdir/morph.ucl" <<EOF
label = "morph";
program = "/usr/bin/true";
restart = "always";
EOF
	kill -HUP "$daemon_pid"
	sleep 2
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'restarting.*morph.*(manifest changed)' '$logfile'"
	stop_oracled
}
reload_change_manifest_cleanup()
{
	cleanup_common
}

atf_test_case reload_no_changes cleanup
reload_no_changes_head()
{
	atf_set "descr" "reload with no changes reports 0 new, 0 changed, 0 removed"
	atf_set "require.user" "root"
}
reload_no_changes_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/stable.ucl" <<EOF
label = "stable";
program = "/usr/bin/true";
EOF
	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1
	kill -HUP "$daemon_pid"
	sleep 2
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'reload: 0 new, 0 changed, 0 removed' '$logfile'"
	stop_oracled
}
reload_no_changes_cleanup()
{
	cleanup_common
}

atf_test_case reload_bad_manifest_rejected cleanup
reload_bad_manifest_rejected_head()
{
	atf_set "descr" "reload rejects invalid new manifests"
	atf_set "require.user" "root"
}
reload_bad_manifest_rejected_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/good.ucl" <<EOF
label = "good-svc";
program = "/usr/bin/true";
EOF
	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	# Add a manifest with a nonexistent program.
	cat > "$manifestdir/bad.ucl" <<EOF
label = "bad-svc";
program = "/nonexistent/program";
EOF
	kill -HUP "$daemon_pid"
	sleep 2
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'rejecting.*bad-svc' '$logfile'"
	stop_oracled
}
reload_bad_manifest_rejected_cleanup()
{
	cleanup_common
}

atf_test_case reload_cycle_rejected cleanup
reload_cycle_rejected_head()
{
	atf_set "descr" "reload rejects new manifest set that creates a cycle"
	atf_set "require.user" "root"
}
reload_cycle_rejected_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/alpha.ucl" <<EOF
label = "alpha";
program = "/usr/bin/true";
provides = ["A"];
EOF
	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	# Add two manifests that form a cycle between themselves.
	cat > "$manifestdir/cycle-x.ucl" <<EOF
label = "cycle-x";
program = "/usr/bin/true";
provides = ["X"];
requires = ["Y"];
EOF
	cat > "$manifestdir/cycle-y.ucl" <<EOF
label = "cycle-y";
program = "/usr/bin/true";
provides = ["Y"];
requires = ["X"];
EOF
	kill -HUP "$daemon_pid"
	sleep 2
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'dependency graph rejected\|depgraph_sort failed' '$logfile'"
	stop_oracled
}
reload_cycle_rejected_cleanup()
{
	cleanup_common
}

atf_test_case reload_multiple_add_remove cleanup
reload_multiple_add_remove_head()
{
	atf_set "descr" "reload handles multiple adds and removes in one pass"
	atf_set "require.user" "root"
}
reload_multiple_add_remove_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/keep.ucl" <<EOF
label = "keep-svc";
program = "/usr/bin/true";
EOF
	cat > "$manifestdir/remove1.ucl" <<EOF
label = "remove1";
program = "/usr/bin/true";
EOF
	cat > "$manifestdir/remove2.ucl" <<EOF
label = "remove2";
program = "/usr/bin/true";
EOF
	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep '3 services launched' '$logfile'"

	# Remove two, add two.
	rm -f "$manifestdir/remove1.ucl" "$manifestdir/remove2.ucl"
	cat > "$manifestdir/add1.ucl" <<EOF
label = "add1";
program = "/usr/bin/true";
EOF
	cat > "$manifestdir/add2.ucl" <<EOF
label = "add2";
program = "/usr/bin/true";
EOF
	kill -HUP "$daemon_pid"
	sleep 2
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'reload: 2 new, 0 changed, 2 removed' '$logfile'"
	# keep-svc must not appear in removed or changed
	atf_check -s not-exit:0 sh -c \
	    "grep 'removing.*keep-svc' '$logfile'"
	atf_check -s not-exit:0 sh -c \
	    "grep 'restarting.*keep-svc' '$logfile'"
	stop_oracled
}
reload_multiple_add_remove_cleanup()
{
	cleanup_common
}

atf_test_case reload_change_and_add cleanup
reload_change_and_add_head()
{
	atf_set "descr" "reload handles simultaneous change and add"
	atf_set "require.user" "root"
}
reload_change_and_add_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/existing.ucl" <<EOF
label = "existing";
program = "/usr/bin/true";
restart = "never";
EOF
	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	# Change existing, add new.
	cat > "$manifestdir/existing.ucl" <<EOF
label = "existing";
program = "/usr/bin/true";
restart = "always";
EOF
	cat > "$manifestdir/fresh.ucl" <<EOF
label = "fresh";
program = "/usr/bin/true";
EOF
	kill -HUP "$daemon_pid"
	sleep 2
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'reload: 1 new, 1 changed, 0 removed' '$logfile'"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'restarting.*existing.*(manifest changed)' '$logfile'"
	stop_oracled
}
reload_change_and_add_cleanup()
{
	cleanup_common
}

atf_test_case reload_empty_dir cleanup
reload_empty_dir_head()
{
	atf_set "descr" "reload to empty manifest dir removes all services"
	atf_set "require.user" "root"
}
reload_empty_dir_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/one.ucl" <<EOF
label = "one";
program = "/usr/bin/true";
EOF
	cat > "$manifestdir/two.ucl" <<EOF
label = "two";
program = "/usr/bin/true";
EOF
	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep '2 services launched' '$logfile'"

	# Remove all manifests.
	rm -f "$manifestdir"/*.ucl
	kill -HUP "$daemon_pid"
	sleep 2
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'reload: 0 new, 0 changed, 2 removed' '$logfile'"
	stop_oracled
}
reload_empty_dir_cleanup()
{
	cleanup_common
}

atf_test_case reload_duplicate_label_at_startup cleanup
reload_duplicate_label_at_startup_head()
{
	atf_set "descr" "duplicate labels at startup are caught by depgraph"
	atf_set "require.user" "root"
}
reload_duplicate_label_at_startup_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/orig.ucl" <<EOF
label = "dup-label";
program = "/usr/bin/true";
EOF
	cat > "$manifestdir/clone.ucl" <<EOF
label = "dup-label";
program = "/usr/bin/true";
restart = "always";
EOF
	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'duplicate label.*dup-label' '$logfile'"
	stop_oracled
}
reload_duplicate_label_at_startup_cleanup()
{
	cleanup_common
}

atf_test_case reload_idempotent_sighup cleanup
reload_idempotent_sighup_head()
{
	atf_set "descr" "multiple SIGHUPs with no changes are safe"
	atf_set "require.user" "root"
}
reload_idempotent_sighup_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/svc.ucl" <<EOF
label = "stable-svc";
program = "/usr/bin/true";
EOF
	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	# Send 3 SIGHUPs with delays to avoid coalescing.
	kill -HUP "$daemon_pid"; sleep 1
	kill -HUP "$daemon_pid"; sleep 1
	kill -HUP "$daemon_pid"; sleep 2

	# All should report 0 changes.
	count=$(grep -c 'reload: 0 new, 0 changed, 0 removed' "$logfile")
	if [ "$count" -lt 3 ]; then
		cat "$logfile"
		atf_fail "expected at least 3 no-change reloads, got $count"
	fi
	stop_oracled
}
reload_idempotent_sighup_cleanup()
{
	cleanup_common
}

# --- config ---

atf_test_case config_manifest_dir cleanup
config_manifest_dir_head()
{
	atf_set "descr" "manifest_dir config key is logged"
	atf_set "require.user" "root"
}
config_manifest_dir_body()
{
	require_cap_rt
	prepare_paths
	write_config

	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'manifest_dir=$(pwd)/oracled.d' '$logfile'"
	stop_oracled
}
config_manifest_dir_cleanup()
{
	cleanup_common
}

# --- service launch ---

atf_test_case svc_launch_order_logged cleanup
svc_launch_order_logged_head()
{
	atf_set "descr" "Services are launched in dependency order"
	atf_set "require.user" "root"
}
svc_launch_order_logged_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/aaa-base.ucl" <<EOF
label = "base";
program = "/usr/bin/true";
provides = ["base"];
EOF
	cat > "$manifestdir/zzz-app.ucl" <<EOF
label = "app";
program = "/usr/bin/true";
requires = ["base"];
EOF
	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	# base should appear before app in the log
	base_line=$(grep -n 'service base:' "$logfile" | head -1 | cut -d: -f1)
	app_line=$(grep -n 'service app:' "$logfile" | head -1 | cut -d: -f1)
	if [ -z "$base_line" ] || [ -z "$app_line" ]; then
		cat "$logfile"
		atf_fail "expected both services in log"
	fi
	if [ "$app_line" -le "$base_line" ]; then
		atf_fail "app should be launched after base"
	fi
	stop_oracled
}
svc_launch_order_logged_cleanup()
{
	cleanup_common
}

atf_test_case svc_capabilities_logged cleanup
svc_capabilities_logged_head()
{
	atf_set "descr" "Service capabilities are logged at startup"
	atf_set "require.user" "root"
}
svc_capabilities_logged_body()
{
	require_cap_rt
	prepare_paths

	cat > "$manifestdir/capsvc.ucl" <<EOF
label = "capsvc";
program = "/usr/bin/true";
capabilities {
    paths = ["/var/log"];
    system = ["kldload", "reboot"];
}
EOF
	write_config
	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	sleep 1

	grep "capabilities: paths=1" "$logfile" || \
	    atf_fail "expected capability log line"
	grep "system=0x" "$logfile" || \
	    atf_fail "expected system gate bitmask in log"
	stop_oracled
}
svc_capabilities_logged_cleanup()
{
	cleanup_common
}

atf_init_test_cases()
{
	# Manifest parsing
	atf_add_test_case manifest_empty_dir
	atf_add_test_case manifest_missing_dir
	atf_add_test_case manifest_invalid_skipped
	atf_add_test_case manifest_missing_program
	atf_add_test_case manifest_relative_program
	atf_add_test_case manifest_non_ucl_ignored
	atf_add_test_case manifest_restart_policies
	atf_add_test_case manifest_capabilities

	atf_add_test_case manifest_unknown_field_ignored
	atf_add_test_case manifest_cap_network
	atf_add_test_case manifest_all_fields

	# Bad manifest inputs
	atf_add_test_case manifest_bad_ucl_syntax
	atf_add_test_case manifest_bad_restart_value
	atf_add_test_case manifest_empty_label
	atf_add_test_case manifest_bad_cap_path
	atf_add_test_case manifest_bad_system_gate

	# Dependency graph
	atf_add_test_case depgraph_order
	atf_add_test_case depgraph_three_level
	atf_add_test_case depgraph_independent
	atf_add_test_case depgraph_cycle
	atf_add_test_case depgraph_unknown_provider
	atf_add_test_case depgraph_duplicate_label
	atf_add_test_case depgraph_duplicate_provides
	atf_add_test_case depgraph_oracled_implicit

	# Reload
	atf_add_test_case reload_add_service
	atf_add_test_case reload_remove_service
	atf_add_test_case reload_change_manifest
	atf_add_test_case reload_no_changes
	atf_add_test_case reload_bad_manifest_rejected
	atf_add_test_case reload_cycle_rejected
	atf_add_test_case reload_multiple_add_remove
	atf_add_test_case reload_change_and_add
	atf_add_test_case reload_empty_dir
	atf_add_test_case reload_duplicate_label_at_startup
	atf_add_test_case reload_idempotent_sighup

	# Config
	atf_add_test_case config_manifest_dir

	# Service launch
	atf_add_test_case svc_launch_order_logged
	atf_add_test_case svc_capabilities_logged
}
