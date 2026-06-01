#
# SPDX-License-Identifier: BSD-2-Clause
#
# Service launcher tests for oracled.
#
# These test manifest parsing, dependency sorting, and service
# lifecycle using oracled in test mode (-T) with a temp manifest
# directory.  No cap_rt required — test mode skips kernel
# integration.
#

# --- helpers ---

start_oracled()
{
	pidfile="$(pwd)/oracled.pid"
	conffile="$(pwd)/oracled.conf"
	manifestdir="$(pwd)/oracled.d"
	logfile="$(pwd)/oracled.log"

	cat > "$conffile" <<EOF
manifest_dir = "$manifestdir";
EOF

	oracled -d -T -f "$conffile" -p "$pidfile" >"$logfile" 2>&1 &
	daemon_pid=$!

	# Wait for pidfile.
	i=0
	while [ ! -s "$pidfile" ] && [ $i -lt 50 ]; do
		i=$((i + 1))
		sleep 0.1
	done

	if [ ! -s "$pidfile" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "oracled did not create pidfile"
	fi
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
	rm -rf oracled.pid oracled.conf oracled.d oracled.log
}

# --- manifest parsing ---

atf_test_case manifest_empty_dir cleanup
manifest_empty_dir_head()
{
	atf_set "descr" "oracled starts with empty manifest directory"
}
manifest_empty_dir_body()
{
	mkdir -p oracled.d
	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'no services to start' oracled.log"
	stop_oracled
}
manifest_empty_dir_cleanup()
{
	cleanup_common
}

atf_test_case manifest_missing_dir cleanup
manifest_missing_dir_head()
{
	atf_set "descr" "oracled starts when manifest directory does not exist"
}
manifest_missing_dir_body()
{
	# Don't create oracled.d — it should log and continue.
	pidfile="$(pwd)/oracled.pid"
	conffile="$(pwd)/oracled.conf"
	logfile="$(pwd)/oracled.log"

	cat > "$conffile" <<EOF
manifest_dir = "$(pwd)/nonexistent.d";
EOF
	oracled -d -T -f "$conffile" -p "$pidfile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -s "$pidfile" ] && [ $i -lt 50 ]; do
		i=$((i + 1))
		sleep 0.1
	done

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'not found' oracled.log"
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
}
manifest_invalid_skipped_body()
{
	mkdir -p oracled.d

	# Missing label — should be skipped.
	cat > oracled.d/bad.ucl <<EOF
program = "/usr/bin/true";
EOF

	# Valid manifest.
	cat > oracled.d/good.ucl <<EOF
label = "test-good";
program = "/usr/bin/true";
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'missing or empty label' oracled.log"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded test-good' oracled.log"
	# Only 1 service should have loaded.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep '1 services loaded' oracled.log"
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
}
manifest_missing_program_body()
{
	mkdir -p oracled.d

	cat > oracled.d/noprog.ucl <<EOF
label = "noprog";
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'missing program' oracled.log"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep '0 services loaded' oracled.log"
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
}
manifest_relative_program_body()
{
	mkdir -p oracled.d

	cat > oracled.d/rel.ucl <<EOF
label = "relative";
program = "bin/true";
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'must be absolute' oracled.log"
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
}
manifest_non_ucl_ignored_body()
{
	mkdir -p oracled.d

	cat > oracled.d/readme.txt <<EOF
This is not a manifest.
EOF
	cat > oracled.d/good.ucl <<EOF
label = "test-svc";
program = "/usr/bin/true";
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep '1 services loaded' oracled.log"
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
}
manifest_restart_policies_body()
{
	mkdir -p oracled.d

	cat > oracled.d/always.ucl <<EOF
label = "svc-always";
program = "/usr/bin/true";
restart = "always";
EOF
	cat > oracled.d/failure.ucl <<EOF
label = "svc-failure";
program = "/usr/bin/true";
restart = "on-failure";
EOF
	cat > oracled.d/never.ucl <<EOF
label = "svc-never";
program = "/usr/bin/true";
restart = "never";
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'svc-always.*restart=always' oracled.log"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'svc-failure.*restart=on-failure' oracled.log"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'svc-never.*restart=never' oracled.log"
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
}
manifest_capabilities_body()
{
	mkdir -p oracled.d

	cat > oracled.d/caps.ucl <<EOF
label = "svc-caps";
program = "/usr/bin/true";
capabilities {
    paths = ["/dev/cap_rt", "/etc/oracled.conf"];
    system = ["kldload", "reboot"];
}
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'capabilities: paths=2 network=0 system=0x9' oracled.log"
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
}
depgraph_order_body()
{
	mkdir -p oracled.d

	# B requires A.  Even though b.ucl sorts before a.ucl,
	# A should appear first in the sorted order.
	cat > oracled.d/b-svc.ucl <<EOF
label = "svc-b";
program = "/usr/bin/true";
provides = ["B"];
requires = ["A"];
EOF
	cat > oracled.d/a-svc.ucl <<EOF
label = "svc-a";
program = "/usr/bin/true";
provides = ["A"];
requires = ["ORACLED"];
EOF

	start_oracled
	# In the log, svc-a should appear before svc-b.
	a_line=$(grep -n 'service: svc-a' oracled.log | head -1 | cut -d: -f1)
	b_line=$(grep -n 'service: svc-b' oracled.log | head -1 | cut -d: -f1)
	if [ -z "$a_line" ] || [ -z "$b_line" ]; then
		cat oracled.log
		atf_fail "could not find service log lines"
	fi
	if [ "$a_line" -ge "$b_line" ]; then
		cat oracled.log
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
}
depgraph_cycle_body()
{
	mkdir -p oracled.d

	cat > oracled.d/x.ucl <<EOF
label = "svc-x";
program = "/usr/bin/true";
provides = ["X"];
requires = ["Y"];
EOF
	cat > oracled.d/y.ucl <<EOF
label = "svc-y";
program = "/usr/bin/true";
provides = ["Y"];
requires = ["X"];
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'cycle detected' oracled.log"
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
}
depgraph_unknown_provider_body()
{
	mkdir -p oracled.d

	cat > oracled.d/lonely.ucl <<EOF
label = "svc-lonely";
program = "/usr/bin/true";
requires = ["nonexistent"];
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'unknown provider.*nonexistent' oracled.log"
	# Service should still be loaded and sorted.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'sorted 1 services' oracled.log"
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
}
depgraph_duplicate_label_body()
{
	mkdir -p oracled.d

	cat > oracled.d/dup1.ucl <<EOF
label = "same-name";
program = "/usr/bin/true";
EOF
	cat > oracled.d/dup2.ucl <<EOF
label = "same-name";
program = "/usr/bin/true";
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'duplicate label.*same-name' oracled.log"
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
}
depgraph_duplicate_provides_body()
{
	mkdir -p oracled.d

	cat > oracled.d/p1.ucl <<EOF
label = "svc-p1";
program = "/usr/bin/true";
provides = ["shared"];
EOF
	cat > oracled.d/p2.ucl <<EOF
label = "svc-p2";
program = "/usr/bin/true";
provides = ["shared"];
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'both provide.*shared' oracled.log"
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
}
depgraph_oracled_implicit_body()
{
	mkdir -p oracled.d

	cat > oracled.d/needs-oracle.ucl <<EOF
label = "svc-needs-oracle";
program = "/usr/bin/true";
requires = ["ORACLED"];
EOF

	start_oracled
	# Should sort without warning about unknown provider.
	atf_check -s not-exit:0 sh -c \
	    "grep 'unknown provider.*ORACLED' oracled.log"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'sorted 1 services' oracled.log"
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
}
manifest_bad_ucl_syntax_body()
{
	mkdir -p oracled.d

	# Invalid UCL — unclosed brace.
	cat > oracled.d/broken.ucl <<EOF
label = "broken";
program = "/usr/bin/true";
capabilities {
    system = ["kldload"
EOF

	# Valid one to confirm it still loads.
	cat > oracled.d/valid.ucl <<EOF
label = "valid-svc";
program = "/usr/bin/true";
EOF

	start_oracled
	# broken.ucl should produce a parse error.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep -i 'broken.ucl' oracled.log"
	# valid-svc should still load.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded valid-svc' oracled.log"
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
}
manifest_bad_restart_value_body()
{
	mkdir -p oracled.d

	cat > oracled.d/bad-restart.ucl <<EOF
label = "bad-restart";
program = "/usr/bin/true";
restart = "whenever";
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'unknown restart policy.*whenever' oracled.log"
	# Should default to never.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'bad-restart.*restart=never' oracled.log"
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
}
manifest_empty_label_body()
{
	mkdir -p oracled.d

	cat > oracled.d/empty-label.ucl <<EOF
label = "";
program = "/usr/bin/true";
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'missing or empty label' oracled.log"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep '0 services loaded' oracled.log"
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
}
manifest_bad_cap_path_body()
{
	mkdir -p oracled.d

	cat > oracled.d/relcap.ucl <<EOF
label = "relcap-svc";
program = "/usr/bin/true";
capabilities {
    paths = ["relative/path"];
}
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'must be absolute.*relative/path' oracled.log"
	# Service still loads, just without that cap path.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded relcap-svc' oracled.log"
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
}
manifest_bad_system_gate_body()
{
	mkdir -p oracled.d

	cat > oracled.d/badgate.ucl <<EOF
label = "badgate-svc";
program = "/usr/bin/true";
capabilities {
    system = ["kldload", "fakegate"];
}
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'unknown system gate.*fakegate' oracled.log"
	# kldload should still be parsed (0x1).
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'capabilities: paths=0 network=0 system=0x1' oracled.log"
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
}
manifest_unknown_field_ignored_body()
{
	mkdir -p oracled.d

	cat > oracled.d/extra.ucl <<EOF
label = "extra-svc";
program = "/usr/bin/true";
jail = "net-agent";
custom_thing = "hello";
EOF

	start_oracled
	# Service should load despite unknown fields.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded extra-svc' oracled.log"
	# Unknown fields must not appear in log output.
	atf_check -s not-exit:0 sh -c \
	    "grep 'jail' oracled.log"
	atf_check -s not-exit:0 sh -c \
	    "grep 'custom_thing' oracled.log"
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
}
manifest_cap_network_body()
{
	mkdir -p oracled.d

	cat > oracled.d/netcap.ucl <<EOF
label = "net-svc";
program = "/usr/bin/true";
capabilities {
    network = [
        { port = 443; protocol = "tcp"; direction = "bind"; },
        { port = 80; protocol = "tcp"; direction = "bind"; },
    ];
}
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'capabilities: paths=0 network=2 system=0x0' oracled.log"
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
}
manifest_all_fields_body()
{
	mkdir -p oracled.d

	cat > oracled.d/full.ucl <<EOF
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

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'full-svc.*restart=on-failure' oracled.log"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'provides: fulltest' oracled.log"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'requires: ORACLED' oracled.log"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'capabilities: paths=1 network=1 system=0x40' oracled.log"
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
}
depgraph_three_level_body()
{
	mkdir -p oracled.d

	# C requires B requires A.
	# Files sorted: a.ucl, b.ucl, c.ucl — but deps force A, B, C.
	cat > oracled.d/c-svc.ucl <<EOF
label = "svc-c";
program = "/usr/bin/true";
provides = ["C"];
requires = ["B"];
EOF
	cat > oracled.d/b-svc.ucl <<EOF
label = "svc-b";
program = "/usr/bin/true";
provides = ["B"];
requires = ["A"];
EOF
	cat > oracled.d/a-svc.ucl <<EOF
label = "svc-a";
program = "/usr/bin/true";
provides = ["A"];
EOF

	start_oracled
	a_line=$(grep -n 'service: svc-a' oracled.log | head -1 | cut -d: -f1)
	b_line=$(grep -n 'service: svc-b' oracled.log | head -1 | cut -d: -f1)
	c_line=$(grep -n 'service: svc-c' oracled.log | head -1 | cut -d: -f1)
	if [ -z "$a_line" ] || [ -z "$b_line" ] || [ -z "$c_line" ]; then
		cat oracled.log
		atf_fail "could not find all service log lines"
	fi
	if [ "$a_line" -ge "$b_line" ] || [ "$b_line" -ge "$c_line" ]; then
		cat oracled.log
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
}
depgraph_independent_body()
{
	mkdir -p oracled.d

	cat > oracled.d/alpha.ucl <<EOF
label = "svc-alpha";
program = "/usr/bin/true";
EOF
	cat > oracled.d/beta.ucl <<EOF
label = "svc-beta";
program = "/usr/bin/true";
EOF
	cat > oracled.d/gamma.ucl <<EOF
label = "svc-gamma";
program = "/usr/bin/true";
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'sorted 3 services' oracled.log"
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
}
reload_add_service_body()
{
	mkdir -p oracled.d
	cat > oracled.d/original.ucl <<EOF
label = "original";
program = "/usr/bin/true";
EOF
	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded original' oracled.log"

	# Add a new manifest and send SIGHUP.
	cat > oracled.d/added.ucl <<EOF
label = "added-svc";
program = "/usr/bin/true";
EOF
	kill -HUP "$daemon_pid"
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'reload:.*1 new' oracled.log"
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
}
reload_remove_service_body()
{
	mkdir -p oracled.d
	cat > oracled.d/keeper.ucl <<EOF
label = "keeper";
program = "/usr/bin/true";
EOF
	cat > oracled.d/doomed.ucl <<EOF
label = "doomed";
program = "/usr/bin/true";
EOF
	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded doomed' oracled.log"

	# Remove manifest and reload.
	rm -f oracled.d/doomed.ucl
	kill -HUP "$daemon_pid"
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'removing.*doomed' oracled.log"
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
}
reload_change_manifest_body()
{
	mkdir -p oracled.d
	cat > oracled.d/morph.ucl <<EOF
label = "morph";
program = "/usr/bin/true";
restart = "never";
EOF
	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded morph' oracled.log"

	# Change the manifest and reload.
	cat > oracled.d/morph.ucl <<EOF
label = "morph";
program = "/usr/bin/true";
restart = "always";
EOF
	kill -HUP "$daemon_pid"
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'restarting.*morph.*(manifest changed)' oracled.log"
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
}
reload_no_changes_body()
{
	mkdir -p oracled.d
	cat > oracled.d/stable.ucl <<EOF
label = "stable";
program = "/usr/bin/true";
EOF
	start_oracled
	kill -HUP "$daemon_pid"
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'reload: 0 new, 0 changed, 0 removed' oracled.log"
	stop_oracled
}
reload_no_changes_cleanup()
{
	cleanup_common
}

atf_test_case reload_config_changes cleanup
reload_config_changes_head()
{
	atf_set "descr" "reload re-reads config file for manifest_dir changes"
}
reload_config_changes_body()
{
	mkdir -p oracled.d
	mkdir -p oracled2.d
	cat > oracled.d/first.ucl <<EOF
label = "first-svc";
program = "/usr/bin/true";
EOF
	cat > oracled2.d/second.ucl <<EOF
label = "second-svc";
program = "/usr/bin/true";
EOF

	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded first-svc' oracled.log"

	# Change manifest_dir in config to point to oracled2.d
	cat > "$conffile" <<EOF
manifest_dir = "$(pwd)/oracled2.d";
EOF
	kill -HUP "$daemon_pid"
	sleep 1
	# After reload, first-svc should be removed and second-svc added.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'removing.*first-svc' oracled.log"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'reload:.*1 new.*1 removed' oracled.log"
	stop_oracled
}
reload_config_changes_cleanup()
{
	cleanup_common
	rm -rf oracled2.d
}

atf_test_case reload_bad_manifest_rejected cleanup
reload_bad_manifest_rejected_head()
{
	atf_set "descr" "reload rejects invalid new manifests"
}
reload_bad_manifest_rejected_body()
{
	mkdir -p oracled.d
	cat > oracled.d/good.ucl <<EOF
label = "good-svc";
program = "/usr/bin/true";
EOF
	start_oracled

	# Add a manifest with a nonexistent program.
	cat > oracled.d/bad.ucl <<EOF
label = "bad-svc";
program = "/nonexistent/program";
EOF
	kill -HUP "$daemon_pid"
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'rejecting.*bad-svc' oracled.log"
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
}
reload_cycle_rejected_body()
{
	mkdir -p oracled.d
	cat > oracled.d/alpha.ucl <<EOF
label = "alpha";
program = "/usr/bin/true";
provides = ["A"];
EOF
	start_oracled

	# Add two manifests that form a cycle between themselves.
	cat > oracled.d/cycle-x.ucl <<EOF
label = "cycle-x";
program = "/usr/bin/true";
provides = ["X"];
requires = ["Y"];
EOF
	cat > oracled.d/cycle-y.ucl <<EOF
label = "cycle-y";
program = "/usr/bin/true";
provides = ["Y"];
requires = ["X"];
EOF
	kill -HUP "$daemon_pid"
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'dependency graph rejected\|depgraph_sort failed' oracled.log"
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
}
reload_multiple_add_remove_body()
{
	mkdir -p oracled.d
	cat > oracled.d/keep.ucl <<EOF
label = "keep-svc";
program = "/usr/bin/true";
EOF
	cat > oracled.d/remove1.ucl <<EOF
label = "remove1";
program = "/usr/bin/true";
EOF
	cat > oracled.d/remove2.ucl <<EOF
label = "remove2";
program = "/usr/bin/true";
EOF
	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep '3 services launched' oracled.log"

	# Remove two, add two.
	rm -f oracled.d/remove1.ucl oracled.d/remove2.ucl
	cat > oracled.d/add1.ucl <<EOF
label = "add1";
program = "/usr/bin/true";
EOF
	cat > oracled.d/add2.ucl <<EOF
label = "add2";
program = "/usr/bin/true";
EOF
	kill -HUP "$daemon_pid"
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'reload: 2 new, 0 changed, 2 removed' oracled.log"
	# keep-svc must not appear in removed or changed
	atf_check -s not-exit:0 sh -c \
	    "grep 'removing.*keep-svc' oracled.log"
	atf_check -s not-exit:0 sh -c \
	    "grep 'restarting.*keep-svc' oracled.log"
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
}
reload_change_and_add_body()
{
	mkdir -p oracled.d
	cat > oracled.d/existing.ucl <<EOF
label = "existing";
program = "/usr/bin/true";
restart = "never";
EOF
	start_oracled

	# Change existing, add new.
	cat > oracled.d/existing.ucl <<EOF
label = "existing";
program = "/usr/bin/true";
restart = "always";
EOF
	cat > oracled.d/fresh.ucl <<EOF
label = "fresh";
program = "/usr/bin/true";
EOF
	kill -HUP "$daemon_pid"
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'reload: 1 new, 1 changed, 0 removed' oracled.log"
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'restarting.*existing.*(manifest changed)' oracled.log"
	stop_oracled
}
reload_change_and_add_cleanup()
{
	cleanup_common
}

atf_test_case reload_bad_config_keeps_existing cleanup
reload_bad_config_keeps_existing_head()
{
	atf_set "descr" "reload with broken config file keeps existing config"
}
reload_bad_config_keeps_existing_body()
{
	mkdir -p oracled.d
	cat > oracled.d/svc.ucl <<EOF
label = "svc";
program = "/usr/bin/true";
EOF
	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'loaded svc' oracled.log"

	# Corrupt the config file.
	echo "this is { broken ucl {{{" > "$conffile"
	kill -HUP "$daemon_pid"
	sleep 1
	# Should log a warning about parse error.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'config.*parse error\|keeping existing' oracled.log"
	# Services should still reload (manifests are separate from config).
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'reload: 0 new, 0 changed, 0 removed' oracled.log"
	stop_oracled
}
reload_bad_config_keeps_existing_cleanup()
{
	cleanup_common
}

atf_test_case reload_empty_dir cleanup
reload_empty_dir_head()
{
	atf_set "descr" "reload to empty manifest dir removes all services"
}
reload_empty_dir_body()
{
	mkdir -p oracled.d
	cat > oracled.d/one.ucl <<EOF
label = "one";
program = "/usr/bin/true";
EOF
	cat > oracled.d/two.ucl <<EOF
label = "two";
program = "/usr/bin/true";
EOF
	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep '2 services launched' oracled.log"

	# Remove all manifests.
	rm -f oracled.d/*.ucl
	kill -HUP "$daemon_pid"
	sleep 1
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'reload: 0 new, 0 changed, 2 removed' oracled.log"
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
}
reload_duplicate_label_at_startup_body()
{
	mkdir -p oracled.d
	cat > oracled.d/orig.ucl <<EOF
label = "dup-label";
program = "/usr/bin/true";
EOF
	cat > oracled.d/clone.ucl <<EOF
label = "dup-label";
program = "/usr/bin/true";
restart = "always";
EOF
	start_oracled
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'duplicate label.*dup-label' oracled.log"
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
}
reload_idempotent_sighup_body()
{
	mkdir -p oracled.d
	cat > oracled.d/svc.ucl <<EOF
label = "stable-svc";
program = "/usr/bin/true";
EOF
	start_oracled

	# Send 3 SIGHUPs with delays to avoid coalescing.
	kill -HUP "$daemon_pid"; sleep 0.5
	kill -HUP "$daemon_pid"; sleep 0.5
	kill -HUP "$daemon_pid"; sleep 1

	# All should report 0 changes.
	count=$(grep -c 'reload: 0 new, 0 changed, 0 removed' oracled.log)
	if [ "$count" -lt 3 ]; then
		cat oracled.log
		atf_fail "expected at least 3 no-change reloads, got $count"
	fi
	stop_oracled
}
reload_idempotent_sighup_cleanup()
{
	cleanup_common
}

atf_test_case reload_claims_config_update cleanup
reload_claims_config_update_head()
{
	atf_set "descr" "reload updates internal claim config from new config file"
}
reload_claims_config_update_body()
{
	mkdir -p oracled.d

	pidfile="$(pwd)/oracled.pid"
	conffile="$(pwd)/oracled.conf"
	logfile="$(pwd)/oracled.log"

	cat > oracled.d/svc.ucl <<EOF
label = "svc";
program = "/usr/bin/true";
EOF

	# Start with claims in config.
	cat > "$conffile" <<EOF
manifest_dir = "$(pwd)/oracled.d";
claims {
    paths = ["/dev/null", "/tmp"];
    system = ["kldload", "reboot"];
}
EOF

	oracled -d -T -f "$conffile" -p "$pidfile" >"$logfile" 2>&1 &
	daemon_pid=$!
	i=0
	while [ ! -s "$pidfile" ] && [ $i -lt 50 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -s "$pidfile" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "oracled did not create pidfile"
	fi

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'claims paths=2 network=0 system=0x9' oracled.log"

	# Change claims: drop /tmp, add /var, drop reboot, add sysctl.
	# Also change manifest_dir to prove config was re-read.
	mkdir -p oracled2.d
	cat > oracled2.d/svc.ucl <<EOF
label = "svc";
program = "/usr/bin/true";
EOF
	cat > "$conffile" <<EOF
manifest_dir = "$(pwd)/oracled2.d";
claims {
    paths = ["/dev/null", "/var"];
    system = ["kldload", "sysctl"];
}
EOF
	kill -HUP "$daemon_pid"
	sleep 1
	# If config was re-read, manifest_dir changed and reload scans oracled2.d.
	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'scanning $(pwd)/oracled2.d' oracled.log"
	# No parse error should be logged.
	atf_check -s not-exit:0 sh -c \
	    "grep 'config.*parse error' oracled.log"
	stop_oracled
}
reload_claims_config_update_cleanup()
{
	cleanup_common
	rm -rf oracled2.d
}

# --- config ---

atf_test_case config_manifest_dir cleanup
config_manifest_dir_head()
{
	atf_set "descr" "manifest_dir config key is logged"
}
config_manifest_dir_body()
{
	mkdir -p oracled.d

	pidfile="$(pwd)/oracled.pid"
	conffile="$(pwd)/oracled.conf"
	logfile="$(pwd)/oracled.log"

	cat > "$conffile" <<EOF
manifest_dir = "$(pwd)/oracled.d";
EOF

	oracled -d -T -f "$conffile" -p "$pidfile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -s "$pidfile" ] && [ $i -lt 50 ]; do
		i=$((i + 1))
		sleep 0.1
	done

	atf_check -s exit:0 -o ignore sh -c \
	    "grep 'manifest_dir=$(pwd)/oracled.d' oracled.log"
	stop_oracled
}
config_manifest_dir_cleanup()
{
	cleanup_common
}

# --- service launch (test mode) ---

atf_test_case svc_test_mode_skips_exec cleanup
svc_test_mode_skips_exec_head()
{
	atf_set "descr" "Test mode logs skip message for each service"
}
svc_test_mode_skips_exec_body()
{
	mkdir -p oracled.d
	cat > oracled.d/mysvc.ucl <<EOF
label = "mysvc";
program = "/bin/sleep";
EOF
	start_oracled
	grep "test mode, skipping exec" oracled.log || \
	    atf_fail "expected skip message in log"
	stop_oracled
}
svc_test_mode_skips_exec_cleanup()
{
	cleanup_common
}

atf_test_case svc_launch_order_logged cleanup
svc_launch_order_logged_head()
{
	atf_set "descr" "Services are launched in dependency order"
}
svc_launch_order_logged_body()
{
	mkdir -p oracled.d
	cat > oracled.d/aaa-base.ucl <<EOF
label = "base";
program = "/usr/bin/true";
provides = ["base"];
EOF
	cat > oracled.d/zzz-app.ucl <<EOF
label = "app";
program = "/usr/bin/true";
requires = ["base"];
EOF
	start_oracled
	# base should appear before app in the log
	base_line=$(grep -n 'service base:' oracled.log | head -1 | cut -d: -f1)
	app_line=$(grep -n 'service app:' oracled.log | head -1 | cut -d: -f1)
	if [ -z "$base_line" ] || [ -z "$app_line" ]; then
		cat oracled.log
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
}
svc_capabilities_logged_body()
{
	mkdir -p oracled.d
	cat > oracled.d/capsvc.ucl <<EOF
label = "capsvc";
program = "/usr/bin/true";
capabilities {
    paths = ["/var/log"];
    system = ["kldload", "reboot"];
}
EOF
	start_oracled
	grep "capabilities: paths=1" oracled.log || \
	    atf_fail "expected capability log line"
	grep "system=0x" oracled.log || \
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
	atf_add_test_case reload_config_changes
	atf_add_test_case reload_bad_manifest_rejected
	atf_add_test_case reload_cycle_rejected
	atf_add_test_case reload_multiple_add_remove
	atf_add_test_case reload_change_and_add
	atf_add_test_case reload_bad_config_keeps_existing
	atf_add_test_case reload_empty_dir
	atf_add_test_case reload_duplicate_label_at_startup
	atf_add_test_case reload_idempotent_sighup
	atf_add_test_case reload_claims_config_update

	# Config
	atf_add_test_case config_manifest_dir

	# Service launch (test mode — verifies log output)
	atf_add_test_case svc_test_mode_skips_exec
	atf_add_test_case svc_launch_order_logged
	atf_add_test_case svc_capabilities_logged
}
