#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# ATF tests for libcapbundle — bundle parsing, validation, and cycle detection.
#

# Development builds can point the installed ATF program at matching object
# binaries without tainting the atf-sh interpreter via its parent environment.
if [ -n "${TEST_BINDIR:-}" ]; then
	PATH="${TEST_BINDIR}:${PATH}"
	export PATH
fi
if [ -n "${TEST_LIBDIR:-}" ]; then
	LD_LIBRARY_PATH="${TEST_LIBDIR}"
	export LD_LIBRARY_PATH
fi

# Helper: create a minimal valid bundle
create_bundle() {
	local name="$1" bundle_id="$2" program="$3" provides="$4"
	local dir="${TMPDIR}/${name}.cap"

	mkdir -p "${dir}/etc"
	mkdir -p "${dir}/bin"

	# Create a dummy executable
	cat > "${dir}/bin/${program}" <<'PROG'
#!/bin/sh
exec sleep 3600
PROG
	chmod 755 "${dir}/bin/${program}"

	# Create service manifest
	cat > "${dir}/etc/${program}.ucl" <<UCL
bundle_id = "${bundle_id}";
version = "1.0";
author = "test";
program = "${program}";
provides = ["${provides}"];
restart = "on-failure";
UCL

	echo "${dir}"
}

# Helper: create bundle with requires
create_bundle_with_requires() {
	local name="$1" bundle_id="$2" program="$3" provides="$4" requires="$5"
	local dir

	dir=$(create_bundle "$name" "$bundle_id" "$program" "$provides")
	# Append requires to the manifest
	cat >> "${dir}/etc/${program}.ucl" <<UCL
requires = ["${requires}"];
UCL
	echo "${dir}"
}

# ---------------------------------------------------------------
# Test: Open a valid bundle
# ---------------------------------------------------------------
atf_test_case open_valid_bundle cleanup
open_valid_bundle_head() {
	atf_set "descr" "Open and parse a valid .cap bundle"
}
open_valid_bundle_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}"

	dir=$(create_bundle "TestApp" "org.test.cap" "testd" "org.test.service")

	# Use the verify tool to test parsing
	atf_check -s exit:0 -o match:"Verification: PASSED" \
	    servicectl verify "${dir}"
}
open_valid_bundle_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: Missing etc/ directory
# ---------------------------------------------------------------
atf_test_case missing_services_dir cleanup
missing_services_dir_head() {
	atf_set "descr" "Reject bundle with no Services directory"
}
missing_services_dir_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/Bad.cap/bin"

	atf_check -s exit:1 -e match:"etc/ not found" \
	    servicectl verify "${TMPDIR}/Bad.cap"
}
missing_services_dir_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: Missing binary
# ---------------------------------------------------------------
atf_test_case missing_binary cleanup
missing_binary_head() {
	atf_set "descr" "Reject bundle where program binary doesn't exist"
}
missing_binary_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/Bad.cap/etc"
	mkdir -p "${TMPDIR}/Bad.cap/bin"

	cat > "${TMPDIR}/Bad.cap/etc/ghost.ucl" <<UCL
bundle_id = "org.test.bad";
version = "1.0";
author = "test";
program = "ghost";
provides = ["org.test.ghost"];
UCL
	# No binary created — should fail verification

	atf_check -s exit:1 -e match:"FAILED" \
	    servicectl verify "${TMPDIR}/Bad.cap"
}
missing_binary_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: Duplicate provides within bundle
# ---------------------------------------------------------------
atf_test_case duplicate_provides cleanup
duplicate_provides_head() {
	atf_set "descr" "Reject bundle with duplicate provides names"
}
duplicate_provides_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/Dup.cap/etc"
	mkdir -p "${TMPDIR}/Dup.cap/bin"

	for prog in svc1 svc2; do
		printf '#!/bin/sh\nsleep 3600\n' > "${TMPDIR}/Dup.cap/bin/${prog}"
		chmod 755 "${TMPDIR}/Dup.cap/bin/${prog}"
		cat > "${TMPDIR}/Dup.cap/etc/${prog}.ucl" <<UCL
bundle_id = "org.test.dup";
version = "1.0";
author = "test";
program = "${prog}";
provides = ["org.test.same.name"];
UCL
	done

	atf_check -s exit:1 -e match:"duplicate provides" \
	    servicectl verify "${TMPDIR}/Dup.cap"
}
duplicate_provides_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: Circular dependency within bundle
# ---------------------------------------------------------------
atf_test_case self_require cleanup
self_require_head() {
	atf_set "descr" "Reject service that requires its own provides"
}
self_require_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/Loop.cap/etc"
	mkdir -p "${TMPDIR}/Loop.cap/bin"

	printf '#!/bin/sh\nsleep 3600\n' > "${TMPDIR}/Loop.cap/bin/loopd"
	chmod 755 "${TMPDIR}/Loop.cap/bin/loopd"

	cat > "${TMPDIR}/Loop.cap/etc/loopd.ucl" <<UCL
bundle_id = "org.test.loop";
version = "1.0";
author = "test";
program = "loopd";
provides = ["org.test.loopsvc"];
requires = ["org.test.loopsvc"];
UCL

	atf_check -s exit:1 -e match:"requires itself" \
	    servicectl verify "${TMPDIR}/Loop.cap"
}
self_require_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: Cross-bundle cycle detection
# ---------------------------------------------------------------
atf_test_case cross_bundle_cycle cleanup
cross_bundle_cycle_head() {
	atf_set "descr" "Detect circular dependency across two bundles"
}
cross_bundle_cycle_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$

	# Bundle A provides org.a, requires org.b
	create_bundle_with_requires "A" "org.a" "ad" "org.a.svc" "org.b.svc"
	# Bundle B provides org.b, requires org.a
	create_bundle_with_requires "B" "org.b" "bd" "org.b.svc" "org.a.svc"

	# Both bundles are valid individually
	atf_check -s exit:0 -o ignore servicectl verify "${TMPDIR}/A.cap"
	atf_check -s exit:0 -o ignore servicectl verify "${TMPDIR}/B.cap"

	# Together they form a cycle and must be rejected.
	atf_check -s exit:1 -o ignore -e match:"circular dependency" \
	    servicectl verify "${TMPDIR}/A.cap" "${TMPDIR}/B.cap"
}
cross_bundle_cycle_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

atf_test_case duplicate_bundle_ids cleanup
duplicate_bundle_ids_head() {
	atf_set "descr" "A loaded bundle set cannot contain duplicate bundle identifiers"
}
duplicate_bundle_ids_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	create_bundle "One" "org.test.duplicate" "oned" "org.test.one"
	create_bundle "Two" "org.test.duplicate" "twod" "org.test.two"
	atf_check -s exit:1 -o ignore -e match:"duplicate bundle_id" \
	    servicectl verify "${TMPDIR}/One.cap" "${TMPDIR}/Two.cap"
}
duplicate_bundle_ids_cleanup() { rm -rf "$(atf_get_srcdir)/work.$$"; }

# ---------------------------------------------------------------
# Test: Multiple services in one bundle
# ---------------------------------------------------------------
atf_test_case multi_service_bundle cleanup
multi_service_bundle_head() {
	atf_set "descr" "Parse bundle with multiple services"
}
multi_service_bundle_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/Multi.cap/etc"
	mkdir -p "${TMPDIR}/Multi.cap/bin"

	for prog in alpha beta gamma; do
		printf '#!/bin/sh\nsleep 3600\n' > "${TMPDIR}/Multi.cap/bin/${prog}"
		chmod 755 "${TMPDIR}/Multi.cap/bin/${prog}"
		cat > "${TMPDIR}/Multi.cap/etc/${prog}.ucl" <<UCL
bundle_id = "org.test.multi";
version = "2.0";
author = "tester";
program = "${prog}";
provides = ["org.test.multi.${prog}"];
on_demand = true;
UCL
	done

	atf_check -s exit:0 -o match:"Services: 3" \
	    servicectl verify "${TMPDIR}/Multi.cap"
	atf_check -s exit:0 -o match:"org.test.multi.alpha" \
	    servicectl verify "${TMPDIR}/Multi.cap"
	atf_check -s exit:0 -o match:"on_demand: yes" \
	    servicectl verify "${TMPDIR}/Multi.cap"
}
multi_service_bundle_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: Capabilities parsing
# ---------------------------------------------------------------
atf_test_case capabilities_parsing cleanup
capabilities_parsing_head() {
	atf_set "descr" "Parse capabilities (paths, system gates) from manifest"
}
capabilities_parsing_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/Cap.cap/etc"
	mkdir -p "${TMPDIR}/Cap.cap/bin"

	printf '#!/bin/sh\nsleep 3600\n' > "${TMPDIR}/Cap.cap/bin/capd"
	chmod 755 "${TMPDIR}/Cap.cap/bin/capd"

	cat > "${TMPDIR}/Cap.cap/etc/capd.ucl" <<UCL
bundle_id = "org.test.cap";
version = "1.0";
author = "test";
program = "capd";
provides = ["org.test.cap.svc"];
capabilities {
    system = ["reboot", "kldload"];
    paths = ["/var/data", "/etc/config"];
}
UCL

	atf_check -s exit:0 -o match:"Verification: PASSED" \
	    servicectl verify "${TMPDIR}/Cap.cap"
}
capabilities_parsing_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: on_demand flag parsing
# ---------------------------------------------------------------
atf_test_case on_demand_flag cleanup
on_demand_flag_head() {
	atf_set "descr" "Parse on_demand = true/false correctly"
}
on_demand_flag_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$

	dir=$(create_bundle "Boot" "org.test.boot" "bootd" "org.test.boot.svc")
	# Default is on_demand = false (not specified)
	atf_check -s exit:0 -o match:"on_demand: no" \
	    servicectl verify "${dir}"
}
on_demand_flag_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: Network capabilities full parsing (port, protocol, domain,
#       direction, address, prefix)
# ---------------------------------------------------------------
atf_test_case network_capabilities cleanup
network_capabilities_head() {
	atf_set "descr" "Parse full network capability fields (port range, domain, address)"
}
network_capabilities_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/Net.cap/etc"
	mkdir -p "${TMPDIR}/Net.cap/bin"

	printf '#!/bin/sh\nsleep 3600\n' > "${TMPDIR}/Net.cap/bin/netd"
	chmod 755 "${TMPDIR}/Net.cap/bin/netd"

	cat > "${TMPDIR}/Net.cap/etc/netd.ucl" <<'UCL'
bundle_id = "org.test.net";
version = "1.0";
author = "test";
program = "netd";
provides = ["org.test.net.svc"];
capabilities {
    network = [
        {port = 8080; protocol = "tcp"; direction = "bind"; domain = "inet";},
        {ports = "5000-5100"; protocol = "udp"; direction = "connect"; domain = "inet6";},
        {port = 443; protocol = "tcp"; direction = "bind"; address = "192.168.1.0/24";},
    ];
}
UCL

	atf_check -s exit:0 -o match:"Verification: PASSED" \
	    servicectl verify "${TMPDIR}/Net.cap"
}
network_capabilities_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: File capabilities with actions
# ---------------------------------------------------------------
atf_test_case file_capabilities cleanup
file_capabilities_head() {
	atf_set "descr" "Parse file capabilities with action lists"
}
file_capabilities_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/File.cap/etc"
	mkdir -p "${TMPDIR}/File.cap/bin"

	printf '#!/bin/sh\nsleep 3600\n' > "${TMPDIR}/File.cap/bin/filed"
	chmod 755 "${TMPDIR}/File.cap/bin/filed"

	cat > "${TMPDIR}/File.cap/etc/filed.ucl" <<'UCL'
bundle_id = "org.test.file";
version = "1.0";
author = "test";
program = "filed";
provides = ["org.test.file.svc"];
capabilities {
    files = [
        {path = "/var/log/app.log"; actions = ["lookup", "stat", "read",
          "write", "append", "create", "delete", "rename_from",
          "rename_to", "link", "exec", "setattr", "truncate", "connect"];},
        {path = "/var/run/app.pid"; actions = "*";},
    ];
}
UCL

	atf_check -s exit:0 -o match:"Verification: PASSED" \
	    servicectl verify "${TMPDIR}/File.cap"
}
file_capabilities_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: Jail capabilities with object form (name, actions)
# ---------------------------------------------------------------
atf_test_case jail_capabilities cleanup
jail_capabilities_head() {
	atf_set "descr" "Parse full jail capabilities (name, jid, actions)"
}
jail_capabilities_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/Jail.cap/etc"
	mkdir -p "${TMPDIR}/Jail.cap/bin"

	printf '#!/bin/sh\nsleep 3600\n' > "${TMPDIR}/Jail.cap/bin/jaild"
	chmod 755 "${TMPDIR}/Jail.cap/bin/jaild"

	cat > "${TMPDIR}/Jail.cap/etc/jaild.ucl" <<'UCL'
bundle_id = "org.test.jail";
version = "1.0";
author = "test";
program = "jaild";
provides = ["org.test.jail.svc"];
capabilities {
    jails = [
        {name = "webapp"; actions = ["create", "attach"];},
        "dbserver",
    ];
}
UCL

	atf_check -s exit:0 -o match:"Verification: PASSED" \
	    servicectl verify "${TMPDIR}/Jail.cap"
}
jail_capabilities_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: All system gate names accepted
# ---------------------------------------------------------------
atf_test_case all_system_gates cleanup
all_system_gates_head() {
	atf_set "descr" "All valid system gate names are accepted"
}
all_system_gates_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/Gate.cap/etc"
	mkdir -p "${TMPDIR}/Gate.cap/bin"

	printf '#!/bin/sh\nsleep 3600\n' > "${TMPDIR}/Gate.cap/bin/gated"
	chmod 755 "${TMPDIR}/Gate.cap/bin/gated"

	# Every valid gate name from gates.h
	cat > "${TMPDIR}/Gate.cap/etc/gated.ucl" <<'UCL'
bundle_id = "org.test.gate";
version = "1.0";
author = "test";
program = "gated";
provides = ["org.test.gate.svc"];
capabilities {
    system = ["kldload", "kldunload", "kldstat", "reboot",
              "swapon", "swapoff", "sysctl", "kenv",
              "acct", "audit", "kenv_read"];
}
UCL

	atf_check -s exit:0 -o match:"Verification: PASSED" \
	    servicectl verify "${TMPDIR}/Gate.cap"
}
all_system_gates_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: Invalid port value (> 65535) rejects the bundle
# ---------------------------------------------------------------
atf_test_case invalid_port_range cleanup
invalid_port_range_head() {
	atf_set "descr" "Reject port value exceeding 65535"
}
invalid_port_range_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/BadPort.cap/etc"
	mkdir -p "${TMPDIR}/BadPort.cap/bin"

	printf '#!/bin/sh\nsleep 3600\n' > "${TMPDIR}/BadPort.cap/bin/bpd"
	chmod 755 "${TMPDIR}/BadPort.cap/bin/bpd"

	cat > "${TMPDIR}/BadPort.cap/etc/bpd.ucl" <<'UCL'
bundle_id = "org.test.badport";
version = "1.0";
author = "test";
program = "bpd";
provides = ["org.test.badport.svc"];
capabilities {
    network = [
        {port = 70000; protocol = "tcp"; direction = "bind";},
    ];
}
UCL

	atf_check -s exit:1 -e match:"invalid network port range" \
	    servicectl verify "${TMPDIR}/BadPort.cap"
}
invalid_port_range_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: out-of-range stop_timeout rejection
# ---------------------------------------------------------------
atf_test_case stop_timeout_rejected cleanup
stop_timeout_rejected_head() {
	atf_set "descr" "stop_timeout outside 1-300 rejects the manifest"
}
stop_timeout_rejected_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$

	dir=$(create_bundle "Clamp" "org.test.clamp" "clampd" "org.test.clamp.svc")
	# Add extreme stop_timeout
	cat >> "${dir}/etc/clampd.ucl" <<UCL
stop_timeout = 9999;
max_failures = 0;
UCL

	# Security-relevant lifecycle values are rejected, not rewritten.
	atf_check -s exit:1 -e match:"stop_timeout must be between" \
	    servicectl verify "${dir}"
}
stop_timeout_rejected_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: Missing program field causes clear error
# ---------------------------------------------------------------
atf_test_case missing_program cleanup
missing_program_head() {
	atf_set "descr" "UCL without program field produces clear error"
}
missing_program_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/NoProg.cap/etc"
	mkdir -p "${TMPDIR}/NoProg.cap/bin"

	cat > "${TMPDIR}/NoProg.cap/etc/bad.ucl" <<'UCL'
bundle_id = "org.test.noprog";
version = "1.0";
provides = ["org.test.noprog.svc"];
UCL

	atf_check -s exit:1 -e match:"missing 'program' field" \
	    servicectl verify "${TMPDIR}/NoProg.cap"
}
missing_program_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: Missing provides causes verify failure
# ---------------------------------------------------------------
atf_test_case missing_provides cleanup
missing_provides_head() {
	atf_set "descr" "Service with no provides fails verification"
}
missing_provides_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/NoProv.cap/etc"
	mkdir -p "${TMPDIR}/NoProv.cap/bin"

	printf '#!/bin/sh\nsleep 3600\n' > "${TMPDIR}/NoProv.cap/bin/npd"
	chmod 755 "${TMPDIR}/NoProv.cap/bin/npd"

	cat > "${TMPDIR}/NoProv.cap/etc/npd.ucl" <<'UCL'
bundle_id = "org.test.noprov";
version = "1.0";
author = "test";
program = "npd";
UCL

	atf_check -s exit:1 -e match:"has no provides" \
	    servicectl verify "${TMPDIR}/NoProv.cap"
}
missing_provides_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: Missing bundle_id causes verify failure
# ---------------------------------------------------------------
atf_test_case missing_bundle_id cleanup
missing_bundle_id_head() {
	atf_set "descr" "Bundle with no bundle_id fails verification"
}
missing_bundle_id_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/NoId.cap/etc"
	mkdir -p "${TMPDIR}/NoId.cap/bin"

	printf '#!/bin/sh\nsleep 3600\n' > "${TMPDIR}/NoId.cap/bin/noid"
	chmod 755 "${TMPDIR}/NoId.cap/bin/noid"

	cat > "${TMPDIR}/NoId.cap/etc/noid.ucl" <<'UCL'
program = "noid";
provides = ["org.test.noid.svc"];
UCL

	atf_check -s exit:1 -e match:"no bundle_id" \
	    servicectl verify "${TMPDIR}/NoId.cap"
}
missing_bundle_id_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: Non-absolute capability path rejected
# ---------------------------------------------------------------
atf_test_case relative_cap_path cleanup
relative_cap_path_head() {
	atf_set "descr" "Relative capability paths are rejected"
}
relative_cap_path_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/Rel.cap/etc"
	mkdir -p "${TMPDIR}/Rel.cap/bin"

	printf '#!/bin/sh\nsleep 3600\n' > "${TMPDIR}/Rel.cap/bin/reld"
	chmod 755 "${TMPDIR}/Rel.cap/bin/reld"

	cat > "${TMPDIR}/Rel.cap/etc/reld.ucl" <<'UCL'
bundle_id = "org.test.rel";
version = "1.0";
author = "test";
program = "reld";
provides = ["org.test.rel.svc"];
capabilities {
    paths = ["relative/path", "/valid/path"];
}
UCL

	atf_check -s exit:1 -e match:"invalid capabilities.paths" \
	    servicectl verify "${TMPDIR}/Rel.cap"
}
relative_cap_path_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: Unknown system gate name produces warning
# ---------------------------------------------------------------
atf_test_case unknown_gate_name cleanup
unknown_gate_name_head() {
	atf_set "descr" "Unknown system gate rejects the manifest"
}
unknown_gate_name_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/UGate.cap/etc"
	mkdir -p "${TMPDIR}/UGate.cap/bin"

	printf '#!/bin/sh\nsleep 3600\n' > "${TMPDIR}/UGate.cap/bin/ugd"
	chmod 755 "${TMPDIR}/UGate.cap/bin/ugd"

	cat > "${TMPDIR}/UGate.cap/etc/ugd.ucl" <<'UCL'
bundle_id = "org.test.ugate";
version = "1.0";
author = "test";
program = "ugd";
provides = ["org.test.ugate.svc"];
capabilities {
    system = ["reboot", "nonexistent_gate", "kldload"];
}
UCL

	atf_check -s exit:1 -e match:"unknown system gate" \
	    servicectl verify "${TMPDIR}/UGate.cap"
}
unknown_gate_name_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
# Test: Empty jail name string is rejected (not added)
# ---------------------------------------------------------------
atf_test_case empty_jail_name cleanup
empty_jail_name_head() {
	atf_set "descr" "Jail with empty name string rejects the manifest"
}
empty_jail_name_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}/EJail.cap/etc"
	mkdir -p "${TMPDIR}/EJail.cap/bin"

	printf '#!/bin/sh\nsleep 3600\n' > "${TMPDIR}/EJail.cap/bin/ejd"
	chmod 755 "${TMPDIR}/EJail.cap/bin/ejd"

	cat > "${TMPDIR}/EJail.cap/etc/ejd.ucl" <<'UCL'
bundle_id = "org.test.ejail";
version = "1.0";
author = "test";
program = "ejd";
provides = ["org.test.ejail.svc"];
capabilities {
    jails = [
        "",
        "validjail",
    ];
}
UCL

	atf_check -s exit:1 -e match:"invalid jail name" \
	    servicectl verify "${TMPDIR}/EJail.cap"
}
empty_jail_name_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

atf_test_case arguments_environment_and_vsock cleanup
arguments_environment_and_vsock_head() {
	atf_set "descr" "Parse literal arguments, environment, and VSOCK capabilities"
}
arguments_environment_and_vsock_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	dir=$(create_bundle "Exec" "org.test.exec" "execd" "org.test.exec.svc")
	cat >> "${dir}/etc/execd.ucl" <<'UCL'
arguments = ["--literal value", "--flag"];
environment { APP_MODE = "test"; EMPTY = ""; }
capabilities {
	services = ["mount", "node", "accounting", "identity"];
    vsock = [
        { cid = "any"; ports = "1024-2048"; direction = "connect"; },
        { cid = 7; port = 9000; direction = "bind"; },
    ];
}
UCL
	atf_check -s exit:0 -o match:'arguments: \[--literal value\] \[--flag\]' \
	    -o match:'environment:.*\[APP_MODE=test\].*\[EMPTY=\]' \
	    -o match:'capabilities: paths=0 files=0 network=0 jails=0 vsock=2 services=4 system=0x0' \
	    -o match:'service: mount' -o match:'service: node' \
	    -o match:'service: accounting' \
	    -o match:'service: identity' \
	    -o match:'vsock: cid=7 ports=9000-9000 direction=bind' \
	    servicectl verify "${dir}"
}
arguments_environment_and_vsock_cleanup() { rm -rf "$(atf_get_srcdir)/work.$$"; }

atf_test_case unknown_key_rejected cleanup
unknown_key_rejected_head() { atf_set "descr" "Reject misspelled manifest keys"; }
unknown_key_rejected_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	dir=$(create_bundle "Typo" "org.test.typo" "typod" "org.test.typo.svc")
	cat >> "${dir}/etc/typod.ucl" <<'UCL'
restert = "always";
UCL
	atf_check -s exit:1 -e match:"unknown key 'restert'" servicectl verify "${dir}"
}
unknown_key_rejected_cleanup() { rm -rf "$(atf_get_srcdir)/work.$$"; }

atf_test_case reserved_environment_rejected cleanup
reserved_environment_rejected_head() {
	atf_set "descr" "Manifest cannot replace serviced protocol environment"
}
reserved_environment_rejected_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	dir=$(create_bundle "Env" "org.test.env" "envd" "org.test.env.svc")
	cat >> "${dir}/etc/envd.ucl" <<'UCL'
environment { ORACLED_CHANNEL_FD = "99"; }
UCL
	atf_check -s exit:1 -e match:"invalid environment entry" servicectl verify "${dir}"
	sed -i '' 's/ORACLED_CHANNEL_FD/SERVICE_BOOTSTRAP_FD/' \
	    "${dir}/etc/envd.ucl"
	atf_check -s exit:1 -e match:"invalid environment entry" \
	    servicectl verify "${dir}"
	sed -i '' 's/SERVICE_BOOTSTRAP_FD/NETWORKCMP/' \
	    "${dir}/etc/envd.ucl"
	atf_check -s exit:1 -e match:"invalid environment entry" \
	    servicectl verify "${dir}"
	sed -i '' 's/NETWORKCMP/FILESYSTEMCMP/' \
	    "${dir}/etc/envd.ucl"
	atf_check -s exit:1 -e match:"invalid environment entry" \
	    servicectl verify "${dir}"
}
reserved_environment_rejected_cleanup() { rm -rf "$(atf_get_srcdir)/work.$$"; }

atf_test_case component_manifest cleanup
component_manifest_head() {
	atf_set "descr" "Versioned components add validated provider dependencies"
}
component_manifest_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	dir=$(create_bundle "Components" "org.test.components" "appd" \
	    "org.test.components.app")
	printf '#!/bin/sh\nexit 0\n' > "${dir}/bin/providerd"
	chmod 755 "${dir}/bin/providerd"
	cat > "${dir}/etc/providerd.ucl" <<'UCL'
bundle_id = "org.test.components";
version = "1.0";
author = "test";
program = "providerd";
provides = ["org.test.component.provider"];
implements = [{
	interface = "org.5bsd.cmp.network";
	version = "1.0.0";
}];
UCL
	cat >> "${dir}/etc/appd.ucl" <<'UCL'
components {
	network {
		interface = "org.5bsd.cmp.network";
		version = "1.0.0";
		scope = "private";
		options { mtu = 1500; quic = false; }
	}
}
UCL
	atf_check -s exit:0 -o match:"Verification: PASSED" \
	    servicectl verify "${dir}"
}
component_manifest_cleanup() { rm -rf "$(atf_get_srcdir)/work.$$"; }

atf_test_case component_resolution_policy cleanup
component_resolution_policy_head() {
	atf_set "descr" \
	    "Provider resolution is exact, deterministic, pinnable, and boot-ordered"
}
component_resolution_policy_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$

	p1=$(create_bundle "ProviderOne" "org.test.provider.one" "p1d" \
	    "org.test.provider.one")
	cat >> "${p1}/etc/p1d.ucl" <<'UCL'
implements = [{
	interface = "org.test.cmp.storage";
	version = "1.0.0";
}];
UCL
	consumer=$(create_bundle "Consumer" "org.test.consumer" "consumerd" \
	    "org.test.consumer")
	cat >> "${consumer}/etc/consumerd.ucl" <<'UCL'
components {
	store {
		interface = "org.test.cmp.storage";
		version = "1.0.0";
	}
}
UCL
	atf_check -s exit:0 \
	    -o match:"component: store.*provider=org.test.provider.one.*required=yes" \
	    servicectl verify "${p1}" "${consumer}"
	atf_check -s exit:0 \
	    -o match:"component: store.*lifetime=process.*sharing=exclusive.*required=yes.*options=\\{\\}" \
	    servicectl verify --effective "${p1}" "${consumer}"
	atf_check -s exit:0 -o match:"user: capability" \
	    servicectl verify --effective "${p1}" "${consumer}"
	atf_check -s exit:0 -o match:"group: capability" \
	    servicectl verify --effective "${p1}" "${consumer}"

	p2=$(create_bundle "ProviderTwo" "org.test.provider.two" "p2d" \
	    "org.test.provider.two")
	cat >> "${p2}/etc/p2d.ucl" <<'UCL'
implements = [{
	interface = "org.test.cmp.storage";
	version = "1.0.0";
}];
UCL
	atf_check -s exit:1 -o ignore -e match:"has 2 providers.*pin provider" \
	    servicectl verify "${p1}" "${p2}" "${consumer}"

	pinned=$(create_bundle "Pinned" "org.test.pinned" "pinnedd" \
	    "org.test.pinned")
	cat >> "${pinned}/etc/pinnedd.ucl" <<'UCL'
components {
	store {
		interface = "org.test.cmp.storage";
		version = "1.0.0";
		provider = "org.test.provider.two";
	}
}
UCL
	atf_check -s exit:0 \
	    -o match:"component: store.*provider=org.test.provider.two" \
	    servicectl verify "${p1}" "${p2}" "${pinned}"

	ondemand=$(create_bundle "OnDemandProvider" "org.test.provider.lazy" \
	    "lazyd" "org.test.provider.lazy")
	cat >> "${ondemand}/etc/lazyd.ucl" <<'UCL'
implements = [{
	interface = "org.test.cmp.storage";
	version = "1.0.0";
}];
on_demand = true;
UCL
	atf_check -s exit:1 -o ignore \
	    -e match:"provider factory.*cannot be on_demand" \
	    servicectl verify "${ondemand}" "${consumer}"

	scoped=$(create_bundle "ScopedConsumer" "org.test.scoped.consumer" \
	    "scopedd" "org.test.scoped.consumer")
	cat >> "${scoped}/etc/scopedd.ucl" <<'UCL'
components {
	store {
		interface = "org.test.cmp.storage";
		version = "1.0.0";
		lifetime = "jail";
		sharing = "shared";
	}
}
UCL
	atf_check -s exit:1 -o ignore \
	    -e match:"no provider.*sharing shared" \
	    servicectl verify "${p1}" "${scoped}"

	feature=$(create_bundle "FeatureProvider" "org.test.feature.provider" \
	    "featured" "org.test.feature.provider")
	cat >> "${feature}/etc/featured.ucl" <<'UCL'
implements = [{
	interface = "org.test.cmp.storage";
	version = "1.0.0";
	lifetimes = ["process", "job", "jail", "system"];
	sharing = ["exclusive", "shared"];
}];
UCL
	atf_check -s exit:0 \
	    -o match:"provider=org.test.feature.provider.*lifetime=jail.*sharing=shared" \
	    servicectl verify "${feature}" "${scoped}"
}
component_resolution_policy_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

atf_test_case administrator_provider_policy cleanup
administrator_provider_policy_head() {
	atf_set "descr" \
	    "Administrator policy selects providers without consumer pins"
}
administrator_provider_policy_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$

	p1=$(create_bundle "PolicyOne" "org.test.policy.one" "p1d" \
	    "org.test.policy.one")
	cat >> "${p1}/etc/p1d.ucl" <<'UCL'
implements = [{
	interface = "org.test.cmp.policy";
	version = "1.0.0";
}];
UCL
	p2=$(create_bundle "PolicyTwo" "org.test.policy.two" "p2d" \
	    "org.test.policy.two")
	cat >> "${p2}/etc/p2d.ucl" <<'UCL'
implements = [{
	interface = "org.test.cmp.policy";
	version = "1.0.0";
}];
UCL
	consumer=$(create_bundle "PolicyConsumer" "org.test.policy.consumer" \
	    "consumerd" "org.test.policy.consumer")
	cat >> "${consumer}/etc/consumerd.ucl" <<'UCL'
components {
	store {
		interface = "org.test.cmp.policy";
		version = "1.0.0";
	}
}
UCL
	cat > "${TMPDIR}/policy.ucl" <<'UCL'
schema = "org.5bsd.serviced.policy";
schema_version = "1.0.0";
provider_defaults {
	"org.test.cmp.policy" {
		version = "1.0.0";
		provider = "org.test.policy.one";
	}
}
service_overrides {
	"org.test.policy.consumer" {
		components {
			store { provider = "org.test.policy.two"; }
		}
	}
}
UCL
	atf_check -s exit:0 -o match:"Validation: PASSED" \
	    servicectl policy-check "${TMPDIR}/policy.ucl"
	atf_check -s exit:0 -o save:effective.out \
	    servicectl verify --effective --policy "${TMPDIR}/policy.ucl" \
	    "${p1}" "${p2}" "${consumer}"
	atf_check -s exit:0 -o match:"Effective configuration \\(policy " \
	    grep "Effective configuration" effective.out
	atf_check -s exit:0 \
	    -o match:"component: store.*provider=org.test.policy.two" \
	    grep "component: store" effective.out

	cat > "${TMPDIR}/bad-policy.ucl" <<'UCL'
schema = "org.5bsd.serviced.policy";
schema_version = "1.0";
provider_defaults = [];
UCL
	atf_check -s exit:1 -o ignore -e match:"schema_version" \
	    servicectl policy-check "${TMPDIR}/bad-policy.ucl"
}
administrator_provider_policy_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

atf_test_case provider_policy_schema_hardening cleanup
provider_policy_schema_hardening_head() {
	atf_set "descr" \
	    "Provider policy rejects unsafe files and malformed nested schemas"
}
provider_policy_schema_hardening_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}"

	check_bad_policy()
	{
		name=$1
		pattern=$2
		shift 2
		printf '%s\n' "$@" > "${TMPDIR}/${name}.ucl"
		atf_check -s exit:1 -o ignore -e match:"${pattern}" \
		    servicectl policy-check "${TMPDIR}/${name}.ucl"
	}

	: > "${TMPDIR}/empty.ucl"
	atf_check -s exit:1 -o ignore -e match:'non-empty regular file' \
	    servicectl policy-check "${TMPDIR}/empty.ucl"
	check_bad_policy wrong-schema 'policy schema must be' \
	    'schema = "org.example.policy";' \
	    'schema_version = "1.0.0";'
	check_bad_policy missing-version 'schema_version' \
	    'schema = "org.5bsd.serviced.policy";'
	check_bad_policy future-version 'schema_version' \
	    'schema = "org.5bsd.serviced.policy";' \
	    'schema_version = "2.0.0";'
	check_bad_policy unknown-top 'unknown key' \
	    'schema = "org.5bsd.serviced.policy";' \
	    'schema_version = "1.0.0";' \
	    'realm = "none";'
	check_bad_policy duplicate-top 'duplicate' \
	    'schema = "org.5bsd.serviced.policy";' \
	    'schema = "org.5bsd.serviced.policy";' \
	    'schema_version = "1.0.0";'
	check_bad_policy defaults-array 'provider_defaults entries' \
	    'schema = "org.5bsd.serviced.policy";' \
	    'schema_version = "1.0.0";' \
	    'provider_defaults = [];'
	check_bad_policy bad-version 'provider_defaults entries' \
	    'schema = "org.5bsd.serviced.policy";' \
	    'schema_version = "1.0.0";' \
	    'provider_defaults { "org.test.cmp" {' \
	    'version = "1.0"; provider = "org.test.provider"; } }'
	check_bad_policy bad-provider 'provider_defaults entries' \
	    'schema = "org.5bsd.serviced.policy";' \
	    'schema_version = "1.0.0";' \
	    'provider_defaults { "org.test.cmp" {' \
	    'version = "1.0.0"; provider = "../provider"; } }'
	check_bad_policy default-extra 'provider_defaults entries' \
	    'schema = "org.5bsd.serviced.policy";' \
	    'schema_version = "1.0.0";' \
	    'provider_defaults { "org.test.cmp" {' \
	    'version = "1.0.0"; provider = "org.test.provider";' \
	    'priority = 10; } }'
	check_bad_policy duplicate-default 'duplicate' \
	    'schema = "org.5bsd.serviced.policy";' \
	    'schema_version = "1.0.0";' \
	    'provider_defaults {' \
	    '"org.test.cmp" { version = "1.0.0";' \
	    'provider = "org.test.one"; }' \
	    '"org.test.cmp" { version = "1.0.0";' \
	    'provider = "org.test.two"; } }'
	check_bad_policy override-empty 'service_overrides entries' \
	    'schema = "org.5bsd.serviced.policy";' \
	    'schema_version = "1.0.0";' \
	    'service_overrides { "org.test.service" { components {} } }'
	check_bad_policy override-extra 'service_overrides entries' \
	    'schema = "org.5bsd.serviced.policy";' \
	    'schema_version = "1.0.0";' \
	    'service_overrides { "org.test.service" {' \
	    'components { store { provider = "org.test.provider"; } }' \
	    'priority = 10; } }'
	check_bad_policy choice-extra 'service_overrides entries' \
	    'schema = "org.5bsd.serviced.policy";' \
	    'schema_version = "1.0.0";' \
	    'service_overrides { "org.test.service" {' \
	    'components { store { provider = "org.test.provider";' \
	    'fallback = true; } } } }'
	check_bad_policy duplicate-override 'duplicate' \
	    'schema = "org.5bsd.serviced.policy";' \
	    'schema_version = "1.0.0";' \
	    'service_overrides { "org.test.service" { components {' \
	    'store { provider = "org.test.one"; }' \
	    'store { provider = "org.test.two"; } } } }'

	mkdir "${TMPDIR}/directory.ucl"
	atf_check -s exit:1 -o ignore -e match:'non-empty regular file' \
	    servicectl policy-check "${TMPDIR}/directory.ucl"
	printf '%s\n' \
	    'schema = "org.5bsd.serviced.policy";' \
	    'schema_version = "1.0.0";' > "${TMPDIR}/target.ucl"
	ln -s target.ucl "${TMPDIR}/symlink.ucl"
	atf_check -s exit:1 -o ignore -e ignore \
	    servicectl policy-check "${TMPDIR}/symlink.ucl"
	dd if=/dev/zero of="${TMPDIR}/oversized.ucl" bs=1048577 count=1 \
	    2>/dev/null
	atf_check -s exit:1 -o ignore -e match:'no larger than 1 MB' \
	    servicectl policy-check "${TMPDIR}/oversized.ucl"
}
provider_policy_schema_hardening_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

atf_test_case execution_jail_manifest cleanup
execution_jail_manifest_head() {
	atf_set "descr" \
	    "Named persistent execution jails and the default identity are visible"
}
execution_jail_manifest_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	dir=$(create_bundle "Jailed" "org.test.jailed" "jailedd" \
	    "org.test.jailed")
	cat >> "${dir}/etc/jailedd.ucl" <<'UCL'
jail {
	name = "org-test-jailed";
	path = "/jails/org-test-jailed";
	hostname = "jailed.example.invalid";
	ip4_addr = "192.0.2.33";
}
UCL
	atf_check -s exit:0 -o match:"user: capability" \
	    servicectl verify "${dir}"
	atf_check -s exit:0 -o match:"jail: name=org-test-jailed.*persistent=yes" \
	    servicectl verify "${dir}"
}
execution_jail_manifest_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

atf_test_case malformed_schema_matrix cleanup
malformed_schema_matrix_head() {
	atf_set "descr" "Every typed manifest surface rejects malformed values"
}
malformed_schema_matrix_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	mkdir -p "${TMPDIR}"

	assert_bad() {
		name="$1"
		expect="$2"
		snippet="$3"
		dir=$(create_bundle "$name" "org.test.$name" "${name}d" \
		    "org.test.$name.svc")
		printf '%s\n' "$snippet" >> "${dir}/etc/${name}d.ucl"
		atf_check -s exit:1 -o ignore -e match:"$expect" \
		    servicectl verify "$dir"
	}

	assert_bad duplicatekey "duplicate" \
	    'bundle_id = "org.test.replacement";'
	assert_bad args "arguments must be an array" 'arguments = "--shell words";'
	assert_bad envtype "environment must be an object" 'environment = ["A=B"];'
	assert_bad envname "invalid environment name" 'environment { "9BAD" = "x"; }'
	assert_bad compenv "invalid environment entry" \
	    'environment { SERVICED_COMPONENT_FDS = "network=99"; }'
	assert_bad kmodname "invalid kernel module name" \
	    'kmod_requires = ["../evil.ko"];'
	assert_bad captype "capabilities must be an object" \
	    'capabilities = "all";'
	assert_bad capkey "unknown key 'sockets'" 'capabilities { sockets = []; }'
	assert_bad netentry "capabilities.network entries must be objects" \
	    'capabilities { network = ["all"]; }'
	assert_bad netdomain "network domain must be a string" \
	    'capabilities { network = [{ domain = 4; }]; }'
	assert_bad netproto "invalid network protocol" \
	    'capabilities { network = [{ protocol = "bogus"; }]; }'
	assert_bad netmismatch "network protocol is incompatible" \
	    'capabilities { network = [{ domain = "bluetooth"; protocol = "tcp"; }]; }'
	assert_bad netdir "invalid network direction" \
	    'capabilities { network = [{ direction = "listen"; }]; }'
	assert_bad netaddr "invalid network address" \
	    'capabilities { network = [{ address = "not-an-address"; }]; }'
	assert_bad netprefix "network prefix must be an integer" \
	    'capabilities { network = [{ prefix = "24"; }]; }'
	assert_bad netprefixnoaddr "network prefix requires a specific address" \
	    'capabilities { network = [{ domain = "inet"; prefix = 24; }]; }'
	assert_bad netanyaddr "specific network address requires an explicit domain" \
	    'capabilities { network = [{ domain = "any"; address = "2001:db8::/32"; }]; }'
	assert_bad fileaction "invalid capabilities.files entry" \
	    'capabilities { files = [{ path = "/tmp/x"; actions = ["bogus"]; }]; }'
	assert_bad jailselector "jail entry requires jid or name" \
	    'capabilities { jails = [{ actions = ["get"]; }]; }'
	assert_bad vsockentry "capabilities.vsock entries must be objects" \
	    'capabilities { vsock = [7]; }'
	assert_bad vsockcid "invalid vsock cid" \
	    'capabilities { vsock = [{ cid = -1; port = 7; }]; }'
	assert_bad vsockdir "invalid vsock direction" \
	    'capabilities { vsock = [{ direction = "listen"; }]; }'
	assert_bad capservice "unknown capability service" \
	    'capabilities { services = ["channel"]; }'
	assert_bad dupservice "duplicate capability service" \
	    'capabilities { services = ["mount", "mount"]; }'
	assert_bad comptype "components must be an object" \
	    'components = [];'
	assert_bad compentry "invalid components entry" \
	    'components { network = "default"; }'
	assert_bad compname "invalid component name" \
	    'components { "bad,name" { interface = "org.test"; version = "1.0.0"; provider = "org.test.provider"; } }'
	assert_bad compiface "requires a valid interface" \
	    'components { network { provider = "org.test.provider"; } }'
	assert_bad compoldiface "requires a valid interface" \
	    'components { network { interface = "org.test/1"; version = "1.0.0"; provider = "org.test.provider"; } }'
	assert_bad compversion "requires a semantic version" \
	    'components { network { interface = "org.test"; provider = "org.test.provider"; } }'
	assert_bad compbadversion "requires a semantic version" \
	    'components { network { interface = "org.test"; version = "1"; provider = "org.test.provider"; } }'
	assert_bad compprovider "invalid provider" \
	    'components { network { interface = "org.test"; version = "1.0.0"; provider = 7; } }'
	assert_bad compmissing "has no provider" \
	    'components { network { interface = "org.test.unknown"; version = "1.0.0"; } }'
	assert_bad compscope "invalid scope" \
	    'components { network { interface = "org.test"; version = "1.0.0"; provider = "org.test.provider"; scope = "global"; } }'
	assert_bad comprealm "invalid scope" \
	    'components { network { interface = "org.test"; version = "1.0.0"; provider = "org.test.provider"; scope = "realm"; } }'
	assert_bad complifetime "invalid lifetime" \
	    'components { network { interface = "org.test"; version = "1.0.0"; lifetime = "realm"; } }'
	assert_bad compbothscope "both scope and lifetime" \
	    'components { network { interface = "org.test"; version = "1.0.0"; scope = "private"; lifetime = "process"; } }'
	assert_bad compsharing "invalid sharing" \
	    'components { network { interface = "org.test"; version = "1.0.0"; sharing = "sometimes"; } }'
	assert_bad comprequired "required must be boolean" \
	    'components { network { interface = "org.test"; version = "1.0.0"; provider = "org.test.provider"; required = "yes"; } }'
	assert_bad compoptions "options must be an object" \
	    'components { network { interface = "org.test"; version = "1.0.0"; provider = "org.test.provider"; options = []; } }'
	assert_bad implementsold "implements entries must be interface declarations" \
	    'implements = ["org.test/1"];'
	assert_bad implementsversion "requires a semantic version" \
	    'implements = [{ interface = "org.test"; version = "1.0"; }];'
	assert_bad implementslifetimetype "implements lifetimes" \
	    'implements = [{ interface = "org.test"; version = "1.0.0"; lifetimes = "process"; }];'
	assert_bad implementslifetime "invalid or duplicate" \
	    'implements = [{ interface = "org.test"; version = "1.0.0"; lifetimes = ["realm"]; }];'
	assert_bad implementssharing "invalid or duplicate" \
	    'implements = [{ interface = "org.test"; version = "1.0.0"; sharing = ["shared", "shared"]; }];'
	assert_bad schemaonly "declared together" \
	    'schema = "org.5bsd.serviced.service";'
	assert_bad schemaname "schema must be" \
	    'schema = "org.example.service"; schema_version = "1.0.0";'
	assert_bad schemaversion "schema_version must be" \
	    'schema = "org.5bsd.serviced.service"; schema_version = "2.0.0";'
	assert_bad jailtype "jail" \
	    'jail = [];'
	assert_bad jailname "requires a valid non-empty name" \
	    'jail { path = "/jails/test"; }'
	assert_bad jailpath "requires an absolute path" \
	    'jail { name = "test"; path = "relative"; }'
	assert_bad jailip "invalid ip4_addr" \
	    'jail { name = "test"; path = "/jails/test"; ip4_addr = "bad"; }'
	assert_bad jailkey "unknown key" \
	    'jail { name = "test"; path = "/jails/test"; vnet = true; }'
}
malformed_schema_matrix_cleanup() { rm -rf "$(atf_get_srcdir)/work.$$"; }

atf_test_case symlink_rejected cleanup
symlink_rejected_head() {
	atf_set "descr" "Executable policy bundles reject symlinks"
}
symlink_rejected_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	dir=$(create_bundle "Link" "org.test.link" "linkd" "org.test.link.svc")
	ln -s bin/linkd "${dir}/alias"
	atf_check -s exit:1 -o ignore -e match:'symlink or non-regular object' \
	    servicectl verify "$dir"
}
symlink_rejected_cleanup() { rm -rf "$(atf_get_srcdir)/work.$$"; }

atf_test_case excess_service_manifests_rejected cleanup
excess_service_manifests_rejected_head() {
	atf_set "descr" "A bundle cannot silently ignore service manifests past its limit"
}
excess_service_manifests_rejected_body() {
	TMPDIR=$(atf_get_srcdir)/work.$$
	dir="${TMPDIR}/Large.cap"
	mkdir -p "$dir/etc" "$dir/bin"
	i=0
	while [ "$i" -lt 33 ]; do
		printf '#!/bin/sh\nexit 0\n' > "$dir/bin/svc$i"
		chmod 755 "$dir/bin/svc$i"
		cat > "$dir/etc/svc$i.ucl" <<UCL
bundle_id = "org.test.large";
program = "svc$i";
provides = ["org.test.large.svc$i"];
UCL
		i=$((i + 1))
	done
	atf_check -s exit:1 -o ignore -e match:"more than 32 service manifests" \
	    servicectl verify "$dir"
}
excess_service_manifests_rejected_cleanup() {
	rm -rf "$(atf_get_srcdir)/work.$$"
}

# ---------------------------------------------------------------
atf_init_test_cases() {
	atf_add_test_case open_valid_bundle
	atf_add_test_case missing_services_dir
	atf_add_test_case missing_binary
	atf_add_test_case duplicate_provides
	atf_add_test_case self_require
	atf_add_test_case cross_bundle_cycle
	atf_add_test_case duplicate_bundle_ids
	atf_add_test_case multi_service_bundle
	atf_add_test_case capabilities_parsing
	atf_add_test_case on_demand_flag
	atf_add_test_case network_capabilities
	atf_add_test_case file_capabilities
	atf_add_test_case jail_capabilities
	atf_add_test_case all_system_gates
	atf_add_test_case invalid_port_range
	atf_add_test_case stop_timeout_rejected
	atf_add_test_case missing_program
	atf_add_test_case missing_provides
	atf_add_test_case missing_bundle_id
	atf_add_test_case relative_cap_path
	atf_add_test_case unknown_gate_name
	atf_add_test_case empty_jail_name
	atf_add_test_case arguments_environment_and_vsock
	atf_add_test_case unknown_key_rejected
	atf_add_test_case reserved_environment_rejected
	atf_add_test_case component_manifest
	atf_add_test_case component_resolution_policy
	atf_add_test_case administrator_provider_policy
	atf_add_test_case provider_policy_schema_hardening
	atf_add_test_case execution_jail_manifest
	atf_add_test_case malformed_schema_matrix
	atf_add_test_case symlink_rejected
	atf_add_test_case excess_service_manifests_rejected
}
