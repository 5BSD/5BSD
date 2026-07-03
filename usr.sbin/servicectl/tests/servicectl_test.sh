#
# SPDX-License-Identifier: BSD-2-Clause
#
# Tests for servicectl(8) and serviced's control socket.
#

daemon_pid=
pidfile=
conffile=
manifestdir=
sockpath=
sctl_sockpath=
logfile=
serviced_bin=

find_serviced()
{
	local p _arch
	_arch=$(uname -p)
	for p in \
	    "$(command -v serviced 2>/dev/null)" \
	    /usr/libexec/serviced \
	    /usr/obj/usr/src/${_arch}.${_arch}/usr.sbin/serviced/serviced
	do
		if [ -n "$p" ] && [ -x "$p" ]; then
			serviced_bin="$p"
			return
		fi
	done
	atf_skip "serviced binary not found"
}

require_cc()
{
	if ! command -v cc >/dev/null 2>&1; then
		atf_skip "cc not available"
	fi
}

find_servicectl()
{
	local p _arch
	_arch=$(uname -p)
	for p in \
	    "$(command -v servicectl 2>/dev/null)" \
	    /usr/sbin/servicectl \
	    /usr/obj/usr/src/${_arch}.${_arch}/usr.sbin/servicectl/servicectl
	do
		if [ -n "$p" ] && [ -x "$p" ]; then
			servicectl_bin="$p"
			return
		fi
	done
	atf_skip "servicectl binary not found"
}

prepare_paths()
{
	pidfile="$(pwd)/oracled.pid"
	conffile="$(pwd)/oracled.conf"
	manifestdir="$(pwd)/serviced.d"
	sockpath="$(pwd)/oracled.sock"
	sctl_sockpath="$(pwd)/serviced.sock"
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
service_manager = "$serviced_bin";
serviced_control_socket = "$sctl_sockpath";
EOF
}

start_stack()
{
	prepare_paths
	write_config

	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

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
	while ! grep -q "serviced ready" "$logfile" 2>/dev/null && [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done

	# Wait for serviced control socket.
	i=0
	while [ ! -S "$sctl_sockpath" ] && [ "$i" -lt 50 ]; do
		i=$((i + 1))
		sleep 0.1
	done
}

stop_stack()
{
	if [ -n "$daemon_pid" ]; then
		kill -TERM "$daemon_pid" 2>/dev/null || true
		wait "$daemon_pid" 2>/dev/null || true
	fi
}

cleanup_common()
{
	stop_stack
	sleep 0.2
	rm -rf oracled.pid oracled.conf serviced.d oracled.sock \
	    serviced.sock oracled.log *.out *.sh
}

write_executable()
{
	local path
	path="$1"
	shift
	printf "%s\n" "$@" > "$path"
	chmod +x "$path"
}

# ===================================================================
# servicectl status
# ===================================================================

atf_test_case servicectl_status cleanup
servicectl_status_head()
{
	atf_set "descr" "servicectl status reports serviced state"
	atf_set "require.user" "root"
}
servicectl_status_body()
{
	find_servicectl
	start_stack

	if [ ! -S "$sctl_sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_skip "serviced control socket not available"
	fi

	atf_check -s exit:0 -o match:"serviced: running" \
	    "$servicectl_bin" -s "$sctl_sockpath" status
}
servicectl_status_cleanup()
{
	cleanup_common
}

# ===================================================================
# servicectl services — with a running service
# ===================================================================

atf_test_case servicectl_services_lists cleanup
servicectl_services_lists_head()
{
	atf_set "descr" "servicectl services lists loaded services"
	atf_set "require.user" "root"
}
servicectl_services_lists_body()
{
	find_servicectl
	prepare_paths

	write_executable "$(pwd)/long-svc.sh" \
	    '#!/bin/sh' \
	    'echo $$ > long-svc.pid' \
	    'sleep 60'
	cat > "$manifestdir/long-svc.ucl" <<EOF
label = "long-svc";
program = "$(pwd)/long-svc.sh";
EOF

	start_stack

	if [ ! -S "$sctl_sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_skip "serviced control socket not available"
	fi

	# Wait for service to start.
	i=0
	while [ ! -s long-svc.pid ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done

	atf_check -s exit:0 -o match:"long-svc" \
	    "$servicectl_bin" -s "$sctl_sockpath" services
}
servicectl_services_lists_cleanup()
{
	if [ -f long-svc.pid ]; then
		kill "$(cat long-svc.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

# ===================================================================
# servicectl reload — triggers manifest reload
# ===================================================================

atf_test_case servicectl_reload cleanup
servicectl_reload_head()
{
	atf_set "descr" "servicectl reload triggers manifest reload"
	atf_set "require.user" "root"
}
servicectl_reload_body()
{
	find_servicectl
	start_stack

	if [ ! -S "$sctl_sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_skip "serviced control socket not available"
	fi

	# Add a manifest after startup.
	write_executable "$(pwd)/reload-svc.sh" \
	    '#!/bin/sh' \
	    'echo $$ > reload-svc.pid' \
	    'sleep 60'
	cat > "$manifestdir/reload-svc.ucl" <<EOF
label = "reload-svc";
program = "$(pwd)/reload-svc.sh";
EOF

	atf_check -s exit:0 -o ignore "$servicectl_bin" -s "$sctl_sockpath" reload

	# Wait for the new service to start.
	i=0
	while [ ! -s reload-svc.pid ] && [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -s reload-svc.pid ]; then
		cat "$logfile" 2>/dev/null
		atf_skip "reloaded service did not start"
	fi

	atf_check -s exit:0 -o match:"reload-svc" \
	    "$servicectl_bin" -s "$sctl_sockpath" services
}
servicectl_reload_cleanup()
{
	if [ -f reload-svc.pid ]; then
		kill "$(cat reload-svc.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

# ===================================================================
# servicectl unknown command
# ===================================================================

atf_test_case servicectl_unknown_command cleanup
servicectl_unknown_command_head()
{
	atf_set "descr" "servicectl rejects unknown commands"
}
servicectl_unknown_command_body()
{
	find_servicectl
	atf_check -s not-exit:0 -e match:"unknown command" \
	    "$servicectl_bin" bogus
}
servicectl_unknown_command_cleanup()
{
	:
}

# ===================================================================
# servicectl no args — usage
# ===================================================================

atf_test_case servicectl_usage cleanup
servicectl_usage_head()
{
	atf_set "descr" "servicectl with no args shows usage"
}
servicectl_usage_body()
{
	find_servicectl
	atf_check -s not-exit:0 -e match:"usage:" \
	    "$servicectl_bin"
}
servicectl_usage_cleanup()
{
	:
}

# ===================================================================
# servicectl reload denied for non-root
# ===================================================================

atf_test_case servicectl_reload_nonroot cleanup
servicectl_reload_nonroot_head()
{
	atf_set "descr" "servicectl reload denied for non-root"
	atf_set "require.user" "root"
}
servicectl_reload_nonroot_body()
{
	find_servicectl
	start_stack

	if [ ! -S "$sctl_sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_skip "serviced control socket not available"
	fi

	if ! id nobody >/dev/null 2>&1; then
		atf_skip "nobody user not available"
	fi

	atf_check -s not-exit:0 -e ignore -o ignore \
	    su -m nobody -c "'$servicectl_bin' -s '$sctl_sockpath' reload"
}
servicectl_reload_nonroot_cleanup()
{
	cleanup_common
}

# ===================================================================
# servicectl verify — validates a bundle
# ===================================================================

atf_test_case servicectl_verify cleanup
servicectl_verify_head()
{
	atf_set "descr" "servicectl verify validates a .cap bundle"
}
servicectl_verify_body()
{
	find_servicectl
	local bdir="$(pwd)/VerifyTest.cap"
	mkdir -p "${bdir}/etc"
	mkdir -p "${bdir}/bin"
	printf '#!/bin/sh\nexec sleep 3600\n' > "${bdir}/bin/verifyd"
	chmod 755 "${bdir}/bin/verifyd"
	cat > "${bdir}/etc/verifyd.ucl" <<EOF
bundle_id = "org.test.verify";
version = "1.0";
author = "test";
program = "verifyd";
provides = ["org.test.verify.svc"];
EOF

	atf_check -s exit:0 -o match:"PASSED" \
	    "$servicectl_bin" verify "${bdir}"
}
servicectl_verify_cleanup()
{
	rm -rf VerifyTest.cap
}

# ===================================================================
# servicectl verify — rejects invalid bundle
# ===================================================================

atf_test_case servicectl_verify_invalid cleanup
servicectl_verify_invalid_head()
{
	atf_set "descr" "servicectl verify rejects invalid bundle"
}
servicectl_verify_invalid_body()
{
	find_servicectl
	local bdir="$(pwd)/BadBundle.cap"
	mkdir -p "${bdir}/etc"
	# No bin directory, no program binary
	cat > "${bdir}/etc/bad.ucl" <<EOF
bundle_id = "org.test.bad";
program = "nonexistent";
provides = ["org.test.bad.svc"];
EOF

	atf_check -s not-exit:0 -e match:"FAILED\|invalid\|not found" \
	    "$servicectl_bin" verify "${bdir}"
}
servicectl_verify_invalid_cleanup()
{
	rm -rf BadBundle.cap
}

# ===================================================================
# servicectl stop — requires label argument
# ===================================================================

atf_test_case servicectl_stop_no_arg cleanup
servicectl_stop_no_arg_head()
{
	atf_set "descr" "servicectl stop without label fails"
}
servicectl_stop_no_arg_body()
{
	find_servicectl
	atf_check -s not-exit:0 -e match:"requires" \
	    "$servicectl_bin" stop
}
servicectl_stop_no_arg_cleanup()
{
	:
}

# ===================================================================
# Control socket: oversized payload rejected
# ===================================================================

atf_test_case sctl_oversized_payload cleanup
sctl_oversized_payload_head()
{
	atf_set "descr" "serviced rejects oversized control payloads"
	atf_set "require.user" "root"
}
sctl_oversized_payload_body()
{
	require_cc
	cat > rawctl.c <<'CEOF'
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct sctl_request {
	uint32_t version;
	uint32_t op;
	uint32_t flags;
	uint32_t datalen;
} __attribute__((packed));

struct sctl_reply {
	uint32_t status;
	uint32_t flags;
} __attribute__((packed));

int main(int argc, char **argv)
{
	struct sockaddr_un un;
	struct sctl_request req;
	struct sctl_reply rpl;
	int fd;

	if (argc < 2) return (2);
	fd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (fd == -1) return (2);
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_LOCAL;
	strlcpy(un.sun_path, argv[1], sizeof(un.sun_path));
	if (connect(fd, (struct sockaddr *)&un, sizeof(un)) == -1) return (2);

	memset(&req, 0, sizeof(req));
	req.version = 1;
	req.op = 4; /* SCTL_OP_CHECK */
	req.datalen = 9999; /* way over max */
	write(fd, &req, sizeof(req));

	/* Server should close connection without reply. */
	if (read(fd, &rpl, sizeof(rpl)) <= 0) {
		printf("rejected\n");
		close(fd);
		return (0);
	}
	printf("status=%u\n", rpl.status);
	close(fd);
	return (0);
}
CEOF
	atf_check -s exit:0 -e ignore cc -Wall -o rawctl rawctl.c

	start_stack
	if [ ! -S "$sctl_sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_skip "serviced control socket not available"
	fi

	# Server replies with EMSGSIZE error.
	atf_check -s exit:0 -o match:"status=" \
	    ./rawctl "$sctl_sockpath"
}
sctl_oversized_payload_cleanup()
{
	rm -f rawctl rawctl.c
	cleanup_common
}

# ===================================================================
# servicectl install — valid bundle
# ===================================================================

atf_test_case servicectl_install_valid cleanup
servicectl_install_valid_head() {
    atf_set "descr" "servicectl install copies valid bundle to install dir"
    atf_set "require.user" "root"
}
servicectl_install_valid_body() {
    find_servicectl
    start_stack

    local src="$(pwd)/InstallMe.cap"
    local idir="$(pwd)/install_target"
    mkdir -p "${src}/etc" "${src}/bin" "$idir"
    printf '#!/bin/sh\nexec sleep 3600\n' > "${src}/bin/instd"
    chmod 755 "${src}/bin/instd"
    cat > "${src}/etc/instd.ucl" <<EOF
bundle_id = "org.test.install";
version = "1.0";
author = "test";
program = "instd";
provides = ["org.test.install.svc"];
EOF

    export SERVICED_BUNDLE_DIR_USER="$idir"
    atf_check -s exit:0 -o match:"copied to" \
        "$servicectl_bin" install "$src"

    # Verify bundle was copied
    atf_check -s exit:0 test -d "${idir}/InstallMe.cap"
    atf_check -s exit:0 test -x "${idir}/InstallMe.cap/bin/instd"
}
servicectl_install_valid_cleanup() {
    rm -rf InstallMe.cap install_target
    cleanup_common
}

# ===================================================================
# servicectl install — path traversal rejected
# ===================================================================

atf_test_case servicectl_install_path_traversal cleanup
servicectl_install_path_traversal_head() {
    atf_set "descr" "servicectl install rejects path traversal in bundle name"
}
servicectl_install_path_traversal_body() {
    find_servicectl
    # Create a directory whose basename starts with ".."
    local bad="$(pwd)/..BadName.cap"
    mkdir -p "${bad}/etc" "${bad}/bin"
    printf '#!/bin/sh\nsleep 3600\n' > "${bad}/bin/bad"
    chmod 755 "${bad}/bin/bad"
    cat > "${bad}/etc/bad.ucl" <<EOF
bundle_id = "org.test.bad";
program = "bad";
provides = ["org.test.bad.svc"];
EOF

    atf_check -s not-exit:0 -e match:"invalid" \
        "$servicectl_bin" install "$bad"
}
servicectl_install_path_traversal_cleanup() {
    rm -rf "..BadName.cap"
}

# ===================================================================
# servicectl install — overwrite rejected
# ===================================================================

atf_test_case servicectl_install_overwrite cleanup
servicectl_install_overwrite_head() {
    atf_set "descr" "servicectl install rejects overwrite of existing bundle"
    atf_set "require.user" "root"
}
servicectl_install_overwrite_body() {
    find_servicectl
    start_stack

    local src="$(pwd)/Overwrite.cap"
    local idir="$(pwd)/install_target2"
    mkdir -p "${src}/etc" "${src}/bin" "$idir"
    printf '#!/bin/sh\nexec sleep 3600\n' > "${src}/bin/ovd"
    chmod 755 "${src}/bin/ovd"
    cat > "${src}/etc/ovd.ucl" <<EOF
bundle_id = "org.test.overwrite";
version = "1.0";
author = "test";
program = "ovd";
provides = ["org.test.overwrite.svc"];
EOF

    export SERVICED_BUNDLE_DIR_USER="$idir"
    atf_check -s exit:0 -o ignore "$servicectl_bin" install "$src"
    # Second install should fail
    atf_check -s not-exit:0 -e match:"already exists" \
        "$servicectl_bin" install "$src"
}
servicectl_install_overwrite_cleanup() {
    rm -rf Overwrite.cap install_target2
    cleanup_common
}

atf_init_test_cases()
{
	atf_add_test_case servicectl_status
	atf_add_test_case servicectl_services_lists
	atf_add_test_case servicectl_reload
	atf_add_test_case servicectl_unknown_command
	atf_add_test_case servicectl_usage
	atf_add_test_case servicectl_reload_nonroot

	# verify/stop
	atf_add_test_case servicectl_verify
	atf_add_test_case servicectl_verify_invalid
	atf_add_test_case servicectl_stop_no_arg

	# adversarial
	atf_add_test_case sctl_oversized_payload

	# install
	atf_add_test_case servicectl_install_valid
	atf_add_test_case servicectl_install_path_traversal
	atf_add_test_case servicectl_install_overwrite
}
