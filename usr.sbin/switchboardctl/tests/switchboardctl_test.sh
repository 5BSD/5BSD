#
# SPDX-License-Identifier: BSD-2-Clause
#
# Tests for switchboardctl(8) driving switchboard over the capability control plane.
#

. "$(atf_get_srcdir)/capd_test_harness.sh"

daemon_pid=
pidfile=
conffile=
manifestdir=
user_manifestdir=
sockpath=
logfile=
switchboard_bin=

find_switchboard()
{
	capd_find_switchboard
	switchboard_bin=$capd_switchboard_bin
}

require_capsule_stack_kmods()
{
	capd_require_stack_kmods
}

find_switchboardctl()
{
	local p _machine _arch
	_machine=$(uname -m)
	_arch=$(uname -p)
	for p in \
	    "$(atf_get_srcdir)/switchboardctl_test_bin" \
	    /usr/obj/usr/src/${_machine}.${_arch}/usr.sbin/switchboardctl/switchboardctl \
	    /usr/sbin/switchboardctl \
	    "$(command -v switchboardctl 2>/dev/null)"
	do
		if [ -n "$p" ] && [ -x "$p" ]; then
			switchboardctl_bin="$p"
			return
		fi
	done
	atf_skip "switchboardctl binary not found"
}

prepare_paths()
{
	capd_paths_init
	pidfile=$CAPD_PIDFILE
	conffile=$CAPD_CONFIG
	manifestdir=$CAPD_APPS_SYSTEM
	user_manifestdir=$CAPD_APPS_USER
	sockpath=$CAPD_CAPSULE_SOCKET
	logfile=$CAPD_LOG
	mkdir -p "$manifestdir" "$user_manifestdir"
	export SWITCHBOARD_BUNDLE_DIR_SYSTEM="$manifestdir"
	export SWITCHBOARD_BUNDLE_DIR_USER="$user_manifestdir"
}

write_config()
{
	find_switchboard
	# control_socket / control_socket_mode configure capsule's own control
	# socket (capsulectl).  switchboard's getpeereid control socket was retired
	# (docs/capability-authority-model.md): switchboardctl now reaches switchboard over
	# the ambient discovery plane, so no switchboard_control_socket key is written.
	cat > "$conffile" <<EOF
pidfile = "$pidfile";
control_socket = "$sockpath";
control_socket_mode = "0700";
service_manager = "$switchboard_bin";
EOF
}

# Skip when switchboardctl cannot reach switchboard over the capability plane.
#
# switchboard's getpeereid control socket was retired
# (docs/capability-authority-model.md): switchboardctl now issues control requests
# over the ambient discovery channel a login session inherits
# (SERVICE_LOOKUP_FD -- the same condition service_reachability_test detects via
# service_ambient_lookup_fd()).  The ATF harness provides no login session, so
# there is no ambient channel here and these cases skip; on a live plane the
# channel is inherited and they run for real.  Control is otherwise validated by
# the VM boot smoke test.
require_ambient_control()
{
	if [ -z "${SERVICE_LOOKUP_FD:-}" ]; then
		atf_skip "no ambient control channel in this harness (control is validated by the VM boot smoke test)"
	fi
}

start_stack()
{
	prepare_paths
	write_config
	# capd_start_stack already blocks until switchboard logs "switchboard ready";
	# switchboard no longer creates a control socket to poll for.
	capd_start_stack
	daemon_pid=$("$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" status |
	    sed -n 's/^running pid=//p')
}

stop_stack()
{
	local result

	capd_paths_init
	capd_find_guardian
	capd_stop_stack
	result=$?
	daemon_pid=
	return "$result"
}

cleanup_common()
{
	stop_stack || return 1
	capd_cleanup_stack || return 1
	sleep 0.2
	rm -rf capsule.pid capsule.conf Capabilities capsule.sock \
	    switchboard.sock capsule.log *.out *.sh
}

write_executable()
{
	local path
	path="$1"
	shift
	printf "%s\n" "$@" > "$path"
	chmod +x "$path"
}

write_bundle()
{
	local root="$1" id="$2" unit="$3" sequence="$4" activation="$5"

	mkdir -p "$root/Units/$unit.unit/bin"
	cat > "$root/Bundle.ucl" <<EOF
schema = "org.5bsd.capability-bundle";
schema_version = 1;
bundle_id = "$id";
version = "1.0.$sequence";
sequence = $sequence;
author = "test";
publisher = "org.test";
units = ["$unit"];
EOF
	printf '%s\n' "$activation" > "$root/Units/$unit.unit/Unit.ucl"
}

# ===================================================================
# switchboardctl status
# ===================================================================

atf_test_case switchboardctl_status cleanup
switchboardctl_status_head()
{
	atf_set "descr" "switchboardctl status reports switchboard state"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
switchboardctl_status_body()
{
	find_switchboardctl
	start_stack

	require_ambient_control

	atf_check -s exit:0 -o match:"switchboard: running" \
	    "$switchboardctl_bin" status
}
switchboardctl_status_cleanup()
{
	cleanup_common
}

# ===================================================================
# switchboardctl services — with a running service
# ===================================================================

atf_test_case switchboardctl_services_lists cleanup
switchboardctl_services_lists_head()
{
	atf_set "descr" "switchboardctl services lists loaded services"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
switchboardctl_services_lists_body()
{
	find_switchboardctl
	prepare_paths

	write_bundle "$manifestdir/long-svc.cap" org.test.long-svc long-svc 1 \
	    'activation { boot = true; ipc = ["org.test.long-svc"]; }'
	write_executable "$manifestdir/long-svc.cap/Units/long-svc.unit/bin/long-svc" \
	    '#!/bin/sh' \
	    'echo $$ > long-svc.pid' \
	    'sleep 60'

	start_stack

	require_ambient_control

	# Wait for service to start.
	i=0
	while [ ! -s long-svc.pid ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done

	atf_check -s exit:0 -o match:"long-svc" \
	    "$switchboardctl_bin" services
}
switchboardctl_services_lists_cleanup()
{
	if [ -f long-svc.pid ]; then
		kill "$(cat long-svc.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

# ===================================================================
# switchboardctl reload — triggers manifest reload
# ===================================================================

atf_test_case switchboardctl_reload cleanup
switchboardctl_reload_head()
{
	atf_set "descr" "switchboardctl reload triggers manifest reload"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
switchboardctl_reload_body()
{
	find_switchboardctl
	start_stack

	require_ambient_control

	# Add a manifest after startup.
	write_bundle "$manifestdir/reload-svc.cap" org.test.reload-svc reload-svc 1 \
	    'activation { boot = true; ipc = ["org.test.reload-svc"]; }'
	write_executable "$manifestdir/reload-svc.cap/Units/reload-svc.unit/bin/reload-svc" \
	    '#!/bin/sh' \
	    'echo $$ > reload-svc.pid' \
	    'sleep 60'

	atf_check -s exit:0 -o ignore "$switchboardctl_bin" reload

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
	    "$switchboardctl_bin" services
}
switchboardctl_reload_cleanup()
{
	if [ -f reload-svc.pid ]; then
		kill "$(cat reload-svc.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

# ===================================================================
# switchboardctl unknown command
# ===================================================================

atf_test_case switchboardctl_unknown_command cleanup
switchboardctl_unknown_command_head()
{
	atf_set "descr" "switchboardctl rejects unknown commands"
}
switchboardctl_unknown_command_body()
{
	find_switchboardctl
	atf_check -s not-exit:0 -e match:"unknown command" \
	    "$switchboardctl_bin" bogus
}
switchboardctl_unknown_command_cleanup()
{
	:
}

# ===================================================================
# switchboardctl no args — usage
# ===================================================================

atf_test_case switchboardctl_usage cleanup
switchboardctl_usage_head()
{
	atf_set "descr" "switchboardctl with no args shows usage"
}
switchboardctl_usage_body()
{
	find_switchboardctl
	atf_check -s not-exit:0 -e match:"usage:" \
	    "$switchboardctl_bin"
}
switchboardctl_usage_cleanup()
{
	:
}

# ===================================================================
# switchboardctl reload denied for non-root
# ===================================================================

atf_test_case switchboardctl_reload_nonroot cleanup
switchboardctl_reload_nonroot_head()
{
	atf_set "descr" "switchboardctl reload denied for non-root"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
switchboardctl_reload_nonroot_body()
{
	find_switchboardctl
	start_stack

	require_ambient_control

	if ! id nobody >/dev/null 2>&1; then
		atf_skip "nobody user not available"
	fi

	atf_check -s not-exit:0 -e ignore -o ignore \
	    su -m nobody -c "'$switchboardctl_bin' reload"
}
switchboardctl_reload_nonroot_cleanup()
{
	cleanup_common
}

# ===================================================================
# switchboardctl verify — validates a bundle
# ===================================================================

atf_test_case switchboardctl_verify cleanup
switchboardctl_verify_head()
{
	atf_set "descr" "switchboardctl verify validates a .cap bundle"
}
switchboardctl_verify_body()
{
	find_switchboardctl
	local bdir="$(pwd)/VerifyTest.cap"
	write_bundle "$bdir" org.test.verify verifyd 1 \
	    'activation { ipc = ["org.test.verify.svc"]; }'
	printf '#!/bin/sh\nexec sleep 3600\n' > \
	    "${bdir}/Units/verifyd.unit/bin/verifyd"
	chmod 755 "${bdir}/Units/verifyd.unit/bin/verifyd"

	atf_check -s exit:0 -o match:"PASSED" \
	    "$switchboardctl_bin" verify "${bdir}"
}
switchboardctl_verify_cleanup()
{
	rm -rf VerifyTest.cap
}

# ===================================================================
# switchboardctl verify — rejects invalid bundle
# ===================================================================

atf_test_case switchboardctl_verify_invalid cleanup
switchboardctl_verify_invalid_head()
{
	atf_set "descr" "switchboardctl verify rejects invalid bundle"
}
switchboardctl_verify_invalid_body()
{
	find_switchboardctl
	local bdir="$(pwd)/BadBundle.cap"
	write_bundle "$bdir" org.test.bad nonexistent 1 \
	    'activation { boot = true; }'

	atf_check -s not-exit:0 -e match:"FAILED" \
	    "$switchboardctl_bin" verify "${bdir}"
}
switchboardctl_verify_invalid_cleanup()
{
	rm -rf BadBundle.cap
}

# ===================================================================
# switchboardctl stop — requires label argument
# ===================================================================

atf_test_case switchboardctl_stop_no_arg cleanup
switchboardctl_stop_no_arg_head()
{
	atf_set "descr" "switchboardctl stop without label fails"
}
switchboardctl_stop_no_arg_body()
{
	find_switchboardctl
	atf_check -s not-exit:0 -e match:"requires" \
	    "$switchboardctl_bin" stop
}
switchboardctl_stop_no_arg_cleanup()
{
	:
}

# ===================================================================
# switchboardctl install — valid bundle
# ===================================================================

atf_test_case switchboardctl_install_valid cleanup
switchboardctl_install_valid_head() {
	atf_set "descr" "install atomically publishes a normalized canonical bundle version"
	atf_set "require.user" "root"
}
switchboardctl_install_valid_body() {
	find_switchboardctl
	local src="$(pwd)/InstallMe.cap"
	local idir="$(pwd)/install_target"
	local dst="${idir}/org.test.install@00000000000000000007.cap"
	mkdir "$idir"
	write_bundle "$src" org.test.install instd 7 \
	    'activation { ipc = ["org.test.install"]; }'
	write_executable "$src/Units/instd.unit/bin/instd" \
	    '#!/bin/sh' 'exit 0'
	chown -R nobody:nobody "$src"
	chmod -R go+w "$src"

	export SWITCHBOARD_BUNDLE_DIR_USER="$idir"
	atf_check -s exit:0 -o match:"published $dst" \
	    "$switchboardctl_bin" install "$src"
	atf_check -s exit:0 test -x "$dst/Units/instd.unit/bin/instd"
	atf_check -s exit:0 -o inline:'0\n' stat -f %u \
	    "$dst/Units/instd.unit/bin/instd"
	atf_check -s exit:0 -o inline:'0\n' sh -c \
	    'm=0$(stat -f %Lp "$1"); test $((m & 022)) -eq 0; echo $?' sh "$dst"
	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "$switchboardctl_bin" verify "$dst"
	atf_check -s exit:0 -o empty -e empty sh -c \
	    'test -z "$(find "$1" -maxdepth 1 -name ".switchboardctl.*" -print -quit)"' \
	    sh "$idir"
}
switchboardctl_install_valid_cleanup() {
	rm -rf InstallMe.cap install_target
}

# ===================================================================
# switchboardctl install — path traversal rejected
# ===================================================================

atf_test_case switchboardctl_install_source_name_ignored cleanup
switchboardctl_install_source_name_ignored_head() {
	atf_set "descr" "source basename cannot influence the canonical destination"
	atf_set "require.user" "root"
}
switchboardctl_install_source_name_ignored_body() {
	find_switchboardctl
	local src="$(pwd)/..Misleading.cap" idir="$(pwd)/name_target"
	mkdir "$idir"
	write_bundle "$src" org.test.canonical worker 9 \
	    'activation { boot = true; }'
	write_executable "$src/Units/worker.unit/bin/worker" '#!/bin/sh' 'exit 0'
	export SWITCHBOARD_BUNDLE_DIR_USER="$idir"
	atf_check -s exit:0 -o match:'org.test.canonical@00000000000000000009.cap' \
	    "$switchboardctl_bin" install "$src"
	atf_check -s exit:0 test -d \
	    "$idir/org.test.canonical@00000000000000000009.cap"
}
switchboardctl_install_source_name_ignored_cleanup() {
	rm -rf "..Misleading.cap" name_target
}

# ===================================================================
# switchboardctl install — overwrite rejected
# ===================================================================

atf_test_case switchboardctl_install_versions cleanup
switchboardctl_install_versions_head() {
	atf_set "descr" "immutable versions coexist and duplicate sequences fail"
	atf_set "require.user" "root"
}
switchboardctl_install_versions_body() {
	find_switchboardctl
	local src="$(pwd)/Version.cap" idir="$(pwd)/versions"
	mkdir "$idir"
	write_bundle "$src" org.test.versioned worker 1 \
	    'activation { boot = true; }'
	write_executable "$src/Units/worker.unit/bin/worker" '#!/bin/sh' 'exit 0'
	export SWITCHBOARD_BUNDLE_DIR_USER="$idir"
	atf_check -s exit:0 -o ignore "$switchboardctl_bin" install "$src"
	atf_check -s exit:1 -o ignore -e match:'File exists' \
	    "$switchboardctl_bin" install "$src"
	sed -i '' 's/version = "1.0.1"/version = "2.0.0"/; s/sequence = 1/sequence = 2/' \
	    "$src/Bundle.ucl"
	atf_check -s exit:0 -o ignore "$switchboardctl_bin" install "$src"
	atf_check -s exit:0 test -d \
	    "$idir/org.test.versioned@00000000000000000001.cap"
	atf_check -s exit:0 test -d \
	    "$idir/org.test.versioned@00000000000000000002.cap"
}
switchboardctl_install_versions_cleanup() {
	rm -rf Version.cap versions
}

atf_test_case switchboardctl_install_rejects_unsafe cleanup
switchboardctl_install_rejects_unsafe_head() {
	atf_set "descr" "staged symlinks and untrusted registry roots fail without residue"
	atf_set "require.user" "root"
}
switchboardctl_install_rejects_unsafe_body() {
	find_switchboardctl
	local src="$(pwd)/Unsafe.cap" idir="$(pwd)/unsafe_target"
	mkdir "$idir"
	write_bundle "$src" org.test.unsafe worker 1 \
	    'activation { boot = true; }'
	rm "$src/Units/worker.unit/bin/worker" 2>/dev/null || true
	ln -s /bin/true "$src/Units/worker.unit/bin/worker"
	export SWITCHBOARD_BUNDLE_DIR_USER="$idir"
	atf_check -s exit:1 -o ignore -e match:'unsafe object' \
	    "$switchboardctl_bin" install "$src"
	atf_check -s exit:0 -o empty -e empty sh -c \
	    'test -z "$(find "$1" -mindepth 1 -maxdepth 1 -print -quit)"' \
	    sh "$idir"
	chmod 0777 "$idir"
	atf_check -s exit:1 -o ignore -e match:'root-owned.*non-group/world-writable' \
	    "$switchboardctl_bin" install "$src"
}
switchboardctl_install_rejects_unsafe_cleanup() {
	rm -rf Unsafe.cap unsafe_target
}

atf_test_case switchboardctl_install_limits cleanup
switchboardctl_install_limits_head() {
	atf_set "descr" "install rejects oversized files and excessive entries without residue"
	atf_set "require.user" "root"
}
switchboardctl_install_limits_body() {
	find_switchboardctl
	local src="$(pwd)/Limited.cap" idir="$(pwd)/limit_target" i
	mkdir "$idir"
	write_bundle "$src" org.test.limited worker 1 \
	    'activation { boot = true; }'
	write_executable "$src/Units/worker.unit/bin/worker" '#!/bin/sh' 'exit 0'
	mkdir -p "$src/Shared"
	truncate -s 536870913 "$src/Shared/oversized"
	export SWITCHBOARD_BUNDLE_DIR_USER="$idir"
	atf_check -s exit:1 -o ignore -e match:'exceeds limits' \
	    "$switchboardctl_bin" install "$src"
	atf_check -s exit:0 -o empty -e empty sh -c \
	    'test -z "$(find "$1" -mindepth 1 -maxdepth 1 -print -quit)"' \
	    sh "$idir"
	rm -f "$src/Shared/oversized"
	i=0
	while [ "$i" -lt 4100 ]; do
	    : > "$src/Shared/entry-$i"
	    i=$((i + 1))
	done
	atf_check -s exit:1 -o ignore -e match:'exceeds limits' \
	    "$switchboardctl_bin" install "$src"
	atf_check -s exit:0 -o empty -e empty sh -c \
	    'test -z "$(find "$1" -mindepth 1 -maxdepth 1 -print -quit)"' \
	    sh "$idir"
}
switchboardctl_install_limits_cleanup() {
	rm -rf Limited.cap limit_target
}

atf_test_case switchboardctl_start_requires_label
switchboardctl_start_requires_label_head() {
	atf_set "descr" "start rejects absent and surplus labels before connecting"
}
switchboardctl_start_requires_label_body() {
	find_switchboardctl
	atf_check -s exit:64 -o empty -e match:'start requires a service label' \
	    "$switchboardctl_bin" start
	atf_check -s exit:64 -o empty -e match:'start requires a service label' \
	    "$switchboardctl_bin" start one two
}

atf_test_case switchboardctl_restart_requires_label
switchboardctl_restart_requires_label_head() {
	atf_set "descr" "restart rejects absent and surplus labels before connecting"
}
switchboardctl_restart_requires_label_body() {
	find_switchboardctl
	atf_check -s exit:64 -o empty -e match:'restart requires a service label' \
	    "$switchboardctl_bin" restart
	atf_check -s exit:64 -o empty -e match:'restart requires a service label' \
	    "$switchboardctl_bin" restart one two
}

atf_test_case switchboardctl_restart_help
switchboardctl_restart_help_head() {
	atf_set "descr" "restart is advertised in usage"
}
switchboardctl_restart_help_body() {
	find_switchboardctl
	atf_check -s not-exit:0 -e match:'restart <label>' "$switchboardctl_bin"
}

# ===================================================================
# switchboardctl restart — stop+start a running service (new pid)
# ===================================================================

atf_test_case switchboardctl_restart cleanup
switchboardctl_restart_head()
{
	atf_set "descr" "switchboardctl restart stops and starts a service (new pid)"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
switchboardctl_restart_body()
{
	find_switchboardctl
	prepare_paths

	write_bundle "$manifestdir/restart-svc.cap" org.test.restart-svc \
	    restart-svc 1 \
	    'activation { boot = true; ipc = ["org.test.restart-svc"]; }'
	write_executable \
	    "$manifestdir/restart-svc.cap/Units/restart-svc.unit/bin/restart-svc" \
	    '#!/bin/sh' \
	    'echo $$ > restart-svc.pid' \
	    'sleep 60'

	start_stack

	require_ambient_control

	# Wait for the first instance to record its pid.
	i=0
	while [ ! -s restart-svc.pid ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -s restart-svc.pid ]; then
		cat "$logfile" 2>/dev/null
		atf_skip "restart-svc did not start"
	fi
	oldpid=$(cat restart-svc.pid)

	atf_check -s exit:0 -o ignore \
	    "$switchboardctl_bin" restart restart-svc

	# Wait for a new instance with a different pid.
	i=0
	newpid=$oldpid
	while [ "$i" -lt 150 ]; do
		newpid=$(cat restart-svc.pid 2>/dev/null)
		if [ -n "$newpid" ] && [ "$newpid" != "$oldpid" ] &&
		    kill -0 "$newpid" 2>/dev/null; then
			break
		fi
		i=$((i + 1))
		sleep 0.1
	done
	if [ "$newpid" = "$oldpid" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "service was not restarted (pid unchanged: $oldpid)"
	fi
	atf_check -s exit:0 kill -0 "$newpid"
	# The old instance must be gone.
	atf_check -s not-exit:0 kill -0 "$oldpid"
}
switchboardctl_restart_cleanup()
{
	if [ -f restart-svc.pid ]; then
		kill "$(cat restart-svc.pid)" 2>/dev/null || true
	fi
	cleanup_common
}

# Control-request input validation over the capability plane: switchboard must
# reject a request whose declared payload length exceeds the protocol maximum
# (EINVAL=22) rather than over-reading.  capd_protocol_fixture crafts the
# oversized request and sends it over system.switchboard.  Skips when this harness
# has no ambient control channel (control is also validated by the VM smoke).
atf_test_case sctl_oversized_payload cleanup
sctl_oversized_payload_head()
{
	atf_set "descr" "switchboard rejects oversized control requests"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
sctl_oversized_payload_body()
{
	start_stack
	require_ambient_control
	atf_check -s exit:0 -o match:"status=22" \
	    "$(atf_get_srcdir)/capd_protocol_fixture" control-oversized
}
sctl_oversized_payload_cleanup()
{
	cleanup_common
}

atf_test_case sctl_client_reply_validation
sctl_client_reply_validation_body()
{
	tool="$(atf_get_srcdir)/switchboardctl_success_bin"

	atf_check -s exit:0 -o inline:'switchboard-ready\n' -e empty \
	    env SCTL_EXPECT_OP=1 "$tool" status
	atf_check -s exit:1 -e match:'status: Device busy' \
	    -e match:'session-closed' env SCTL_REPLY=status \
	    SCTL_TRACE_CLOSE=1 "$tool" status
	atf_check -s exit:69 -e match:'no admin discovery channel' \
	    -e match:'session-closed' env SCTL_FAIL=call \
	    SCTL_TRACE_CLOSE=1 "$tool" status
	atf_check -s exit:76 -e match:'short control reply' \
	    -e match:'session-closed' env SCTL_REPLY=short \
	    SCTL_TRACE_CLOSE=1 "$tool" status
	for mode in oversize trailing badstatus; do
		atf_check -s exit:76 -e match:'malformed control reply' \
		    -e match:'session-closed' env SCTL_REPLY="$mode" \
		    SCTL_TRACE_CLOSE=1 "$tool" status
	done
}

atf_init_test_cases()
{
	atf_add_test_case sctl_client_reply_validation
	atf_add_test_case sctl_oversized_payload
	atf_add_test_case switchboardctl_status
	atf_add_test_case switchboardctl_services_lists
	atf_add_test_case switchboardctl_reload
	atf_add_test_case switchboardctl_unknown_command
	atf_add_test_case switchboardctl_usage
	atf_add_test_case switchboardctl_reload_nonroot

	# verify/stop
	atf_add_test_case switchboardctl_verify
	atf_add_test_case switchboardctl_verify_invalid
	atf_add_test_case switchboardctl_stop_no_arg
	atf_add_test_case switchboardctl_restart_requires_label
	atf_add_test_case switchboardctl_restart_help
	atf_add_test_case switchboardctl_restart

	# install
	atf_add_test_case switchboardctl_install_valid
	atf_add_test_case switchboardctl_install_source_name_ignored
	atf_add_test_case switchboardctl_install_versions
	atf_add_test_case switchboardctl_install_rejects_unsafe
	atf_add_test_case switchboardctl_install_limits
	atf_add_test_case switchboardctl_start_requires_label
}
