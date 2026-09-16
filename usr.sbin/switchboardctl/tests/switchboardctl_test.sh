#
# SPDX-License-Identifier: BSD-2-Clause
#
# Tests for switchboardctl(8) driving switchboard over the capability control plane.
#

. "$(atf_get_srcdir)/capd_test_harness.sh"

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

# These cases deliberately exercise the manager belonging to the root login.
# An inherited channel cannot address an independently started fixture manager.
# Opt in only in a disposable VM: the service cases install one temporary bundle.
require_ambient_control()
{
	[ "$(atf_config_get live_admin no)" = yes ] ||
	    atf_skip "requires live_admin=yes in a disposable normal-plane VM"
	[ -n "${SERVICE_LOOKUP_FD:-}" ] || atf_fail "root login has no discovery channel"
	[ "$(ps -p 1 -o comm=)" = capsule ] || atf_fail "Capsule is not PID 1"
	find_switchboardctl
	touch .live-admin-mode
	atf_check -s exit:0 -o match:"switchboard: running" "$switchboardctl_bin" status
}

live_admin_bundle()
{
	local fixture dir
	fixture=$(atf_config_get service_fixture /usr/tests/lib/libservice/capd_service_fixture)
	[ -x "$fixture" ] || atf_fail "managed service fixture is missing"
	dir=/Capabilities/System/authority-admin-qa.cap
	mkdir "$dir" || atf_fail "qualification bundle already exists or cannot be created"
	touch .live-admin-bundle
	chmod 0777 "$(pwd)"
	write_bundle "$dir" org.test.authority.admin worker 1 'activation { boot = true; }'
	cp "$fixture" "$dir/Units/worker.unit/bin/worker"
	chmod 0555 "$dir/Units/worker.unit/bin/worker"
	printf 'directories = ["%s"];\narguments = ["lifecycle-hold", "pid", "ready", "ready"];\nrestart = "never";\n' "$(pwd)" >> "$dir/Units/worker.unit/Unit.ucl"
	# The bundle is now installed by dropping it under System/; switchboard
	# picks it up on a registry rescan.
	atf_check "$switchboardctl_bin" reload
}

live_admin_wait()
{
	local i=0
	while [ "$i" -lt 300 ]; do
		[ ! -s pid ] || [ "$(cat pid)" = "${1:-}" ] || return 0
		i=$((i + 1))
		sleep 0.1
	done
	cat fixture-errors fixture-init-failure.result 2>/dev/null || true
	atf_fail "qualification service did not start or restart"
}

live_admin_cleanup()
{
	[ -e .live-admin-bundle ] || return 0
	find_switchboardctl
	# Removing the bundle directory is the uninstall; switchboard drops the
	# unit on the next rescan.
	rm -rf /Capabilities/System/authority-admin-qa.cap
	"$switchboardctl_bin" reload
}

cleanup_common()
{
	[ ! -e .live-admin-mode ] || live_admin_cleanup
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
	atf_set is.exclusive true
	atf_set "descr" "switchboardctl status reports switchboard state"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
switchboardctl_status_body()
{
	require_ambient_control
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
	atf_set is.exclusive true
	atf_set "descr" "switchboardctl services lists loaded services"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
switchboardctl_services_lists_body()
{
	require_ambient_control
	live_admin_bundle
	atf_check -o ignore "$switchboardctl_bin" reload
	live_admin_wait
	atf_check -o match:'org.test.authority.admin/worker' "$switchboardctl_bin" services
}

switchboardctl_services_lists_cleanup()
{
	cleanup_common
}

# ===================================================================
# switchboardctl reload — triggers manifest reload
# ===================================================================

atf_test_case switchboardctl_reload cleanup
switchboardctl_reload_head()
{
	atf_set is.exclusive true
	atf_set "descr" "switchboardctl reload triggers manifest reload"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
switchboardctl_reload_body()
{
	local rc_service rc_pid
	require_ambient_control
	rc_service=$(atf_config_get preserve_rc_service "")
	if [ -n "$rc_service" ]; then
		atf_check -o match:"$rc_service .*running" "$switchboardctl_bin" services
		rc_pid=$(pgrep -x "$rc_service") || atf_fail "adopted daemon is absent"
	fi
	live_admin_bundle
	atf_check -o ignore "$switchboardctl_bin" reload
	live_admin_wait
	atf_check -o match:'org.test.authority.admin/worker' "$switchboardctl_bin" services
	if [ -n "$rc_service" ]; then
		atf_check -o match:"$rc_service .*running" "$switchboardctl_bin" services
		[ "$(pgrep -x "$rc_service")" = "$rc_pid" ] ||
		    atf_fail "bundle reload replaced or stopped the adopted daemon"
	fi
}

switchboardctl_reload_cleanup()
{
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
	atf_set is.exclusive true
	atf_set "descr" "switchboardctl reload denied for non-root"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
switchboardctl_reload_nonroot_body()
{
	require_ambient_control
	id nobody >/dev/null 2>&1 || atf_fail "nobody account is missing"
	atf_check -s not-exit:0 -e ignore -o ignore su -m nobody -c "'$switchboardctl_bin' reload"
	atf_check -o match:'switchboard: running' "$switchboardctl_bin" status
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
	export SWITCHBOARD_LIFECYCLE_ROOT="$(pwd)"
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
	export SWITCHBOARD_LIFECYCLE_ROOT="$(pwd)"
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
	export SWITCHBOARD_LIFECYCLE_ROOT="$(pwd)"
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
	export SWITCHBOARD_LIFECYCLE_ROOT="$(pwd)"
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
	export SWITCHBOARD_LIFECYCLE_ROOT="$(pwd)"
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
	atf_set is.exclusive true
	atf_set "descr" "switchboardctl restart stops and starts a service (new pid)"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
switchboardctl_restart_body()
{
	local oldpid
	require_ambient_control
	live_admin_bundle
	atf_check -o ignore "$switchboardctl_bin" reload
	live_admin_wait
	oldpid=$(cat pid)
	atf_check -o ignore "$switchboardctl_bin" restart org.test.authority.admin/worker
	live_admin_wait "$oldpid"
	atf_check -s not-exit:0 -e match:"No such process" kill -0 "$oldpid"
	atf_check kill -0 "$(cat pid)"
}

switchboardctl_restart_cleanup()
{
	cleanup_common
}

# Control-request input validation over the capability plane: switchboard must
# reject a request whose declared payload length exceeds the protocol maximum
# (EINVAL=22) rather than over-reading.  capd_protocol_fixture crafts the
# oversized request and sends it over system.switchboard. Requires the same
# explicit disposable-VM live_admin configuration as the administrative cases.
atf_test_case sctl_oversized_payload cleanup
sctl_oversized_payload_head()
{
	atf_set is.exclusive true
	atf_set "descr" "switchboard rejects oversized control requests"
	atf_set "require.user" "root"
	require_capsule_stack_kmods
}
sctl_oversized_payload_body()
{
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
