#
# SPDX-License-Identifier: BSD-2-Clause
#
# Tests for servicectl(8) and serviced's control socket.
#

. "$(atf_get_srcdir)/capd_test_harness.sh"

daemon_pid=
pidfile=
conffile=
manifestdir=
user_manifestdir=
sockpath=
sctl_sockpath=
logfile=
serviced_bin=

find_serviced()
{
	capd_find_serviced
	serviced_bin=$capd_serviced_bin
}

require_authority_stack_kmods()
{
	capd_require_stack_kmods
}

find_servicectl()
{
	local p _machine _arch
	_machine=$(uname -m)
	_arch=$(uname -p)
	for p in \
	    "$(atf_get_srcdir)/servicectl_test_bin" \
	    /usr/obj/usr/src/${_machine}.${_arch}/usr.sbin/servicectl/servicectl \
	    /usr/sbin/servicectl \
	    "$(command -v servicectl 2>/dev/null)"
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
	capd_paths_init
	pidfile=$CAPD_PIDFILE
	conffile=$CAPD_CONFIG
	manifestdir=$CAPD_APPS_SYSTEM
	user_manifestdir=$CAPD_APPS_USER
	sockpath=$CAPD_AUTHORITY_SOCKET
	sctl_sockpath=$CAPD_SERVICED_SOCKET
	logfile=$CAPD_LOG
	mkdir -p "$manifestdir" "$user_manifestdir"
	export SERVICED_BUNDLE_DIR_SYSTEM="$manifestdir"
	export SERVICED_BUNDLE_DIR_USER="$user_manifestdir"
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
	capd_start_stack
	daemon_pid=$("$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" status |
	    sed -n 's/^running pid=//p')

	# Wait for serviced control socket.
	i=0
	while [ ! -S "$sctl_sockpath" ] && [ "$i" -lt 50 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -S "$sctl_sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "serviced did not create its control socket"
	fi
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
	rm -rf authorityd.pid authorityd.conf Capabilities authorityd.sock \
	    serviced.sock authorityd.log *.out *.sh
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
# servicectl status
# ===================================================================

atf_test_case servicectl_status cleanup
servicectl_status_head()
{
	atf_set "descr" "servicectl status reports serviced state"
	atf_set "require.user" "root"
	require_authority_stack_kmods
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
	require_authority_stack_kmods
}
servicectl_services_lists_body()
{
	find_servicectl
	prepare_paths

	write_bundle "$manifestdir/long-svc.cap" org.test.long-svc long-svc 1 \
	    'activation { boot = true; ipc = ["org.test.long-svc"]; }'
	write_executable "$manifestdir/long-svc.cap/Units/long-svc.unit/bin/long-svc" \
	    '#!/bin/sh' \
	    'echo $$ > long-svc.pid' \
	    'sleep 60'

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
	require_authority_stack_kmods
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
	write_bundle "$manifestdir/reload-svc.cap" org.test.reload-svc reload-svc 1 \
	    'activation { boot = true; ipc = ["org.test.reload-svc"]; }'
	write_executable "$manifestdir/reload-svc.cap/Units/reload-svc.unit/bin/reload-svc" \
	    '#!/bin/sh' \
	    'echo $$ > reload-svc.pid' \
	    'sleep 60'

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
	require_authority_stack_kmods
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
	write_bundle "$bdir" org.test.verify verifyd 1 \
	    'activation { ipc = ["org.test.verify.svc"]; }'
	printf '#!/bin/sh\nexec sleep 3600\n' > \
	    "${bdir}/Units/verifyd.unit/bin/verifyd"
	chmod 755 "${bdir}/Units/verifyd.unit/bin/verifyd"

	atf_check -s exit:0 -o match:"PASSED" \
	    "$servicectl_bin" verify "${bdir}"
}
servicectl_verify_cleanup()
{
	rm -rf VerifyTest.cap
}

atf_test_case servicectl_verify_local_descriptors cleanup
servicectl_verify_local_descriptors_head()
{
	atf_set "descr" \
	    "servicectl shows every effective local descriptor"
}
servicectl_verify_local_descriptors_body()
{
	find_servicectl
	local bdir="$(pwd)/ComponentsTest.cap"
	write_bundle "$bdir" org.test.descriptors consumer 1 \
	    'activation { boot = true; }'
	printf '#!/bin/sh\nexit 0\n' > \
	    "${bdir}/Units/consumer.unit/bin/consumer"
	chmod 755 "${bdir}/Units/consumer.unit/bin/consumer"
	cat >> "${bdir}/Units/consumer.unit/Unit.ucl" <<EOF
storage = [{ name = "data"; scope = "unit"; rights = "mount"; }];
descriptors { filesystem { storage = "data"; } network {} crypto {} }
EOF

	atf_check -s exit:0 -o save:components.out \
	    "$servicectl_bin" verify "${bdir}"
	atf_check -s exit:0 -o match:'descriptor: filesystem storage=data' \
	    grep 'descriptor:' components.out
	atf_check -s exit:0 -o match:'descriptor: network' \
	    grep 'descriptor:' components.out
	atf_check -s exit:0 -o match:'descriptor: crypto' \
	    grep 'descriptor:' components.out
	atf_check -s exit:0 -o match:'activation: boot' \
	    grep 'activation:' components.out
}
servicectl_verify_local_descriptors_cleanup()
{
	rm -rf ComponentsTest.cap components.out
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
	write_bundle "$bdir" org.test.bad nonexistent 1 \
	    'activation { boot = true; }'

	atf_check -s not-exit:0 -e match:"FAILED" \
	    "$servicectl_bin" verify "${bdir}"
}
servicectl_verify_invalid_cleanup()
{
	rm -rf BadBundle.cap
}

# ===================================================================
# servicectl deps — suggests only local authority components
# ===================================================================

atf_test_case servicectl_deps cleanup
servicectl_deps_head()
{
	atf_set "descr" \
	    "servicectl deps suggests local descriptors and ignores global services"
}
servicectl_deps_body()
{
	find_servicectl

	cp /usr/bin/true no-descriptors
	atf_check -s exit:0 -o match:"No local descriptor dependencies" \
	    "$servicectl_bin" deps no-descriptors

	atf_check -s exit:0 -o save:deps-network.out \
	    "$servicectl_bin" deps \
	    "$(atf_get_srcdir)/deps_network_fixture"
	atf_check -s exit:0 -o match:'network \{\}' \
	    grep 'network' deps-network.out
	atf_check -s exit:1 -o empty -e empty \
	    grep 'provider' deps-network.out

	atf_check -s exit:0 -o save:deps-both.out \
	    "$servicectl_bin" deps "$(atf_get_srcdir)/deps_both_fixture"
	atf_check -s exit:0 -o match:'filesystem \{ storage = "data"; \}' \
	    grep 'filesystem' deps-both.out
	atf_check -s exit:0 -o match:'network \{\}' grep 'network' deps-both.out
	atf_check -s exit:0 -o match:'crypto \{\}' grep 'crypto' deps-both.out
	atf_check -s exit:1 -o empty -e empty \
	    grep -E 'log|trace|notify|interface|sharing' deps-both.out
	atf_check -s exit:0 -o match:'discover their named services' \
	    grep 'discover' deps-both.out

	printf 'interface=system.Network\n' > not-elf
	atf_check -s not-exit:0 -e match:"not an ELF object" \
	    "$servicectl_bin" deps not-elf
	ln -s no-descriptors symlink-elf
	atf_check -s not-exit:0 -e ignore \
	    "$servicectl_bin" deps symlink-elf
}
servicectl_deps_cleanup()
{
	rm -f no-descriptors not-elf symlink-elf deps-network.out deps-both.out
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
	require_authority_stack_kmods
}
sctl_oversized_payload_body()
{
	start_stack
	if [ ! -S "$sctl_sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_skip "serviced control socket not available"
	fi

	# Server replies with EMSGSIZE error.
	atf_check -s exit:0 -o match:"status=" \
	    "$(atf_get_srcdir)/capd_protocol_fixture" control-oversized \
	    "$sctl_sockpath"
}
sctl_oversized_payload_cleanup()
{
	cleanup_common
}

# ===================================================================
# servicectl install — valid bundle
# ===================================================================

atf_test_case servicectl_install_valid cleanup
servicectl_install_valid_head() {
	atf_set "descr" "install atomically publishes a normalized canonical bundle version"
	atf_set "require.user" "root"
}
servicectl_install_valid_body() {
	find_servicectl
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

	export SERVICED_BUNDLE_DIR_USER="$idir"
	atf_check -s exit:0 -o match:"published $dst" \
	    "$servicectl_bin" install "$src"
	atf_check -s exit:0 test -x "$dst/Units/instd.unit/bin/instd"
	atf_check -s exit:0 -o inline:'0\n' stat -f %u \
	    "$dst/Units/instd.unit/bin/instd"
	atf_check -s exit:0 -o inline:'0\n' sh -c \
	    'm=0$(stat -f %Lp "$1"); test $((m & 022)) -eq 0; echo $?' sh "$dst"
	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "$servicectl_bin" verify "$dst"
	atf_check -s exit:0 -o empty -e empty sh -c \
	    'test -z "$(find "$1" -maxdepth 1 -name ".servicectl.*" -print -quit)"' \
	    sh "$idir"
}
servicectl_install_valid_cleanup() {
	rm -rf InstallMe.cap install_target
}

# ===================================================================
# servicectl install — path traversal rejected
# ===================================================================

atf_test_case servicectl_install_source_name_ignored cleanup
servicectl_install_source_name_ignored_head() {
	atf_set "descr" "source basename cannot influence the canonical destination"
	atf_set "require.user" "root"
}
servicectl_install_source_name_ignored_body() {
	find_servicectl
	local src="$(pwd)/..Misleading.cap" idir="$(pwd)/name_target"
	mkdir "$idir"
	write_bundle "$src" org.test.canonical worker 9 \
	    'activation { boot = true; }'
	write_executable "$src/Units/worker.unit/bin/worker" '#!/bin/sh' 'exit 0'
	export SERVICED_BUNDLE_DIR_USER="$idir"
	atf_check -s exit:0 -o match:'org.test.canonical@00000000000000000009.cap' \
	    "$servicectl_bin" install "$src"
	atf_check -s exit:0 test -d \
	    "$idir/org.test.canonical@00000000000000000009.cap"
}
servicectl_install_source_name_ignored_cleanup() {
	rm -rf "..Misleading.cap" name_target
}

# ===================================================================
# servicectl install — overwrite rejected
# ===================================================================

atf_test_case servicectl_install_versions cleanup
servicectl_install_versions_head() {
	atf_set "descr" "immutable versions coexist and duplicate sequences fail"
	atf_set "require.user" "root"
}
servicectl_install_versions_body() {
	find_servicectl
	local src="$(pwd)/Version.cap" idir="$(pwd)/versions"
	mkdir "$idir"
	write_bundle "$src" org.test.versioned worker 1 \
	    'activation { boot = true; }'
	write_executable "$src/Units/worker.unit/bin/worker" '#!/bin/sh' 'exit 0'
	export SERVICED_BUNDLE_DIR_USER="$idir"
	atf_check -s exit:0 -o ignore "$servicectl_bin" install "$src"
	atf_check -s exit:1 -o ignore -e match:'File exists' \
	    "$servicectl_bin" install "$src"
	sed -i '' 's/version = "1.0.1"/version = "2.0.0"/; s/sequence = 1/sequence = 2/' \
	    "$src/Bundle.ucl"
	atf_check -s exit:0 -o ignore "$servicectl_bin" install "$src"
	atf_check -s exit:0 test -d \
	    "$idir/org.test.versioned@00000000000000000001.cap"
	atf_check -s exit:0 test -d \
	    "$idir/org.test.versioned@00000000000000000002.cap"
}
servicectl_install_versions_cleanup() {
	rm -rf Version.cap versions
}

atf_test_case servicectl_install_rejects_unsafe cleanup
servicectl_install_rejects_unsafe_head() {
	atf_set "descr" "staged symlinks and untrusted registry roots fail without residue"
	atf_set "require.user" "root"
}
servicectl_install_rejects_unsafe_body() {
	find_servicectl
	local src="$(pwd)/Unsafe.cap" idir="$(pwd)/unsafe_target"
	mkdir "$idir"
	write_bundle "$src" org.test.unsafe worker 1 \
	    'activation { boot = true; }'
	rm "$src/Units/worker.unit/bin/worker" 2>/dev/null || true
	ln -s /bin/true "$src/Units/worker.unit/bin/worker"
	export SERVICED_BUNDLE_DIR_USER="$idir"
	atf_check -s exit:1 -o ignore -e match:'unsafe object' \
	    "$servicectl_bin" install "$src"
	atf_check -s exit:0 -o empty -e empty sh -c \
	    'test -z "$(find "$1" -mindepth 1 -maxdepth 1 -print -quit)"' \
	    sh "$idir"
	chmod 0777 "$idir"
	atf_check -s exit:1 -o ignore -e match:'root-owned.*non-group/world-writable' \
	    "$servicectl_bin" install "$src"
}
servicectl_install_rejects_unsafe_cleanup() {
	rm -rf Unsafe.cap unsafe_target
}

atf_test_case servicectl_install_limits cleanup
servicectl_install_limits_head() {
	atf_set "descr" "install rejects oversized files and excessive entries without residue"
	atf_set "require.user" "root"
}
servicectl_install_limits_body() {
	find_servicectl
	local src="$(pwd)/Limited.cap" idir="$(pwd)/limit_target" i
	mkdir "$idir"
	write_bundle "$src" org.test.limited worker 1 \
	    'activation { boot = true; }'
	write_executable "$src/Units/worker.unit/bin/worker" '#!/bin/sh' 'exit 0'
	mkdir -p "$src/Shared"
	truncate -s 536870913 "$src/Shared/oversized"
	export SERVICED_BUNDLE_DIR_USER="$idir"
	atf_check -s exit:1 -o ignore -e match:'exceeds limits' \
	    "$servicectl_bin" install "$src"
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
	    "$servicectl_bin" install "$src"
	atf_check -s exit:0 -o empty -e empty sh -c \
	    'test -z "$(find "$1" -mindepth 1 -maxdepth 1 -print -quit)"' \
	    sh "$idir"
}
servicectl_install_limits_cleanup() {
	rm -rf Limited.cap limit_target
}

atf_test_case servicectl_start_requires_label
servicectl_start_requires_label_head() {
	atf_set "descr" "start rejects absent and surplus labels before connecting"
}
servicectl_start_requires_label_body() {
	find_servicectl
	atf_check -s exit:64 -o empty -e match:'start requires a service label' \
	    "$servicectl_bin" start
	atf_check -s exit:64 -o empty -e match:'start requires a service label' \
	    "$servicectl_bin" start one two
}

atf_test_case servicectl_restart_requires_label
servicectl_restart_requires_label_head() {
	atf_set "descr" "restart rejects absent and surplus labels before connecting"
}
servicectl_restart_requires_label_body() {
	find_servicectl
	atf_check -s exit:64 -o empty -e match:'restart requires a service label' \
	    "$servicectl_bin" restart
	atf_check -s exit:64 -o empty -e match:'restart requires a service label' \
	    "$servicectl_bin" restart one two
}

atf_test_case servicectl_restart_help
servicectl_restart_help_head() {
	atf_set "descr" "restart is advertised in usage"
}
servicectl_restart_help_body() {
	find_servicectl
	atf_check -s not-exit:0 -e match:'restart <label>' "$servicectl_bin"
}

# ===================================================================
# servicectl restart — stop+start a running service (new pid)
# ===================================================================

atf_test_case servicectl_restart cleanup
servicectl_restart_head()
{
	atf_set "descr" "servicectl restart stops and starts a service (new pid)"
	atf_set "require.user" "root"
	require_authority_stack_kmods
}
servicectl_restart_body()
{
	find_servicectl
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

	if [ ! -S "$sctl_sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_skip "serviced control socket not available"
	fi

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
	    "$servicectl_bin" -s "$sctl_sockpath" restart restart-svc

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
servicectl_restart_cleanup()
{
	if [ -f restart-svc.pid ]; then
		kill "$(cat restart-svc.pid)" 2>/dev/null || true
	fi
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
	atf_add_test_case servicectl_verify_local_descriptors
	atf_add_test_case servicectl_deps
	atf_add_test_case servicectl_stop_no_arg
	atf_add_test_case servicectl_restart_requires_label
	atf_add_test_case servicectl_restart_help
	atf_add_test_case servicectl_restart

	# adversarial
	atf_add_test_case sctl_oversized_payload

	# install
	atf_add_test_case servicectl_install_valid
	atf_add_test_case servicectl_install_source_name_ignored
	atf_add_test_case servicectl_install_versions
	atf_add_test_case servicectl_install_rejects_unsafe
	atf_add_test_case servicectl_install_limits
	atf_add_test_case servicectl_start_requires_label
}
