#
# SPDX-License-Identifier: BSD-2-Clause
#
# Common test helpers shared across serviced test suites.
#

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
	    /usr/libexec/serviced \
	    /usr/obj/usr/src/arm64.aarch64/usr.sbin/serviced/serviced
	do
		if [ -n "$p" ] && [ -x "$p" ]; then
			serviced_bin="$p"
			return
		fi
	done
	atf_skip "serviced binary not found"
}

prepare_paths()
{
	pidfile="$(pwd)/oracled.pid"
	conffile="$(pwd)/oracled.conf"
	manifestdir="$(pwd)/serviced.d"
	sockpath="$(pwd)/oracled.sock"
	logfile="$(pwd)/oracled.log"
	mkdir -p "$manifestdir"
	mkdir -p "${APPS_DIR}" "${USER_APPS_DIR}"
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
serviced_control_socket = "${CTL_SOCK}";
EOF
	# Export bundle directory overrides so serviced scans test-local paths.
	export SERVICED_BUNDLE_DIR_SYSTEM="${APPS_DIR}"
	export SERVICED_BUNDLE_DIR_USER="${USER_APPS_DIR}"
}

start_stack()
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

	# Wait for serviced to be ready (check oracle status).
	i=0
	while ! grep -q "serviced ready" "$logfile" 2>/dev/null && [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done
}

wait_for_file()
{
	local path max i
	path="$1"
	max=$(( ${2:-15} * 10 ))
	i=0
	while [ ! -s "$path" ] && [ "$i" -lt "$max" ]; do
		i=$((i + 1))
		sleep 0.1
	done
	test -s "$path"
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
	pkill -9 -f "serviced.d" 2>/dev/null || true
	sleep 0.2
	rm -rf oracled.pid oracled.conf serviced.d oracled.sock \
	    serviced.sock oracled.log lookup-name *.out *.pid *.sh *.c \
	    provider_svc client_svc ready_svc squat_svc
}

write_executable()
{
	local path
	path="$1"
	shift
	printf "%s\n" "$@" > "$path"
	chmod +x "$path"
}

require_cc()
{
	if ! command -v cc >/dev/null 2>&1; then
		atf_skip "cc not available"
	fi
}

# --- Bundle test helpers ---

export WORK="$(pwd)"
APPS_DIR="${WORK}/Capabilities/System"
USER_APPS_DIR="${WORK}/Capabilities"
CTL_SOCK="${WORK}/serviced.sock"

# Create a system bundle (.cap) in the fake /Capabilities/System.
# Usage: create_system_bundle <name> <bundle_id> <program> <provides> [ucl_extra]
create_system_bundle()
{
	local name="$1" bid="$2" prog="$3" provides="$4" extra="${5:-}"
	local dir="${APPS_DIR}/${name}.cap"

	mkdir -p "${dir}/etc"
	mkdir -p "${dir}/bin"

	cat > "${dir}/bin/${prog}" <<-SVCEOF
	#!/bin/sh
	# Minimal test service: write ready file then sleep.
	touch "${WORK}/\${0##*/}.ready"
	exec sleep 3600
	SVCEOF
	chmod 755 "${dir}/bin/${prog}"

	cat > "${dir}/etc/${prog}.ucl" <<-UCL
	bundle_id = "${bid}";
	version = "1.0";
	author = "test";
	program = "${prog}";
	provides = ["${provides}"];
	${extra}
	UCL

	echo "${dir}"
}

# Create a system bundle with requires.
create_system_bundle_with_requires()
{
	local name="$1" bid="$2" prog="$3" provides="$4" requires="$5"
	create_system_bundle "$name" "$bid" "$prog" "$provides" \
	    "requires = [\"${requires}\"];"
}

# Create a user bundle (.cap) in the fake /Capabilities.
# Usage: create_user_bundle <name> <bundle_id> <program> <provides> [ucl_extra]
create_user_bundle()
{
	local name="$1" bid="$2" prog="$3" provides="$4" extra="${5:-}"
	local dir="${USER_APPS_DIR}/${name}.cap"

	mkdir -p "${dir}/etc"
	mkdir -p "${dir}/bin"

	cat > "${dir}/bin/${prog}" <<-SVCEOF
	#!/bin/sh
	touch "${WORK}/\${0##*/}.ready"
	exec sleep 3600
	SVCEOF
	chmod 755 "${dir}/bin/${prog}"

	cat > "${dir}/etc/${prog}.ucl" <<-UCL
	bundle_id = "${bid}";
	version = "1.0";
	author = "test";
	program = "${prog}";
	provides = ["${provides}"];
	${extra}
	UCL

	echo "${dir}"
}

# Create a user bundle with custom UCL content (full file).
create_user_bundle_custom()
{
	local name="$1" prog="$2" ucl_content="$3"
	local dir="${USER_APPS_DIR}/${name}.cap"

	mkdir -p "${dir}/etc"
	mkdir -p "${dir}/bin"

	printf '#!/bin/sh\nexec sleep 3600\n' > "${dir}/bin/${prog}"
	chmod 755 "${dir}/bin/${prog}"

	printf '%s\n' "${ucl_content}" > \
	    "${dir}/etc/${prog}.ucl"

	echo "${dir}"
}

# Run a lookup client that connects to a named service.
# Requires a compiled lookup_client binary.
run_lookup_client()
{
	local name="$1" timeout="${2:-5}"

	timeout "$timeout" ./lookup_client "$name" 2>&1
}

# Start the stack expecting it to fail (for negative tests).
start_stack_expect_failure()
{
	prepare_paths
	write_config

	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	local pid=$!
	sleep 1
	# If it's still running, it didn't fail as expected
	if kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null
		return 1
	fi
	return 0
}
