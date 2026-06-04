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
	local path i
	path="$1"
	i=0
	while [ ! -s "$path" ] && [ "$i" -lt 150 ]; do
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
	pkill -9 -f "oracled.d" 2>/dev/null || true
	sleep 0.2
	rm -rf oracled.pid oracled.conf oracled.d oracled.sock \
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
