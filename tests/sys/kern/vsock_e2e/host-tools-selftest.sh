#!/bin/sh
# VM-free checks for the host programs used by the VirtIO E2E runner.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
if [ -z "${TOOLS:-}" ]; then
	if [ -f "$here/Makefile" ]; then
		TOOLS=$(make -C "$here" -V .OBJDIR)
	else
		TOOLS=$here
	fi
fi
work=$(mktemp -d)
server_pid=
cleanup()
{
	[ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

for tool in unix-pipe vsh-connect vsh-connect-test-server uinput-inject; do
	[ -x "$TOOLS/$tool" ] || {
		echo "missing helper: $TOOLS/$tool" >&2
		exit 1
	}
done

wait_for_socket()
{
	path=$1
	i=0
	while [ ! -S "$path" ] && [ "$i" -lt 50 ]; do
		kill -0 "$server_pid" 2>/dev/null || return 1
		sleep 0.1
		i=$((i + 1))
	done
	[ -S "$path" ]
}

wait_for_file()
{
	path=$1
	i=0
	while [ ! -s "$path" ] && [ "$i" -lt 50 ]; do
		kill -0 "$server_pid" 2>/dev/null || return 1
		sleep 0.1
		i=$((i + 1))
	done
	[ -s "$path" ]
}

check_vsh()
{
	type=$1
	flag=$2
	payload="vsh-$type-probe"
	dir="$work/vsh-$type"
	mkdir "$dir"
	"$TOOLS/vsh-connect-test-server" "$dir/sock" "$type" \
	    >"$dir/server.log" 2>&1 &
	server_pid=$!
	wait_for_socket "$dir/sock" || {
		cat "$dir/server.log" >&2
		return 1
	}
	if [ -n "$flag" ]; then
		out=$(printf %s "$payload" | timeout 10 \
		    "$TOOLS/vsh-connect" "$flag" "$dir" 7001)
	else
		out=$(printf %s "$payload" | timeout 10 \
		    "$TOOLS/vsh-connect" "$dir" 7001)
	fi
	wait "$server_pid"
	server_pid=
	[ "$out" = "$payload" ]
	echo "PASS  vsh_connect_$type"
}

check_unix_pipe()
{
	type=$1
	flag=$2
	payload="unix-$type-probe"
	sock="$work/unix-$type.sock"
	if [ -n "$flag" ]; then
		"$TOOLS/unix-pipe" -l "$flag" -e -n 1 "$sock" \
		    >"$work/unix-$type.log" 2>&1 &
	else
		"$TOOLS/unix-pipe" -l -e -n 1 "$sock" \
		    >"$work/unix-$type.log" 2>&1 &
	fi
	server_pid=$!
	wait_for_socket "$sock" || {
		cat "$work/unix-$type.log" >&2
		return 1
	}
	if [ -n "$flag" ]; then
		out=$(printf %s "$payload" | timeout 10 \
		    "$TOOLS/unix-pipe" "$flag" "$sock")
	else
		out=$(printf %s "$payload" | timeout 10 \
		    "$TOOLS/unix-pipe" "$sock")
	fi
	wait "$server_pid"
	server_pid=
	[ "$out" = "$payload" ]
	echo "PASS  unix_pipe_$type"
}

check_vsh_bulk()
{
	dir="$work/vsh-bulk"
	mkdir "$dir"
	"$TOOLS/vsh-connect-test-server" "$dir/sock" stream \
	    >"$dir/server.log" 2>&1 &
	server_pid=$!
	wait_for_socket "$dir/sock" || {
		cat "$dir/server.log" >&2
		return 1
	}
	timeout 20 "$TOOLS/vsh-connect" "$dir" 7001 \
	    < "$work/bulk.in" > "$work/vsh-bulk.out"
	wait "$server_pid"
	server_pid=
	cmp -s "$work/bulk.in" "$work/vsh-bulk.out"
	echo "PASS  vsh_connect_stream_bulk"
}

check_unix_pipe_bulk()
{
	sock="$work/unix-bulk.sock"
	"$TOOLS/unix-pipe" -l -e -n 1 "$sock" \
	    >"$work/unix-bulk.log" 2>&1 &
	server_pid=$!
	wait_for_socket "$sock" || {
		cat "$work/unix-bulk.log" >&2
		return 1
	}
	timeout 20 "$TOOLS/unix-pipe" "$sock" \
	    < "$work/bulk.in" > "$work/unix-bulk.out"
	wait "$server_pid"
	server_pid=
	cmp -s "$work/bulk.in" "$work/unix-bulk.out"
	echo "PASS  unix_pipe_stream_bulk"
}

check_unix_pipe_seq_record()
{
	sock="$work/unix-seq-record.sock"
	"$TOOLS/unix-pipe" -l -s -e -n 1 "$sock" \
	    >"$work/unix-seq-record.log" 2>&1 &
	server_pid=$!
	wait_for_socket "$sock" || {
		cat "$work/unix-seq-record.log" >&2
		return 1
	}
	timeout 20 "$TOOLS/unix-pipe" -s "$sock" \
	    < "$work/record.in" > "$work/unix-seq-record.out"
	wait "$server_pid"
	server_pid=
	cmp -s "$work/record.in" "$work/unix-seq-record.out"
	echo "PASS  unix_pipe_seq_200k_record"
}

check_payload_chunks()
{
	source=$1
	name=${source##*/}
	encoded="$work/$name.b64"
	decoded="$work/$name.decoded"
	: > "$encoded"
	{ base64 < "$source" | tr -d '\n'; printf '\n'; } | fold -w 1024 |
	while IFS= read -r chunk; do
		printf %s "$chunk" >> "$encoded"
	done
	base64 -d "$encoded" > "$decoded"
	cmp -s "$source" "$decoded"
	echo "PASS  payload_chunks_$name"
}

check_cli_rejection()
{
	if "$TOOLS/vsh-connect" /does/not/exist invalid \
	    >"$work/vsh-invalid.log" 2>&1; then
		echo "vsh-connect accepted an invalid port" >&2
		return 1
	else
		status=$?
	fi
	[ "$status" -eq 2 ]
	if "$TOOLS/unix-pipe" -l -n invalid "$work/invalid.sock" \
	    >"$work/unix-invalid.log" 2>&1; then
		echo "unix-pipe accepted an invalid connection count" >&2
		return 1
	else
		status=$?
	fi
	[ "$status" -eq 2 ]
	echo "PASS  malformed_helper_arguments_rejected"
}

check_console_status()
{
	expected_status=$1
	log="$work/console-$expected_status.log"
	input="$work/console-$expected_status.in"
	output="$work/console-$expected_status.out"
	error="$work/console-$expected_status.err"
	printf '%s\n' '__VSOCK_BEGIN_stale__' stale \
	    '__VSOCK_END_stale__:0' > "$log"
	: > "$input"
	CONSOLE_LOG="$log" CONSOLE_INPUT="$input" \
	    sh "$here/acmd-console.sh" 'ignored-command' 5 \
	    > "$output" 2> "$error" &
	server_pid=$!
	wait_for_file "$input"
	begin=$(sed -n 's/.*\(__VSOCK_BEGIN_[0-9_]*__\).*/\1/p' "$input")
	end=$(sed -n 's/.*\(__VSOCK_END_[0-9_]*__\).*/\1/p' "$input")
	[ -n "$begin" ] && [ -n "$end" ]
	printf 'echoed guest command\r\n%s:0\r\n%s\r\nguest-payload\r\n%s:%s\r\n' \
	    '__VSOCK_END_unrelated__' "$begin" "$end" "$expected_status" >> "$log"
	if wait "$server_pid"; then
		status=0
	else
		status=$?
	fi
	server_pid=
	[ "$status" -eq "$expected_status" ]
	[ "$(cat "$output")" = guest-payload ]
	[ ! -s "$error" ]
	echo "PASS  console_command_status_$expected_status"
}

check_console_timeout()
{
	log="$work/console-timeout.log"
	input="$work/console-timeout.in"
	: > "$log"
	: > "$input"
	if CONSOLE_LOG="$log" CONSOLE_INPUT="$input" \
	    sh "$here/acmd-console.sh" 'ignored-command' 1 \
	    >"$work/console-timeout.out" 2>"$work/console-timeout.err"; then
		echo "console helper accepted a missing completion marker" >&2
		return 1
	else
		status=$?
	fi
	[ "$status" -eq 124 ]
	grep -q 'timed out after 1s' "$work/console-timeout.err"
	echo "PASS  console_command_timeout"
}

check_vsh stream ""
check_vsh seq -s
check_unix_pipe stream ""
check_unix_pipe seq -s
dd if=/dev/zero bs=1024 count=1024 2>/dev/null | tr '\0' B > "$work/bulk.in"
dd if=/dev/zero bs=1024 count=200 2>/dev/null | tr '\0' R > "$work/record.in"
check_vsh_bulk
check_unix_pipe_bulk
check_unix_pipe_seq_record
check_cli_rejection
check_console_status 0
check_console_status 7
check_console_timeout
"$TOOLS/uinput-inject" --self-test | grep -q '^SELFTEST PASS$'
echo "PASS  uinput_provider_selftest"
check_payload_chunks "$here/gvsock.py"
check_payload_chunks "$here/ginput.py"
check_payload_chunks "$here/grng.py"
echo "host helper self-tests completed successfully"
