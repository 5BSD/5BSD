#!/bin/sh
# Root-only, disposable Alpine ISO test: boot, provision over the serial
# console, and run the requested transport test.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
ISO=${ISO:?set ISO to an Alpine virt ISO}
BHYVE=${BHYVE:-/usr/obj/usr/src/$(uname -p).$(uname -p)/usr.sbin/bhyve/bhyve}
UEFI=${UEFI:-/usr/local/share/uefi-firmware/BHYVE_UEFI.fd}
WORKDIR=${WORKDIR:-/tmp/bhyve-vsock-alpine}
TRANSPORTS=${TRANSPORTS:-modern}
DEVICES=${DEVICES:-"vsock rng input"}
CID=${CID:-4}
CONSOLE_PORT=${CONSOLE_PORT:-}
KEEP_VM=${KEEP_VM:-no}
VSOCK_DEBUG=${VSOCK_DEBUG:-1}
INPUT_DEBUG=${INPUT_DEBUG:-1}

[ "$(id -u)" -eq 0 ] || { echo "run-alpine-auto.sh must run as root" >&2; exit 1; }
[ -f "$ISO" ] || { echo "ISO not found: $ISO" >&2; exit 1; }
[ -x "$BHYVE" ] || { echo "bhyve not found: $BHYVE" >&2; exit 1; }
[ -f "$UEFI" ] || { echo "UEFI firmware not found: $UEFI" >&2; exit 1; }

run_vsock=no
run_rng_device=no
run_input_device=no
for device in $DEVICES; do
	case "$device" in
	vsock) run_vsock=yes ;;
	rng) run_rng_device=yes ;;
	input) run_input_device=yes ;;
	*) echo "invalid device test: $device" >&2; exit 2 ;;
	esac
done
[ "$run_vsock" = yes ] || [ "$run_rng_device" = yes ] ||
    [ "$run_input_device" = yes ] || {
	echo "DEVICES must select vsock, rng, input, or a combination" >&2
	exit 2
}

for transport in $TRANSPORTS; do
	case "$transport" in
	modern) ;;
	legacy)
		[ "$run_input_device" = no ] || {
			echo "the Alpine verifier cannot bind bhyve's historical virtio-input interface; use transport=modern or remove input from DEVICES" >&2
			exit 2
		}
		;;
	*) echo "invalid transport: $transport" >&2; exit 2 ;;
	esac
done

prepare_workdir()
{
	path=$1
	[ ! -L "$path" ] || {
		echo "WORKDIR must not be a symbolic link: $path" >&2
		return 1
	}
	mkdir -p -m 0700 "$path"
	[ -d "$path" ] || {
		echo "WORKDIR is not a directory: $path" >&2
		return 1
	}
	owner=$(stat -f %u "$path")
	[ "$owner" -eq 0 ] || {
		echo "WORKDIR must be owned by root: $path (uid $owner)" >&2
		return 1
	}
	mode=$(stat -f %Lp "$path")
	[ "$mode" = 700 ] || {
		echo "WORKDIR must have mode 0700: $path (mode $mode)" >&2
		return 1
	}
}
prepare_workdir "$WORKDIR"
if [ -f "$here/Makefile" ]; then
	make -C "$here"
	tools=${TOOLS:-$(make -C "$here" -V .OBJDIR)}
else
	tools=${TOOLS:-$here}
fi
required_tools=
[ "$run_vsock" = no ] || required_tools="unix-pipe vsh-connect vsh-connect-test-server uinput-inject"
[ "$run_input_device" = no ] || required_tools="$required_tools uinput-inject"
for tool in $required_tools; do
	[ -x "$tools/$tool" ] || {
		echo "built helper not found: $tools/$tool" >&2
		exit 1
	}
done
[ "$run_vsock" = no ] || TOOLS="$tools" sh "$here/host-tools-selftest.sh"
kldload -n vmm
[ "$run_input_device" = no ] || kldload -n uinput
[ "$run_input_device" = no ] || "$tools/uinput-inject" --kernel-self-test
sysctl net.link.tap.up_on_open=1 >/dev/null

if [ -z "$CONSOLE_PORT" ]; then
	CONSOLE_PORT=4400
	while nc -z 127.0.0.1 "$CONSOLE_PORT" >/dev/null 2>&1; do
		CONSOLE_PORT=$((CONSOLE_PORT + 1))
		[ "$CONSOLE_PORT" -lt 4500 ] || {
			echo "no free TCP console port in 4400..4499" >&2
			exit 1
		}
	done
fi

bridge_created=no
if ! ifconfig bridge0 >/dev/null 2>&1; then
	ifconfig bridge0 create
	bridge_created=yes
	nic=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
	[ -z "$nic" ] || ifconfig bridge0 addm "$nic"
	ifconfig bridge0 up
fi
tap=$(ifconfig tap create)
ifconfig bridge0 addm "$tap"
ifconfig "$tap" up

vm_pid=
console_pid=
input_pid=
vmname=
console_log=
bhyve_log=
input_log=
cleanup_vm()
{
	[ -z "$console_pid" ] || pkill -TERM -P "$console_pid" 2>/dev/null || true
	[ -z "$console_pid" ] || kill "$console_pid" 2>/dev/null || true
	console_pid=
	if [ -n "$vm_pid" ]; then
		kill "$vm_pid" 2>/dev/null || true
		i=0
		while kill -0 "$vm_pid" 2>/dev/null && [ "$i" -lt 5 ]; do
			sleep 1
			i=$((i + 1))
		done
		kill -KILL "$vm_pid" 2>/dev/null || true
		wait "$vm_pid" 2>/dev/null || true
	fi
	vm_pid=
	[ -z "$vmname" ] || bhyvectl --vm="$vmname" --destroy >/dev/null 2>&1 || true
	if [ -n "$input_pid" ]; then
		kill "$input_pid" 2>/dev/null || true
		wait "$input_pid" 2>/dev/null || true
	fi
	input_pid=
}
cleanup_all()
{
	if [ "$KEEP_VM" = yes ]; then
		echo "KEEP_VM=yes: preserving VM, console, provider, and tap $tap" >&2
		return
	fi
	cleanup_vm
	ifconfig bridge0 deletem "$tap" >/dev/null 2>&1 || true
	ifconfig "$tap" destroy >/dev/null 2>&1 || true
	[ "$bridge_created" = no ] || ifconfig bridge0 destroy >/dev/null 2>&1 || true
}
report_failure()
{
	echo "==== retained failure diagnostics ====" >&2
	for item in "bhyve:$bhyve_log" "input-provider:$input_log" \
	    "guest-console:$console_log"; do
		label=${item%%:*}
		path=${item#*:}
		if [ -n "$path" ] && [ -r "$path" ]; then
			echo "---- $label ($path), last 80 lines ----" >&2
			tail -n 80 "$path" >&2 || true
		fi
	done
	echo "full logs remain under $WORKDIR" >&2
}
on_exit()
{
	status=$?
	trap - EXIT
	[ "$status" -eq 0 ] || report_failure
	cleanup_all
	exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT TERM

wait_for()
{
	pattern=$1
	limit=$2
	i=0
	while [ "$i" -lt "$limit" ]; do
		grep -q "$pattern" "$console_log" 2>/dev/null && return 0
		sleep 1
		i=$((i + 1))
	done
	echo "timed out waiting for console pattern: $pattern" >&2
	return 1
}

start_console()
{
	: > "$console_input"
	: > "$console_log"
	i=0
	while ! sockstat -4 -l | grep -q ":${CONSOLE_PORT}[[:space:]]"; do
		kill -0 "$vm_pid" 2>/dev/null || {
			echo "bhyve exited before its console became ready:" >&2
			tail -n 20 "$bhyve_log" >&2
			return 1
		}
		[ "$i" -lt 30 ] || { echo "bhyve console did not listen" >&2; return 1; }
		sleep 1
		i=$((i + 1))
	done
	(tail -f "$console_input" | nc 127.0.0.1 "$CONSOLE_PORT" > "$console_log" 2>&1) &
	console_pid=$!
}

launch_vm()
{
	set -- "$BHYVE" -c 2 -m 2G -H -w \
	    -s 0,hostbridge -s "3,ahci-cd,$ISO" -s "4,virtio-net,$tap"
	[ "$run_vsock" = no ] || set -- "$@" \
	    -s "5,virtio-vsock,cid=$CID,path=$sockdir$vsock_transport_opt"
	[ "$run_input_device" = no ] || set -- "$@" \
	    -s "6,virtio-input,$input_path$input_transport_opt"
	[ "$run_rng_device" = no ] || set -- "$@" \
	    -s "7,virtio-rnd$rng_transport_opt"
	set -- "$@" -s 31,lpc -l "com1,tcp=127.0.0.1:$CONSOLE_PORT" \
	    -l "bootrom,$UEFI" "$vmname"
	env BHYVE_VTVSOCK_DEBUG="$VSOCK_DEBUG" \
	    BHYVE_VTINPUT_DEBUG="$INPUT_DEBUG" "$@" \
	    >> "$bhyve_log" 2>&1 &
	vm_pid=$!
	start_console
}

guest_cmd()
{
	CONSOLE_LOG=$console_log CONSOLE_INPUT=$console_input \
	    sh "$here/acmd-console.sh" "$1" "${2:-30}"
}

copy_guest_file()
{
	source=$1
	destination=$2
	set -- $(cksum < "$source")
	expected_sum=$1
	expected_size=$2

	guest_cmd ": > '$destination.b64'" 30
	{ base64 < "$source" | tr -d '\n'; printf '\n'; } | fold -w 1024 |
	while IFS= read -r chunk; do
		guest_cmd "printf %s '$chunk' >> '$destination.b64'" 30
	done
	guest_cmd "base64 -d '$destination.b64' > '$destination' && rm -f '$destination.b64' && set -- \$(cksum < '$destination') && [ \"\$1\" = '$expected_sum' ] && [ \"\$2\" = '$expected_size' ]" 30
}

provision_guest()
{
	wait_for 'login:' 120
	printf 'root\r' >> "$console_input"
	sleep 2
	guest_cmd 'set -eu; ip link set eth0 up; udhcpc -n -q -t 5 -T 3 -i eth0; release=$(cut -d. -f1,2 /etc/alpine-release); case "$release" in *.*) ;; *) echo "invalid Alpine release: $release" >&2; exit 1;; esac; major=${release%.*}; minor=${release#*.}; case "$major:$minor" in *[!0-9:]*|:|*:) echo "invalid Alpine release: $release" >&2; exit 1;; esac; repository="https://dl-cdn.alpinelinux.org/alpine/v${release}/main"; printf "%s\n" "$repository" > /etc/apk/repositories; apk add --no-cache python3; printf "PROVISION alpine=%s repository=%s " "$(cat /etc/alpine-release)" "$repository"; python3 --version' 150
	if [ "$run_vsock" = yes ]; then
		guest_cmd 'modprobe vsock; modprobe vmw_vsock_virtio_transport' 30
		copy_guest_file "$here/gvsock.py" /tmp/gvsock.py
		guest_cmd 'python3 /tmp/gvsock.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_input_device" = yes ]; then
		guest_cmd 'modprobe virtio_input' 30
		copy_guest_file "$here/ginput.py" /tmp/ginput.py
		guest_cmd 'python3 /tmp/ginput.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_rng_device" = yes ]; then
		guest_cmd 'modprobe virtio_rng' 30
		copy_guest_file "$here/grng.py" /tmp/grng.py
		guest_cmd 'python3 /tmp/grng.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
}

run_matrix()
{
	DIR=$sockdir TRANSPORT=$transport GPY=/tmp/gvsock.py \
	TOOLS="$tools" \
	HOST_WORK="$WORKDIR/$transport.host" \
	BHYVE_LOG="$bhyve_log" CONSOLE_LOG_PATH="$console_log" \
	ACMD="env CONSOLE_LOG=$console_log CONSOLE_INPUT=$console_input sh $here/acmd-console.sh" \
	    sh "$here/run-linux.sh"
}

run_input()
{
	if ! guest_cmd "rm -f /tmp/ginput.out; nohup python3 /tmp/ginput.py '$input_name' '$transport' >/tmp/ginput.out 2>&1 & i=0; while ! grep -q '^READY$' /tmp/ginput.out 2>/dev/null && [ \"\$i\" -lt 15 ]; do sleep 1; i=\$((i + 1)); done; grep -q '^READY$' /tmp/ginput.out" 20 >/dev/null; then
		echo "guest virtio-input verifier failed to become ready" >&2
		guest_cmd 'cat /tmp/ginput.out 2>/dev/null || true' 12 >&2 || true
		return 1
	fi
	printf 'tap\n' > "$input_fifo"
	if ! guest_cmd 'i=0; while ! grep -q "^PASS$" /tmp/ginput.out 2>/dev/null && [ "$i" -lt 20 ]; do sleep 1; i=$((i + 1)); done; cat /tmp/ginput.out; grep -q "^PASS$" /tmp/ginput.out' 25; then
		echo "guest virtio-input event verification failed" >&2
		return 1
	fi
	if ! wait "$input_pid"; then
		cat "$input_log" >&2
		return 1
	fi
	input_pid=
}

run_rng()
{
	output=$(guest_cmd "python3 /tmp/grng.py '$transport'" 60) || {
		status=$?
		echo "guest virtio-rng verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	printf '%s\n' "$output" | grep -q '^PASS rng bytes='
}

for transport in $TRANSPORTS; do
	vmname="alpine-virtio-${transport}-$$"
	sockdir="$WORKDIR/$transport"
	console_input="$WORKDIR/$transport.console.in"
	console_log="$WORKDIR/$transport.console.log"
	bhyve_log="$WORKDIR/$transport.bhyve.log"
	input_fifo="$WORKDIR/$transport.input.fifo"
	input_path_file="$WORKDIR/$transport.input.path"
	input_log="$WORKDIR/$transport.input.log"
	input_name="bhyve-e2e-input-$transport-$$"
	if [ "$transport" = modern ]; then
		vsock_transport_opt=",transport=modern"
		input_transport_opt=",transport=modern"
		rng_transport_opt=",transport=modern"
	else
		# Deliberately omit the option to exercise the compatibility default.
		vsock_transport_opt=
		rng_transport_opt=
	fi
	mkdir -p "$sockdir"
	chmod 0700 "$sockdir"
	rm -f "$sockdir/sock"
	: > "$bhyve_log"
	if [ "$run_input_device" = yes ]; then
		rm -f "$input_fifo" "$input_path_file"
		mkfifo -m 0600 "$input_fifo"
		"$tools/uinput-inject" "$input_fifo" "$input_name" > "$input_path_file" 2> "$input_log" &
		input_pid=$!
		i=0
		while [ ! -s "$input_path_file" ] && kill -0 "$input_pid" 2>/dev/null && [ "$i" -lt 10 ]; do
			sleep 1
			i=$((i + 1))
		done
		[ -s "$input_path_file" ] || { cat "$input_log" >&2; exit 1; }
		input_path=$(sed -n '1p' "$input_path_file")
		case "$input_path" in
		/dev/input/event*)
			input_unit=${input_path#/dev/input/event}
			case "$input_unit" in ''|*[!0-9]*) echo "unsafe uinput path: $input_path" >&2; exit 1;; esac
			;;
		*) echo "unsafe uinput path: $input_path" >&2; exit 1;;
		esac
	fi

	echo "== Alpine $transport: boot and test =="
	launch_vm
	provision_guest
	[ "$run_vsock" = no ] || run_matrix
	[ "$run_rng_device" = no ] || run_rng
	[ "$run_input_device" = no ] || run_input

	cleanup_vm
done

echo "Alpine transport automation completed successfully"
