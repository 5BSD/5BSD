#!/bin/sh
# Root-only, disposable Alpine ISO test: boot, provision over the serial
# console, and run the requested transport test.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
ISO=${ISO:?set ISO to an Alpine virt ISO}
BHYVE=${BHYVE:-}
UEFI=${UEFI:-}
SRCTOP=${SRCTOP:-$(cd "$here/../../../.." && pwd)}
OBJROOT=${OBJROOT:-/usr/obj}
WORKDIR=${WORKDIR:-/tmp/bhyve-vsock-alpine}
TRANSPORTS=${TRANSPORTS:-modern}
DEVICES=${DEVICES:-"vsock rng input"}
VSOCK_BACKEND=${VSOCK_BACKEND:-unix}
CID=${CID:-4}
CONSOLE_PORT=${CONSOLE_PORT:-}
KEEP_VM=${KEEP_VM:-no}
VSOCK_DEBUG=${VSOCK_DEBUG:-1}
INPUT_DEBUG=${INPUT_DEBUG:-1}
SCSI_DEBUG=${SCSI_DEBUG:-1}
VIRTIO_MSIX=${VIRTIO_MSIX:-yes}
RESET_TEST=${RESET_TEST:-no}
REBOOT_TEST=${REBOOT_TEST:-no}
BLOCK_TEST_MB=${BLOCK_TEST_MB:-256}
BLOCK_IMAGE_MB=${BLOCK_IMAGE_MB:-1024}
SCSI_TEST_MB=${SCSI_TEST_MB:-32}
SCSI_IMAGE_MB=${SCSI_IMAGE_MB:-128}
BRIDGE=${BRIDGE:-bridge0}
UPLINK=${UPLINK:-}

if [ -z "$BHYVE" ]; then
	object_bhyve="$OBJROOT$SRCTOP/$(uname -p).$(uname -p)/usr.sbin/bhyve/bhyve"
	if [ -x "$object_bhyve" ]; then
		BHYVE=$object_bhyve
	else
		BHYVE=$(command -v bhyve 2>/dev/null || true)
	fi
fi
if [ -z "$UEFI" ]; then
	for candidate in \
	    /usr/local/share/uefi-firmware/BHYVE_UEFI.fd \
	    /usr/local/share/edk2-bhyve/BHYVE_UEFI.fd; do
		if [ -f "$candidate" ]; then
			UEFI=$candidate
			break
		fi
	done
fi

[ "$(id -u)" -eq 0 ] || { echo "run-alpine-auto.sh must run as root" >&2; exit 1; }
[ -f "$ISO" ] || { echo "ISO not found: $ISO" >&2; exit 1; }
[ -x "$BHYVE" ] || { echo "bhyve not found: $BHYVE" >&2; exit 1; }
[ -f "$UEFI" ] || { echo "UEFI firmware not found: $UEFI" >&2; exit 1; }
case "$VSOCK_BACKEND" in
unix|native) ;;
*) echo "VSOCK_BACKEND must be unix or native" >&2; exit 2 ;;
esac
[ "$VSOCK_BACKEND" != native ] || [ -c /dev/vsock ] || {
	echo "backend=native requires /dev/vsock" >&2
	exit 1
}

run_vsock=no
run_net_device=no
run_rng_device=no
run_input_device=no
run_block_device=no
run_scsi_device=no
run_console_device=no
run_9p_device=no
for device in $DEVICES; do
	case "$device" in
	vsock) run_vsock=yes ;;
	net) run_net_device=yes ;;
	rng) run_rng_device=yes ;;
	input) run_input_device=yes ;;
	block) run_block_device=yes ;;
	scsi) run_scsi_device=yes ;;
	console) run_console_device=yes ;;
	9p) run_9p_device=yes ;;
	*) echo "invalid device test: $device" >&2; exit 2 ;;
	esac
done
[ "$run_vsock" = yes ] || [ "$run_net_device" = yes ] ||
    [ "$run_rng_device" = yes ] ||
    [ "$run_input_device" = yes ] || [ "$run_block_device" = yes ] ||
    [ "$run_scsi_device" = yes ] || [ "$run_console_device" = yes ] ||
    [ "$run_9p_device" = yes ] || {
	echo "DEVICES must select net, vsock, rng, input, block, scsi, console, 9p, or a combination" >&2
	exit 2
}

for setting in "VIRTIO_MSIX:$VIRTIO_MSIX" "RESET_TEST:$RESET_TEST" \
    "REBOOT_TEST:$REBOOT_TEST" "KEEP_VM:$KEEP_VM"; do
	name=${setting%%:*}
	value=${setting#*:}
	case "$value" in
	yes|no) ;;
	*) echo "$name must be yes or no" >&2; exit 2 ;;
	esac
done
case "$BLOCK_TEST_MB:$BLOCK_IMAGE_MB" in
*[!0-9:]*|:*|*:) echo "block sizes must be positive integer MiB values" >&2; exit 2 ;;
esac
[ "$BLOCK_TEST_MB" -gt 0 ] && [ "$BLOCK_IMAGE_MB" -gt 0 ] &&
    [ "$BLOCK_TEST_MB" -le "$BLOCK_IMAGE_MB" ] || {
	echo "require 0 < BLOCK_TEST_MB <= BLOCK_IMAGE_MB" >&2
	exit 2
}
case "$SCSI_TEST_MB:$SCSI_IMAGE_MB" in
*[!0-9:]*|:*|*:) echo "SCSI sizes must be positive integer MiB values" >&2; exit 2 ;;
esac
[ "$SCSI_TEST_MB" -gt 0 ] && [ "$SCSI_IMAGE_MB" -gt 0 ] &&
    [ "$SCSI_TEST_MB" -le "$SCSI_IMAGE_MB" ] || {
	echo "require 0 < SCSI_TEST_MB <= SCSI_IMAGE_MB" >&2
	exit 2
}
if { [ "$RESET_TEST" = yes ] || [ "$REBOOT_TEST" = yes ]; } &&
    [ "$run_input_device" = yes ]; then
	echo "reset/reboot lifecycle tests do not yet support the one-shot input provider" >&2
	exit 2
fi

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
[ "$run_vsock" = no ] || required_tools="unix-pipe vsock-pipe vsh-connect vsh-connect-test-server uinput-inject"
[ "$run_console_device" = no ] || required_tools="$required_tools unix-pipe"
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
[ "$run_scsi_device" = no ] || kldload -n ctl
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
if ! ifconfig "$BRIDGE" >/dev/null 2>&1; then
	ifconfig "$BRIDGE" create
	bridge_created=yes
	nic=$UPLINK
	[ -n "$nic" ] || nic=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
	[ -z "$nic" ] || ifconfig "$BRIDGE" addm "$nic"
	ifconfig "$BRIDGE" up
fi
tap=$(ifconfig tap create)
ifconfig "$BRIDGE" addm "$tap"
ifconfig "$tap" up

vm_pid=
console_pid=
input_pid=
reboot_stream_pid=
reboot_seq_pid=
console_exchange_pid=
vmname=
console_log=
bhyve_log=
input_log=
reboot_stream_log=
reboot_seq_log=
scsi_create_log=
scsi_lun_id=
scsi_size_bytes=
console_exchange_log=
stop_console()
{
	[ -z "$console_pid" ] || pkill -TERM -P "$console_pid" 2>/dev/null || true
	[ -z "$console_pid" ] || kill "$console_pid" 2>/dev/null || true
	[ -z "$console_pid" ] || wait "$console_pid" 2>/dev/null || true
	console_pid=
}
cleanup_vm()
{
	if [ -n "$console_exchange_pid" ]; then
		pkill -TERM -P "$console_exchange_pid" 2>/dev/null || true
		kill "$console_exchange_pid" 2>/dev/null || true
		wait "$console_exchange_pid" 2>/dev/null || true
	fi
	console_exchange_pid=
	for hold_pid in "$reboot_stream_pid" "$reboot_seq_pid"; do
		[ -z "$hold_pid" ] || kill "$hold_pid" 2>/dev/null || true
		[ -z "$hold_pid" ] || wait "$hold_pid" 2>/dev/null || true
	done
	reboot_stream_pid=
	reboot_seq_pid=
	stop_console
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
	if [ -n "$scsi_lun_id" ]; then
		ctladm remove -b ramdisk -l "$scsi_lun_id" >/dev/null ||
		    echo "warning: failed to remove CTL LUN $scsi_lun_id" >&2
		scsi_lun_id=
	fi
	ifconfig "$BRIDGE" deletem "$tap" >/dev/null 2>&1 || true
	ifconfig "$tap" destroy >/dev/null 2>&1 || true
	[ "$bridge_created" = no ] || ifconfig "$BRIDGE" destroy >/dev/null 2>&1 || true
}
report_failure()
{
	echo "==== retained failure diagnostics ====" >&2
	for item in "bhyve:$bhyve_log" "input-provider:$input_log" \
	    "scsi-create:$scsi_create_log" \
	    "console-exchange:$console_exchange_log" \
	    "reboot-stream:$reboot_stream_log" "reboot-seq:$reboot_seq_log" \
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

if [ "$run_scsi_device" = yes ]; then
	scsi_create_log="$WORKDIR/scsi-create.log"
	scsi_size_bytes=$((SCSI_IMAGE_MB * 1024 * 1024 + ($$ % 8192) * 512))
	# A ramdisk without capacity is CTL's intentionally fake backend: it
	# discards writes and returns zeroes.  Back the full advertised LUN so
	# the guest test verifies real data persistence.
	ctladm create -b ramdisk -s "$scsi_size_bytes" \
	    -o "capacity=$scsi_size_bytes" > "$scsi_create_log"
	scsi_lun_id=$(awk '/^LUN ID:/ {print $NF}' "$scsi_create_log")
	case "$scsi_lun_id" in
	''|*[!0-9]*) echo "invalid CTL LUN ID: $scsi_lun_id" >&2; exit 1 ;;
	esac
	[ "$scsi_lun_id" -le 16383 ] || {
		echo "CTL LUN ID exceeds virtio-scsi limit: $scsi_lun_id" >&2
		exit 1
	}
	grep -q '^LUN created successfully$' "$scsi_create_log"
fi

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

wait_for_login()
{
	limit=$1
	i=0
	while [ "$i" -lt "$limit" ]; do
		grep -q 'login:' "$console_log" 2>/dev/null && return 0
		# A TCP console attached after boot misses the getty's first prompt.
		# A carriage return asks getty to print a fresh one; repeat in case
		# the first write races the new monitor child accepting the socket.
		[ $((i % 5)) -ne 0 ] || printf '\r' >> "$console_input"
		kill -0 "$vm_pid" 2>/dev/null || {
			echo "bhyve exited while waiting for the guest login" >&2
			return 1
		}
		sleep 1
		i=$((i + 1))
	done
	echo "timed out waiting for console pattern: login:" >&2
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
	    -s 0,hostbridge -s "3,ahci-cd,$ISO" \
	    -s "4,virtio-net,$tap$net_transport_opt"
	[ "$VIRTIO_MSIX" = yes ] || set -- "$@" -W
	[ "$REBOOT_TEST" = no ] || set -- "$@" -M
	[ "$run_vsock" = no ] || set -- "$@" \
	    -s "5,virtio-vsock,cid=$CID$vsock_backend_opt$vsock_transport_opt"
	[ "$run_input_device" = no ] || set -- "$@" \
	    -s "6,virtio-input,$input_path$input_transport_opt"
	[ "$run_rng_device" = no ] || set -- "$@" \
	    -s "7,virtio-rnd$rng_transport_opt"
	[ "$run_block_device" = no ] || set -- "$@" \
	    -s "8,virtio-blk,$block_image$block_transport_opt"
	[ "$run_scsi_device" = no ] || set -- "$@" \
	    -s "9,virtio-scsi,/dev/cam/ctl$scsi_transport_opt"
	[ "$run_console_device" = no ] || set -- "$@" \
	    -s "10,virtio-console,$console_name=$console_socket$console_transport_opt"
	[ "$run_9p_device" = no ] || set -- "$@" \
	    -s "11,virtio-9p,$ninep_tag=$ninep_share$ninep_transport_opt"
	set -- "$@" -s 31,lpc -l "com1,tcp=127.0.0.1:$CONSOLE_PORT" \
	    -l "bootrom,$UEFI" "$vmname"
	env BHYVE_VTVSOCK_DEBUG="$VSOCK_DEBUG" \
	    BHYVE_VTINPUT_DEBUG="$INPUT_DEBUG" \
	    BHYVE_VTSCSI_DEBUG="$SCSI_DEBUG" "$@" \
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
	wait_for_login 120
	printf 'root\r' >> "$console_input"
	sleep 2
	guest_cmd 'set -eu; ip link set eth0 up; udhcpc -n -q -t 5 -T 3 -i eth0; release=$(cut -d. -f1,2 /etc/alpine-release); case "$release" in *.*) ;; *) echo "invalid Alpine release: $release" >&2; exit 1;; esac; major=${release%.*}; minor=${release#*.}; case "$major:$minor" in *[!0-9:]*|:|*:) echo "invalid Alpine release: $release" >&2; exit 1;; esac; repository="https://dl-cdn.alpinelinux.org/alpine/v${release}/main"; printf "%s\n" "$repository" > /etc/apk/repositories; apk add --no-cache python3; printf "PROVISION alpine=%s repository=%s " "$(cat /etc/alpine-release)" "$repository"; python3 --version' 150
	copy_guest_file "$here/gnet.py" /tmp/gnet.py
	guest_cmd 'python3 /tmp/gnet.py --self-test | grep -q "^SELFTEST PASS$"' 30
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
	if [ "$run_block_device" = yes ]; then
		guest_cmd 'modprobe virtio_blk' 30
		copy_guest_file "$here/gblock.py" /tmp/gblock.py
		guest_cmd 'python3 /tmp/gblock.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_scsi_device" = yes ]; then
		guest_cmd 'modprobe virtio_scsi' 30
		copy_guest_file "$here/gscsi.py" /tmp/gscsi.py
		guest_cmd 'python3 /tmp/gscsi.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_console_device" = yes ]; then
		guest_cmd 'modprobe virtio_console' 30
		copy_guest_file "$here/gconsole.py" /tmp/gconsole.py
		guest_cmd 'python3 /tmp/gconsole.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
	if [ "$run_9p_device" = yes ]; then
		guest_cmd 'modprobe 9p; modprobe 9pnet; modprobe 9pnet_virtio' 30
		copy_guest_file "$here/g9p.py" /tmp/g9p.py
		guest_cmd 'python3 /tmp/g9p.py --self-test | grep -q "^SELFTEST PASS$"' 30
	fi
}

run_matrix()
{
	DIR=$sockdir TRANSPORT=$transport VSOCK_BACKEND=$VSOCK_BACKEND \
	BACKEND=$VSOCK_BACKEND GUEST_CID=$CID GPY=/tmp/gvsock.py \
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

run_block()
{
	block_bytes=$((BLOCK_TEST_MB * 1024 * 1024))
	output=$(guest_cmd "python3 /tmp/gblock.py write '$transport' '$block_bytes'" 180) || {
		status=$?
		echo "guest virtio-blk verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	block_sha256=$(printf '%s\n' "$output" |
	    sed -n 's/^PASS block bytes=[0-9][0-9]* sha256=\([0-9a-f][0-9a-f]*\) device=.*/\1/p')
	[ "${#block_sha256}" -eq 64 ]
}

verify_block()
{
	output=$(guest_cmd "python3 /tmp/gblock.py verify '$transport' '$block_bytes' '$block_sha256'" 120) || {
		status=$?
		echo "post-lifecycle virtio-blk verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	printf '%s\n' "$output" | grep -q '^PASS block-persist bytes='
}

run_scsi()
{
	scsi_bytes=$((SCSI_TEST_MB * 1024 * 1024))
	output=$(guest_cmd "python3 /tmp/gscsi.py write '$transport' '$scsi_size_bytes' '$scsi_bytes'" 120) || {
		status=$?
		echo "guest virtio-scsi verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	scsi_sha256=$(printf '%s\n' "$output" |
	    sed -n 's/^PASS scsi bytes=[0-9][0-9]* sha256=\([0-9a-f][0-9a-f]*\) device=.*/\1/p')
	[ "${#scsi_sha256}" -eq 64 ]
}

verify_scsi()
{
	output=$(guest_cmd "python3 /tmp/gscsi.py verify '$transport' '$scsi_size_bytes' '$scsi_bytes' '$scsi_sha256'" 120) || {
		status=$?
		echo "post-lifecycle virtio-scsi verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	printf '%s\n' "$output" | grep -q '^PASS scsi-persist bytes='
}

run_console()
{
	host_token="host-$transport-$$"
	guest_token="guest-$transport-$$"
	console_exchange_log="$WORKDIR/$transport.console-exchange.log"
	guest_cmd "i=0; until python3 /tmp/gconsole.py check '$transport' '$console_name'; do i=\$((i + 1)); [ \"\$i\" -lt 20 ]; sleep 1; done" 30
	i=0
	while [ ! -S "$console_socket" ] && [ "$i" -lt 20 ]; do
		sleep 1
		i=$((i + 1))
	done
	[ -S "$console_socket" ] || {
		echo "virtio-console host socket did not appear: $console_socket" >&2
		return 1
	}
	: > "$console_exchange_log"
	# Do not send until the guest has opened the port and sent its token.
	# The port node can exist before the virtio PORT_READY handshake, and bytes
	# written in that interval are allowed to be discarded by the backend.
	( { i=0; until grep -q "$guest_token" "$console_exchange_log" 2>/dev/null; do
	        [ "$i" -lt 20 ] || exit 1
	        sleep 1
	        i=$((i + 1))
	    done
	    printf '%s' "$host_token"
	    sleep 30
	  } |
	    timeout 35 "$tools/unix-pipe" "$console_socket" > "$console_exchange_log" ) &
	console_exchange_pid=$!
	guest_cmd "python3 /tmp/gconsole.py exchange '$transport' '$console_name' '$host_token' '$guest_token'" 30
	i=0
	while ! grep -q "^$guest_token$" "$console_exchange_log" 2>/dev/null; do
		kill -0 "$console_exchange_pid" 2>/dev/null || {
			echo "virtio-console host exchange exited early" >&2
			return 1
		}
		[ "$i" -lt 20 ] || {
			echo "timed out waiting for virtio-console guest payload" >&2
			return 1
		}
		sleep 1
		i=$((i + 1))
	done
	pkill -TERM -P "$console_exchange_pid" 2>/dev/null || true
	kill "$console_exchange_pid" 2>/dev/null || true
	wait "$console_exchange_pid" 2>/dev/null || true
	console_exchange_pid=
	sleep 1
	echo "PASS console bidirectional transport=$transport name=$console_name"
}

run_9p()
{
	mountpoint=/mnt/bhyve-9p
	guest_token="guest-9p-$transport-$$"
	host_token="host-9p-$transport-$$"
	guest_cmd "python3 /tmp/g9p.py '$transport'" 30
	guest_cmd "set -eu; mkdir -p '$mountpoint'; grep -qs ' $mountpoint ' /proc/mounts || mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 '$ninep_tag' '$mountpoint'; [ \"\$(cat '$mountpoint/host-seed')\" = '$ninep_seed' ]; printf %s '$guest_token' > '$mountpoint/guest-to-host'; sync" 45
	[ "$(cat "$ninep_share/guest-to-host")" = "$guest_token" ]
	printf %s "$host_token" > "$ninep_share/host-to-guest"
	guest_cmd "[ \"\$(cat '$mountpoint/host-to-guest')\" = '$host_token' ]" 30
	echo "PASS 9p bidirectional transport=$transport tag=$ninep_tag"
}

run_vsock_smoke()
{
	DIR=$sockdir TRANSPORT=$transport GPY=/tmp/gvsock.py \
	TOOLS="$tools" SMOKE_ONLY=yes \
	HOST_WORK="$WORKDIR/$transport.lifecycle.host" \
	BHYVE_LOG="$bhyve_log" CONSOLE_LOG_PATH="$console_log" \
	ACMD="env CONSOLE_LOG=$console_log CONSOLE_INPUT=$console_input sh $here/acmd-console.sh" \
	    sh "$here/run-linux.sh"
}

run_network_smoke()
{
	output=$(guest_cmd "python3 /tmp/gnet.py '$transport'" 30) || {
		status=$?
		echo "guest virtio-net verification failed (status $status)" >&2
		[ -z "$output" ] || printf '%s\n' "$output" >&2
		return "$status"
	}
	printf '%s\n' "$output"
	printf '%s\n' "$output" | grep -q '^PASS net interface=eth0 '
	guest_cmd 'set -eu; ip link set eth0 up; udhcpc -n -q -t 5 -T 3 -i eth0; gateway=$(ip route | awk '\''/^default/{print $3; exit}'\''); [ -n "$gateway" ]; ping -c 3 -W 2 "$gateway"; echo "PASS network gateway=$gateway"' 45
}

verify_no_msix()
{
	[ "$VIRTIO_MSIX" = no ] || return 0
	guest_cmd "set -eu; for bdf in $virtio_bdfs; do d=/sys/bus/pci/devices/\$bdf; [ -d \"\$d\" ]; vectors=0; [ ! -d \"\$d/msi_irqs\" ] || vectors=\$(find \"\$d/msi_irqs\" -mindepth 1 -maxdepth 1 | wc -l); [ \"\$vectors\" -le 1 ]; irq=\$(cat \"\$d/irq\"); line=\$(grep \"^ *\$irq:\" /proc/interrupts); case \"\$line\" in *MSI-X*) exit 1;; esac; printf 'PASS no-msix bdf=%s irq=%s vectors=%s\\n' \"\$bdf\" \"\$irq\" \"\$vectors\"; done" 30
}

reset_devices()
{
	echo "== Alpine $transport: reset and rebind virtio devices =="
	[ "$run_9p_device" = no ] || guest_cmd 'umount /mnt/bhyve-9p' 30
	guest_cmd "set -eu; for bdf in $virtio_bdfs; do echo \"reset \$bdf\"; echo \"\$bdf\" > /sys/bus/pci/drivers/virtio-pci/unbind; sleep 1; echo \"\$bdf\" > /sys/bus/pci/drivers/virtio-pci/bind; sleep 1; done" 90
	run_lifecycle_smokes
}

run_lifecycle_smokes()
{
	run_network_smoke
	verify_no_msix
	[ "$run_vsock" = no ] || run_vsock_smoke
	[ "$run_rng_device" = no ] || run_rng
	[ "$run_block_device" = no ] || verify_block
	[ "$run_scsi_device" = no ] || verify_scsi
	[ "$run_console_device" = no ] || run_console
	[ "$run_9p_device" = no ] || run_9p
}

reboot_hold_connector()
{
	type=$1
	port=$2
	log=$3
	shift 3
	attempt=0
	while [ "$attempt" -lt 5 ]; do
		if timeout 180 "$tools/vsh-connect" "$@" -w \
		    "$sockdir" "$port" > "$log" 2>&1; then
			return 0
		else
			status=$?
		fi
		# Retry only the explicit guest-not-ready control response, and only
		# before the helper has proved an established connection.
		[ "$status" -eq 4 ] && ! grep -q '^READY$' "$log" || return "$status"
		attempt=$((attempt + 1))
		sleep 1
	done
	echo "$type lifecycle connector exhausted readiness retries" >> "$log"
	return 4
}

start_reboot_vsock_holds()
{
	echo "== Alpine $transport: establish live vsock reboot endpoints =="
	reboot_stream_log="$WORKDIR/$transport.reboot-stream.log"
	reboot_seq_log="$WORKDIR/$transport.reboot-seq.log"
	: > "$reboot_stream_log"
	: > "$reboot_seq_log"
	guest_cmd "set -eu; pkill -9 python3 2>/dev/null || true; rm -f /tmp/reboot-stream.out /tmp/reboot-seq.out; nohup python3 /tmp/gvsock.py echo-l stream 7011 >/tmp/reboot-stream.out 2>&1 & nohup python3 /tmp/gvsock.py echo-l seq 7012 >/tmp/reboot-seq.out 2>&1 & i=0; while { ! grep -q '^up$' /tmp/reboot-stream.out 2>/dev/null || ! grep -q '^up$' /tmp/reboot-seq.out 2>/dev/null; } && [ \"\$i\" -lt 15 ]; do sleep 1; i=\$((i + 1)); done; grep -q '^up$' /tmp/reboot-stream.out; grep -q '^up$' /tmp/reboot-seq.out" 20 >/dev/null
	reboot_hold_connector stream 7011 "$reboot_stream_log" &
	reboot_stream_pid=$!
	reboot_hold_connector seq 7012 "$reboot_seq_log" -s &
	reboot_seq_pid=$!

	i=0
	while { ! grep -q '^READY$' "$reboot_stream_log" 2>/dev/null ||
	    ! grep -q '^READY$' "$reboot_seq_log" 2>/dev/null; }; do
		kill -0 "$reboot_stream_pid" 2>/dev/null || {
			cat "$reboot_stream_log" >&2
			return 1
		}
		kill -0 "$reboot_seq_pid" 2>/dev/null || {
			cat "$reboot_seq_log" >&2
			return 1
		}
		[ "$i" -lt 30 ] || {
			echo "timed out establishing reboot lifecycle endpoints" >&2
			return 1
		}
		sleep 1
		i=$((i + 1))
	done
	# READY must describe endpoints that are still open, not helpers that
	# connected and immediately observed an unrelated close.
	kill -0 "$reboot_stream_pid" 2>/dev/null
	kill -0 "$reboot_seq_pid" 2>/dev/null
	echo "PASS live reboot endpoints stream=7011 seq=7012"
}

verify_reboot_vsock_disconnects()
{
	i=0
	while { ! grep -q '^DISCONNECTED$' "$reboot_stream_log" 2>/dev/null ||
	    ! grep -q '^DISCONNECTED$' "$reboot_seq_log" 2>/dev/null; } &&
	    [ "$i" -lt 30 ]; do
		kill -0 "$reboot_stream_pid" 2>/dev/null || {
			cat "$reboot_stream_log" >&2
			return 1
		}
		kill -0 "$reboot_seq_pid" 2>/dev/null || {
			cat "$reboot_seq_log" >&2
			return 1
		}
		sleep 1
		i=$((i + 1))
	done
	[ "$i" -lt 30 ] || {
		echo "old vsock endpoints survived guest reboot for 30s" >&2
		return 1
	}
	stream_status=0
	wait "$reboot_stream_pid" || stream_status=$?
	seq_status=0
	wait "$reboot_seq_pid" || seq_status=$?
	reboot_stream_pid=
	reboot_seq_pid=
	[ "$stream_status" -eq 0 ] && [ "$seq_status" -eq 0 ] &&
	    grep -q '^READY$' "$reboot_stream_log" &&
	    grep -q '^DISCONNECTED$' "$reboot_stream_log" &&
	    grep -q '^READY$' "$reboot_seq_log" &&
	    grep -q '^DISCONNECTED$' "$reboot_seq_log" || {
		echo "vsock reboot disconnect verification failed: stream=$stream_status seq=$seq_status" >&2
		cat "$reboot_stream_log" >&2
		cat "$reboot_seq_log" >&2
		return 1
	}
	echo "PASS reboot disconnected established stream and seqpacket endpoints"
}

reboot_guest()
{
	echo "== Alpine $transport: monitor-mode reboot =="
	old_boot_id=$(guest_cmd 'cat /proc/sys/kernel/random/boot_id' 15)
	negotiations=0
	[ "$run_vsock" = no ] || negotiations=$(grep -c 'negotiated features=' "$bhyve_log" 2>/dev/null || true)
	[ "$run_vsock" = no ] || start_reboot_vsock_holds
	printf 'sync; reboot -f\r' >> "$console_input"

	i=0
	if [ "$run_vsock" = yes ]; then
		while [ "$i" -lt 120 ]; do
			current=$(grep -c 'negotiated features=' "$bhyve_log" 2>/dev/null || true)
			[ "$current" -gt "$negotiations" ] && break
			kill -0 "$vm_pid" 2>/dev/null || {
				echo "bhyve monitor exited during guest reboot" >&2
				return 1
			}
			sleep 1
			i=$((i + 1))
		done
		[ "$i" -lt 120 ] || { echo "timed out waiting for bhyve monitor restart" >&2; return 1; }
	else
		sleep 8
		kill -0 "$vm_pid" 2>/dev/null || { echo "bhyve monitor exited during guest reboot" >&2; return 1; }
	fi
	[ "$run_vsock" = no ] || verify_reboot_vsock_disconnects

	stop_console
	start_console
	wait_for_login 120
	printf 'root\r' >> "$console_input"
	sleep 2
	new_boot_id=$(guest_cmd 'cat /proc/sys/kernel/random/boot_id' 15)
	[ -n "$old_boot_id" ] && [ -n "$new_boot_id" ] &&
	    [ "$old_boot_id" != "$new_boot_id" ] || {
		echo "guest boot ID did not change across reboot" >&2
		return 1
	}
	echo "PASS reboot old_boot_id=$old_boot_id new_boot_id=$new_boot_id"
	provision_guest
	run_lifecycle_smokes
}

for transport in $TRANSPORTS; do
	vmname="alpine-virtio-${transport}-$$"
	sockdir="$WORKDIR/$transport"
	console_input="$WORKDIR/$transport.console.in"
	console_log="$WORKDIR/$transport.console.log"
	bhyve_log="$WORKDIR/$transport.bhyve.log"
	block_image="$WORKDIR/$transport.block.img"
	input_fifo="$WORKDIR/$transport.input.fifo"
	input_path_file="$WORKDIR/$transport.input.path"
	input_log="$WORKDIR/$transport.input.log"
	input_name="bhyve-e2e-input-$transport-$$"
	console_socket="$WORKDIR/$transport.virtio-console.sock"
	console_name="bhyve-e2e-console-$transport-$$"
	ninep_share="$WORKDIR/$transport.9p-share"
	ninep_tag="bhyve-e2e-9p-$transport-$$"
	ninep_seed="seed-9p-$transport-$$"
	if [ "$transport" = modern ]; then
		net_transport_opt=",transport=modern"
		vsock_transport_opt=",transport=modern"
		input_transport_opt=",transport=modern"
		rng_transport_opt=",transport=modern"
		block_transport_opt=",transport=modern"
		scsi_transport_opt=",transport=modern"
		console_transport_opt=",transport=modern"
		ninep_transport_opt=",transport=modern"
	else
		# Deliberately omit the option to exercise the compatibility default.
		net_transport_opt=
		vsock_transport_opt=
		rng_transport_opt=
		block_transport_opt=
		scsi_transport_opt=
		console_transport_opt=
		ninep_transport_opt=
	fi
	if [ "$VSOCK_BACKEND" = native ]; then
		vsock_backend_opt=",backend=native"
	else
		vsock_backend_opt=",path=$sockdir"
	fi
	virtio_bdfs="0000:00:04.0"
	[ "$run_vsock" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:05.0"
	[ "$run_input_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:06.0"
	[ "$run_rng_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:07.0"
	[ "$run_block_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:08.0"
	[ "$run_scsi_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:09.0"
	[ "$run_console_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:0a.0"
	[ "$run_9p_device" = no ] || virtio_bdfs="$virtio_bdfs 0000:00:0b.0"
	mkdir -p "$sockdir"
	chmod 0700 "$sockdir"
	rm -f "$sockdir/sock"
	[ "$run_console_device" = no ] || rm -f "$console_socket"
	if [ "$run_9p_device" = yes ]; then
		mkdir -p -m 0700 "$ninep_share"
		chmod 0700 "$ninep_share"
		rm -f "$ninep_share/host-seed" \
		    "$ninep_share/guest-to-host" "$ninep_share/host-to-guest"
		printf %s "$ninep_seed" > "$ninep_share/host-seed"
	fi
	: > "$bhyve_log"
	if [ "$run_block_device" = yes ]; then
		truncate -s "${BLOCK_IMAGE_MB}M" "$block_image"
		chmod 0600 "$block_image"
	fi
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
	run_network_smoke
	[ "$run_vsock" = no ] || run_matrix
	[ "$run_rng_device" = no ] || run_rng
	[ "$run_input_device" = no ] || run_input
	[ "$run_block_device" = no ] || run_block
	[ "$run_scsi_device" = no ] || run_scsi
	[ "$run_console_device" = no ] || run_console
	[ "$run_9p_device" = no ] || run_9p
	verify_no_msix
	[ "$RESET_TEST" = no ] || reset_devices
	[ "$REBOOT_TEST" = no ] || reboot_guest

	cleanup_vm
done

echo "Alpine transport automation completed successfully"
