#!/bin/sh
# Root-only, disposable Alpine ISO test: boot, provision over the serial
# console, and run the modern/legacy matrix.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
ISO=${ISO:?set ISO to an Alpine virt ISO}
BHYVE=${BHYVE:-/usr/obj/usr/src/$(uname -p).$(uname -p)/usr.sbin/bhyve/bhyve}
UEFI=${UEFI:-/usr/local/share/uefi-firmware/BHYVE_UEFI.fd}
WORKDIR=${WORKDIR:-/tmp/bhyve-vsock-alpine}
TRANSPORTS=${TRANSPORTS:-"modern legacy"}
CID=${CID:-4}
CONSOLE_PORT=${CONSOLE_PORT:-}
KEEP_VM=${KEEP_VM:-no}

[ "$(id -u)" -eq 0 ] || { echo "run-alpine-auto.sh must run as root" >&2; exit 1; }
[ -f "$ISO" ] || { echo "ISO not found: $ISO" >&2; exit 1; }
[ -x "$BHYVE" ] || { echo "bhyve not found: $BHYVE" >&2; exit 1; }
[ -f "$UEFI" ] || { echo "UEFI firmware not found: $UEFI" >&2; exit 1; }

[ ! -L "$WORKDIR" ] || {
	echo "WORKDIR must not be a symbolic link: $WORKDIR" >&2
	exit 1
}
mkdir -p -m 0700 "$WORKDIR"
chmod 0700 "$WORKDIR"
make -C "$here"
kldload -n vmm
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
vmname=
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
}
cleanup_all()
{
	[ "$KEEP_VM" = yes ] || cleanup_vm
	ifconfig bridge0 deletem "$tap" >/dev/null 2>&1 || true
	ifconfig "$tap" destroy >/dev/null 2>&1 || true
	[ "$bridge_created" = no ] || ifconfig bridge0 destroy >/dev/null 2>&1 || true
}
trap cleanup_all EXIT INT TERM

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
	"$BHYVE" -c 2 -m 2G -H -w \
	    -s 0,hostbridge -s "3,ahci-cd,$ISO" -s "4,virtio-net,$tap" \
	    -s "5,virtio-vsock,cid=$CID,path=$sockdir,transport=$transport" \
	    -s 31,lpc -l "com1,tcp=127.0.0.1:$CONSOLE_PORT" \
	    -l "bootrom,$UEFI" "$vmname" >> "$bhyve_log" 2>&1 &
	vm_pid=$!
	start_console
}

guest_cmd()
{
	CONSOLE_LOG=$console_log CONSOLE_INPUT=$console_input \
	    sh "$here/acmd-console.sh" "$1" "${2:-30}"
}

provision_guest()
{
	wait_for 'login:' 120
	printf 'root\r' >> "$console_input"
	sleep 2
	guest_cmd 'ip link set eth0 up; udhcpc -i eth0; printf "https://dl-cdn.alpinelinux.org/alpine/latest-stable/main\n" > /etc/apk/repositories; apk add --no-cache python3; modprobe vsock; modprobe vmw_vsock_virtio_transport' 120
	payload=$(base64 < "$here/gvsock.py" | tr -d '\n')
	guest_cmd "printf %s '$payload' | base64 -d > /tmp/gvsock.py" 30
}

run_matrix()
{
	DIR=$sockdir TRANSPORT=$transport GPY=/tmp/gvsock.py \
	HOST_WORK="$WORKDIR/$transport.host" \
	ACMD="env CONSOLE_LOG=$console_log CONSOLE_INPUT=$console_input sh $here/acmd-console.sh" \
	    sh "$here/run-linux.sh"
}

for transport in $TRANSPORTS; do
	case "$transport" in modern|legacy) ;; *) echo "invalid transport: $transport" >&2; exit 2;; esac
	vmname="alpine-vsock-${transport}-$$"
	sockdir="$WORKDIR/$transport"
	console_input="$WORKDIR/$transport.console.in"
	console_log="$WORKDIR/$transport.console.log"
	bhyve_log="$WORKDIR/$transport.bhyve.log"
	mkdir -p "$sockdir"
	chmod 0700 "$sockdir"
	rm -f "$sockdir/sock"
	: > "$bhyve_log"

	echo "== Alpine $transport: boot and test =="
	launch_vm
	provision_guest
	run_matrix

	cleanup_vm
done

echo "Alpine modern/legacy automation completed successfully"
