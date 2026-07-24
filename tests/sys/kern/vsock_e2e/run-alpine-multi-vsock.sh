#!/bin/sh
# Run two complete kernel-backed VirtIO-vsock guests concurrently.  Each VM
# uses a distinct CID, console endpoint, work directory, and AF_VSOCK port
# range.  Both exercise reset/rebind while the other provider remains active.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
ISO=${ISO:?set ISO to an Alpine virt ISO}
WORKDIR=${WORKDIR:-/tmp/bhyve-vsock-multi}
TRANSPORT=${TRANSPORT:-modern}
CID1=${CID1:-40}
CID2=${CID2:-41}
PORT_OFFSET1=${PORT_OFFSET1:-0}
PORT_OFFSET2=${PORT_OFFSET2:-1000}
CONSOLE_PORT1=${CONSOLE_PORT1:-4480}
CONSOLE_PORT2=${CONSOLE_PORT2:-4481}
BRIDGE=${BRIDGE:-bridge0}
UPLINK=${UPLINK:-}

[ "$(id -u)" -eq 0 ] || {
	echo "run-alpine-multi-vsock.sh must run as root" >&2
	exit 1
}
[ -c /dev/vsock ] || {
	echo "kernel-backed multi-VM testing requires /dev/vsock" >&2
	exit 1
}
case "$TRANSPORT" in
modern|legacy) ;;
*) echo "TRANSPORT must be modern or legacy" >&2; exit 2 ;;
esac
for value in "$CID1" "$CID2" "$PORT_OFFSET1" "$PORT_OFFSET2" \
    "$CONSOLE_PORT1" "$CONSOLE_PORT2"; do
	case "$value" in
	''|*[!0-9]*) echo "CIDs, offsets, and console ports must be numeric" >&2; exit 2 ;;
	esac
done
[ "$CID1" -ge 3 ] && [ "$CID2" -ge 3 ] && [ "$CID1" -ne "$CID2" ] || {
	echo "CID1 and CID2 must be distinct non-reserved CIDs" >&2
	exit 2
}
[ "$CID1" -le 4294967294 ] && [ "$CID2" -le 4294967294 ] || {
	echo "CID1 and CID2 must fit in the 32-bit guest CID field" >&2
	exit 2
}
if [ "$PORT_OFFSET1" -gt "$PORT_OFFSET2" ]; then
	port_gap=$((PORT_OFFSET1 - PORT_OFFSET2))
else
	port_gap=$((PORT_OFFSET2 - PORT_OFFSET1))
fi
[ "$port_gap" -ge 300 ] || {
	echo "PORT_OFFSET1 and PORT_OFFSET2 must differ by at least 300" >&2
	exit 2
}
[ "$CONSOLE_PORT1" -ne "$CONSOLE_PORT2" ] || {
	echo "CONSOLE_PORT1 and CONSOLE_PORT2 must differ" >&2
	exit 2
}
for port in "$CONSOLE_PORT1" "$CONSOLE_PORT2"; do
	[ "$port" -gt 0 ] && [ "$port" -le 65535 ] || {
		echo "console ports must be in 1..65535" >&2
		exit 2
	}
	if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
		echo "console port $port is already in use" >&2
		exit 1
	fi
done

[ ! -L "$WORKDIR" ] || {
	echo "WORKDIR must not be a symbolic link: $WORKDIR" >&2
	exit 1
}
mkdir -p -m 0700 "$WORKDIR"
[ "$(stat -f %u "$WORKDIR")" -eq 0 ] || {
	echo "WORKDIR must be owned by root: $WORKDIR" >&2
	exit 1
}
chmod 0700 "$WORKDIR"
barrier_dir="$WORKDIR/provider-barrier"
[ ! -L "$barrier_dir" ] || {
	echo "provider barrier must not be a symbolic link: $barrier_dir" >&2
	exit 1
}
mkdir -p -m 0700 "$barrier_dir"
chmod 0700 "$barrier_dir"
rm -f "$barrier_dir/cid-$CID1" "$barrier_dir/cid-$CID2"

if [ -f "$here/Makefile" ]; then
	make -C "$here"
	TOOLS=${TOOLS:-$(make -C "$here" -V .OBJDIR)}
else
	TOOLS=${TOOLS:-$here}
fi

bridge_created=no
if ! ifconfig "$BRIDGE" >/dev/null 2>&1; then
	ifconfig "$BRIDGE" create
	bridge_created=yes
	nic=$UPLINK
	[ -n "$nic" ] ||
	    nic=$(route -n get default 2>/dev/null |
	    awk '/interface:/{print $2}')
	[ -z "$nic" ] || ifconfig "$BRIDGE" addm "$nic"
	ifconfig "$BRIDGE" up
fi

pid1=
pid2=
cleanup()
{
	for pid in "$pid1" "$pid2"; do
		[ -z "$pid" ] || kill "$pid" 2>/dev/null || true
	done
	for pid in "$pid1" "$pid2"; do
		[ -z "$pid" ] || wait "$pid" 2>/dev/null || true
	done
	if [ "$bridge_created" = yes ]; then
		ifconfig "$BRIDGE" destroy >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT INT TERM HUP

run_one()
{
	cid=$1
	offset=$2
	console=$3
	name=$4

	env ISO="$ISO" TOOLS="$TOOLS" TRANSPORTS="$TRANSPORT" \
	    DEVICES=vsock VSOCK_BACKEND=kernel CID="$cid" \
	    PORT_OFFSET="$offset" CONSOLE_PORT="$console" \
	    VSOCK_BARRIER_DIR="$barrier_dir" \
	    VSOCK_BARRIER_CIDS="$CID1 $CID2" \
	    RESET_TEST=yes REBOOT_TEST=no BRIDGE="$BRIDGE" \
	    WORKDIR="$WORKDIR/$name" \
	    sh "$here/run-alpine-auto.sh"
}

echo "Starting concurrent kernel VSOCK guests CID $CID1 and CID $CID2"
run_one "$CID1" "$PORT_OFFSET1" "$CONSOLE_PORT1" cid1 \
    >"$WORKDIR/cid1.log" 2>&1 &
pid1=$!
run_one "$CID2" "$PORT_OFFSET2" "$CONSOLE_PORT2" cid2 \
    >"$WORKDIR/cid2.log" 2>&1 &
pid2=$!

status1=0
status2=0
wait "$pid1" || status1=$?
pid1=
wait "$pid2" || status2=$?
pid2=
if [ "$status1" -ne 0 ] || [ "$status2" -ne 0 ]; then
	echo "multi-provider gate failed: CID1=$status1 CID2=$status2" >&2
	for name in cid1 cid2; do
		echo "---- $name, last 100 lines ----" >&2
		tail -n 100 "$WORKDIR/$name.log" >&2 || true
	done
	exit 1
fi

providers=$(sysctl -n kern.vsock.userspace_providers)
[ "$providers" -eq 0 ] || {
	echo "provider count leaked after test: $providers" >&2
	exit 1
}
echo "PASS concurrent kernel VSOCK guests CID $CID1 and CID $CID2"
