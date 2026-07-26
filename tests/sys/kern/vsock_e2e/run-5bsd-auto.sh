#!/bin/sh
# Clone an existing 5BSD test image and run the complete vsock matrix against
# opt-in modern and default (option omitted) legacy VirtIO PCI transports.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
IMAGE=${IMAGE:?set IMAGE to a 5BSD raw disk base image}
BHYVE=${BHYVE:-}
BHYVELOAD=${BHYVELOAD:-$(command -v bhyveload 2>/dev/null || true)}
BHYVECTL=${BHYVECTL:-$(command -v bhyvectl 2>/dev/null || true)}
SRCTOP=${SRCTOP:-$(cd "$here/../../../.." && pwd)}
OBJROOT=${OBJROOT:-/usr/obj}
WORKDIR=${WORKDIR:-/tmp/bhyve-vsock-5bsd}
TRANSPORTS=${TRANSPORTS:-"modern legacy"}
CID=${CID:-3}
CONSOLE_PORT=${CONSOLE_PORT:-}
BULK_MB=${BULK_MB:-256}
KEEP_VM=${KEEP_VM:-no}
VM_FREE_GATES=${VM_FREE_GATES:-yes}

if [ -z "$BHYVE" ]; then
	object_bhyve="$OBJROOT$SRCTOP/$(uname -p).$(uname -p)/usr.sbin/bhyve/bhyve"
	if [ -x "$object_bhyve" ]; then
		BHYVE=$object_bhyve
	else
		BHYVE=$(command -v bhyve 2>/dev/null || true)
	fi
fi

[ "$(id -u)" -eq 0 ] || {
	echo "run-5bsd-auto.sh must run as root" >&2
	exit 1
}
[ -f "$IMAGE" ] || { echo "5BSD image not found: $IMAGE" >&2; exit 1; }
[ -x "$BHYVE" ] || { echo "bhyve not found: $BHYVE" >&2; exit 1; }
[ -x "$BHYVELOAD" ] || { echo "bhyveload not found: $BHYVELOAD" >&2; exit 1; }
[ -x "$BHYVECTL" ] || { echo "bhyvectl not found: $BHYVECTL" >&2; exit 1; }
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

# A raw image must never be attached writable to two guests at once.  Refuse
# instead of stopping a VM the caller may still be using.
if pgrep -f "bhyve.*virtio-blk,$IMAGE" >/dev/null 2>&1; then
	echo "another bhyve process is already using $IMAGE" >&2
	echo "stop that VM before running this writable-image test" >&2
	exit 1
fi

prepare_workdir "$WORKDIR"
if [ -f "$here/Makefile" ]; then
	case "$VM_FREE_GATES" in
	yes) make -C "$here" ;;
	no) ;;
	*) echo "VM_FREE_GATES must be yes or no" >&2; exit 2 ;;
	esac
	tools=${TOOLS:-$(make -C "$here" -V .OBJDIR)}
else
	tools=${TOOLS:-$here}
fi
for tool in unix-pipe vsh-connect vsh-connect-test-server uinput-inject; do
	[ -x "$tools/$tool" ] || {
		echo "built helper not found: $tools/$tool" >&2
		exit 1
	}
done
[ "$VM_FREE_GATES" = no ] ||
    TOOLS="$tools" sh "$here/host-tools-selftest.sh"
kldload -n vmm

if [ -z "$CONSOLE_PORT" ]; then
	CONSOLE_PORT=4500
	while nc -z 127.0.0.1 "$CONSOLE_PORT" >/dev/null 2>&1; do
		CONSOLE_PORT=$((CONSOLE_PORT + 1))
		[ "$CONSOLE_PORT" -lt 4600 ] || {
			echo "no free TCP console port in 4500..4599" >&2
			exit 1
		}
	done
fi

vm_pid=
console_pid=
vmname=
image_md=
cleanup_vm()
{
	[ -z "$console_pid" ] || pkill -TERM -P "$console_pid" 2>/dev/null || true
	[ -z "$console_pid" ] || kill "$console_pid" 2>/dev/null || true
	[ -z "$console_pid" ] || wait "$console_pid" 2>/dev/null || true
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
	[ -z "$vmname" ] || "$BHYVECTL" --vm="$vmname" --destroy \
	    >/dev/null 2>&1 || true
	if [ -n "$image_md" ]; then
		mdconfig -d -u "$image_md" >/dev/null 2>&1 || true
		image_md=
	fi
}
cleanup_all()
{
	[ "$KEEP_VM" = yes ] || cleanup_vm
}
trap cleanup_all EXIT INT TERM

start_console()
{
	: > "$console_input"
	: > "$console_log"
	i=0
	while ! sockstat -4 -l | grep -q ":${CONSOLE_PORT}[[:space:]]"; do
		kill -0 "$vm_pid" 2>/dev/null || {
			echo "bhyve exited before its console became ready:" >&2
			tail -n 30 "$bhyve_log" >&2
			return 1
		}
		[ "$i" -lt 30 ] || {
			echo "bhyve console did not listen" >&2
			return 1
		}
		sleep 1
		i=$((i + 1))
	done
	(tail -f "$console_input" |
	    nc 127.0.0.1 "$CONSOLE_PORT" > "$console_log" 2>&1) &
	console_pid=$!
}

guest_cmd()
{
	CONSOLE_LOG=$console_log CONSOLE_INPUT=$console_input \
	    sh "$here/acmd-console.sh" "$1" "${2:-30}"
}

guest_check()
{
	label=$1
	command=$2
	limit=${3:-15}
	output=
	if output=$(guest_cmd "$command" "$limit"); then
		echo "PASS  preflight_$label"
		return 0
	else
		status=$?
	fi
	echo "FAIL  preflight_$label (guest status $status)" >&2
	[ -z "$output" ] || printf '%s\n' "$output" >&2
	if [ "$status" -eq 124 ]; then
		echo "recent guest console output:" >&2
		tail -n 30 "$console_log" >&2
	fi
	return "$status"
}

wait_for_guest()
{
	login_sent=no
	i=0
	while [ "$i" -lt 120 ]; do
		if [ "$login_sent" = no ] && grep -q 'login:' "$console_log" 2>/dev/null; then
			printf 'root\r' >> "$console_input"
			login_sent=yes
			sleep 2
		fi
		if grep -Eq '(^|[[:space:]])root@[^[:space:]]+.*#[[:space:]]*$' \
		    "$console_log" 2>/dev/null &&
		    guest_cmd 'echo guest-ready' 8 2>/dev/null |
		    grep -q '^guest-ready$'; then
			return 0
		fi
		sleep 1
		i=$((i + 1))
	done
	echo "5BSD guest did not reach a usable root console" >&2
	tail -n 30 "$console_log" >&2
	return 1
}

prepare_guest_image()
{
	base=$1
	copy=$2
	fsck_log=$3

	echo "Creating sparse per-attempt guest image"
	dd if="$base" of="$copy" bs=4m conv=sparse status=none
	image_md=$(mdconfig -a -t vnode -f "$copy")
	ufs_partition=$(gpart show -p "$image_md" |
	    awk '$4 == "freebsd-ufs" { print "/dev/" $3; exit }')
	if [ -z "$ufs_partition" ]; then
		echo "no FreeBSD UFS partition found in $base" >&2
		return 1
	fi
	# Repair only the disposable copy.  The base image remains immutable.
	if ! fsck_ufs -fy "$ufs_partition" >"$fsck_log" 2>&1; then
		echo "fsck failed for cloned guest image:" >&2
		tail -n 40 "$fsck_log" >&2
		return 1
	fi
	mdconfig -d -u "$image_md"
	image_md=
}

shutdown_guest()
{
	# Prefer a clean UFS unmount.  A wedged or panicked guest is bounded by
	# cleanup_vm(), which escalates from TERM to KILL after five seconds.
	guest_cmd 'shutdown -p now' 8 >/dev/null 2>&1 || true
	i=0
	while kill -0 "$vm_pid" 2>/dev/null && [ "$i" -lt 60 ]; do
		sleep 1
		i=$((i + 1))
	done
}

for transport in $TRANSPORTS; do
	case "$transport" in
	modern)
		transport_opt=,transport=modern
		vsock_id=1053
		rng_id=1044
		;;
	legacy)
		# Deliberately omit transport=legacy: this validates compatibility
		# for every existing command line which has no transport option.
		transport_opt=
		vsock_id=1013
		rng_id=1005
		;;
	*)
		echo "invalid transport: $transport" >&2
		exit 2
		;;
	esac

	vmname="vsock-5bsd-${transport}-$$"
	rundir="$WORKDIR/$transport.$$"
	sockdir="$rundir/sockets"
	console_input="$rundir/console.in"
	console_log="$rundir/console.log"
	bhyve_log="$rundir/bhyve.log"
	guest_image="$rundir/guest.img"
	fsck_log="$rundir/fsck.log"
	mkdir -p -m 0700 "$sockdir"
	: > "$bhyve_log"

	echo "== 5BSD $transport: boot and test =="
	prepare_guest_image "$IMAGE" "$guest_image" "$fsck_log"
	"$BHYVELOAD" -c /dev/null -m 2G -d "$guest_image" "$vmname" \
	    >> "$bhyve_log" 2>&1
	"$BHYVE" -c 2 -m 2G -H -w \
	    -s 0,hostbridge \
	    -s "3,virtio-blk,$guest_image" \
	    -s "5,virtio-vsock,cid=$CID,path=$sockdir$transport_opt" \
	    -s "6,virtio-rnd$transport_opt" \
	    -s 31,lpc -l "com1,tcp=127.0.0.1:$CONSOLE_PORT" \
	    "$vmname" >> "$bhyve_log" 2>&1 &
	vm_pid=$!
	start_console
	wait_for_guest

	guest_check cid \
	    "test \"\$(sysctl -n kern.vsock.guest_cid)\" = $CID"
	guest_check vsock_pci \
	    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x${vsock_id}([[:space:]]|$)'"
	guest_check rng_pci \
	    "pciconf -l | grep -Eqi 'vendor=0x1af4 device=0x${rng_id}([[:space:]]|$)'"
	guest_check vsock_driver \
	    "devinfo -rv | grep -q 'virtio_vsock0'"
	guest_check rng_driver \
	    "devinfo -rv | grep -q 'vtrnd0'"
	guest_check rng_read \
	    "timeout 10 dd if=/dev/random of=/dev/null bs=32 count=1 2>/dev/null" 15

	mkdir -p -m 0700 "$rundir/data"
	DIR=$sockdir BULK_MB=$BULK_MB \
	    TOOLS="$tools" \
	    WORK="$rundir/data" \
	    VCMD="env CONSOLE_LOG=$console_log CONSOLE_INPUT=$console_input sh $here/acmd-console.sh" \
	    sh "$here/run.sh"
	shutdown_guest
	cleanup_vm
	rm -f "$guest_image"
done

echo "5BSD transport automation completed successfully: $TRANSPORTS"
