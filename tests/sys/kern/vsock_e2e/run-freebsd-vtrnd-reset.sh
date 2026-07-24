#!/bin/sh
#
# Exercise the FreeBSD virtio-rng driver's VIRTIO_F_RING_RESET detach path.
# Run this inside a disposable FreeBSD bhyve guest whose entropy device uses
# bhyve's modern virtio-rng transport.

set -eu

iterations=${ITERATIONS:-100}
workdir=$(mktemp -d /tmp/vtrnd-reset.XXXXXX)
trace=$workdir/queue-reset.trace
reader_failed=$workdir/reader.failed
detached=0
reader_pid=
dtrace_pid=
vtrnd=
completed=no

cleanup()
{
	status=$?
	set +e
	if [ -n "$reader_pid" ]; then
		kill "$reader_pid" 2>/dev/null
		wait "$reader_pid" 2>/dev/null
	fi
	if [ -n "$dtrace_pid" ]; then
		kill -INT "$dtrace_pid" 2>/dev/null
		wait "$dtrace_pid" 2>/dev/null
	fi
	if [ "$detached" -eq 1 ] && [ -n "$vtrnd" ]; then
		devctl attach "$vtrnd" >/dev/null 2>&1
	fi
	if [ "$completed" = yes ]; then
		rm -rf "$workdir"
	elif [ -d "$workdir" ]; then
		echo "retained failure diagnostics under $workdir" >&2
	fi
	return "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

[ "$(id -u)" -eq 0 ] || {
	echo "must be run as root" >&2
	exit 1
}
[ "$(sysctl -n kern.vm_guest)" = "bhyve" ] || {
	echo "must be run inside a disposable bhyve guest" >&2
	exit 1
}
case "$iterations" in
*[!0-9]*|'')
	echo "ITERATIONS must be a positive integer" >&2
	exit 1
	;;
esac
[ "$iterations" -gt 0 ] || {
	echo "ITERATIONS must be a positive integer" >&2
	exit 1
}

vtrnd=$(devinfo | sed -n 's/.*\(vtrnd[0-9][0-9]*\).*/\1/p' | head -n 1)
[ -n "$vtrnd" ] || {
	echo "no attached virtio-rng device found" >&2
	exit 1
}
devinfo -p "$vtrnd" | grep -q 'virtio_pci' || {
	echo "$vtrnd is not attached through virtio_pci" >&2
	exit 1
}
sysctl -n kern.random.random_sources | grep -q "'VirtIO Entropy Adapter'" || {
	echo "VirtIO entropy source is not registered" >&2
	exit 1
}
dtrace -l -n 'virtio:::queue-reset-end' 2>/dev/null |
    grep -q 'queue-reset-end' || {
	echo "virtio queue-reset DTrace probes are unavailable" >&2
	exit 1
}

dtrace -q -o "$trace" \
    -n 'virtio:::queue-reset-begin {
	printf("begin %p %d\n", arg0, arg1);
    }' \
    -n 'virtio:::queue-reset-end {
	printf("end %p %d %d\n", arg0, arg1, arg2);
    }' &
dtrace_pid=$!
sleep 1
kill -0 "$dtrace_pid"

(
	while :; do
		if ! dd if=/dev/random of=/dev/null bs=65536 count=4 \
		    >/dev/null 2>&1; then
			: >"$reader_failed"
			exit 1
		fi
	done
) &
reader_pid=$!

i=1
while [ "$i" -le "$iterations" ]; do
	devctl detach "$vtrnd"
	detached=1
	if sysctl -n kern.random.random_sources |
	    grep -q "'VirtIO Entropy Adapter'"; then
		echo "iteration $i: entropy source survived detach" >&2
		exit 1
	fi

	devctl attach "$vtrnd"
	detached=0
	sysctl -n kern.random.random_sources |
	    grep -q "'VirtIO Entropy Adapter'" || {
		echo "iteration $i: entropy source did not return" >&2
		exit 1
	}
	[ ! -e "$reader_failed" ] || {
		echo "iteration $i: concurrent random read failed" >&2
		exit 1
	}
	i=$((i + 1))
done

kill "$reader_pid" 2>/dev/null || true
wait "$reader_pid" 2>/dev/null || true
reader_pid=
kill -INT "$dtrace_pid"
wait "$dtrace_pid" 2>/dev/null || true
dtrace_pid=

begins=$(awk '$1 == "begin" && $3 == 0 { n++ } END { print n + 0 }' \
    "$trace")
ends=$(awk '$1 == "end" && $3 == 0 { n++ } END { print n + 0 }' "$trace")
successes=$(awk '$1 == "end" && $3 == 0 && $4 == 0 { n++ }
    END { print n + 0 }' "$trace")
failures=$(awk '$1 == "end" && $4 != 0 { n++ } END { print n + 0 }' \
    "$trace")
devices=$(awk '$1 == "end" { seen[$2] = 1 }
    END { for (device in seen) n++; print n + 0 }' "$trace")
[ "$begins" -ge "$iterations" ] || {
	echo "observed $begins queue-reset starts; expected at least $iterations" >&2
	exit 1
}
[ "$ends" -eq "$begins" ] || {
	echo "observed unpaired queue resets: begins=$begins ends=$ends" >&2
	exit 1
}
[ "$successes" -ge "$iterations" ] || {
	echo "observed $successes successful queue resets; expected at least $iterations" >&2
	exit 1
}
[ "$failures" -eq 0 ] || {
	echo "observed $failures failed queue resets" >&2
	exit 1
}
[ "$devices" -eq 1 ] || {
	echo "queue-reset evidence covered $devices device objects, expected one" >&2
	exit 1
}

completed=yes
echo "PASS vtrnd queue reset iterations=$iterations begins=$begins " \
    "successes=$successes devices=$devices"
