#!/bin/sh
# Scheduler-only executor used by virtio-lab-selftest.sh.
set -eu

probe_sleep=${LAB_PROBE_SLEEP:-0}
probe_child_sleep=${LAB_PROBE_CHILD_SLEEP:-0}
probe_status=${LAB_PROBE_STATUS:-0}
probe_fail_first=${LAB_PROBE_FAIL_FIRST:-no}

case $probe_sleep in
*[!0-9]*|'')
	echo "LAB_PROBE_SLEEP must be a non-negative integer" >&2
	exit 2
	;;
esac
case $probe_child_sleep in
*[!0-9]*|'')
	echo "LAB_PROBE_CHILD_SLEEP must be a non-negative integer" >&2
	exit 2
	;;
esac
case $probe_status in
*[!0-9]*|'')
	echo "LAB_PROBE_STATUS must be a non-negative integer" >&2
	exit 2
	;;
esac
case $probe_fail_first in
yes|no)
	;;
*)
	echo "LAB_PROBE_FAIL_FIRST must be yes or no" >&2
	exit 2
	;;
esac

[ "$probe_child_sleep" -eq 0 ] || {
	: "${WORKDIR:?LAB_PROBE_CHILD_SLEEP requires WORKDIR}"
	mkdir -p "$WORKDIR"
	sleep "$probe_child_sleep" &
	printf '%s\n' "$!" >"$WORKDIR/probe-child.pid"
}
[ "$probe_sleep" -eq 0 ] || sleep "$probe_sleep"
echo "virtio-lab probe case=${LAB_PROBE_NAME:-unnamed} cid=${CID:-none}"
[ "$probe_fail_first" != yes ] || [ "${VIRTIO_LAB_ATTEMPT:-0}" -ne 1 ] ||
    exit 7
exit "$probe_status"
