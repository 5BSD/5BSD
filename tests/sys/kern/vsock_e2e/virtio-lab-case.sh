#!/bin/sh
# Supervised case wrapper for virtio-lab.  This is an internal interface.
set -u

[ "$#" -eq 3 ] || exit 2
case_timeout=$1
status_path=$2
runner=$3
child=

finish()
{
	rc=$1
	trap - HUP INT TERM
	printf '%s\n' "$rc" >"$status_path.tmp" || exit 125
	mv "$status_path.tmp" "$status_path" || exit 125
	exit "$rc"
}

terminate()
{
	descendants=
	trap - HUP INT TERM
	if [ -n "$child" ]; then
		# Signal the runner (timeout's direct child) first so its cleanup
		# trap can stop bhyve and remove provider resources.
		descendants=$(pgrep -P "$child" 2>/dev/null || true)
		[ -z "$descendants" ] || kill -TERM $descendants 2>/dev/null || true
		i=0
		while [ -n "$descendants" ] && [ "$i" -lt 300 ]; do
			alive=
			for pid in $descendants; do
				kill -0 "$pid" 2>/dev/null && alive="$alive $pid"
			done
			[ -n "$alive" ] || break
			sleep 0.1
			descendants=$alive
			i=$((i + 1))
		done
		kill -TERM "$child" 2>/dev/null || true
		wait "$child" 2>/dev/null || true
	fi
	finish 143
}
trap terminate HUP INT TERM

/bin/timeout -k 30 "$case_timeout" /bin/sh "$runner" &
child=$!
wait "$child"
rc=$?
child=
finish "$rc"
