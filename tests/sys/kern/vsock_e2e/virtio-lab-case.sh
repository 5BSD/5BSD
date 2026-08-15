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

# Return every current descendant of the supplied process, not only its
# direct children.  Each returned token includes a fingerprint of the process
# start time and command.  The lab runners commonly start bhyve plus one or
# more helper processes; after the runner receives TERM those helpers can be
# reparented before a direct-parent lookup sees them again.  Keep the original
# tree membership, but never later signal a bare PID that might have been
# reused by an unrelated process.
process_record()
{
	pid=$1
	# The record is later used to decide whether it is still safe to signal a
	# descendant after the runner has exited and the PID could have been
	# reused.  Use the platform SHA-256 tool rather than a small checksum: a
	# matching PID alone is never authority to signal a process outside this
	# case's original tree.
	# sha256(1) successfully hashes an empty stream.  Treat an empty ps(1)
	# result as no process rather than as a stable identity for a PID that
	# exited in the collection window.
	process=$(ps -o lstart= -o command= -p "$pid" 2>/dev/null) || return 1
	[ -n "$process" ] || return 1
	digest=$(printf '%s\n' "$process" | /sbin/sha256 -q) || return 1
	case "$digest" in
	*[!0-9a-f]* | '')
		return 1
		;;
	esac
	[ "${#digest}" -eq 64 ] || return 1
	printf '%s:%s\n' "$pid" "$digest"
}

process_record_matches()
{
	record=$1
	pid=${record%%:*}
	current=$(process_record "$pid") || return 1
	[ "$current" = "$record" ]
}

collect_descendants()
{
	frontier=$1
	all=
	while [ -n "$frontier" ]; do
		next=
		for parent in $frontier; do
			for pid in $(pgrep -P "$parent" 2>/dev/null || true); do
				record=$(process_record "$pid") || continue
				case " $all " in
				*" $record "*)
					;;
				*)
					all="$all $record"
					next="$next $pid"
					;;
				esac
			done
		done
		frontier=$next
	done
	printf '%s\n' "$all"
}

terminate()
{
	direct_record=
	descendants=
	targets=
	trap - HUP INT TERM
	if [ -n "$child" ]; then
		# Signal the runner (timeout's direct child) first so its cleanup
		# trap can stop bhyve and remove provider resources.  Preserve the
		# complete initial descendant tree: once that runner exits its helpers
		# may be reparented and a later pgrep -P would no longer find them.
		# Keep the direct timeout child in the bounded escalation set too:
		# otherwise a TERM-ignoring timeout process could make the final wait
		# unbounded even after all recorded descendants have gone away.
		direct_record=$(process_record "$child") || direct_record=
		descendants=$(collect_descendants "$child")
		targets="$direct_record$descendants"
		kill -TERM "$child" 2>/dev/null || true
		i=0
		alive="$targets"
		while [ -n "$alive" ] && [ "$i" -lt 50 ]; do
			alive=
			# Include the direct timeout child as well as the originally
			# discovered descendants.  It is fingerprinted for the same PID
			# reuse protection, so it cannot silently fall out of the bounded
			# escalation merely because it has no children of its own.
			for record in $targets; do
				if process_record_matches "$record"; then
					alive="$alive $record"
				fi
			done
			[ -n "$alive" ] || break
			sleep 0.1
			i=$((i + 1))
		done
		# The runner's trap had a bounded opportunity to clean up.  Do not
		# leave a reparented device model or helper running after cancellation.
		for record in $alive; do
			pid=${record%%:*}
			process_record_matches "$record" &&
				kill -TERM "$pid" 2>/dev/null || true
		done
		i=0
		while [ -n "$alive" ] && [ "$i" -lt 50 ]; do
			next=
			for record in $alive; do
				if process_record_matches "$record"; then
					next="$next $record"
				fi
			done
			alive=$next
			[ -z "$alive" ] || sleep 0.1
			i=$((i + 1))
		done
		for record in $alive; do
			pid=${record%%:*}
			process_record_matches "$record" &&
				kill -KILL "$pid" 2>/dev/null || true
		done
		# $child is still our waitable child, so its PID cannot be reused
		# before wait(2).  Retain this fallback if process fingerprinting was
		# unavailable while the signal arrived.
		[ -n "$direct_record" ] || kill -KILL "$child" 2>/dev/null || true
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
