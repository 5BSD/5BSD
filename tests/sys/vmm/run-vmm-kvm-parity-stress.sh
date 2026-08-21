#!/bin/sh
# Bounded parallel stress runner for the low-level KVM-parity VMM cases.
set -eu

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 077

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
program=${PROGRAM:-$here/vmm_kvm_parity_live_test}
iterations=${ITERATIONS:-10}
jobs=${JOBS:-4}
require_root=${REQUIRE_ROOT:-yes}
keep_work=${KEEP_WORK:-no}
result_file=${RESULT_FILE:-}

case "$iterations" in
''|*[!0-9]*|0) echo "ITERATIONS must be a positive integer" >&2; exit 2 ;;
esac
case "$jobs" in
''|*[!0-9]*|0) echo "JOBS must be a positive integer" >&2; exit 2 ;;
esac
case "$require_root" in
yes|no) ;;
*) echo "REQUIRE_ROOT must be yes or no" >&2; exit 2 ;;
esac
case "$keep_work" in
yes|no) ;;
*) echo "KEEP_WORK must be yes or no" >&2; exit 2 ;;
esac
[ "$require_root" = no ] || [ "$(id -u)" -eq 0 ] || {
	echo "VMM parity stress requires root" >&2
	exit 1
}
[ -x "$program" ] || { echo "missing test program: $program" >&2; exit 1; }

if [ -n "${WORKDIR:-}" ]; then
	work=$WORKDIR
	case "$work" in
	/*) ;;
	*) echo "WORKDIR must be absolute" >&2; exit 2 ;;
	esac
	if [ -e "$work" ]; then
		[ -d "$work" ] && [ ! -L "$work" ] || {
			echo "WORKDIR must be a real directory" >&2
			exit 2
		}
		set -- $(stat -f '%u %Lp' "$work")
		[ "$1" -eq "$(id -u)" ] && [ "$2" = 700 ] || {
			echo "WORKDIR must be caller-owned mode 0700" >&2
			exit 2
		}
	else
		mkdir -m 0700 "$work"
	fi
else
	work=$(mktemp -d /tmp/vmm-kvm-parity-stress.XXXXXX)
fi

cleanup()
{
	status=${1:-$?}
	trap - EXIT HUP INT TERM
	if [ -n "$result_file" ]; then
		tmp_result="${result_file}.tmp.$$"
		if [ "$status" -eq 0 ]; then
			printf 'PASS vmm-kvm-parity-stress iterations=%s jobs=%s cases=%s\n' \
			    "$iterations" "$jobs" "${completed:-0}" >"$tmp_result"
		else
			printf 'FAIL vmm-kvm-parity-stress exit=%s workdir=%s\n' \
			    "$status" "$work" >"$tmp_result"
		fi
		mv -f "$tmp_result" "$result_file"
	fi
	if [ "$status" -eq 0 ] && [ "$keep_work" = no ]; then
		rm -rf "$work"
	else
		echo "VMM parity stress artifacts: $work" >&2
	fi
	exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

if ! "$program" -l >"$work/inventory" 2>&1; then
	echo "ATF case discovery failed" >&2
	exit 1
fi
cases=$(awk '$1 == "ident:" { print $2 }' "$work/inventory")
[ -n "$cases" ] || { echo "ATF case discovery returned no cases" >&2; exit 1; }

run_one()
{
	round=$1
	test_case=$2
	sequence=$3
	case_dir=$work/$(printf '%04d-%04d-%s' "$round" "$sequence" "$test_case")
	mkdir -m 0700 "$case_dir"
	if ! (cd "$case_dir" && "$program" -r /dev/stdout "$test_case") \
	    >"$case_dir/result" 2>&1 ||
	    ! tail -n 1 "$case_dir/result" | grep -qx passed; then
		echo "FAIL round=$round case=$test_case log=$case_dir/result" >&2
		return 1
	fi
}

completed=0
round=1
while [ "$round" -le "$iterations" ]; do
	batch_pids=
	batch_count=0
	sequence=0
	for test_case in $cases; do
		sequence=$((sequence + 1))
		run_one "$round" "$test_case" "$sequence" &
		batch_pids="$batch_pids $!"
		batch_count=$((batch_count + 1))
		if [ "$batch_count" -eq "$jobs" ]; then
			batch_status=0
			for pid in $batch_pids; do
				wait "$pid" || batch_status=1
			done
			[ "$batch_status" -eq 0 ] || exit 1
			completed=$((completed + batch_count))
			batch_pids=
			batch_count=0
		fi
	done
	if [ "$batch_count" -ne 0 ]; then
		batch_status=0
		for pid in $batch_pids; do
			wait "$pid" || batch_status=1
		done
		[ "$batch_status" -eq 0 ] || exit 1
		completed=$((completed + batch_count))
	fi
	round=$((round + 1))
done

echo "PASS VMM KVM-parity stress: iterations=$iterations jobs=$jobs cases=$completed"
