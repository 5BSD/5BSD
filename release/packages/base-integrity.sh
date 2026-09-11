#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Keyless integrity baseline for an offline pkgbase generation.
set -eu
[ "$#" -eq 3 ] || { echo "usage: $0 create|check|veriexec candidate-root manifest" >&2; exit 64; }
operation=$1
case "$operation" in create|check|veriexec) ;; *) exit 64 ;; esac
root=$(realpath "$2")
[ -d "$root" ] && [ "$root" != / ] || {
	echo "base-integrity: use an offline candidate directory, not /" >&2
	exit 64
}
parent=$(realpath "$(dirname "$3")")
manifest="$parent/$(basename "$3")"
case "$manifest" in "$root"|"$root"/*)
	echo "base-integrity: manifest must be outside the candidate" >&2
	exit 64 ;;
esac
if [ "$operation" = check ]; then
	[ -f "$manifest" ] && [ ! -L "$manifest" ] || exit 66
	# No repair flags: verification must never modify the candidate.
	report=$(mktemp -t base-integrity)
	trap 'rm -f "$report"' EXIT HUP INT TERM
	status=0
	mtree -P -f "$manifest" -p "$root" > "$report" || status=$?
	# FreeBSD mtree can report extra entries while returning success.
	if [ -s "$report" ]; then
		cat "$report"
		[ "$status" -ne 0 ] || status=1
	fi
	exit "$status"
fi
[ ! -e "$manifest" ] && [ ! -L "$manifest" ] || {
	echo "base-integrity: refusing to overwrite an existing baseline" >&2
	exit 73
}
umask 077
temporary=$(mktemp "$parent/.base-integrity.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM
if [ "$operation" = veriexec ]; then
	# The veriexec lexer has no pathname quoting/escaping syntax. Refuse
	# ambiguous names rather than silently omitting or misidentifying files.
	(
		cd "$root"
		LC_ALL=C find -s . -type f -exec /bin/sh -ec '
			for path do
				case "$path" in *[!A-Za-z0-9_./+-]*)
					echo "base-integrity: unsupported veriexec pathname: $path" >&2
					exit 65 ;;
				esac
				mode=$(stat -f %Lp "$path")
				digest=$(sha256 -q "$path")
				printf "%s sha256=%s mode=%s\n" "$path" "$digest" "$mode"
			done
		' sh {} +
	) > "$temporary"
	grep -q ' sha256=' "$temporary" || {
		echo "base-integrity: refusing an empty veriexec manifest" >&2
		exit 65
	}
else
{
	echo "# 5BSD local integrity baseline; NOT publisher-authenticated."
	echo "# Generate only from a quiescent, fully populated candidate."
	LC_ALL=C mtree -c -P -k type,uid,gid,mode,nlink,size,link,sha256digest -p "$root"
} > "$temporary"
fi
# Publish without overwriting a concurrently created baseline.
ln "$temporary" "$manifest"
