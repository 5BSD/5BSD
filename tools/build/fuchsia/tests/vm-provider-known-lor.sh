#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# vm-provider.sh with known-lor.txt: each recorded report under known-lor/
# named known-* is classed KNOWN_LOR, each named unknown-* stops the run,
# alone and after a known one, with LF and with the serial console's CRLF
# line ends.  Runs the actual unknown_lor function; no guest.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
fix=$root/tests/known-lor
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL: $*"; exit 1; }
sed -n '/^unknown_lor() {/,/^}/p' "$root/vm-provider.sh" > "$work/fn.sh"
grep -q 'PYEOF' "$work/fn.sh" || fail 'no unknown_lor function'
# unknown_lor LOG: 0 when a report matches no known-lor.txt entry.
unknown() {
	sh -c 'log=$1 known_lor=$2; . "$3"; unknown_lor' sh "$1" \
	    "$root/known-lor.txt" "$work/fn.sh"
}
crlf() { sed 's/$/\r/' "$1" > "$work/crlf"; }
n=0
for f in "$fix"/known-*.txt "$fix"/unknown-*.txt; do
	[ -f "$f" ] || fail "no fixture $f"
	b=${f##*/}
	{ echo 'Syncing disks, vnodes remaining... 0 0 0 done'; cat "$f"
	  echo 'Uptime: 1m31s'; } > "$work/log"
	crlf "$work/log"
	case $b in
	known-*)
		unknown "$work/log" && fail "$b: not known"
		unknown "$work/crlf" && fail "$b: not known with CRLF"
		;;
	*)
		unknown "$work/log" || fail "$b: classed known"
		unknown "$work/crlf" || fail "$b: classed known with CRLF"
		cat "$fix"/known-shutdown-tmpfs-devfs.txt "$f" > "$work/log2"
		unknown "$work/log2" || fail "$b: hidden by a known report before it"
		;;
	esac
	n=$((n + 1))
done
: > "$work/none"
unknown "$work/none" && fail 'a log without reversals reported one'
# After the run: a reversal the 10 s poll never saw (printed just before
# the guest powered off) still makes the run not clean.
sed -n '/^# --- LOR verdict/,/^# --- end of the LOR verdict$/p' \
    "$root/vm-provider.sh" > "$work/verdict.sh"
grep -q 'lor_unknown=1' "$work/verdict.sh" || fail 'no LOR verdict block'
grep -q '^if \[ \$forced = 0 \] && \[ \$lor_unknown = 0 \] &&' "$root/vm-provider.sh" ||
    fail 'the verdict does not require lor_unknown=0'
after() {
	sh -c 'log=$1 known_lor=$2; . "$3"; n=$(grep -ac "lock order reversal" "$log" || true)
	    . "$4"; echo "lor_unknown=$lor_unknown"' sh "$1" \
	    "$root/known-lor.txt" "$work/fn.sh" "$work/verdict.sh"
}
cat "$fix"/known-shutdown-tmpfs-devfs.txt "$fix"/unknown-quota.txt > "$work/log"
after "$work/log" > "$work/out"
grep -qx 'lor_unknown=1' "$work/out" && grep -q '^UNKNOWN_LOR' "$work/out" ||
    fail "an unseen unknown reversal left clean: $(cat "$work/out")"
after "$fix"/known-shutdown-tmpfs-ufs-vflush.txt > "$work/out"
grep -qx 'lor_unknown=0' "$work/out" && grep -q '^KNOWN_LOR=1 ' "$work/out" ||
    fail "a known reversal: $(cat "$work/out")"
(export FATAL_LOR=no; after "$fix"/unknown-quota.txt) > "$work/out"
grep -qx 'lor_unknown=0' "$work/out" || fail "FATAL_LOR=no: $(cat "$work/out")"
after "$work/none" > "$work/out"
[ "$(cat "$work/out")" = lor_unknown=0 ] || fail "no reversal: $(cat "$work/out")"
echo "PASS known-lor.txt classes the $n recorded reports as intended; an unseen unknown reversal is not clean"
