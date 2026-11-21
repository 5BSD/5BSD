#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# vm-provider.sh skip accounting: a skip without a DEFERRED_* token is listed
# as a PLAIN_SKIP, every one of them; a skip for a program or file the stage
# lacks makes the run not clean (STAGE_PREREQ_SKIPPED), a kernel-option
# device such as /dev/kcov stays a plain skip; expected
# failures, which kyua counts as passed, are listed.  Runs the actual block
# of vm-provider.sh; no guest.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL: $*"; exit 1; }
sed -n '/^# --- skip accounting/,/^# --- end of the skip accounting/p' \
    "$root/vm-provider.sh" > "$work/block.sh"
grep -q PLAIN_SKIPS "$work/block.sh" || fail 'no skip accounting block'
run() { log=$1 sh -c 'verdict=VM_CLEAN; . "$0"; echo "verdict=$verdict"' "$work/block.sh"; }
log=$work/serial.log
{
	echo KYUA_SKIPPED_LIST_BEGIN
	echo "sys/a:one  ->  skipped: DEFERRED_ENFORCED_TIER: enforce=0  [0.1s]"
	echo "sys/m:dv  ->  skipped: DEFERRED_DISPOSABLE_GUEST: requires disposable_vm=yes  [0.1s]"
	echo "sys/m:ten  ->  skipped: Required configuration property 'authority_anchor' not defined  [0.1s]"
	echo "sys/k:km  ->  skipped: Required kmods are not loaded: zfs  [0.1s]"
	echo "sys/opencrypto/runtests:main  ->  skipped: Required program 'python3' not found in PATH  [0.1s]"
	echo "sys/k/v:t  ->  skipped: The required program rg could not be found in the PATH  [0.1s]"
	echo "sys/k/l:busybox  ->  skipped: Required file '/compat/linux/bin/busybox' not found  [0.1s]"
	echo "sys/kern/kcov:kcov_basic  ->  skipped: Failed to open /dev/kcov  [0.1s]"
	i=0
	while [ $i -lt 60 ]; do
		echo "sys/p:case$i  ->  skipped: failed to allocate 1073741824-byte superpage  [0.3s]"
		i=$((i + 1))
	done
	echo KYUA_SKIPPED_LIST_END
	echo KYUA_XFAIL_LIST_BEGIN
	echo "lib/x:y  ->  expected_failure: CP_SF_VISIBLE not enforced  [0.2s]"
	echo KYUA_XFAIL_LIST_END
} > "$log"
run "$log" > "$work/out"
grep -qx 'PLAIN_SKIPS=61 (skips without a DEFERRED_\* token; these cases did not run; not a pass):' "$work/out" ||
    fail "plain skip count: $(grep PLAIN_SKIPS "$work/out")"
[ "$(grep -c '^PLAIN_SKIP: ' "$work/out")" = 61 ] || fail 'not every plain skip listed'
grep -qx 'PLAIN_SKIP: sys/p:case59  ->  skipped: failed to allocate 1073741824-byte superpage' "$work/out" ||
    fail 'the last plain skip is missing'
grep -E '^PLAIN_SKIP: .*(DEFERRED_|authority_anchor|kmods|Required|required program)' "$work/out" &&
    fail 'a tokened, kmod or prerequisite skip listed as plain'
grep -qx 'STAGE_PREREQ_SKIPPED=3 (the stage lacks a program or file these cases require; not a pass):' "$work/out" ||
    fail "prerequisite count: $(grep STAGE_PREREQ "$work/out")"
grep -qx 'EXPECTED_FAILURES=1 (cases marked as expected to fail; kyua counts them as passed; not a pass):' "$work/out" ||
    fail 'expected failure not counted'
grep -qx 'PLAIN_SKIP: sys/kern/kcov:kcov_basic  ->  skipped: Failed to open /dev/kcov' "$work/out" ||
    fail 'the kcov device skip is not a plain skip'
grep -qx 'verdict=VM_NOT_CLEAN' "$work/out" || fail 'a missing stage prerequisite left the run clean'
# Plain skips and expected failures alone leave the verdict to the rest.
printf 'KYUA_SKIPPED_LIST_BEGIN\nsys/p:a  ->  skipped: root required  [0.1s]\nKYUA_SKIPPED_LIST_END\nKYUA_XFAIL_LIST_BEGIN\nKYUA_XFAIL_LIST_END\n' > "$log"
run "$log" > "$work/out"
grep -qx 'PLAIN_SKIPS=1 (skips without a DEFERRED_\* token; these cases did not run; not a pass):' "$work/out" &&
    { grep -q 'verdict=VM_CLEAN' "$work/out" && ! grep -q 'EXPECTED_FAILURES\|STAGE_PREREQ' "$work/out"; } ||
    fail "plain skip only: $(cat "$work/out")"
printf 'KYUA_SKIPPED_LIST_BEGIN\nKYUA_SKIPPED_LIST_END\n' > "$log"
run "$log" > "$work/out"
[ "$(cat "$work/out")" = verdict=VM_CLEAN ] || fail "no skips: $(cat "$work/out")"
echo 'PASS skips are accounted: plain skips all listed, stage prerequisites not clean, expected failures listed'
