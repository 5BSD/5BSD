#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# vm-provider.sh test-stage packages: the pinned list names real packages
# with their sha256; extraction keeps them under /usr/local and refuses a
# package that installs anywhere else.  Runs the actual blocks; no guest.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL: $*"; exit 1; }
list=$root/test-stage-packages
for want in python3- python- py312-pytest- python312- py312-dpkt- nist-kat-; do
	grep -q "^$want" "$list" || fail "test-stage-packages lacks $want"
done
awk '!/^#/ && NF { if ($2 !~ /^[0-9a-f]{64}$/) bad = 1 } END { exit bad }' "$list" ||
    fail 'a pinned package without a sha256'
sed -n '/^# ----------------------------------------------------- test-stage packages ---$/,/^# --------------------------------------------------------------- manifest ---$/p' \
    "$root/vm-provider.sh" > "$work/block.sh"
grep -q 'outside /usr/local' "$work/block.sh" || fail 'no extraction block'
mkpkg() {	# NAME PATH: a package archive holding one file at PATH
	mkdir -p "$work/src/$1/$(dirname "$2")"
	echo data > "$work/src/$1/$2"
	echo "name: $1" > "$work/src/$1/+COMPACT_MANIFEST"
	(cd "$work/src/$1" && bsdtar -cJf "$work/pkgs/$1.pkg" +COMPACT_MANIFEST "$2")
}
mkdir -p "$work/pkgs"
mkpkg good-1 usr/local/bin/good
mkpkg bad-1 usr/bin/bad
run() {
	sh -c 'die() { echo "DIE: $*"; exit 2; }; x=$1 test_pkgdir=$2 test_pkgs=$3; . "$4"' sh \
	    "$work/x" "$work/pkgs" "$1" "$work/block.sh"
}
mkdir -p "$work/x"
run good-1 > "$work/out" 2>&1 || fail "good package refused: $(cat "$work/out")"
[ -f "$work/x/testpkgs/usr/local/bin/good" ] || fail 'good package not extracted'
[ ! -e "$work/x/testpkgs/+COMPACT_MANIFEST" ] || fail 'package metadata extracted'
if run "good-1 bad-1" > "$work/out" 2>&1; then fail 'a package outside /usr/local accepted'; fi
grep -q 'outside /usr/local' "$work/out" || fail "wrong refusal: $(cat "$work/out")"
# A symlink whose target has a space (or another unlisted character).
mkdir -p "$work/src/link-1/usr/local/bin"
ln -s 'a target' "$work/src/link-1/usr/local/bin/l"
(cd "$work/src/link-1" && bsdtar -cJf "$work/pkgs/link-1.pkg" usr/local/bin/l)
rm -rf "$work/x"; mkdir -p "$work/x"
if run "good-1 link-1" > "$work/out" 2>&1; then fail 'a symlink target with a space accepted'; fi
grep -q 'symlink target with unexpected characters' "$work/out" || fail "wrong refusal: $(cat "$work/out")"
echo 'PASS test-stage packages are pinned with sha256 and kept under /usr/local'
