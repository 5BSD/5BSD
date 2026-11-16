#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# SYSCTL_WRITE: the image's system.Sysctl policy gets the given names as the
# default write list, nothing else changes, and a policy without an empty
# default write list is refused rather than left as shipped.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
src=$(CDPATH= cd -- "$root/../../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
conf=Capabilities/System/Sysctl.cap/Units/bsdsysctl.unit/Config/sysctl.conf
sed -n '/^if \[ -n "\$sysctl_write" \]; then/,/^fi$/p' "$root/vm-provider.sh" > "$work/block.sh"
[ -s "$work/block.sh" ]
run() { # stage-dir names
	( die() { echo "die: $*" >&2; exit 2; }
	  stage=$1 x=$work/out sysctl_write=$2 sysctl_conf=$conf
	  mkdir -p "$x"; . "$work/block.sh" )
}
mkdir -p "$work/stage/$(dirname $conf)"
cp "$src/usr.sbin/BSDSysctl/capbundle/sysctl.conf" "$work/stage/$conf"
run "$work/stage" "kern.maxfiles kern.maxfilesperproc"
grep -q '^	write = \["kern.maxfiles", "kern.maxfilesperproc"\];$' "$work/out/sysctl.conf"
# Only that line differs, and only the default block's list was filled.
[ "$(diff "$work/stage/$conf" "$work/out/sysctl.conf" | grep -c '^[<>]')" = 2 ]
[ "$(grep -c 'write = \[\];' "$work/out/sysctl.conf")" = \
    "$(($(grep -c 'write = \[\];' "$work/stage/$conf") - 1))" ]
# A policy that already grants writes, or has no default block, is refused.
sed 's/^	write = \[\];$/	write = ["kern.hostname"];/' "$work/stage/$conf" > "$work/granted"
cp "$work/granted" "$work/stage/$conf"
if run "$work/stage" kern.maxfiles 2>/dev/null; then exit 1; fi
rm "$work/stage/$conf"
if run "$work/stage" kern.maxfiles 2>/dev/null; then exit 1; fi
echo 'PASS SYSCTL_WRITE fills the default write list only and refuses a policy it cannot recognise'
