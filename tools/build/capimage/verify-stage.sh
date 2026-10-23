#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Read-only verification of an unpacked signed system using native host tools.
set -eu
usage() { echo 'usage: verify-stage.sh -r root -p trusted-code-public.pem' >&2; exit 64; }
stage= public=
while getopts r:p: option; do
    case "$option" in r) stage=$OPTARG;; p) public=$OPTARG;; *) usage;; esac
done
shift $((OPTIND - 1))
[ $# = 0 ] && [ -n "$stage" ] && [ -n "$public" ] || usage
[ -d "$stage" ] && [ ! -L "$stage" ] || { echo 'invalid stage root' >&2; exit 1; }
stage=$(cd "$stage" && pwd -P)
[ "$stage" != / ] || { echo 'verify-stage requires an alternate root' >&2; exit 1; }
[ -f "$public" ] && [ -r "$public" ] || { echo 'trusted public key is not readable' >&2; exit 1; }
capsign=${CAPSIGN:-capsign}
for part in Capabilities Capabilities/System etc etc/capability; do
    [ -d "$stage/$part" ] && [ ! -L "$stage/$part" ] || { echo "invalid stage directory: $part" >&2; exit 1; }
done
[ -f "$stage/etc/capability/require-signatures" ] && [ ! -L "$stage/etc/capability/require-signatures" ] || {
    echo 'stage does not require signed bundle policies' >&2; exit 1;
}
count=0
for bundle in "$stage"/Capabilities/System/*.cap; do
    [ -d "$bundle" ] && [ ! -L "$bundle" ] || { echo "invalid bundle: $bundle" >&2; exit 1; }
    "$capsign" verify -r -p "$public" "$bundle"
    count=$((count + 1))
done
[ "$count" -gt 0 ] || { echo 'stage has no signed system bundles' >&2; exit 1; }
printf 'verified signed system bundles=%s root=%s\n' "$count" "$stage"
