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
elfcache=${ELFCACHE:-elfcache}
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
cache="$stage/usr/libdata/5bsd/cache/elf.cache"
if [ -e "$cache" ] || [ -L "$cache" ]; then
    for part in usr usr/libdata usr/libdata/5bsd usr/libdata/5bsd/cache; do
        [ -d "$stage/$part" ] && [ ! -L "$stage/$part" ] || { echo "invalid cache directory: $part" >&2; exit 1; }
    done
    [ -f "$cache" ] && [ ! -L "$cache" ] && [ -f "$cache.sig" ] && [ ! -L "$cache.sig" ] || {
        echo 'cache and signature must be regular files' >&2; exit 1;
    }
    "$elfcache" verify -p "$public" "$cache"
elif [ -e "$cache.sig" ] || [ -L "$cache.sig" ]; then
    echo 'cache signature without cache' >&2; exit 1
fi
seed="$stage/usr/libexec/elfcache-seed"
layout="$stage/usr/libdata/5bsd/cache/elf.layout"
if [ -e "$seed" ] || [ -L "$seed" ]; then
    for part in usr usr/libexec; do
        [ -d "$stage/$part" ] && [ ! -L "$stage/$part" ] || { echo "invalid seed directory: $part" >&2; exit 1; }
    done
    [ -f "$seed" ] && [ ! -L "$seed" ] && [ -x "$seed" ] || { echo 'invalid cache seed' >&2; exit 1; }
    "$capsign" verify -p "$public" "$seed"
fi
if [ -e "$layout" ] || [ -L "$layout" ] || [ -e "$layout.sig" ] || [ -L "$layout.sig" ]; then
    [ -f "$cache" ] && [ -f "$seed" ] || { echo 'layout requires cache and signed seed' >&2; exit 1; }
    [ -f "$layout" ] && [ ! -L "$layout" ] && [ -f "$layout.sig" ] && [ ! -L "$layout.sig" ] || {
        echo 'layout and signature must be regular files' >&2; exit 1;
    }
    "$elfcache" layout-verify -p "$public" -l "$layout" "$cache"
fi
printf 'verified signed system bundles=%s root=%s\n' "$count" "$stage"
