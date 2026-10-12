#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Select a signing workflow for an unpublished NO_ROOT stage.
set -eu
umask 077
usage() { echo 'usage: prepare-stage.sh -r private-stage (configured through CAPIMAGE_SIGNING_MODE and CAPIMAGE_SIGNING_KEY)' >&2; exit 64; }
fail() { echo "capimage-stage: $*" >&2; exit 1; }
stage=
while getopts r: flag; do
    case "$flag" in r) stage=$OPTARG;; *) usage;; esac
done
shift $((OPTIND - 1))
[ $# = 0 ] && [ -n "$stage" ] || usage
stage=$(cd "$stage" && pwd -P)
[ "$stage" != / ] && [ -f "$stage/METALOG" ] && [ ! -L "$stage/METALOG" ] || fail 'a private NO_ROOT stage is required'
mode=${CAPIMAGE_SIGNING_MODE:-auto}
key=${CAPIMAGE_SIGNING_KEY:-}
cache=${CAPIMAGE_BUILD_CACHE:-no}
layout=${CAPIMAGE_BUILD_LAYOUT:-no}
enforce=${CAPIMAGE_REQUIRE_SIGNATURES:-}
if [ "$mode" = auto ]; then
    if [ -n "$key" ]; then mode=signed; else mode=unsigned; fi
fi
if [ -z "$enforce" ]; then
    if [ "$mode" = unsigned ]; then enforce=no; else enforce=yes; fi
fi
case "$cache:$enforce" in yes:yes|yes:no|no:yes|no:no) ;; *) fail 'cache and signature requirement options must be yes or no';; esac
case "$layout" in yes|no) ;; *) fail 'CAPIMAGE_BUILD_LAYOUT must be yes or no';; esac
if [ "$layout" = yes ]; then
    [ "$cache" = yes ] || fail 'layout generation requires CAPIMAGE_BUILD_CACHE=yes'
    [ "${CAPIMAGE_TARGET_ARCH:-$(uname -p)}" = amd64 ] || fail 'layout generation currently requires target amd64'
fi
case "$mode" in
unsigned)
    [ -z "$key" ] || fail 'unsigned mode cannot accept a signing key'
    [ "$enforce" = no ] || fail 'unsigned mode cannot require signatures'
    [ "$cache" = no ] || fail 'the shared cache requires signed or development mode'
    [ -z "${CAPIMAGE_CACHE_LIST:-}" ] || fail 'unsigned mode cannot select cache libraries'
    for marker in "$stage/etc/capability/require-signatures" "$stage/usr/libdata/5bsd/cache/elf.cache" "$stage/usr/libdata/5bsd/cache/elf.cache.sig" "$stage"/Capabilities/System/*.cap/Signature; do
        [ ! -e "$marker" ] && [ ! -L "$marker" ] || fail 'unsigned mode requires a fresh stage without signed deployment artifacts'
    done
    echo 'capimage-stage: mode=unsigned; external development manifests retained; no key generated'
    exit 0
    ;;
signed)
    [ -n "$key" ] || fail 'signed mode requires CAPIMAGE_SIGNING_KEY; no key is generated automatically'
    ;;
development)
    [ -z "$key" ] || fail 'development mode uses CAPIMAGE_DEVELOPMENT_KEY; use signed mode for an existing signing key'
    key=${CAPIMAGE_DEVELOPMENT_KEY:-/usr/obj/usr/src/signing-keys/development.pem}
    ;;
*) fail 'CAPIMAGE_SIGNING_MODE must be auto, unsigned, signed, or development';;
esac
capsign=${CAPSIGN:-capsign}
command -v "$capsign" >/dev/null 2>&1 || fail 'a native CAPSIGN tool is required'
if [ "$cache" = yes ]; then
    command -v "${ELFCACHE:-elfcache}" >/dev/null 2>&1 || fail 'a native ELFCACHE tool is required'
elif [ -n "${CAPIMAGE_CACHE_LIST:-}" ]; then
    fail 'CAPIMAGE_CACHE_LIST requires CAPIMAGE_BUILD_CACHE=yes'
fi
# Canonicalize the parent before placing any private key there. The default
# directory is persistent across ordinary clean world builds, outside stages.
parent=$(dirname "$key")
name=$(basename "$key")
[ "$name" != . ] && [ "$name" != .. ] || fail 'invalid key filename'
if [ "$mode" = development ]; then
    mkdir -p -m 0700 "$parent"
fi
parent=$(cd "$parent" && pwd -P)
key=$parent/$name
parent_permissions=$(stat -f %Lp "$parent")
[ $((0$parent_permissions & 022)) = 0 ] || fail 'private key directory must not be writable by group or others'
case "$key" in /usr/obj/usr/src/repo|/usr/obj/usr/src/repo/*) fail 'private keys must be outside the publication repository';; esac
case "$key" in "$stage"|"$stage"/*) fail 'private keys must be outside the staged image';; esac
scratch=
cleanup() { [ -z "$scratch" ] || rm -rf "$scratch"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
if [ "$mode" = development ] && [ ! -e "$key" ] && [ ! -L "$key" ]; then
    # mktemp and link give private construction and atomic no-clobber creation.
    # Concurrent builders may race; a winner's existing key is reused below.
    scratch=$(mktemp -d "$parent/.capimage-key.XXXXXX")
    openssl genpkey -algorithm ed25519 -out "$scratch/private.pem"
    chmod 0600 "$scratch/private.pem"
    if ln "$scratch/private.pem" "$key" 2>/dev/null; then
        echo "capimage-stage: generated development key at $key"
    else
        [ -f "$key" ] && [ ! -L "$key" ] || fail 'cannot publish development key'
    fi
    cleanup
    scratch=
fi
[ -f "$key" ] && [ ! -L "$key" ] || fail 'signing key must be a regular file, not a symlink'
permissions=$(stat -f %Lp "$key")
[ $((0$permissions & 077)) = 0 ] || fail 'private key must not be accessible to group or others'
[ -r "$key" ] || fail 'private key is not readable by the signing user'
echo "capimage-stage: mode=$mode; key=$key; require-signatures=$enforce; cache=$cache"
set -- -r "$stage" -k "$key"
[ "$enforce" = no ] || set -- "$@" -e
[ "$cache" = no ] || set -- "$@" -c
[ "$layout" = no ] || set -- "$@" -d
[ -z "${CAPIMAGE_CACHE_LIST:-}" ] || set -- "$@" -l "$CAPIMAGE_CACHE_LIST"
CAPSIGN="$capsign" sh "$(dirname "$0")/sign-stage.sh" "$@"
